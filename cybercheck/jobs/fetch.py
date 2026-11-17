"""Worker job "fetch": drive the sandboxed fetcher over suspicious domains and record what it saw.

Each run:
1. If the fetcher is unavailable (no VPN profile up, or it is failing closed because the egress is not
   the expected country), return {"skipped": "fetcher unavailable"} and change nothing. No log spam.
2. Pick due domains (resolving, review/high tier or score >= FETCH_MIN_SCORE, status open/confirmed,
   not taken down, due per schedule), newest/high-tier first, bounded by FETCH_BATCH.
3. For each, with bounded concurrency FETCH_CONCURRENCY, fetch https://<first hostname>/ (falling back
   to http://). The mobile profile is always fetched; the desktop profile is added on the first round.
   Each snapshot is stored as a pages row (screenshot WebP to data_dir/screenshots/<domain_id>/,
   gzipped HTML to data_dir/html/<domain_id>/, retain_until = now + SCREENSHOT_RETENTION_DAYS). A new
   screenshot/HTML file is not written when its content hash matches the previous snapshot of the same
   profile; the row reuses the previous file's path. When the data directory's filesystem has less than
   FETCH_MIN_FREE_GB free, no file is written (the row is still stored, features.files_skipped =
   "low_disk") and the run reports low_disk: that disk may also hold Postgres.
4. Page features (cybercheck.pagefeatures) and page_score are written; live_state is maintained:
   'live' once a page loads with content; 'down' only after two consecutive failed fetches at least 15
   minutes apart (a single blip must not flip it, because enrich reads 'down' after 'live' as a takedown
   signal). Events 'went_live' and 'page_down' are recorded.
5. A round in which every snapshot was a fetcher fault (browser crash, hard timeout, a request the
   healthy fetcher could not answer) says nothing about the page: it does not use up a schedule step
   (fetch_state.n stays, so a first round keeps its desktop profile) and is retried after 30 min,
   doubling per fault in a row (fetch_state.faults) up to 6 h.

Tracked domains (confirmed / reported / AI verdict phishing) are re-fetched every
FETCH_TRACK_INTERVAL_H for ENRICH_TRACK_DAYS from the latest of first_seen, reported_at and the
confirmation: the same window as enrich's hourly checks (enrich.track_end). Only enrich records a
takedown, so fetching must not outlive it; after the window a domain follows the normal watch-window
schedule like any other.

The fetcher stores nothing itself; everything persisted here comes from the JSON it returned, which is
treated as hostile input (lengths capped, paths kept under data_dir, HTML never rendered).

Settings read here (documented in docs/FETCHER.md and .env.example):
  FETCH_CONCURRENCY          domains fetched at once (config.py default 2)
  FETCH_MIN_SCORE            name-score floor for watch-tier domains worth fetching (config.py default 60)
  SCREENSHOT_RETENTION_DAYS  retain_until = now + this many days (config.py default 60)
  FETCH_BATCH                due domains per run (default 20)
  FETCH_EXPECTED_COUNTRY     required egress country, "" disables the check in the fetcher (default AU)
  FETCH_TRACK_INTERVAL_H     re-fetch interval for confirmed / reported / AI-phishing domains (default 2)
  FETCH_MIN_FREE_GB          write no snapshot files below this much free disk (default 10; 0 disables)
  ENRICH_TRACK_DAYS          length of the tracking window (read through cybercheck.enrich, default 30)
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import gzip
import hashlib
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import db, enrich
from ..config import settings
from ..fetch_client import FetchClient
from ..pagefeatures import PageFeatures, combine, extract, page_loaded
from ..worker import Job, JobContext

UTC = timezone.utc
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

SCREENSHOT_CAP = 8_000_000      # bytes of decoded WebP we will store (the fetcher caps the capture itself)
HTML_CAP = 2_000_000            # bytes of HTML we gzip and store
MIN_DOWN_GAP = timedelta(minutes=15)   # two failures this far apart flip live_state to 'down'
BACKOFF_H = (1, 6, 24)          # hours after fetch round 1, 2, 3; then daily
DOWN_RECHECK = timedelta(minutes=20)   # after a live domain's first failure, confirm (or clear) it soon
FAULT_RETRY = timedelta(minutes=30)    # after a round of fetcher faults only; doubles per fault in a row
FAULT_RETRY_MAX = timedelta(hours=6)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class FetcherUnavailable(Exception):
    """The fetcher went away (or started failing closed) mid-run: record nothing for this domain."""


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).isoformat() if ts else None


def parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _env_float(name: str, default: float) -> float:
    try:
        v = float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default
    return v if 0 <= v < 1e6 else default            # also rejects nan / inf


def track_days() -> int:
    """ENRICH_TRACK_DAYS, read the way enrich reads it, so both jobs use one tracking window."""
    return enrich.load_config().track_days


def is_tracked(d: dict, now: datetime | None = None, days: int | None = None) -> bool:
    """Confirmed / reported / AI-phishing domains are re-fetched often while not taken down, but only
    inside enrich's tracking window (enrich.track_end): enrich is the only job that records a takedown,
    so tracked fetching ends when enrich's hourly tracking ends."""
    end = enrich.track_end(d, track_days() if days is None else days)
    return end is not None and (now or utcnow()) < end


def next_fetch_at(d: dict, n: int, now: datetime, track_interval_h: int,
                  days: int | None = None) -> datetime:
    """When to fetch this domain next. n = completed fetch rounds (including the one just done).
    days = the tracking window (ENRICH_TRACK_DAYS when None).

    Never returns None: NULL next_fetch_at means "fetch as soon as possible" in DUE_SQL, so returning
    None near the end of the watch window would re-fetch the domain every run until watch_until.
    Past the watch window an untracked domain (or a tracked one past its tracking window) is parked at
    watch_until; DUE_SQL then excludes it until a new certificate extends watch_until or it becomes
    tracked again (then it is due at once)."""
    if is_tracked(d, now, days):
        return now + timedelta(hours=max(1, track_interval_h))
    wu = parse_ts(d.get("watch_until"))
    step = BACKOFF_H[n - 1] if 1 <= n <= len(BACKOFF_H) else 24
    t = now + timedelta(hours=step)
    if wu is not None and t >= wu:
        return max(wu, now)         # end of the watch window: no further fetch unless re-armed
    return t


DUE_SQL = """
SELECT d.id, d.registered_domain, d.hostnames, d.hostnames[1] AS hostname, d.tier, d.status, d.score,
       d.brand_id, d.dns_state, d.live_state, d.first_live_at, d.last_live_at, d.watch_until,
       d.reported_at, d.ai_verdict, d.next_fetch_at, d.fetch_state, d.first_seen, d.status_changed_at
FROM domains d
WHERE d.dns_state = 'resolves' AND d.takedown_at IS NULL
  AND d.status IN ('open', 'confirmed')
  AND (d.tier IN ('review', 'high') OR d.score >= %(min_score)s OR d.status = 'confirmed')
  AND (d.next_fetch_at IS NULL OR d.next_fetch_at <= now())
  AND (d.watch_until IS NULL OR d.watch_until > now()
       OR ((d.status = 'confirmed' OR d.reported_at IS NOT NULL OR d.ai_verdict = 'phishing')
           AND GREATEST(d.first_seen, d.reported_at, CASE WHEN d.status = 'confirmed' THEN d.status_changed_at END)
               > now() - make_interval(days => %(track_days)s)))
ORDER BY (d.next_fetch_at IS NULL) DESC,
         CASE d.tier WHEN 'high' THEN 0 WHEN 'review' THEN 1 ELSE 2 END,
         d.next_fetch_at NULLS FIRST, d.id DESC
LIMIT %(batch)s
"""

INSERT_PAGE_SQL = """
INSERT INTO pages (domain_id, url, final_url, http_status, title, egress_ip, user_agent_profile,
                   has_password_field, has_otp_field, has_card_field, form_actions, external_form_post,
                   brand_mentions, text_excerpt, features, error, retain_until)
VALUES (%(domain_id)s, %(url)s, %(final_url)s, %(http_status)s, %(title)s, %(egress_ip)s, %(profile)s,
        %(has_password)s, %(has_otp)s, %(has_card)s, %(form_actions)s, %(external_form_post)s,
        %(brand_mentions)s, %(text_excerpt)s, %(features)s, %(error)s, %(retain_until)s)
RETURNING id
"""


def _valid_hostname(h) -> str | None:
    if not isinstance(h, str):
        return None
    h = h.strip().lower().rstrip(".")
    return h if _HOSTNAME.match(h) else None


def _first_hostname(d: dict) -> str | None:
    """The first stored hostname, validated (hostnames come from CT, CZDS and bot users); else the
    registered domain. None when nothing is a plain DNS name (never build a URL from junk)."""
    hosts = d.get("hostnames") or []
    for h in [d.get("hostname"), *(hosts[:1] if isinstance(hosts, list) else [])]:
        v = _valid_hostname(h)
        if v:
            return v
    return _valid_hostname(d.get("registered_domain"))


def _decode_screenshot(b64: str | None) -> bytes | None:
    if not b64 or not isinstance(b64, str):
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > SCREENSHOT_CAP:
        return None
    return raw


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rel_under(data_dir, rel: str):
    base = data_dir.resolve()
    path = (base / rel).resolve()
    if base != path and base not in path.parents:
        raise ValueError(f"path escapes data_dir: {rel}")
    return path


def _reusable(data_dir, rel) -> bool:
    """A previous snapshot's file can be reused only if it is still on disk (retention may have
    deleted it while the domain was not being fetched)."""
    if not isinstance(rel, str) or not rel:
        return False
    try:
        return _rel_under(data_dir, rel).is_file()
    except (ValueError, OSError):
        return False


def _write_file(data_dir, rel: str, data: bytes) -> None:
    path = _rel_under(data_dir, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()                              # never leave a partial file behind
        raise


def _remove_quietly(data_dir, rel: str) -> None:
    with contextlib.suppress(OSError, ValueError):
        _rel_under(data_dir, rel).unlink()


def _free_bytes(path) -> int | None:
    """Free bytes on the filesystem holding path (or its nearest existing parent); None if unknown."""
    p = Path(path)
    for cand in (p, *p.parents):
        try:
            return shutil.disk_usage(cand).free
        except FileNotFoundError:
            continue
        except OSError:
            return None
    return None


class Store:
    """Persists one fetch round for one domain: page rows, files, the domain update and events."""

    def __init__(self, data_dir, retain_days: int, min_free_gb: float | None = None):
        self.data_dir = data_dir
        self.retain_days = retain_days
        gb = _env_float("FETCH_MIN_FREE_GB", 10.0) if min_free_gb is None else min_free_gb
        self.min_free_bytes = int(max(0.0, gb) * 1024 ** 3)
        self.low_disk = False                         # set when files were skipped for lack of space

    def disk_ok(self) -> bool:
        """Enough free space to write snapshot files? (Blocking: call in a thread.) The data directory
        may share its filesystem with Postgres and other services on the host, so a page that serves
        noise on every load must not be able to fill it."""
        if self.min_free_bytes <= 0:
            return True
        free = _free_bytes(self.data_dir)
        if free is None or free >= self.min_free_bytes:
            return True
        self.low_disk = True
        return False

    async def save_page(self, conn, domain: dict, profile: str, result: dict, feats: PageFeatures,
                        state: dict, round_files: list | None = None) -> int:
        """Insert one pages row and write its files. round_files, if given, collects the paths this call
        wrote, so the caller can remove them if the rest of the round fails (its transaction rolls back)."""
        now = utcnow()
        loaded = page_loaded(result)
        screenshot = _decode_screenshot(result.get("screenshot_webp_b64"))
        html = result.get("html")
        raw_html = html.encode("utf-8", "replace")[:HTML_CAP] if isinstance(html, str) and html else None
        files_ok = True
        if screenshot or raw_html:
            files_ok = await asyncio.to_thread(self.disk_ok)
        chain = result.get("redirect_chain")
        features = {**feats.as_dict(),
                    "redirect_chain": [_clip(u, 2000) for u in (chain if isinstance(chain, list) else [])[:20]],
                    "egress_country": _clip(result.get("egress_country"), 8),
                    "timings": result.get("timings") if isinstance(result.get("timings"), dict) else None,
                    "loaded": loaded, "profile": profile}
        if not files_ok:
            features["files_skipped"] = "low_disk"
        row = await (await conn.execute(INSERT_PAGE_SQL, {
            "domain_id": domain["id"],
            "url": str(result.get("url") or "")[:2000] or None,
            "final_url": str(result.get("final_url") or "")[:2000] or None,
            "http_status": _http_status(result.get("http_status")),
            "title": _clip(result.get("title"), 500),
            "egress_ip": _clip(result.get("egress_ip"), 64),
            "profile": profile,
            "has_password": feats.has_password_field,
            "has_otp": feats.has_otp_field,
            "has_card": feats.has_card_field,
            "form_actions": feats.form_actions,
            "external_form_post": feats.external_form_post,
            "brand_mentions": feats.brand_mentions,
            "text_excerpt": _clip(result.get("text_excerpt"), 20000),
            "features": db.jsonb(features),
            # pages.error IS NULL means "the page loaded" for every reader (judge, reports, dashboard), so a
            # snapshot that did not load always carries a reason, even when the fetcher sent none (HTTP 403
            # "Account suspended", 5xx, an empty response).
            "error": None if loaded else (_clip(result.get("error"), 500) or _not_loaded_reason(result)),
            "retain_until": now + timedelta(days=self.retain_days),
        })).fetchone()
        page_id = row["id"]

        shots = state.get("shots")
        if not isinstance(shots, dict):
            shots = state["shots"] = {}
        htmls = state.get("htmls")
        if not isinstance(htmls, dict):
            htmls = state["htmls"] = {}

        # Files are written after the row exists (their names carry its id) and recorded right after.
        # If anything in between fails (disk full, I/O error, cancellation), the files this call wrote
        # are removed again: retention only finds files through pages rows, so an unrecorded file
        # would stay on disk for good.
        written: list[str] = []
        shot_path = shot_sha = html_path = html_sha = None
        try:
            if screenshot:
                shot_sha = _sha(screenshot)
                prev = shots.get(profile) if isinstance(shots.get(profile), dict) else None
                if prev and prev.get("sha") == shot_sha and await asyncio.to_thread(_reusable, self.data_dir, prev.get("path")):
                    shot_path = prev["path"]                   # unchanged: reuse the previous file
                elif files_ok:
                    shot_path = f"screenshots/{domain['id']}/{page_id}-{profile}.webp"
                    await asyncio.to_thread(_write_file, self.data_dir, shot_path, screenshot)
                    written.append(shot_path)

            if raw_html:
                html_sha = _sha(raw_html)
                prev = htmls.get(profile) if isinstance(htmls.get(profile), dict) else None
                if prev and prev.get("sha") == html_sha and await asyncio.to_thread(_reusable, self.data_dir, prev.get("path")):
                    html_path = prev["path"]
                elif files_ok:
                    html_path = f"html/{domain['id']}/{page_id}-{profile}.html.gz"
                    await asyncio.to_thread(_write_file, self.data_dir, html_path,
                                            gzip.compress(raw_html, compresslevel=6))
                    written.append(html_path)

            if shot_path or html_path:
                await conn.execute(
                    "UPDATE pages SET screenshot_path = %s, screenshot_sha256 = %s, html_path = %s, html_sha256 = %s "
                    "WHERE id = %s", (shot_path, shot_sha if shot_path else None,
                                      html_path, html_sha if html_path else None, page_id))
        except BaseException:
            for rel in written:
                _remove_quietly(self.data_dir, rel)
            raise

        if round_files is not None:
            round_files.extend(written)
        if shot_path:
            shots[profile] = {"sha": shot_sha, "path": shot_path}
        if html_path:
            htmls[profile] = {"sha": html_sha, "path": html_path}
        return page_id


def _int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _http_status(v):
    """An HTTP status code, or None: pages.http_status is an int column, and a value past its range would
    make the INSERT (and so every save of the domain) fail."""
    n = _int(v)
    return n if n is not None and 0 < n < 1000 else None


def _not_loaded_reason(result: dict) -> str:
    status = result.get("http_status")
    if isinstance(status, int) and not isinstance(status, bool) and 0 < status < 1000:
        return f"page did not load (HTTP {status})"
    return "page did not load (empty response)"


def _clip(v, n: int):
    if v is None:
        return None
    s = str(v)
    return s[:n] or None


def apply_live_state(domain: dict, state: dict, loaded: bool, now: datetime) -> tuple[dict, list]:
    """Return (domain-column updates, events) for the live_state transition after one round.

    'live' as soon as a page loads with content. 'down' only after two consecutive failed fetches at
    least MIN_DOWN_GAP apart, and only for a domain that had been live (so a never-live domain is not
    reported as taken down, and one blip does not flip a live domain)."""
    cols: dict = {}
    events: list = []
    if loaded:
        state.pop("fail_since", None)
        state.pop("fail_count", None)
        cols["last_live_at"] = now
        if domain.get("first_live_at") is None and not state.get("_first_live"):
            cols["first_live_at"] = now
        if domain.get("live_state") != "live":
            cols["live_state"] = "live"
            events.append(("went_live", {"from": domain.get("live_state")}))
        return cols, events

    # failed fetch
    fail_since = parse_ts(state.get("fail_since"))
    if fail_since is None:
        state["fail_since"] = iso(now)
        state["fail_count"] = 1
        return cols, events
    state["fail_count"] = int(state.get("fail_count") or 1) + 1
    was_live = domain.get("live_state") == "live" or domain.get("first_live_at") is not None
    if was_live and domain.get("live_state") != "down" and (now - fail_since) >= MIN_DOWN_GAP:
        cols["live_state"] = "down"
        events.append(("page_down", {"failures": state["fail_count"],
                                     "first_failure": state.get("fail_since")}))
    return cols, events


DOMAIN_UPDATE_COLS = {"live_state", "first_live_at", "last_live_at", "page_score"}


async def _update_domain(conn, domain_id: int, cols: dict, next_at: datetime | None, state: dict,
                         events: list) -> None:
    sets, params = [], []
    for col, value in cols.items():
        if col not in DOMAIN_UPDATE_COLS:
            raise ValueError(f"fetch may not write domains.{col}")
        sets.append(f"{col} = %s")
        params.append(value)
    sets += ["next_fetch_at = %s", "fetch_state = %s"]
    params += [next_at, db.jsonb(state)]
    async with conn.transaction():
        await conn.execute(f"UPDATE domains SET {', '.join(sets)} WHERE id = %s", params + [domain_id])
        for kind, detail in events:
            await db.add_event(conn, domain_id, kind, detail)


def fetcher_fault(result: dict | None) -> bool:
    """The fetcher itself failed (browser crash, hard timeout, internal error): says nothing about
    whether the page is up, so it must not count towards live_state 'down'."""
    return bool(result) and bool(result.get("fetcher_error"))


async def _fetch_one_profile(client: FetchClient, hostname: str, profile: str) -> dict:
    """Fetch https first, fall back to http. Returns the result dict (ok=False on a page failure).
    Raises FetcherUnavailable if the fetcher cannot be reached or is failing closed (no VPN), so a
    VPN drop mid-run is never recorded as the page being down."""
    last: dict | None = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        result = await client.fetch(url, profile)
        if result is None:
            raise FetcherUnavailable(url)
        if page_loaded(result) or fetcher_fault(result):
            return result
        last = result
    return last  # type: ignore[return-value]


async def process_domain(ctx: JobContext, client: FetchClient, store: Store, domain: dict) -> dict:
    now = utcnow()
    state = dict(domain.get("fetch_state") or {})
    n_prev = int(state.get("n") or 0)
    first_round = n_prev == 0
    hostname = _first_hostname(domain)
    if not hostname:
        raise ValueError(f"no valid hostname for domain {domain.get('id')}")
    profiles = ["mobile", "desktop"] if first_round else ["mobile"]

    results: list[tuple[str, dict]] = []
    for profile in profiles:
        result = await _fetch_one_profile(client, hostname, profile)   # may raise FetcherUnavailable
        results.append((profile, result))

    try:
        from ..scoring import default_watchlist
        watchlist = default_watchlist()
    except Exception:
        watchlist = None

    feats_list: list[PageFeatures] = []
    any_loaded = any(page_loaded(r) for _, r in results)
    # Only real page failures count towards 'down'; a round where every snapshot was a fetcher fault
    # leaves live_state (and the failure streak) untouched.
    conclusive = any_loaded or any(not fetcher_fault(r) for _, r in results)
    p = await db.pool()
    # One transaction per round: if a later snapshot or the domain update fails, the rows already
    # inserted for this round roll back with it and the files written for them are removed. Otherwise
    # every retry (30 min later, a full round again) would leave rows the domain never accounted for:
    # loaded-looking snapshots without files, which the judge picks up. A kill before the commit leaves
    # only files, which the retention job's orphan sweep removes.
    round_files: list[str] = []
    async with p.connection() as conn, conn.transaction():
        try:
            for profile, result in results:
                feats = extract(result, domain, watchlist)
                feats_list.append(feats)
                await store.save_page(conn, domain, profile, result, feats, state, round_files)

            if conclusive:
                state["n"] = n_prev + 1
                state.pop("faults", None)
                live_cols, events = apply_live_state(domain, state, any_loaded, now)
                next_at = next_fetch_at(domain, state["n"], now, _env_int("FETCH_TRACK_INTERVAL_H", 2),
                                        track_days())
            else:
                # Every snapshot was a fetcher fault (dead browser, crash, hard timeout, a request the
                # healthy fetcher could not answer): nothing was learnt about the page, so do not use up a
                # schedule step (n stays; a first round keeps its desktop profile). Retry after
                # FAULT_RETRY, doubling per fault in a row, so a page that always breaks the fetcher is
                # backed off instead of being retried every run.
                faults = max(0, _int(state.get("faults")) or 0) + 1
                state["faults"] = faults
                live_cols, events = {}, []
                next_at = now + min(FAULT_RETRY * 2 ** min(faults - 1, 8), FAULT_RETRY_MAX)
            cols = dict(live_cols)
            if any_loaded:
                cols["page_score"] = combine(feats_list)
            was_live = domain.get("live_state") == "live" and cols.get("live_state") != "down"
            if not any_loaded and conclusive and was_live:
                # A live page just failed: check again soon so 'down' (a takedown signal for enrich) is
                # confirmed or cleared quickly rather than a day later.
                next_at = min(next_at, now + DOWN_RECHECK)
            await _update_domain(conn, domain["id"], cols, next_at, state, events)
        except BaseException:
            for rel in round_files:
                _remove_quietly(store.data_dir, rel)
            raise

    return {"id": domain["id"], "domain": domain.get("registered_domain"), "loaded": any_loaded,
            "profiles": [pr for pr, _ in results],
            "page_score": cols.get("page_score"), "events": [e[0] for e in events]}


async def postpone(domain_id: int, minutes: int = 30) -> None:
    try:
        p = await db.pool()
        async with p.connection() as conn:
            await conn.execute(
                "UPDATE domains SET next_fetch_at = now() + make_interval(mins => %s) "
                "WHERE id = %s AND (next_fetch_at IS NULL OR next_fetch_at <= now())", (minutes, domain_id))
    except Exception:
        pass


async def run_once(ctx: JobContext) -> dict:
    s = settings()
    result = {"due": 0, "fetched": 0, "live": 0, "failed": 0}
    async with FetchClient() as client:
        if not client.configured:
            return {"skipped": "fetcher not configured"}
        health = await client.health()
        if not health or not health.get("ok"):
            ctx.log.debug("fetcher unavailable: %s", health)
            out = {"skipped": "fetcher unavailable"}
            if health and health.get("http_status") == 401:
                out["reason"] = "fetcher rejected FETCHER_TOKEN"
            return out
        result["egress_ip"] = health.get("egress_ip")
        result["egress_country"] = health.get("egress_country")

        p = await db.pool()
        async with p.connection() as conn:
            # max(1, ...): Postgres refuses a negative LIMIT, which would fail every run
            rows = await (await conn.execute(DUE_SQL, {
                "min_score": s.fetch_min_score, "batch": max(1, _env_int("FETCH_BATCH", 20)),
                "track_days": track_days()})).fetchall()
        result["due"] = len(rows)
        if not rows:
            return result

        store = Store(s.data_dir, s.screenshot_retention_days)
        sem = asyncio.Semaphore(max(1, s.fetch_concurrency))
        gone = asyncio.Event()          # the fetcher went away mid-run: stop, change nothing more

        async def one(domain: dict) -> None:
            async with sem:
                if gone.is_set():
                    return
                try:
                    out = await process_domain(ctx, client, store, domain)
                except FetcherUnavailable:
                    gone.set()          # domain left exactly as it was; it is still due next run
                    return
                except Exception as e:
                    result["failed"] += 1
                    ctx.log.warning("fetch %s failed: %s: %s", domain.get("registered_domain"),
                                    type(e).__name__, e, exc_info=True)
                    await postpone(domain["id"])
                    return
                result["fetched"] += 1
                if out["loaded"]:
                    result["live"] += 1

        await asyncio.gather(*(one(d) for d in rows))
        if gone.is_set():
            result["stopped"] = "fetcher became unavailable"
        if store.low_disk:
            result["low_disk"] = True
            ctx.log.warning("less than FETCH_MIN_FREE_GB free under %s: snapshot files were not written",
                            s.data_dir)
    return result


JOB = Job(name="fetch", interval=30, run=run_once, initial_delay=20)
