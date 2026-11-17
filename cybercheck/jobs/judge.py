"""Judge job: AI page checks, combined confidence (final_score), optional triage of domains with no page.

Each run:
1. Pages not yet judged, for open review/high domains, newest first with credential-collecting pages
   first: one page per domain per run. A snapshot whose final URL is on a watchlist brand's official
   site (another domain) is not sent to the AI: it shows the real site, so there is nothing to judge
   about the domain that redirected there (cybercheck.confidence treats it as a weak benign signal).
   A page identical to an already-judged snapshot of the same domain (same HTML and screenshot hashes,
   and credential fields present in both or in neither) reuses that verdict. A domain with an AI
   attempt of any kind in the last AI_JUDGE_COOLDOWN_H hours, failed ones (refusal, invalid output,
   repeated timeouts) included, is not judged again unless the new page collects credentials and the earlier one did not, or the
   earlier verdict was parked/error and the content changed (new HTML, and not the same screenshot).
   Verdicts go to pages.ai_result and to domains.ai_verdict / ai_confidence / ai_brand, with an
   'ai_verdict' event.
2. final_score is recomputed (cybercheck.confidence) for every domain whose inputs changed: domain
   score, page_score, latest page, AI verdict, or the scoring rules / their settings
   (confidence.basis_tag). This runs even when AI is unavailable.
3. Optional text-only triage (<= 25 domains per call, <= AI_TRIAGE_BUDGET_FRACTION of the daily
   budget) of open review/high domains that still have no page AI_TRIAGE_AFTER_H hours after first sight.
"""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone

from .. import db
from ..ai import api
from ..confidence import basis_tag, compute_final_score, final_host, host_under, official_brand
from ..config import settings
from ..worker import Job, JobContext

RUN_LOCK_KEY = 7_303_000_031   # pg_try_advisory_lock: one judge run at a time across worker processes
MAX_SCREENSHOT_BYTES = 15_000_000


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    return default if not v else v in ("1", "true", "yes", "on")


PENDING_SQL = """
SELECT p.id, p.domain_id, d.registered_domain, p.fetched_at, p.url, p.final_url, p.http_status, p.title,
       p.user_agent_profile,
       p.has_password_field, p.has_otp_field, p.has_card_field, p.form_actions, p.external_form_post,
       p.brand_mentions, p.text_excerpt, p.screenshot_path, p.screenshot_sha256, p.html_sha256,
       (COALESCE(p.has_password_field, false) OR COALESCE(p.has_otp_field, false)
        OR COALESCE(p.has_card_field, false)) AS creds
FROM pages p JOIN domains d ON d.id = p.domain_id
WHERE p.ai_judged_at IS NULL AND p.error IS NULL
  AND p.fetched_at > now() - make_interval(hours => %s::int)
  AND d.status = 'open' AND d.tier IN ('review', 'high')
ORDER BY creds DESC, p.fetched_at DESC, p.id DESC
LIMIT %s
"""
# p.id breaks ties: the fetch job inserts a round's snapshots in one transaction, so they share fetched_at
# (now()); within a round the later insert (higher id) counts as the newer snapshot, here and below.

# Earlier AI attempts for the domain: verdicts (judged or reused) and failed attempts (refusal,
# non-retryable error, repeated timeouts: {'error': ...}; invalid output: {'verdict': 'error', 'invalid': true}).
# Skip marks ({'skipped': ...}) are not attempts.
PREVIOUS_SQL = """
SELECT id, fetched_at, ai_judged_at, ai_result, screenshot_sha256, html_sha256,
       (COALESCE(has_password_field, false) OR COALESCE(has_otp_field, false)
        OR COALESCE(has_card_field, false)) AS creds
FROM pages
WHERE domain_id = %s AND id <> %s AND ai_judged_at IS NOT NULL
  AND (ai_result ? 'verdict' OR ai_result ? 'error')
ORDER BY ai_judged_at DESC
LIMIT 10
"""

DOMAIN_SQL = """
SELECT id, registered_domain, unicode_domain, brand_id, score, tier, reasons, asn, as_name, ip_country,
       registrar, registered_at, ai_verdict
FROM domains WHERE id = %s
"""

# Only update the domain's AI columns from the newest page with a verdict (judged or reused). A newer
# 'error' verdict (the page could not be judged) doesn't hold back a real verdict, just as it never
# replaces one (store_verdict). Newer means (fetched_at, id): a round's snapshots share fetched_at.
# %(changed_only)s: also require that the values differ (used for reused verdicts, so an event is
# written only when the domain's verdict actually changes).
SET_DOMAIN_AI_SQL = """
UPDATE domains SET ai_verdict = %(verdict)s, ai_confidence = %(confidence)s, ai_brand = %(brand)s
WHERE id = %(domain_id)s AND NOT EXISTS (
    SELECT 1 FROM pages q WHERE q.domain_id = %(domain_id)s AND q.id <> %(page_id)s
      AND q.ai_judged_at IS NOT NULL AND q.ai_result ? 'verdict' AND NOT q.ai_result ? 'invalid'
      AND q.ai_result ->> 'verdict' <> 'error'
      AND (q.fetched_at, q.id) > (%(fetched_at)s::timestamptz, %(page_id)s::bigint))
  AND (NOT %(changed_only)s OR ai_verdict IS DISTINCT FROM %(verdict)s
       OR ai_confidence IS DISTINCT FROM %(confidence)s::real OR ai_brand IS DISTINCT FROM %(brand)s)
RETURNING id
"""

# %s: confidence.basis_tag() (rule version + settings), so a rule or settings change recomputes stored scores
BASIS = ("concat_ws('|', %s::text, d.score, COALESCE(d.brand_id, ''), COALESCE(d.page_score::text, ''), "
         "COALESCE(lp.id::text, ''), COALESCE(d.ai_verdict, ''), COALESCE(d.ai_confidence::text, ''), "
         "COALESCE(d.ai_brand, ''))")

# Page evidence comes from the latest fetch round: the fetcher takes desktop and mobile snapshots
# together and kits often show the form to only one of them, so among the loaded snapshots taken
# within SNAPSHOT_ROUND of the newest one, a credential-collecting snapshot whose final URL is on the
# domain itself wins, then an identity-collecting one on the domain (it keeps the benign floor), then any
# snapshot on the domain, then the rest (confidence.snapshot_on_domain is the authority; this only picks
# which snapshot it gets).
SNAPSHOT_ROUND = "15 minutes"
_FINAL_HOST_SQL = ("rtrim(lower(substring(p.final_url from "
                   "'^(?:[Bb][Ll][Oo][Bb]:)?[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#]*@)?([^/?#:]+)')), '.')")
_ON_DOMAIN_SQL = (f"COALESCE({_FINAL_HOST_SQL} = d.registered_domain OR "
                  f"right({_FINAL_HOST_SQL}, length(d.registered_domain) + 1) = '.' || d.registered_domain, false)")
_CREDS_SQL = ("(COALESCE(p.has_password_field, false) OR COALESCE(p.has_otp_field, false) "
              "OR COALESCE(p.has_card_field, false))")
_IDENTITY_SQL = "COALESCE(p.features -> 'has_identity_field' = 'true'::jsonb, false)"

FINAL_CANDIDATES_SQL = f"""
SELECT * FROM (
    SELECT d.id, d.registered_domain, d.score, d.tier, d.brand_id, d.page_score, d.ai_verdict,
           d.ai_confidence, d.ai_brand, d.final_score, d.final_basis, lp.id AS page_id, {BASIS} AS basis
    FROM domains d
    LEFT JOIN LATERAL (
        SELECT id, fetched_at, (error IS NULL) AS ok FROM pages WHERE domain_id = d.id
        ORDER BY (error IS NULL) DESC, fetched_at DESC, id DESC LIMIT 1
    ) lp0 ON true
    LEFT JOIN LATERAL (
        SELECT p.id FROM pages p
        WHERE p.domain_id = d.id
          AND (p.id = lp0.id OR (lp0.ok AND p.error IS NULL
                                 AND p.fetched_at >= lp0.fetched_at - interval '{SNAPSHOT_ROUND}'))
        ORDER BY ({_CREDS_SQL} AND {_ON_DOMAIN_SQL}) DESC, ({_IDENTITY_SQL} AND {_ON_DOMAIN_SQL}) DESC,
                 {_ON_DOMAIN_SQL} DESC, {_CREDS_SQL} DESC, p.fetched_at DESC, p.id DESC
        LIMIT 1
    ) lp ON true
    WHERE (d.tier IN ('review', 'high') OR d.page_score IS NOT NULL OR d.ai_verdict IS NOT NULL)
      AND (d.final_basis IS NULL OR d.watch_until IS NULL OR d.watch_until > now() - interval '7 days'
           OR d.status = 'confirmed' OR d.reported_at IS NOT NULL)
) x
WHERE x.final_basis IS DISTINCT FROM x.basis
ORDER BY x.id DESC
LIMIT %s
"""

# has_identity_field is not a column: pagefeatures stores it in the features JSON
PAGES_BY_ID_SQL = """
SELECT id, url, final_url, http_status, error, has_password_field, has_otp_field, has_card_field,
       COALESCE(features -> 'has_identity_field' = 'true'::jsonb, false) AS has_identity_field,
       form_actions, external_form_post, brand_mentions
FROM pages WHERE id = ANY(%s)
"""

TRIAGE_SQL = """
SELECT d.id, d.registered_domain, d.unicode_domain, d.hostnames, d.brand_id, d.score, d.dns_state,
       d.registrar, d.registered_at, d.first_seen
FROM domains d
WHERE d.status = 'open' AND d.tier IN ('review', 'high') AND d.ai_triaged_at IS NULL
  AND d.first_seen < now() - make_interval(hours => %s::int)
  AND d.first_seen > now() - interval '14 days'
  AND NOT EXISTS (SELECT 1 FROM pages p WHERE p.domain_id = d.id)
ORDER BY d.score DESC, d.first_seen DESC
LIMIT %s
"""


async def _mark_page(conn, page_id: int, result: dict) -> None:
    await conn.execute("UPDATE pages SET ai_judged_at = now(), ai_result = %s WHERE id = %s",
                       (db.jsonb(result), page_id))


def _read_screenshot(rel_path: str | None) -> bytes | None:
    if not rel_path:
        return None
    base = settings().data_dir.resolve()
    path = (base / rel_path).resolve()
    if base not in path.parents or not path.is_file() or path.stat().st_size > MAX_SCREENSHOT_BYTES:
        return None
    return path.read_bytes()


async def load_screenshot(rel_path: str | None) -> bytes | None:
    try:
        return await asyncio.to_thread(_read_screenshot, rel_path)
    except OSError:
        return None


def _aware(ts):
    if isinstance(ts, datetime) and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def _failed(q: dict) -> bool:
    """An attempt that produced no usable verdict (refusal, API error, timeouts, invalid output)."""
    r = q.get("ai_result") or {}
    return bool(r.get("invalid")) or "verdict" not in r


def _same_page(page: dict, q: dict) -> bool:
    """Same main-frame HTML and the same screenshot (or no screenshot in both)."""
    html = page.get("html_sha256")
    return bool(html) and q.get("html_sha256") == html \
        and page.get("screenshot_sha256") == q.get("screenshot_sha256")


def _content_changed(page: dict, last: dict) -> bool:
    shot = page.get("screenshot_sha256")
    if shot and shot == last.get("screenshot_sha256"):
        return False       # looks the same: a nonce or a rotating ad in the HTML is not worth another call
    return page.get("html_sha256") != last.get("html_sha256")


def choose_action(page: dict, previous: list[dict], cooldown: timedelta, now: datetime | None = None) -> tuple[str, dict | None]:
    """('reuse', prev) | ('skip', prev) | ('judge', None) for one pending page. previous: the domain's
    earlier attempts, newest first, verdicts and failed attempts alike."""
    now = now or datetime.now(timezone.utc)
    creds = bool(page.get("creds"))
    for q in previous:
        if _failed(q) or bool(q.get("creds")) != creds:
            continue       # nothing to reuse, or credential fields appeared / went away since
        if _same_page(page, q) and (q.get("ai_result") or {}).get("verdict") != "error":
            return "reuse", q
    if not previous:
        return "judge", None
    last = previous[0]     # the newest attempt of any kind: the cooldown counts failed calls too
    recent = _aware(last.get("ai_judged_at")) and now - _aware(last["ai_judged_at"]) < cooldown
    if not recent:
        return "judge", None
    if creds and not last.get("creds"):
        return "judge", None
    verdict = None if _failed(last) else (last.get("ai_result") or {}).get("verdict")
    if verdict in ("parked", "error") and _content_changed(page, last):
        return "judge", None
    return "skip", last


def official_redirect(page: dict) -> str | None:
    """Brand id when the browser ended this snapshot on a brand's official site, off the domain itself."""
    host = final_host(page)
    if not host or host_under(host, page.get("registered_domain")):
        return None
    return official_brand(host)


async def store_verdict(conn, domain: dict, page: dict, result: dict) -> bool:
    """Save a verdict on the page and (when it is the newest) on the domain. Returns True if the
    domain columns were updated."""
    await _mark_page(conn, page["id"], result)
    if result.get("invalid"):
        return False
    if result["verdict"] == "error" and domain.get("ai_verdict") not in (None, "error"):
        return False   # an error page doesn't wipe out an earlier real verdict
    row = await _set_domain_ai(conn, domain["id"], page, result, changed_only=False)
    await db.add_event(conn, domain["id"], "ai_verdict", {
        "page_id": page["id"], "verdict": result["verdict"], "confidence": result["confidence"],
        "brand": result["imitated_brand"], "asks_for": result["asks_for"],
        "explanation": result["explanation"], "ai_call_id": result.get("ai_call_id")})
    return row is not None


async def _set_domain_ai(conn, domain_id: int, page: dict, result: dict, *, changed_only: bool):
    return await (await conn.execute(SET_DOMAIN_AI_SQL, {
        "verdict": result["verdict"], "confidence": result.get("confidence"),
        "brand": result.get("imitated_brand"), "domain_id": domain_id, "page_id": page["id"],
        "fetched_at": page["fetched_at"], "changed_only": changed_only})).fetchone()


async def store_reused(conn, page: dict, prev: dict) -> None:
    """Copy a verdict from an identical earlier snapshot; the domain's AI columns follow it when this
    is the newest page (e.g. a site that went back to an earlier phishing page)."""
    kept = {k: v for k, v in (prev.get("ai_result") or {}).items() if k not in ("reused_from_page", "skipped")}
    result = {**kept, "reused_from_page": prev["id"]}
    await _mark_page(conn, page["id"], result)
    if result.get("verdict") in (None, "error"):
        return
    if await _set_domain_ai(conn, page["domain_id"], page, result, changed_only=True):
        await db.add_event(conn, page["domain_id"], "ai_verdict", {
            "page_id": page["id"], "verdict": result["verdict"], "confidence": result.get("confidence"),
            "brand": result.get("imitated_brand"), "asks_for": result.get("asks_for"),
            "explanation": result.get("explanation"), "ai_call_id": result.get("ai_call_id"),
            "reused_from_page": prev["id"]})


async def judge_pages(conn, ctx: JobContext) -> dict:
    per_run = _env_int("AI_JUDGE_PER_RUN", 10)
    max_age_h = _env_int("AI_JUDGE_MAX_AGE_H", 72)
    cooldown = timedelta(hours=_env_int("AI_JUDGE_COOLDOWN_H", 12))
    attempts: dict = ctx.state.setdefault("attempts", {})
    if len(attempts) > 1000:
        attempts.clear()
    counts = {"judged": 0, "reused": 0, "skipped": 0, "failed": 0}
    rows = await (await conn.execute(PENDING_SQL, (max_age_h, per_run * 4))).fetchall()
    seen: set[int] = set()
    for page in rows:
        if counts["judged"] + counts["failed"] >= per_run:
            break
        if page["domain_id"] in seen:
            continue
        seen.add(page["domain_id"])
        brand = official_redirect(page)
        if brand:
            await _mark_page(conn, page["id"], {"skipped": "redirected to an official brand site",
                                                "final_host": final_host(page), "brand": brand})
            counts["skipped"] += 1
            continue
        previous = await (await conn.execute(PREVIOUS_SQL, (page["domain_id"], page["id"]))).fetchall()
        action, prev = choose_action(page, previous, cooldown)
        if action == "reuse":
            async with conn.transaction():   # page mark, domain columns and event together (free to retry)
                await store_reused(conn, page, prev)
            counts["reused"] += 1
            continue
        if action == "skip":
            await _mark_page(conn, page["id"], {"skipped": "domain judged recently", "latest_judged_page": prev["id"]})
            counts["skipped"] += 1
            continue

        domain = await (await conn.execute(DOMAIN_SQL, (page["domain_id"],))).fetchone()
        if not domain:
            continue
        shot = await load_screenshot(page.get("screenshot_path"))
        result, out = await api.judge_page_with_status(conn, dict(domain), dict(page), shot)
        if result is not None:
            try:
                async with conn.transaction():
                    await store_verdict(conn, domain, page, result)
            except Exception as e:
                # The call was paid for: a page left pending would be paid for again on every run.
                ctx.log.exception("could not store the AI verdict for page %s", page["id"])
                await _mark_page(conn, page["id"], {"error": f"could not store the verdict: {type(e).__name__}",
                                                    "ai_call_id": result.get("ai_call_id")})
                counts["failed"] += 1
                continue
            counts["judged" if not result.get("invalid") else "failed"] += 1
            continue
        if out.status in ("unavailable", "over_budget"):
            counts["stopped"] = out.error
            break
        if out.call_id is None:
            # no API request was made (e.g. the budget check itself failed): not the page's fault
            counts["stopped"] = out.error or out.status
            break
        if out.status == "api_error" and out.retryable:
            # rate limits and overload say nothing about the page: they don't count towards giving up
            n = attempts.get(page["id"], 0) + (0 if out.http_status in (429, 529) else 1)
            attempts[page["id"]] = n
            if n >= 3:
                attempts.pop(page["id"], None)
                await _mark_page(conn, page["id"], {"error": out.error, "attempts": n, "ai_call_id": out.call_id})
            counts["failed"] += 1
            counts["stopped"] = f"API error, backing off: {out.error}"
            break   # rate limit / overload / network: try again next run
        # refusal, non-retryable API error, unexpected error: don't pay for this page again
        err = {"error": out.status if out.status == "refusal" else out.error, "ai_call_id": out.call_id}
        if out.category:
            err["category"] = out.category
        await _mark_page(conn, page["id"], err)
        counts["failed"] += 1
    return counts


async def recompute_final_scores(conn, limit: int | None = None) -> int:
    limit = limit or _env_int("FINAL_SCORE_BATCH", 500)
    rows = await (await conn.execute(FINAL_CANDIDATES_SQL, (basis_tag(), limit))).fetchall()
    if not rows:
        return 0
    page_ids = [r["page_id"] for r in rows if r["page_id"] is not None]
    pages = {}
    if page_ids:
        for p in await (await conn.execute(PAGES_BY_ID_SQL, (page_ids,))).fetchall():
            pages[p["id"]] = p
    for r in rows:
        page = pages.get(r["page_id"]) if r["page_id"] is not None else None
        ai = {"verdict": r["ai_verdict"], "confidence": r["ai_confidence"], "imitated_brand": r["ai_brand"]} \
            if r["ai_verdict"] else None
        score, reasons = compute_final_score(dict(r), dict(page) if page else None, ai)
        await conn.execute(
            "UPDATE domains SET final_score = %s, final_reasons = %s, final_score_at = now(), final_basis = %s "
            "WHERE id = %s", (score, db.jsonb(reasons), r["basis"], r["id"]))
        old = r["final_score"]
        if page is not None and (old is None or abs(score - old) >= 10):
            await db.add_event(conn, r["id"], "final_score", {"final_score": score, "previous": old,
                                                               "page_id": r["page_id"], "ai_verdict": r["ai_verdict"]})
    return len(rows)


async def triage(conn, ctx: JobContext) -> dict:
    after_h = _env_int("AI_TRIAGE_AFTER_H", 2)
    rows = await (await conn.execute(TRIAGE_SQL, (after_h, api.TRIAGE_BATCH))).fetchall()
    if not rows:
        return {"triaged": 0}
    domains = [dict(r) for r in rows]
    items, out = await api.triage_domains_with_status(conn, domains)
    if items:
        for it in items:
            await conn.execute("UPDATE domains SET ai_triage = %s, ai_triaged_at = now() WHERE id = %s",
                               (db.jsonb(it), it["domain_id"]))
            await db.add_event(conn, it["domain_id"], "ai_triage", it)
        return {"triaged": len(items)}
    if out is not None and out.status in ("refusal", "invalid"):
        for d in domains:   # don't pay for the same batch again
            await conn.execute("UPDATE domains SET ai_triage = %s, ai_triaged_at = now() WHERE id = %s",
                               (db.jsonb({"error": out.error, "ai_call_id": out.call_id}), d["id"]))
    return {"triaged": 0, "triage_error": out.error if out else None}


async def run_once(ctx: JobContext) -> dict:
    result: dict = {}
    p = await ctx.pool()
    async with p.connection() as conn:
        got = await (await conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (RUN_LOCK_KEY,))).fetchone()
        if not got or not got["ok"]:
            return {"skipped": "another judge run is in progress"}
        try:
            await conn.execute(
                "UPDATE ai_calls SET status = 'abandoned', error = 'process ended before the call finished' "
                "WHERE status = 'pending' AND at < now() - interval '30 minutes'")
            status = await api.budget_status(conn)
            result["ai"] = status["reason"]
            if status["available"]:
                try:
                    result.update(await judge_pages(conn, ctx))
                except Exception as e:
                    ctx.log.exception("page judging failed")
                    result["judge_error"] = f"{type(e).__name__}: {e}"[:300]
            try:
                result["final_scores"] = await recompute_final_scores(conn)
            except Exception as e:
                ctx.log.exception("final score recompute failed")
                result["final_error"] = f"{type(e).__name__}: {e}"[:300]
            if status["available"] and _env_bool("AI_TRIAGE_ENABLED", True):
                due = ctx.state.get("triage_at", 0.0)
                if time.monotonic() >= due:
                    ctx.state["triage_at"] = time.monotonic() + 60 * _env_int("AI_TRIAGE_INTERVAL_MIN", 15)
                    try:
                        result.update(await triage(conn, ctx))
                    except Exception as e:
                        ctx.log.exception("domain triage failed")
                        result["triage_error"] = f"{type(e).__name__}: {e}"[:300]
        finally:
            try:
                await conn.execute("SELECT pg_advisory_unlock(%s)", (RUN_LOCK_KEY,))
            except Exception:
                ctx.log.exception("could not release the judge run lock")
    return result


JOB = Job(name="judge", interval=60, run=run_once, initial_delay=20)
