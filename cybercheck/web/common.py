"""Shared helpers for dashboard pages (core and module pages_<name>.py files)."""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates

from .. import db
from ..config import settings

HERE = Path(__file__).resolve().parent
_log = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(HERE / "templates"))


def _ago(ts) -> str:
    if ts is None:
        return "-"
    if isinstance(ts, str):             # job status times are stored as ISO text in kv
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    secs = (datetime.now(timezone.utc) - ts).total_seconds()
    if secs < 60:
        return f"{int(secs)}s ago"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def _iso(ts) -> str:
    """A timestamp for <time datetime="...">: ISO 8601 with offset ('' for None; strings pass through)."""
    if ts is None:
        return ""
    if isinstance(ts, str):
        return ts
    try:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    except AttributeError:
        return str(ts)


def _utc(ts, fmt: str = "%Y-%m-%d %H:%M UTC") -> str:
    """A timestamp as absolute UTC text ('-' for None)."""
    if ts is None:
        return "-"
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return ts
    try:
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc)
        return ts.strftime(fmt)
    except (AttributeError, ValueError):
        return str(ts)


templates.env.filters["ago"] = _ago
templates.env.filters["iso"] = _iso
templates.env.filters["utc"] = _utc
templates.env.globals["now"] = lambda: datetime.now(timezone.utc)
# Nav entries: (path, label). Module pages append to this list in their register().
templates.env.globals["nav"] = [("/", "Overview"), ("/review", "Review"), ("/domains", "All domains")]
# Two-key "g x" shortcuts for nav entries (app.js reads them from data-chord on the top bar's nav links).
NAV_CHORDS = {"/": "g o", "/review": "g r", "/domains": "g d", "/reports": "g p", "/blocklist": "g b",
              "/takedown": "g t", "/ai": "g a"}
templates.env.globals["nav_chords"] = NAV_CHORDS


def nav_active(current: str, path: str) -> bool:
    """Whether the rail entry `path` is the section of the page at `current` (a domain page belongs to
    All domains, a report page to Reports)."""
    if not current:
        return False
    if path == "/":
        return current == "/"
    if path == "/domains" and current.startswith("/domain/"):
        return True
    return current == path or current.startswith(path.rstrip("/") + "/")


templates.env.globals["nav_active"] = nav_active

# The top bar's segmented control shows these sections; every other nav entry goes under "More".
NAV_PRIMARY = ("/", "/review", "/domains", "/reports")
# Shorter labels for the segmented control (the full label stays in the "g x" shortcut help).
NAV_SHORT = {"/domains": "Domains"}


def nav_groups(current: str = "", nav: list | None = None) -> dict:
    """The nav entries split for the top bar: {"primary": [...], "more": [...], "more_active": item|None}.

    Each item is {"path", "label" (short), "full", "active", "chord" ("g r"|None), "chord_label"}. Module pages
    still append (path, label) to templates.env.globals["nav"]; anything not in NAV_PRIMARY lands in More."""
    if nav is None:
        nav = templates.env.globals.get("nav") or []
    primary, more = [], []
    for path, label in nav:
        chord = NAV_CHORDS.get(path)
        item = {"path": path, "label": NAV_SHORT.get(path, label), "full": label,
                "active": nav_active(current, path), "chord": chord,
                "chord_label": "Go to " + (label if label == label.upper() else label.lower())}
        (primary if path in NAV_PRIMARY else more).append(item)
    return {"primary": primary, "more": more, "more_active": next((i for i in more if i["active"]), None)}


templates.env.globals["nav_groups"] = nav_groups


# ---------------------------------------------------------------------------------------------------------
# Numbers and small chart geometry for the _ui.html macros (pure functions: the macros cannot do trig)
# ---------------------------------------------------------------------------------------------------------

def compact(n, digits: int = 1) -> str:
    """882000 -> '882k', 1234 -> '1.2k', 2400000 -> '2.4M', 981 -> '981', None -> '-' (en-AU, no rounding up
    past a unit: 999950 -> '1M')."""
    if n is None or n == "":
        return "-"
    try:
        v = float(n)
    except (TypeError, ValueError):
        return str(n)
    if v != v:                                  # NaN
        return "-"
    sign = "-" if v < 0 else ""
    v = abs(v)
    for size, unit in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if v >= size * 0.99995:
            x = v / size
            text = f"{x:.0f}" if x >= 100 else f"{x:.{digits}f}".rstrip("0").rstrip(".")
            return f"{sign}{text}{unit}"
    return f"{sign}{v:,.0f}" if v == int(v) else f"{sign}{v:,.{digits}f}"


templates.env.filters["compact"] = compact
templates.env.globals["compact"] = compact

GAUGE_R = 40.0          # ring radius in a 100 x 100 viewBox
GAUGE_SWEEP = 270.0     # degrees of the ring that are drawn (the gap is at the bottom)


def gauge_geom(value, total, sweep: float = GAUGE_SWEEP) -> dict:
    """Geometry for ui.gauge(): SVG arc paths and the needle end point, in a 100 x 100 viewBox.

    The ring starts at the lower left and runs clockwise over the top (the gap is at the bottom). Paths, not a
    rotated circle, so the gradient (userSpaceOnUse, left green to right red) stays upright.
    Returns {"frac": 0..1, "pct": int, "track" (path d of the whole ring), "arc" (path d up to the value, "" at 0),
    "ticks" (path d of the inner dotted ring), "nx", "ny" (needle end), "ex", "ey" (value end on the ring),
    "empty": bool (no total)}."""
    import math
    try:
        v = float(value or 0)
        t = float(total or 0)
    except (TypeError, ValueError):
        v, t = 0.0, 0.0
    if v != v or t != t:                        # NaN
        v, t = 0.0, 0.0
    frac = 0.0 if t <= 0 else max(0.0, min(1.0, v / t))
    a0 = 90.0 + (360.0 - sweep) / 2.0          # 135 degrees: lower left (SVG angles run clockwise)

    def pt(r, deg):
        a = math.radians(deg)
        return round(50 + r * math.cos(a), 2), round(50 + r * math.sin(a), 2)

    def arc(r, start, span):
        if span <= 0:
            return ""
        x0, y0 = pt(r, start)
        x1, y1 = pt(r, start + min(span, 359.99))
        return f"M{x0} {y0}A{r:g} {r:g} 0 {1 if span > 180 else 0} 1 {x1} {y1}"

    nx, ny = pt(30, a0 + sweep * frac)
    ex, ey = pt(GAUGE_R, a0 + sweep * frac)
    return {"frac": frac, "pct": int(round(frac * 100)), "track": arc(GAUGE_R, a0, sweep),
            "arc": arc(GAUGE_R, a0, sweep * frac), "ticks": arc(33, a0, sweep),
            "nx": nx, "ny": ny, "ex": ex, "ey": ey, "empty": t <= 0}


def spark_geom(values, kind: str = "bars", w: float = 120.0, h: float = 32.0) -> dict:
    """Geometry for ui.sparkline() in a w x h viewBox (y down, baseline at h - 1).

    kind "bars": thin bars ({"bars": [(x, y, width, height, is_peak)]}); "peaks": one triangle per non-zero value, joined
    in a single path ({"path"}); "line": a polyline ({"points"}). Always: "n", "max", "min", "sum", "peak_i",
    "peak_x", "peak_y", "base" (baseline y), "w", "h"."""
    vals = []
    for x in values or []:
        try:
            vals.append(max(0.0, float(x or 0)))
        except (TypeError, ValueError):
            vals.append(0.0)
    n = len(vals)
    base = h - 1.0
    out = {"n": n, "w": w, "h": h, "base": base, "bars": [], "path": "", "points": "",
           "max": max(vals) if vals else 0, "min": min(vals) if vals else 0, "sum": sum(vals),
           "peak_i": None, "peak_x": None, "peak_y": None}
    if not n:
        return out
    top = out["max"] or 1.0
    step = w / n
    usable = base - 2.0
    peak_i = vals.index(out["max"]) if out["max"] > 0 else None

    def y(v):
        return round(base - usable * v / top, 2)

    if kind == "peaks":
        hw = min(step * 1.6, w / 6)
        parts = []
        for i, v in enumerate(vals):
            if v <= 0:
                continue
            cx = step * (i + 0.5)
            parts.append(f"M{max(0, cx - hw):.2f} {base:.2f}L{cx:.2f} {y(v):.2f}L{min(w, cx + hw):.2f} {base:.2f}Z")
        out["path"] = "".join(parts)
    elif kind == "line":
        out["points"] = " ".join(f"{step * (i + 0.5):.2f},{y(v):.2f}" for i, v in enumerate(vals))
    else:
        bw = round(max(0.5, step * 0.55), 2)
        for i, v in enumerate(vals):
            if v <= 0:
                continue
            yy = y(v)
            out["bars"].append((round(step * (i + 0.5) - bw / 2, 2), yy, bw, round(max(0.6, base - yy), 2),
                                i == peak_i))
    if peak_i is not None:
        out.update(peak_i=peak_i, peak_x=round(step * (peak_i + 0.5), 2), peak_y=y(vals[peak_i]))
    return out


templates.env.globals["gauge_geom"] = gauge_geom
templates.env.globals["spark_geom"] = spark_geom

STATIC_DIR = HERE / "static"


@lru_cache(maxsize=64)
def _asset_version(name: str) -> str:
    import hashlib
    try:
        return hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:10]
    except OSError:
        return "0"


def asset(name: str) -> str:
    """URL of a file in cybercheck/web/static with a content hash, so browsers never run a stale app.js after
    a deploy: asset("app.css") -> "/static/app.css?v=3f2a9c01de"."""
    name = name.lstrip("/")
    return f"/static/{name}?v={_asset_version(name)}"


templates.env.globals["asset"] = asset


# Addresses the dashboard answers on, as Host header values ("host:port", or "host" for a proxy that drops the
# port). app.py rejects every other Host (DNS rebinding). Override with WEB_ALLOWED_HOSTS (comma list), or keep the
# default and name the proxy's hostname in WEB_PUBLIC_HOSTNAME (e.g. dashboard.example.ts.net).
_PORT_RE = re.compile(r".+:\d+")
_NAME_WITH_PORT_RE = re.compile(r"(\[[^\]]+\]|[^:\[\]]+):\d+")    # "name:8430" or "[v6]:8430", not a bare "::1"


def default_allowed_hosts() -> str:
    """Loopback on WEB_PORT (8430), the bind address WEB_HOST when it is a specific one (e.g. a tailnet IP such
    as 100.64.0.10), and each WEB_PUBLIC_HOSTNAME both on WEB_PORT (`tailscale serve --https=<port>` uses the same
    port) and port-less. A WEB_PUBLIC_HOSTNAME entry that already names a port is taken as it is."""
    s = settings()
    port = s.web_port
    hosts = [f"127.0.0.1:{port}", f"localhost:{port}"]
    for name in s.web_public_hostnames:
        if _NAME_WITH_PORT_RE.fullmatch(name):
            hosts.append(name)
        else:
            hosts += [f"{name}:{port}", name]
    bind = (s.web_host or "").strip().strip("[]").lower()
    if bind and bind not in ("0.0.0.0", "::"):          # a wildcard bind is not an address anyone browses to
        hosts.append(f"[{bind}]:{port}" if ":" in bind else f"{bind}:{port}")
    return ",".join(hosts)


@lru_cache(maxsize=8)
def _parse_hosts(raw: str) -> frozenset[str]:
    hosts = {h.strip().lower() for h in raw.split(",")}
    hosts.discard("")
    return frozenset(hosts)


def allowed_hosts() -> frozenset[str]:
    """WEB_ALLOWED_HOSTS (empty means the default), read on every call so a test or a restart with a new .env
    picks it up."""
    return _parse_hosts(os.environ.get("WEB_ALLOWED_HOSTS", "").strip() or default_allowed_hosts())


def host_allowed(host: str | None) -> bool:
    return bool(host) and host.strip().lower() in allowed_hosts()


def host_rejected_message(host: str | None) -> str:
    shown = repr((host or "")[:200]) if host else "(missing)"
    return (f"Host {shown} is not an address of this dashboard. If it should be, add it to WEB_ALLOWED_HOSTS "
            "(comma-separated host:port list) and restart the web service.")


def _origin_host_port(value: str) -> str | None:
    """'https://Name.example:8430/x' -> 'name.example:8430', with the scheme's default port made explicit."""
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname or u.username is not None or u.password is not None:
        return None
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{host}:{port or (443 if u.scheme == 'https' else 80)}"


def origin_allowed(value: str | None) -> bool:
    """True when an Origin (or Referer) URL is one of the dashboard's own addresses.

    Only allowlist entries with an explicit port count here. A port-less entry exists for a proxy that drops the
    port from Host, but as an origin it would mean port 443, and https://<public hostname> (443) may be a
    different app on the same machine."""
    hp = _origin_host_port(value or "")
    return hp is not None and hp in {h for h in allowed_hosts() if _PORT_RE.fullmatch(h)}


def same_origin(request: Request) -> None:
    """Block cross-site form posts (CSRF) and DNS rebinding: call on every POST.

    A POST is accepted only with positive evidence that one of the dashboard's own pages sent it:
    - Sec-Fetch-Site: same-origin (the browser's own statement; with an allowlisted Host it means our origin), or
    - no Sec-Fetch-Site (older browsers) but an Origin, or failing that a Referer, on an allowlisted address.
      Origin: null never counts: it is what sandboxed iframes and no-referrer pages send.
    - A request with no Sec-Fetch-Site, no Origin and no Referer is let through. Every browser that a web page can
      drive today sends Origin on a POST (Chrome, Safari, and Firefox since 70 in 2019), so such a request comes
      from curl or a script on the host or the private network, which could reach the dashboard directly anyway. The Host
      still has to be allowlisted, so a rebinding name cannot use this path. The remaining gap is a pre-2019
      Firefox, which sent no Origin on form posts and let the attacking page strip its Referer.
    An Origin that is present must be ours whatever Sec-Fetch-Site says (so Origin: null is always refused);
    the Referer is only consulted when there is no Origin. The dashboard sends Referrer-Policy: same-origin, so
    browsers put the real origin, not null, on its own form posts.
    """
    host = request.headers.get("host")
    if not host_allowed(host):
        raise HTTPException(400, host_rejected_message(host))
    site = request.headers.get("sec-fetch-site")
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    # same-site is rejected too: other ports on this host and other machines under the same name share the site
    if site is not None and site not in ("same-origin", "none"):
        raise HTTPException(403, f"cross-site request blocked (Sec-Fetch-Site: {site[:40]!r})")
    if origin is not None:
        if not origin_allowed(origin):
            raise HTTPException(403, f"cross-site request blocked (Origin {origin[:200]!r} is not this dashboard; "
                                     "WEB_ALLOWED_HOSTS entries need an explicit port)")
    elif referer is not None:
        if not origin_allowed(referer):
            raise HTTPException(403, "cross-site request blocked (Referer is not this dashboard)")
    elif site == "none":
        # a browser (it sent fetch metadata), but with no Origin or Referer nothing says our page sent it
        raise HTTPException(403, "cross-site request blocked (no Origin)")


async def fetchall(sql: str, params=()):
    p = await db.pool()
    async with p.connection() as conn:
        return await (await conn.execute(sql, params)).fetchall()


async def fetchone(sql: str, params=()):
    p = await db.pool()
    async with p.connection() as conn:
        return await (await conn.execute(sql, params)).fetchone()




_NOTE_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_note(value: str | None, limit: int = 2000) -> str:
    """A reviewer's free-text note as Postgres can store it: no NUL (text and jsonb both refuse it, so a pasted
    or scripted %00 was a 500) or other control characters except tab and newline, CRLF as LF, length capped."""
    if not value:
        return ""
    s = value.replace("\r\n", "\n").replace("\r", "\n")
    return _NOTE_CTRL.sub("", s).strip()[:limit]


def clean_param(value: str | None, limit: int = 300) -> str:
    """A query-string filter value without NUL (Postgres text cannot hold it) and surrounding spaces."""
    return (value or "").replace("\x00", "").strip()[:limit]


def reviewer(request: Request) -> str:
    """Who is acting (tailscale serve adds Tailscale-User-Login)."""
    return request.headers.get("tailscale-user-login") or "local"


# ---------------------------------------------------------------------------------------------------------
# Status line (the tmux-style bar at the top of every page, and GET /api/status)
# ---------------------------------------------------------------------------------------------------------
# One small query, cached in-process for STATUS_TTL_S. StatusLineMiddleware refreshes the cache (awaiting it)
# before a page request when it is stale, and base.html reads it synchronously through the template global
# status_line(). Any failure renders "unknown": the status line never breaks a page.

STATUS_TTL_S = 15.0
STATUS_TIMEOUT_S = 2.5
STATUS_INGEST_STALE_S = 180      # the same threshold as /healthz
STATUS_WORKER_STALE_S = 600      # the same threshold as /healthz/worker
STATUS_FETCH_STALE_S = 600       # the fetch job runs every 30 s
AI_WARN_PCT = 70

STATUS_SQL = """
SELECT
  (SELECT COALESCE(sum(certs), 0) FROM ingest_stats WHERE minute > now() - interval '5 minutes') AS certs_5m,
  (SELECT updated_at FROM kv WHERE key = 'ingest:heartbeat') AS heartbeat_at,
  (SELECT count(*) FROM domains WHERE status = 'open' AND tier IN ('review', 'high')) AS open_review,
  (SELECT count(*) FROM domains WHERE status = 'open' AND tier = 'high') AS open_high,
  (SELECT max(updated_at) FROM kv WHERE left(key, 4) = 'job:') AS worker_at,
  (SELECT value FROM kv WHERE key = 'job:fetch') AS fetch_job,
  (SELECT updated_at FROM kv WHERE key = 'job:fetch') AS fetch_at,
  (SELECT COALESCE(sum(cost_usd), 0) FROM ai_calls WHERE at >= date_trunc('day', now(), 'UTC')) AS ai_today,
  now() AS db_now
"""

# tone -> the glyph shown with it (colour is never the only signal: every segment also has text)
TONE_GLYPH = {"teal": "●", "amber": "▲", "red": "■", "violet": "◆", "muted": "○"}

_status_cache: dict = {"at": None, "data": None, "busy": False}


def _age_s(now, ts) -> int | None:
    if ts is None or now is None:
        return None
    try:
        return max(0, int((now - ts).total_seconds()))
    except (TypeError, AttributeError):
        return None


def _short_age(s: int | None) -> str:
    if s is None:
        return "?"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _seg(key: str, label: str, value: str, tone: str, title: str, href: str | None = None) -> dict:
    return {"key": key, "label": label, "value": value, "tone": tone, "glyph": TONE_GLYPH.get(tone, "○"),
            "title": title, "href": href}


def _ai_config() -> tuple[float | None, bool]:
    """(daily cap, AI usable at all) without touching the database."""
    try:
        from ..ai import budget
        cfg = budget.config()
        return float(cfg.daily_cap), bool(cfg.enabled and cfg.api_key)
    except Exception:
        return None, False


def unknown_status(reason: str = "not checked yet") -> dict:
    """What the status line shows when its query failed or has not run."""
    segs = [
        _seg("ct", "ct", "unknown", "muted", f"Certificate stream: {reason}", "/"),
        _seg("queue", "queue", "unknown", "muted", f"Review queue: {reason}", "/review"),
        _seg("worker", "worker", "unknown", "muted", f"Worker: {reason}"),
        _seg("fetcher", "fetcher", "unknown", "muted", f"Page fetcher: {reason}"),
        _seg("vpn", "vpn", "unknown", "muted", f"VPN egress: {reason}"),
        _seg("ai", "ai", "unknown", "muted", f"AI spend today: {reason}", "/ai"),
    ]
    return {"ok": False, "reason": reason, "checked_at": None, "certs_per_min": None, "stream": "unknown",
            "heartbeat_age_s": None, "open_review": None, "open_high": None, "worker": "unknown",
            "worker_age_s": None, "fetcher": "unknown", "fetcher_detail": reason, "vpn": "unknown",
            "vpn_country": None, "ai": "unknown", "ai_spent_today": None, "ai_daily_cap": None, "ai_pct": None,
            "segments": segs}


def build_status(row: dict | None, ai_cap: float | None = None, ai_usable: bool = False) -> dict:
    """The status line from one STATUS_SQL row (pure: unit-testable without a database)."""
    if not row:
        return unknown_status("no data")
    now = row.get("db_now") or datetime.now(timezone.utc)
    out = unknown_status()
    out.update(ok=True, reason="ok", checked_at=_iso(now))

    # certificate stream
    hb = _age_s(now, row.get("heartbeat_at"))
    certs = row.get("certs_5m")
    cpm = int(round(float(certs) / 5)) if certs is not None else None
    stream = "unknown" if hb is None else ("live" if hb < STATUS_INGEST_STALE_S else "stale")
    out.update(certs_per_min=cpm, stream=stream, heartbeat_age_s=hb)
    if stream == "live":
        ct = _seg("ct", "ct", f"{cpm:,}/min" if cpm is not None else "live", "teal",
                  f"Certificate stream live: {cpm if cpm is not None else '?'} certificates a minute over the "
                  f"last 5 minutes, heartbeat {_short_age(hb)} ago", "/")
    elif stream == "stale":
        ct = _seg("ct", "ct", f"stalled {_short_age(hb)}", "red",
                  f"Certificate stream stalled: no heartbeat for {_short_age(hb)}", "/")
    else:
        ct = _seg("ct", "ct", "no heartbeat", "muted", "Certificate stream: ingest has never reported", "/")

    # review queue
    n, high = row.get("open_review"), row.get("open_high")
    out.update(open_review=n, open_high=high)
    if n is None:
        queue = _seg("queue", "queue", "unknown", "muted", "Review queue: unknown", "/review")
    elif n == 0:
        queue = _seg("queue", "queue", "empty", "teal", "Review queue is empty", "/review")
    else:
        text = f"{n:,} open" + (f", {high:,} high" if high else "")
        queue = _seg("queue", "queue", text, "red" if high else "amber",
                     f"{n} domains wait for review" + (f", {high} of them high tier" if high else ""), "/review")

    # worker (any job reporting recently)
    wa = _age_s(now, row.get("worker_at"))
    worker_state = "unknown" if wa is None else ("ok" if wa < STATUS_WORKER_STALE_S else "stale")
    out.update(worker=worker_state, worker_age_s=wa)
    if worker_state == "ok":
        worker = _seg("worker", "worker", "ok", "teal", f"Worker jobs reporting, last {_short_age(wa)} ago")
    elif worker_state == "stale":
        worker = _seg("worker", "worker", f"stalled {_short_age(wa)}", "red",
                      f"No worker job has reported for {_short_age(wa)}")
    else:
        worker = _seg("worker", "worker", "not running", "muted", "No worker job has reported yet")

    # fetcher and VPN, from the fetch job's last result (the job asks the fetcher's /health every 30 s; the
    # fetcher fails closed, so "ok" also means the VPN is up and exits in the expected country)
    job = row.get("fetch_job") if isinstance(row.get("fetch_job"), dict) else None
    fa = _age_s(now, row.get("fetch_at"))
    result = (job or {}).get("result") if isinstance((job or {}).get("result"), dict) else {}
    skipped = str(result.get("skipped") or "")
    country = result.get("egress_country")
    country = str(country)[:24] if country else None
    if job is None:
        fstate, detail = "unknown", "the fetch job has not reported yet"
    elif fa is not None and fa >= STATUS_FETCH_STALE_S:
        fstate, detail = "stale", f"the fetch job last reported {_short_age(fa)} ago"
    elif job.get("ok") is False:
        fstate, detail = "error", str(job.get("error") or "the fetch job failed")[:200]
    elif skipped == "fetcher not configured":
        fstate, detail = "off", "FETCHER_TOKEN is not set"
    elif skipped:
        fstate, detail = "down", str(result.get("reason") or skipped)[:200]
    else:
        fstate, detail = "ok", "the fetcher answered its health check"
    out.update(fetcher=fstate, fetcher_detail=detail)
    ftone = {"ok": "teal", "down": "red", "error": "red", "stale": "amber"}.get(fstate, "muted")
    fetcher = _seg("fetcher", "fetcher", fstate, ftone, f"Page fetcher {fstate}: {detail}")
    if fstate == "ok":
        vstate, vpn = "ok", _seg("vpn", "vpn", country or "ok", "teal",
                                 f"VPN up, egress {country or 'country not reported'}")
    elif fstate == "off":
        vstate, vpn = "off", _seg("vpn", "vpn", "off", "muted", "No fetcher configured, so no VPN in use")
    else:
        vstate, vpn = "unknown", _seg("vpn", "vpn", "unknown", "muted" if fstate == "unknown" else "amber",
                                      "VPN state unknown while the fetcher is not healthy (it fails closed "
                                      "when the VPN is down)")
    out.update(vpn=vstate, vpn_country=country if vstate == "ok" else None)

    # AI spend today against the daily cap
    spent = row.get("ai_today")
    spent = float(spent) if spent is not None else None
    pct = None
    if spent is not None and ai_cap:
        pct = int(round(100 * spent / ai_cap)) if ai_cap > 0 else 100
    if spent is None:
        astate, ai = "unknown", _seg("ai", "ai", "unknown", "muted", "AI spend today: unknown", "/ai")
    elif not ai_usable:
        astate = "off"
        ai = _seg("ai", "ai", "off" if spent == 0 else f"off, ${spent:.2f}", "muted",
                  "AI is off (no Anthropic API key, or AI_ENABLED=false)", "/ai")
    else:
        cap_text = f"${ai_cap:.2f}" if ai_cap is not None else "?"
        astate = "over" if (pct or 0) >= 100 else ("warn" if (pct or 0) >= AI_WARN_PCT else "ok")
        ai = _seg("ai", "ai", f"${spent:.2f} of {cap_text}",
                  {"over": "red", "warn": "amber"}.get(astate, "violet"),
                  f"AI spend today (UTC): ${spent:.2f} of the ${cap_text.lstrip('$')} daily cap"
                  + (f" ({pct}%)" if pct is not None else ""), "/ai")
    out.update(ai=astate, ai_spent_today=round(spent, 4) if spent is not None else None, ai_daily_cap=ai_cap,
               ai_pct=pct)
    out["segments"] = [ct, queue, worker, fetcher, vpn, ai]
    return out


async def _query_status() -> dict:
    row = await fetchone(STATUS_SQL)
    cap, usable = _ai_config()
    return build_status(dict(row) if row else None, cap, usable)


async def refresh_status(force: bool = False) -> dict:
    """Refresh the cached status line if it is older than STATUS_TTL_S (or `force`). Never raises.

    Concurrent requests do not pile up: while one refresh runs, the others use the previous value."""
    import asyncio
    import time
    c = _status_cache
    fresh = c["at"] is not None and time.monotonic() - c["at"] < STATUS_TTL_S
    if (fresh and not force) or c["busy"]:
        return c["data"] or unknown_status()
    c["busy"] = True
    try:
        data = await asyncio.wait_for(_query_status(), STATUS_TIMEOUT_S)
    except Exception as e:          # includes the timeout: an unknown status line, never a 500
        _log.warning("status line query failed: %s", type(e).__name__)
        data = unknown_status(f"status query failed ({type(e).__name__})")
    finally:
        c["busy"] = False
    c["at"], c["data"] = time.monotonic(), data
    return data


def status_line() -> dict:
    """The cached status line (template global, synchronous). Always a complete dict."""
    return _status_cache["data"] or unknown_status()


def reset_status_cache() -> None:
    _status_cache.update(at=None, data=None, busy=False)


templates.env.globals["status_line"] = status_line

# Paths that never render base.html: the middleware does not refresh the status line for them.
_NO_STATUS_PREFIXES = ("/static/", "/screenshot/", "/healthz", "/api/", "/robots.txt", "/blocklist/files/",
                       "/favicon")


class StatusLineMiddleware:
    """Refresh the status-line cache before GET requests for pages. Pure ASGI; app.py adds it innermost, so
    it only runs for requests the Host allowlist already accepted."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("method") in ("GET", "HEAD"):
            path = scope.get("path") or ""
            if not path.startswith(_NO_STATUS_PREFIXES) and not path.endswith((".jpg", ".png", ".webp")):
                await refresh_status()
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------------------------------------
# Dot-matrix heatmap (overview): 24 rows (hours) x 60 columns (minutes)
# ---------------------------------------------------------------------------------------------------------

def dot_matrix(certs: dict, flags: dict | None = None, end: datetime | None = None, hours: int = 24) -> dict:
    """Cells for the _ui.html dot_matrix() macro: one row per clock hour (oldest first, the current hour last),
    one column per minute of the hour.

    certs: {minute (tz-aware datetime; seconds are ignored): certificates that minute}
    flags: {minute: "review" | "high"} for minutes that stored a review/high hit (high wins)
    end:   the newest minute shown (default: now). Minutes after it in the current hour are "future" cells.
    Returns {"rows": [{"label": "14:00", "cells": [{"level": 0-4 or None (future), "flag": None|"review"|"high",
    "title": str|None}]}], "max": int, "total": int, "flagged": int, "start": datetime, "end": datetime}."""
    from datetime import timedelta
    flags = flags or {}
    end = (end or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    start = end.replace(minute=0) - timedelta(hours=hours - 1)
    norm: dict = {}
    for k, v in (certs or {}).items():
        try:
            k = k.replace(second=0, microsecond=0)
            norm[k] = norm.get(k, 0) + int(v or 0)
        except (AttributeError, TypeError, ValueError):
            continue
    fl: dict = {}
    for k, v in flags.items():
        try:
            k = k.replace(second=0, microsecond=0)
        except AttributeError:
            continue
        if v == "high" or fl.get(k) != "high":
            fl[k] = "high" if v == "high" else "review"
    peak = max((v for k, v in norm.items() if start <= k <= end), default=0)
    rows, total, flagged = [], 0, 0
    for r in range(hours):
        row_start = start + timedelta(hours=r)
        cells = []
        for c in range(60):
            m = row_start + timedelta(minutes=c)
            if m > end:
                cells.append({"level": None, "flag": None, "title": None})
                continue
            v = norm.get(m, 0)
            total += v
            level = 0 if v <= 0 or peak <= 0 else min(4, max(1, -(-4 * v // peak)))
            f = fl.get(m)
            title = None
            if f:
                flagged += 1
                title = f"{m.strftime('%H:%M')} UTC: {v:,} certificates, {f} hit"
            cells.append({"level": level, "flag": f, "title": title})
        rows.append({"label": row_start.strftime("%H:%M"), "cells": cells})
    return {"rows": rows, "max": peak, "total": total, "flagged": flagged, "start": start, "end": end}
