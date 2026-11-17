"""CyberCheck dashboard (FastAPI + server-rendered templates). Bound to 127.0.0.1, shared via `tailscale serve`."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.datastructures import Headers

from .. import db
from ..config import settings
from .common import (STATIC_DIR, StatusLineMiddleware, clean_note, clean_param, fetchall, fetchone, host_allowed,
                     host_rejected_message, refresh_status, same_origin, templates)

HERE = Path(__file__).resolve().parent
log = logging.getLogger(__name__)


class AllowedHostsMiddleware:
    """Refuse any request whose Host is not one of the dashboard's addresses (WEB_ALLOWED_HOSTS).

    Without it, a page on rebind.attacker.example:8430 whose DNS later points at 127.0.0.1 is same-origin with the
    dashboard and can read and post to it. Pure ASGI so it also covers websockets and unknown paths."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            host = Headers(scope=scope).get("host")
            if not host_allowed(host):
                log.warning("rejected request for Host %r", (host or "")[:200])
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    resp = PlainTextResponse(host_rejected_message(host) + "\n", status_code=400)
                    await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


app = FastAPI(title="CyberCheck", docs_url=None, redoc_url=None, openapi_url=None)
# Middleware added first runs innermost. The status line refresh sits inside the Host allowlist, so a rejected
# Host never reaches the database.
app.add_middleware(StatusLineMiddleware)
# Added before security_headers below, so it sits inside it and its 400 responses get those headers too.
app.add_middleware(AllowedHostsMiddleware)
# The dashboard's own CSS and JS (no external assets anywhere). Mounted on the app, so the Host allowlist and
# security headers cover it like every route.
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Every page: no inline script, style attribute or event handler runs, nothing loads from another origin.
# Routes that serve hostile content (screenshots, blocklist files) set a stricter one of their own.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

STATUSES = ("open", "confirmed", "false_positive", "benign")
TIERS = ("high", "review", "watch")


NAV = templates.env.globals["nav"]


async def overview_stats() -> dict:
    s = await fetchone("""
        SELECT
          (SELECT COALESCE(sum(certs),0) FROM ingest_stats WHERE minute > now() - interval '5 minutes') AS certs_5m,
          (SELECT COALESCE(sum(hostnames),0) FROM ingest_stats WHERE minute > now() - interval '5 minutes') AS hosts_5m,
          (SELECT COALESCE(sum(certs),0) FROM ingest_stats WHERE minute > now() - interval '24 hours') AS certs_24h,
          (SELECT count(*) FROM domains WHERE first_seen > now() - interval '24 hours') AS hits_24h,
          (SELECT count(*) FROM domains WHERE first_seen > now() - interval '24 hours' AND tier = 'high') AS high_24h,
          (SELECT count(*) FROM domains WHERE status = 'open' AND tier IN ('review','high')) AS open_review,
          (SELECT count(*) FROM domains) AS total,
          (SELECT count(*) FROM domains WHERE status = 'confirmed') AS confirmed,
          (SELECT count(*) FROM domains WHERE live_state = 'live') AS live,
          (SELECT max(first_seen) FROM domains) AS last_hit,
          (SELECT updated_at FROM kv WHERE key = 'ingest:heartbeat') AS heartbeat
    """)
    return dict(s)


@app.get("/", response_class=HTMLResponse)
async def overview(request: Request):
    stats = await overview_stats()
    rows = await fetchall("SELECT * FROM domains ORDER BY id DESC LIMIT 100")
    return templates.TemplateResponse(request, "overview.html", {"stats": stats, "rows": rows})


@app.get("/api/recent")
async def api_recent(after_id: int = 0):
    rows = await fetchall(
        "SELECT id, registered_domain, unicode_domain, hostnames[1] AS hostname, brand_id, score, tier, status, "
        "first_seen, issuer, live_state, ai_verdict, final_score FROM domains WHERE id > %s ORDER BY id DESC LIMIT 100",
        (after_id,))
    stats = await overview_stats()
    return JSONResponse({"rows": [{**r, "first_seen": r["first_seen"].isoformat()} for r in rows],
                         "stats": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in stats.items()}})


@app.get("/api/status")
async def api_status():
    """The status line (base.html) as JSON, for app.js to refresh it in place. Cached for a few seconds."""
    data = await refresh_status()
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


# ---- review queue (triage) ---------------------------------------------------------------------------
# The queue is every open domain of tier review or high. The page is a two-pane triage screen: the queue on the
# left, the selected domain's evidence on the right (GET /review/evidence/{id} renders that pane on its own for
# triage.js). Decisions still post to /domain/{id}/status.

QUEUE_WHERE = "status = 'open' AND tier IN ('review','high')"
# priority: high tier first, then review; inside each, the combined score (domain + page + AI) when there is one.
# id breaks ties so the order (and the j/k and [/] neighbours) is stable.
QUEUE_SORTS = {
    "priority": "(tier = 'high') DESC, COALESCE(final_score, score) DESC, first_seen DESC, id DESC",
    "score": "COALESCE(final_score, score) DESC, first_seen DESC, id DESC",
    "newest": "first_seen DESC, id DESC",
}
QUEUE_SORT_LABELS = (("priority", "High tier first"), ("score", "Highest score first"), ("newest", "Newest first"))
QUEUE_TIERS = ("high", "review")
AI_FILTERS = ("phishing", "suspicious", "benign", "parked", "error", "none")
LIVE_FILTERS = ("yes", "no")
REVIEW_LIMIT = 300


def review_query(tier: str = "", brand: str = "", live: str = "", ai: str = "", sort: str = "") -> tuple[str, list, dict]:
    """WHERE clause, parameters and the cleaned filters for the review queue. Unknown values mean no filter."""
    where, params = [QUEUE_WHERE], []
    tier = tier if tier in QUEUE_TIERS else ""
    brand = clean_param(brand)
    live = live if live in LIVE_FILTERS else ""
    ai = ai if ai in AI_FILTERS else ""
    sort = sort if sort in QUEUE_SORTS else "priority"
    if tier:
        where.append("tier = %s"); params.append(tier)
    if brand:
        where.append("brand_id = %s"); params.append(brand)
    if live == "yes":
        where.append("live_state = 'live'")
    elif live == "no":
        where.append("live_state <> 'live'")
    if ai == "none":
        where.append("ai_verdict IS NULL")
    elif ai:
        where.append("ai_verdict = %s"); params.append(ai)
    return " AND ".join(where), params, {"tier": tier, "brand": brand, "live": live, "ai": ai, "sort": sort}


def filters_active(f: dict) -> bool:
    return any(f.get(k) for k in ("tier", "brand", "live", "ai"))


ASK_ORDER = ("password", "otp", "card", "identity", "personal_info")
ASK_LABELS = {"password": "password", "otp": "one-time code", "card": "card details",
              "identity": "identity documents", "personal_info": "personal details"}
_AI_ASK = {"passwords": "password", "password": "password", "otp": "otp", "card": "card", "identity": "identity",
           "personal_info": "personal_info"}


def _features(p: dict) -> dict:
    f = p.get("features")
    return f if isinstance(f, dict) else {}


def page_asks(pages: list[dict], ai: dict | None = None) -> list[dict]:
    """What the newest snapshot of each profile (desktop, mobile) asks visitors for, from its form fields,
    plus what the AI said the page asks for. [{key, label, form: bool, ai: bool}] in a fixed order."""
    seen_profiles, found = set(), {}
    for p in pages or ():
        prof = p.get("user_agent_profile") or "desktop"
        if prof in seen_profiles:
            continue
        seen_profiles.add(prof)
        for key, on in (("password", p.get("has_password_field")), ("otp", p.get("has_otp_field")),
                        ("card", p.get("has_card_field")), ("identity", _features(p).get("has_identity_field") is True)):
            if on:
                found.setdefault(key, {"form": False, "ai": False})["form"] = True
    asks = (ai or {}).get("asks_for") if isinstance(ai, dict) else None
    for a in asks if isinstance(asks, list) else ():
        key = _AI_ASK.get(str(a))
        if key:
            found.setdefault(key, {"form": False, "ai": False})["ai"] = True
    return [{"key": k, "label": ASK_LABELS[k], **found[k]} for k in ASK_ORDER if k in found]


def _usable_ai(p: dict) -> dict | None:
    r = p.get("ai_result")
    if isinstance(r, dict) and r.get("verdict") and not r.get("invalid"):
        return r
    return None


def evidence(d: dict, pages: list[dict], ai_calls: list[dict] | None = None) -> dict:
    """Everything the evidence pane and the domain page show about one domain, from rows already loaded
    (pure: unit-testable). pages: newest first. ai_calls: page_judge calls, newest first (explanation fallback)."""
    shots = [p for p in pages if p.get("screenshot_path")]
    desktop = next((p for p in shots if (p.get("user_agent_profile") or "desktop") != "mobile"), None)
    mobile = next((p for p in shots if p.get("user_agent_profile") == "mobile"), None)
    judged = [p for p in pages if _usable_ai(p)]
    ai_page = next((p for p in judged if _usable_ai(p)["verdict"] != "error"), judged[0] if judged else None)
    ai = dict(_usable_ai(ai_page)) if ai_page else None
    if ai is not None and not ai.get("explanation"):
        # older rows keep the explanation only on the AI call
        for c in ai_calls or ():
            r = c.get("result")
            if isinstance(r, dict) and r.get("explanation") and (c.get("page_id") in (None, ai_page["id"])):
                ai["explanation"] = r["explanation"]
                ai.setdefault("asks_for", r.get("asks_for"))
                break
    return {
        "d": d, "pages": pages, "latest": pages[0] if pages else None,
        "shot": desktop or mobile, "shot_mobile": mobile if desktop else None,
        "ai": ai, "ai_page": ai_page, "asks": page_asks(pages, ai),
        "bl_scope": _blocklist_preview(d), "official": _is_official(d.get("registered_domain")),
    }


async def load_evidence(domain_id: int) -> dict | None:
    d = await fetchone("SELECT * FROM domains WHERE id = %s", (domain_id,))
    if not d:
        return None
    pages = await fetchall("SELECT * FROM pages WHERE domain_id = %s ORDER BY fetched_at DESC, id DESC LIMIT 10",
                           (domain_id,))
    calls = await fetchall("SELECT page_id, result FROM ai_calls WHERE domain_id = %s AND purpose = 'page_judge' "
                           "AND result ? 'explanation' ORDER BY at DESC, id DESC LIMIT 5", (domain_id,))
    return evidence(d, pages, calls)


def queue_neighbours(ids: list[int], current: int) -> dict:
    """Previous/next domain in the queue order around `current`. When it is not in the queue (just decided,
    or never queued) next is the top of the queue."""
    try:
        i = ids.index(current)
    except ValueError:
        return {"pos": None, "total": len(ids), "prev": None, "next": ids[0] if ids else None}
    return {"pos": i + 1, "total": len(ids), "prev": ids[i - 1] if i > 0 else None,
            "next": ids[i + 1] if i + 1 < len(ids) else None}


@app.get("/review", response_class=HTMLResponse)
async def review(request: Request, tier: str = "", brand: str = "", live: str = "", ai: str = "",
                 sort: str = "", id: int | None = None):
    where, params, f = review_query(tier, brand, live, ai, sort)
    rows = await fetchall(
        "SELECT id, registered_domain, unicode_domain, hostnames, brand_id, score, tier, final_score, status, "
        f"live_state, ai_verdict, ai_confidence, first_seen FROM domains WHERE {where} "
        f"ORDER BY {QUEUE_SORTS[f['sort']]} LIMIT {REVIEW_LIMIT}", params)
    counts = await fetchone(
        f"SELECT count(*) AS n, count(*) FILTER (WHERE tier = 'high') AS high, "
        "count(*) FILTER (WHERE live_state = 'live') AS live, "
        f"count(*) FILTER (WHERE ai_verdict = 'phishing') AS ai_phish FROM domains WHERE {where}", params)
    brands = await fetchall(f"SELECT brand_id, count(*) AS n FROM domains WHERE {QUEUE_WHERE} "
                            "AND brand_id IS NOT NULL GROUP BY brand_id ORDER BY n DESC, brand_id")
    selected = id if id is not None and 0 < id < 2 ** 63 else (rows[0]["id"] if rows else None)
    ev = await load_evidence(selected) if selected is not None else None
    return templates.TemplateResponse(request, "review.html", {
        "rows": rows, "title": "Review queue", "filters": f, "filtered": filters_active(f),
        "total": (counts or {}).get("n") or 0, "high": (counts or {}).get("high") or 0, "limit": REVIEW_LIMIT,
        "live": (counts or {}).get("live") or 0, "ai_phish": (counts or {}).get("ai_phish") or 0,
        "brands": brands, "ev": ev, "selected": ev["d"]["id"] if ev else None, "statuses": STATUSES,
        "sorts": QUEUE_SORT_LABELS, "ai_filters": AI_FILTERS})


# The evidence pane alone, for triage.js to swap in without reloading the queue. Same markup as the page.
_EVIDENCE_PANE = templates.env.from_string(
    '{% from "_row.html" import evidence_pane %}{{ evidence_pane(ev, statuses) }}')


@app.get("/review/evidence/{domain_id}", response_class=HTMLResponse)
async def review_evidence(domain_id: int):
    ev = await load_evidence(domain_id) if 0 < domain_id < 2 ** 63 else None
    if not ev:
        raise HTTPException(404)
    return HTMLResponse(_EVIDENCE_PANE.render(ev=ev, statuses=STATUSES), headers={"Cache-Control": "no-store"})


PAGE_SIZE = 200
MAX_PAGE = 100_000          # keeps OFFSET inside bigint: ?page=10**20 would otherwise be a 500 from Postgres


def _like_escape(s: str) -> str:
    """A search box value as a literal LIKE pattern: '%' and '_' match themselves, not anything."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# Sortable columns of /domains: ?sort=<key>&dir=asc|desc. Expressions are fixed strings (never user input).
DOMAIN_SORTS = {
    "seen": ("first_seen", "desc"),
    "tier": ("CASE tier WHEN 'high' THEN 3 WHEN 'review' THEN 2 ELSE 1 END", "desc"),
    "score": ("score", "desc"),
    "combined": ("final_score", "desc"),
    "host": ("registered_domain", "asc"),
    "brand": ("brand_id", "asc"),
}


def domains_order(sort: str = "", direction: str = "") -> tuple[str, str, str]:
    """(ORDER BY clause, sort key, direction). Unknown keys fall back to newest first. first_seen and id always
    break ties, so pages never overlap."""
    key = sort if sort in DOMAIN_SORTS else "seen"
    expr, default_dir = DOMAIN_SORTS[key]
    d = direction if direction in ("asc", "desc") else default_dir
    if key == "seen":
        return f"first_seen {d.upper()}, id {d.upper()}", key, d
    return f"{expr} {d.upper()} NULLS LAST, first_seen DESC, id DESC", key, d


def domains_query_string(filters: dict, page: int, sort: str = "seen", direction: str = "desc", **override) -> str:
    """The /domains query for a link: the filters always (empty ones too), then the page, then sort and dir
    only when they are not the default."""
    from urllib.parse import urlencode
    v = {**filters, "page": page, "sort": sort, "dir": direction, **override}
    pairs = [(k, v.get(k) or "") for k in ("q", "tier", "status", "brand")] + [("page", v["page"])]
    if v["sort"] != "seen" or v["dir"] != DOMAIN_SORTS["seen"][1]:
        pairs += [("sort", v["sort"]), ("dir", v["dir"])]
    return urlencode(pairs)


def sort_links(filters: dict, sort: str, direction: str) -> dict:
    """For each sortable column: the link that sorts by it (flipping the direction when it is the current one)
    and its aria-sort value."""
    out = {}
    for key, (_, default_dir) in DOMAIN_SORTS.items():
        if key == sort:
            nd, aria = ("asc" if direction == "desc" else "desc"), ("descending" if direction == "desc" else "ascending")
        else:
            nd, aria = default_dir, None
        out[key] = {"href": "?" + domains_query_string(filters, 1, key, nd), "aria": aria, "next_dir": nd}
    return out


@app.get("/domains", response_class=HTMLResponse)
async def domains(request: Request, tier: str = "", status: str = "", brand: str = "", q: str = "", page: int = 1,
                  sort: str = "", dir: str = ""):
    page = max(1, min(page, MAX_PAGE))
    brand, q = clean_param(brand), clean_param(q)
    where, params = [], []
    if tier in TIERS:
        where.append("tier = %s"); params.append(tier)
    if brand:
        where.append("brand_id = %s"); params.append(brand)
    if q:
        # the displayed (unicode) form too: a reviewer pastes what the dashboard shows for an IDN
        pattern = f"%{_like_escape(q)}%"
        where.append("(registered_domain ILIKE %s OR unicode_domain ILIKE %s OR %s = ANY(hostnames))")
        params += [pattern, pattern, q.lower()]
    # the decision tiles count every decision under the other filters (so they work as a switch)
    base_sql, base_params = ((" WHERE " + " AND ".join(where)) if where else ""), list(params)
    if status in STATUSES:
        where.append("status = %s"); params.append(status)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    order, sort, dir = domains_order(sort, dir)
    # id breaks first_seen ties (rows stored in one transaction share now()): without it Postgres may order tied
    # rows differently for page 1 and page 2, so some rows show twice and others never
    sql = f"SELECT * FROM domains{where_sql} ORDER BY {order} LIMIT {PAGE_SIZE} OFFSET %s"
    rows = await fetchall(sql, params + [(page - 1) * PAGE_SIZE])
    total = await fetchone(f"SELECT count(*) AS n FROM domains{where_sql}", params)
    brands = await fetchall("SELECT brand_id, count(*) AS n FROM domains GROUP BY brand_id ORDER BY n DESC")
    by_status = {r["status"]: r["n"] for r in await fetchall(
        f"SELECT status, count(*) AS n FROM domains{base_sql} GROUP BY status", base_params)}
    filters = {"tier": tier if tier in TIERS else "", "status": status if status in STATUSES else "",
               "brand": brand, "q": q}
    n = (total or {}).get("n") or 0
    return templates.TemplateResponse(request, "domains.html", {
        "rows": rows, "title": "All domains", "brands": brands, "page": page, "page_size": PAGE_SIZE,
        "total": n, "pages": max(1, -(-n // PAGE_SIZE)),
        # the raw values, so a filter the reviewer typed still shows in the form (unknown ones filter nothing)
        "filters": {"tier": tier, "status": status, "brand": brand, "q": q},
        "sort": sort, "dir": dir, "sorts": sort_links(filters, sort, dir),
        "prev_qs": domains_query_string(filters, page - 1, sort, dir) if page > 1 else None,
        "next_qs": domains_query_string(filters, page + 1, sort, dir) if len(rows) == PAGE_SIZE else None,
        "statuses": STATUSES, "tiers": TIERS, "by_status": by_status,
        # each tile switches the decision filter (the same one again clears it); other filters and the sort stay
        "status_links": {s: "?" + domains_query_string({**filters, "status": "" if filters["status"] == s else s},
                                                       1, sort, dir) for s in STATUSES}})


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_detail(request: Request, domain_id: int):
    d = await fetchone("SELECT * FROM domains WHERE id = %s", (domain_id,))
    if not d:
        raise HTTPException(404)
    events = await fetchall("SELECT * FROM domain_events WHERE domain_id = %s ORDER BY at, id", (domain_id,))
    checks = await fetchall("SELECT * FROM checks WHERE domain_id = %s ORDER BY at DESC LIMIT 50", (domain_id,))
    pages = await fetchall("SELECT * FROM pages WHERE domain_id = %s ORDER BY fetched_at DESC, id DESC LIMIT 10", (domain_id,))
    ai = await fetchall("SELECT * FROM ai_calls WHERE domain_id = %s ORDER BY at DESC LIMIT 10", (domain_id,))
    reports = await fetchall("SELECT * FROM reports WHERE domain_id = %s ORDER BY created_at", (domain_id,))
    queue = await fetchall(f"SELECT id FROM domains WHERE {QUEUE_WHERE} ORDER BY {QUEUE_SORTS['priority']} "
                           f"LIMIT {REVIEW_LIMIT}")
    ev = evidence(d, pages, [a for a in ai if a.get("purpose") == "page_judge"])
    return templates.TemplateResponse(request, "domain.html", {
        "d": d, "events": events, "checks": checks, "pages": pages, "ai": ai, "reports": reports,
        "statuses": STATUSES, "bl_scope": ev["bl_scope"], "ev": ev,
        "nav_q": queue_neighbours([r["id"] for r in queue], d["id"])})


def _is_official(name: str | None) -> bool:
    try:
        from ..scoring import default_watchlist
        return bool(name) and default_watchlist().is_official(name)
    except Exception:
        log.exception("watchlist unavailable")
        return False


def _blocklist_preview(d: dict):
    """What the blocklist would list if this domain is (or stays) confirmed: shown before a reviewer clicks
    Confirm, so a shared platform or compromised site is never blocked whole by surprise."""
    try:
        from ..blocklist import scope
        from ..scoring import default_watchlist
        return scope(dict(d, status="confirmed"), default_watchlist())
    except Exception:
        return None


@app.post("/domain/{domain_id}/status")
async def set_status(request: Request, domain_id: int, status: str = Form(...), note: str = Form("")):
    same_origin(request)
    if status not in STATUSES:
        raise HTTPException(400, "bad status")
    note = clean_note(note)
    who = request.headers.get("tailscale-user-login") or "local"
    p = await db.pool()
    async with p.connection() as conn:
        if status == "confirmed":
            cur = await (await conn.execute("SELECT registered_domain FROM domains WHERE id = %s", (domain_id,))).fetchone()
            if cur and _is_official(cur["registered_domain"]):
                # The bot, the stats and /takedown would otherwise call the real brand's site phishing.
                raise HTTPException(400, f"{cur['registered_domain']} is an official brand domain or on the allowlist, "
                                         "so it cannot be confirmed as phishing. If a page on it was compromised, "
                                         "tell the brand directly.")
        # the decision and its timeline event commit together, so the newest event always matches the row
        async with conn.transaction():
            row = await (await conn.execute(
                "UPDATE domains SET status = %s, status_changed_at = now(), status_by = %s, "
                # the hostnames the reviewer was shown: a decision never covers hostnames that arrive later
                "reviewed_hostnames = CASE WHEN %s::text = 'open' THEN NULL ELSE hostnames END, "
                # explicit casts: concat_ws takes VARIADIC "any", so an untyped parameter cannot be resolved
                "notes = CASE WHEN %s::text <> '' THEN concat_ws(E'\\n', notes, %s::text) ELSE notes END "
                "WHERE id = %s RETURNING id", (status, who, status, note, note, domain_id))).fetchone()
            if not row:
                raise HTTPException(404)
            await db.add_event(conn, domain_id, "status", {"status": status, "by": who, "note": note})
        # After the commit, so a blocklist build that started meanwhile cannot miss the change (its own
        # now() is earlier than this request, which it keeps for the next run).
        try:
            from ..blocklist import request_rebuild
            await request_rebuild(conn, "status", who)
        except Exception:
            log.exception("could not request a blocklist rebuild")
        if status == "confirmed":
            # keep screenshots of confirmed phishing past the retention window (evidence). Never in one
            # transaction with the domain UPDATE above: the judge locks a page and then its domain, and holding
            # them in the opposite order here could deadlock with it.
            await conn.execute("UPDATE pages SET is_evidence = true WHERE domain_id = %s", (domain_id,))
    return RedirectResponse(f"/domain/{domain_id}", status_code=303)


@app.get("/screenshot/{page_id}")
async def screenshot(page_id: int):
    row = await fetchone("SELECT screenshot_path FROM pages WHERE id = %s", (page_id,))
    if not row or not row["screenshot_path"]:
        raise HTTPException(404)
    base = settings().data_dir.resolve()
    path = (base / row["screenshot_path"]).resolve()
    if base not in path.parents or not path.is_file():
        raise HTTPException(404)
    # Screenshot of a hostile page: serve as an image only, never as HTML
    return FileResponse(path, media_type="image/webp", headers={"Content-Security-Policy": "default-src 'none'",
                                                                "X-Content-Type-Options": "nosniff"})


@app.get("/healthz")
async def healthz():
    s = await fetchone("SELECT updated_at FROM kv WHERE key = 'ingest:heartbeat'")
    age = (datetime.now(timezone.utc) - s["updated_at"]).total_seconds() if s else None
    ok = age is not None and age < 180
    return JSONResponse({"ok": ok, "ingest_heartbeat_age_s": age}, status_code=200 if ok else 503)


# Uptime-monitor checks (Uptime Kuma or similar; the dashboard is private). Each answers 200 when healthy and 503
# otherwise, and never includes secrets, so a monitor needs no token.
WORKER_STALE_S = 600           # the fastest jobs run every 30-60 s; 10 minutes of silence means trouble
SANDBOX_MAX_AGE_DAYS = 9       # verify-sandbox.sh runs weekly; one missed run is tolerated


@app.get("/healthz/worker")
async def healthz_worker():
    row = await fetchone("SELECT max(updated_at) AS last FROM kv WHERE key LIKE 'job:%%'")
    age = (datetime.now(timezone.utc) - row["last"]).total_seconds() if row and row["last"] else None
    ok = age is not None and age < WORKER_STALE_S
    return JSONResponse({"ok": ok, "last_job_status_age_s": age}, status_code=200 if ok else 503)


@app.get("/healthz/fetcher")
async def healthz_fetcher():
    from ..fetch_client import FetchClient
    try:
        async with FetchClient(connect_timeout=3.0, read_timeout=15.0) as fc:
            h = await fc.health() if fc.configured else None
    except Exception:
        h = None
    ok = bool(h and h.get("ok"))
    body = {"ok": ok}
    if h:
        body.update({k: h.get(k) for k in ("vpn_running", "egress_country", "error") if k in h})
    else:
        body["error"] = "fetcher unreachable or not configured"
    return JSONResponse(body, status_code=200 if ok else 503)


@app.get("/healthz/sandbox")
async def healthz_sandbox():
    """The isolation test (scripts/verify-sandbox.sh) passed recently. It deletes its file on any failure."""
    import json as _json
    path = settings().data_dir / "sandbox_verified.json"
    age_days, passed = None, None
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        at = datetime.fromisoformat(str(data["verified_at"]).replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - at).total_seconds() / 86400
        passed = data.get("tests_passed")
    except (OSError, ValueError, KeyError, TypeError):
        pass
    ok = age_days is not None and age_days <= SANDBOX_MAX_AGE_DAYS
    return JSONResponse({"ok": ok, "verified_days_ago": round(age_days, 2) if age_days is not None else None,
                         "tests_passed": passed}, status_code=200 if ok else 503)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # same-origin, not no-referrer: no-referrer makes browsers send Origin: null on the dashboard's own form posts,
    # which same_origin() must refuse. Other sites still get no Referer.
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Content-Security-Policy", CSP)
    return resp


@app.on_event("shutdown")
async def _shutdown():
    await db.close()


def register_module_routes() -> None:
    """Optional module pages (reports, blocklist, takedown stats, AI spend, CZDS, bot)."""
    import importlib
    for mod in ("live", "reports", "blocklist", "takedown", "ai", "czds", "bot"):
        try:
            m = importlib.import_module(f".pages_{mod}", __package__)
        except ModuleNotFoundError as e:
            if e.name and e.name.endswith(f"pages_{mod}"):
                continue
            raise
        m.register(app, templates, NAV)


register_module_routes()


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nDisallow: /\n"
