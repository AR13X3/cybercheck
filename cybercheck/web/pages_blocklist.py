"""Dashboard page for the DNS blocklist: counts, downloads, listed domains, exclusions, rebuild."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from .. import blocklist, db
from .common import clean_note, fetchall, fetchone, reviewer, same_origin

MESSAGES = {
    "built": "Blocklist rebuilt.",
    "busy": "A build was already running. Another one runs within a minute.",
    "failed": "The build failed (see the web log). The worker retries within a minute.",
    "excluded": "Removed from the blocklist and excluded from future builds.",
    "included": "Exclusion lifted. The domain is listed again on the next build if it still qualifies.",
}

# flash tone for each message (ok | info | warn | error)
MESSAGE_TONES = {"built": "ok", "busy": "info", "failed": "error", "excluded": "ok", "included": "ok"}

# domain_events kinds shown under "Recent changes": (label, pill tone, glyph)
EVENT_LABELS = {
    "blocklisted": ("listed", "teal", "●"),
    "unblocklisted": ("removed", "muted", "○"),
    "blocklist_excluded": ("excluded", "amber", "▲"),
    "blocklist_included": ("exclusion lifted", "outline", "○"),
}
EXPIRING_DAYS = 7

COUNTS_SQL = """
SELECT count(*) FILTER (WHERE blocklisted) AS listed,
       count(*) FILTER (WHERE blocklisted AND status = 'confirmed') AS confirmed,
       count(*) FILTER (WHERE blocklisted AND status <> 'confirmed') AS automated,
       count(*) FILTER (WHERE blocklist_excluded) AS excluded,
       count(*) FILTER (WHERE blocklisted AND blocklist_expires_at < now() + interval '7 days') AS expiring
FROM domains WHERE blocklisted OR blocklist_excluded
"""
LISTED_SQL = """
SELECT id, registered_domain, unicode_domain, brand_id, status, final_score, ai_verdict, ai_confidence, live_state,
       blocklist_listed_at, blocklist_expires_at
FROM domains WHERE blocklisted
ORDER BY blocklist_listed_at DESC NULLS LAST, registered_domain LIMIT %s
"""
EXCLUDED_SQL = """
SELECT id, registered_domain, unicode_domain, brand_id, status, blocklist_excluded_at, blocklist_excluded_by
FROM domains WHERE blocklist_excluded
ORDER BY blocklist_excluded_at DESC NULLS LAST LIMIT 200
"""
EVENTS_SQL = """
SELECT e.at, e.kind, e.detail, d.id, d.registered_domain
FROM domain_events e JOIN domains d ON d.id = e.domain_id
WHERE e.kind IN ('blocklisted', 'unblocklisted', 'blocklist_excluded', 'blocklist_included')
ORDER BY e.at DESC LIMIT 30
"""
LISTED_LIMIT = 500


def event_label(kind) -> tuple[str, str, str]:
    return EVENT_LABELS.get(kind, (str(kind or "-").replace("_", " "), "muted", "○"))


def annotate_listed(rows, now: datetime | None = None) -> list[dict]:
    """Listed rows for the page, with why each one is listed and whether it expires soon."""
    now = now or datetime.now(timezone.utc)
    out = []
    for r in rows:
        r = dict(r)
        exp = r.get("blocklist_expires_at")
        r["via"] = "confirmed" if r.get("status") == "confirmed" else "score"
        r["expires_soon"] = bool(exp and exp < now + timedelta(days=EXPIRING_DAYS))
        out.append(r)
    return out


def _msg_for(result: dict) -> str:
    return "busy" if result.get("busy") else "failed" if result.get("error") else "built"


def register(app, templates, nav):
    nav.append(("/blocklist", "Blocklist"))

    @app.get("/blocklist", response_class=HTMLResponse)
    async def blocklist_page(request: Request, msg: str = ""):
        counts = await fetchone(COUNTS_SQL)
        rows = annotate_listed(await fetchall(LISTED_SQL, (LISTED_LIMIT,)))
        excluded = await fetchall(EXCLUDED_SQL)
        events = await fetchall(EVENTS_SQL)
        state = await fetchone("SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,))
        requested = await fetchone("SELECT updated_at FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))
        directory = blocklist.out_dir()
        files = []
        for name in blocklist.FILES:
            path = directory / name
            files.append({"name": name, "about": blocklist.FILE_INFO[name], "url": f"/blocklist/files/{name}",
                          "size": path.stat().st_size if path.is_file() else None})
        st = (state or {}).get("value") or {}
        cfg = blocklist.BuildConfig.from_env()
        return templates.TemplateResponse(request, "blocklist_index.html", {
            "counts": counts or {}, "rows": rows, "excluded": excluded, "events": events, "files": files,
            "built_at": blocklist.parse_ts(st.get("built_at")), "updated_at": blocklist.parse_ts(st.get("updated_at")),
            "serial": st.get("serial"), "requested_at": (requested or {}).get("updated_at"),
            "hostname_only": blocklist.hostname_only_entries(directory), "held_czds": st.get("held_czds") or 0,
            "cfg": cfg, "limit": LISTED_LIMIT, "message": MESSAGES.get(msg),
            "message_tone": MESSAGE_TONES.get(msg, "info"), "event_label": event_label,
            "built": any(f["size"] is not None for f in files), "expiring_days": EXPIRING_DAYS})

    @app.get("/blocklist/files/{name}")
    async def blocklist_file(name: str):
        if name not in blocklist.FILES:       # allowlist: no paths, no other files from the data dir
            raise HTTPException(404)
        path = blocklist.out_dir() / name
        if not path.is_file():
            raise HTTPException(404, "not built yet")
        return FileResponse(path, media_type="text/plain", headers={
            "Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-cache"})

    @app.post("/blocklist/rebuild")
    async def blocklist_rebuild(request: Request):
        same_origin(request)
        who = reviewer(request)
        result = await blocklist.build_now(f"rebuild by {who}", who)
        return RedirectResponse(f"/blocklist?msg={_msg_for(result)}", status_code=303)

    @app.post("/blocklist/{domain_id}/exclude")
    async def blocklist_exclude(request: Request, domain_id: int, note: str = Form("")):
        same_origin(request)
        who = reviewer(request)
        p = await db.pool()
        async with p.connection() as conn:
            row = await (await conn.execute(
                "UPDATE domains SET blocklist_excluded = true, blocklist_excluded_at = now(), "
                "blocklist_excluded_by = %s WHERE id = %s RETURNING id, registered_domain",
                (who, domain_id))).fetchone()
            if not row:
                raise HTTPException(404)
            await db.add_event(conn, domain_id, "blocklist_excluded", {"by": who, "note": clean_note(note, 500)})
            await blocklist.request_rebuild(conn, "exclusion", who)
        result = await blocklist.build_now(f"excluded by {who}", who)
        msg = "excluded" if _msg_for(result) == "built" else _msg_for(result)
        return RedirectResponse(f"/blocklist?msg={msg}", status_code=303)

    @app.post("/blocklist/{domain_id}/include")
    async def blocklist_include(request: Request, domain_id: int):
        same_origin(request)
        who = reviewer(request)
        p = await db.pool()
        async with p.connection() as conn:
            row = await (await conn.execute(
                "UPDATE domains SET blocklist_excluded = false, blocklist_excluded_at = NULL, "
                "blocklist_excluded_by = NULL WHERE id = %s AND blocklist_excluded RETURNING id",
                (domain_id,))).fetchone()
            if not row:
                raise HTTPException(404)
            await db.add_event(conn, domain_id, "blocklist_included", {"by": who})
            await blocklist.request_rebuild(conn, "exclusion lifted", who)
        result = await blocklist.build_now(f"exclusion lifted by {who}", who)
        msg = "included" if _msg_for(result) == "built" else _msg_for(result)
        return RedirectResponse(f"/blocklist?msg={msg}", status_code=303)
