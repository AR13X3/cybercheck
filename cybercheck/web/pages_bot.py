"""Dashboard page /bot: Telegram chats (allow / block) and the domains people forwarded. No message text exists."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import psycopg
from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..config import settings
from .common import fetchall, fetchone, reviewer, same_origin

log = logging.getLogger("cybercheck.web.bot")

STATUSES = ("allowed", "blocked", "pending")
MAX_CHAT_ID = 2 ** 53        # Telegram chat ids fit in 52 bits

CHATS_SQL = """
SELECT chat_id, chat_type, title, username, status, status_changed_at, status_by, first_seen, last_seen,
       CASE WHEN counter_day = %(day)s THEN day_messages ELSE 0 END AS today_messages,
       CASE WHEN counter_day = %(day)s THEN day_ai ELSE 0 END AS today_ai,
       total_messages, total_domains, total_ai
FROM bot_chats
ORDER BY (status = 'pending') DESC, last_seen DESC
LIMIT 500
"""

RECENT_SQL = """
SELECT m.id, m.at, m.chat_id, c.title, c.username, x.host, x.reg, x.verdict,
       d.id AS domain_id, d.tier, d.status AS domain_status, d.source
FROM (SELECT * FROM bot_messages WHERE cardinality(domains) > 0 ORDER BY at DESC LIMIT 100) m
CROSS JOIN LATERAL unnest(m.domains, m.registered, m.verdicts) WITH ORDINALITY AS x(host, reg, verdict, n)
LEFT JOIN bot_chats c ON c.chat_id = m.chat_id
LEFT JOIN domains d ON d.registered_domain = x.reg
ORDER BY m.at DESC, m.id DESC, x.n
LIMIT 300
"""

TOP_SQL = """
SELECT x.reg, count(DISTINCT m.id) AS n, count(DISTINCT m.chat_id) AS chats, max(m.at) AS last_at,
       d.id AS domain_id, d.tier, d.status AS domain_status
FROM bot_messages m
CROSS JOIN LATERAL unnest(m.registered) AS x(reg)
LEFT JOIN domains d ON d.registered_domain = x.reg
WHERE m.at > now() - interval '30 days'
GROUP BY x.reg, d.id, d.tier, d.status
ORDER BY n DESC, last_at DESC
LIMIT 20
"""

STATS_SQL = """
SELECT
  (SELECT count(*) FROM bot_messages WHERE at > now() - interval '24 hours') AS checks_24h,
  (SELECT count(*) FROM bot_messages WHERE at > now() - interval '30 days') AS checks_30d,
  (SELECT COALESCE(sum(cardinality(domains)), 0) FROM bot_messages WHERE at > now() - interval '30 days') AS domains_30d,
  (SELECT COALESCE(sum(new_domains), 0) FROM bot_messages WHERE at > now() - interval '30 days') AS new_30d,
  (SELECT count(*) FROM domains WHERE source = 'bot') AS stored_by_bot
"""


# What the bot told the person, per domain: (pill tone, glyph). Text is the verdict itself.
VERDICT_LOOK = {"confirmed": ("red", "■"), "suspicious": ("amber", "▲"), "official": ("teal", "✓")}
CHAT_LOOK = {"allowed": ("teal", "●"), "pending": ("amber", "▲"), "blocked": ("red", "■")}


def verdict_look(verdict) -> tuple[str, str, str]:
    """(label, tone, glyph) for a bot verdict such as 'confirmed', 'suspicious', 'official', 'shortener'."""
    tone, glyph = VERDICT_LOOK.get(verdict or "", ("muted", "○"))
    return (str(verdict or "unknown").replace("_", " "), tone, glyph)


def chat_look(status) -> tuple[str, str, str]:
    tone, glyph = CHAT_LOOK.get(status or "", ("muted", "○"))
    return (status or "unknown", tone, glyph)


def split_chats(chats: list[dict]) -> tuple[list[dict], list[dict]]:
    """(waiting for approval, every other chat): the page shows the chats that need a decision first."""
    pending = [c for c in chats if c.get("effective") == "pending"]
    return pending, [c for c in chats if c.get("effective") != "pending"]


def _effective(status: str, env_allowed: bool) -> str:
    if status == "blocked":
        return "blocked"
    return "allowed" if status == "allowed" or env_allowed else status


def register(app, templates, nav) -> None:
    nav.append(("/bot", "Bot"))

    @app.get("/bot", response_class=HTMLResponse)
    async def bot_page(request: Request):
        s = settings()
        env_ids = set(s.telegram_allowed_chats)
        day = datetime.now(timezone.utc).date()
        error = None
        chats, recent, top, stats, status = [], [], [], {}, None
        try:
            chats = [dict(c) for c in await fetchall(CHATS_SQL, {"day": day})]
            recent = await fetchall(RECENT_SQL)
            top = await fetchall(TOP_SQL)
            stats = dict(await fetchone(STATS_SQL) or {})
            status = await fetchone("SELECT value, updated_at FROM kv WHERE key = %s", ("bot:status",))
        except psycopg.errors.UndefinedTable:
            error = "The bot tables don't exist yet. Run: python -m cybercheck migrate"
        for c in chats:
            c["env"] = c["chat_id"] in env_ids
            c["effective"] = _effective(c["status"], c["env"])
        seen = {c["chat_id"] for c in chats}
        counts = {k: sum(1 for c in chats if c["effective"] == k) for k in STATUSES}
        try:
            from ..bot import ai_daily_limit
            ai_limit = ai_daily_limit()
        except Exception:
            ai_limit = None
        pending, others = split_chats(chats)
        return templates.TemplateResponse(request, "bot_index.html", {
            "chats": chats, "pending": pending, "others": others, "verdict_look": verdict_look,
            "chat_look": chat_look, "env_unseen": sorted(env_ids - seen), "recent": recent, "top": top,
            "stats": stats, "counts": counts, "status": status, "error": error,
            "token_set": bool(s.telegram_bot_token), "daily_limit": s.bot_daily_limit_per_chat,
            "ai_limit": ai_limit})

    @app.post("/bot/chat/{chat_id}/status")
    async def bot_chat_status(request: Request, chat_id: int, status: str = Form(...)):
        same_origin(request)
        if status not in STATUSES:
            raise HTTPException(400, "bad status")
        if abs(chat_id) >= MAX_CHAT_ID:
            raise HTTPException(400, "bad chat id")
        who = reviewer(request)
        await fetchone(
            "INSERT INTO bot_chats (chat_id, status, status_changed_at, status_by) VALUES (%s, %s, now(), %s) "
            "ON CONFLICT (chat_id) DO UPDATE SET status = EXCLUDED.status, status_changed_at = now(), "
            "status_by = EXCLUDED.status_by RETURNING chat_id", (chat_id, status, who))
        log.info("bot chat %s set to %s by %s", chat_id, status, who)
        return RedirectResponse("/bot", status_code=303)
