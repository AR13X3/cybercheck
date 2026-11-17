"""Dashboard page /ai: AI spend against the caps, availability, recent calls and refusals."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse

from .. import db
from ..ai import api
from .pages_czds import fmt_until

RECENT_SQL = """
SELECT c.id, c.at, c.purpose, c.model, c.fallback_model, c.status, c.stop_reason, c.input_tokens, c.output_tokens,
       c.cache_read_tokens, c.cache_write_tokens, c.cost_usd, c.estimated_cost_usd, c.duration_ms, c.error,
       c.domain_id, c.page_id, d.registered_domain,
       c.result->>'verdict' AS verdict, c.result->>'refusal_category' AS refusal_category
FROM ai_calls c LEFT JOIN domains d ON d.id = c.domain_id
ORDER BY c.at DESC
LIMIT %s
"""

BY_PURPOSE_SQL = """
SELECT purpose, count(*) AS calls, COALESCE(sum(cost_usd), 0) AS cost,
       count(*) FILTER (WHERE status = 'refusal') AS refusals,
       count(*) FILTER (WHERE status IN ('api_error', 'error', 'invalid', 'abandoned')) AS errors,
       COALESCE(sum(cache_read_tokens), 0) AS cache_read, COALESCE(sum(input_tokens), 0) AS input
FROM ai_calls WHERE at >= date_trunc('month', now(), 'UTC')
GROUP BY purpose ORDER BY cost DESC
"""

QUEUE_SQL = """
SELECT
  (SELECT count(*) FROM pages p JOIN domains d ON d.id = p.domain_id
    WHERE p.ai_judged_at IS NULL AND p.error IS NULL AND d.status = 'open' AND d.tier IN ('review', 'high')
      AND p.fetched_at > now() - make_interval(hours => %s::int)) AS pages_pending,
  (SELECT count(*) FROM pages WHERE ai_judged_at > now() - interval '24 hours' AND ai_result ? 'verdict') AS judged_24h,
  (SELECT count(*) FROM domains WHERE ai_triaged_at > now() - interval '24 hours') AS triaged_24h
"""


# Calls per purpose and hour over the last 24 h, for the dot grid and the hourly charts. ago_h 0 is the newest
# hour. (Grouped "ago_h, purpose", not "purpose": the unit tests' fake connection keys on that text.)
HOURLY_SQL = """
SELECT purpose, LEAST(23, GREATEST(0, floor(extract(epoch FROM (now() - at)) / 3600)))::int AS ago_h,
       count(*) AS calls, COALESCE(sum(cost_usd), 0) AS cost,
       count(*) FILTER (WHERE status = 'refusal') AS refusals,
       count(*) FILTER (WHERE status IN ('api_error', 'error', 'invalid', 'abandoned')) AS errors
FROM ai_calls WHERE at > now() - interval '24 hours'
GROUP BY ago_h, purpose
"""

HOURS = 24
# Known purposes first, in this order; anything else after them, alphabetically.
PURPOSE_ORDER = ("page_judge", "domain_triage", "watchlist", "report_draft", "bot")
PURPOSE_LABEL = {"page_judge": "Page judge", "domain_triage": "Domain triage", "watchlist": "Watchlist",
                 "report_draft": "Report drafts", "bot": "Bot replies"}


def _level(v: float, peak: float) -> int:
    """0 (no calls) or 1-4 by share of the busiest cell."""
    if v <= 0 or peak <= 0:
        return 0
    return max(1, min(4, int(-(-4 * v // peak))))


def hourly_view(rows) -> dict:
    """AI activity over the last 24 h for /ai: a dot grid with one row per purpose and one column per hour
    (oldest first; a marker on hours with refusals or errors) and hourly totals for the sparklines.
    rows: HOURLY_SQL rows. Returns {"rows": [...ui.dot_grid rows], "calls": [24 ints], "cost": [24 floats],
    "total_calls", "total_cost", "problems", "label" (the grid's accessible summary)}."""
    by: dict = {}
    calls, cost = [0] * HOURS, [0.0] * HOURS
    for r in rows or ():
        try:
            i = HOURS - 1 - max(0, min(HOURS - 1, int(r["ago_h"])))
        except (KeyError, TypeError, ValueError):
            continue
        purpose = str(r.get("purpose") or "other")
        cell = by.setdefault(purpose, [None] * HOURS)
        n, c = int(r.get("calls") or 0), float(r.get("cost") or 0)
        ref, err = int(r.get("refusals") or 0), int(r.get("errors") or 0)
        old = cell[i] or {"calls": 0, "cost": 0.0, "refusals": 0, "errors": 0}
        cell[i] = {"calls": old["calls"] + n, "cost": old["cost"] + c, "refusals": old["refusals"] + ref,
                   "errors": old["errors"] + err}
        calls[i] += n
        cost[i] += c
    peak = max((c["calls"] for cells in by.values() for c in cells if c), default=0)
    order = [p for p in PURPOSE_ORDER if p in by] + sorted(p for p in by if p not in PURPOSE_ORDER)
    out, problems = [], 0
    for p in order:
        cells = []
        for i, c in enumerate(by[p]):
            ago = HOURS - 1 - i
            when = "this hour" if ago == 0 else f"{ago} h ago"
            if not c:
                cells.append({"level": 0, "title": None, "marker": None})
                continue
            bad = c["refusals"] + c["errors"]
            problems += bad
            title = f"{when}: {c['calls']} call{'s' if c['calls'] != 1 else ''}, ${c['cost']:.4f}"
            if c["refusals"]:
                title += f", {c['refusals']} refused"
            if c["errors"]:
                title += f", {c['errors']} failed"
            marker = "danger" if c["errors"] else ("alert" if c["refusals"] else None)
            cells.append({"level": _level(c["calls"], peak), "title": title, "marker": marker})
        n = sum(c["calls"] for c in by[p] if c)
        out.append({"label": PURPOSE_LABEL.get(p, p.replace("_", " ").capitalize()), "total": f"{n:,}",
                    "cells": cells})
    total_calls, total_cost = sum(calls), sum(cost)
    parts = [f"{r['label']} {r['total']}" for r in out]
    label = (f"AI calls per hour by purpose, last 24 hours: {total_calls:,} calls, ${total_cost:.2f}"
             + (f" ({', '.join(parts)})" if parts else "") + (f", {problems} refused or failed" if problems else ""))
    return {"rows": out, "calls": calls, "cost": [round(v, 4) for v in cost], "total_calls": total_calls,
            "total_cost": total_cost, "problems": problems, "label": label}


def judge_max_age_h() -> int:
    """AI_JUDGE_MAX_AGE_H as the judge job reads it (cybercheck/jobs/judge.py, default 72): it never judges an
    older page, so "pages waiting for a check" uses the same window."""
    try:
        h = int((os.environ.get("AI_JUDGE_MAX_AGE_H") or "").strip() or 72)
    except ValueError:
        h = 72
    return max(0, min(h, 100_000))      # inside int4 for make_interval: a typo must not take the page down


def _pct(spent: float, cap: float) -> int:
    if cap <= 0:
        return 100
    return max(0, min(100, int(round(100 * spent / cap))))


# Call status -> (label, pill tone, glyph). Anything else (api_error, error, invalid, abandoned) is a failure.
CALL_STATUS = {"ok": ("ok", "teal", "●"), "refusal": ("refusal", "amber", "▲"), "pending": ("pending", "outline", "◌")}
PROBLEM_STATUSES = ("refusal", "api_error", "error", "invalid", "abandoned")


def call_status(status) -> tuple[str, str, str]:
    """(label, tone, glyph) for an ai_calls.status value."""
    if not status:
        return ("-", "muted", "○")
    return CALL_STATUS.get(status, (str(status).replace("_", " "), "red", "■"))


def spend_tone(pct: int) -> str | None:
    """Meter tone for AI spend: violet while comfortably under the cap, then the meter's own amber/red."""
    return "violet" if pct < 70 else None


def _resets(now: datetime | None = None) -> dict:
    """When the daily (UTC midnight) and monthly (first of the month, UTC) caps reset."""
    now = now or datetime.now(timezone.utc)
    day = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    month = (now.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return {"day": day, "month": month}


def spend_view(s: dict, now: datetime | None = None) -> list[dict]:
    """The three spend meters on /ai: today, this month, and domain triage's share of today's cap."""
    r = _resets(now)
    out = []
    for key, label, spent, cap, reset in (
            ("day", "Spent today (UTC)", s.get("spent_today") or 0.0, s.get("daily_cap") or 0.0, r["day"]),
            ("month", "Spent this month", s.get("spent_month") or 0.0, s.get("monthly_cap") or 0.0, r["month"]),
            ("triage", "Domain triage today", s.get("triage_spent_today") or 0.0, s.get("triage_cap") or 0.0,
             r["day"])):
        pct = _pct(spent, cap)
        out.append({"key": key, "label": label, "spent": spent, "cap": cap, "pct": pct,
                    "left": max(0.0, cap - spent), "tone": spend_tone(pct), "resets": reset,
                    "state": "over" if pct >= 100 else ("warn" if pct >= 70 else "ok")})
    return out


def register(app, templates, nav) -> None:
    if ("/ai", "AI") not in nav:
        nav.append(("/ai", "AI"))

    @app.get("/ai", response_class=HTMLResponse)
    async def ai_overview(request: Request, limit: int = 100):
        limit = max(10, min(500, limit))
        p = await db.pool()
        async with p.connection() as conn:
            status = await api.budget_status(conn)
            calls = await (await conn.execute(RECENT_SQL, (limit,))).fetchall()
            by_purpose = await (await conn.execute(BY_PURPOSE_SQL)).fetchall()
            queue = await (await conn.execute(QUEUE_SQL, (judge_max_age_h(),))).fetchone()
            job = await db.kv_get(conn, "job:judge")
            hourly = await (await conn.execute(HOURLY_SQL)).fetchall()
        return templates.TemplateResponse(request, "ai_overview.html", {
            "s": status, "calls": calls, "by_purpose": by_purpose, "queue": queue or {}, "job": job,
            "pct_day": _pct(status["spent_today"], status["daily_cap"]),
            "pct_month": _pct(status["spent_month"], status["monthly_cap"]),
            "limit": limit, "spend": spend_view(status), "call_status": call_status,
            "fmt_until": fmt_until,
            "problems": sum(1 for c in calls if c["status"] in PROBLEM_STATUSES),
            "judge_window_h": judge_max_age_h(), "hourly": hourly_view(hourly),
        })
