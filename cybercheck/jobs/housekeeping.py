"""Core housekeeping: keep tables small, drop personal data on schedule, and delete CZDS zone data when the
czds job is turned off (its own runs do that while it is on; ICANN CZDS terms s1.4)."""
from __future__ import annotations

import asyncio

from .. import czds
from ..worker import Job, JobContext

SQL = [
    # raw re-check results: keep 90 days, longer for confirmed phishing (takedown evidence)
    ("checks", "DELETE FROM checks c USING domains d WHERE c.domain_id = d.id AND c.at < now() - interval '90 days' "
               "AND d.status <> 'confirmed'"),
    ("checks_confirmed", "DELETE FROM checks WHERE at < now() - interval '400 days'"),
    # bot explanations may paraphrase a forwarded message: drop the text after 30 days
    ("ai_bot", "UPDATE ai_calls SET result = NULL WHERE purpose = 'bot' AND result IS NOT NULL AND at < now() - interval '30 days'"),
    # domains that never went anywhere: watch-tier, open, no page, no report, last seen > 120 days ago
    ("stale_watch", "DELETE FROM domains d WHERE d.tier = 'watch' AND d.status = 'open' AND d.last_seen < now() - interval '120 days' "
                    "AND NOT EXISTS (SELECT 1 FROM pages p WHERE p.domain_id = d.id) "
                    "AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.domain_id = d.id)"),
]


async def run_once(ctx: JobContext) -> dict:
    out = {}
    # first, before any database work, so a database outage cannot skip it; never raises
    deleted = await asyncio.to_thread(czds.cleanup_if_disabled, ctx.settings)
    if deleted:
        out["czds_deleted_lists"] = deleted
    p = await ctx.pool()
    async with p.connection() as conn:
        for name, sql in SQL:
            cur = await conn.execute(sql)
            out[name] = cur.rowcount
    return out


JOB = Job(name="housekeeping", interval=6 * 3600, run=run_once, initial_delay=120)
