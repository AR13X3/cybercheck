"""Worker job: keep the DNS blocklist files up to date (rules and formats in cybercheck/blocklist.py).

Runs every minute but only does a cheap check unless a build is due: a full build every
BLOCKLIST_BUILD_INTERVAL seconds (default 600), and sooner after a review change on the dashboard
(status, blocklist exclusion) or a rebuild request in kv['blocklist:rebuild'].
"""
from __future__ import annotations

from .. import blocklist
from ..worker import Job, JobContext


async def run_once(ctx: JobContext) -> dict:
    cfg = blocklist.BuildConfig.from_env()
    p = await ctx.pool()
    async with p.connection() as conn:
        why = await blocklist.rebuild_reason(conn, cfg, blocklist.build_interval())
        if why is None:
            return {**ctx.state.get("last", {}), "rebuilt": False}
        result = await blocklist.build(conn, cfg=cfg, trigger=why)
    if result is None:  # the dashboard is building right now
        return {**ctx.state.get("last", {}), "rebuilt": False, "busy": True}
    ctx.state["last"] = result
    return {**result, "rebuilt": True}


JOB = Job(name="blocklist", interval=60, run=run_once, initial_delay=30)
