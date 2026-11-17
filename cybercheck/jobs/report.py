"""Worker job: report planning and the rate-limited send queue (cybercheck.reporting.engine)."""
from __future__ import annotations

from ..reporting.engine import run_once
from ..worker import Job, JobContext


async def run(ctx: JobContext) -> dict:
    return await run_once(ctx)


JOB = Job(name="report", interval=60, run=run, initial_delay=20)
