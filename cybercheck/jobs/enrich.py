"""Worker job: DNS / RDAP / ASN enrichment, the re-check schedule and takedown detection (cybercheck.enrich)."""
from __future__ import annotations

from ..enrich import run_once
from ..worker import Job, JobContext


async def run(ctx: JobContext) -> dict:
    return await run_once(ctx)


JOB = Job(name="enrich", interval=30, run=run, initial_delay=10)
