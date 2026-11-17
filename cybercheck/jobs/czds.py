"""Worker job: ICANN CZDS zone files -> newly delegated names -> brand scoring (cybercheck.czds).

Hourly. Each zone is downloaded at most once per 24 h, inside the daily window after ICANN's collection
(CZDS_WINDOW_START, default 06:30 UTC); a run waits up to about an hour for a zone that is nearly due.
Without CZDS_USERNAME / CZDS_PASSWORD it returns {"skipped": "no CZDS credentials"}, makes no network or
database calls, and only cleans up data/czds (T&C s1.4): raw and partial downloads at once, every TLD's lists
CZDS_KEEP_UNCONFIGURED_DAYS after their last update. With JOB_CZDS_ENABLED=false this job never runs, so it
cannot clean up: czds.cleanup_if_disabled() is that clean-up for a job that still runs, and docs/CZDS.md
("Stopping CZDS") gives the command to delete the files by hand.
"""
from __future__ import annotations

from ..czds import run_once
from ..worker import Job, JobContext


async def run(ctx: JobContext) -> dict:
    return await run_once(ctx)


JOB = Job(name="czds", interval=3600, run=run, initial_delay=90)
