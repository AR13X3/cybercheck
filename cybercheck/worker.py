"""Background worker: runs every job module in cybercheck/jobs/ on its own interval.

A job module defines:

    JOB = Job(name="enrich", interval=60, run=run_once)   # async def run_once(ctx: JobContext) -> dict | None

Each job runs in its own loop; one failing job never stops the others. Status goes to kv['job:<name>']
and is shown on the dashboard. Disable a job with JOB_<NAME>_ENABLED=false.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import pkgutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from . import db
from .config import Settings, settings

log = logging.getLogger("cybercheck.worker")


@dataclass
class JobContext:
    settings: Settings
    log: logging.Logger
    state: dict = field(default_factory=dict)   # per-job memory between runs

    async def pool(self):
        return await db.pool()


@dataclass
class Job:
    name: str
    interval: float                                   # seconds between runs
    run: Callable[[JobContext], Awaitable[dict | None]]
    initial_delay: float = 5.0
    enabled_by_default: bool = True


def discover_jobs() -> list[Job]:
    from . import jobs as jobs_pkg
    found = []
    for mod in pkgutil.iter_modules(jobs_pkg.__path__):
        if mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"{jobs_pkg.__name__}.{mod.name}")
        job = getattr(m, "JOB", None)
        if isinstance(job, Job):
            found.append(job)
    return found


def job_enabled(job: Job) -> bool:
    v = os.environ.get(f"JOB_{job.name.upper()}_ENABLED", "").strip().lower()
    return job.enabled_by_default if not v else v in ("1", "true", "yes", "on")


async def _loop(job: Job) -> None:
    ctx = JobContext(settings=settings(), log=logging.getLogger(f"cybercheck.job.{job.name}"))
    await asyncio.sleep(job.initial_delay)
    while True:
        started = time.monotonic()
        status = {"last_run": datetime.now(timezone.utc).isoformat()}
        try:
            result = await job.run(ctx)
            status.update({"ok": True, "result": result or {}})
        except Exception as e:  # keep the loop alive; record the error
            ctx.log.exception("job %s failed", job.name)
            status.update({"ok": False, "error": f"{type(e).__name__}: {e}"[:500]})
        status["duration_s"] = round(time.monotonic() - started, 2)
        try:
            # values straight from SQL (timestamptz, numeric) are not JSON: store them as text rather than
            # failing the status write (kv.value is jsonb)
            status = json.loads(db.dumps(status))
            p = await db.pool()
            async with p.connection() as conn:
                await db.kv_set(conn, f"job:{job.name}", status)
        except Exception:
            log.exception("could not record status for %s", job.name)
        await asyncio.sleep(job.interval)


async def run() -> None:
    db.migrate()
    jobs = [j for j in discover_jobs() if job_enabled(j)]
    log.info("starting jobs: %s", ", ".join(f"{j.name}({j.interval}s)" for j in jobs) or "none")
    if not jobs:
        while True:
            await asyncio.sleep(3600)
    await asyncio.gather(*(_loop(j) for j in jobs))
