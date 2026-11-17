"""Worker job "retention": delete fetched screenshot / HTML files once they are past retain_until.

A snapshot's files are deleted when:
  - its retain_until has passed, and
  - it is not marked is_evidence, and
  - its domain is not status = 'confirmed' (a confirmed domain's snapshots are kept as takedown
    evidence; the job sets is_evidence on them instead of deleting).

is_evidence only means something while the domain is confirmed. When a reviewer moves a confirmed
domain to another status (false_positive, benign, or reopened), its snapshots lose the evidence mark
EVIDENCE_GRACE_DAYS after that change (the grace covers a mis-click), and then follow the normal
retention rule like any other snapshot.

Only files under the data directory are ever touched (paths are resolved and checked), and a file that
another still-kept snapshot reuses (the fetch job writes one file when consecutive snapshots are
identical) is left in place. The pages rows stay; only screenshot_path / html_path are nulled, and a
path is nulled only once its file is gone (deleted, already missing, or still used by a kept row): a
file that could not be deleted (permissions, I/O error) keeps its path and is tried again next run.

Orphan sweep (at most once a day): files under data/screenshots/<domain_id>/ and data/html/<domain_id>/
that are older than ORPHAN_GRACE_HOURS and that no pages row references are deleted. The fetch job
removes its files when saving a snapshot fails, but a kill between writing a file and recording it
(OOM, container stop) would otherwise leave the file on disk for good.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

from .. import db
from ..config import settings
from ..worker import Job, JobContext

log = logging.getLogger("cybercheck.job.retention")

EVIDENCE_GRACE_DAYS = 7
ORPHAN_GRACE_HOURS = 24
ORPHAN_SWEEP_EVERY_S = 24 * 3600
SNAPSHOT_DIRS = ("screenshots", "html")      # what the fetch job writes under data_dir
MAX_ORPHAN_DELETES = 20_000                  # per sweep

# Evidence marks on domains that are no longer confirmed (after the grace period) are cleared, so the
# snapshots fall back to the normal retention rule.
CLEAR_EVIDENCE_SQL = """
UPDATE pages p SET is_evidence = false
FROM domains d
WHERE d.id = p.domain_id AND p.is_evidence AND d.status <> 'confirmed'
  AND COALESCE(d.status_changed_at, '-infinity'::timestamptz) < now() - make_interval(days => %s)
"""

CANDIDATES_SQL = """
SELECT p.id, p.domain_id, p.screenshot_path, p.html_path, d.status
FROM pages p JOIN domains d ON d.id = p.domain_id
WHERE p.retain_until IS NOT NULL AND p.retain_until < now() AND NOT p.is_evidence
  AND (p.screenshot_path IS NOT NULL OR p.html_path IS NOT NULL)
  AND p.id <> ALL(%(skip)s::bigint[])
ORDER BY p.retain_until
LIMIT %(batch)s
"""

# Is this file still referenced by a snapshot that must be kept? (evidence, confirmed domain, or not
# yet past its own retention.) If so, do not delete the file even though this row is releasing it.
REFERENCED_SQL = """
SELECT 1 FROM pages o JOIN domains od ON od.id = o.domain_id
WHERE o.id <> %(id)s AND (o.screenshot_path = %(path)s OR o.html_path = %(path)s)
  AND (o.is_evidence OR od.status = 'confirmed' OR o.retain_until IS NULL OR o.retain_until > now())
LIMIT 1
"""

# Every path any row of this domain still records (the fetch job only ever writes a domain's files
# under its own <domain_id> directory, and only rows of that domain reuse them).
DOMAIN_PATHS_SQL = "SELECT screenshot_path, html_path FROM pages WHERE domain_id = %s"

_PATH_COLS = ("screenshot_path", "html_path")


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _safe_path(data_dir, rel: str):
    """Resolve rel under data_dir; return the path only if it stays inside data_dir."""
    base = data_dir.resolve()
    try:
        path = (base / rel).resolve()
    except (OSError, ValueError):
        return None
    if base != path and base not in path.parents:
        return None
    return path


def _unlink(path) -> str:
    """'deleted', 'missing' (already gone) or 'error' (still there: keep its path and retry later)."""
    try:
        path.unlink()
        return "deleted"
    except FileNotFoundError:
        return "missing"
    except OSError:
        log.warning("could not delete %s", path)
        return "error"


MAX_BATCHES = 20     # per run: up to RETENTION_BATCH * MAX_BATCHES snapshots, so a backlog drains


def _old_snapshot_files(data_dir, now: float) -> dict[int, list[tuple[str, Path]]]:
    """{domain_id: [(relative path, path)]} for regular files under data_dir/{screenshots,html}/<id>/
    last modified more than ORPHAN_GRACE_HOURS ago. Blocking: call in a thread."""
    out: dict[int, list[tuple[str, Path]]] = {}
    base = Path(data_dir).resolve()
    cutoff = now - ORPHAN_GRACE_HOURS * 3600
    for top in SNAPSHOT_DIRS:
        try:
            dirs = list(os.scandir(base / top))
        except OSError:
            continue
        for d in dirs:
            try:
                # ASCII digits only: str.isdigit() also accepts e.g. Arabic-Indic digits, which int() maps
                # onto another domain's id, and superscripts, which int() rejects (aborting the sweep).
                if not (d.name.isascii() and d.name.isdigit()) or not d.is_dir(follow_symlinks=False):
                    continue
                files = list(os.scandir(d.path))
            except OSError:
                continue
            for f in files:
                try:
                    if not f.is_file(follow_symlinks=False) or f.stat(follow_symlinks=False).st_mtime >= cutoff:
                        continue
                except OSError:
                    continue
                out.setdefault(int(d.name), []).append((f"{top}/{d.name}/{f.name}", Path(f.path)))
    return out


async def sweep_orphans(conn, data_dir) -> int:
    """Delete old snapshot files that no pages row references. Returns how many were deleted."""
    found = await asyncio.to_thread(_old_snapshot_files, data_dir, time.time())
    deleted = 0
    for domain_id, files in found.items():
        if deleted >= MAX_ORPHAN_DELETES:
            break
        rows = await (await conn.execute(DOMAIN_PATHS_SQL, (domain_id,))).fetchall()
        referenced = {r.get(c) for r in rows for c in _PATH_COLS if r.get(c)}
        for rel, path in files:
            if rel in referenced or deleted >= MAX_ORPHAN_DELETES:
                continue
            if _safe_path(data_dir, rel) is None:
                continue
            if await asyncio.to_thread(_unlink, path) == "deleted":
                deleted += 1
    if deleted:
        log.info("deleted %d orphaned snapshot file(s)", deleted)
    return deleted


async def run_once(ctx: JobContext) -> dict:
    data_dir = settings().data_dir
    batch = max(1, _env_int("RETENTION_BATCH", 500))
    state = getattr(ctx, "state", None)
    if not isinstance(state, dict):
        state = {}
    out = {"released": 0, "files_deleted": 0, "kept_evidence": 0}
    skip: list[int] = []                 # rows whose file could not be deleted: retried next run
    p = await db.pool()
    async with p.connection() as conn:
        cleared = (await conn.execute(CLEAR_EVIDENCE_SQL, (EVIDENCE_GRACE_DAYS,))).rowcount
        if cleared and cleared > 0:
            out["evidence_cleared"] = cleared
        for _ in range(MAX_BATCHES):
            rows = await (await conn.execute(CANDIDATES_SQL, {"batch": batch, "skip": skip})).fetchall()
            for row in rows:
                if row["status"] == "confirmed":
                    await conn.execute("UPDATE pages SET is_evidence = true WHERE id = %s", (row["id"],))
                    out["kept_evidence"] += 1
                    continue
                release: list[str] = []
                for col in _PATH_COLS:
                    rel = row.get(col)
                    if not rel:
                        continue
                    ref = await (await conn.execute(REFERENCED_SQL, {"id": row["id"], "path": rel})).fetchone()
                    if ref:
                        release.append(col)          # a kept row still uses the file: drop only our reference
                        continue
                    path = _safe_path(data_dir, rel)
                    if path is None:
                        log.warning("refusing to delete out-of-tree path %r", rel)
                        release.append(col)
                        continue
                    res = await asyncio.to_thread(_unlink, path)
                    if res == "deleted":
                        out["files_deleted"] += 1
                    if res == "error":
                        out["delete_errors"] = out.get("delete_errors", 0) + 1
                    else:
                        release.append(col)
                if release:
                    sets = ", ".join(f"{c} = NULL" for c in release)       # names from _PATH_COLS only
                    await conn.execute(f"UPDATE pages SET {sets} WHERE id = %s", (row["id"],))
                    out["released"] += 1
                if len(release) < sum(1 for c in _PATH_COLS if row.get(c)):
                    skip.append(row["id"])           # a path was kept: leave this row for the next run
            if len(rows) < batch:
                break
        if time.monotonic() - state.get("orphan_sweep_at", -1e18) >= ORPHAN_SWEEP_EVERY_S:
            state["orphan_sweep_at"] = time.monotonic()
            try:
                out["orphans_deleted"] = await sweep_orphans(conn, data_dir)
            except Exception:
                log.exception("orphan sweep failed")
    return out


JOB = Job(name="retention", interval=6 * 3600, run=run_once, initial_delay=180)
