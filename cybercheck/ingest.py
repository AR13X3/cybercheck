"""Read the certstream-server-go websocket (lite stream), score every hostname, store suspicious ones.

certstream does not replay missed entries, so a hit must not be lost to a short database outage: hits wait
in a bounded in-memory backlog (BACKLOG_MAX) and the writer retries a database outage with capped back-off.
A hit that is dropped (backlog full, a non-transient error, or retries given up) is logged with its hostname
and forgotten by the SeenCache, so a later certificate for the same name is scored again. The backlog lives
in memory only: hits still waiting are lost if the ingest container restarts.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from datetime import datetime, timezone

import orjson
import psycopg
import websockets

from . import db
from .config import settings
from .scoring import default_watchlist
from .store import store_hit

log = logging.getLogger("cybercheck.ingest")

BACKLOG_MAX = 10_000              # hits waiting for the database; ~1.5 KB each, so ~15-30 MB at most (mem_limit 384m)
RETRY_MAX_DELAY_S = 60.0          # back-off between attempts: 1, 2, 4 ... 60 s (plus the pool's 30 s getconn timeout)
RETRY_GIVE_UP_S = 6 * 3600.0      # a hit that still cannot be stored after this long is dropped (and logged)
RETRY_LOG_EVERY = 10              # while retrying, log one line per this many attempts

# Errors worth retrying: lost or refused connections, pool timeouts (psycopg_pool.PoolTimeout), server
# restarts or shutdowns, paused logins, deadlocks and serialization failures. All subclass this.
TRANSIENT_DB_ERRORS = (psycopg.OperationalError,)


async def _sleep(seconds: float) -> None:   # replaced in tests
    await asyncio.sleep(seconds)


_clock = time.monotonic                     # replaced in tests


class SeenCache:
    """Bounded LRU of hostnames already scored (CT repeats names across precerts, certs and logs)."""

    def __init__(self, size: int = 300_000):
        self.size = size
        self._d: OrderedDict[str, None] = OrderedDict()

    def seen(self, key: str) -> bool:
        if key in self._d:
            self._d.move_to_end(key)
            return True
        self._d[key] = None
        if len(self._d) > self.size:
            self._d.popitem(last=False)
        return False

    def forget(self, key: str) -> None:
        """Score this hostname again next time (its hit could not be stored)."""
        self._d.pop(key, None)


class Counters:
    def __init__(self):
        self.reset()
        self.last_message_at = 0.0

    def reset(self):
        self.certs = self.hostnames = self.scored = self.hits = 0


async def flush_stats(counters: Counters) -> None:
    """Write per-minute counters so the dashboard can show stream health."""
    while True:
        await asyncio.sleep(60)
        c = (counters.certs, counters.hostnames, counters.scored, counters.hits)
        counters.reset()
        try:
            p = await db.pool()
            async with p.connection() as conn:
                await conn.execute(
                    "INSERT INTO ingest_stats (minute, source, certs, hostnames, scored, hits) "
                    "VALUES (date_trunc('minute', now()), 'ct', %s, %s, %s, %s) "
                    "ON CONFLICT (minute, source) DO UPDATE SET certs = ingest_stats.certs + EXCLUDED.certs, "
                    "hostnames = ingest_stats.hostnames + EXCLUDED.hostnames, scored = ingest_stats.scored + EXCLUDED.scored, "
                    "hits = ingest_stats.hits + EXCLUDED.hits", c)
                await conn.execute("DELETE FROM ingest_stats WHERE minute < now() - interval '14 days'")
                await db.kv_set(conn, "ingest:heartbeat", {"at": datetime.now(timezone.utc).isoformat(),
                                                          "last_message_at": counters.last_message_at})
        except Exception:
            log.exception("stats flush failed")


async def handle(message: bytes | str, wl, cache: SeenCache, counters: Counters, hits_q: asyncio.Queue) -> None:
    try:
        msg = orjson.loads(message)
    except orjson.JSONDecodeError:
        return
    if msg.get("message_type") != "certificate_update":
        return
    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    domains = leaf.get("all_domains") or []
    counters.certs += 1
    counters.last_message_at = time.time()
    issuer = ((leaf.get("issuer") or {}).get("O")) or ((leaf.get("issuer") or {}).get("CN"))
    ct_log = (data.get("source") or {}).get("name")
    for raw in domains:
        counters.hostnames += 1
        if not isinstance(raw, str):
            continue
        key = raw.lower().lstrip("*.")
        if cache.seen(key):
            continue
        counters.scored += 1
        hit = wl.score_hostname(raw)
        if hit is not None:
            counters.hits += 1
            try:   # never block the stream on the database: certstream would not replay what we miss
                hits_q.put_nowait((hit, issuer, ct_log, key))
            except asyncio.QueueFull:
                cache.forget(key)
                log.warning("backlog full (%d hits waiting for the database): dropped %s %d %s %s",
                            hits_q.qsize(), hit.tier, hit.score, hit.brand_id, hit.hostname)


async def _store(hit, issuer, ct_log) -> tuple[int, bool]:
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():   # all or nothing, so a retry never counts half a hit twice
            return await store_hit(conn, hit, "ct", issuer, ct_log)


async def store_with_retry(hit, issuer, ct_log, backlog: asyncio.Queue | None = None) -> tuple[int, bool] | None:
    """Store one hit, retrying database outages with capped back-off for up to RETRY_GIVE_UP_S.
    Returns (domain_id, inserted), or None if the hit was not stored (already logged)."""
    started = _clock()
    attempt = 0
    while True:
        try:
            result = await _store(hit, issuer, ct_log)
        except TRANSIENT_DB_ERRORS as e:
            attempt += 1
            waited = _clock() - started
            err = f"{type(e).__name__}: {e}"[:300]
            if waited >= RETRY_GIVE_UP_S:
                log.error("dropped %s %d %s %s: database still unavailable after %d attempts over %.0f s (%s)",
                          hit.tier, hit.score, hit.brand_id, hit.hostname, attempt, waited, err)
                return None
            if attempt == 1 or attempt % RETRY_LOG_EVERY == 0:
                log.warning("database unavailable, retrying %s (attempt %d, %d more waiting): %s",
                            hit.hostname, attempt, backlog.qsize() if backlog is not None else 0, err)
            await _sleep(min(2.0 ** (attempt - 1), RETRY_MAX_DELAY_S))
        except Exception:
            log.exception("dropped %s %d %s %s: could not store it", hit.tier, hit.score, hit.brand_id, hit.hostname)
            return None
        else:
            if attempt:
                log.info("database back: stored %s after %d attempts (%d more waiting)", hit.hostname, attempt + 1,
                         backlog.qsize() if backlog is not None else 0)
            return result


async def writer(hits_q: asyncio.Queue, cache: SeenCache | None = None) -> None:
    while True:
        hit, issuer, ct_log, key = await hits_q.get()
        try:
            result = await store_with_retry(hit, issuer, ct_log, hits_q)
        finally:
            hits_q.task_done()
        if result is None:
            if cache is not None:
                cache.forget(key)   # a later certificate for it is scored and stored again
            continue
        _dom_id, inserted = result
        if inserted:
            log.info("NEW %-6s %3d %-14s %s", hit.tier, hit.score, hit.brand_id, hit.hostname)


async def run() -> None:
    wl = default_watchlist()
    cache = SeenCache()
    counters = Counters()
    hits_q: asyncio.Queue = asyncio.Queue(maxsize=BACKLOG_MAX)
    background = [asyncio.create_task(flush_stats(counters)),   # keep references so the tasks are not collected
                  asyncio.create_task(writer(hits_q, cache))]
    url = settings().certstream_url
    backoff = 1
    while True:
        try:
            log.info("connecting to %s", url)
            async with websockets.connect(url, ping_interval=30, ping_timeout=30, max_size=2**22,
                                          open_timeout=20) as ws:
                backoff = 1
                log.info("connected")
                async for message in ws:
                    await handle(message, wl, cache, counters, hits_q)
        except (OSError, websockets.WebSocketException, asyncio.TimeoutError) as e:
            log.warning("stream error: %s; reconnecting in %ss", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)
