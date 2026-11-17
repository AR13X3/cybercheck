"""Tests for the CT ingest writer (cybercheck/ingest.py): hits survive a database outage. No network, no database."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import orjson
import psycopg
import psycopg_pool
import pytest

from cybercheck import ingest
from cybercheck.scoring import Watchlist

WL = Watchlist({
    "brands": [{"id": "commbank", "name": "Commonwealth Bank", "keywords": ["commbank"],
                "official_domains": ["commbank.com.au"]}],
    "bait_words": {"strong": ["login", "verify"], "weak": []},
})


def run(coro):
    return asyncio.run(coro)


def cert(*domains: str) -> bytes:
    return orjson.dumps({"message_type": "certificate_update",
                         "data": {"leaf_cert": {"all_domains": list(domains), "issuer": {"O": "Let's Encrypt"}},
                                  "source": {"name": "Test log"}}})


class FakeConn:
    def __init__(self):
        self.in_tx = False

    @asynccontextmanager
    async def transaction(self):
        self.in_tx = True
        try:
            yield
        finally:
            self.in_tx = False


class Db:
    """Stands in for db.pool(), store_hit, the clock and the back-off sleep."""

    def __init__(self, monkeypatch, fail=None, attempt_s: float = 30.0):
        self.fail = fail or (lambda: None)     # returns an exception to raise for this attempt, or None
        self.attempt_s = attempt_s             # time one failed attempt takes (psycopg_pool waits 30 s)
        self.now = 1000.0
        self.sleeps: list[float] = []
        self.stored: list[tuple[str, bool]] = []
        self.store_error: Exception | None = None
        db = self

        class Pool:
            @asynccontextmanager
            async def connection(self):
                err = db.fail()
                if err is not None:
                    db.now += db.attempt_s
                    raise err
                yield FakeConn()

        async def pool():
            return Pool()

        async def store_hit(conn, hit, source, issuer, ct_log):
            if db.store_error is not None:
                raise db.store_error
            db.stored.append((hit.hostname, conn.in_tx))
            return len(db.stored), True

        async def sleep(seconds):
            db.sleeps.append(seconds)
            db.now += seconds

        monkeypatch.setattr(ingest.db, "pool", pool)
        monkeypatch.setattr(ingest, "store_hit", store_hit)
        monkeypatch.setattr(ingest, "_sleep", sleep)
        monkeypatch.setattr(ingest, "_clock", lambda: db.now)


def fail_times(*errors):
    errors = list(errors)
    return lambda: errors.pop(0) if errors else None


async def feed_and_drain(messages, cache=None, maxsize=ingest.BACKLOG_MAX):
    """Run handle() on the messages and the writer until the backlog is empty."""
    cache = cache or ingest.SeenCache()
    counters = ingest.Counters()
    q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
    task = asyncio.create_task(ingest.writer(q, cache))
    for m in messages:
        await asyncio.wait_for(ingest.handle(m, WL, cache, counters, q), 1)
    await asyncio.wait_for(q.join(), 5)
    task.cancel()
    return cache, counters


def test_seen_cache_forget():
    c = ingest.SeenCache(size=10)
    assert not c.seen("a.example") and c.seen("a.example")
    c.forget("a.example")
    c.forget("never-seen.example")
    assert not c.seen("a.example")


def test_database_outage_is_retried_and_the_hit_is_kept(monkeypatch, caplog):
    db = Db(monkeypatch, fail_times(
        psycopg_pool.PoolTimeout("couldn't get a connection after 30.00 sec"),
        psycopg.OperationalError("consuming input failed: server closed the connection unexpectedly"),
        psycopg.errors.AdminShutdown("terminating connection due to administrator command")))
    with caplog.at_level(logging.INFO, logger="cybercheck.ingest"):
        cache, _ = run(feed_and_drain([cert("commbank-login.top")]))
    assert db.stored == [("commbank-login.top", True)]           # stored once, inside one transaction
    assert db.sleeps == [1, 2, 4]
    assert cache.seen("commbank-login.top")                       # not forgotten: it was stored
    assert "database back" in caplog.text and "dropped" not in caplog.text


def test_backoff_is_capped(monkeypatch):
    db = Db(monkeypatch, fail_times(*[psycopg.OperationalError("connection refused")] * 9))
    run(feed_and_drain([cert("commbank-login.top")]))
    assert db.sleeps == [1, 2, 4, 8, 16, 32, 60, 60, 60]
    assert db.stored == [("commbank-login.top", True)]


def test_hits_found_during_an_outage_wait_in_the_backlog(monkeypatch):
    down = {"until": 1000.0 + 200}
    db = Db(monkeypatch)
    db.fail = lambda: psycopg_pool.PoolTimeout("timeout") if db.now < down["until"] else None
    run(feed_and_drain([cert("commbank-login.top"), cert("commbank-verify.xyz", "www.example.com")]))
    assert [h for h, _ in db.stored] == ["commbank-login.top", "commbank-verify.xyz"]


def test_retries_give_up_after_the_limit_and_the_name_is_scored_again(monkeypatch, caplog):
    monkeypatch.setattr(ingest, "RETRY_GIVE_UP_S", 100.0)
    db = Db(monkeypatch, attempt_s=0.0)
    db.fail = lambda: psycopg_pool.PoolTimeout("timeout") if db.now < 1000.0 + 150 else None
    cache = ingest.SeenCache()
    with caplog.at_level(logging.WARNING, logger="cybercheck.ingest"):
        run(feed_and_drain([cert("commbank-login.top"), cert("commbank-verify.xyz")], cache))
    assert "dropped watch 57 commbank commbank-login.top" in caplog.text
    assert db.stored == [("commbank-verify.xyz", True)]           # the next hit is stored once the database is back
    assert not cache.seen("commbank-login.top")                    # forgotten: its next certificate is scored again
    assert cache.seen("commbank-verify.xyz")


def test_non_transient_error_drops_the_hit_without_retrying(monkeypatch, caplog):
    db = Db(monkeypatch)
    db.store_error = psycopg.errors.UndefinedColumn('column "watch_until" does not exist')
    cache = ingest.SeenCache()
    with caplog.at_level(logging.WARNING, logger="cybercheck.ingest"):
        run(feed_and_drain([cert("commbank-login.top")], cache))
    assert db.sleeps == [] and db.stored == []
    assert "dropped watch 57 commbank commbank-login.top" in caplog.text
    assert not cache.seen("commbank-login.top")


def test_full_backlog_never_blocks_the_stream_and_logs_what_is_dropped(caplog):
    async def go():
        cache, counters = ingest.SeenCache(), ingest.Counters()
        q: asyncio.Queue = asyncio.Queue(maxsize=1)                # no writer: the database is "down"
        with caplog.at_level(logging.WARNING, logger="cybercheck.ingest"):
            await asyncio.wait_for(ingest.handle(cert("commbank-login.top", "commbank-verify.xyz"), WL, cache,
                                                 counters, q), 1)
        assert q.qsize() == 1 and q.get_nowait()[0].hostname == "commbank-login.top"
        assert counters.hits == 2
        assert "backlog full" in caplog.text and "commbank-verify.xyz" in caplog.text
        assert cache.seen("commbank-login.top") and not cache.seen("commbank-verify.xyz")
    run(go())


def test_backlog_cap_bounds_memory():
    assert 1000 <= ingest.BACKLOG_MAX <= 20_000                    # ~1.5 KB a hit; ingest has mem_limit 384m


@pytest.mark.parametrize("err", [psycopg_pool.PoolTimeout("x"), psycopg_pool.PoolClosed("x"),
                                 psycopg.errors.SerializationFailure("x"), psycopg.errors.CannotConnectNow("x")])
def test_transient_error_classes(err):
    assert isinstance(err, ingest.TRANSIENT_DB_ERRORS)
