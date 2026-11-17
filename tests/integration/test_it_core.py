"""Integration tests for the core group against a real (disposable) Postgres 17: CT ingest, store_hit upserts,
the enrich job, the housekeeping job, the rescore CLI, worker status rows and concurrent migrations.

Every network boundary is stubbed: the certstream websocket (a fake connect), DNS (a fake dnspython resolver),
RDAP / IANA bootstrap (httpx.MockTransport). A guard fails the test on any socket connection that is not to the
disposable server on 127.0.0.1. The database is real: rows are created the way the pipeline creates them
(store_hit for domains, the fetch job's INSERT for pages, the reporting engine's INSERT for reports,
cybercheck.ai.budget for ai_calls, enrich.write_update for checks) and the real jobs run over them.
"""
from __future__ import annotations

import asyncio
import dataclasses
import functools
import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
import httpx
import orjson
import psycopg
import pytest

from cybercheck import config, db, enrich, ingest, worker
from cybercheck.scoring import Watchlist, default_watchlist
from cybercheck.store import store_hit

UTC = timezone.utc
ADMIN = __import__("os").environ.get("CYBERCHECK_IT_PG", "")


# ---------------------------------------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def only_local_sockets(monkeypatch):
    """Any Python-level connection to something other than 127.0.0.1 fails the test (libpq's own socket to the
    disposable server is opened in C and is not affected)."""
    real_connect = socket.socket.connect
    real_sendto = socket.socket.sendto

    def local(addr) -> bool:
        return isinstance(addr, tuple) and addr[0] in ("127.0.0.1", "::1", "localhost")

    def connect(self, addr, *a, **kw):
        if self.family in (socket.AF_INET, socket.AF_INET6) and not local(addr):
            raise AssertionError(f"test tried to connect to {addr}")
        return real_connect(self, addr, *a, **kw)

    def sendto(self, data, *args):
        addr = args[-1]
        if self.family in (socket.AF_INET, socket.AF_INET6) and not local(addr):
            raise AssertionError(f"test tried to send to {addr}")
        return real_sendto(self, data, *args)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "sendto", sendto)


@pytest.fixture
def clean(it_db):
    """Empty tables before each test (only in this module's own database)."""
    with db.connect_sync() as c:
        c.execute("TRUNCATE domains, kv, ingest_stats, ai_calls RESTART IDENTITY CASCADE")
    yield it_db


def arun(coro):
    """Run a coroutine on a fresh loop and close the db pool on that same loop."""
    async def main():
        try:
            return await coro
        finally:
            await db.close()
    return asyncio.run(main())


def q(sql, params=None) -> list[dict]:
    with db.connect_sync() as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else []


def q1(sql, params=None) -> dict | None:
    rows = q(sql, params)
    return rows[0] if rows else None


def dom(name: str) -> dict:
    return q1("SELECT * FROM domains WHERE registered_domain = %s", (name,))


def events(domain_id: int, kind: str | None = None) -> list[dict]:
    if kind:
        return q("SELECT kind, detail, at FROM domain_events WHERE domain_id = %s AND kind = %s ORDER BY id",
                 (domain_id, kind))
    return q("SELECT kind, detail, at FROM domain_events WHERE domain_id = %s ORDER BY id", (domain_id,))


def db_now() -> datetime:
    return q1("SELECT now() AS n")["n"]


WL = None


def wl():
    global WL
    if WL is None:
        WL = default_watchlist()
    return WL


def hit(hostname: str, watchlist=None):
    h = (watchlist or wl()).score_hostname(hostname)
    assert h is not None, hostname
    return h


async def store(hostname: str, source="ct", issuer="Let's Encrypt", ct_log="Google 'Argon2026h2' log", watchlist=None):
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            return await store_hit(conn, hit(hostname, watchlist), source, issuer, ct_log)


def store_sync(*hostnames, **kw) -> int:
    async def go():
        ids = [await store(h, **kw) for h in hostnames]
        return ids[-1][0]
    return arun(go())


def admin(sql, params=None, dbname=None):
    url = ADMIN if dbname is None else ADMIN.rsplit("/", 1)[0] + "/" + dbname
    with psycopg.connect(url, autocommit=True) as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else None


# ---------------------------------------------------------------------------------------------- store_hit

def test_store_hit_insert_then_repeat_sightings_and_best_score(clean):
    async def go():
        first = await store("www.commbank-login.top")
        again = await store("www.commbank-login.top")
        better = await store("secure.commbank-login.top")
        worse = await store("login.commbank-login.top")
        return first, again, better, worse
    first, again, better, worse = arun(go())
    did = first[0]
    assert first == (did, True) and again == (did, False) and better == (did, False) and worse == (did, False)

    d = dom("commbank-login.top")
    assert d["id"] == did and d["tld"] == "top" and d["brand_id"] == "commbank" and d["unicode_domain"] is None
    assert d["hostnames"] == ["www.commbank-login.top", "secure.commbank-login.top", "login.commbank-login.top"]
    assert d["sightings"] == 4
    assert d["score"] == 81 and d["tier"] == "high"               # the best hit wins ...
    assert d["reasons"] == hit("secure.commbank-login.top").reasons  # ... with its reasons; the 69 later did not undo it
    assert d["source"] == "ct" and d["issuer"] == "Let's Encrypt" and d["ct_log"] == "Google 'Argon2026h2' log"
    assert d["status"] == "open" and d["dns_state"] == "unknown" and d["takedown_at"] is None
    assert d["last_seen"] >= d["first_seen"]
    now = db_now()
    assert d["next_check_at"] <= now
    assert timedelta(days=13, hours=23) < d["watch_until"] - d["first_seen"] < timedelta(days=14, hours=1)

    evs = events(did)
    assert [e["kind"] for e in evs] == ["first_seen"]
    assert evs[0]["detail"] == {"source": "ct", "hostname": "www.commbank-login.top", "score": 69, "tier": "review",
                                "brand": "commbank", "issuer": "Let's Encrypt", "ct_log": "Google 'Argon2026h2' log"}


def test_store_hit_reschedules_checks_and_extends_the_watch_window(clean):
    did = store_sync("www.commbank-login.top")

    # enrich scheduled the next check 3 days out: a new certificate pulls it in to <= 10 minutes
    q("UPDATE domains SET next_check_at = now() + interval '3 days' WHERE id = %s", (did,))
    store_sync("www.commbank-login.top")
    d = dom("commbank-login.top")
    assert d["next_check_at"] <= db_now() + timedelta(minutes=10)
    assert d["next_check_at"] >= db_now() + timedelta(minutes=9)

    # enrich stopped checking (watch window over): a new certificate re-arms it now
    q("UPDATE domains SET next_check_at = NULL, watch_until = now() - interval '1 day' WHERE id = %s", (did,))
    store_sync("www.commbank-login.top")
    d = dom("commbank-login.top")
    assert d["next_check_at"] <= db_now()
    assert d["watch_until"] > db_now() + timedelta(days=13, hours=23)

    # a sooner check and a longer window are kept
    q("UPDATE domains SET next_check_at = now() + interval '2 minutes', watch_until = now() + interval '30 days' "
      "WHERE id = %s", (did,))
    store_sync("www.commbank-login.top")
    d = dom("commbank-login.top")
    assert db_now() + timedelta(minutes=1) < d["next_check_at"] <= db_now() + timedelta(minutes=2)
    assert d["watch_until"] > db_now() + timedelta(days=29)
    assert d["sightings"] == 4


def test_store_hit_source_upgrade_rules(clean):
    store_sync("netbank-verify.xyz", source="czds", issuer=None, ct_log=None)
    store_sync("netbank-verify.xyz", source="czds", issuer=None, ct_log=None)   # next day's zone diff
    assert dom("netbank-verify.xyz")["source"] == "czds"
    store_sync("www.netbank-verify.xyz", source="ct")                            # now in CT: public data
    assert dom("netbank-verify.xyz")["source"] == "ct"
    store_sync("netbank-verify.xyz", source="czds", issuer=None, ct_log=None)
    d = dom("netbank-verify.xyz")
    assert d["source"] == "ct" and d["sightings"] == 4 and d["issuer"] is None   # issuer is from the first row
    assert events(d["id"], "first_seen")[0]["detail"]["source"] == "czds"

    store_sync("westpac-secure.top", source="bot", issuer=None, ct_log=None)
    store_sync("www.westpac-secure.top", source="ct")
    assert dom("westpac-secure.top")["source"] == "bot"

    store_sync("telstra-billing.top", source="manual", issuer=None, ct_log=None)
    store_sync("telstra-billing.top", source="ct")
    assert dom("telstra-billing.top")["source"] == "manual"


def test_store_hit_reappeared_after_takedown(clean):
    did = store_sync("auspost-delivery.top")
    assert events(did, "reappeared") == []
    q("UPDATE domains SET takedown_at = now() - interval '2 days', takedown_signal = 'nxdomain', next_check_at = NULL "
      "WHERE id = %s", (did,))
    old_takedown = dom("auspost-delivery.top")["takedown_at"]

    store_sync("www.auspost-delivery.top")
    d = dom("auspost-delivery.top")
    assert d["takedown_at"] is None and d["takedown_signal"] is None
    assert d["next_check_at"] <= db_now()
    ev = events(did, "reappeared")
    assert len(ev) == 1
    assert ev[0]["detail"] == {"hostname": "www.auspost-delivery.top", "taken_down_at": str(old_takedown)}

    store_sync("login.auspost-delivery.top")              # still up: no second "reappeared"
    assert len(events(did, "reappeared")) == 1
    assert [e["kind"] for e in events(did)] == ["first_seen", "reappeared"]


def test_store_hit_caps_hostnames_at_50(clean):
    names = [f"s{i}.commbank-login.top" for i in range(60)]
    did = store_sync(*names)
    d = dom("commbank-login.top")
    assert d["hostnames"] == names[:50] and d["sightings"] == 60
    store_sync("s3.commbank-login.top", "s59.commbank-login.top")
    d = dom("commbank-login.top")
    assert len(d["hostnames"]) == 50 and d["sightings"] == 62
    assert q1("SELECT cardinality(hostnames) AS n FROM domains WHERE id = %s", (did,))["n"] == 50


def test_store_hit_unicode_domains(clean):
    store_sync("xn--cmmbank-login-prj.top", "www.xn--cmmbank-login-prj.top")
    d = dom("xn--cmmbank-login-prj.top")
    assert d["unicode_domain"] == "cοmmbank-login.top"            # Greek omicron kept as text
    assert d["hostnames"] == ["xn--cmmbank-login-prj.top", "www.xn--cmmbank-login-prj.top"]
    assert d["tier"] == "high"
    assert q1("SELECT count(*) AS n FROM domains WHERE unicode_domain = %s", ("cοmmbank-login.top",))["n"] == 1

    store_sync("commbank-login.xn--p1ai")                           # IDN TLD (.рф)
    d = dom("commbank-login.xn--p1ai")
    assert d["tld"] == "xn--p1ai" and d["unicode_domain"] == "commbank-login.рф"


def test_store_hit_cleans_certificate_text(clean):
    """issuer / ct_log come from certificates and CT log metadata: Postgres text and jsonb cannot hold NUL, so a
    NUL there must not make the hit unstorable."""
    did = store_sync("www.commbank-login.top", issuer="Evil\x00 CA\r\n Ltd" + "x" * 500, ct_log="Log\x00 One")
    d = dom("commbank-login.top")
    assert "\x00" not in d["issuer"] and d["issuer"].startswith("Evil") and len(d["issuer"]) <= 200
    assert d["ct_log"] == "Log One"
    assert events(did, "first_seen")[0]["detail"]["issuer"] == d["issuer"]
    store_sync("secure.commbank-login.top", issuer=["not", "a", "string"], ct_log=12)
    assert dom("commbank-login.top")["sightings"] == 2


# A crafted xn-- label can punycode-decode to a lone UTF-16 surrogate. scoring keeps it in unicode_domain and in a
# "mixed scripts" reason, but it is not valid Unicode: psycopg cannot encode it for a text column and Postgres jsonb
# rejects its \ud800 escape.
SURR_REG = "xn--cmmbank-8of35100c.top"                 # 'cοmmbank\ud800.top' (Greek omicron + lone surrogate)
SURR_SUB = "xn--lgin-55d77363a.commbank-secure.top"    # sub-domain label 'lоgin\ud800' (Cyrillic o + surrogate)


def test_store_hit_idn_that_decodes_to_a_lone_surrogate(clean, caplog):
    """Such a label is not valid IDNA (normalize.decode_idna keeps it as xn--), so nothing invalid reaches
    Postgres. It is still scored on its xn-- form and stored, and store_hit's own guards stay in place."""
    h = hit(SURR_REG)
    assert h.unicode_domain is None and not any("\ud800" in r["why"] for r in h.reasons)
    did = store_sync(SURR_REG, "www." + SURR_REG)
    d = dom(SURR_REG)
    assert d["id"] == did and d["unicode_domain"] is None
    assert d["score"] == h.score and d["tier"] == h.tier and d["sightings"] == 2
    assert d["hostnames"] == [SURR_REG, "www." + SURR_REG]
    assert not any("\ufffd" in r["why"] or "\ud800" in r["why"] for r in d["reasons"])

    # the bad label only in a sub-domain of a row already stored: stored safely, no invalid text
    sid = store_sync("www.commbank-secure.top")
    store_sync(SURR_SUB)
    s = dom("commbank-secure.top")
    assert s["id"] == sid and s["sightings"] == 2 and s["unicode_domain"] is None
    assert SURR_SUB in s["hostnames"]
    assert not any("\ud800" in r["why"] for r in s["reasons"])

    # through the CT ingest writer: stored, not dropped
    caplog.set_level(logging.INFO, logger="cybercheck.ingest")

    async def go():
        cache, counters = ingest.SeenCache(), ingest.Counters()
        hits_q: asyncio.Queue = asyncio.Queue(maxsize=ingest.BACKLOG_MAX)
        writer = asyncio.create_task(ingest.writer(hits_q, cache))
        try:
            await ingest.handle(cert("xn--commbnk-6fg84380c.top"), wl(), cache, counters, hits_q)
            await asyncio.wait_for(hits_q.join(), 10)
        finally:
            writer.cancel()
    arun(go())
    stored = dom("xn--commbnk-6fg84380c.top")
    assert stored is not None and stored["unicode_domain"] is None       # kept in its xn-- form
    assert "dropped" not in caplog.text


def test_store_hit_concurrent_first_sightings(clean):
    """Many CT writers see the same new domain at once: one insert, every hostname kept, one first_seen event."""
    names = [f"h{i}.commbank-login.top" for i in range(5)] * 2

    async def one(name, gate):
        p = await db.pool()
        async with p.connection() as conn:
            async with conn.transaction():
                await gate.wait()
                return await store_hit(conn, hit(name), "ct", "Let's Encrypt", "log")

    async def go():
        gate = asyncio.Event()
        tasks = [asyncio.create_task(one(n, gate)) for n in names]
        await asyncio.sleep(0.2)
        gate.set()
        return await asyncio.gather(*tasks)
    results = arun(go())
    assert len({r[0] for r in results}) == 1
    assert sum(1 for r in results if r[1]) == 1
    d = dom("commbank-login.top")
    assert d["sightings"] == 10 and sorted(d["hostnames"]) == sorted(set(names))
    assert len(events(d["id"], "first_seen")) == 1


# ---------------------------------------------------------------------------------------------- ingest

def cert(*domains, issuer=None, log_name="Google 'Argon2026h2' log", kind="certificate_update") -> bytes:
    return orjson.dumps({"message_type": kind,
                         "data": {"leaf_cert": {"all_domains": list(domains),
                                                "issuer": issuer if issuer is not None else {"O": "Let's Encrypt", "CN": "R11"}},
                                  "source": {"name": log_name, "url": "https://ct.googleapis.com/logs/us1/argon2026h2/"}}})


class StopStream(Exception):
    pass


class FakeWebsocket:
    def __init__(self, messages):
        self.messages = messages

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for m in self.messages:
            await asyncio.sleep(0)
            yield m


class FakeConnect:
    def __init__(self, outcome):
        self.outcome = outcome

    async def __aenter__(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            await self.outcome()
        return FakeWebsocket(self.outcome)

    async def __aexit__(self, *exc):
        return False


def test_ingest_run_stores_hits_from_a_ct_stream(clean, monkeypatch):
    stream = [
        cert("commbank-login.top", "*.commbank-login.top", "www.commbank-login.top"),
        cert("commbank-login.top", "*.commbank-login.top", "www.commbank-login.top"),    # cert after precert
        b"not json",
        orjson.dumps({"message_type": "heartbeat", "timestamp": 1}),
        cert("xn--cmmbank-login-prj.top", "www.xn--cmmbank-login-prj.top", issuer={"C": "US", "O": None, "CN": "E5"},
             log_name="Cloudflare 'Nimbus2026' Log"),
        cert("example.com", "shop.example.org", "www.commbank.com.au"),                  # nothing / official
        cert("SECURE.COMMBANK-LOGIN.TOP.", None, 123),                                   # odd entries
        cert("secure.commbank-login.com.au"),
        cert("auspost-delivery.top", issuer={"O": "Evil\x00CA"}),
    ]
    expected = {"commbank-login.top": 3, "xn--cmmbank-login-prj.top": 2, "commbank-login.com.au": 1,
                "auspost-delivery.top": 1}

    async def stop_when_stored():
        for _ in range(200):
            rows = await asyncio.to_thread(q, "SELECT registered_domain, sightings FROM domains")
            if {r["registered_domain"]: r["sightings"] for r in rows} == expected:
                raise StopStream()
            await asyncio.sleep(0.05)
        raise AssertionError(f"hits not stored: {rows}")

    script = [OSError("connection refused"), stream, stop_when_stored]
    calls = []

    def fake_connect(url, **kw):
        calls.append(url)
        return FakeConnect(script.pop(0))
    monkeypatch.setattr(ingest.websockets, "connect", fake_connect)

    async def go():
        with pytest.raises(StopStream):
            await asyncio.wait_for(ingest.run(), 30)
    arun(go())
    assert calls == [config.settings().certstream_url] * 3        # refused, streamed, reconnected

    d = dom("commbank-login.top")
    assert d["hostnames"] == ["commbank-login.top", "www.commbank-login.top", "secure.commbank-login.top"]
    assert d["sightings"] == 3 and d["score"] == 81 and d["tier"] == "high"
    assert d["issuer"] == "Let's Encrypt" and d["ct_log"] == "Google 'Argon2026h2' log" and d["source"] == "ct"
    idn = dom("xn--cmmbank-login-prj.top")
    assert idn["unicode_domain"] == "cοmmbank-login.top" and idn["issuer"] == "E5"
    assert idn["ct_log"] == "Cloudflare 'Nimbus2026' Log"
    assert idn["hostnames"] == ["xn--cmmbank-login-prj.top", "www.xn--cmmbank-login-prj.top"]
    au = dom("commbank-login.com.au")
    assert au["tld"] == "com.au" and au["tier"] == hit("secure.commbank-login.com.au").tier
    assert dom("auspost-delivery.top")["issuer"] == "Evil CA"
    assert q1("SELECT count(*) AS n FROM domain_events WHERE kind = 'first_seen'")["n"] == 4
    assert dom("example.com") is None and dom("commbank.com.au") is None


def test_ingest_writer_survives_a_real_database_outage(clean, monkeypatch, caplog):
    """Postgres goes away (connections terminated, logins refused, like a restart or a paused login) while CT
    hits keep arriving: they wait in the backlog, are retried, and every one is stored exactly once."""
    dbname = clean.rsplit("/", 1)[1]
    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def fast_sleep(seconds):
        sleeps.append(seconds)
        await real_sleep(0.05)
    monkeypatch.setattr(ingest, "_sleep", fast_sleep)
    caplog.set_level(logging.INFO, logger="cybercheck.ingest")

    def outage(on: bool):
        admin(f'ALTER DATABASE "{dbname}" WITH ALLOW_CONNECTIONS {"false" if on else "true"}')
        if on:
            admin("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                  (dbname,))

    async def go():
        p = await db.pool()
        p.timeout = 1.0           # production waits 30 s per attempt for a connection; same code path, faster
        cache, counters = ingest.SeenCache(), ingest.Counters()
        hits_q: asyncio.Queue = asyncio.Queue(maxsize=ingest.BACKLOG_MAX)
        writer = asyncio.create_task(ingest.writer(hits_q, cache))
        try:
            await ingest.handle(cert("www.commbank-login.top"), wl(), cache, counters, hits_q)
            await asyncio.wait_for(hits_q.join(), 10)
            await asyncio.to_thread(outage, True)
            for m in (cert("secure.commbank-login.top"), cert("auspost-delivery.top", "www.auspost-delivery.top"),
                      cert("xn--cmmbank-login-prj.top")):
                await ingest.handle(m, wl(), cache, counters, hits_q)
            for _ in range(400):
                if len(sleeps) >= 3:
                    break
                await real_sleep(0.05)
            assert len(sleeps) >= 3, "writer never hit the outage"
            assert hits_q.qsize() >= 3                 # the others wait in the backlog meanwhile
            await asyncio.to_thread(outage, False)
            await asyncio.wait_for(hits_q.join(), 90)
        finally:
            writer.cancel()
            await asyncio.to_thread(outage, False)
    try:
        arun(go())
    finally:
        outage(False)

    assert sleeps[:3] == [1.0, 2.0, 4.0]
    d = dom("commbank-login.top")
    assert d["sightings"] == 2 and d["hostnames"] == ["www.commbank-login.top", "secure.commbank-login.top"]
    a = dom("auspost-delivery.top")
    assert a["sightings"] == 2 and a["hostnames"] == ["auspost-delivery.top", "www.auspost-delivery.top"]
    assert dom("xn--cmmbank-login-prj.top")["sightings"] == 1
    assert q1("SELECT count(*) AS n FROM domain_events WHERE kind = 'first_seen'")["n"] == 3
    text = caplog.text
    assert "database unavailable, retrying secure.commbank-login.top" in text
    assert "database back: stored secure.commbank-login.top" in text
    assert "dropped" not in text


def test_ingest_flush_stats_writes_counters_and_heartbeat(clean, monkeypatch):
    q("INSERT INTO ingest_stats (minute, source, certs) VALUES (date_trunc('minute', now() - interval '15 days'), 'ct', 7), "
      "(date_trunc('minute', now() - interval '13 days'), 'ct', 5)")
    counters = ingest.Counters()
    counters.last_message_at = 1763280000.5
    rounds = [(10, 25, 20, 2), (5, 10, 8, 1), (0, 0, 0, 0)]
    real_sleep = asyncio.sleep

    async def fake_sleep(delay, *a, **kw):
        if delay == 60:
            if not rounds:
                raise StopStream()
            counters.certs, counters.hostnames, counters.scored, counters.hits = rounds.pop(0)
            return await real_sleep(0)
        return await real_sleep(delay, *a, **kw)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def go():
        with pytest.raises(StopStream):
            await ingest.flush_stats(counters)
    arun(go())
    recent = q("SELECT * FROM ingest_stats WHERE minute > now() - interval '1 hour' ORDER BY minute")
    assert 1 <= len(recent) <= 2
    assert [sum(r[k] for r in recent) for k in ("certs", "hostnames", "scored", "hits")] == [15, 35, 28, 3]
    assert [r["certs"] for r in q("SELECT certs FROM ingest_stats WHERE minute < now() - interval '1 hour'")] == [5]
    hb = q1("SELECT value FROM kv WHERE key = 'ingest:heartbeat'")["value"]
    assert hb["last_message_at"] == 1763280000.5 and datetime.fromisoformat(hb["at"]).tzinfo is not None


# ---------------------------------------------------------------------------------------------- enrich

HANG = object()

BOOT_DNS = {"services": [[["top", "xyz"], ["https://rdap.nic.top/"]],
                         [["au"], ["https://rdap.cctld.au/rdap/"]],
                         [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                         [["dev"], ["https://pubapi.registry.google/rdap/"]]]}
BOOT_V4 = {"services": [[["104.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
                        [["1.0.0.0/8"], ["https://rdap.apnic.net/"]]]}
BOOT_V6 = {"services": [[["2400::/12"], ["https://rdap.apnic.net/"]]]}

RDAP_IP = {
    "objectClassName": "ip network", "handle": "NET-104-16-0-0-1", "name": "CLOUDFLARENET", "country": "US",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
                  "entities": [{"roles": ["abuse", "noc"],
                                "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                                         ["email", {}, "text", "mailto:abuse@cloudflare.com"]]]}]}],
}


def rdap_domain(name, status=("client transfer prohibited",)):
    return {
        "objectClassName": "domain", "ldhName": name.upper(), "status": list(status),
        "events": [{"eventAction": "registration", "eventDate": "2026-11-14T03:04:05Z"},
                   {"eventAction": "expiration", "eventDate": "2027-11-14T03:04:05Z"}],
        "entities": [
            {"objectClassName": "entity", "roles": ["registrant"],
             "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
            {"objectClassName": "entity", "roles": ["registrar"], "handle": "1479",
             "publicIds": [{"type": "IANA Registrar ID", "identifier": "1479"}],
             "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameSilo, LLC"]]],
             "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                           "vcardArray": ["vcard", [["fn", {}, "text", ""],
                                                    ["email", {}, "text", "Abuse@NameSilo.com"]]]}]},
        ],
    }


def nx(name):
    """NXDOMAIN as dnspython raises it, with the zone SOA in the authority section (a real negative answer)."""
    qname = dns.name.from_text(name)
    resp = dns.message.make_response(dns.message.make_query(qname, "A"))
    resp.set_rcode(dns.rcode.NXDOMAIN)
    resp.authority.append(dns.rrset.from_text(name.split(".", 1)[-1] + ".", 300, "IN", "SOA",
                                              "a.nic.top. hostmaster.nic.top. 1 7200 900 1209600 300"))
    return dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: resp})


class Net:
    """Stubbed DNS resolver and RDAP/IANA HTTP, installed into cybercheck.enrich."""

    def __init__(self, monkeypatch):
        self.dns: dict = {}
        self.rdap: dict = {}           # registered domain -> (status, json)
        self.rdap_ip: dict = RDAP_IP
        self.requests: list[str] = []
        self.unexpected: list[str] = []
        self.queries: list[tuple] = []
        net = self

        class Resolver:
            async def resolve(self, qname, rdtype="A", search=None, **kw):
                name = str(qname).rstrip(".").lower()
                net.queries.append((name, rdtype))
                v = net.dns.get((name, rdtype), dns.resolver.NoAnswer())
                if v is HANG:
                    await asyncio.sleep(3600)
                if isinstance(v, BaseException):
                    raise v
                if rdtype == "TXT":
                    return [SimpleNamespace(strings=(x.encode(),)) for x in v]
                return [SimpleNamespace(address=x) for x in v]
        self.resolver = Resolver()
        monkeypatch.setattr(enrich, "make_resolver", lambda cfg: self.resolver)
        real_client = httpx.AsyncClient
        monkeypatch.setattr(enrich.httpx, "AsyncClient",
                            functools.partial(real_client, transport=httpx.MockTransport(self.handle)))

    @staticmethod
    def json_response(status: int, body) -> httpx.Response:
        # ASCII JSON as RDAP servers send it (non-ASCII and any lone surrogate as \u escapes)
        return httpx.Response(status, content=json.dumps(body).encode(), headers={"content-type": "application/rdap+json"})

    def handle(self, req: httpx.Request) -> httpx.Response:
        url, host, path = str(req.url), req.url.host, req.url.path
        self.requests.append(url)
        if host == "data.iana.org":
            return self.json_response(200, {"/rdap/dns.json": BOOT_DNS, "/rdap/ipv4.json": BOOT_V4,
                                            "/rdap/ipv6.json": BOOT_V6}[path])
        if host == "rdap.nic.top" and path.startswith("/domain/"):
            status, body = self.rdap.get(path.rsplit("/", 1)[1], (404, {"errorCode": 404}))
            return self.json_response(status, body)
        if host == "rdap.arin.net" and path.startswith("/registry/ip/"):
            return self.json_response(200, self.rdap_ip)
        self.unexpected.append(url)
        return httpx.Response(599)

    def resolves(self, name, *ips):
        self.dns[(name, "A")] = [i for i in ips if ":" not in i]
        self.dns[(name, "AAAA")] = [i for i in ips if ":" in i]

    def nxdomain(self, name):
        self.dns[(name, "A")] = nx(name)
        self.dns[(name, "AAAA")] = nx(name)

    def asn(self, ip, asn=13335, prefix="104.16.0.0/13", cc="US", as_name="CLOUDFLARENET - Cloudflare, Inc., US"):
        rev = ".".join(reversed(ip.split(".")))
        self.dns[(f"{rev}.origin.asn.cymru.com", "TXT")] = [f"{asn} | {prefix} | {cc} | arin | 2014-03-28"]
        self.dns[(f"as{asn}.asn.cymru.com", "TXT")] = [f"{asn} | {cc} | arin | 2010-07-14 | {as_name}"]


def new_ctx():
    return worker.JobContext(settings=config.settings(), log=logging.getLogger("it.enrich"),
                             state={"rdap": enrich.RdapClient(min_interval=0.0)})


def enrich_run(ctx) -> dict:
    return arun(enrich.run_once(ctx))


def make_due(*names):
    q("UPDATE domains SET next_check_at = now() WHERE registered_domain = ANY(%s)", (list(names),))


def checks(domain_id) -> list[dict]:
    return q("SELECT kind, ok, result FROM checks WHERE domain_id = %s ORDER BY id", (domain_id,))


def test_enrich_run_once_over_seeded_domains(clean, monkeypatch):
    net = Net(monkeypatch)
    monkeypatch.setattr(enrich, "DOMAIN_TIMEOUT_S", 1.5)
    a = store_sync("www.commbank-login.top")
    b = store_sync("secure.commbank-login.com.au")
    c = store_sync("xn--cmmbank-login-prj.top")
    d = store_sync("commbank-login.pages.dev")
    e = store_sync("www.netbank-verify.xyz")
    f = store_sync("westpac-secure.top")
    g = store_sync("auspost-delivery.top")
    h = store_sync("mygov-verify.top")
    i = store_sync("ato-refund.top")
    j = store_sync("telstra-billing.top")
    # g: watch window over, still due -> expired; h: a reviewer said false positive -> expired
    q("UPDATE domains SET watch_until = now() - interval '1 day', next_check_at = now() - interval '1 hour' WHERE id = %s", (g,))
    q("UPDATE domains SET status = 'false_positive', status_changed_at = now(), status_by = 'alice' WHERE id = %s", (h,))
    # i: schedule ended, then reported -> revived; j: schedule ended, then a reviewer reopened it -> revived
    q("UPDATE domains SET next_check_at = NULL, watch_until = now() - interval '1 day', first_seen = now() - interval '20 days', "
      "reported_at = now() - interval '1 hour' WHERE id = %s", (i,))
    q("UPDATE domains SET next_check_at = NULL, enriched_at = now() - interval '2 days', status_changed_at = now(), "
      "status_by = 'alice' WHERE id = %s", (j,))

    async def seed_kv():
        p = await db.pool()
        async with p.connection() as conn:
            await db.kv_set(conn, "enrich:ip:1.2.3.4", {"ip": "1.2.3.4", "asn": 4826, "as_name": "VOCUS-BACKBONE-AS",
                                                       "country": "AU", "abuse_email": "abuse@vocus.example",
                                                       "partial": False, "asn_state": "ok", "rdap_state": "ok"})
            await db.kv_set(conn, "enrich:ip:9.9.9.9", {"ip": "9.9.9.9", "asn": 19281})
            await db.kv_set(conn, "job:old", {"ok": True})
    arun(seed_kv())
    q("UPDATE kv SET updated_at = now() - interval '8 days' WHERE key IN ('enrich:ip:9.9.9.9', 'job:old')")

    net.resolves("commbank-login.top", "104.16.1.1")
    net.resolves("www.commbank-login.top", "104.16.1.1", "2606:4700::6810:101")
    net.asn("104.16.1.1")
    net.rdap["commbank-login.top"] = (200, rdap_domain("commbank-login.top"))
    net.resolves("commbank-login.com.au", "1.2.3.4")
    net.resolves("secure.commbank-login.com.au", "1.2.3.4")
    net.nxdomain("xn--cmmbank-login-prj.top")
    net.resolves("commbank-login.pages.dev", "172.66.44.1")
    net.asn("172.66.44.1", prefix="172.64.0.0/13")
    for name in ("netbank-verify.xyz", "www.netbank-verify.xyz"):
        net.dns[(name, "A")] = dns.exception.Timeout()
        net.dns[(name, "AAAA")] = dns.exception.Timeout()
    net.rdap["netbank-verify.xyz"] = (500, {"errorCode": 500})
    net.dns[("westpac-secure.top", "A")] = HANG

    ctx = new_ctx()
    before = db_now()
    result = enrich_run(ctx)
    after = db_now()
    assert result == {"due": 8, "checked": 7, "failed": 1, "rdap": 7, "takedowns": 0, "expired": 2, "revived": 2}
    assert net.unexpected == []
    assert net.requests[:3] == ["https://data.iana.org/rdap/dns.json", "https://data.iana.org/rdap/ipv4.json",
                                "https://data.iana.org/rdap/ipv6.json"]
    assert sorted(net.requests[3:]) == sorted([
        "https://rdap.nic.top/domain/commbank-login.top", "https://rdap.nic.top/domain/xn--cmmbank-login-prj.top",
        "https://rdap.nic.top/domain/netbank-verify.xyz", "https://rdap.nic.top/domain/ato-refund.top",
        "https://rdap.nic.top/domain/telstra-billing.top", "https://rdap.arin.net/registry/ip/104.16.1.1"])

    # a: resolves, registrar + hosting from RDAP / Team Cymru
    ra = q1("SELECT * FROM domains WHERE id = %s", (a,))
    assert ra["dns_state"] == "resolves" and ra["ips"] == ["104.16.1.1", "2606:4700::6810:101"]
    assert ra["asn"] == 13335 and ra["as_name"] == "CLOUDFLARENET - Cloudflare, Inc., US" and ra["ip_country"] == "US"
    assert ra["registrar"] == "NameSilo, LLC" and ra["registrar_iana_id"] == 1479
    assert ra["registrar_abuse_email"] == "Abuse@namesilo.com" and ra["hosting_abuse_email"] == "abuse@cloudflare.com"
    assert ra["rdap_status"] == ["client transfer prohibited"]
    assert ra["registered_at"] == datetime(2026, 11, 14, 3, 4, 5, tzinfo=UTC)
    assert ra["check_count"] == 1 and before <= ra["enriched_at"] <= after
    assert abs(ra["next_check_at"] - (ra["first_seen"] + timedelta(minutes=10))) < timedelta(seconds=1)
    st = ra["enrich_state"]
    assert st["dns"] == "resolves" and st["dns_err"] == 0 and st["ip"] == "104.16.1.1" and st["rdap_at"] and st["resolved_at"]
    assert [(c["kind"], c["ok"]) for c in checks(a)] == [("dns", True), ("rdap", True), ("asn", True)]
    assert checks(a)[1]["result"]["registered_at"] == "2026-11-14T03:04:05+00:00"
    assert [x["kind"] for x in events(a)] == ["first_seen", "dns_resolves"]
    assert events(a, "dns_resolves")[0]["detail"] == {"ips": ["104.16.1.1", "2606:4700::6810:101"], "first": True}

    # b: .com.au: no RDAP query (auDA policy), IP info from the kv cache
    rb = q1("SELECT * FROM domains WHERE id = %s", (b,))
    assert rb["dns_state"] == "resolves" and rb["registrar"] is None and rb["rdap_status"] == []
    assert rb["asn"] == 4826 and rb["ip_country"] == "AU" and rb["hosting_abuse_email"] == "abuse@vocus.example"
    cb = checks(b)
    assert [(c["kind"], c["ok"]) for c in cb] == [("dns", True), ("rdap", False), ("asn", True)]
    assert cb[1]["result"] == {"state": "unsupported", "tld": "au"} and cb[2]["result"]["cached"] is True
    assert rb["enrich_state"]["rdap_at"]
    assert not any("cctld.au" in u for u in net.requests)

    # c: IDN that never resolved: nxdomain, no "nxdomain" event (it never went anywhere), RDAP 404
    rc = q1("SELECT * FROM domains WHERE id = %s", (c,))
    assert rc["dns_state"] == "nxdomain" and rc["ips"] == [] and rc["asn"] is None
    assert ("xn--cmmbank-login-prj.top", "A") in net.queries
    assert [(x["kind"], x["ok"]) for x in checks(c)] == [("dns", True), ("rdap", False)]
    assert checks(c)[1]["result"]["state"] == "not_found"
    assert [x["kind"] for x in events(c)] == ["first_seen"]

    # d: hosting platform suffix: RDAP skipped (platform), ASN from Cymru, no IP RDAP for an unknown range
    rd = q1("SELECT * FROM domains WHERE id = %s", (d,))
    assert rd["asn"] == 13335 and rd["hosting_abuse_email"] is None
    assert checks(d)[1]["result"] == {"state": "platform", "parent": "pages.dev"}

    # e: DNS errors keep dns_state 'error', RDAP 500 counted for back-off, retried soon
    re_ = q1("SELECT * FROM domains WHERE id = %s", (e,))
    assert re_["dns_state"] == "error" and re_["enrich_state"]["dns_err"] == 1
    assert re_["enrich_state"]["rdap_fail"] == 1 and "rdap_at" not in re_["enrich_state"]
    assert re_["next_check_at"] <= after + timedelta(minutes=10)
    assert [(x["kind"], x["ok"]) for x in checks(e)] == [("dns", False), ("rdap", False)]

    # f: lookup hung past the per-domain timeout: postponed 30 minutes, nothing written
    rf = q1("SELECT * FROM domains WHERE id = %s", (f,))
    assert rf["check_count"] == 0 and rf["enriched_at"] is None and checks(f) == []
    assert before + timedelta(minutes=29) < rf["next_check_at"] <= after + timedelta(minutes=30)

    # g, h: expired; i, j: revived and checked in the same run
    assert q1("SELECT next_check_at FROM domains WHERE id = %s", (g,))["next_check_at"] is None
    assert q1("SELECT next_check_at FROM domains WHERE id = %s", (h,))["next_check_at"] is None
    ri = q1("SELECT * FROM domains WHERE id = %s", (i,))
    assert ri["check_count"] == 1 and ri["dns_state"] == "no_answer"
    assert after + timedelta(minutes=59) < ri["next_check_at"] <= after + timedelta(hours=1)   # tracked: hourly
    rj = q1("SELECT * FROM domains WHERE id = %s", (j,))
    assert rj["check_count"] == 1 and rj["next_check_at"] is not None

    keys = {r["key"] for r in q("SELECT key FROM kv")}
    assert keys == {"enrich:rdap_bootstrap:dns", "enrich:rdap_bootstrap:ipv4", "enrich:rdap_bootstrap:ipv6",
                    "enrich:ip:104.16.1.1", "enrich:ip:172.66.44.1", "enrich:ip:1.2.3.4", "job:old"}
    assert q1("SELECT value FROM kv WHERE key = 'enrich:ip:104.16.1.1'")["value"]["abuse_email"] == "abuse@cloudflare.com"

    # second run straight after: nothing due, no network, housekeeping not repeated
    net.requests.clear()
    assert enrich_run(ctx) == {"due": 0, "checked": 0, "failed": 0, "rdap": 0, "takedowns": 0}
    assert net.requests == []

    # worker restart (fresh job state): bootstrap and IP info come from kv, RDAP not due yet, no events
    make_due("commbank-login.top")
    result = enrich_run(new_ctx())
    assert result == {"due": 1, "checked": 1, "failed": 0, "rdap": 0, "takedowns": 0, "expired": 0, "revived": 0}
    assert net.requests == [] and net.unexpected == []
    assert [(x["kind"], x["ok"]) for x in checks(a)][3:] == [("dns", True)]
    assert [x["kind"] for x in events(a)] == ["first_seen", "dns_resolves"]
    assert q1("SELECT check_count FROM domains WHERE id = %s", (a,))["check_count"] == 2


def test_enrich_takedown_by_nxdomain_needs_two_checks_then_revives(clean, monkeypatch):
    net = Net(monkeypatch)
    did = store_sync("www.auspost-delivery.top")
    q("UPDATE domains SET status = 'confirmed', status_changed_at = now(), status_by = 'alice' WHERE id = %s", (did,))
    for name in ("auspost-delivery.top", "www.auspost-delivery.top"):
        net.resolves(name, "104.16.2.2")
    net.asn("104.16.2.2")
    net.rdap["auspost-delivery.top"] = (200, rdap_domain("auspost-delivery.top"))
    ctx = new_ctx()
    assert enrich_run(ctx)["checked"] == 1
    assert dom("auspost-delivery.top")["dns_state"] == "resolves"

    for name in ("auspost-delivery.top", "www.auspost-delivery.top"):
        net.nxdomain(name)
    make_due("auspost-delivery.top")
    t2 = db_now()
    r2 = enrich_run(ctx)
    assert r2["checked"] == 1 and r2["takedowns"] == 0 and r2["rdap"] == 0       # RDAP checked < 1 h ago
    d2 = dom("auspost-delivery.top")
    assert d2["takedown_at"] is None and d2["dns_state"] == "nxdomain" and d2["ips"] == []
    assert d2["enrich_state"]["pending"]["nxdomain"]["n"] == 1
    assert events(did, "nxdomain")[0]["detail"] == {"previous_ips": ["104.16.2.2"]}
    assert d2["next_check_at"] <= db_now() + timedelta(hours=1)

    # a resolver timeout in between neither confirms nor clears the pending signal, and keeps the last real
    # DNS state (nothing but the bookkeeping columns is written)
    for name in ("auspost-delivery.top", "www.auspost-delivery.top"):
        net.dns[(name, "A")] = dns.exception.Timeout()
        net.dns[(name, "AAAA")] = dns.exception.Timeout()
    make_due("auspost-delivery.top")
    r_err = enrich_run(ctx)
    assert r_err["checked"] == 1 and r_err["takedowns"] == 0
    de = dom("auspost-delivery.top")
    assert de["dns_state"] == "nxdomain" and de["check_count"] == 3 and de["takedown_at"] is None
    assert de["enrich_state"]["pending"] == d2["enrich_state"]["pending"] and de["enrich_state"]["dns_err"] == 1
    assert de["next_check_at"] <= db_now() + timedelta(minutes=10)
    assert checks(did)[-1]["kind"] == "dns" and checks(did)[-1]["ok"] is False
    for name in ("auspost-delivery.top", "www.auspost-delivery.top"):
        net.nxdomain(name)

    make_due("auspost-delivery.top")
    r3 = enrich_run(ctx)
    assert r3["takedowns"] == 1
    d3 = dom("auspost-delivery.top")
    assert d3["takedown_signal"] == "nxdomain" and d3["next_check_at"] is None
    assert t2 <= d3["takedown_at"] <= t2 + timedelta(seconds=30)                # first seen gone on check 2
    assert "pending" not in d3["enrich_state"]
    td = events(did, "taken_down")
    assert len(td) == 1 and td[0]["detail"]["signal"] == "nxdomain"
    assert td[0]["detail"]["hours_from_first_seen"] is not None and td[0]["detail"]["hours_from_reported"] is None

    # taken down: not due again; a stray schedule is cleared by housekeeping
    make_due("auspost-delivery.top")
    ctx.state.pop("housekeep_at", None)
    r4 = enrich_run(ctx)
    assert r4["due"] == 0 and r4["expired"] == 1
    assert dom("auspost-delivery.top")["next_check_at"] is None

    # a new certificate: store_hit clears the takedown and re-arms the checks; enrich sees it resolve again
    for name in ("auspost-delivery.top", "www.auspost-delivery.top", "login.auspost-delivery.top"):
        net.resolves(name, "104.16.2.3")
    net.asn("104.16.2.3")
    store_sync("login.auspost-delivery.top")
    assert len(events(did, "reappeared")) == 1
    r5 = enrich_run(ctx)
    assert r5["due"] == 1 and r5["checked"] == 1 and r5["takedowns"] == 0
    d5 = dom("auspost-delivery.top")
    assert d5["takedown_at"] is None and d5["dns_state"] == "resolves" and d5["ips"] == ["104.16.2.3"]
    assert events(did, "dns_resolves")[-1]["detail"] == {"ips": ["104.16.2.3"], "first": False}
    assert len(events(did, "taken_down")) == 1
    assert d5["next_check_at"] is not None


def test_enrich_takedown_by_rdap_hold_is_immediate(clean, monkeypatch):
    net = Net(monkeypatch)
    did = store_sync("nab-login-secure.top")
    q("UPDATE domains SET reported_at = now() WHERE id = %s", (did,))            # reporting module: tracked
    net.resolves("nab-login-secure.top", "104.16.3.3")
    net.asn("104.16.3.3")
    net.rdap["nab-login-secure.top"] = (200, rdap_domain("nab-login-secure.top"))
    ctx = new_ctx()
    assert enrich_run(ctx)["takedowns"] == 0

    # an hour later: the registry put the domain on hold (it still resolves from caches)
    old = enrich.iso(datetime.now(UTC) - timedelta(hours=2))
    q("UPDATE domains SET enrich_state = enrich_state || jsonb_build_object('rdap_at', %s::text) WHERE id = %s", (old, did))
    net.rdap["nab-login-secure.top"] = (200, rdap_domain("nab-login-secure.top", ("client transfer prohibited", "server hold")))
    make_due("nab-login-secure.top")
    r = enrich_run(ctx)
    assert r["takedowns"] == 1 and r["rdap"] == 1
    d = dom("nab-login-secure.top")
    assert d["takedown_signal"] == "rdap_hold" and d["takedown_at"] is not None and d["next_check_at"] is None
    assert d["rdap_status"] == ["client transfer prohibited", "server hold"]
    assert events(did, "taken_down")[0]["detail"]["hours_from_reported"] is not None


def test_enrich_takedown_by_page_gone_uses_the_fetchers_time(clean, monkeypatch):
    net = Net(monkeypatch)
    did = store_sync("telstra-billing.top")
    # judge + fetch modules: AI phishing verdict, page was live
    q("UPDATE domains SET ai_verdict = 'phishing', ai_confidence = 0.95, live_state = 'live', "
      "first_live_at = now() - interval '1 day', last_live_at = now() - interval '6 hours' WHERE id = %s", (did,))
    net.resolves("telstra-billing.top", "104.16.4.4")
    net.asn("104.16.4.4")
    ctx = new_ctx()
    assert enrich_run(ctx)["checked"] == 1

    # fetch module: the page is gone (event five hours ago), DNS still resolves
    q("UPDATE domains SET live_state = 'down' WHERE id = %s", (did,))
    q("INSERT INTO domain_events (domain_id, kind, detail, at) VALUES (%s, 'page_down', %s, now() - interval '5 hours')",
      (did, db.jsonb({"profile": "desktop", "error": "net::ERR_NAME_NOT_RESOLVED"})))
    page_down_at = events(did, "page_down")[0]["at"]
    # an older outage, before the page was last live: the latest page_down event is the one that counts
    q("INSERT INTO domain_events (domain_id, kind, detail, at) VALUES (%s, 'page_down', %s, now() - interval '2 days')",
      (did, db.jsonb({"profile": "mobile", "error": "net::ERR_CONNECTION_REFUSED"})))
    make_due("telstra-billing.top")
    assert enrich_run(ctx)["takedowns"] == 0
    assert dom("telstra-billing.top")["enrich_state"]["pending"]["http_gone"]["n"] == 1
    make_due("telstra-billing.top")
    assert enrich_run(ctx)["takedowns"] == 1
    d = dom("telstra-billing.top")
    assert d["takedown_signal"] == "http_gone" and d["takedown_at"] == page_down_at
    assert d["dns_state"] == "resolves"


def test_enrich_rdap_text_with_a_lone_surrogate_escape(clean, monkeypatch):
    """RDAP answers are parsed with json.loads, which turns a \\ud800 escape into a lone surrogate. It must still be
    storable (text columns, checks.result jsonb, the kv IP cache), or the domain fails and is postponed every run."""
    net = Net(monkeypatch)
    did = store_sync("www.commbank-login.top")
    for name in ("commbank-login.top", "www.commbank-login.top"):
        net.resolves(name, "104.16.1.1")
    net.asn("104.16.1.1")
    body = rdap_domain("commbank-login.top", ("client transfer prohibited", "active\ud800"))
    body["entities"][1]["vcardArray"][1][1][3] = "NameSilo\ud800, LLC"
    net.rdap["commbank-login.top"] = (200, body)
    net.rdap_ip = dict(RDAP_IP, name="EVIL\udc00NET")
    r = enrich_run(new_ctx())
    assert r["checked"] == 1 and r["failed"] == 0 and r["rdap"] == 1
    d = dom("commbank-login.top")
    assert d["check_count"] == 1 and d["dns_state"] == "resolves" and d["registrar_iana_id"] == 1479
    assert d["registrar"] == "NameSilo\ufffd, LLC"
    assert d["rdap_status"] == ["client transfer prohibited", "active\ufffd"]
    assert d["hosting_abuse_email"] == "abuse@cloudflare.com" and d["asn"] == 13335
    by_kind = {c["kind"]: c for c in checks(did)}
    assert by_kind["rdap"]["result"]["registrar"] == "NameSilo\ufffd, LLC"
    assert by_kind["asn"]["result"]["network"] == "EVIL\ufffdNET"
    assert q1("SELECT value FROM kv WHERE key = 'enrich:ip:104.16.1.1'")["value"]["network"] == "EVIL\ufffdNET"


def test_enrich_due_query_handles_null_and_empty_columns(clean, monkeypatch):
    """A confirmed row with no watch window and no hostnames (e.g. added by hand) is still checked."""
    net = Net(monkeypatch)
    q("INSERT INTO domains (registered_domain, tld, score, tier, source, status, status_changed_at, watch_until) "
      "VALUES ('commbank-netbank.top', 'top', 80, 'high', 'manual', 'confirmed', now(), NULL)")
    net.resolves("commbank-netbank.top", "104.16.5.5")
    net.asn("104.16.5.5")
    r = enrich_run(new_ctx())
    assert r["due"] == 1 and r["checked"] == 1 and r["failed"] == 0
    d = dom("commbank-netbank.top")
    assert d["dns_state"] == "resolves" and d["ips"] == ["104.16.5.5"]
    assert d["next_check_at"] <= db_now() + timedelta(hours=1)
    assert net.queries[:2] == [("commbank-netbank.top", "A"), ("commbank-netbank.top", "AAAA")]


def test_enrich_housekeeping_expire_and_revive_branches(clean):
    """EXPIRE_SQL / REVIVE_SQL row by row, and REVIVE's tracking window agrees with enrich.track_end()."""
    names = {
        "c1": "auspost-delivery.top", "c2": "mygov-verify.top", "c3": "ato-refund.top", "c4": "telstra-billing.top",
        "c5": "optus-bill.top", "c6": "anz-login.top", "c8": "anz-verify.top", "e1": "westpac-login.top",
        "e2": "nab-verify.top", "e3": "medicare-claim.top", "e4": "commbank-verify.top", "e5": "westpac-secure.top",
    }
    ids = {k: store_sync(v) for k, v in names.items()}
    sets = {
        # confirmed 10 days ago, first seen 50 days ago, schedule ended: inside the 30-day window -> revived
        "c1": "status = 'confirmed', status_changed_at = now() - interval '10 days', first_seen = now() - interval '50 days', "
              "watch_until = now() - interval '36 days', next_check_at = NULL",
        # confirmed 40 days ago: tracking over -> stays unscheduled
        "c2": "status = 'confirmed', status_changed_at = now() - interval '40 days', first_seen = now() - interval '50 days', "
              "watch_until = now() - interval '36 days', next_check_at = NULL",
        # reported 40 days ago; a recent status change of an OPEN row does not restart tracking
        "c3": "reported_at = now() - interval '40 days', first_seen = now() - interval '45 days', "
              "status_changed_at = now() - interval '1 day', watch_until = now() - interval '31 days', next_check_at = NULL",
        # confirmed just now, next check days away -> pulled in to now
        "c4": "status = 'confirmed', status_changed_at = now(), next_check_at = now() + interval '3 days'",
        # confirmed, next check within the hour -> untouched
        "c5": "status = 'confirmed', status_changed_at = now(), next_check_at = now() + interval '30 minutes'",
        # reopened inside its watch window but already enriched since -> not revived
        "c6": "status_changed_at = now() - interval '2 hours', enriched_at = now() - interval '1 hour', next_check_at = NULL",
        # AI said phishing but a reviewer said benign: due -> expired
        "c8": "ai_verdict = 'phishing', status = 'benign', status_changed_at = now(), next_check_at = now() - interval '1 minute'",
        # no watch window at all (NULL) and nothing tracked -> expired
        "e1": "watch_until = NULL, next_check_at = now()",
        # watch window over but AI phishing (tracked) -> kept
        "e2": "watch_until = now() - interval '1 day', ai_verdict = 'phishing', next_check_at = now() - interval '1 minute'",
        # confirmed but taken down -> expired, never revived
        "e3": "status = 'confirmed', status_changed_at = now(), takedown_at = now() - interval '1 hour', "
              "takedown_signal = 'nxdomain', next_check_at = now() - interval '1 minute'",
        # inside the watch window -> kept
        "e4": "next_check_at = now() - interval '1 minute'",
        "e5": "status = 'false_positive', status_changed_at = now(), next_check_at = now() - interval '1 minute'",
    }
    for k, s in sets.items():
        q(f"UPDATE domains SET {s} WHERE id = %s", (ids[k],))
    before = {k: dom(v) for k, v in names.items()}

    cfg = enrich.load_config()
    out = arun(enrich.housekeeping({}, cfg))
    t = db_now()
    assert out == {"expired": 4, "revived": 2}
    after = {k: dom(v) for k, v in names.items()}
    for k in ("c8", "e1", "e3", "e5"):
        assert after[k]["next_check_at"] is None, k
    for k in ("c1", "c4"):
        assert after[k]["next_check_at"] <= t, k
    for k in ("c2", "c3", "c5", "c6", "e2", "e4"):
        assert after[k]["next_check_at"] == before[k]["next_check_at"], k
    # same window as the Python rule used by decide() and the fetch job
    for k in ("c1", "c2", "c3"):
        end = enrich.track_end(before[k], cfg.track_days)
        assert (end is not None and end > t) == (k == "c1"), k

    # throttled within HOUSEKEEP_EVERY_S; a fresh run finds nothing more to do
    state: dict = {}
    assert arun(enrich.housekeeping(state, cfg)) == {"expired": 0, "revived": 0}
    assert arun(enrich.housekeeping(state, cfg)) == {}


def test_enrich_due_order_high_tier_first_within_the_batch_limit(clean, monkeypatch):
    net = Net(monkeypatch)
    monkeypatch.setenv("ENRICH_BATCH_SIZE", "1")
    ids = {
        "watch": store_sync("foo.commbank-login.com.au"),
        "review": store_sync("www.commbank-secure.top"),
        "high_late": store_sync("auspost-delivery.top"),
        "high_early": store_sync("secure.commbank-login.top"),
    }
    for k, ago in (("watch", "3 hours"), ("review", "2 hours"), ("high_late", "1 minute"), ("high_early", "10 minutes")):
        q("UPDATE domains SET next_check_at = now() - %s::interval WHERE id = %s", (ago, ids[k]))

    def checked():
        return {k for k, i in ids.items() if q1("SELECT check_count FROM domains WHERE id = %s", (i,))["check_count"]}
    ctx = new_ctx()
    assert enrich_run(ctx)["due"] == 1 and checked() == {"high_early"}
    monkeypatch.setenv("ENRICH_BATCH_SIZE", "2")
    assert enrich_run(ctx)["checked"] == 2 and checked() == {"high_early", "high_late", "review"}
    assert enrich_run(ctx)["checked"] == 1 and checked() == set(ids)
    assert enrich_run(ctx)["due"] == 0
    assert net.unexpected == []


def test_enrich_schedule_with_a_non_utc_database_session(clean, monkeypatch):
    """Nothing may depend on the session TimeZone (the shared server's default could change): run store + enrich
    with a +10:30 / +9:30 session and check the absolute times written."""
    monkeypatch.setenv("CYBERCHECK_DB_OPTIONS", "")      # turn off db.py's UTC pin: prove the code holds without it
    monkeypatch.setenv("PGTZ", "Australia/Adelaide")
    net = Net(monkeypatch)
    did = store_sync("www.commbank-login.top")
    d0 = dom("commbank-login.top")
    assert d0["first_seen"].utcoffset() in (timedelta(hours=10, minutes=30), timedelta(hours=9, minutes=30))
    net.resolves("commbank-login.top", "104.16.1.1")
    net.resolves("www.commbank-login.top", "104.16.1.1")
    net.asn("104.16.1.1")
    net.rdap["commbank-login.top"] = (200, rdap_domain("commbank-login.top"))
    assert enrich_run(new_ctx())["checked"] == 1
    d1 = dom("commbank-login.top")
    assert abs(d1["next_check_at"] - (d1["first_seen"] + timedelta(minutes=10))) < timedelta(seconds=1)
    assert d1["registered_at"] == datetime(2026, 11, 14, 3, 4, 5, tzinfo=UTC)
    st = d1["enrich_state"]
    assert datetime.fromisoformat(st["resolved_at"]).utcoffset() == timedelta(0)
    assert abs(datetime.fromisoformat(st["resolved_at"]) - d1["enriched_at"]) < timedelta(seconds=5)
    q("UPDATE domains SET status = 'confirmed', status_changed_at = now() - interval '29 days', "
      "first_seen = now() - interval '40 days', watch_until = now() - interval '26 days', next_check_at = NULL "
      "WHERE id = %s", (did,))
    assert arun(enrich.housekeeping({}, enrich.load_config())) == {"expired": 0, "revived": 1}


def test_enrich_job_with_empty_tables(clean, monkeypatch):
    Net(monkeypatch)
    from cybercheck.jobs import enrich as enrich_job
    r = arun(enrich_job.JOB.run(new_ctx()))
    assert r == {"due": 0, "checked": 0, "failed": 0, "rdap": 0, "takedowns": 0, "expired": 0, "revived": 0}


# ---------------------------------------------------------------------------------------------- housekeeping

def test_housekeeping_run_once_each_statement(clean, monkeypatch):
    from cybercheck.ai import budget
    from cybercheck.jobs import fetch, housekeeping
    from cybercheck.reporting import engine

    open_id = store_sync("www.westpac-secure.top")
    conf_id = store_sync("commbank-verify.top")
    q("UPDATE domains SET status = 'confirmed', status_changed_at = now(), status_by = 'alice' WHERE id = %s", (conf_id,))
    stale = store_sync("foo.commbank-login.com.au")                 # watch, open, nothing else
    with_page = store_sync("netbank.secure-host.top")               # watch, has a snapshot
    with_report = store_sync("auspost.parcel-site.top")             # watch, has a report
    benign = store_sync("telstra.web-host.top")                     # watch, reviewed benign
    review_old = store_sync("optus-bill.top")                        # review tier
    recent_watch = store_sync("westpac.cloud-host.xyz")             # watch, seen recently
    q("UPDATE domains SET status = 'benign', status_changed_at = now() WHERE id = %s", (benign,))
    q("UPDATE domains SET last_seen = now() - interval '130 days' WHERE id = ANY(%s)",
      ([stale, with_page, with_report, benign, review_old],))
    assert {dom(n)["tier"] for n in ("commbank-login.com.au", "secure-host.top", "parcel-site.top", "web-host.top",
                                      "cloud-host.xyz")} == {"watch"}

    async def seed():
        p = await db.pool()
        async with p.connection() as conn:
            for domain_id in (open_id, conf_id):
                for _ in range(2):
                    await enrich.write_update(conn, domain_id, enrich.Update(
                        checks=[("dns", True, {"state": "resolves", "ips": ["104.16.1.1"]})], state={},
                        next_check_at=None))
            await conn.execute(fetch.INSERT_PAGE_SQL, {
                "domain_id": with_page, "url": "https://netbank.secure-host.top/", "final_url": "https://netbank.secure-host.top/login",
                "http_status": 200, "title": "NetBank - Log on", "egress_ip": "185.1.2.3", "profile": "desktop",
                "has_password": True, "has_otp": False, "has_card": False, "form_actions": ["/post.php"],
                "external_form_post": False, "brand_mentions": ["commbank"], "text_excerpt": "Log on to NetBank",
                "features": db.jsonb({"inputs": 2}), "error": None, "retain_until": datetime.now(UTC) + timedelta(days=60)})
            await conn.execute(engine.INSERT_SQL, (with_report, "netcraft", "draft", False, "api", db.jsonb({"url": "x"})))
            ids = []
            for purpose in ("bot", "bot", "page_judge"):
                call_id, reason = await budget.reserve(conn, purpose=purpose, model="claude-opus-5-5", estimate=0.01,
                                                       domain_id=open_id)
                assert reason is None
                await budget.finish(conn, call_id, status="ok", model="claude-opus-5-5", cost_usd=0.004,
                                    tokens={"input_tokens": 1200, "output_tokens": 150}, stop_reason="end_turn",
                                    result={"explanation": "looks like a CommBank phishing page"}, duration_ms=2100)
                ids.append(call_id)
            return ids
    bot_old, bot_new, judge_old = arun(seed())
    for domain_id, ages in ((open_id, ("100 days", "10 days")), (conf_id, ("100 days", "500 days"))):
        cids = [r["id"] for r in q("SELECT id FROM checks WHERE domain_id = %s ORDER BY id", (domain_id,))]
        for cid, age in zip(cids, ages):
            q("UPDATE checks SET at = now() - %s::interval WHERE id = %s", (age, cid))
    q("UPDATE ai_calls SET at = now() - interval '40 days' WHERE id = ANY(%s)", ([bot_old, judge_old],))
    q("UPDATE ai_calls SET at = now() - interval '5 days' WHERE id = %s", (bot_new,))

    monkeypatch.setenv("JOB_CZDS_ENABLED", "false")      # its clean-up of (empty) zone files runs too
    ctx = worker.JobContext(settings=config.settings(), log=logging.getLogger("it.housekeeping"))
    out = arun(housekeeping.run_once(ctx))
    assert out == {"checks": 1, "checks_confirmed": 1, "ai_bot": 1, "stale_watch": 1}

    assert [r["at"] > db_now() - timedelta(days=11) for r in
            q("SELECT at FROM checks WHERE domain_id = %s", (open_id,))] == [True]
    assert len(q("SELECT 1 FROM checks WHERE domain_id = %s", (conf_id,))) == 1
    results = {r["id"]: r["result"] for r in q("SELECT id, result FROM ai_calls")}
    assert results[bot_old] is None and results[bot_new] and results[judge_old]
    assert dom("commbank-login.com.au") is None
    assert q("SELECT 1 FROM domain_events WHERE domain_id = %s", (stale,)) == []
    for name in ("secure-host.top", "parcel-site.top", "web-host.top", "optus-bill.top", "cloud-host.xyz",
                 "westpac-secure.top", "commbank-verify.top"):
        assert dom(name) is not None, name

    assert arun(housekeeping.run_once(ctx)) == {"checks": 0, "checks_confirmed": 0, "ai_bot": 0, "stale_watch": 0}


def test_housekeeping_on_empty_tables(clean):
    from cybercheck.jobs import housekeeping
    ctx = worker.JobContext(settings=config.settings(), log=logging.getLogger("it.housekeeping"))
    assert arun(housekeeping.run_once(ctx)) == {"checks": 0, "checks_confirmed": 0, "ai_bot": 0, "stale_watch": 0}


# ---------------------------------------------------------------------------------------------- CLI

def test_rescore_cli(clean, capsys):
    from cybercheck.__main__ import main
    from cybercheck.jobs import fetch
    from cybercheck.reporting import engine
    old_wl = Watchlist({"brands": [{"id": "oldbank", "name": "Old Bank", "keywords": ["oldbankau"],
                                    "official_domains": ["oldbank.com.au"]}],
                        "bait_words": {"strong": ["login", "verify", "account", "secure"], "weak": []}})
    r1 = store_sync("www.commbank-login.top", "secure.commbank-login.top")
    store_sync("westpac-secure.top")
    store_sync("xn--cmmbank-login-prj.top")
    r3 = store_sync("oldbankau-login.top", watchlist=old_wl)        # brand since removed from the watchlist
    r4 = store_sync("oldbankau-verify.top", watchlist=old_wl)       # ... but it has a snapshot
    r5 = store_sync("oldbankau-account.top", watchlist=old_wl)      # ... but it has a report
    r6 = store_sync("oldbankau-secure.top", watchlist=old_wl)       # ... but a reviewer confirmed it
    q("UPDATE domains SET status = 'confirmed', status_changed_at = now() WHERE id = %s", (r6,))
    q("UPDATE domains SET score = 50, tier = 'watch', reasons = '[]', brand_id = 'westpac' WHERE id = %s", (r1,))

    async def seed():
        p = await db.pool()
        async with p.connection() as conn:
            await conn.execute(fetch.INSERT_PAGE_SQL, {
                "domain_id": r4, "url": "https://oldbankau-verify.top/", "final_url": None, "http_status": 200,
                "title": "Verify", "egress_ip": "185.1.2.3", "profile": "mobile", "has_password": False,
                "has_otp": True, "has_card": False, "form_actions": [], "external_form_post": None,
                "brand_mentions": [], "text_excerpt": None, "features": db.jsonb({}), "error": None, "retain_until": None})
            await conn.execute(engine.INSERT_SQL, (r5, "registrar_abuse", "draft", False, "email", db.jsonb({})))
    arun(seed())
    snapshot = q("SELECT id, score, tier, reasons, brand_id FROM domains ORDER BY id")

    assert main(["rescore", "--dry-run"]) == 0
    assert capsys.readouterr().out.strip() == "kept 5 (score changed on 1), dropped 1 (dry run)"
    assert q("SELECT id, score, tier, reasons, brand_id FROM domains ORDER BY id") == snapshot

    assert main(["rescore"]) == 0
    assert capsys.readouterr().out.strip() == "kept 5 (score changed on 1), dropped 1"
    assert dom("oldbankau-login.top") is None and q("SELECT 1 FROM domain_events WHERE domain_id = %s", (r3,)) == []
    d1 = dom("commbank-login.top")
    best = hit("secure.commbank-login.top")
    assert (d1["score"], d1["tier"], d1["brand_id"], d1["reasons"]) == (best.score, best.tier, "commbank", best.reasons)
    for name in ("oldbankau-verify.top", "oldbankau-account.top", "oldbankau-secure.top"):
        assert dom(name)["score"] == 57 and dom(name)["brand_id"] == "oldbank"
    assert dom("xn--cmmbank-login-prj.top")["score"] == 94

    assert main(["rescore"]) == 0
    assert capsys.readouterr().out.strip() == "kept 5 (score changed on 0), dropped 0"


def test_rescore_and_score_cli_with_an_idn_that_decodes_to_a_lone_surrogate(clean, capsys):
    """rescore re-scores every open row and writes the reasons back (jsonb); such a row must not stop it."""
    from cybercheck.__main__ import main
    bad = store_sync(SURR_REG)
    good = store_sync("www.commbank-login.top")
    q("UPDATE domains SET score = 40, tier = 'watch', reasons = '[]' WHERE id = ANY(%s)", ([bad, good],))
    assert main(["rescore"]) == 0
    assert capsys.readouterr().out.strip() == "kept 2 (score changed on 2), dropped 0"
    b = dom(SURR_REG)
    assert b["score"] == hit(SURR_REG).score and b["tier"] == hit(SURR_REG).tier and b["reasons"]
    assert dom("commbank-login.top")["score"] == hit("www.commbank-login.top").score

    # score prints JSON lines for a list of names (stdin or args): such a name must not end the run
    assert main(["score", SURR_REG, "secure.commbank-login.top"]) == 0
    lines = [orjson.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [x["hostname"] for x in lines] == [SURR_REG, "secure.commbank-login.top"]


def test_rescore_cli_on_empty_table(clean, capsys):
    from cybercheck.__main__ import main
    assert main(["rescore"]) == 0
    assert capsys.readouterr().out.strip() == "kept 0 (score changed on 0), dropped 0"


def test_migrate_and_score_cli(clean, capsys):
    from cybercheck.__main__ import main
    assert main(["migrate"]) == 0
    assert capsys.readouterr().out.strip() == "applied: nothing (up to date)"
    assert main(["score", "secure.commbank-login.top", "example.com", "--all"]) == 0
    lines = [orjson.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert lines[0]["hostname"] == "secure.commbank-login.top" and lines[0]["brand"] == "commbank"
    assert lines[0]["score"] == 81 and lines[1] == {"hostname": "example.com", "score": None}
    assert q("SELECT 1 FROM domains") == []


# ---------------------------------------------------------------------------------------------- worker

def test_worker_loop_records_job_status_in_kv(clean):
    runs = {"n": 0}

    async def ok_job(ctx):
        runs["n"] += 1
        p = await ctx.pool()
        async with p.connection() as conn:
            n = (await (await conn.execute("SELECT count(*) AS n FROM domains")).fetchone())["n"]
        ctx.state["runs"] = runs["n"]
        return {"domains": n, "run": ctx.state["runs"]}

    async def bad_job(ctx):
        raise RuntimeError("boom " + "x" * 600)

    async def none_job(ctx):
        return None

    async def typed_job(ctx):     # values straight from SQL (timestamptz, numeric) in a job's summary
        p = await ctx.pool()
        async with p.connection() as conn:
            row = await (await conn.execute("SELECT now() AS at, 0.0123::numeric AS spent")).fetchone()
        return {"last_at": row["at"], "spent_usd": row["spent"]}

    async def go():
        jobs = [worker.Job(name="it_ok", interval=0.05, run=ok_job, initial_delay=0),
                worker.Job(name="it_bad", interval=3600, run=bad_job, initial_delay=0),
                worker.Job(name="it_none", interval=3600, run=none_job, initial_delay=0),
                worker.Job(name="it_typed", interval=3600, run=typed_job, initial_delay=0)]
        tasks = [asyncio.create_task(worker._loop(j)) for j in jobs]
        try:
            for _ in range(200):
                await asyncio.sleep(0.05)
                rows = await asyncio.to_thread(q, "SELECT key, value FROM kv WHERE key LIKE 'job:it_%'")
                vals = {r["key"]: r["value"] for r in rows}
                if len(vals) == 4 and vals["job:it_ok"].get("result", {}).get("run", 0) >= 3:
                    return vals
            raise AssertionError(f"job status not recorded: {vals}")
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    store_sync("westpac-secure.top")
    vals = arun(go())
    okv = vals["job:it_ok"]
    assert okv["ok"] is True and okv["result"]["domains"] == 1 and okv["result"]["run"] >= 3
    assert okv["duration_s"] >= 0 and datetime.fromisoformat(okv["last_run"]).tzinfo is not None
    bad = vals["job:it_bad"]
    assert bad["ok"] is False and bad["error"].startswith("RuntimeError: boom") and len(bad["error"]) == 500
    assert vals["job:it_none"] == {"last_run": vals["job:it_none"]["last_run"], "ok": True, "result": {},
                                   "duration_s": vals["job:it_none"]["duration_s"]}
    assert len(q("SELECT 1 FROM kv WHERE key = 'job:it_ok'")) == 1
    typed = vals["job:it_typed"]
    assert typed["ok"] is True and typed["result"]["spent_usd"] == "0.0123"
    assert datetime.fromisoformat(typed["result"]["last_at"]).tzinfo is not None


def test_worker_runs_real_core_jobs_through_the_loop(clean, monkeypatch):
    Net(monkeypatch)
    from cybercheck.jobs import enrich as enrich_job
    from cybercheck.jobs import housekeeping
    store_sync("westpac-secure.top")
    q("UPDATE domains SET next_check_at = now() + interval '1 hour'")

    async def go():
        jobs = [dataclasses.replace(housekeeping.JOB, initial_delay=0, interval=3600),
                dataclasses.replace(enrich_job.JOB, initial_delay=0, interval=3600)]
        tasks = [asyncio.create_task(worker._loop(j)) for j in jobs]
        try:
            for _ in range(200):
                await asyncio.sleep(0.05)
                rows = await asyncio.to_thread(q, "SELECT key, value FROM kv WHERE key IN ('job:housekeeping', 'job:enrich')")
                if len(rows) == 2:
                    return {r["key"]: r["value"] for r in rows}
            raise AssertionError("job status not recorded")
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    vals = arun(go())
    assert vals["job:housekeeping"]["ok"] is True
    assert vals["job:housekeeping"]["result"] == {"checks": 0, "checks_confirmed": 0, "ai_bot": 0, "stale_watch": 0}
    assert vals["job:enrich"]["ok"] is True and vals["job:enrich"]["result"]["due"] == 0


def test_worker_run_migrates_and_idles_with_every_job_disabled(clean, monkeypatch):
    for job in worker.discover_jobs():
        monkeypatch.setenv(f"JOB_{job.name.upper()}_ENABLED", "false")
    # the fixture already migrated this database: forget the last (idempotent) migration so run() must apply it
    last = sorted(p.name for p in (config.ROOT / "migrations").glob("*.sql"))[-1]
    q("DELETE FROM schema_migrations WHERE version = %s", (last,))
    t = db_now()

    async def go():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(worker.run(), 0.5)
    arun(go())
    row = q1("SELECT applied_at FROM schema_migrations WHERE version = %s", (last,))
    assert row is not None and row["applied_at"] >= t
    assert len(q("SELECT 1 FROM schema_migrations")) == len(list((config.ROOT / "migrations").glob("*.sql")))


# ---------------------------------------------------------------------------------------------- db

@pytest.fixture
def scratch_db(it_db):
    """A second, empty database of this module's own (for migrate()); DATABASE_URL points at it meanwhile."""
    import os
    name = "it_core_mig_" + uuid.uuid4().hex[:8]
    admin(f'CREATE DATABASE "{name}"')
    old = os.environ["DATABASE_URL"]
    os.environ["DATABASE_URL"] = ADMIN.rsplit("/", 1)[0] + "/" + name
    config.settings.cache_clear()
    try:
        yield name
    finally:
        os.environ["DATABASE_URL"] = old
        config.settings.cache_clear()
        admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def test_migrate_concurrent_callers_apply_each_migration_once(scratch_db):
    barrier = threading.Barrier(6)
    results, errors = [], []

    def one():
        try:
            barrier.wait()
            results.append(db.migrate())
        except Exception as e:      # noqa: BLE001
            errors.append(e)
    threads = [threading.Thread(target=one) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert errors == []
    applied = [r for r in results if r]
    assert len(results) == 6 and len(applied) == 1
    names = sorted(p.name for p in (config.ROOT / "migrations").glob("*.sql"))
    assert applied[0] == names
    rows = admin("SELECT version FROM schema_migrations ORDER BY version", dbname=scratch_db)
    assert [r[0] for r in rows] == names
    assert admin("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = "
                 "(SELECT oid FROM pg_database WHERE datname = %s)", (scratch_db,))[0][0] == 0


def test_migrate_waits_for_the_advisory_lock(scratch_db):
    url = ADMIN.rsplit("/", 1)[0] + "/" + scratch_db
    holder = psycopg.connect(url, autocommit=True)
    try:
        holder.execute("SELECT pg_advisory_lock(727001)")          # another container is migrating
        out = []
        t = threading.Thread(target=lambda: out.append(db.migrate()))
        t.start()
        time.sleep(0.7)
        assert t.is_alive() and out == []
        assert holder.execute("SELECT to_regclass('schema_migrations')").fetchone()[0] is None
        holder.execute("SELECT pg_advisory_unlock(727001)")
        t.join(60)
        assert not t.is_alive() and len(out[0]) >= 9
    finally:
        holder.close()
    assert db.migrate() == []


def test_pool_recovers_from_terminated_connections(clean):
    """After a Postgres restart every pooled connection is dead; the next caller must get a working one."""
    dbname = clean.rsplit("/", 1)[1]

    async def go():
        p = await db.pool()
        async with p.connection() as c1, p.connection() as c2:      # two connections in the pool
            await db.kv_set(c1, "it:a", 1)
            await db.kv_set(c2, "it:b", 2)
        await asyncio.to_thread(admin, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                       "WHERE datname = %s AND pid <> pg_backend_pid()", (dbname,))
        await asyncio.sleep(0.2)
        for i in range(3):
            async with p.connection() as conn:
                await db.kv_set(conn, "it:a", i + 10)
                assert await db.kv_get(conn, "it:a") == i + 10
        async with p.connection() as conn:
            await db.add_event(conn, store_id, "status", {"from": "open", "to": "confirmed"})
    store_id = store_sync("westpac-secure.top")
    arun(go())
    assert q1("SELECT value FROM kv WHERE key = 'it:a'")["value"] == 12
    assert events(store_id, "status")[0]["detail"] == {"from": "open", "to": "confirmed"}


def test_enrich_write_does_not_undo_a_certificate_that_arrived_during_the_check(clean):
    """enrich reads a due row, spends seconds on DNS/RDAP, then writes. If store_hit recorded a new certificate in
    between (re-check soon, takedown cleared), the stale write must keep that, not set next_check_at to NULL or
    record a takedown."""
    wl = default_watchlist()
    hit = wl.score_hostname("commbank-login.top")

    async def go():
        p = await db.pool()
        async with p.connection() as conn:
            did, _ = await store_hit(conn, hit)
            await conn.execute("UPDATE domains SET next_check_at = now() - interval '1 minute' WHERE id = %s", (did,))
            due = await (await conn.execute(enrich.DUE_SQL, (10,))).fetchall()
            read = next(r for r in due if r["id"] == did)
            await asyncio.sleep(0.01)
            await store_hit(conn, wl.score_hostname("secure.commbank-login.top"))      # new certificate now
            stale = enrich.Update(next_check_at=None, takedown=("nxdomain", datetime.now(UTC)),
                                  cols={"takedown_at": datetime.now(UTC), "takedown_signal": "nxdomain"},
                                  events=[("taken_down", {"signal": "nxdomain"}), ("dns_resolves", {})])
            await enrich.write_update(conn, did, stale, read["last_seen"])
            fresh_read = await (await conn.execute("SELECT last_seen FROM domains WHERE id = %s", (did,))).fetchone()
            # same check without a concurrent certificate: written as computed
            normal = enrich.Update(next_check_at=None, cols={"takedown_at": datetime.now(UTC),
                                                             "takedown_signal": "nxdomain"},
                                   events=[("taken_down", {"signal": "nxdomain"})])
            return did, normal, fresh_read["last_seen"]
    did, normal, last_seen = arun(go())
    row = dom("commbank-login.top")
    assert row["takedown_at"] is None and row["takedown_signal"] is None
    assert row["next_check_at"] is not None and row["next_check_at"] <= db_now() + timedelta(minutes=11)
    assert [e["kind"] for e in events(did, "taken_down")] == []
    assert [e["kind"] for e in events(did, "dns_resolves")] == ["dns_resolves"]

    async def go2():
        p = await db.pool()
        async with p.connection() as conn:
            await enrich.write_update(conn, did, normal, last_seen)
    arun(go2())
    row = dom("commbank-login.top")
    assert row["takedown_signal"] == "nxdomain" and row["next_check_at"] is None
    assert len(events(did, "taken_down")) == 1
