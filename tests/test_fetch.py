"""Tests for the fetch worker side (cybercheck.jobs.fetch, cybercheck.jobs.retention,
cybercheck.fetch_client). Offline: a fake fetcher client, a fake database pool, a temp data dir."""
from __future__ import annotations

import asyncio
import base64
import gzip
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from cybercheck import db
from cybercheck.fetch_client import FetchClient
from cybercheck.jobs import fetch, retention

UTC = timezone.utc
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    # The test data dirs live on /tmp, which may be a small tmpfs: the free-disk guard has its own tests.
    monkeypatch.setenv("FETCH_MIN_FREE_GB", "0")
    monkeypatch.delenv("ENRICH_TRACK_DAYS", raising=False)
    monkeypatch.delenv("FETCH_TRACK_INTERVAL_H", raising=False)


def dom(**kw) -> dict:
    d = dict(id=1, registered_domain="commbank-login.top", hostnames=["www.commbank-login.top"],
             hostname="www.commbank-login.top", tier="high", status="open", score=80, brand_id="commbank",
             dns_state="resolves", live_state="unknown", first_live_at=None, last_live_at=None,
             watch_until=NOW + timedelta(days=14), reported_at=None, ai_verdict=None,
             next_fetch_at=None, fetch_state={}, first_seen=NOW - timedelta(days=1), status_changed_at=None)
    d.update(kw)
    return d


# ---- schedule: next_fetch_at -------------------------------------------------------------------

def test_next_fetch_backoff_steps():
    d = dom()
    assert fetch.next_fetch_at(d, 1, NOW, 2) == NOW + timedelta(hours=1)
    assert fetch.next_fetch_at(d, 2, NOW, 2) == NOW + timedelta(hours=6)
    assert fetch.next_fetch_at(d, 3, NOW, 2) == NOW + timedelta(hours=24)
    assert fetch.next_fetch_at(d, 4, NOW, 2) == NOW + timedelta(hours=24)


def test_next_fetch_stops_past_watch_window():
    # +6h is past watch_until and the domain is not tracked: park it AT watch_until. It must never be
    # None, because NULL next_fetch_at means "due now" and the domain would be re-fetched every run.
    wu = NOW + timedelta(minutes=30)
    d = dom(watch_until=wu)
    assert fetch.next_fetch_at(d, 2, NOW, 2) == wu
    d = dom(watch_until=NOW - timedelta(hours=1))
    assert fetch.next_fetch_at(d, 2, NOW, 2) == NOW


def test_next_fetch_never_none():
    for d in (dom(), dom(watch_until=None), dom(watch_until=NOW), dom(status="confirmed")):
        for n in range(0, 8):
            assert fetch.next_fetch_at(d, n, NOW, 2) is not None


def test_next_fetch_tracked_is_two_hourly():
    for d in (dom(status="confirmed", status_changed_at=NOW), dom(reported_at=NOW), dom(ai_verdict="phishing")):
        assert fetch.next_fetch_at(d, 9, NOW, 2) == NOW + timedelta(hours=2)
    # tracked keeps going past the watch window, inside the tracking window
    d = dom(status="confirmed", status_changed_at=NOW - timedelta(days=3), watch_until=NOW - timedelta(days=1))
    assert fetch.next_fetch_at(d, 9, NOW, 2) == NOW + timedelta(hours=2)


# ---- live_state transitions --------------------------------------------------------------------

def test_goes_live_on_first_load():
    d = dom(live_state="unknown", first_live_at=None)
    state = {}
    cols, events = fetch.apply_live_state(d, state, loaded=True, now=NOW)
    assert cols["live_state"] == "live"
    assert cols["first_live_at"] == NOW and cols["last_live_at"] == NOW
    assert any(e[0] == "went_live" for e in events)


def test_single_failure_does_not_flip_down():
    d = dom(live_state="live", first_live_at=NOW - timedelta(hours=2))
    state = {}
    cols, events = fetch.apply_live_state(d, state, loaded=False, now=NOW)
    assert "live_state" not in cols
    assert events == []
    assert state["fail_since"] is not None


def test_two_failures_15min_apart_flip_down():
    d = dom(live_state="live", first_live_at=NOW - timedelta(hours=3))
    state = {}
    fetch.apply_live_state(d, state, loaded=False, now=NOW)
    cols, events = fetch.apply_live_state(d, state, loaded=False, now=NOW + timedelta(minutes=20))
    assert cols["live_state"] == "down"
    assert any(e[0] == "page_down" for e in events)


def test_two_failures_too_close_do_not_flip():
    d = dom(live_state="live", first_live_at=NOW - timedelta(hours=3))
    state = {}
    fetch.apply_live_state(d, state, loaded=False, now=NOW)
    cols, events = fetch.apply_live_state(d, state, loaded=False, now=NOW + timedelta(minutes=5))
    assert "live_state" not in cols and events == []


def test_never_live_domain_not_marked_down():
    d = dom(live_state="unknown", first_live_at=None)
    state = {}
    fetch.apply_live_state(d, state, loaded=False, now=NOW)
    cols, events = fetch.apply_live_state(d, state, loaded=False, now=NOW + timedelta(minutes=30))
    assert "live_state" not in cols and events == []


def test_success_clears_failure_streak():
    d = dom(live_state="live", first_live_at=NOW - timedelta(hours=3))
    state = {"fail_since": fetch.iso(NOW), "fail_count": 1}
    cols, events = fetch.apply_live_state(d, state, loaded=True, now=NOW + timedelta(minutes=30))
    assert "fail_since" not in state and "fail_count" not in state
    assert cols["last_live_at"] == NOW + timedelta(minutes=30)


# ---- first hostname ----------------------------------------------------------------------------

def test_first_hostname():
    assert fetch._first_hostname(dom(hostname="a.b.top")) == "a.b.top"
    assert fetch._first_hostname(dom(hostname=None, hostnames=["h.top"])) == "h.top"
    assert fetch._first_hostname(dom(hostname=None, hostnames=[], registered_domain="r.top")) == "r.top"


def test_first_hostname_rejects_junk():
    # never build a URL from something that is not a plain DNS name
    for junk in ("evil.top/path", "a b.top", "user@evil.top", "evil.top:8080", "*.evil.top", "-x.top",
                 "127.0.0.1#.top", "", "x" * 300 + ".top"):
        assert fetch._first_hostname(dom(hostname=junk, hostnames=[junk], registered_domain="r.top")) == "r.top"
    assert fetch._first_hostname(dom(hostname="bad/x", hostnames=["bad/x"], registered_domain="bad/y")) is None
    assert fetch._first_hostname(dom(hostname="WWW.Example.TOP.")) == "www.example.top"


# ---- fetch client fallback (https then http) ---------------------------------------------------

class CannedClient:
    def __init__(self, by_url):
        self.by_url = by_url
        self.calls = []

    async def fetch(self, url, profile):
        self.calls.append((url, profile))
        return self.by_url.get(url)


def test_fetch_one_profile_falls_back_to_http():
    client = CannedClient({
        "https://h.top/": {"ok": True, "http_status": 500, "title": "err"},   # not loaded
        "http://h.top/": {"ok": True, "http_status": 200, "title": "ok"},      # loaded
    })
    out = run(fetch._fetch_one_profile(client, "h.top", "mobile"))
    assert out["http_status"] == 200
    assert [c[0] for c in client.calls] == ["https://h.top/", "http://h.top/"]


def test_fetch_one_profile_unreachable_raises():
    # The fetcher going away mid-run is NOT a page failure: it must not be recorded at all.
    client = CannedClient({"https://h.top/": None, "http://h.top/": None})
    with pytest.raises(fetch.FetcherUnavailable):
        run(fetch._fetch_one_profile(client, "h.top", "mobile"))


def test_fetch_one_profile_fetcher_fault_no_http_fallback():
    client = CannedClient({"https://h.top/": {"ok": False, "error": "hard timeout", "fetcher_error": True}})
    out = run(fetch._fetch_one_profile(client, "h.top", "mobile"))
    assert out["fetcher_error"] and [c[0] for c in client.calls] == ["https://h.top/"]


# ---- fake database -----------------------------------------------------------------------------

class FakeCursor:
    def __init__(self, rows=None, rowcount=0):
        self.rows, self.rowcount = rows or [], rowcount

    async def fetchall(self):
        return self.rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None


class _Ctx:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, due_rows=None, candidates=None, referenced=False):
        self.due_rows = due_rows or []
        self.candidates = candidates or []
        self.referenced = referenced
        self.calls = []
        self._page_id = 100

    async def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        s = " ".join(sql.split())
        if s.startswith("SELECT d.id, d.registered_domain, d.hostnames"):
            return FakeCursor(self.due_rows)
        if s.startswith("INSERT INTO pages"):
            self._page_id += 1
            return FakeCursor([{"id": self._page_id}])
        if s.startswith("SELECT p.id, p.domain_id, p.screenshot_path"):   # retention candidates
            return FakeCursor(self.candidates)
        if s.startswith("SELECT 1 FROM pages o"):                         # retention referenced?
            return FakeCursor([{"?column?": 1}] if self.referenced else [])
        return FakeCursor([], rowcount=1)

    def transaction(self):
        return _Ctx(None)

    def find(self, prefix):
        return [(s, p) for s, p in self.calls if s.startswith(prefix)]


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def connection(self):
        return _Ctx(self.conn)


def _webp_b64():
    return base64.b64encode(b"RIFF....WEBPfake-image-bytes").decode("ascii")


class FakeFetchClient:
    """Replaces cybercheck.jobs.fetch.FetchClient. Class attributes set per test."""
    health_data = {"ok": True, "egress_ip": "203.0.113.5", "egress_country": "Australia"}
    responder = None
    configured = True

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def health(self):
        return type(self).health_data

    async def fetch(self, url, profile):
        return type(self).responder(url, profile)


def _settings(tmp_path, **over):
    base = dict(data_dir=tmp_path, screenshot_retention_days=60, fetch_min_score=60, fetch_concurrency=2)
    base.update(over)
    return SimpleNamespace(**base)


# ---- run_once: skip when the fetcher is unavailable --------------------------------------------

def test_run_once_skips_when_fetcher_down(monkeypatch, tmp_path):
    FakeFetchClient.health_data = {"ok": False, "vpn_running": False}
    monkeypatch.setattr(fetch, "FetchClient", FakeFetchClient)
    conn = FakeConn(due_rows=[dom()])
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(fetch, "settings", lambda: _settings(tmp_path))
    ctx = SimpleNamespace(log=_log())
    out = run(fetch.run_once(ctx))
    assert out == {"skipped": "fetcher unavailable"}
    assert conn.find("SELECT d.id, d.registered_domain, d.hostnames") == []   # never queried


# ---- run_once: happy path, a live credential page ----------------------------------------------

def test_run_once_stores_live_page(monkeypatch, tmp_path):
    FakeFetchClient.health_data = {"ok": True, "egress_ip": "203.0.113.5", "egress_country": "Australia"}

    def responder(url, profile):
        if url.startswith("https://"):
            return {"ok": True, "http_status": 200, "final_url": url, "url": url,
                    "title": "Commonwealth Bank NetBank login", "redirect_chain": [],
                    "text_excerpt": "Enter your password and one-time code.",
                    "html": "<html><body>login</body></html>",
                    "screenshot_webp_b64": _webp_b64(),
                    "forms": [{"action": "https://evil-collector.ru/p", "method": "post",
                               "has_password": True, "has_otp": True, "has_card": False,
                               "inputs": [{"type": "password", "name": "password", "autocomplete": "current-password"},
                                          {"type": "text", "name": "otp", "autocomplete": "one-time-code"}]}],
                    "egress_ip": "203.0.113.5", "egress_country": "Australia", "timings": {"total_ms": 900}}
        return {"ok": False, "error": "should not reach http", "http_status": None, "final_url": None}

    FakeFetchClient.responder = staticmethod(responder)
    monkeypatch.setattr(fetch, "FetchClient", FakeFetchClient)

    from cybercheck import scoring

    class FakeBrand:
        id = "commbank"; name = "Commonwealth Bank"; keywords = ["commbank", "netbank"]

    class FakeWL:
        brands = {"commbank": FakeBrand()}
        official = {}

        def is_official(self, n):
            return False
    monkeypatch.setattr(scoring, "default_watchlist", lambda: FakeWL())

    conn = FakeConn(due_rows=[dom()])
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(fetch, "settings", lambda: _settings(tmp_path))
    ctx = SimpleNamespace(log=_log())

    out = run(fetch.run_once(ctx))
    assert out["due"] == 1 and out["fetched"] == 1 and out["live"] == 1

    # two profiles on the first round -> two page inserts
    inserts = conn.find("INSERT INTO pages")
    assert len(inserts) == 2
    # a screenshot file was written under the temp data dir
    shots = list((tmp_path / "screenshots" / "1").glob("*-mobile.webp"))
    assert shots, "expected a mobile screenshot file"
    htmls = list((tmp_path / "html" / "1").glob("*-mobile.html.gz"))
    assert htmls and gzip.decompress(htmls[0].read_bytes()).startswith(b"<html")

    # the domain update went live, set a page_score, and scheduled the next fetch
    dom_updates = conn.find("UPDATE domains SET")
    assert dom_updates
    sql, params = dom_updates[-1]
    assert "live_state = %s" in sql and "page_score = %s" in sql
    events = [p for (s, p) in conn.find("INSERT INTO domain_events")]
    assert any(e and e[1] == "went_live" for e in events)


# ---- dedup: identical screenshot is not rewritten ----------------------------------------------

def test_screenshot_dedup_reuses_previous_file(monkeypatch, tmp_path):
    store = fetch.Store(tmp_path, retain_days=30)
    conn = FakeConn()
    state = {}
    result = {"ok": True, "http_status": 200, "final_url": "https://x.top/", "url": "https://x.top/",
              "title": "t", "screenshot_webp_b64": _webp_b64(), "html": "<html>x</html>", "forms": []}
    from cybercheck.pagefeatures import extract
    feats = extract(result, {"registered_domain": "x.top"}, None)
    run(store.save_page(conn, dom(), "mobile", result, feats, state))
    first_files = list((tmp_path / "screenshots" / "1").glob("*.webp"))
    assert len(first_files) == 1
    # same content again: no new screenshot file, the row reuses the previous path
    run(store.save_page(conn, dom(), "mobile", result, feats, state))
    assert len(list((tmp_path / "screenshots" / "1").glob("*.webp"))) == 1


# ---- retention ---------------------------------------------------------------------------------

def test_retention_deletes_expired_files(monkeypatch, tmp_path):
    (tmp_path / "screenshots" / "7").mkdir(parents=True)
    shot = tmp_path / "screenshots" / "7" / "55-mobile.webp"
    shot.write_bytes(b"img")
    conn = FakeConn(candidates=[{"id": 55, "domain_id": 7, "screenshot_path": "screenshots/7/55-mobile.webp",
                                 "html_path": None, "status": "open"}], referenced=False)
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(retention, "settings", lambda: _settings(tmp_path))
    ctx = SimpleNamespace(log=_log())
    out = run(retention.run_once(ctx))
    assert out["files_deleted"] == 1 and out["released"] == 1
    assert not shot.exists()
    assert conn.find("UPDATE pages SET screenshot_path = NULL")


def test_retention_keeps_confirmed_as_evidence(monkeypatch, tmp_path):
    (tmp_path / "screenshots" / "9").mkdir(parents=True)
    shot = tmp_path / "screenshots" / "9" / "1-mobile.webp"
    shot.write_bytes(b"img")
    conn = FakeConn(candidates=[{"id": 1, "domain_id": 9, "screenshot_path": "screenshots/9/1-mobile.webp",
                                 "html_path": None, "status": "confirmed"}])
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(retention, "settings", lambda: _settings(tmp_path))
    out = run(retention.run_once(SimpleNamespace(log=_log())))
    assert out["kept_evidence"] == 1 and out["files_deleted"] == 0
    assert shot.exists()
    assert conn.find("UPDATE pages SET is_evidence = true")


def test_retention_will_not_delete_outside_data_dir(monkeypatch, tmp_path):
    conn = FakeConn(candidates=[{"id": 2, "domain_id": 1, "screenshot_path": "../../etc/passwd",
                                 "html_path": None, "status": "open"}], referenced=False)
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(retention, "settings", lambda: _settings(tmp_path))
    out = run(retention.run_once(SimpleNamespace(log=_log())))
    assert out["files_deleted"] == 0   # refused the out-of-tree path
    assert out["released"] == 1        # the row's paths were still nulled


# ---- fetch_client over a mock transport --------------------------------------------------------

def test_fetch_client_returns_none_when_unreachable(monkeypatch):
    c = FetchClient(base_url="http://127.0.0.1:8432", token="tok")

    async def go():
        transport = httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("no")))
        c._client = httpx.AsyncClient(transport=transport,
                                      headers={"Authorization": "Bearer tok"})
        assert await c.health() is None
        assert await c.fetch("https://x.top/", "mobile") is None
        await c.close()
    run(go())


def test_fetch_client_503_is_unavailable_not_failure():
    c = FetchClient(base_url="http://127.0.0.1:8432", token="tok")

    async def go():
        def handler(req):
            if req.url.path == "/health":
                return httpx.Response(503, json={"ok": False, "vpn_running": False})
            return httpx.Response(503, json={"ok": False, "error": "failing closed"})
        c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                      headers={"Authorization": "Bearer tok"})
        h = await c.health()
        assert h == {"ok": False, "vpn_running": False, "http_status": 503}
        assert await c.fetch("https://x.top/", "mobile") is None   # 503 -> unavailable, not a page failure
        await c.close()
    run(go())


def test_fetch_client_parses_ok_response():
    c = FetchClient(base_url="http://127.0.0.1:8432", token="tok")

    async def go():
        def handler(req):
            return httpx.Response(200, json={"ok": True, "http_status": 200, "title": "hi"})
        c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                      headers={"Authorization": "Bearer tok"})
        data = await c.fetch("https://x.top/", "mobile")
        assert data["ok"] and data["url"] == "https://x.top/" and data["profile"] == "mobile"
        await c.close()
    run(go())


# ---- small async / logging helpers -------------------------------------------------------------

def _async(value):
    async def _coro():
        return value
    return _coro()


def _log():
    import logging
    return logging.getLogger("test.fetch")


# ---- review additions --------------------------------------------------------------------------

def _wire(monkeypatch, tmp_path, conn, responder, health=None):
    FakeFetchClient.health_data = health or {"ok": True, "egress_ip": "203.0.113.5", "egress_country": "Australia"}
    FakeFetchClient.responder = staticmethod(responder)
    monkeypatch.setattr(fetch, "FetchClient", FakeFetchClient)
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(fetch, "settings", lambda: _settings(tmp_path))
    from cybercheck import scoring
    monkeypatch.setattr(scoring, "default_watchlist", lambda: None)


def _writes(conn):
    return [s for s, _ in conn.calls if s.startswith(("INSERT", "UPDATE"))]


def test_fetcher_vanishing_mid_run_changes_nothing(monkeypatch, tmp_path):
    """Health said OK, then the fetcher started failing closed (VPN dropped): no page rows, no domain
    update, no failure streak; the run stops instead of hammering the remaining domains."""
    calls = []

    def responder(url, profile):
        calls.append(url)
        return None                                   # FetchClient returns None on 503 / unreachable

    conn = FakeConn(due_rows=[dom(id=1, live_state="live", first_live_at=NOW),
                              dom(id=2), dom(id=3), dom(id=4)])
    _wire(monkeypatch, tmp_path, conn, responder)
    out = run(fetch.run_once(SimpleNamespace(log=_log())))
    assert _writes(conn) == []
    assert out["fetched"] == 0 and out.get("stopped")
    assert len(calls) <= 2                            # at most the in-flight ones (concurrency 2)


def test_fetcher_fault_does_not_count_towards_down(monkeypatch, tmp_path):
    def responder(url, profile):
        return {"ok": False, "url": url, "error": "hard timeout", "fetcher_error": True}

    d = dom(live_state="live", first_live_at=NOW - timedelta(days=1),
            fetch_state={"n": 3, "fail_since": fetch.iso(NOW - timedelta(hours=1)), "fail_count": 1})
    conn = FakeConn(due_rows=[d])
    _wire(monkeypatch, tmp_path, conn, responder)
    run(fetch.run_once(SimpleNamespace(log=_log())))
    sql, params = conn.find("UPDATE domains SET")[-1]
    assert "live_state" not in sql                    # not flipped to down
    assert not conn.find("INSERT INTO domain_events")
    state = params[-2].obj
    assert state["fail_count"] == 1                   # streak unchanged


def test_live_page_failure_rechecks_soon(monkeypatch, tmp_path):
    def responder(url, profile):
        return {"ok": False, "url": url, "error": "net::ERR_CONNECTION_REFUSED", "http_status": None}

    d = dom(live_state="live", first_live_at=NOW - timedelta(days=1), fetch_state={"n": 5})
    conn = FakeConn(due_rows=[d])
    _wire(monkeypatch, tmp_path, conn, responder)
    before = datetime.now(UTC)
    run(fetch.run_once(SimpleNamespace(log=_log())))
    sql, params = conn.find("UPDATE domains SET")[-1]
    next_at = params[-3]
    assert next_at <= before + fetch.DOWN_RECHECK + timedelta(seconds=30)
    assert params[-2].obj["fail_count"] == 1


def test_dedup_rewrites_when_previous_file_was_deleted(tmp_path):
    store = fetch.Store(tmp_path, retain_days=30)
    conn = FakeConn()
    state = {}
    result = {"ok": True, "http_status": 200, "final_url": "https://x.top/", "url": "https://x.top/",
              "title": "t", "screenshot_webp_b64": _webp_b64(), "html": "<html>x</html>", "forms": []}
    from cybercheck.pagefeatures import extract
    feats = extract(result, {"registered_domain": "x.top"}, None)
    run(store.save_page(conn, dom(), "mobile", result, feats, state))
    for f in (tmp_path / "screenshots" / "1").glob("*.webp"):
        f.unlink()                                    # retention removed it meanwhile
    run(store.save_page(conn, dom(), "mobile", result, feats, state))
    files = list((tmp_path / "screenshots" / "1").glob("*.webp"))
    assert len(files) == 1 and state["shots"]["mobile"]["path"].endswith(files[0].name)


def test_due_sql_shape():
    sql = " ".join(fetch.DUE_SQL.split())
    assert "d.dns_state = 'resolves' AND d.takedown_at IS NULL" in sql
    assert "d.status IN ('open', 'confirmed')" in sql
    assert "%(min_score)s" in sql and "%(batch)s" in sql


def test_retention_is_bounded_per_run(monkeypatch, tmp_path):
    monkeypatch.setenv("RETENTION_BATCH", "1")
    conn = FakeConn(candidates=[{"id": 5, "domain_id": 1, "screenshot_path": None,
                                 "html_path": "html/1/5-mobile.html.gz", "status": "open"}])
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(retention, "settings", lambda: _settings(tmp_path))
    out = run(retention.run_once(SimpleNamespace(log=_log())))
    assert out["released"] == retention.MAX_BATCHES   # kept draining, but stopped at the bound


def test_fetch_client_fetcher_errors_are_unavailable():
    c = FetchClient(base_url="http://127.0.0.1:8432", token="tok")

    async def go():
        for code in (401, 403, 500, 502, 503):
            c._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req, code=code: httpx.Response(code, json={})))
            assert await c.fetch("https://x.top/", "mobile") is None, code
            await c.close()
        # a lying 503 body cannot make health() look OK
        c._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(503, json={"ok": True})))
        assert (await c.health())["ok"] is False
        await c.close()
    run(go())


# ---- fetcher/app.py (the sandboxed fetcher API), with playwright stubbed out -------------------

def _load_fetcher_app(monkeypatch, **env):
    import importlib.util
    import sys
    import types
    from pathlib import Path

    pw = types.ModuleType("playwright")
    api = types.ModuleType("playwright.async_api")
    api.Browser = object
    api.async_playwright = lambda: None
    pw.async_api = api
    monkeypatch.setitem(sys.modules, "playwright", pw)
    monkeypatch.setitem(sys.modules, "playwright.async_api", api)
    base = {"FETCHER_TOKEN": "t" * 32, "GLUETUN_API_KEY": "k" * 32, "FETCH_EXPECTED_COUNTRY": "AU"}
    base.update(env)
    for k, v in base.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    path = Path(__file__).resolve().parent.parent / "fetcher" / "app.py"
    spec = importlib.util.spec_from_file_location("fetcher_app_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fetcher_blocks_local_and_private_targets(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    blocked = ["localhost", "LOCALHOST.", "api.localhost", "127.0.0.1", "127.1", "0x7f000001", "2130706433",
               "0.0.0.0", "0", "10.1.2.3", "172.29.254.1", "192.168.0.1", "100.64.0.10", "100.100.100.100",
               "169.254.169.254", "[::1]", "::", "[::ffff:127.0.0.1]", "::ffff:a9fe:a9fe", "fd7a:115c:a1e0::1",
               "fe80::1", "224.0.0.251", "255.255.255.255", "192.0.2.1", "198.18.0.1", "", None]
    for h in blocked:
        assert app._blocked_host(h), h
    for h in ("example.com", "commbank-login.top", "8.8.8.8", "203.0.114.1", "1.1.1.1", "2606:4700::1111"):
        assert not app._blocked_host(h), h


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _egress_with(monkeypatch, app, handler):
    real = _REAL_ASYNC_CLIENT

    def factory(*a, **k):
        k["transport"] = app.httpx.MockTransport(handler)
        return real(*a, **k)
    monkeypatch.setattr(app.httpx, "AsyncClient", factory)
    return app.Egress()


def _gluetun(no_auth=False, status="running", country="Australia", ip="203.0.113.7"):
    def handler(req):
        if not no_auth and req.headers.get("x-api-key") != "k" * 32:
            return httpx.Response(401)
        if req.url.path == "/v1/vpn/status":
            return httpx.Response(200, json={"status": status})
        if req.url.path == "/v1/publicip/ip":
            return httpx.Response(200, json={"public_ip": ip, "country": country})
        return httpx.Response(404)
    return handler


def test_fetcher_egress_gate_ok(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    e = run(_egress_with(monkeypatch, app, _gluetun()).get())
    assert e["ok"] and e["egress_ip"] == "203.0.113.7" and e["egress_country"] == "Australia"


def test_fetcher_egress_gate_fails_closed(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    cases = [_gluetun(no_auth=True),            # control server without auth: page JS could drive the VPN
             _gluetun(status="stopped"),
             _gluetun(country="United States"),
             _gluetun(country=""),
             _gluetun(ip=""),
             _gluetun(ip="not-an-ip")]
    for h in cases:
        e = run(_egress_with(monkeypatch, app, h).get(force=True))
        assert not e["ok"], e

    def boom(req):
        raise httpx.ConnectError("refused")
    eg = _egress_with(monkeypatch, app, boom)
    e = run(eg.get())
    assert not e["ok"] and eg.unreachable_since is not None


def test_fetcher_refuses_short_or_missing_key(monkeypatch):
    app = _load_fetcher_app(monkeypatch, GLUETUN_API_KEY="short")
    e = run(_egress_with(monkeypatch, app, _gluetun(no_auth=True)).get())
    assert not e["ok"] and "GLUETUN_API_KEY" in e["error"]


def test_fetcher_country_check_can_be_disabled_only_explicitly(monkeypatch):
    app = _load_fetcher_app(monkeypatch, FETCH_EXPECTED_COUNTRY="")
    assert app._country_matches("United States")
    app = _load_fetcher_app(monkeypatch, FETCH_EXPECTED_COUNTRY=None)     # unset -> AU
    assert app.EXPECTED_COUNTRY == "AU" and not app._country_matches("United States")
    assert app._country_matches("Australia") and app._country_matches("au")


def test_fetcher_api_auth_origin_and_target_checks(monkeypatch):
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch)
    client = TestClient(app.app)                      # no `with`: lifespan (browser start) not run
    good = {"Authorization": "Bearer " + "t" * 32}
    assert client.post("/fetch", json={"url": "https://x.top/"}).status_code == 401
    assert client.post("/fetch", json={"url": "https://x.top/"},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    # page JavaScript reaching the shared namespace always carries an Origin
    assert client.post("/fetch", json={"url": "https://x.top/"},
                       headers={**good, "Origin": "https://evil.top"}).status_code == 403
    assert client.get("/health", headers={**good, "Origin": "null"}).status_code == 403
    for bad in ("http://127.0.0.1:8000/v1/vpn/status", "http://localhost:8432/fetch", "file:///etc/passwd",
                "javascript:alert(1)", "http://[::1]/", "http://169.254.169.254/", "http://0x7f.1/"):
        assert client.post("/fetch", json={"url": bad}, headers=good).status_code == 400, bad


def test_fetcher_api_fails_closed_without_vpn(monkeypatch):
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch)

    async def closed(force=False):
        return {"ok": False, "vpn_running": False, "egress_ip": None, "egress_country": None, "error": "VPN is not running"}
    monkeypatch.setattr(app.egress, "get", closed)

    async def never(url, profile):
        raise AssertionError("must not fetch without a verified VPN")
    monkeypatch.setattr(app.pool, "fetch", never)
    client = TestClient(app.app)
    good = {"Authorization": "Bearer " + "t" * 32}
    assert client.post("/fetch", json={"url": "https://x.top/"}, headers=good).status_code == 503
    assert client.get("/health", headers=good).status_code == 503


def test_fetcher_rejects_short_token(monkeypatch):
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch, FETCHER_TOKEN="abc")
    client = TestClient(app.app)
    assert client.get("/health", headers={"Authorization": "Bearer abc"}).status_code == 401


def test_fetcher_watchdog(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    eg = app.Egress()
    assert not eg.watchdog_expired()
    eg.started -= 10_000
    eg.unreachable_since = eg.started + 1
    assert eg.watchdog_expired()


def test_compose_isolation_invariants():
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    c = yaml.safe_load((root / "fetcher" / "compose.yaml").read_text())
    vpn, fe = c["services"]["vpn"], c["services"]["fetcher"]
    assert vpn["profiles"] == ["fetch"] and fe["profiles"] == ["fetch"]
    assert fe["network_mode"] == "service:vpn" and "ports" not in fe and "networks" not in fe
    assert "env_file" not in fe
    assert set(fe["environment"]) <= {"FETCHER_TOKEN", "GLUETUN_API_KEY", "GLUETUN_CONTROL_URL",
                                       "FETCH_EXPECTED_COUNTRY", "FETCH_CONCURRENCY", "FETCH_MAX_PAGES"}
    assert all(p.startswith("127.0.0.1:") for p in vpn["ports"])
    assert fe["cap_drop"] == ["ALL"] and fe["read_only"] is True and fe["user"] == "pwuser"
    assert "no-new-privileges:true" in fe["security_opt"]
    assert any(o.startswith("seccomp=") for o in fe["security_opt"])
    assert (root / fe["security_opt"][1].split("=", 1)[1]).is_file()    # relative to the repo root
    assert fe["depends_on"]["vpn"] == {"condition": "service_healthy", "restart": True}
    env = vpn["environment"]
    assert env["BLOCK_MALICIOUS"] == "off" and env["BLOCK_SURVEILLANCE"] == "off"
    assert "100.64.0.0/10" in env["DNS_BLOCK_IP_PREFIXES"]
    assert env["HTTP_CONTROL_SERVER_ADDRESS"] == "127.0.0.1:8000"
    assert '"auth":"apikey"' in env["HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE"]
    assert "FIREWALL_OUTBOUND_SUBNETS" not in env
    assert not any(k.startswith("FIREWALL_ENABLED") for k in env)
    assert "net.ipv6.conf.all.disable_ipv6=1" in vpn["sysctls"]
    for svc in (vpn, fe):
        assert svc["restart"] == "unless-stopped" and svc["mem_limit"]
        assert svc["logging"]["options"] == {"max-size": "10m", "max-file": "3"}
    assert "@sha256:" in vpn["image"]
    text = (root / "fetcher" / "compose.yaml").read_text()
    code = "\n".join(l.split("#", 1)[0] for l in text.splitlines())
    assert ":?" not in code      # a required-var error would break plain `docker compose up -d`
    net = c["networks"]["ccvpn"]
    assert net["enable_ipv6"] is False and net["ipam"]["config"][0]["subnet"] == "172.29.254.0/28"
    # post-rules: every non-public range rejected for NEW connections on any interface
    rules = [l for l in (root / "fetcher" / "post-rules.txt").read_text().splitlines() if l.startswith("iptables")]
    for cidr in ("172.29.254.0/28", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                 "169.254.0.0/16"):
        assert any(f"-d {cidr} " in r and "--ctstate NEW" in r and "-j REJECT" in r and " -o " not in r
                   for r in rules), cidr
    assert not any(l.startswith("ip6tables") for l in (root / "fetcher" / "post-rules.txt").read_text().splitlines())


# ---- security review fixes ---------------------------------------------------------------------

# Tracking: fetch and enrich use one window (enrich.track_end), so fetching never outlives enrich, which
# is the only job that records a takedown.

def test_tracked_fetching_ends_with_enrichs_tracking_window():
    from cybercheck import enrich
    cfg = enrich.EnrichConfig()
    d = dom(ai_verdict="phishing", first_seen=NOW - timedelta(days=40), watch_until=NOW - timedelta(days=26))
    assert not fetch.is_tracked(d, NOW)
    assert enrich.next_check(d, NOW, cfg) is None
    assert fetch.next_fetch_at(d, 9, NOW, 2) == NOW         # parked: DUE_SQL no longer selects it
    # the two jobs agree at every point of the window (watch window over, so only tracking counts)
    for kind in ({"ai_verdict": "phishing"}, {"reported_at": NOW - timedelta(days=10)},
                 {"status": "confirmed", "status_changed_at": NOW - timedelta(days=5)}):
        d = dom(first_seen=NOW - timedelta(days=12), watch_until=NOW - timedelta(days=1), **kind)
        for h in range(0, 40 * 24, 7):
            t = NOW + timedelta(hours=h)
            assert fetch.is_tracked(d, t) == (enrich.next_check(d, t, cfg) is not None), (kind, h)
            if fetch.is_tracked(d, t):
                assert fetch.next_fetch_at(d, 9, t, 2) == t + timedelta(hours=2)
            else:
                assert fetch.next_fetch_at(d, 9, t, 2) == t


def test_tracking_window_follows_enrich_track_days(monkeypatch):
    d = dom(ai_verdict="phishing", first_seen=NOW - timedelta(days=12), watch_until=NOW - timedelta(days=1))
    assert fetch.is_tracked(d, NOW)
    monkeypatch.setenv("ENRICH_TRACK_DAYS", "10")
    assert not fetch.is_tracked(d, NOW)
    assert fetch.next_fetch_at(d, 9, NOW, 2) == NOW


def test_due_sql_bounds_tracked_domains_like_enrich_revive():
    from cybercheck import enrich
    due = " ".join(fetch.DUE_SQL.split())
    revive = " ".join(enrich.REVIVE_SQL.split())
    anchor = ("GREATEST(first_seen, reported_at, CASE WHEN status = 'confirmed' THEN status_changed_at END) "
              "> now() - make_interval(days =>")
    assert anchor in revive
    assert anchor.replace("first_seen", "d.first_seen").replace("reported_at", "d.reported_at") \
        .replace("status = ", "d.status = ").replace("status_changed_at", "d.status_changed_at") \
        + " %(track_days)s)" in due
    assert "d.first_seen" in due.split("FROM")[0] and "d.status_changed_at" in due.split("FROM")[0]


def test_run_once_passes_the_tracking_window(monkeypatch, tmp_path):
    monkeypatch.setenv("ENRICH_TRACK_DAYS", "12")
    conn = FakeConn(due_rows=[])
    _wire(monkeypatch, tmp_path, conn, lambda u, p: None)
    run(fetch.run_once(SimpleNamespace(log=_log())))
    (_, params), = conn.find("SELECT d.id, d.registered_domain")
    assert params["track_days"] == 12


# Disk: no snapshot files below FETCH_MIN_FREE_GB, the row is still stored, and the run says so.

def _page_result(**kw):
    r = {"ok": True, "http_status": 200, "final_url": "https://x.top/", "url": "https://x.top/",
         "title": "t", "screenshot_webp_b64": _webp_b64(), "html": "<html>x</html>", "forms": []}
    r.update(kw)
    return r


def test_low_disk_skips_snapshot_files_but_keeps_the_row(monkeypatch, tmp_path):
    from cybercheck.pagefeatures import extract
    monkeypatch.setattr(fetch, "_free_bytes", lambda p: 2 * 1024 ** 3)       # 2 GB free
    store = fetch.Store(tmp_path, retain_days=30, min_free_gb=10)
    conn = FakeConn()
    state = {}
    result = _page_result()
    run(store.save_page(conn, dom(), "mobile", result, extract(result, {"registered_domain": "x.top"}, None), state))
    assert store.low_disk
    assert len(conn.find("INSERT INTO pages")) == 1
    assert not conn.find("UPDATE pages SET screenshot_path")
    assert not list(tmp_path.rglob("*.webp")) and not list(tmp_path.rglob("*.gz"))
    feats = conn.find("INSERT INTO pages")[0][1]["features"].obj
    assert feats["files_skipped"] == "low_disk"
    assert state["shots"] == {} and state["htmls"] == {}
    # with room again the files are written
    monkeypatch.setattr(fetch, "_free_bytes", lambda p: 50 * 1024 ** 3)
    store2 = fetch.Store(tmp_path, retain_days=30, min_free_gb=10)
    run(store2.save_page(conn, dom(), "mobile", result, extract(result, {"registered_domain": "x.top"}, None), state))
    assert not store2.low_disk and list(tmp_path.rglob("*.webp"))


def test_run_once_reports_low_disk(monkeypatch, tmp_path):
    monkeypatch.setenv("FETCH_MIN_FREE_GB", "10")
    monkeypatch.setattr(fetch, "_free_bytes", lambda p: 1024 ** 3)
    conn = FakeConn(due_rows=[dom()])
    _wire(monkeypatch, tmp_path, conn, lambda url, profile: _page_result(url=url))
    out = run(fetch.run_once(SimpleNamespace(log=_log())))
    assert out["low_disk"] is True and out["fetched"] == 1
    assert not list(tmp_path.rglob("*.webp"))


def test_free_bytes_walks_up_to_an_existing_directory(tmp_path):
    assert fetch._free_bytes(tmp_path / "not" / "yet" / "there") == fetch.shutil.disk_usage(tmp_path).free
    assert fetch.Store(tmp_path, 30, min_free_gb=0).disk_ok()


# Orphans: files written by a save that then fails are removed again, and no .tmp is left.

def test_failed_save_removes_the_files_it_wrote(monkeypatch, tmp_path):
    from cybercheck.pagefeatures import extract
    real = fetch._write_file

    def flaky(data_dir, rel, data):
        if rel.startswith("html/"):
            raise OSError(28, "No space left on device")
        return real(data_dir, rel, data)
    monkeypatch.setattr(fetch, "_write_file", flaky)
    store = fetch.Store(tmp_path, retain_days=30)
    state = {}
    result = _page_result()
    with pytest.raises(OSError):
        run(store.save_page(FakeConn(), dom(), "mobile", result,
                            extract(result, {"registered_domain": "x.top"}, None), state))
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []           # the screenshot was removed
    assert state.get("shots") == {}                                          # and is not remembered


def test_failed_path_update_removes_both_files(tmp_path):
    from cybercheck.pagefeatures import extract

    class BrokenUpdate(FakeConn):
        async def execute(self, sql, params=None):
            if sql.startswith("UPDATE pages SET screenshot_path"):
                raise RuntimeError("connection lost")
            return await super().execute(sql, params)
    store = fetch.Store(tmp_path, retain_days=30)
    result = _page_result()
    with pytest.raises(RuntimeError):
        run(store.save_page(BrokenUpdate(), dom(), "mobile", result,
                            extract(result, {"registered_domain": "x.top"}, None), {}))
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_write_file_leaves_no_tmp_on_failure(monkeypatch, tmp_path):
    def boom(self, target):
        raise OSError(5, "I/O error")
    monkeypatch.setattr(fetch.Path, "replace", boom)
    with pytest.raises(OSError):
        fetch._write_file(tmp_path, "screenshots/1/5-mobile.webp", b"img")
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


# Fetcher faults: a round of faults only does not use up the schedule and backs off.

def test_all_fault_round_keeps_the_schedule_step(monkeypatch, tmp_path):
    calls = []

    def responder(url, profile):
        calls.append(profile)
        return {"ok": False, "url": url, "error": "browser has been closed", "fetcher_error": True}

    conn = FakeConn(due_rows=[dom()])                 # a new domain: first round, mobile + desktop
    _wire(monkeypatch, tmp_path, conn, responder)
    before = datetime.now(UTC)
    run(fetch.run_once(SimpleNamespace(log=_log())))
    assert calls == ["mobile", "desktop"]
    sql, params = conn.find("UPDATE domains SET")[-1]
    state, next_at = params[-2].obj, params[-3]
    assert state.get("n", 0) == 0 and state["faults"] == 1      # first round (desktop) still pending
    assert before + timedelta(minutes=29) <= next_at <= datetime.now(UTC) + timedelta(minutes=31)
    assert "live_state" not in sql


def test_fault_backoff_doubles_and_is_capped(monkeypatch, tmp_path):
    def responder(url, profile):
        return {"ok": False, "url": url, "error": "hard timeout", "fetcher_error": True}
    for faults, expect in ((1, timedelta(hours=1)), (3, timedelta(hours=4)), (4, timedelta(hours=6)),
                           (500, timedelta(hours=6))):
        conn = FakeConn(due_rows=[dom(fetch_state={"n": 4, "faults": faults})])
        _wire(monkeypatch, tmp_path, conn, responder)
        before = datetime.now(UTC)
        run(fetch.run_once(SimpleNamespace(log=_log())))
        _, params = conn.find("UPDATE domains SET")[-1]
        assert params[-2].obj["faults"] == faults + 1 and params[-2].obj["n"] == 4
        assert before + expect - timedelta(seconds=5) <= params[-3] <= datetime.now(UTC) + expect


def test_conclusive_round_clears_faults_and_advances(monkeypatch, tmp_path):
    conn = FakeConn(due_rows=[dom(fetch_state={"n": 0, "faults": 3})])
    _wire(monkeypatch, tmp_path, conn, lambda url, profile: _page_result(url=url))
    run(fetch.run_once(SimpleNamespace(log=_log())))
    _, params = conn.find("UPDATE domains SET")[-1]
    assert params[-2].obj["n"] == 1 and "faults" not in params[-2].obj


def test_request_the_healthy_fetcher_cannot_answer_is_backed_off_not_retried_every_run(monkeypatch, tmp_path):
    """A page that makes /fetch fail (HTTP 500) while /health is fine: the domain is backed off and the
    run carries on with the other domains, instead of the domain staying due at the head of the queue."""
    calls = []

    def handler(req):
        if req.url.path == "/health":
            return httpx.Response(200, json={"ok": True, "egress_ip": "203.0.113.5"})
        url = __import__("json").loads(req.content)["url"]
        calls.append(url)
        if "poison" in url:
            return httpx.Response(500, text="Internal Server Error")
        return httpx.Response(200, json=_page_result(url=url))

    real_init = FetchClient.__init__

    def init(self, *a, **k):
        real_init(self, base_url="http://127.0.0.1:8432", token="tok")
    monkeypatch.setattr(FetchClient, "__init__", init)
    real_enter = FetchClient.__aenter__

    async def enter(self):
        await real_enter(self)
        await self._client.aclose()
        self._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return self
    monkeypatch.setattr(FetchClient, "__aenter__", enter)
    monkeypatch.setattr(fetch, "FetchClient", FetchClient)
    conn = FakeConn(due_rows=[dom(id=1, hostnames=["poison.top"], hostname="poison.top",
                                  registered_domain="poison.top"),
                              dom(id=2, hostnames=["fine.top"], hostname="fine.top", registered_domain="fine.top")])
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(fetch, "settings", lambda: _settings(tmp_path))
    from cybercheck import scoring
    monkeypatch.setattr(scoring, "default_watchlist", lambda: None)
    out = run(fetch.run_once(SimpleNamespace(log=_log())))
    assert "stopped" not in out and out["fetched"] == 2
    updates = {p[-1]: p for s, p in conn.find("UPDATE domains SET")}
    assert updates[1][-2].obj["faults"] == 1 and updates[1][-3] > datetime.now(UTC) + timedelta(minutes=25)
    assert "faults" not in updates[2][-2].obj
    assert sum("poison" in c for c in calls) == 2      # mobile + desktop once each, https only (no http retry)


# fetch_client: responses that say nothing about the page are fetcher faults, never page failures.

def _client_with(handler):
    c = FetchClient(base_url="http://127.0.0.1:8432", token="tok")
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


def test_fetch_client_oversize_and_garbage_are_fetcher_faults(monkeypatch):
    from cybercheck import fetch_client
    from cybercheck.pagefeatures import page_loaded

    async def go():
        monkeypatch.setattr(fetch_client, "MAX_RESPONSE_BYTES", 1000)
        cases = [httpx.Response(200, json={"ok": True, "html": "x" * 5000}),
                 httpx.Response(200, text="<html>not json</html>"),
                 httpx.Response(200, json=[1, 2]),
                 httpx.Response(400, json={"detail": "target not allowed"})]
        for resp in cases:
            c = _client_with(lambda req, resp=resp: resp)
            r = await c.fetch("https://x.top/", "mobile")
            await c.close()
            assert r["fetcher_error"] is True and r["ok"] is False and r["url"] == "https://x.top/", r
            assert fetch.fetcher_fault(r) and not page_loaded(r)
    run(go())


def test_fetch_client_limit_covers_the_fetchers_cap(monkeypatch):
    from cybercheck import fetch_client
    app = _load_fetcher_app(monkeypatch)
    assert fetch_client.MAX_RESPONSE_BYTES >= app.MAX_RESPONSE_BYTES


def test_fetch_client_500_or_timeout_with_healthy_fetcher_is_a_fault():
    async def go():
        def h500(req):
            if req.url.path == "/health":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(500, text="boom")

        def htimeout(req):
            if req.url.path == "/health":
                return httpx.Response(200, json={"ok": True})
            raise httpx.ReadTimeout("slow", request=req)

        def hdead(req):
            if req.url.path == "/health":
                raise httpx.ConnectError("refused")
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")

        for handler in (h500, htimeout):
            c = _client_with(handler)
            r = await c.fetch("https://x.top/", "mobile")
            await c.close()
            assert r is not None and r["fetcher_error"] is True, handler.__name__
        c = _client_with(hdead)                       # the fetcher really went away: unavailable
        assert await c.fetch("https://x.top/", "mobile") is None
        await c.close()
        c = _client_with(lambda req: (_ for _ in ()).throw(httpx.ConnectTimeout("no")))
        assert await c.fetch("https://x.top/", "mobile") is None
        await c.close()
    run(go())


# Retention: evidence marks expire with the confirmation, undeletable files keep their path, orphans go.

class RetentionConn(FakeConn):
    def __init__(self, candidates=None, domain_paths=None, referenced=False):
        super().__init__(candidates=candidates, referenced=referenced)
        self.domain_paths = domain_paths or {}
        self._served = False

    async def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if s.startswith("SELECT screenshot_path, html_path FROM pages WHERE domain_id"):
            self.calls.append((s, params))
            return FakeCursor([{"screenshot_path": p, "html_path": None} for p in self.domain_paths.get(params[0], [])])
        if s.startswith("SELECT p.id, p.domain_id, p.screenshot_path"):
            self.calls.append((s, params))
            rows = [] if self._served else self.candidates
            self._served = True
            return FakeCursor(rows)
        return await super().execute(sql, params)


def _retention(monkeypatch, tmp_path, conn, state=None):
    monkeypatch.setattr(db, "pool", lambda: _async(FakePool(conn)))
    monkeypatch.setattr(retention, "settings", lambda: _settings(tmp_path))
    return run(retention.run_once(SimpleNamespace(log=_log(), state=state if state is not None else {})))


def test_retention_clears_evidence_once_a_domain_is_no_longer_confirmed(monkeypatch, tmp_path):
    conn = RetentionConn()
    _retention(monkeypatch, tmp_path, conn)
    first = conn.calls[0]
    sql = first[0]
    assert sql.startswith("UPDATE pages p SET is_evidence = false FROM domains d")
    assert "p.is_evidence AND d.status <> 'confirmed'" in sql and "status_changed_at" in sql
    assert first[1] == (retention.EVIDENCE_GRACE_DAYS,) and retention.EVIDENCE_GRACE_DAYS >= 1
    # ...before the candidates are picked, so those snapshots are released in the same run
    order = [s[:40] for s, _ in conn.calls]
    assert order.index(sql[:40]) < next(i for i, s in enumerate(order) if s.startswith("SELECT p.id"))
    # the candidate scan still skips evidence rows (confirmed ones and those inside the grace period)
    assert "NOT p.is_evidence" in " ".join(retention.CANDIDATES_SQL.split())


def test_retention_keeps_the_path_when_a_file_cannot_be_deleted(monkeypatch, tmp_path):
    (tmp_path / "screenshots" / "7").mkdir(parents=True)
    (tmp_path / "html" / "7").mkdir(parents=True)
    shot = tmp_path / "screenshots" / "7" / "55-mobile.webp"
    shot.write_bytes(b"img")
    html = tmp_path / "html" / "7" / "55-mobile.html.gz"
    html.write_bytes(b"gz")
    real = retention._unlink
    monkeypatch.setattr(retention, "_unlink", lambda p: "error" if p.name.endswith(".webp") else real(p))
    conn = RetentionConn(candidates=[{"id": 55, "domain_id": 7, "screenshot_path": "screenshots/7/55-mobile.webp",
                                      "html_path": "html/7/55-mobile.html.gz", "status": "open"}])
    out = _retention(monkeypatch, tmp_path, conn)
    assert shot.exists() and not html.exists()
    (sql, params), = conn.find("UPDATE pages SET html_path = NULL")
    assert "screenshot_path" not in sql                     # still references the undeleted file
    assert out["delete_errors"] == 1 and out["files_deleted"] == 1
    # the row is skipped for the rest of this run (retried next run) instead of blocking the batch
    cand = conn.find("SELECT p.id, p.domain_id")
    assert all(isinstance(p["skip"], list) for _, p in cand)


def test_unlink_reports_what_happened(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"x")
    assert retention._unlink(f) == "deleted"
    assert retention._unlink(f) == "missing"
    assert retention._unlink(tmp_path) == "error"            # a directory: unlink fails with an OSError


def test_orphan_sweep_deletes_old_unreferenced_files_only(monkeypatch, tmp_path):
    import os
    import time as _time
    d = tmp_path / "screenshots" / "7"
    h = tmp_path / "html" / "7"
    d.mkdir(parents=True)
    h.mkdir(parents=True)
    old = _time.time() - 3 * 86400
    files = {"kept": d / "10-mobile.webp", "orphan": d / "11-mobile.webp", "tmp": h / "12-mobile.html.gz.tmp",
             "fresh": d / "13-mobile.webp"}
    for name, f in files.items():
        f.write_bytes(b"x")
        if name != "fresh":
            os.utime(f, (old, old))
    other = tmp_path / "czds" / "7"                          # not a snapshot directory: never touched
    other.mkdir(parents=True)
    (other / "zone.gz").write_bytes(b"z")
    os.utime(other / "zone.gz", (old, old))
    conn = RetentionConn(domain_paths={7: ["screenshots/7/10-mobile.webp"]})
    state = {}
    out = _retention(monkeypatch, tmp_path, conn, state)
    assert out["orphans_deleted"] == 2
    assert files["kept"].exists() and files["fresh"].exists() and (other / "zone.gz").exists()
    assert not files["orphan"].exists() and not files["tmp"].exists()
    # at most once a day
    files["orphan"].write_bytes(b"x")
    os.utime(files["orphan"], (old, old))
    out = _retention(monkeypatch, tmp_path, RetentionConn(), state)
    assert "orphans_deleted" not in out and files["orphan"].exists()


def test_orphan_sweep_only_reads_ascii_domain_directories(monkeypatch, tmp_path):
    """str.isdigit() is true for Arabic-Indic digits (int() maps '١' onto domain 1) and for
    superscripts (int() raises): neither is a directory the fetch job writes, so neither is touched,
    and the sweep still runs."""
    import os
    import time as _time
    old = _time.time() - 3 * 86400
    odd = []
    for name in ("١", "²", "7"):
        d = tmp_path / "screenshots" / name
        d.mkdir(parents=True)
        f = d / "11-mobile.webp"
        f.write_bytes(b"x")
        os.utime(f, (old, old))
        odd.append(f)
    out = _retention(monkeypatch, tmp_path, RetentionConn(domain_paths={1: []}), {})
    assert out["orphans_deleted"] == 1                       # only screenshots/7/11-mobile.webp
    assert odd[0].exists() and odd[1].exists() and not odd[2].exists()


# ---- fetcher/app.py: hostile page values, launch failures, VPN drop mid-fetch ------------------

class _FakeFrame:
    def __init__(self, forms):
        self._forms = forms

    async def evaluate(self, js):
        return self._forms


class _FakePage:
    def __init__(self, title="t", html="<html></html>", text="hello", forms=None, goto_exc=None, status=200):
        self._title, self._html, self._text = title, html, text
        self._forms = forms if forms is not None else []
        self._goto_exc, self._status = goto_exc, status
        self.url = "https://x.top/"
        self.viewport_size = {"width": 412, "height": 839}
        self.main_frame = object()

    def on(self, event, cb):
        pass

    async def goto(self, url, **kw):
        if self._goto_exc:
            raise self._goto_exc
        return SimpleNamespace(status=self._status)

    async def title(self):
        return self._title

    async def content(self):
        return self._html

    async def evaluate(self, js):
        return self._text

    @property
    def frames(self):
        return [_FakeFrame(self._forms)]

    async def screenshot(self, **kw):
        return b"RIFF\x00\x00\x00\x00WEBPfake"


class _FakeContext:
    def __init__(self, page):
        self.page = page

    def set_default_timeout(self, ms):
        pass

    def set_default_navigation_timeout(self, ms):
        pass

    async def route(self, pattern, handler):
        pass

    async def new_page(self):
        return self.page

    async def close(self):
        pass


class _FakeBrowser:
    def __init__(self, page):
        self.page = page

    def is_connected(self):
        return True

    async def new_context(self, **kw):
        return _FakeContext(self.page)

    async def close(self):
        pass


def _egress_ok(ip="203.0.113.7"):
    return {"ok": True, "vpn_running": True, "egress_ip": ip, "egress_country": "Australia", "error": None}


def _fetcher_with_page(monkeypatch, page, egress=None):
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch)

    async def launch():
        return _FakeBrowser(page)
    monkeypatch.setattr(app.pool, "_launch", launch)
    calls = []

    async def get(force=False):
        calls.append(force)
        return egress(force) if egress else _egress_ok()
    monkeypatch.setattr(app.egress, "get", get)
    return app, TestClient(app.app), calls


_GOOD = {"Authorization": "Bearer " + "t" * 32}


def test_fetcher_rebuilds_hostile_forms_and_strings(monkeypatch):
    nan = float("nan")
    forms = [{"action": nan, "method": {"x": 1}, "has_password": nan, "has_otp": "yes", "has_card": True,
              "inputs": [{"type": nan, "name": "pw\ud800", "autocomplete": ["a"], "label": "Pass\x01word"},
                         "junk", {"type": "PASSWORD"}]},
             "not a form", {"inputs": "nope"}]
    page = _FakePage(title="NetBank \ud83d login", html="<p>\ud800\x00x</p>", text="a\x1bb", forms=forms)
    app, client, _ = _fetcher_with_page(monkeypatch, page)
    r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True and data["fetcher_error"] is False
    assert data["title"] == "NetBank ? login" and data["text_excerpt"] == "ab" and data["html"] == "<p>?x</p>"
    f0, f1 = data["forms"]
    assert f0["action"] == "" and f0["method"] == "" and f0["has_password"] is False and f0["has_otp"] is False
    assert f0["has_card"] is True
    assert f0["inputs"] == [{"type": "", "name": "pw?", "autocomplete": "", "label": "Password"},
                            {"type": "password", "name": "", "autocomplete": "", "label": ""}]
    assert f1["inputs"] == []


def test_fetcher_never_answers_500_for_an_unencodable_result(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    for bad in ({"ok": True, "timings": {"x": float("nan")}, "url": "https://x.top/"},
                {"ok": True, "title": "\ud800", "url": "https://x.top/"},
                {"ok": True, "forms": [object()], "url": "https://x.top/\ud800"}):
        resp = app._respond(dict(bad))
        data = __import__("json").loads(resp.body)
        assert data["fetcher_error"] is True and data["error"] == "unencodable result" and data["ok"] is False


def test_fetcher_caps_html_by_bytes_and_the_response_fits_the_worker(monkeypatch):
    from cybercheck import fetch_client
    for html in ("\U0001F600" * 2_000_000, "\x01" * 2_000_000, '"' * 3_000_000, "é" * 2_500_000):
        many = [{"action": "https://e.top/" + "é" * 3000, "method": "post",
                 "inputs": [{"type": "text", "name": "\U0001F600" * 200, "autocomplete": "x" * 100,
                             "label": "\\" * 300} for _ in range(300)]} for _ in range(80)]
        page = _FakePage(title="\U0001F600" * 1000, html=html, text="\U0001F600" * 50_000, forms=many)
        app, client, _ = _fetcher_with_page(monkeypatch, page)
        r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
        assert r.status_code == 200
        assert len(r.content) <= app.MAX_RESPONSE_BYTES <= fetch_client.MAX_RESPONSE_BYTES
        data = r.json()
        assert data["ok"] is True
        if data["html"]:
            assert len(data["html"].encode("utf-8")) <= app.HTML_CAP
        assert len(data["forms"]) <= app.MAX_FORMS
        assert sum(len(f["inputs"]) for f in data["forms"]) <= app.MAX_INPUTS_TOTAL


def test_fetcher_drops_html_rather_than_exceed_the_cap(monkeypatch):
    app = _load_fetcher_app(monkeypatch)
    monkeypatch.setattr(app, "MAX_RESPONSE_BYTES", 10_000)
    resp = app._respond({"ok": True, "html": "x" * 50_000, "title": "kept", "url": "https://x.top/"})
    data = __import__("json").loads(resp.body)
    assert data["html"] is None and data["title"] == "kept" and data["ok"] is True
    assert len(resp.body) <= 10_000


def test_fetcher_answers_503_when_chromium_cannot_start_and_exits_after_repeats(monkeypatch):
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch)
    exits = []
    monkeypatch.setattr(app, "_exit", lambda code: exits.append(code))

    async def launch():
        raise RuntimeError("Connection closed while reading from the driver")
    monkeypatch.setattr(app.pool, "_launch", launch)

    async def ok(force=False):
        return _egress_ok()
    monkeypatch.setattr(app.egress, "get", ok)
    client = TestClient(app.app)
    r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
    assert r.status_code == 503 and r.json()["browser_ok"] is False      # the worker changes nothing
    h = client.get("/health", headers=_GOOD)                            # tries again: failure 2
    assert h.status_code == 503 and h.json()["browser_ok"] is False and "browser" in h.json()["error"]
    assert exits == []
    client.get("/health", headers=_GOOD)                                # failure 3: restart the container
    assert exits == [71]

    async def works():
        return _FakeBrowser(_FakePage())
    monkeypatch.setattr(app.pool, "_launch", works)
    h = client.get("/health", headers=_GOOD)
    assert h.status_code == 200 and h.json()["browser_ok"] is True and app.pool.launch_failures == 0
    assert client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD).status_code == 200


def test_fetcher_counts_a_launch_that_hangs(monkeypatch):
    """A hung Playwright driver never raises: the launch must time out inside the fetch's own budget
    (HARD_TIMEOUT_MS + 5 s) and be counted, not end as a 'hard timeout' result with /health still 200."""
    from fastapi.testclient import TestClient
    app = _load_fetcher_app(monkeypatch)
    assert 30 < app.LAUNCH_TIMEOUT_S < app.HARD_TIMEOUT_MS / 1000 + 5 - 5     # defaults: 40 s vs 50 s
    app = _load_fetcher_app(monkeypatch, FETCH_HARD_TIMEOUT_MS="1000")         # fetch budget 6 s
    assert app.LAUNCH_TIMEOUT_S < app.HARD_TIMEOUT_MS / 1000 + 5
    monkeypatch.setattr(app, "LAUNCH_TIMEOUT_S", 0.05)
    exits = []
    monkeypatch.setattr(app, "_exit", lambda code: exits.append(code))

    async def hang():
        await asyncio.Event().wait()
    monkeypatch.setattr(app.pool, "_launch", hang)

    async def ok(force=False):
        return _egress_ok()
    monkeypatch.setattr(app.egress, "get", ok)
    client = TestClient(app.app)
    r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
    assert r.status_code == 503 and r.json()["browser_ok"] is False and app.pool.launch_failures == 1
    h = client.get("/health", headers=_GOOD)
    assert h.status_code == 503 and "did not finish" in h.json()["error"]
    client.get("/health", headers=_GOOD)
    assert exits == [71]


def test_fetcher_rechecks_egress_after_a_failed_navigation(monkeypatch):
    err = RuntimeError("net::ERR_NAME_NOT_RESOLVED at https://x.top/")
    # VPN dropped during the fetch: 503 (the worker records nothing), not a page failure
    for later in ({"ok": False, "vpn_running": False, "egress_ip": None, "egress_country": None,
                   "error": "VPN is not running"},
                  _egress_ok(ip="198.51.100.9")):            # reconnected to another exit meanwhile
        app, client, calls = _fetcher_with_page(monkeypatch, _FakePage(goto_exc=err),
                                                egress=lambda force, later=later: later if force else _egress_ok())
        r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
        assert r.status_code == 503 and calls == [False, True]
    # same exit, VPN fine: a real page failure, reported as such
    app, client, calls = _fetcher_with_page(monkeypatch, _FakePage(goto_exc=err))
    r = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD)
    assert r.status_code == 200 and r.json()["ok"] is False and r.json()["fetcher_error"] is False
    assert calls == [False, True]
    # a page that loaded needs no re-check
    app, client, calls = _fetcher_with_page(monkeypatch, _FakePage())
    assert client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD).json()["ok"] is True
    assert calls == [False]


# ---- container settings: DNS upstreams, swap, seccomp socket filters ----------------------------

UNFILTERED_DNS = {"cloudflare", "google", "quad9 unsecured"}


def _compose():
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    return root, yaml.safe_load((root / "fetcher" / "compose.yaml").read_text())


def test_gluetun_uses_unfiltered_dns_upstreams_only():
    root, c = _compose()
    env = c["services"]["vpn"]["environment"]
    ups = [u.strip().lower() for u in env["DNS_UPSTREAM_RESOLVERS"].split(",")]
    assert ups and set(ups) <= UNFILTERED_DNS, ups          # "quad9" is Quad9's threat-blocking 9.9.9.9
    assert env["BLOCK_MALICIOUS"] == "off"
    script = (root / "scripts" / "verify-sandbox.sh").read_text()
    assert "DNS_UPSTREAM_RESOLVERS" in script and 'cloudflare|google|"quad9 unsecured"' in script


def test_containers_get_no_swap():
    _, c = _compose()
    for name in ("vpn", "fetcher"):
        svc = c["services"][name]
        assert svc["memswap_limit"] == svc["mem_limit"], name


def _seccomp():
    import json
    from pathlib import Path
    return json.loads((Path(__file__).resolve().parent.parent / "fetcher" / "seccomp.json").read_text())


def _denied(profile, name, args):
    """Evaluate the profile the way runc builds it: conditions on the same argument index are separate
    rules (OR), conditions on different indexes are one rule (AND). Unsigned 64-bit comparisons."""
    for rule in profile["syscalls"]:
        if name not in rule["names"] or rule["action"] == "SCMP_ACT_ALLOW":
            continue
        conds = rule.get("args") or []
        if not conds:
            return True
        by_index: dict = {}
        for c in conds:
            by_index.setdefault(c["index"], []).append(c)

        def ok(c):
            v = args[c["index"]] & (2 ** 64 - 1)
            op = c["op"]
            if op == "SCMP_CMP_EQ":
                return v == c["value"]
            if op == "SCMP_CMP_GE":
                return v >= c["value"]
            if op == "SCMP_CMP_MASKED_EQ":
                return v & c["value"] == c.get("valueTwo", 0)
            raise AssertionError(op)
        if any(len(cs) > 1 for cs in by_index.values()):
            if any(ok(c) for c in conds):
                return True
        elif all(ok(c) for c in conds):
            return True
    return False


def test_seccomp_denies_risky_socket_families_and_32bit_abi():
    prof = _seccomp()
    assert prof["defaultAction"] == "SCMP_ACT_ALLOW"
    assert prof["architectures"] == ["SCMP_ARCH_X86_64"]     # no int 0x80 / socketcall way around the filters
    hi = 1 << 32
    for fam, proto in ((17, 0), (hi | 17, 0), (38, 0), (40, 0), (15, 2), (21, 0), (30, 0), (44, 0), (5, 0),
                       (16, 12), (hi | 16, hi | 12), (16, 6), (2 ** 64 - 1, 0)):
        assert _denied(prof, "socket", (fam, 3, proto)), (fam, proto)
    for fam in (17, 38, 40):
        assert _denied(prof, "socketpair", (fam, 1, 0)), fam
    # what Chromium, Node and Python need stays open
    for fam, typ, proto in ((1, 1, 0), (2, 1, 0), (2, 2, 17), (10, 1, 0), (10, 2, 0), (16, 3, 0), (16, 2, 15)):
        assert not _denied(prof, "socket", (fam, typ, proto)), (fam, typ, proto)
    assert not _denied(prof, "socketpair", (1, 1, 0))
    # Chromium's namespace sandbox needs these (Docker's default profile only allows them with CAP_SYS_ADMIN)
    for name in ("clone", "clone3", "unshare", "setns"):
        assert not _denied(prof, name, (0x10000000 | 0x40000000, 0, 0, 0, 0, 0)), name
    for name in ("bpf", "ptrace", "mount", "keyctl", "io_uring_setup", "userfaultfd"):
        assert _denied(prof, name, (0, 0, 0, 0, 0, 0)), name


def test_fetcher_reports_the_address_the_forms_came_from(monkeypatch):
    """A JS redirect after DOMContentLoaded moves the page while forms are collected: final_url must be the
    address the browser is on after capture, with the earlier one kept in the redirect chain."""
    class MovingPage(_FakePage):
        async def screenshot(self, **kw):
            self.url = "https://www.commbank.com.au/netbank/logon"     # moved during capture
            return await super().screenshot(**kw)
    page = MovingPage(forms=[{"action": "/logon", "method": "post", "has_password": True,
                              "inputs": [{"type": "password", "name": "password"}]}])
    app, client, _ = _fetcher_with_page(monkeypatch, page)
    data = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD).json()
    assert data["final_url"] == "https://www.commbank.com.au/netbank/logon"
    assert data["redirect_chain"][-1] == "https://x.top/" and data["url_changed_during_capture"] is True
    still = _FakePage()
    app, client, _ = _fetcher_with_page(monkeypatch, still)
    data = client.post("/fetch", json={"url": "https://x.top/"}, headers=_GOOD).json()
    assert data["final_url"] == "https://x.top/" and "url_changed_during_capture" not in data
