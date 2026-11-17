"""Integration tests for the fetch group (cybercheck/jobs/fetch.py, cybercheck/jobs/retention.py,
cybercheck/fetch_client.py, cybercheck/pagefeatures.py) against a real Postgres 17 (scripts/it-postgres.sh).

Only the network is fake. The fetcher API is an httpx.MockTransport behind the real FetchClient, so the
client's own health / fault / unavailable logic runs too, and it answers with the JSON fetcher/app.py
returns (including the Chrome error page a failed navigation still captures). Domains are created with
store_hit as ingest does, then moved along with the column writes enrich, judge and the dashboard make (the
dashboard's own status route handler is called for review decisions).

"Time passing" is simulated by travel(): every stored timestamp (and fetch_state.fail_since) is moved back by
the same amount, so Postgres now() and the job's own clock both see that much time elapse.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import io
import json
import logging
import os
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from PIL import Image

from cybercheck import config, db, fetch_client
from cybercheck.jobs import fetch, retention
from cybercheck.scoring import default_watchlist
from cybercheck.store import store_hit
from cybercheck.worker import JobContext

UTC = timezone.utc
FETCHER_HOST = "fetcher.it.invalid"
TOKEN = "it-fetcher-token-0123456789abcdef0123"
EGRESS_IP = "203.0.113.7"
ISSUER = "C=US, O=Let's Encrypt, CN=R11"
CT_LOG = "Google 'Argon2026h2' log"
LOG = logging.getLogger("it.fetch")

_ENV_CLEAR = ("FETCH_BATCH", "FETCH_TRACK_INTERVAL_H", "ENRICH_TRACK_DAYS", "FETCH_MIN_SCORE",
              "FETCH_CONCURRENCY", "SCREENSHOT_RETENTION_DAYS", "RETENTION_BATCH", "WEB_ALLOWED_HOSTS",
              "WEB_PUBLIC_HOSTNAME", "WEB_PORT", "WEB_HOST", "REVIEW_THRESHOLD", "HIGH_THRESHOLD", "STORE_THRESHOLD", "WATCH_DAYS",
              "WATCHLIST_PATH")


# ---- harness ------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _env(it_db, monkeypatch):
    """Clean tables and data dir for every test; fetcher settings pointing at the fake."""
    for k in _ENV_CLEAR:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FETCHER_URL", f"http://{FETCHER_HOST}:8432")
    monkeypatch.setenv("FETCHER_TOKEN", TOKEN)
    monkeypatch.setenv("FETCH_MIN_FREE_GB", "0")   # the temp data dir may sit on a small tmpfs
    config.settings.cache_clear()
    db._pool = None
    with db.connect_sync() as c:
        c.execute("TRUNCATE domains, domain_events, pages, checks, ai_calls, reports, kv RESTART IDENTITY CASCADE")
    data_dir = config.settings().data_dir
    for child in list(data_dir.iterdir()):
        if child.is_dir() and not child.is_symlink():
            _chmod_tree(child, 0o755)
            shutil.rmtree(child)
        else:
            child.unlink()
    yield data_dir
    config.settings.cache_clear()


def _chmod_tree(path: Path, mode: int) -> None:
    for root, dirs, _files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
    os.chmod(path, mode)


def run(coro):
    """Run one test body on a fresh event loop; the db pool belongs to that loop, so close it there."""
    async def main():
        try:
            return await coro
        finally:
            await db.close()
    return asyncio.run(main())


def q(sql: str, params=None) -> list[dict]:
    with db.connect_sync() as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else []


def q1(sql: str, params=None) -> dict | None:
    rows = q(sql, params)
    return rows[0] if rows else None


def ctx() -> JobContext:
    return JobContext(settings=config.settings(), log=LOG)


_WL = None


def wl():
    global _WL
    if _WL is None:
        _WL = default_watchlist()
    return _WL


async def seed(hostname: str, *, tier: str | None = None, dns: str | None = "resolves",
               source: str = "ct") -> int:
    """Store a hit exactly as ingest does, then write what enrich writes once the name resolves."""
    hit = wl().score_hostname(hostname)
    assert hit is not None, hostname
    if tier:
        assert hit.tier == tier, (hostname, hit.tier, hit.score)
    p = await db.pool()
    async with p.connection() as conn:
        did, _ = await store_hit(conn, hit, source, ISSUER, CT_LOG)
        if dns:
            await conn.execute(
                "UPDATE domains SET dns_state = %s, ips = %s, asn = 13335, as_name = 'CLOUDFLARENET', "
                "ip_country = 'US', enriched_at = now(), check_count = check_count + 1 WHERE id = %s",
                (dns, ["104.21.32.7"] if dns == "resolves" else [], did))
    return did


async def new_cert(hostname: str) -> None:
    hit = wl().score_hostname(hostname)
    p = await db.pool()
    async with p.connection() as conn:
        await store_hit(conn, hit, "ct", ISSUER, CT_LOG)


DOMAIN_TS = ("first_seen", "last_seen", "status_changed_at", "registered_at", "enriched_at", "first_live_at",
             "last_live_at", "reported_at", "takedown_at", "next_check_at", "watch_until",
             "blocklist_expires_at", "next_fetch_at")


def travel(**delta) -> None:
    """Pretend this much time passed: move every stored timestamp back by it."""
    d = timedelta(**delta)
    with db.connect_sync() as c:
        c.execute("UPDATE domains SET " + ", ".join(f"{col} = {col} - %(d)s" for col in DOMAIN_TS), {"d": d})
        c.execute("UPDATE pages SET fetched_at = fetched_at - %(d)s, retain_until = retain_until - %(d)s", {"d": d})
        c.execute("UPDATE domain_events SET at = at - %(d)s", {"d": d})
        for r in c.execute("SELECT id, fetch_state FROM domains WHERE fetch_state ? 'fail_since'").fetchall():
            st = r["fetch_state"]
            st["fail_since"] = (fetch.parse_ts(st["fail_since"]) - d).isoformat()
            c.execute("UPDATE domains SET fetch_state = %s WHERE id = %s", (db.jsonb(st), r["id"]))


def dom(did: int) -> dict:
    return q1("SELECT *, next_fetch_at - now() AS fetch_in FROM domains WHERE id = %s", (did,))


def pages(did: int) -> list[dict]:
    return q("SELECT * FROM pages WHERE domain_id = %s ORDER BY id", (did,))


def events(did: int, kind: str | None = None) -> list[dict]:
    rows = q("SELECT kind, detail FROM domain_events WHERE domain_id = %s ORDER BY id", (did,))
    return [r for r in rows if kind is None or r["kind"] == kind]


def near(td: timedelta, expected: timedelta, slack: timedelta = timedelta(minutes=2)) -> bool:
    return abs(td - expected) <= slack


def files_under(data_dir: Path) -> set[str]:
    return {str(p.relative_to(data_dir)) for p in data_dir.rglob("*") if p.is_file() or p.is_symlink()}


async def set_status(domain_id: int, status: str, note: str = "") -> None:
    """The dashboard's own POST /domain/{id}/status handler (a reviewer's decision)."""
    from starlette.requests import Request
    from cybercheck.web import app as webapp
    scope = {"type": "http", "method": "POST", "path": f"/domain/{domain_id}/status", "query_string": b"",
             "headers": [(b"host", b"127.0.0.1:8430"), (b"origin", b"http://127.0.0.1:8430"),
                         (b"tailscale-user-login", b"reviewer@example.org")],
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8430), "scheme": "http"}
    resp = await webapp.set_status(Request(scope), domain_id, status=status, note=note)
    assert resp.status_code == 303


# ---- the fake fetcher ---------------------------------------------------------------------------

def webp(color, profile: str = "mobile") -> bytes:
    size = (390, 844) if profile == "mobile" else (1366, 768)
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "WEBP", quality=60)
    return buf.getvalue()


ERROR_PAGE_HTML = '<html><head></head><body><div id="main-frame-error"></div></body></html>'

LOGIN_FORMS = [{"action": "https://collect-au.xyz/gate.php", "method": "post",
                "has_password": True, "has_otp": False, "has_card": False,
                "inputs": [{"type": "text", "name": "clientNumber", "autocomplete": "username",
                            "label": "Client number"},
                           {"type": "password", "name": "password", "autocomplete": "current-password",
                            "label": "Password"},
                           {"type": "hidden", "name": "_token", "autocomplete": "", "label": ""},
                           {"type": "submit", "name": "", "autocomplete": "", "label": "Log on"}]}]

LOGIN_HTML = ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>NetBank - Log on to NetBank - "
              "Commonwealth Bank</title><link rel=\"stylesheet\" href=\"/assets/cba.css\"></head><body>"
              "<div class=\"logon\"><h1>Log on to NetBank</h1><form action=\"https://collect-au.xyz/gate.php\" "
              "method=\"post\"><label>Client number <input name=\"clientNumber\" autocomplete=\"username\"></label>"
              "<label>Password <input type=\"password\" name=\"password\"></label>"
              "<input type=\"hidden\" name=\"_token\" value=\"9f8e\"><button>Log on</button></form></div>"
              "</body></html>")


def loaded(url: str, profile: str, *, title="NetBank - Log on to NetBank - Commonwealth Bank",
           text="Log on to NetBank\nClient number\nPassword\nRemember client number\nLog on\nForgot your password?",
           forms=None, html=LOGIN_HTML, color=(255, 204, 0), status=200, final_url=None, chain=None) -> dict:
    """A /fetch result for a page that loaded (fetcher/app.py _fetch)."""
    return {"ok": True, "final_url": final_url or url, "http_status": status,
            "redirect_chain": chain if chain is not None else [], "title": title, "html": html,
            "text_excerpt": text, "screenshot_webp_b64": base64.b64encode(webp(color, profile)).decode("ascii"),
            "forms": LOGIN_FORMS if forms is None else forms, "timings": {"nav_ms": 640, "total_ms": 2210},
            "error": None, "fetcher_error": False, "egress_ip": EGRESS_IP, "egress_country": "AU",
            "profile": profile, "url": url}


def nav_failed(url: str, profile: str, err: str = "net::ERR_CONNECTION_REFUSED") -> dict:
    """page.goto raised: ok False, but the Chrome error page is still captured (html + screenshot)."""
    return {"ok": False, "final_url": "chrome-error://chromewebdata/", "http_status": None, "redirect_chain": [],
            "title": "", "html": ERROR_PAGE_HTML, "text_excerpt": "",
            "screenshot_webp_b64": base64.b64encode(webp((255, 255, 255), profile)).decode("ascii"), "forms": [],
            "timings": {"nav_ms": 95, "total_ms": 410},
            "error": f"Error: page.goto: {err} at {url}\nCall log:\n  - navigating to \"{url}\", waiting until "
                     "\"domcontentloaded\"",
            "fetcher_error": False, "egress_ip": EGRESS_IP, "egress_country": "AU", "profile": profile, "url": url}


def crashed(url: str, profile: str) -> dict:
    """The browser itself failed (fetcher/app.py marks fetcher_error)."""
    return {"ok": False, "final_url": None, "http_status": None, "redirect_chain": [], "title": None, "html": None,
            "text_excerpt": None, "screenshot_webp_b64": None, "forms": [], "timings": {"nav_ms": 30001},
            "error": "TargetClosedError: Target page, context or browser has been closed", "fetcher_error": True,
            "egress_ip": EGRESS_IP, "egress_country": "AU", "profile": profile, "url": url}


def failing_closed() -> httpx.Response:
    return httpx.Response(503, json={"ok": False, "error": "fetcher failing closed: egress check failed",
                                     "vpn_running": False, "egress_country": None})


class FakeFetcher:
    """fetcher/app.py's API: GET /health, POST /fetch. sites maps a hostname to fn(url, profile) returning a
    result dict, an httpx.Response or an exception to raise. Unknown hosts: connection refused."""

    def __init__(self) -> None:
        self.health_status = 200
        self.health_body = {"ok": True, "vpn_running": True, "egress_ip": EGRESS_IP, "egress_country": "AU",
                            "browser_ok": True, "error": None}
        self.health_exc: Exception | None = None
        self.health_seq: list[tuple[int, dict]] = []        # answered first, one per /health call
        self.sites: dict = {}
        self.calls: list[tuple[str, str]] = []
        self.health_calls = 0
        self.delay = 0.0
        self.in_flight = 0
        self.max_in_flight = 0

    async def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == f"Bearer {TOKEN}"
        assert request.url.host == FETCHER_HOST
        if request.method == "GET" and request.url.path == "/health":
            self.health_calls += 1
            if self.health_exc:
                raise self.health_exc
            status, body = self.health_seq.pop(0) if self.health_seq else (self.health_status, self.health_body)
            return self._json(status, body)
        assert request.method == "POST" and request.url.path == "/fetch"
        body = json.loads(request.content)
        url, profile = body["url"], body["profile"]
        self.calls.append((url, profile))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            site = self.sites.get(urlsplit(url).hostname)
            out = site(url, profile) if site else nav_failed(url, profile)
        finally:
            self.in_flight -= 1
        if isinstance(out, Exception):
            raise out
        if isinstance(out, httpx.Response):
            return out
        return self._json(200, out)

    @staticmethod
    def _json(status: int, body) -> httpx.Response:
        # json.dumps defaults (ensure_ascii, allow_nan) so tests can send what a broken fetcher could
        return httpx.Response(status, content=json.dumps(body).encode("ascii"),
                              headers={"content-type": "application/json"})

    def urls(self) -> list[tuple[str, str]]:
        out, self.calls = self.calls, []
        return out


@pytest.fixture
def fetcher(monkeypatch) -> FakeFetcher:
    fake = FakeFetcher()
    real = httpx.AsyncClient

    class MockedClient(real):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(fake.handle)
            super().__init__(*a, **kw)

    monkeypatch.setattr(fetch_client.httpx, "AsyncClient", MockedClient)
    return fake


# ---- fetch: run_once guards ---------------------------------------------------------------------

def test_fetcher_not_configured_or_unavailable_changes_nothing(fetcher, monkeypatch):
    async def body():
        did = await seed("login.commbank-verify.top", tier="high")
        before = dom(did)

        monkeypatch.setenv("FETCHER_TOKEN", "")
        config.settings.cache_clear()
        assert await fetch.run_once(ctx()) == {"skipped": "fetcher not configured"}
        monkeypatch.setenv("FETCHER_TOKEN", TOKEN)
        config.settings.cache_clear()

        fetcher.health_status, fetcher.health_body = 503, {"ok": False, "vpn_running": False, "egress_ip": None,
                                                            "egress_country": None, "error": "egress check failed"}
        assert await fetch.run_once(ctx()) == {"skipped": "fetcher unavailable"}
        fetcher.health_status, fetcher.health_body = 401, {"detail": "unauthorized"}
        assert await fetch.run_once(ctx()) == {"skipped": "fetcher unavailable",
                                               "reason": "fetcher rejected FETCHER_TOKEN"}
        # up, but its egress is the wrong country: 200 with ok false
        fetcher.health_status = 200
        fetcher.health_body = {"ok": False, "vpn_running": True, "egress_ip": "198.51.100.9",
                               "egress_country": "NL", "error": "egress country 'NL' is not AU"}
        assert await fetch.run_once(ctx()) == {"skipped": "fetcher unavailable"}
        fetcher.health_exc = httpx.ConnectError("connection refused")
        assert await fetch.run_once(ctx()) == {"skipped": "fetcher unavailable"}

        assert fetcher.calls == []
        after = dom(did)
        for col in ("next_fetch_at", "fetch_state", "live_state", "page_score", "first_live_at"):
            assert after[col] == before[col]
        assert pages(did) == []
    run(body())


def test_empty_table_and_nothing_due(fetcher):
    async def body():
        assert await fetch.run_once(ctx()) == {"due": 0, "fetched": 0, "live": 0, "failed": 0,
                                               "egress_ip": EGRESS_IP, "egress_country": "AU"}
        # a stored domain enrich has not resolved yet is not fetched
        await seed("login.commbank-verify.top", dns=None)
        out = await fetch.run_once(ctx())
        assert out["due"] == 0 and fetcher.calls == []
    run(body())


# ---- fetch: due selection -----------------------------------------------------------------------

def test_due_selection_sql(fetcher, monkeypatch):
    async def body():
        ids = {}
        for name, host, tier in [
            ("high_new", "login.commbank-verify.top", "high"),
            ("review_new", "commbank-secure.top", "review"),
            ("high_new2", "mygov-secure-login.xyz", "high"),
            ("watch57", "www.commbank-netbank-login.com", "watch"),
            ("watch45", "commbank-news.blog", "watch"),
            ("nxdomain", "auspost-parcel-redelivery.info", "high"),
            ("taken_down", "anz-login-verify.top", "review"),
            ("false_pos", "nab-secure-login.top", "review"),
            ("benign", "westpac-secure.top", "review"),
            ("future", "ato-refund-claim.top", "review"),
            ("past_due", "commbankrewards.shop", "high"),
            ("parked", "netbank-commbank.com", "review"),
        ]:
            ids[name] = await seed(host, tier=tier)
        idn = await seed("xn--commbnk-login-01k.top", tier="high")      # commbаnk-login.top (Cyrillic а)
        ids["idn"] = idn
        assert dom(idn)["unicode_domain"] == "commbаnk-login.top"

        with db.connect_sync() as c:
            c.execute("UPDATE domains SET dns_state = 'nxdomain', ips = '{}' WHERE id = %s", (ids["nxdomain"],))
            c.execute("UPDATE domains SET takedown_at = now(), takedown_signal = 'nxdomain' WHERE id = %s",
                      (ids["taken_down"],))
            c.execute("UPDATE domains SET next_fetch_at = now() + interval '3 hours' WHERE id = %s", (ids["future"],))
            c.execute("UPDATE domains SET next_fetch_at = now() - interval '5 minutes' WHERE id = %s",
                      (ids["past_due"],))
            # parked at the end of its watch window (fetch.next_fetch_at parks it AT watch_until)
            c.execute("UPDATE domains SET watch_until = now() - interval '1 hour', "
                      "next_fetch_at = now() - interval '1 hour' WHERE id = %s", (ids["parked"],))
        await set_status(ids["false_pos"], "false_positive", "brand's own campaign site")
        await set_status(ids["benign"], "benign")

        async def due(**over) -> list[str]:
            params = {"min_score": 60, "batch": 50, "track_days": 30, **over}
            p = await db.pool()
            async with p.connection() as conn:
                rows = await (await conn.execute(fetch.DUE_SQL, params)).fetchall()
            by_id = {v: k for k, v in ids.items()}
            return [by_id[r["id"]] for r in rows]

        # never fetched (NULL) first, high before review, newest id first; then due-by-time
        assert await due() == ["idn", "high_new2", "high_new", "review_new", "past_due"]
        assert await due(batch=2) == ["idn", "high_new2"]
        # a watch-tier name above FETCH_MIN_SCORE counts; below it does not
        assert await due(min_score=50) == ["idn", "high_new2", "high_new", "review_new", "watch57", "past_due"]
        # a confirmed watch-tier domain is fetched whatever its score
        await set_status(ids["watch45"], "confirmed")
        assert "watch45" in await due()
        async with (await db.pool()).connection() as conn:
            row = await (await conn.execute(fetch.DUE_SQL, {"min_score": 60, "batch": 1,
                                                            "track_days": 30})).fetchone()
        assert set(row) >= {"id", "registered_domain", "hostnames", "hostname", "tier", "status", "score",
                            "brand_id", "dns_state", "live_state", "first_live_at", "last_live_at", "watch_until",
                            "reported_at", "ai_verdict", "next_fetch_at", "fetch_state", "first_seen",
                            "status_changed_at"}
        assert row["hostname"] == "xn--commbnk-login-01k.top" and row["fetch_state"] == {}

        # parked past the watch window: due again while tracked, inside the tracking window only
        with db.connect_sync() as c:
            c.execute("UPDATE domains SET ai_verdict = 'phishing', ai_confidence = 0.93, ai_brand = 'commbank' "
                      "WHERE id = %s", (ids["parked"],))
        assert "parked" in await due()
        with db.connect_sync() as c:
            c.execute("UPDATE domains SET first_seen = now() - interval '31 days' WHERE id = %s", (ids["parked"],))
        assert "parked" not in await due()
        assert "parked" in await due(track_days=45)       # ENRICH_TRACK_DAYS=45
        with db.connect_sync() as c:   # reported 2 days ago re-anchors the window
            c.execute("UPDATE domains SET reported_at = now() - interval '2 days' WHERE id = %s", (ids["parked"],))
        assert "parked" in await due()

        # run_once honours FETCH_BATCH and fetches the selected domains only
        monkeypatch.setenv("FETCH_BATCH", "3")
        out = await fetch.run_once(ctx())
        assert out["due"] == 3
        hosts = {urlsplit(u).hostname for u, _ in fetcher.urls()}
        assert hosts == {"xn--commbnk-login-01k.top", "mygov-secure-login.xyz", "login.commbank-verify.top"}
    run(body())


def test_nonsense_fetch_batch_still_runs(fetcher, monkeypatch):
    async def body():
        did = await seed("login.commbank-verify.top", tier="high")
        other = await seed("commbank-secure.top", tier="review")
        for h in ("login.commbank-verify.top", "commbank-secure.top"):
            fetcher.sites[h] = lambda url, profile: loaded(url, profile)
        seen = []
        for bad in ("-5", "0", "lots"):
            monkeypatch.setenv("FETCH_BATCH", bad)
            out = await fetch.run_once(ctx())
            assert out["failed"] == 0
            seen.append(out["due"])
        assert seen == [1, 1, 0]                        # -5 and 0 mean a batch of 1; junk means the default
        assert len(pages(did)) == 2 and len(pages(other)) == 2
    run(body())


# ---- fetch: a first round on a live phishing page -----------------------------------------------

def test_first_round_stores_snapshots_files_features_and_goes_live(fetcher, _env):
    data_dir = _env

    async def body():
        did = await seed("login.commbank-verify.top", tier="high")
        host = "login.commbank-verify.top"
        # https refuses, http serves the kit (common on fresh phishing hosts)
        fetcher.sites[host] = lambda url, profile: (nav_failed(url, profile) if url.startswith("https://")
                                                    else loaded(url, profile))
        out = await fetch.run_once(ctx())
        assert out == {"due": 1, "fetched": 1, "live": 1, "failed": 0, "egress_ip": EGRESS_IP,
                       "egress_country": "AU"}
        assert fetcher.urls() == [(f"https://{host}/", "mobile"), (f"http://{host}/", "mobile"),
                                  (f"https://{host}/", "desktop"), (f"http://{host}/", "desktop")]

        rows = pages(did)
        assert [r["user_agent_profile"] for r in rows] == ["mobile", "desktop"]
        for r in rows:
            assert r["url"] == f"http://{host}/" and r["final_url"] == f"http://{host}/"
            assert r["http_status"] == 200 and r["error"] is None
            assert r["title"] == "NetBank - Log on to NetBank - Commonwealth Bank"
            assert r["egress_ip"] == EGRESS_IP
            assert r["has_password_field"] is True and r["has_otp_field"] is False and r["has_card_field"] is False
            assert r["form_actions"] == ["collect-au.xyz"] and r["external_form_post"] is True
            assert "commbank" in r["brand_mentions"]
            assert r["text_excerpt"].startswith("Log on to NetBank")
            assert near(r["retain_until"] - r["fetched_at"], timedelta(days=60))
            assert r["is_evidence"] is False
            f = r["features"]
            assert f["loaded"] is True and f["profile"] == r["user_agent_profile"]
            assert f["egress_country"] == "AU" and f["timings"] == {"nav_ms": 640, "total_ms": 2210}
            assert f["page_score"] == 65 and f["inconclusive"] is False and "files_skipped" not in f
            # files: WebP bytes exactly as captured, HTML gzipped
            assert r["screenshot_path"] == f"screenshots/{did}/{r['id']}-{r['user_agent_profile']}.webp"
            assert r["html_path"] == f"html/{did}/{r['id']}-{r['user_agent_profile']}.html.gz"
            shot = (data_dir / r["screenshot_path"]).read_bytes()
            assert shot == webp((255, 204, 0), r["user_agent_profile"])
            assert fetch._sha(shot) == r["screenshot_sha256"]
            raw = gzip.decompress((data_dir / r["html_path"]).read_bytes())
            assert raw.decode() == LOGIN_HTML and fetch._sha(raw) == r["html_sha256"]

        d = dom(did)
        assert d["live_state"] == "live" and d["page_score"] == 65
        assert d["first_live_at"] is not None and d["first_live_at"] == d["last_live_at"]
        assert near(d["fetch_in"], timedelta(hours=1))
        st = d["fetch_state"]
        assert st["n"] == 1 and "fail_since" not in st
        assert st["shots"] == {p["user_agent_profile"]: {"sha": p["screenshot_sha256"], "path": p["screenshot_path"]}
                               for p in rows}
        assert st["htmls"]["mobile"]["path"] == rows[0]["html_path"]
        assert events(did, "went_live") == [{"kind": "went_live", "detail": {"from": "unknown"}}]

        # the dashboard serves the stored path as an image
        from cybercheck.web import app as webapp
        resp = await webapp.screenshot(rows[0]["id"])
        assert Path(resp.path) == (data_dir / rows[0]["screenshot_path"]).resolve()

        # run again at once: nothing due, nothing written
        out = await fetch.run_once(ctx())
        assert out["due"] == 0 and fetcher.calls == [] and len(pages(did)) == 2
    run(body())


# ---- fetch: identical snapshots are not written twice ------------------------------------------

def test_identical_snapshots_reuse_files_and_changes_write_new_ones(fetcher, _env):
    data_dir = _env

    async def body():
        host = "mygov-secure-login.xyz"
        did = await seed(host, tier="high")
        look = {"color": (0, 102, 204), "title": "myGov - Sign in"}
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, **look)
        await fetch.run_once(ctx())
        r1 = pages(did)
        assert len(r1) == 2 and len(files_under(data_dir)) == 4
        fetcher.urls()

        travel(hours=1, minutes=1)
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1
        assert fetcher.urls() == [(f"https://{host}/", "mobile")]     # desktop only on the first round
        r2 = pages(did)[-1]
        assert r2["user_agent_profile"] == "mobile"
        assert r2["screenshot_path"] == r1[0]["screenshot_path"] and r2["html_path"] == r1[0]["html_path"]
        assert r2["screenshot_sha256"] == r1[0]["screenshot_sha256"]
        assert len(files_under(data_dir)) == 4                         # nothing new written
        d = dom(did)
        assert d["fetch_state"]["n"] == 2 and near(d["fetch_in"], timedelta(hours=6))
        assert events(did, "went_live") and len(events(did, "went_live")) == 1

        # the kit changes its look: new screenshot file, same HTML reused
        travel(hours=6, minutes=1)
        look["color"] = (200, 0, 0)
        await fetch.run_once(ctx())
        r3 = pages(did)[-1]
        assert r3["screenshot_path"] == f"screenshots/{did}/{r3['id']}-mobile.webp"
        assert r3["screenshot_sha256"] != r1[0]["screenshot_sha256"]
        assert r3["html_path"] == r1[0]["html_path"]
        assert len(files_under(data_dir)) == 5
        d = dom(did)
        assert d["fetch_state"]["n"] == 3 and near(d["fetch_in"], timedelta(hours=24))
        assert d["fetch_state"]["shots"]["mobile"]["path"] == r3["screenshot_path"]
        assert d["fetch_state"]["shots"]["desktop"]["path"] == r1[1]["screenshot_path"]

        # retention deleted the previous file meanwhile: an identical snapshot writes it again
        (data_dir / r3["screenshot_path"]).unlink()
        travel(hours=24, minutes=1)
        await fetch.run_once(ctx())
        r4 = pages(did)[-1]
        assert r4["screenshot_path"] == f"screenshots/{did}/{r4['id']}-mobile.webp"
        assert (data_dir / r4["screenshot_path"]).read_bytes() == webp((200, 0, 0))
        assert r4["html_path"] == r1[0]["html_path"]
    run(body())


# ---- fetch: live_state transitions -------------------------------------------------------------

def test_live_page_goes_down_only_after_two_failures_15_minutes_apart(fetcher):
    async def body():
        host = "auspost-parcel-redelivery.info"
        did = await seed(host, tier="high")
        up = {"v": True}
        fetcher.sites[host] = lambda url, profile: (
            loaded(url, profile, title="Australia Post - Redelivery", color=(220, 20, 60),
                   text="Your parcel is waiting. Pay the $1.99 redelivery fee.",
                   forms=[{"action": "/pay.php", "method": "post", "has_password": False, "has_otp": False,
                           "has_card": True, "inputs": [
                               {"type": "text", "name": "cardNumber", "autocomplete": "cc-number",
                                "label": "Card number"},
                               {"type": "text", "name": "exp", "autocomplete": "cc-exp", "label": "Expiry"},
                               {"type": "text", "name": "cvv", "autocomplete": "cc-csc", "label": "CVV"}]}])
            if up["v"] else nav_failed(url, profile, "net::ERR_NAME_NOT_RESOLVED"))
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "live" and d["page_score"] > 0
        assert pages(did)[0]["has_card_field"] is True and pages(did)[0]["external_form_post"] is False

        # first failure: still live, failure streak starts, re-check in 20 min instead of 6 h
        up["v"] = False
        travel(hours=1, minutes=1)
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1 and out["live"] == 0
        d = dom(did)
        assert d["live_state"] == "live" and d["page_score"] == pages(did)[0]["features"]["page_score"]
        assert d["fetch_state"]["fail_count"] == 1 and "fail_since" in d["fetch_state"]
        assert near(d["fetch_in"], timedelta(minutes=20))
        failed = pages(did)[-1]
        assert failed["url"] == f"http://{host}/" and failed["http_status"] is None
        assert failed["error"].startswith("Error: page.goto: net::ERR_NAME_NOT_RESOLVED")
        assert failed["final_url"] == "chrome-error://chromewebdata/" and failed["features"]["loaded"] is False
        assert failed["has_password_field"] is False and failed["form_actions"] == []
        assert events(did, "page_down") == []
        assert (await fetch.run_once(ctx()))["due"] == 0

        # 10 minutes later (forced): too close to the first failure, still live
        travel(minutes=10)
        with db.connect_sync() as c:
            c.execute("UPDATE domains SET next_fetch_at = now() WHERE id = %s", (did,))
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "live" and d["fetch_state"]["fail_count"] == 2 and events(did, "page_down") == []

        # 31 minutes after the first failure (its 20-minute re-check): down, one page_down event, and no
        # early re-check any more
        travel(minutes=21)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "down"
        downs = events(did, "page_down")
        assert len(downs) == 1 and downs[0]["detail"]["failures"] == 3
        assert near(d["fetch_in"], timedelta(hours=24))
        assert near(d["first_live_at"] - pages(did)[0]["fetched_at"], timedelta(0), timedelta(seconds=5))

        # still failing a day later: no second page_down
        travel(hours=24, minutes=1)
        await fetch.run_once(ctx())
        assert dom(did)["live_state"] == "down" and len(events(did, "page_down")) == 1

        # back up: live again, streak cleared, first_live_at kept
        up["v"] = True
        travel(hours=24, minutes=1)
        out = await fetch.run_once(ctx())
        assert out["live"] == 1
        d = dom(did)
        assert d["live_state"] == "live"
        assert near(d["first_live_at"] - pages(did)[0]["fetched_at"], timedelta(0), timedelta(seconds=5))
        assert near(d["last_live_at"] - pages(did)[-1]["fetched_at"], timedelta(0), timedelta(seconds=5))
        assert "fail_since" not in d["fetch_state"] and "fail_count" not in d["fetch_state"]
        assert [e["detail"] for e in events(did, "went_live")] == [{"from": "unknown"}, {"from": "down"}]
    run(body())


def test_http_error_status_counts_as_failure(fetcher):
    async def body():
        host = "commbankrewards.shop"
        did = await seed(host, tier="high")
        status = {"v": 200}
        fetcher.sites[host] = lambda url, profile: loaded(
            url, profile, status=status["v"], title="Account Suspended" if status["v"] != 200 else "CommBank Rewards",
            text="This Account has been suspended." if status["v"] != 200 else "Claim your rewards points",
            forms=[] if status["v"] != 200 else None)
        await fetch.run_once(ctx())
        assert dom(did)["live_state"] == "live"
        status["v"] = 403                                  # the host suspended the account
        for _ in range(2):
            travel(hours=1, minutes=1)
            await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "down" and len(events(did, "page_down")) == 1
        last = pages(did)[-1]
        assert last["http_status"] == 403 and last["features"]["loaded"] is False
        assert last["error"] == "page did not load (HTTP 403)" and last["title"] == "Account Suspended"
    run(body())


def test_never_live_domain_is_never_marked_down(fetcher):
    async def body():
        host = "ato-refund-claim.top"
        did = await seed(host, tier="review")
        await fetch.run_once(ctx())                           # unknown host: connection refused everywhere
        assert len(fetcher.urls()) == 4                       # https + http, mobile + desktop
        d = dom(did)
        assert d["live_state"] == "unknown" and d["first_live_at"] is None and d["page_score"] is None
        assert d["fetch_state"]["fail_count"] == 1 and near(d["fetch_in"], timedelta(hours=1))
        assert [p["error"] is not None for p in pages(did)] == [True, True]

        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "unknown" and d["fetch_state"]["fail_count"] == 2
        assert d["fetch_state"]["n"] == 2 and near(d["fetch_in"], timedelta(hours=6))
        assert events(did, "page_down") == [] and events(did, "went_live") == []
        assert d["page_score"] is None
    run(body())


# ---- fetch: fetcher faults and the fetcher going away -------------------------------------------

def test_fetcher_faults_back_off_without_using_a_round(fetcher):
    async def body():
        host = "westpac-secure.top"
        did = await seed(host, tier="review")
        mode = {"v": "http500"}

        def answer(url, profile):
            if mode["v"] == "http500":
                return httpx.Response(500, text="Internal Server Error")
            if mode["v"] == "timeout":
                return httpx.ReadTimeout("timed out")
            if mode["v"] == "crash":
                return crashed(url, profile)
            if mode["v"] == "mixed":
                return crashed(url, profile) if profile == "mobile" else nav_failed(url, profile)
            return loaded(url, profile, title="Westpac Online Banking", color=(218, 41, 28))
        fetcher.sites[host] = answer

        await fetch.run_once(ctx())
        # a fault is not retried over http, and /health was asked to tell a fault from an outage
        assert fetcher.urls() == [(f"https://{host}/", "mobile"), (f"https://{host}/", "desktop")]
        assert fetcher.health_calls == 3
        d = dom(did)
        assert d["fetch_state"]["faults"] == 1 and "n" not in d["fetch_state"] and d["live_state"] == "unknown"
        assert near(d["fetch_in"], timedelta(minutes=30))
        rows = pages(did)
        assert [r["error"] for r in rows] == ["fetcher HTTP 500", "fetcher HTTP 500"]
        assert all(r["screenshot_path"] is None and r["html_path"] is None for r in rows)

        mode["v"] = "timeout"
        travel(minutes=31)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["fetch_state"]["faults"] == 2 and near(d["fetch_in"], timedelta(hours=1))
        assert pages(did)[-1]["error"] == "fetcher request failed: ReadTimeout"

        mode["v"] = "crash"
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["fetch_state"]["faults"] == 3 and near(d["fetch_in"], timedelta(hours=2))
        assert pages(did)[-1]["error"].startswith("TargetClosedError")

        # a round with one real page failure is conclusive: it counts, faults reset
        mode["v"] = "mixed"
        travel(hours=2, minutes=1)
        fetcher.urls()
        await fetch.run_once(ctx())
        assert len(fetcher.urls()) == 3                       # mobile fault, desktop https + http
        d = dom(did)
        assert d["fetch_state"]["n"] == 1 and "faults" not in d["fetch_state"]
        assert d["fetch_state"]["fail_count"] == 1 and near(d["fetch_in"], timedelta(hours=1))

        mode["v"] = "ok"
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "live" and d["fetch_state"]["n"] == 2 and near(d["fetch_in"], timedelta(hours=6))
    run(body())


def test_first_round_after_faults_still_fetches_desktop(fetcher):
    async def body():
        host = "nab-secure-login.top"
        did = await seed(host, tier="review")
        ok = {"v": False}
        fetcher.sites[host] = lambda url, profile: (loaded(url, profile, title="NAB Internet Banking")
                                                    if ok["v"] else crashed(url, profile))
        await fetch.run_once(ctx())
        ok["v"] = True
        travel(minutes=31)
        fetcher.urls()
        await fetch.run_once(ctx())
        assert [p for _, p in fetcher.urls()] == ["mobile", "desktop"]
        d = dom(did)
        assert d["fetch_state"]["n"] == 1 and "faults" not in d["fetch_state"] and d["live_state"] == "live"
    run(body())


def test_fetcher_going_away_mid_run_leaves_domains_untouched(fetcher, monkeypatch):
    async def body():
        monkeypatch.setenv("FETCH_CONCURRENCY", "1")
        config.settings.cache_clear()
        a = await seed("login.commbank-verify.top", tier="high")       # first: high tier
        b = await seed("commbank-secure.top", tier="review")
        fetcher.sites["login.commbank-verify.top"] = lambda url, profile: loaded(url, profile)
        # b: the mobile snapshot works, then the VPN drops before desktop
        fetcher.sites["commbank-secure.top"] = lambda url, profile: (
            loaded(url, profile) if profile == "mobile" else failing_closed())
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1 and out["stopped"] == "fetcher became unavailable" and out["failed"] == 0
        assert dom(a)["live_state"] == "live" and len(pages(a)) == 2
        db_b = dom(b)
        assert pages(b) == [] and db_b["next_fetch_at"] is None and db_b["fetch_state"] == {}
        assert db_b["live_state"] == "unknown"

        # an ambiguous failure (502) and /health, asked again, now fails too: unavailable, not a fault
        fetcher.sites["commbank-secure.top"] = lambda url, profile: httpx.Response(502)
        fetcher.health_seq = [(200, fetcher.health_body),
                              (503, {"ok": False, "vpn_running": False, "error": "egress check failed"})]
        out = await fetch.run_once(ctx())
        assert out["stopped"] == "fetcher became unavailable" and out["due"] == 1
        assert pages(b) == [] and dom(b)["next_fetch_at"] is None
        # the connection to the fetcher fails outright mid-run: same
        fetcher.sites["commbank-secure.top"] = lambda url, profile: httpx.ConnectError("refused")
        out = await fetch.run_once(ctx())
        assert out["stopped"] == "fetcher became unavailable" and pages(b) == []

        # back: b is still due and fetched normally
        fetcher.sites["commbank-secure.top"] = lambda url, profile: loaded(url, profile)
        out = await fetch.run_once(ctx())
        assert out["due"] == 1 and out["fetched"] == 1 and "stopped" not in out
        assert len(pages(b)) == 2 and dom(b)["live_state"] == "live"
    run(body())


# ---- fetch: low disk, failures, postpone ---------------------------------------------------------

def test_low_disk_stores_rows_without_files(fetcher, monkeypatch, _env):
    data_dir = _env

    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        monkeypatch.setenv("FETCH_MIN_FREE_GB", "999999")
        out = await fetch.run_once(ctx())
        assert out["low_disk"] is True and out["fetched"] == 1 and out["live"] == 1
        rows = pages(did)
        assert len(rows) == 2 and files_under(data_dir) == set()
        for r in rows:
            assert r["screenshot_path"] is None and r["html_path"] is None and r["screenshot_sha256"] is None
            assert r["features"]["files_skipped"] == "low_disk" and r["has_password_field"] is True
        d = dom(did)
        assert d["live_state"] == "live" and d["page_score"] == 65
        assert "shots" not in d["fetch_state"] or d["fetch_state"]["shots"] == {}

        monkeypatch.setenv("FETCH_MIN_FREE_GB", "0")
        travel(hours=1, minutes=1)
        out = await fetch.run_once(ctx())
        assert "low_disk" not in out
        r = pages(did)[-1]
        assert r["screenshot_path"] and (data_dir / r["screenshot_path"]).is_file()
        assert "files_skipped" not in r["features"]
    run(body())


def test_processing_error_postpones_and_leaves_no_partial_files(fetcher, _env):
    data_dir = _env

    async def body():
        host = "mygov-secure-login.xyz"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title="myGov")
        (data_dir / "html").mkdir()
        (data_dir / "html" / str(did)).write_bytes(b"")     # not a directory: the HTML write fails
        out = await fetch.run_once(ctx())
        assert out["failed"] == 1 and out["fetched"] == 0
        d = dom(did)
        assert near(d["fetch_in"], timedelta(minutes=30)) and d["fetch_state"] == {}
        assert d["live_state"] == "unknown" and events(did, "went_live") == []
        # the screenshot written just before was removed again, and no row points at a file
        assert files_under(data_dir) == {f"html/{did}"}
        assert pages(did) == []                     # the round's transaction rolled the mobile row back

        # postpone never moves a domain that is already scheduled later
        with db.connect_sync() as c:
            c.execute("UPDATE domains SET next_fetch_at = now() + interval '5 hours' WHERE id = %s", (did,))
        await fetch.postpone(did)
        assert near(dom(did)["fetch_in"], timedelta(hours=5))

        # a row whose names are junk (hand-inserted / legacy): ValueError, postponed, never a URL
        with db.connect_sync() as c:
            bad = c.execute(
                "INSERT INTO domains (registered_domain, tld, brand_id, score, tier, hostnames, dns_state, "
                "watch_until) VALUES ('commbank login.top', 'top', 'commbank', 80, 'high', "
                "ARRAY['*.commbank login.top'], 'resolves', now() + interval '14 days') RETURNING id"
            ).fetchone()["id"]
        fetcher.urls()
        out = await fetch.run_once(ctx())
        assert out["failed"] == 1 and fetcher.urls() == []
        assert near(dom(bad)["fetch_in"], timedelta(minutes=30)) and pages(bad) == []
    run(body())


# ---- fetch: scheduling -------------------------------------------------------------------------

def test_schedule_backoff_watch_window_park_and_rearm(fetcher):
    async def body():
        host = "netbank-commbank.com"
        did = await seed(host, tier="review")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title="NetBank")
        steps = []
        for _ in range(4):
            await fetch.run_once(ctx())
            d = dom(did)
            steps.append((d["fetch_state"]["n"], round(d["fetch_in"].total_seconds() / 3600)))
            travel(seconds=d["fetch_in"].total_seconds() + 60)
        assert steps == [(1, 1), (2, 6), (3, 24), (4, 24)]

        # near the end of the watch window the next fetch is parked AT watch_until ...
        with db.connect_sync() as c:
            c.execute("UPDATE domains SET watch_until = now() + interval '30 minutes', "
                      "next_fetch_at = now() WHERE id = %s", (did,))
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["next_fetch_at"] == d["watch_until"]
        # ... and once the window has passed it is not due, run after run
        travel(minutes=31)
        fetcher.urls()
        for _ in range(2):
            assert (await fetch.run_once(ctx()))["due"] == 0
        assert fetcher.calls == []

        # a new certificate extends the watch window: due at once
        await new_cert("secure.netbank-commbank.com")
        d = dom(did)
        assert d["watch_until"] > d["next_fetch_at"] and "secure.netbank-commbank.com" in d["hostnames"]
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1 and fetcher.urls() == [("https://netbank-commbank.com/", "mobile")]
        assert dom(did)["fetch_state"]["n"] == 6
    run(body())


def test_tracked_domains_are_refetched_every_track_interval(fetcher, monkeypatch):
    async def body():
        host = "commbankrewards.shop"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title="CommBank Rewards")
        await fetch.run_once(ctx())
        await set_status(did, "confirmed", "credential kit, reported to Netcraft")
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        assert near(dom(did)["fetch_in"], timedelta(hours=2))
        monkeypatch.setenv("FETCH_TRACK_INTERVAL_H", "5")
        travel(hours=2, minutes=1)
        await fetch.run_once(ctx())
        assert near(dom(did)["fetch_in"], timedelta(hours=5))

        # past the watch window, still inside enrich's tracking window: still due
        travel(days=20)
        d = dom(did)
        assert d["watch_until"] < datetime.now(UTC) - timedelta(days=1)
        assert (await fetch.run_once(ctx()))["fetched"] == 1
        # tracking window over (30 days from the confirmation): parked like any other domain
        travel(days=11)
        assert (await fetch.run_once(ctx()))["due"] == 0
        monkeypatch.setenv("ENRICH_TRACK_DAYS", "60")
        assert (await fetch.run_once(ctx()))["due"] == 1
    run(body())


# ---- fetch: unicode, hostile strings, decoys, concurrency ---------------------------------------

def test_unicode_hostname_and_text_round_trip(fetcher):
    async def body():
        host = "xn--commbnk-login-01k.top"                      # commbаnk-login.top
        did = await seed(host, tier="high")
        title = "Вход в NetBank – Commonwealth Bank 🔒"
        text = "Добро пожаловать. Введите номер клиента и пароль 🔐 — مرحبا — 日本語"
        forms = [{"action": "https://пример.рф/collect", "method": "post", "has_password": True,
                  "has_otp": False, "has_card": False,
                  "inputs": [{"type": "password", "name": "пароль", "autocomplete": "", "label": "Пароль"}]}]
        html = f"<html><title>{title}</title><body>{text}</body></html>"
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title=title, text=text, forms=forms,
                                                           html=html)
        out = await fetch.run_once(ctx())
        assert out["live"] == 1
        assert fetcher.urls()[0] == (f"https://{host}/", "mobile")
        r = pages(did)[0]
        assert r["title"] == title and r["text_excerpt"] == text
        assert r["form_actions"] == ["пример.рф"] and r["external_form_post"] is True
        assert r["has_password_field"] is True
        assert dom(did)["live_state"] == "live"
    run(body())


def test_hostile_fetcher_json_is_stored_safely(fetcher, _env):
    """Postgres refuses NUL in text, \\u0000 / lone surrogates / NaN in jsonb, and psycopg cannot encode a
    lone surrogate: a result carrying them must still be stored (a page must not be able to make its own
    domain unrecordable), with the bad characters dropped."""
    data_dir = _env

    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")

        def hostile(url, profile):
            r = loaded(url, profile,
                       title="NetBank\x00 Log on \ud83d",
                       text="Client number\x00 Password \udc00 end",
                       chain=[f"https://{host}/\x00x", "https://\ud800.example/"],
                       forms=[{"action": "https://evil\x00.top/gate", "method": "post", "has_password": True,
                               "has_otp": False, "has_card": False,
                               "inputs": [{"type": "password", "name": "pw\x00", "autocomplete": "",
                                           "label": "Pass\ud800word"}]}],
                       html="<html>\x00<title>x</title>\ud800</html>")
            r["timings"] = {"nav_ms": float("nan"), "total_ms": float("inf"), "x\x00": 1}
            r["egress_country"] = "AU\x00"
            r["url"] = None
            return r
        fetcher.sites[host] = hostile
        fetcher.health_body = {**fetcher.health_body, "egress_country": "AU\x00", "error": "\ud800"}
        out = await fetch.run_once(ctx())
        assert out["failed"] == 0 and out["fetched"] == 1 and out["egress_country"] == "AU"
        # the worker stores each run's result as the job status (cybercheck/worker.py)
        async with (await db.pool()).connection() as conn:
            await db.kv_set(conn, "job:fetch", {"ok": True, "result": out})
        assert q1("SELECT value FROM kv WHERE key = 'job:fetch'")["value"]["result"]["egress_country"] == "AU"
        rows = pages(did)
        assert len(rows) == 2
        r = rows[0]
        assert "\x00" not in r["title"] and r["title"].startswith("NetBank Log on")
        assert "\x00" not in r["text_excerpt"] and r["url"] == f"https://{host}/"
        assert r["title"] == "NetBank Log on ?" and r["text_excerpt"] == "Client number Password ? end"
        assert r["features"]["redirect_chain"] == [f"https://{host}/x", "https://?.example/"]
        assert r["form_actions"] == ["evil.top"]
        assert r["features"]["timings"] == {"nav_ms": None, "total_ms": None, "x": 1}
        assert r["features"]["egress_country"] == "AU"
        raw = gzip.decompress((data_dir / r["html_path"]).read_bytes())
        assert b"<title>x</title>" in raw
        assert dom(did)["live_state"] == "live"
    run(body())


def test_redirect_to_the_real_brand_is_a_decoy_not_evidence(fetcher):
    async def body():
        host = "commbank-secure.top"
        did = await seed(host, tier="review")
        fetcher.sites[host] = lambda url, profile: loaded(
            url, profile, final_url="https://www.commbank.com.au/", chain=[url, "https://www.commbank.com.au/"],
            forms=[{"action": "https://www.commbank.com.au/netbank/logon", "method": "post", "has_password": True,
                    "has_otp": False, "has_card": False,
                    "inputs": [{"type": "password", "name": "password", "autocomplete": "current-password",
                                "label": "Password"}]}])
        await fetch.run_once(ctx())
        r = pages(did)[0]
        assert r["final_url"] == "https://www.commbank.com.au/"
        assert r["has_password_field"] is False and r["external_form_post"] is False
        assert r["features"]["decoy"] is True and r["features"]["offsite_credentials"] == ["password"]
        assert r["features"]["redirect_chain"] == [f"https://{host}/", "https://www.commbank.com.au/"]
        d = dom(did)
        assert d["live_state"] == "live" and d["page_score"] is not None
    run(body())


def test_concurrent_domains_share_the_pool_correctly(fetcher, monkeypatch, _env):
    data_dir = _env

    async def body():
        hosts = ["login.commbank-verify.top", "mygov-secure-login.xyz", "auspost-parcel-redelivery.info",
                 "commbankrewards.shop", "xn--auspst-delivery-ctb.top", "xn--westpac-scure-jhb.top"]
        ids = [await seed(h) for h in hosts]
        colours = {h: (i * 40 % 256, 80, 160) for i, h in enumerate(hosts)}
        for h in hosts:
            fetcher.sites[h] = (lambda hh: lambda url, profile: loaded(url, profile, title=f"Login {hh}",
                                                                       color=colours[hh]))(h)
        fetcher.delay = 0.02
        monkeypatch.setenv("FETCH_CONCURRENCY", "3")
        config.settings.cache_clear()
        out = await fetch.run_once(ctx())
        assert out["due"] == 6 and out["fetched"] == 6 and out["live"] == 6 and out["failed"] == 0
        assert 2 <= fetcher.max_in_flight <= 3
        for did, h in zip(ids, hosts):
            rows = pages(did)
            assert [r["user_agent_profile"] for r in rows] == ["mobile", "desktop"]
            for r in rows:
                assert r["title"] == f"Login {h}" and r["url"] == f"https://{h}/"
                assert r["screenshot_path"].startswith(f"screenshots/{did}/")
                assert (data_dir / r["screenshot_path"]).read_bytes() == webp(colours[h], r["user_agent_profile"])
            assert dom(did)["live_state"] == "live"
        assert q1("SELECT count(*) AS n FROM domain_events WHERE kind = 'went_live'")["n"] == 6
    run(body())


# ---- retention ---------------------------------------------------------------------------------

def _elapsed_since_first_page() -> timedelta:
    return q1("SELECT now() - min(fetched_at) AS e FROM pages")["e"]


def test_retention_on_empty_tables():
    async def body():
        out = await retention.run_once(ctx())
        assert out == {"released": 0, "files_deleted": 0, "kept_evidence": 0, "orphans_deleted": 0}
    run(body())


def test_retention_releases_expired_snapshots_and_shared_files(fetcher, _env):
    data_dir = _env

    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")
        look = {"color": (255, 204, 0)}
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, color=look["color"])
        await fetch.run_once(ctx())                         # r1 mobile + desktop: 4 files
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())                         # r2 mobile: reuses r1 mobile's files
        travel(hours=6, minutes=1)
        look["color"] = (0, 0, 0)
        await fetch.run_once(ctx())                         # r3 mobile: new screenshot, html reused
        r1m, r1d, r2m, r3m = pages(did)
        assert r2m["screenshot_path"] == r1m["screenshot_path"] and r3m["html_path"] == r1m["html_path"]
        assert len(files_under(data_dir)) == 5

        # nothing has expired yet
        c = ctx()
        out = await retention.run_once(c)
        assert out == {"released": 0, "files_deleted": 0, "kept_evidence": 0, "orphans_deleted": 0}

        # 60 days + 30 min after r1: r1 rows expire; r1 mobile's files are still used by r2 / r3
        travel(seconds=(timedelta(days=60, minutes=30) - _elapsed_since_first_page()).total_seconds())
        out = await retention.run_once(c)
        assert out == {"released": 2, "files_deleted": 2, "kept_evidence": 0}    # r1 desktop's two files
        r1m, r1d, r2m, r3m = pages(did)
        assert r1m["screenshot_path"] is None and r1m["html_path"] is None
        assert r1d["screenshot_path"] is None and r1d["html_path"] is None
        assert r1m["screenshot_sha256"] is not None                 # the row and its hashes stay
        assert (data_dir / r2m["screenshot_path"]).is_file() and (data_dir / r2m["html_path"]).is_file()
        assert len(files_under(data_dir)) == 3

        # an hour later r2 expires: its screenshot goes, the html is still r3's
        travel(hours=1)
        out = await retention.run_once(c)
        assert out == {"released": 1, "files_deleted": 1, "kept_evidence": 0}
        assert files_under(data_dir) == {r3m["screenshot_path"], r3m["html_path"]}

        # r3 expires: everything is gone, rows remain; running again changes nothing
        travel(hours=6)
        out = await retention.run_once(c)
        assert out == {"released": 1, "files_deleted": 2, "kept_evidence": 0}
        assert files_under(data_dir) == set()
        assert len(pages(did)) == 4 and all(p["screenshot_path"] is None and p["html_path"] is None
                                            for p in pages(did))
        assert await retention.run_once(c) == {"released": 0, "files_deleted": 0, "kept_evidence": 0}

        # a new certificate re-arms the domain; an identical snapshot writes its file again
        await new_cert("secure.login.commbank-verify.top")
        await fetch.run_once(ctx())
        r5 = pages(did)[-1]
        assert r5["screenshot_path"] == f"screenshots/{did}/{r5['id']}-mobile.webp"
        assert (data_dir / r5["screenshot_path"]).is_file()
    run(body())


def test_retention_keeps_confirmed_evidence_and_releases_it_after_a_status_change(fetcher, _env):
    data_dir = _env

    async def body():
        a, b = "commbankrewards.shop", "mygov-secure-login.xyz"
        da, dbb = await seed(a, tier="high"), await seed(b, tier="high")
        for h in (a, b):
            fetcher.sites[h] = lambda url, profile: loaded(url, profile)
        await fetch.run_once(ctx())
        await set_status(da, "confirmed", "kit confirmed")
        await set_status(dbb, "confirmed")
        assert all(p["is_evidence"] for p in pages(da) + pages(dbb))     # the dashboard marks existing rows
        travel(hours=2, minutes=1)
        await fetch.run_once(ctx())                                      # tracked: a new row each, not evidence
        assert [p["is_evidence"] for p in pages(da)] == [True, True, False]
        n_files = len(files_under(data_dir))
        assert n_files == 8

        travel(days=61)
        c = ctx()
        out = await retention.run_once(c)
        assert out == {"released": 0, "files_deleted": 0, "kept_evidence": 2, "orphans_deleted": 0}
        assert all(p["is_evidence"] for p in pages(da) + pages(dbb))
        assert len(files_under(data_dir)) == n_files

        # a reviewer clears a: within the grace period nothing changes
        await set_status(da, "false_positive", "brand's own promo microsite")
        out = await retention.run_once(c)
        assert out == {"released": 0, "files_deleted": 0, "kept_evidence": 0}
        assert all(p["is_evidence"] for p in pages(da))
        # b is reopened (unconfirmed) as well
        await set_status(dbb, "open", "needs another look")

        travel(days=7, hours=1)
        out = await retention.run_once(c)
        # 3 rows each lose the mark; a's and b's files go (the mobile rows share one file per domain)
        assert out == {"evidence_cleared": 6, "released": 6, "files_deleted": 8, "kept_evidence": 0}
        assert files_under(data_dir) == set()
        assert not any(p["is_evidence"] for p in pages(da) + pages(dbb))
    run(body())


def test_retention_keeps_a_path_whose_file_cannot_be_deleted(fetcher, monkeypatch, _env):
    data_dir = _env

    async def body():
        host = "auspost-parcel-redelivery.info"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        await fetch.run_once(ctx())
        travel(days=61)
        shots = data_dir / "screenshots" / str(did)
        os.chmod(shots, 0o555)                       # screenshots cannot be unlinked, html can
        monkeypatch.setenv("RETENTION_BATCH", "1")   # one row per batch: later batches carry the skip list
        try:
            out = await retention.run_once(ctx())
        finally:
            os.chmod(shots, 0o755)
        assert out["delete_errors"] == 2 and out["files_deleted"] == 2 and out["released"] == 2
        for p in pages(did):
            assert p["screenshot_path"] is not None and p["html_path"] is None
            assert (data_dir / p["screenshot_path"]).is_file()
        # retried next run
        out = await retention.run_once(ctx())
        assert out["files_deleted"] == 2 and "delete_errors" not in out
        assert files_under(data_dir) == set()
        assert all(p["screenshot_path"] is None for p in pages(did))
    run(body())


def test_retention_never_touches_paths_outside_the_data_dir(fetcher, _env, tmp_path):
    data_dir = _env

    async def body():
        host = "westpac-secure.top"
        did = await seed(host, tier="review")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        await fetch.run_once(ctx())
        outside = tmp_path / "precious.txt"
        outside.write_text("keep me")
        rel = os.path.relpath(outside, data_dir)
        r1, r2 = pages(did)
        with db.connect_sync() as c:                # corrupted / tampered rows
            c.execute("UPDATE pages SET screenshot_path = %s WHERE id = %s", (rel, r1["id"]))
            c.execute("UPDATE pages SET html_path = %s WHERE id = %s", (str(outside), r2["id"]))
        travel(days=61)
        out = await retention.run_once(ctx())
        assert outside.read_text() == "keep me"
        assert out["released"] == 2
        assert all(p["screenshot_path"] is None and p["html_path"] is None for p in pages(did))
    run(body())


def test_retention_drains_a_backlog_in_batches(fetcher, monkeypatch, _env):
    data_dir = _env

    async def body():
        hosts = ["login.commbank-verify.top", "mygov-secure-login.xyz", "auspost-parcel-redelivery.info",
                 "commbankrewards.shop"]
        for i, h in enumerate(hosts):
            await seed(h)
            fetcher.sites[h] = (lambda col: lambda url, profile: loaded(url, profile, color=col))((i * 50, 0, 0))
        await fetch.run_once(ctx())
        assert len(files_under(data_dir)) == 16
        travel(days=61)
        monkeypatch.setenv("RETENTION_BATCH", "3")
        out = await retention.run_once(ctx())
        assert out["released"] == 8 and out["files_deleted"] == 16
        assert files_under(data_dir) == set()
        left = q1("SELECT count(*) AS n FROM pages WHERE screenshot_path IS NOT NULL OR html_path IS NOT NULL")
        assert left["n"] == 0
    run(body())


def test_orphan_sweep(fetcher, _env, tmp_path):
    data_dir = _env

    async def body():
        host = "commbank-secure.top"
        did = await seed(host, tier="review")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        await fetch.run_once(ctx())
        referenced = {p["screenshot_path"] for p in pages(did)} | {p["html_path"] for p in pages(did)}
        old = time.time() - 2 * 86400

        def make(rel: str, age: float | None = old) -> Path:
            p = data_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x")
            if age:
                os.utime(p, (age, age))
            return p

        orphans = [make(f"screenshots/{did}/999-mobile.webp"), make(f"html/{did}/999-mobile.html.gz"),
                   make(f"screenshots/{did}/1000-desktop.webp.tmp"),          # killed mid-write
                   make("screenshots/424242/5-mobile.webp")]                 # domain row long gone
        keep = [make(f"screenshots/{did}/fresh-mobile.webp", None),         # younger than the grace
                make("screenshots/notanid/1-mobile.webp"), make("screenshots/٣/1-mobile.webp"),
                make("thumbnails/1/1.webp")]
        target = tmp_path / "target.webp"
        target.write_bytes(b"t")
        link = data_dir / "screenshots" / str(did) / "link.webp"
        link.symlink_to(target)
        os.utime(link, (old, old), follow_symlinks=False)
        for rel in referenced:                                             # referenced files are old too
            os.utime(data_dir / rel, (old, old))

        c = ctx()
        out = await retention.run_once(c)
        assert out["orphans_deleted"] == 4
        assert not any(p.exists() for p in orphans)
        assert all(p.exists() for p in keep) and link.is_symlink() and target.exists()
        assert all((data_dir / rel).is_file() for rel in referenced)
        # at most once a day per worker
        out = await retention.run_once(c)
        assert "orphans_deleted" not in out
    run(body())



# Each value Postgres (or psycopg) refuses, alone: (mutation of a loaded result, column, stored value)
HOSTILE = {
    "nul_title": (lambda r: r.update(title="NetBank\x00 Log on"), "title", "NetBank Log on"),
    "nul_text": (lambda r: r.update(text_excerpt="Client number\x00 Password"), "text_excerpt",
                 "Client number Password"),
    "surrogate_title": (lambda r: r.update(title="NetBank \ud83d"), "title", "NetBank ?"),
    "nul_form_action": (lambda r: r["forms"][0].update(action="https://evil\x00.top/gate"), "form_actions",
                        ["evil.top"]),
    "nul_redirect_jsonb": (lambda r: r.update(redirect_chain=["https://x.top/\x00"]), "features.redirect_chain",
                           ["https://x.top/"]),
    "nan_timing_jsonb": (lambda r: r.update(timings={"nav_ms": float("nan")}), "features.timings",
                         {"nav_ms": None}),
    "nul_error": (lambda r: r.update(ok=False, error="net::ERR_FAILED\x00"), "error", "net::ERR_FAILED"),
    "huge_status": (lambda r: r.update(http_status=10 ** 12), "http_status", None),
    "null_url": (lambda r: r.update(url=None), "url", "https://login.commbank-verify.top/"),
}


@pytest.mark.parametrize("kind", sorted(HOSTILE))
def test_each_unstorable_value_alone_is_cleaned(fetcher, kind):
    mutate, col, expected = HOSTILE[kind]

    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")

        def answer(url, profile):
            r = loaded(url, profile)
            mutate(r)
            return r
        fetcher.sites[host] = answer
        out = await fetch.run_once(ctx())
        assert out["failed"] == 0 and out["fetched"] == 1
        rows = pages(did)
        assert len(rows) == 2
        value = rows[0]
        for part in col.split("."):
            value = value[part]
        assert value == expected
        assert dom(did)["fetch_state"]["n"] == 1
    run(body())


# ---- verifier additions -------------------------------------------------------------------------

def _next_page_id() -> int:
    r = q1("SELECT last_value, is_called FROM pages_id_seq")
    return r["last_value"] + 1 if r["is_called"] else r["last_value"]


def test_a_round_that_fails_to_save_leaves_no_rows_and_retries_do_not_pile_up(fetcher, _env):
    """A save that keeps failing (here: the domain's HTML directory is unusable) must not leave a
    half-recorded pages row behind on every 30-minute retry: those rows look like loaded credential
    snapshots (features.loaded, has_password_field, error NULL) that the domain never accounted for, and the
    judge's PENDING_SQL picks them up."""
    data_dir = _env

    async def body():
        from cybercheck.jobs import judge
        host = "mygov-secure-login.xyz"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title="myGov - Sign in")
        (data_dir / "html").mkdir()
        (data_dir / "html" / str(did)).write_bytes(b"")
        for _ in range(3):
            out = await fetch.run_once(ctx())
            assert out["failed"] == 1 and out["fetched"] == 0
            assert near(dom(did)["fetch_in"], timedelta(minutes=30))
            travel(minutes=31)
        assert pages(did) == []
        assert files_under(data_dir) == {f"html/{did}"}
        d = dom(did)
        assert d["fetch_state"] == {} and d["live_state"] == "unknown" and d["page_score"] is None
        assert events(did) == [e for e in events(did) if e["kind"] not in ("went_live", "page_down")]
        async with (await db.pool()).connection() as conn:
            pending = await (await conn.execute(judge.PENDING_SQL, (48, 50))).fetchall()
        assert pending == []

        # repaired: the next round is a normal first round (both profiles)
        (data_dir / "html" / str(did)).unlink()
        fetcher.urls()
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1 and [p for _, p in fetcher.urls()] == ["mobile", "desktop"]
        rows = pages(did)
        assert [r["user_agent_profile"] for r in rows] == ["mobile", "desktop"]
        assert all((data_dir / r["screenshot_path"]).is_file() and (data_dir / r["html_path"]).is_file()
                   for r in rows)
        assert dom(did)["fetch_state"]["n"] == 1 and dom(did)["live_state"] == "live"
    run(body())


def test_a_failure_on_the_second_profile_rolls_back_the_first(fetcher, _env):
    """The mobile snapshot saves, then the desktop one fails: the round is retried in full, so the mobile
    row (and its files) of the failed round must not stay as a duplicate."""
    data_dir = _env

    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        desktop_id = _next_page_id() + 1
        blocker = data_dir / "html" / str(did) / f"{desktop_id}-desktop.html.gz"
        blocker.mkdir(parents=True)              # a directory where the desktop HTML file must go
        out = await fetch.run_once(ctx())
        assert out["failed"] == 1
        assert pages(did) == []
        assert files_under(data_dir) == set()    # mobile's screenshot + HTML removed again, no .tmp left
        assert dom(did)["fetch_state"] == {}

        travel(minutes=31)
        out = await fetch.run_once(ctx())
        assert out["fetched"] == 1 and out["failed"] == 0
        rows = pages(did)
        assert [r["user_agent_profile"] for r in rows] == ["mobile", "desktop"]
        st = dom(did)["fetch_state"]
        assert st["n"] == 1
        assert {k: v["path"] for k, v in st["shots"].items()} == {r["user_agent_profile"]: r["screenshot_path"]
                                                                  for r in rows}
        assert files_under(data_dir) == {r["screenshot_path"] for r in rows} | {r["html_path"] for r in rows}
        assert len(events(did, "went_live")) == 1
    run(body())


def test_retention_keeps_a_file_shared_with_a_row_that_has_no_retain_until(fetcher, _env):
    """REFERENCED_SQL's retain_until IS NULL branch: a row kept with no expiry (set by hand for a case file,
    or a legacy row) still needs the file an expiring row releases."""
    data_dir = _env

    async def body():
        host = "auspost-parcel-redelivery.info"
        did = await seed(host, tier="high")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile, title="Australia Post")
        await fetch.run_once(ctx())
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        r1m, r1d, r2m = pages(did)
        assert r2m["screenshot_path"] == r1m["screenshot_path"] and r2m["html_path"] == r1m["html_path"]
        with db.connect_sync() as c:
            c.execute("UPDATE pages SET retain_until = NULL WHERE id = %s", (r2m["id"],))
        travel(days=61)
        out = await retention.run_once(ctx())
        assert out["released"] == 2 and out["files_deleted"] == 2          # r1 desktop's two files only
        r1m, r1d, r2m = pages(did)
        assert r1m["screenshot_path"] is None and r1m["html_path"] is None
        assert files_under(data_dir) == {r2m["screenshot_path"], r2m["html_path"]}
        travel(days=365)
        assert (await retention.run_once(ctx()))["released"] == 0
        assert files_under(data_dir) == {r2m["screenshot_path"], r2m["html_path"]}
    run(body())


def test_identity_field_is_stored_in_the_shape_judge_reads(fetcher):
    """has_identity_field has no column: it lives in pages.features, and judge/confidence read it with
    features -> 'has_identity_field' = 'true'::jsonb. The fetch job must store a jsonb boolean there."""
    async def body():
        from cybercheck.jobs import judge
        host = "mygov-secure-login.xyz"
        did = await seed(host, tier="high")
        forms = [{"action": "/verify.php", "method": "post", "has_password": False, "has_otp": False,
                  "has_card": False,
                  "inputs": [{"type": "text", "name": "medicareNo", "autocomplete": "",
                              "label": "Medicare number"},
                             {"type": "text", "name": "dob", "autocomplete": "bday", "label": "Date of birth"},
                             {"type": "submit", "name": "", "autocomplete": "", "label": "Continue"}]}]
        fetcher.sites[host] = lambda url, profile: loaded(
            url, profile, title="myGov - Confirm your identity", forms=forms,
            text="Confirm your identity to receive your refund. Medicare number. Date of birth.")
        await fetch.run_once(ctx())
        rows = pages(did)
        assert all(r["features"]["has_identity_field"] is True for r in rows)
        assert all(r["has_password_field"] is False and r["has_card_field"] is False for r in rows)
        async with (await db.pool()).connection() as conn:
            got = await (await conn.execute(judge.PAGES_BY_ID_SQL, ([r["id"] for r in rows],))).fetchall()
        assert [g["has_identity_field"] for g in got] == [True, True]
        assert all(g["form_actions"] == ["mygov-secure-login.xyz"] and g["external_form_post"] is False for g in got)
        assert dom(did)["page_score"] > 0
    run(body())


def test_orphan_sweep_with_odd_numeric_directory_names(fetcher, _env):
    """Directory names are only checked to be ASCII digits: one past bigint (compared as numeric) or with
    leading zeros must neither abort the sweep (it is all-or-nothing behind a catch-all) nor protect files."""
    data_dir = _env

    async def body():
        host = "commbank-secure.top"
        did = await seed(host, tier="review")
        fetcher.sites[host] = lambda url, profile: loaded(url, profile)
        await fetch.run_once(ctx())
        referenced = {p["screenshot_path"] for p in pages(did)} | {p["html_path"] for p in pages(did)}
        old = time.time() - 3 * 86400
        made = []
        for rel in ("screenshots/99999999999999999999999/1-mobile.webp",     # > bigint
                    f"screenshots/{did:05d}/1-mobile.webp",                   # leading zeros: not where fetch writes
                    f"html/{did}/77-desktop.html.gz"):
            p = data_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x")
            os.utime(p, (old, old))
            made.append(p)
        for rel in referenced:
            os.utime(data_dir / rel, (old, old))
        out = await retention.run_once(ctx())
        assert out["orphans_deleted"] == 3
        assert not any(p.exists() for p in made)
        assert files_under(data_dir) == referenced
    run(body())


def test_odd_field_types_and_array_quoting_from_the_fetcher(fetcher):
    """A redirect_chain that is not a list must not make the domain unrecordable, and hostnames with
    characters that need quoting in a Postgres array literal round-trip through pages.form_actions."""
    async def body():
        host = "login.commbank-verify.top"
        did = await seed(host, tier="high")

        def answer(url, profile):
            r = loaded(url, profile, forms=[
                {**LOGIN_FORMS[0], "action": 'https://a"b,c{d}\\e.top/gate'},
                {**LOGIN_FORMS[0], "action": "https://NULL.top/x"}])
            r["redirect_chain"] = {"0": url} if profile == "mobile" else "https://x.top/"
            if profile == "desktop":
                r["final_url"] = 443
            return r
        fetcher.sites[host] = answer
        out = await fetch.run_once(ctx())
        assert out["failed"] == 0 and out["fetched"] == 1
        rows = pages(did)
        assert [r["features"]["redirect_chain"] for r in rows] == [[], []]
        assert rows[0]["form_actions"] == ['a"b,c{d}\\e.top', "null.top"]
        assert rows[0]["external_form_post"] is True
        assert rows[1]["final_url"] == "443" and rows[1]["form_actions"] == ['a"b,c{d}\\e.top', "null.top"]
        hit = q1("SELECT count(*) AS n FROM pages WHERE %s = ANY(form_actions)", ("null.top",))
        assert hit["n"] == 2
    run(body())


def test_a_non_utc_session_timezone_changes_nothing(fetcher, it_db):
    """A host's Postgres may run with a local TimeZone: psycopg then returns timestamptz values with that
    offset. Schedules, the failure streak and the retention cut-off must be unaffected."""
    name = it_db.rsplit("/", 1)[1]
    import os
    old_opts = os.environ.get("CYBERCHECK_DB_OPTIONS")
    os.environ["CYBERCHECK_DB_OPTIONS"] = ""             # turn off db.py's UTC pin: prove the code holds without it

    def set_tz(tz):
        with db.connect_sync() as c:
            c.execute(f'ALTER DATABASE "{name}" SET timezone TO {tz}')

    async def body():
        host = "auspost-parcel-redelivery.info"
        did = await seed(host, tier="high")
        up = {"v": True}
        fetcher.sites[host] = lambda url, profile: (loaded(url, profile, title="Australia Post") if up["v"]
                                                    else nav_failed(url, profile))
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["first_live_at"].utcoffset() != timedelta(0)        # really a non-UTC session
        assert near(d["fetch_in"], timedelta(hours=1))
        up["v"] = False
        travel(hours=1, minutes=1)
        await fetch.run_once(ctx())
        assert near(dom(did)["fetch_in"], timedelta(minutes=20))
        travel(minutes=21)
        await fetch.run_once(ctx())
        d = dom(did)
        assert d["live_state"] == "down" and len(events(did, "page_down")) == 1
        since = fetch.parse_ts(d["fetch_state"]["fail_since"])
        assert since is not None and near(datetime.now(UTC) - since, timedelta(minutes=21), timedelta(minutes=1))
        travel(seconds=(timedelta(days=60, minutes=-10) - _elapsed_since_first_page()).total_seconds())
        assert (await retention.run_once(ctx()))["released"] == 0
        travel(minutes=20)
        assert (await retention.run_once(ctx()))["released"] == 2      # the first round's two rows
    set_tz("'Australia/Sydney'")
    try:
        run(body())
    finally:
        set_tz("DEFAULT")
        if old_opts is None:
            os.environ.pop("CYBERCHECK_DB_OPTIONS", None)
        else:
            os.environ["CYBERCHECK_DB_OPTIONS"] = old_opts


def test_sessions_are_pinned_to_utc_by_default(fetcher, it_db):
    """db.py pins every session to UTC, so an ALTER DATABASE ... SET timezone cannot shift what the app sees."""
    name = it_db.rsplit("/", 1)[1]
    with db.connect_sync() as c:
        c.execute(f"ALTER DATABASE \"{name}\" SET timezone TO 'Australia/Sydney'")
    try:
        with db.connect_sync() as c:
            assert c.execute("SHOW TimeZone").fetchone()["TimeZone"] == "UTC"
            assert c.execute("SELECT now() AS n").fetchone()["n"].utcoffset() == timedelta(0)

        async def pooled():
            async with (await db.pool()).connection() as conn:
                return (await (await conn.execute("SHOW TimeZone")).fetchone())["TimeZone"]
        assert run(pooled()) == "UTC"
    finally:
        with db.connect_sync() as c:
            c.execute(f'ALTER DATABASE "{name}" SET timezone TO DEFAULT')
