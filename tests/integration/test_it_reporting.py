"""Integration tests for the reporting group against a real Postgres (tests/integration/conftest.py):
the report job (cybercheck/jobs/report.py, cybercheck/reporting/) and the blocklist job
(cybercheck/jobs/blocklist.py, cybercheck/blocklist.py).

The database is real. Every network boundary is stubbed: Netcraft is an httpx.MockTransport behind
netcraft.new_client(), SMTP is a fake smtplib class, the AI goes through the real anthropic SDK with an
httpx2.MockTransport (realistic messages with usage numbers), and the fetcher is a fake FetchClient fed to
the fetch job's own process_domain(), so pages and screenshots are stored the way the pipeline stores them.
Domains are created with cybercheck.store.store_hit from real watchlist scores. Sockets to anything other
than the disposable Postgres are refused.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import smtplib
import socket
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import anthropic
import httpx
import httpx2
import psycopg
import pytest
from PIL import Image
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from cybercheck import blocklist, config, db, scoring
from cybercheck.ai import budget as ai_budget
from cybercheck.ai import client as ai_client
from cybercheck.jobs import blocklist as blocklist_job
from cybercheck.jobs import fetch as fetch_job
from cybercheck.jobs import report as report_job
from cybercheck.reporting import engine, evidence, netcraft
from cybercheck.reporting.conf import load_config
from cybercheck.store import store_hit
from cybercheck.worker import JobContext

UTC = timezone.utc
EGRESS_IP = "198.51.100.7"
REPORTER = "reports@cybercheck-test.example"
REVIEWER = "alice@tailnet"

# Reviewer approval / mark-sent, as the /reports page does it (cybercheck/web/pages_reports.py).
APPROVE_SQL = """
UPDATE reports SET status = 'approved', attempts = 0, next_attempt_at = now(), error = NULL,
       reviewed_by = %s, reviewed_at = now(), updated_at = now(), payload = payload || %s
WHERE id = %s
"""
REJECT_SQL = """
UPDATE reports SET status = 'rejected', reviewed_by = %s, reviewed_at = now(), error = %s, updated_at = now()
WHERE id = %s
"""

REPORT_ENV = ("REPORTING_MODE", "AUTO_REPORT_MIN_FINAL_SCORE", "REPORT_RATE_PER_HOUR", "REPORTER_EMAIL",
              "REPORTER_NAME", "REPORT_CHANNEL_MIN_INTERVAL_S", "REPORT_LOOKBACK_DAYS", "REPORT_MAX_ATTEMPTS",
              "REPORT_AI_DRAFTS", "REPORT_AI_DRAFTS_PER_RUN", "REPORT_MANUAL_CHANNELS", "NETCRAFT_ENABLED",
              "NETCRAFT_TEST", "NETCRAFT_API_KEY", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD",
              "SMTP_FROM", "ANTHROPIC_API_KEY", "AI_ENABLED", "AI_MODEL", "AI_DAILY_BUDGET_USD",
              "AI_MONTHLY_BUDGET_USD", "AI_FALLBACKS", "AI_EFFORT", "BLOCKLIST_MIN_FINAL_SCORE", "BLOCKLIST_DAYS",
              "BLOCKLIST_HOMEPAGE", "BLOCKLIST_CONTACT", "BLOCKLIST_LICENSE", "BLOCKLIST_BUILD_INTERVAL",
              "BLOCKLIST_CZDS_TERMS_OK", "FETCH_MIN_FREE_GB", "WATCH_DAYS")


# ---- harness -------------------------------------------------------------------------------------

def arun(coro):
    """Run one coroutine on a fresh loop; the global pool belongs to that loop, so close it after."""
    async def main():
        try:
            return await coro
        finally:
            await db.close()
    return asyncio.run(main())


@pytest.fixture
def pg(it_db, monkeypatch, tmp_path):
    """Empty tables, deterministic settings, no network but the disposable Postgres."""
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        if isinstance(address, tuple) and address[:2] not in (("127.0.0.1", 55432),):
            raise AssertionError(f"network access in a test: {address!r}")
        return real_connect(self, address)

    def refuse(*a, **kw):
        raise AssertionError("network access in a test")
    real_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(host, *a, **kw):
        if host not in ("127.0.0.1", "localhost", None):
            raise AssertionError(f"DNS lookup in a test: {host!r}")
        return real_getaddrinfo(host, *a, **kw)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)

    for k in REPORT_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("REPORTING_MODE", "review")
    monkeypatch.setenv("REPORTER_EMAIL", REPORTER)
    monkeypatch.setenv("REPORTER_NAME", "CyberCheck IT")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")          # AI unavailable unless a test installs the fake
    monkeypatch.setenv("FETCH_MIN_FREE_GB", "0")
    config.settings.cache_clear()
    ai_client.set_client(None)
    ai_budget._logged.clear()

    with psycopg.connect(it_db, autocommit=True) as c:
        c.execute("TRUNCATE domains, domain_events, checks, pages, ai_calls, reports, report_attempts, kv "
                  "RESTART IDENTITY CASCADE")
    data = config.settings().data_dir
    for sub in ("blocklist", "screenshots", "html"):
        d = data / sub
        if d.exists():
            for p in sorted(d.rglob("*"), reverse=True):
                p.unlink() if p.is_file() else p.rmdir()
    (data / "sandbox_verified.json").unlink(missing_ok=True)
    yield it_db
    ai_client.set_client(None)
    config.settings.cache_clear()


def setenv(monkeypatch, **kw):
    for k, v in kw.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, str(v))
    config.settings.cache_clear()


def q(url, sql, params=()):
    with psycopg.connect(url, autocommit=True, row_factory=dict_row) as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else cur.rowcount


def q1(url, sql, params=()):
    rows = q(url, sql, params)
    return rows[0] if rows else None


def ctx_for(state=None) -> JobContext:
    return JobContext(settings=config.settings(), log=logging.getLogger("it"), state={} if state is None else state)


def run_report(ctx=None) -> dict:
    return arun(report_job.run(ctx or ctx_for()))


def reports(url, domain_id=None) -> dict:
    sql = "SELECT * FROM reports" + (" WHERE domain_id = %s" if domain_id else "") + " ORDER BY id"
    return {r["channel"]: r for r in q(url, sql, (domain_id,) if domain_id else ())}


def webp_b64(color=(255, 204, 0), size=(390, 844)) -> str:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="WEBP", quality=60)
    return base64.b64encode(buf.getvalue()).decode()


SHOT = webp_b64()


# ---- seeding the way the pipeline does it ------------------------------------------------------------

WL = None


def watchlist():
    global WL
    if WL is None:
        WL = scoring.default_watchlist()
    return WL


async def _store(hostnames, source="ct"):
    p = await db.pool()
    async with p.connection() as conn:
        did = None
        for h in hostnames:
            hit = watchlist().score_hostname(h)
            assert hit is not None, h
            did, _ = await store_hit(conn, hit, source=source, issuer="C=US, O=Let's Encrypt, CN=R11",
                                     ct_log="Google 'Argon2026h2' log")
        return did


async def _enrich(did, *, registrar="NameSilo, LLC", registrar_abuse="abuse@namesilo.com",
                  hosting_abuse="abuse@hostinger.com", ips=("203.0.113.10",), asn=47583,
                  as_name="AS-HOSTINGER - Hostinger International Limited", country="LT", registered_days_ago=2):
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            "UPDATE domains SET dns_state = 'resolves', ips = %s, asn = %s, as_name = %s, ip_country = %s, "
            # .au: never queried by RDAP (auDA WHOIS Policy 5.1), so no registrar data
            "registrar = CASE WHEN right(registered_domain, 3) = '.au' THEN NULL ELSE %s END, "
            "registrar_iana_id = CASE WHEN right(registered_domain, 3) = '.au' THEN NULL ELSE 1479 END, "
            "registrar_abuse_email = CASE WHEN right(registered_domain, 3) = '.au' THEN NULL ELSE %s END, "
            "hosting_abuse_email = %s, registered_at = CASE WHEN right(registered_domain, 3) = '.au' THEN NULL "
            "ELSE now() - make_interval(days => %s) END, enriched_at = now() WHERE id = %s",
            (list(ips), asn, as_name, country, registrar, registrar_abuse, hosting_abuse, registered_days_ago, did))


def page_result(url, profile, *, creds=True, title="NetBank - Log on", status=200, shot=True, egress_ip=EGRESS_IP,
                final_url=None, ok=True, error=None):
    if not ok:
        return {"ok": False, "url": url, "final_url": None, "http_status": None, "error": error or "net::ERR_NAME_NOT_RESOLVED",
                "profile": profile}
    forms = [{"action": "/auth/logon.php", "method": "post", "inputs": [
        {"type": "text", "name": "client_number", "label": "Client number"},
        {"type": "password", "name": "password", "label": "Password"},
        {"type": "submit", "name": "logon", "label": "Log on"}]}] if creds else []
    return {"ok": True, "url": url, "final_url": final_url or (url + ("netbank/logon" if creds else "")),
            "http_status": status, "title": title,
            "text_excerpt": "Commonwealth Bank NetBank. Log on with your client number and password. "
                            "Suspicious activity was detected on your account." if creds else "Welcome",
            "html": "<html><body><form action='/auth/logon.php'><input name=client_number>"
                    "<input type=password name=password></form></body></html>",
            "forms": forms, "egress_ip": egress_ip, "egress_country": "AU",
            "screenshot_webp_b64": SHOT if shot else None, "redirect_chain": [url],
            "timings": {"nav_ms": 840, "total_ms": 1900}, "profile": profile, "error": None}


class FakeFetcher:
    """Stands in for cybercheck.fetch_client.FetchClient (the fetcher API inside the VPN)."""

    def __init__(self, **kw):
        self.kw = kw
        self.urls = []

    async def fetch(self, url, profile="mobile"):
        self.urls.append((url, profile))
        return page_result(url, profile, **self.kw)


async def _fetch_round(did, **kw):
    p = await db.pool()
    async with p.connection() as conn:
        d = await (await conn.execute("SELECT * FROM domains WHERE id = %s", (did,))).fetchone()
    store = fetch_job.Store(config.settings().data_dir, retain_days=60, min_free_gb=0)
    return await fetch_job.process_domain(ctx_for(), FakeFetcher(**kw), store, dict(d))


async def _judge(did, *, verdict="phishing", confidence=0.93, final=96):
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            "UPDATE domains SET ai_verdict = %s, ai_confidence = %s, ai_brand = brand_id, final_score = %s, "
            "final_reasons = %s, final_score_at = now() WHERE id = %s",
            (verdict, confidence, final, Jsonb([{"points": final, "why": "test"}]), did))
        await conn.execute("UPDATE pages SET ai_judged_at = now(), ai_result = %s WHERE domain_id = %s",
                           (Jsonb({"verdict": verdict, "confidence": confidence}), did))
        await db.add_event(conn, did, "ai_verdict", {"verdict": verdict, "confidence": confidence})


async def _set_status(did, status, by=REVIEWER, days_ago=0):
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            "UPDATE domains SET status = %s, status_by = %s, reviewed_hostnames = hostnames, "
            "status_changed_at = now() - make_interval(days => %s) WHERE id = %s", (status, by, days_ago, did))
        await db.add_event(conn, did, "status", {"status": status, "by": by})


async def _phish(hostnames, *, confirm=True, judge=True, fetch=True, enrich=True, final=96, confidence=0.93,
                 source="ct", **page_kw):
    did = await _store(hostnames, source=source)
    if enrich:
        await _enrich(did)
    if fetch:
        await _fetch_round(did, **page_kw)
    if judge:
        await _judge(did, final=final, confidence=confidence)
    if confirm:
        await _set_status(did, "confirmed")
    return did


def phish(hostnames, **kw) -> int:
    return arun(_phish(hostnames, **kw))


def age_pages(url, did, hours=2):
    """Earlier fetch rounds happened hours ago (the fetch job re-fetches on a schedule)."""
    q(url, "UPDATE pages SET fetched_at = fetched_at - make_interval(hours => %s) WHERE domain_id = %s", (hours, did))


def write_sandbox(days_ago=1.0, ip=EGRESS_IP):
    at = datetime.now(UTC) - timedelta(days=days_ago)
    (config.settings().data_dir / "sandbox_verified.json").write_text(json.dumps(
        {"verified_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "egress_ip": ip, "egress_country": "AU",
         "tests_passed": 12}))


# ---- Netcraft (httpx.MockTransport) ------------------------------------------------------------------

class Netcraft:
    def __init__(self):
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[str] = []
        self.replies: list = []            # queued replies for POST (Response, or an exception to raise)
        self.status: dict = {}             # uuid -> (submission json, urls json) | int http status
        self.submitted: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "report.netcraft.com", request.url
        if request.method == "POST":
            assert request.url.path in ("/api/v3/report/urls", "/api/v3/test/report/urls"), request.url.path
            self.posts.append((str(request.url), json.loads(request.content)))
            if self.replies:
                r = self.replies.pop(0)
                if isinstance(r, BaseException):
                    raise r
                return r
            uid = uuidlib.uuid4().hex
            self.submitted.add(uid)
            return httpx.Response(200, json={"message": "Successfully reported", "uuid": uid, "invalid_urls": []})
        self.gets.append(str(request.url))
        parts = request.url.path.split("/")
        uid = parts[parts.index("submission") + 1]
        new = ({"state": "processing", "is_archived": False}, {"urls": []})
        st = self.status.get(uid, new if uid in self.submitted else 404)
        if isinstance(st, int):
            return httpx.Response(st, json={"message": "not found"})
        sub, urls = st
        body = urls if request.url.path.endswith("/urls") else sub
        # json.dumps escapes as ASCII, as a JSON API may (lone surrogates survive as \\udxxx escapes)
        return httpx.Response(200, content=json.dumps(body).encode(), headers={"content-type": "application/json"})


@pytest.fixture
def nc(pg, monkeypatch):
    mock = Netcraft()
    monkeypatch.setattr(netcraft, "new_client", lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(mock.handler), headers={"User-Agent": netcraft.USER_AGENT}))
    return mock


def age_attempts(url, seconds=120):
    """Let time pass for the per-channel interval and the hourly rate limit."""
    q(url, "UPDATE report_attempts SET at = at - make_interval(secs => %s)", (seconds,))
    q(url, "UPDATE reports SET next_attempt_at = next_attempt_at - make_interval(secs => %s), "
           "last_attempt_at = last_attempt_at - make_interval(secs => %s) WHERE next_attempt_at IS NOT NULL",
      (seconds, seconds))


# ---- fake SMTP ---------------------------------------------------------------------------------------

class FakeSMTP:
    sessions: list["FakeSMTP"] = []
    starttls_offered = True
    fail_login: Exception | None = None
    fail_send: Exception | None = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.tls = context is not None
        self.messages = []
        self.logged_in = None
        FakeSMTP.sessions.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        return 250, b"ok"

    def has_extn(self, name):
        return name.lower() == "starttls" and FakeSMTP.starttls_offered

    def starttls(self, context=None):
        assert context is not None
        self.tls = True

    def login(self, user, password):
        assert self.tls, "login before TLS"
        if FakeSMTP.fail_login:
            raise FakeSMTP.fail_login
        self.logged_in = user

    def send_message(self, msg):
        if FakeSMTP.fail_send:
            raise FakeSMTP.fail_send
        self.messages.append(msg)


@pytest.fixture
def smtp(pg, monkeypatch):
    FakeSMTP.sessions = []
    FakeSMTP.starttls_offered = True
    FakeSMTP.fail_login = None
    FakeSMTP.fail_send = None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    setenv(monkeypatch, SMTP_HOST="smtp.mail-provider.example", SMTP_PORT="587", SMTP_USER="reports",
           SMTP_PASSWORD="not-a-real-password", SMTP_FROM=REPORTER)
    return FakeSMTP


# ---- fake Anthropic API (real SDK, mock transport) ---------------------------------------------------

class FakeClaude:
    def __init__(self):
        self.requests = []
        self.bad_for: set[str] = set()     # domains whose draft names an address that is not in the facts

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append(body)
        prompt = body["messages"][0]["content"][0]["text"]
        domain = next(line.split(": ", 1)[1] for line in prompt.splitlines() if line.startswith("Phishing domain:"))
        text = (f"The website {domain} appears to impersonate Commonwealth Bank and asks visitors for their "
                "client number and password. It was first seen in a Certificate Transparency log. "
                "Please investigate and suspend the domain.")
        if domain in self.bad_for:
            text += " Collected details are sent to drop-box-collector.top."
        msg = {"id": "msg_" + uuidlib.uuid4().hex[:20], "type": "message", "role": "assistant",
               "model": body["model"],
               "content": [{"type": "thinking", "thinking": "", "signature": "sig"},
                           {"type": "text", "text": json.dumps({"body": text})}],
               "stop_reason": "end_turn", "stop_sequence": None, "stop_details": None,
               "usage": {"input_tokens": 1840, "output_tokens": 310, "cache_read_input_tokens": 1200,
                         "cache_creation_input_tokens": 0}}
        return httpx2.Response(200, json=msg)


@pytest.fixture
def claude(pg, monkeypatch):
    setenv(monkeypatch, ANTHROPIC_API_KEY="sk-ant-test-not-real", AI_ENABLED="true", AI_MODEL="claude-opus-5-5",
           AI_DAILY_BUDGET_USD="1.60", AI_MONTHLY_BUDGET_USD="48")
    fake = FakeClaude()

    async def no_sleep(_s):
        return None
    monkeypatch.setattr(ai_client, "_sleep", no_sleep)
    ai_client.set_client(anthropic.AsyncAnthropic(
        api_key="sk-ant-test-not-real", max_retries=0,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(fake))))
    return fake


# =====================================================================================================
# report job
# =====================================================================================================

CONFIRMED_CHANNELS = {"netcraft", "registrar_abuse", "hosting_abuse", "brand:commbank", "scamwatch",
                      "google_safe_browsing", "microsoft_smartscreen"}


def test_mode_off_creates_and_sends_nothing(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="off")
    phish(["commbank-login-secure.top", "www.commbank-login-secure.top"])
    assert run_report() == {"mode": "off"}
    assert q(pg, "SELECT count(*) AS n FROM reports")[0]["n"] == 0
    assert nc.posts == []


def test_empty_tables_run_cleanly(pg, nc):
    out = run_report()
    assert out["mode"] == "review" and out["sent"] == 0
    assert q(pg, "SELECT count(*) AS n FROM reports")[0]["n"] == 0
    assert nc.posts == [] and nc.gets == []


def test_review_mode_plans_one_row_per_channel_and_sends_netcraft(pg, nc):
    did = phish(["commbank-login-secure.top", "www.commbank-login-secure.top"])
    other = phish(["auspost-parcel-redelivery.xyz"], confirm=False)       # open, high score: review mode ignores
    out = run_report()
    assert out["planned"] == len(CONFIRMED_CHANNELS) and out["sent"] == 1, out
    rows = reports(pg, did)
    assert set(rows) == CONFIRMED_CHANNELS
    assert reports(pg, other) == {}

    n = rows["netcraft"]
    assert n["status"] == "sent" and n["kind"] == "api" and n["auto"] is False and n["attempts"] == 1
    assert n["sent_via"] == "api" and n["sent_by"] == "worker" and n["external_id"] == n["response"]["uuid"]
    assert n["response"]["test"] is False
    for ch in ("registrar_abuse", "hosting_abuse", "brand:commbank"):
        assert rows[ch]["status"] == "pending_review" and rows[ch]["kind"] == "email"
        assert rows[ch]["payload"]["ai"] == "unavailable"                  # no ANTHROPIC_API_KEY: template kept
    for ch in ("scamwatch", "google_safe_browsing", "microsoft_smartscreen"):
        assert rows[ch]["status"] == "pending_review" and rows[ch]["kind"] == "manual"
    assert rows["registrar_abuse"]["payload"]["to"] == "abuse@namesilo.com"
    assert rows["hosting_abuse"]["payload"]["to"] == "abuse@hostinger.com"
    assert rows["brand:commbank"]["payload"]["attach_screenshot"] is True

    # the Netcraft request: the reporter, URLs on the domain only, the screenshot as a JPEG
    assert len(nc.posts) == 1
    endpoint, body = nc.posts[0]
    assert endpoint == "https://report.netcraft.com/api/v3/report/urls"
    assert body["email"] == REPORTER
    urls = [u["url"] for u in body["urls"]]
    assert urls and all("commbank-login-secure.top/" in u for u in urls)
    assert any(u.endswith("/netbank/logon") for u in urls)
    jpeg = base64.b64decode(body["urls"][0]["screenshot"]["base64"])
    assert jpeg[:3] == b"\xff\xd8\xff" and body["urls"][0]["screenshot"]["ext"] == "jpg"
    assert "confirmed as phishing by a human reviewer" in body["reason"]
    assert n["payload"]["sent"]["urls"][0]["screenshot"]["bytes"] == len(jpeg)   # audit copy without base64

    d = q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (did,))
    assert d["reported_at"] is not None
    ev = q(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'reported'", (did,))
    assert len(ev) == 1 and ev[0]["detail"]["channel"] == "netcraft" and ev[0]["detail"]["reviewed_by_human"]
    att = q(pg, "SELECT * FROM report_attempts")
    assert len(att) == 1 and att[0]["ok"] is True and att[0]["http_status"] == 200 and att[0]["via"] == "api"

    # idempotent: a second run creates nothing and sends nothing
    out2 = run_report()
    assert not out2.get("planned") and out2["sent"] == 0
    assert len(nc.posts) == 1
    assert q(pg, "SELECT count(*) AS n FROM reports")[0]["n"] == len(CONFIRMED_CHANNELS)


def test_null_columns_unenriched_unfetched_confirmed_domain(pg, nc):
    """No pages, no RDAP/IP data, no AI: reports still plan and Netcraft gets the hostnames seen."""
    did = phish(["westpac-verify.top"], enrich=False, fetch=False, judge=False)
    out = run_report()
    rows = reports(pg, did)
    assert "hosting_abuse" not in rows                    # no IPs, no hosting abuse address
    assert rows["registrar_abuse"]["payload"]["to"] == ""
    assert "RDAP" in rows["registrar_abuse"]["payload"]["to_hint"]
    assert rows["netcraft"]["status"] == "sent" and out["sent"] == 1
    body = nc.posts[0][1]
    assert [u["url"] for u in body["urls"]] == ["https://westpac-verify.top/"]
    assert "screenshot" not in body["urls"][0]
    facts = rows["registrar_abuse"]["payload"]["facts"]
    assert facts["page_id"] is None and facts["ips"] == [] and facts["registered"] is None


def test_unicode_hostname(pg, nc):
    host = "cоmmbank-login.top".encode("idna").decode()           # Cyrillic о
    did = phish([host])
    run_report()
    rows = reports(pg, did)
    assert rows["netcraft"]["status"] == "sent"
    urls = [u["url"] for u in nc.posts[0][1]["urls"]]
    assert urls and all(u.startswith(f"https://{host}/") for u in urls)
    facts = rows["brand:commbank"]["payload"]["facts"]
    assert facts["domain"] == host and facts["displayed_as"] == "cоmmbank-login.top"
    assert host in rows["brand:commbank"]["payload"]["subject"] or host in rows["brand:commbank"]["payload"]["body"]


def test_lookback_and_takedown(pg, nc):
    old = phish(["anz-secure-login.top"])
    arun(_set_status(old, "confirmed", days_ago=40))                  # confirmed 40 days ago: past lookback
    gone = phish(["nab-login-verify.top"])
    q(pg, "UPDATE domains SET takedown_at = now(), takedown_signal = 'nxdomain' WHERE id = %s", (gone,))
    run_report()
    assert reports(pg, old) == {} and reports(pg, gone) == {}

    # queued before the takedown: skipped at send time
    live = phish(["mygov-refund-au.click"])
    q(pg, "UPDATE domains SET takedown_at = NULL WHERE id = %s", (gone,))
    arun(_plan_only(live))
    q(pg, "UPDATE domains SET takedown_at = now(), takedown_signal = 'http_gone' WHERE id = %s", (live,))
    out = run_report()
    n = reports(pg, live)["netcraft"]
    assert n["status"] == "skipped" and "taken down" in n["error"]
    assert out["skipped"] >= 1 and all("mygov" not in json.dumps(b) for _, b in nc.posts)


async def _plan_only(did, trigger="confirmed", by="worker"):
    """Plan one domain without sending (what the /reports "Create reports" button does)."""
    p = await db.pool()
    async with p.connection() as conn:
        d = await (await conn.execute(engine.ONE_DOMAIN_SQL, (did,))).fetchone()
        return await engine.plan_for_domain(conn, load_config(), dict(d), trigger, by=by)


def test_dashboard_create_reports_path(pg, nc):
    """POST /reports/create/{id} runs ONE_DOMAIN_SQL + plan_for_domain; a second call creates nothing."""
    did = phish(["commbank-login-secure.top"])
    created = arun(_plan_only(did, by=REVIEWER))
    assert set(created) == CONFIRMED_CHANNELS
    assert arun(_plan_only(did, by=REVIEWER)) == []
    rows = reports(pg, did)
    assert rows["scamwatch"]["payload"]["created_by"] == REVIEWER
    assert rows["netcraft"]["status"] == "approved" and rows["netcraft"]["next_attempt_at"] is not None


def test_auto_mode(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="auto")
    good = phish(["commbank-login-secure.top"], confirm=False, final=96, confidence=0.93)
    low = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=89)
    unsure = phish(["mygov-refund-au.click"], confirm=False, final=95, confidence=0.5)
    nocreds = phish(["anz-secure-login.top"], confirm=False, final=95, creds=False)
    fp = phish(["nab-login-verify.top"], confirm=False, final=97)
    arun(_set_status(fp, "false_positive"))

    # no sandbox verification yet: nothing automatic
    out = run_report()
    assert out["sandbox_ok"] is False and not out.get("auto_planned")
    assert q(pg, "SELECT count(*) AS n FROM reports")[0]["n"] == 0

    write_sandbox(days_ago=2)
    out = run_report()
    assert out["auto_planned"] == 1 and out["sent"] == 1, out
    rows = reports(pg, good)
    assert set(rows) == {"netcraft"}                                    # automated channels only
    assert rows["netcraft"]["auto"] is True and rows["netcraft"]["status"] == "sent"
    assert rows["netcraft"]["payload"]["trigger"] == "auto"
    body = nc.posts[0][1]
    assert "not yet reviewed by a person" in body["reason"] and "combined score 96/100" in body["reason"]
    for did in (low, unsure, nocreds, fp):
        assert reports(pg, did) == {}
    ev = q1(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'reported'", (good,))
    assert ev["detail"]["reviewed_by_human"] is False

    # a reviewer confirms it later: the email drafts and checklist items follow; Netcraft is not resent
    arun(_set_status(good, "confirmed"))
    run_report()
    assert set(reports(pg, good)) == CONFIRMED_CHANNELS
    assert len(nc.posts) == 1

    # a stale sandbox verification stops automatic sends
    write_sandbox(days_ago=31)
    newer = phish(["westpaс-secure.top".encode("idna").decode()], confirm=False, final=97)
    out = run_report()
    assert out["sandbox_ok"] is False and reports(pg, newer) == {}


def test_auto_rules_rechecked_before_sending(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="auto", REPORT_RATE_PER_HOUR="0")
    write_sandbox()
    did = phish(["commbank-login-secure.top"], confirm=False)
    out = run_report()
    assert out["auto_planned"] == 1 and out["rate_limited"] is True and nc.posts == []
    assert reports(pg, did)["netcraft"]["status"] == "approved"

    # hours later, the newest fetch round no longer asks for credentials (kit removed, or cloaking)
    age_pages(pg, did, hours=2)
    arun(_fetch_round(did, creds=False))
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="10")
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert n["status"] == "skipped" and n["error"].startswith("no longer meets the automatic-report rules")
    assert nc.posts == [] and out["skipped"] == 1
    # skipped auto rows are not revived for unreviewed domains
    run_report()
    assert reports(pg, did)["netcraft"]["status"] == "skipped"


def test_netcraft_429_pauses_channel_and_never_fails(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORT_MAX_ATTEMPTS="1")
    did = phish(["commbank-login-secure.top"])
    nc.replies = [httpx.Response(429, headers={"Retry-After": "120"}, json={"message": "Too many requests"})]
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["retry"] == 1 and out["sent"] == 0
    assert n["status"] == "approved" and n["attempts"] == 1 and "429" in n["error"]
    wait = q1(pg, "SELECT EXTRACT(EPOCH FROM next_attempt_at - now()) AS s FROM reports WHERE id = %s", (n["id"],))
    assert 250 < wait["s"] <= 300                                       # max(back-off 300 s, Retry-After 120 s)
    pause = q1(pg, "SELECT value FROM kv WHERE key = %s", (engine.KV_PAUSE,))["value"]
    until = datetime.fromisoformat(pause["netcraft"])
    assert timedelta(seconds=100) < until - datetime.now(UTC) <= timedelta(seconds=120)
    att = q1(pg, "SELECT * FROM report_attempts")
    assert att["ok"] is False and att["http_status"] == 429

    # due again, but the channel is still paused: it waits, nothing is sent
    q(pg, "UPDATE reports SET next_attempt_at = now() WHERE id = %s", (n["id"],))
    q(pg, "UPDATE report_attempts SET at = at - interval '2 minutes'")
    out = run_report()
    assert out.get("waiting") == 1 and len(nc.posts) == 1
    # pause over: sent
    q(pg, "UPDATE kv SET value = %s WHERE key = %s",
      (Jsonb({"netcraft": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}), engine.KV_PAUSE))
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["sent"] == 1 and n["status"] == "sent" and n["attempts"] == 2 and n["error"] is None


def test_netcraft_5xx_retries_with_backoff_then_fails(pg, nc):
    """Default REPORT_MAX_ATTEMPTS (5): back-off 5 min, 15 min, 1 h, 3 h, then failed."""
    did = phish(["commbank-login-secure.top"])
    expected = [300, 900, 3600, 3 * 3600]
    for i in range(5):
        nc.replies = [httpx.Response(503, text="<html>Service Unavailable</html>")]
        out = run_report()
        n = reports(pg, did)["netcraft"]
        assert n["attempts"] == i + 1
        if i < 4:
            assert n["status"] == "approved" and out["retry"] == 1 and n["error"] == "Netcraft: HTTP 503"
            wait = q1(pg, "SELECT EXTRACT(EPOCH FROM next_attempt_at - now()) AS s FROM reports WHERE id = %s",
                      (n["id"],))["s"]
            assert expected[i] - 60 < wait <= expected[i]
            # not due yet: the next run leaves it alone
            assert run_report()["sent"] == 0 and len(nc.posts) == i + 1
            age_attempts(pg, expected[i] + 1)
        else:
            assert n["status"] == "failed" and out["failed"] == 1
    assert len(nc.posts) == 5
    att = q(pg, "SELECT ok, http_status FROM report_attempts ORDER BY id")
    assert [(a["ok"], a["http_status"]) for a in att] == [(False, 503)] * 5
    assert q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (did,))["reported_at"] is None


def test_netcraft_transport_error_and_missing_uuid_retry(pg, nc):
    did = phish(["commbank-login-secure.top"])
    nc.replies = [httpx.ConnectError("connection refused")]
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["retry"] == 1 and n["status"] == "approved" and n["error"] == "Netcraft: ConnectError"
    age_attempts(pg, 301)
    nc.replies = [httpx.Response(200, json={"message": "ok"})]           # 200 without a uuid
    run_report()
    n = reports(pg, did)["netcraft"]
    assert n["status"] == "approved" and "uuid" in n["error"] and n["attempts"] == 2


def test_netcraft_permanent_4xx_and_all_invalid(pg, nc):
    a = phish(["commbank-login-secure.top"])
    nc.replies = [httpx.Response(400, json={"message": "urls[0].url: invalid", "status": 400})]
    out = run_report()
    n = reports(pg, a)["netcraft"]
    assert out["failed"] == 1 and n["status"] == "failed" and n["error"].startswith("Netcraft: HTTP 400")
    assert n["response"]["http_status"] == 400

    b = phish(["auspost-parcel-redelivery.xyz"])
    age_attempts(pg)
    nc.replies = [httpx.Response(200, json={"message": "ok", "uuid": uuidlib.uuid4().hex,
                                            "invalid_urls": ["https://auspost-parcel-redelivery.xyz/netbank/logon",
                                                             "https://auspost-parcel-redelivery.xyz/"]})]
    run_report()
    n = reports(pg, b)["netcraft"]
    assert n["status"] == "failed" and "invalid" in n["error"]
    assert q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (b,))["reported_at"] is None


def test_netcraft_test_endpoint_then_production(pg, nc, monkeypatch):
    setenv(monkeypatch, NETCRAFT_TEST="true")
    did = phish(["commbank-login-secure.top"])
    ctx = ctx_for()
    out = run_report(ctx)
    n = reports(pg, did)["netcraft"]
    assert out["test"] == 1 and out["sent"] == 0
    assert nc.posts[0][0] == "https://report.netcraft.com/api/v3/test/report/urls"
    assert n["status"] == "skipped" and n["response"]["test"] is True and n["external_id"]
    assert n["error"].startswith("test submission (NETCRAFT_TEST)")
    assert q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (did,))["reported_at"] is None
    assert not q(pg, "SELECT 1 FROM domain_events WHERE kind = 'reported'")

    # never to the test endpoint twice
    age_attempts(pg)
    run_report(ctx)
    assert len(nc.posts) == 1 and reports(pg, did)["netcraft"]["status"] == "skipped"

    # NETCRAFT_TEST removed: revived and sent to production
    setenv(monkeypatch, NETCRAFT_TEST=None)
    out = run_report(ctx)
    n = reports(pg, did)["netcraft"]
    assert out["planned"] == 1 and out["sent"] == 1
    assert nc.posts[1][0] == "https://report.netcraft.com/api/v3/report/urls"
    assert n["status"] == "sent" and n["response"]["test"] is False and n["attempts"] == 1
    assert q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (did,))["reported_at"] is not None


def test_netcraft_test_mode_auto_domain_revived(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="auto", NETCRAFT_TEST="true")
    write_sandbox()
    did = phish(["commbank-login-secure.top"], confirm=False)
    assert run_report()["test"] == 1
    age_attempts(pg)
    setenv(monkeypatch, NETCRAFT_TEST=None)
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["auto_planned"] == 1 and out["sent"] == 1 and n["status"] == "sent" and n["auto"] is True


def test_legacy_test_sends_released_by_housekeeping(pg, nc, monkeypatch):
    """Older versions recorded test submissions as 'sent' and set reported_at: housekeeping fixes both."""
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="0")      # first look at the release itself, before any send
    did = phish(["commbank-login-secure.top"])
    keep = phish(["auspost-parcel-redelivery.xyz"])
    q(pg, "INSERT INTO reports (domain_id, channel, status, auto, kind, payload, sent_at, response, external_id) "
          "VALUES (%s, 'netcraft', 'sent', false, 'api', '{}', now() - interval '1 day', %s, %s)",
      (did, Jsonb({"test": True, "uuid": "ab" * 16}), "ab" * 16))
    q(pg, "INSERT INTO reports (domain_id, channel, status, auto, kind, payload, sent_at, response, external_id) "
          "VALUES (%s, 'netcraft', 'sent', false, 'api', '{}', now() - interval '1 day', %s, %s), "
          "(%s, 'registrar_abuse', 'sent', false, 'email', '{}', now(), NULL, NULL)",
      (keep, Jsonb({"test": True, "uuid": "cd" * 16}), "cd" * 16, keep))
    q(pg, "UPDATE domains SET reported_at = now() - interval '1 day'")
    q(pg, "INSERT INTO report_attempts (report_id, channel, via, at, ok) "
          "SELECT id, channel, 'api', now() - interval '200 days', true FROM reports WHERE channel = 'netcraft'")
    ctx = ctx_for()
    out = run_report(ctx)
    assert out["test_released"] == 2 and out["rate_limited"] is True
    assert q(pg, "SELECT count(*) AS n FROM report_attempts WHERE at < now() - interval '180 days'")[0]["n"] == 0
    rows, rows2 = reports(pg, did), reports(pg, keep)
    # released (skipped test rows), then queued again for production by planning in the same run
    for r in (rows["netcraft"], rows2["netcraft"]):
        assert r["status"] == "approved" and r["attempts"] == 0 and r["error"] is None
        assert r["response"]["test"] is True                          # the test submission stays on record
    d = {r["id"]: r for r in q(pg, "SELECT id, reported_at FROM domains")}
    assert d[did]["reported_at"] is None                              # only a test submission: not reported
    assert d[keep]["reported_at"] is not None                         # a real (manual) send exists
    # housekeeping does not run again within HOUSEKEEP_EVERY_S; the production send sets reported_at
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="10")
    ctx = ctx_for(state=ctx.state)                                    # new settings, same job state
    out = run_report(ctx)
    assert "test_released" not in out and out["sent"] == 1
    age_attempts(pg)
    assert run_report(ctx)["sent"] == 1
    assert {reports(pg, x)["netcraft"]["status"] for x in (did, keep)} == {"sent"}
    assert reports(pg, did)["netcraft"]["response"]["test"] is False
    assert q1(pg, "SELECT reported_at FROM domains WHERE id = %s", (did,))["reported_at"] is not None


def test_status_polling(pg, nc):
    did = phish(["commbank-login-secure.top"])
    run_report()
    n = reports(pg, did)["netcraft"]
    uid = n["external_id"]
    nc.status[uid] = ({"state": "processing", "is_archived": False},
                      {"urls": [{"url": "https://commbank-login-secure.top/netbank/logon", "url_state": "processing",
                                 "url_takedown_state": "not_started", "country_code": "LT"}]})
    # polled in the same run as the send (checked_at NULL), not again for 6 hours
    assert n["checked_at"] is not None and n["response"]["status"]["state"] == "processing"
    assert n["response"]["status"]["final"] is False and len(n["response"]["status_history"]) == 1
    assert n["response"]["uuid"] == uid and n["response"]["message"]     # merged, not replaced
    assert len(nc.gets) == 2
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    out = run_report()
    assert out["polled"] == 1
    n = reports(pg, did)["netcraft"]
    assert len(n["response"]["status_history"]) == 2                   # the URL list appeared
    assert n["response"]["status"]["urls"][0]["country_code"] == "LT"

    # not due again for 6 hours
    gets = len(nc.gets)
    run_report()
    assert len(nc.gets) == gets
    # state changed
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    nc.status[uid] = ({"state": "malicious", "is_archived": False},
                      {"urls": [{"url": "https://commbank-login-secure.top/netbank/logon", "url_state": "malicious",
                                 "url_takedown_state": "in_progress"}]})
    run_report()
    hist = reports(pg, did)["netcraft"]["response"]["status_history"]
    assert [h["state"] for h in hist] == ["processing", "processing", "malicious"]
    assert hist[-1]["urls"][0]["url_takedown_state"] == "in_progress"
    # same state again: no new history entry
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    run_report()
    assert len(reports(pg, did)["netcraft"]["response"]["status_history"]) == 3
    # a transient error is noted, the state is kept
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    nc.status[uid] = 502
    assert not run_report().get("polled")
    resp = reports(pg, did)["netcraft"]["response"]
    assert "status_error" in resp and resp["status"]["state"] == "malicious"
    # archived (404): final, never polled again
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    nc.status[uid] = 404
    run_report()
    assert reports(pg, did)["netcraft"]["response"]["status"]["final"] is True
    q(pg, "UPDATE reports SET checked_at = now() - interval '7 hours' WHERE id = %s", (n["id"],))
    gets = len(nc.gets)
    run_report()
    assert len(nc.gets) == gets


def test_rate_limit_counted_from_report_attempts(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="2", REPORT_CHANNEL_MIN_INTERVAL_S="30")
    ids = [phish([h]) for h in ("commbank-login-secure.top", "auspost-parcel-redelivery.xyz", "mygov-refund-au.click")]
    out = run_report()
    assert out["sent"] == 1 and out["waiting"] == 2                    # per-channel interval
    age_attempts(pg, 31)
    out = run_report()
    assert out["sent"] == 1
    age_attempts(pg, 31)
    out = run_report()
    assert out["sent"] == 0 and out["rate_limited"] is True           # 2 attempts in the last hour
    assert sum(r["status"] == "sent" for d in ids for r in [reports(pg, d)["netcraft"]]) == 2
    # failed attempts count too: an hour later one old attempt is replaced by a failure
    age_attempts(pg, 3600)
    nc.replies = [httpx.Response(500, text="oops")]
    out = run_report()
    assert out["retry"] == 1
    age_attempts(pg, 31)
    q(pg, "UPDATE reports SET next_attempt_at = now() WHERE status = 'approved'")
    out = run_report()
    assert out["sent"] == 1                                            # 1 failure + 1 send = 2 in the hour
    age_attempts(pg, 31)
    assert run_report()["rate_limited"] is True


def test_crash_recovery_of_sending_rows(pg, nc):
    did = phish(["commbank-login-secure.top"])
    nc.replies = [asyncio.CancelledError()]           # the worker is killed while the request is in flight
    with pytest.raises(asyncio.CancelledError):
        run_report()
    n = reports(pg, did)["netcraft"]
    assert n["status"] == "sending" and n["attempts"] == 1
    att = q1(pg, "SELECT * FROM report_attempts")
    assert att["ok"] is None

    # within 15 minutes it is left alone (the worker may still be sending)
    out = run_report()
    assert not out.get("recovered") and reports(pg, did)["netcraft"]["status"] == "sending"
    q(pg, "UPDATE reports SET last_attempt_at = now() - interval '16 minutes'")
    q(pg, "UPDATE report_attempts SET at = now() - interval '16 minutes'")
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["recovered"] == 1 and n["status"] == "failed" and "outcome is unknown" in n["error"]
    att = q1(pg, "SELECT * FROM report_attempts")
    assert att["ok"] is False and att["error"] == "interrupted (outcome unknown)"
    run_report()
    assert len(nc.posts) == 1                                           # never re-sent automatically


def test_false_positive_skips_pending_and_queued(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="0")
    did = phish(["commbank-login-secure.top"])
    run_report()
    q(pg, REJECT_SQL, (REVIEWER, "not applicable", reports(pg, did)["scamwatch"]["id"]))
    q(pg, "UPDATE reports SET status = 'sent', sent_via = 'manual', sent_by = %s, sent_at = now() "
          "WHERE domain_id = %s AND channel = 'google_safe_browsing'", (REVIEWER, did))
    arun(_set_status(did, "false_positive"))
    out = run_report()
    rows = reports(pg, did)
    assert out["cancelled"] == len(CONFIRMED_CHANNELS) - 2
    for ch, r in rows.items():
        if ch == "scamwatch":
            assert r["status"] == "rejected"
        elif ch == "google_safe_browsing":
            assert r["status"] == "sent"
        else:
            assert r["status"] == "skipped" and r["error"] == "domain marked false_positive by a reviewer; not sent"
    # confirmed again later: skipped rows are not revived for email/manual, nothing is duplicated
    arun(_set_status(did, "confirmed"))
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="10")
    out = run_report()
    rows = reports(pg, did)
    assert len(rows) == len(CONFIRMED_CHANNELS)
    assert rows["registrar_abuse"]["status"] == "skipped"
    assert rows["netcraft"]["status"] == "sent"                       # api rows are revived when confirmed again


def test_benign_queued_item_skipped_at_send_time(pg, nc):
    """Status flips between planning and the send loop: precheck skips it."""
    did = phish(["commbank-login-secure.top"])
    arun(_plan_only(did))
    q(pg, "UPDATE domains SET status = 'open' WHERE id = %s", (did,))
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert n["status"] == "skipped" and n["error"] == "the domain is no longer confirmed by a reviewer"
    assert out["skipped"] == 1 and nc.posts == []


def test_netcraft_not_configured_is_held(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTER_EMAIL=None)
    did = phish(["commbank-login-secure.top"])
    arun(_plan_only(did))                       # created on demand while Netcraft is not ready
    q(pg, "INSERT INTO reports (domain_id, channel, status, auto, kind, payload, next_attempt_at) "
          "VALUES (%s, 'netcraft', 'approved', false, 'api', '{}', now())", (did,))
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["held"] == 1 and n["status"] == "approved" and n["error"].startswith("waiting: Netcraft needs")
    wait = q1(pg, "SELECT EXTRACT(EPOCH FROM next_attempt_at - now()) AS s FROM reports WHERE id = %s", (n["id"],))
    assert 800 < wait["s"] <= 900
    assert nc.posts == []


def test_concurrent_send_runs_claim_once(pg, nc):
    did = phish(["commbank-login-secure.top"])
    arun(_plan_only(did))
    cfg = load_config()
    sandbox = engine.current_sandbox(cfg)

    async def both():
        clients = [netcraft.new_client(), netcraft.new_client()]
        try:
            return await asyncio.gather(*(engine.send_due(cfg, sandbox, c) for c in clients))
        finally:
            for c in clients:
                await c.aclose()
    results = arun(both())
    assert sum(r["sent"] for r in results) == 1 and len(nc.posts) == 1
    assert reports(pg, did)["netcraft"]["attempts"] == 1


def test_advisory_lock_held_elsewhere_blocks_claims(pg, nc):
    did = phish(["commbank-login-secure.top"])
    arun(_plan_only(did))
    with psycopg.connect(pg) as other:                 # another worker inside claim_next
        other.execute("SELECT pg_advisory_xact_lock(%s)", (engine.LOCK_KEY,))
        out = run_report()
        assert out["sent"] == 0 and nc.posts == []
        other.rollback()
    assert run_report()["sent"] == 1


# ---- email: AI drafts and SMTP -------------------------------------------------------------------

def test_ai_drafts_replace_templates(pg, nc, claude, monkeypatch):
    setenv(monkeypatch, REPORT_AI_DRAFTS_PER_RUN="2")
    did = phish(["commbank-login-secure.top"])
    out = run_report()
    assert out["ai_drafts"] == 2
    rows = reports(pg, did)
    emails = {ch: r for ch, r in rows.items() if r["kind"] == "email"}
    used = [r for r in emails.values() if r["payload"]["ai"] == "used"]
    pending = [r for r in emails.values() if r["payload"]["ai"] == "pending"]
    assert len(used) == 2 and len(pending) == 1
    for r in used:
        p = r["payload"]
        assert p["ai_body"].startswith("The website commbank-login-secure.top appears to impersonate")
        assert p["ai_body"] in p["body"] and p["body"] != p["template_body"]
        assert "CyberCheck IT" in p["body"]                              # own signature appended
    calls = q(pg, "SELECT * FROM ai_calls ORDER BY id")
    assert len(calls) == 2 and all(c["purpose"] == "report_draft" and c["status"] == "ok" for c in calls)
    assert all(c["domain_id"] == did and c["input_tokens"] == 1840 and c["output_tokens"] == 310 for c in calls)
    assert all(float(c["cost_usd"]) > 0 for c in calls)
    assert {c["result"]["channel"] for c in calls} == {r["channel"] for r in used}

    # the reviewer edits the remaining draft before the next run: the AI never overwrites it
    left = pending[0]
    q(pg, "UPDATE reports SET payload = payload || %s WHERE id = %s",
      (Jsonb({"body": "edited by the reviewer", "ai": "edited"}), left["id"]))
    run_report()
    assert len(claude.requests) == 2
    assert reports(pg, did)[left["channel"]]["payload"]["body"] == "edited by the reviewer"


def test_ai_draft_naming_unknown_address_keeps_template(pg, nc, claude):
    did = phish(["commbank-login-secure.top"])
    claude.bad_for.add("commbank-login-secure.top")
    run_report()
    emails = [r for r in reports(pg, did).values() if r["kind"] == "email"]
    assert emails and all(r["payload"]["ai"] == "unavailable" for r in emails)
    assert all(r["payload"]["body"] == r["payload"]["template_body"] for r in emails)
    statuses = {c["status"] for c in q(pg, "SELECT status FROM ai_calls")}
    assert statuses == {"invalid"}


def test_smtp_sends_approved_drafts(pg, nc, smtp):
    did = phish(["commbank-login-secure.top"])
    run_report()
    rows = reports(pg, did)
    brand = rows["brand:commbank"]
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({"subject": brand["payload"]["subject"]}), brand["id"]))
    out = run_report()
    assert out["sent"] == 1
    r = reports(pg, did)["brand:commbank"]
    assert r["status"] == "sent" and r["sent_via"] == "smtp" and r["external_id"].startswith("<")
    assert r["response"] == {"smtp": "accepted"} and r["payload"]["sent"]["attachment"] is True
    sess = smtp.sessions[-1]
    assert sess.host == "smtp.mail-provider.example" and sess.port == 587 and sess.tls and sess.logged_in == "reports"
    msg = sess.messages[0]
    assert msg["To"] == brand["payload"]["to"] and msg["From"] == REPORTER and msg["Subject"]
    atts = list(msg.iter_attachments())
    assert len(atts) == 1 and atts[0].get_content_type() == "image/jpeg"
    assert atts[0].get_content()[:3] == b"\xff\xd8\xff"
    ev = q(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'reported' ORDER BY id", (did,))
    assert [e["detail"]["channel"] for e in ev] == ["netcraft", "brand:commbank"]
    att = q(pg, "SELECT via, ok FROM report_attempts WHERE channel = 'brand:commbank'")
    assert att == [{"via": "smtp", "ok": True}]


def test_smtp_failures(pg, nc, smtp, monkeypatch):
    setenv(monkeypatch, REPORT_MAX_ATTEMPTS="5")
    did = phish(["commbank-login-secure.top"])
    run_report()
    rows = reports(pg, did)
    # login failure: permanent
    smtp.fail_login = smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({}), rows["registrar_abuse"]["id"]))
    run_report()
    r = reports(pg, did)["registrar_abuse"]
    assert r["status"] == "failed" and "SMTP login failed" in r["error"]
    # temporary 4xx: retried later
    smtp.fail_login = None
    smtp.fail_send = smtplib.SMTPDataError(451, b"4.7.1 Try again later")
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({}), rows["hosting_abuse"]["id"]))
    run_report()
    r = reports(pg, did)["hosting_abuse"]
    assert r["status"] == "approved" and r["attempts"] == 1 and r["error"].startswith("SMTP 451")
    # no STARTTLS: never sent in clear text
    smtp.fail_send = None
    smtp.starttls_offered = False
    age_attempts(pg, 301)
    run_report()
    r = reports(pg, did)["hosting_abuse"]
    assert r["status"] == "failed" and "STARTTLS" in r["error"]
    assert all(not s.messages for s in smtp.sessions)


def test_email_to_flagged_contact_skipped_and_smtp_off_held(pg, nc, monkeypatch):
    # the registrar abuse address is on another domain CyberCheck tracks as suspicious
    did = phish(["commbank-login-secure.top"])
    phish(["auspost-parcel-redelivery.xyz"], confirm=False)          # open: tracked as suspicious
    run_report()
    r = reports(pg, did)["registrar_abuse"]
    # a reviewer typed the attacker's address in by hand and approved it (Approve refuses this; the worker too)
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({"to": "abuse@auspost-parcel-redelivery.xyz"}), r["id"]))
    # SMTP off: held, not sent
    out = run_report()
    r = reports(pg, did)["registrar_abuse"]
    assert out["held"] == 1 and r["status"] == "approved" and r["error"].startswith("waiting: SMTP is off")
    # SMTP on: skipped at send time
    FakeSMTP.sessions = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    setenv(monkeypatch, SMTP_HOST="smtp.mail-provider.example", SMTP_PORT="465", SMTP_USER="u",
           SMTP_PASSWORD="p", SMTP_FROM=REPORTER)
    q(pg, "UPDATE reports SET next_attempt_at = now() WHERE id = %s", (r["id"],))
    out = run_report()
    r = reports(pg, did)["registrar_abuse"]
    assert r["status"] == "skipped" and "tracks as suspicious" in r["error"] and FakeSMTP.sessions == []
    # contact_problem, as the dashboard's Approve uses it
    async def check():
        p = await db.pool()
        async with p.connection() as conn:
            d = dict(await (await conn.execute(engine.ONE_DOMAIN_SQL, (did,))).fetchone())
            return (await engine.contact_problem(conn, "abuse@mail.auspost-parcel-redelivery.xyz", d),
                    await engine.contact_problem(conn, "abuse@commbank-login-secure.top", d),
                    await engine.contact_problem(conn, "abuse@namesilo.com", d))
    flagged, own, fine = arun(check())
    assert "tracks as suspicious" in flagged and "reported domain itself" in own and fine == ""


def test_mark_domain_reported_manual(pg):
    did = phish(["commbank-login-secure.top"], judge=False)

    async def mark():
        p = await db.pool()
        async with p.connection() as conn:
            await engine.mark_domain_reported(conn, did, {"channel": "scamwatch", "via": "manual", "by": REVIEWER,
                                                          "at": datetime.now(UTC)})
            first = (await (await conn.execute("SELECT reported_at FROM domains WHERE id = %s", (did,))).fetchone())
            await engine.mark_domain_reported(conn, did, {"channel": "google_safe_browsing", "via": "manual"})
            second = (await (await conn.execute("SELECT reported_at FROM domains WHERE id = %s", (did,))).fetchone())
            return first["reported_at"], second["reported_at"]
    a, b = arun(mark())
    assert a is not None and a == b                                    # first report time kept
    assert len(q(pg, "SELECT 1 FROM domain_events WHERE kind = 'reported'")) == 2


def test_shared_platform_and_hacked_site_urls(pg, nc):
    """Only lookalike hostnames are reported: never weebly.com itself, never the hacked business's own site."""
    plat = phish(["commbank-login.weebly.com"])
    q(pg, "UPDATE domains SET registrar_abuse_email = 'abuse@weebly.com', hosting_abuse_email = 'abuse@weebly.com' "
          "WHERE id = %s", (plat,))
    hacked = phish(["netbank-login.someplumber.com.au"], final_url="https://someplumber.com.au/")   # cloaks home
    run_report()
    age_attempts(pg)
    run_report()
    urls = {b["urls"][0]["url"].split("/")[2]: [u["url"] for u in b["urls"]] for _, b in nc.posts}
    assert set(urls) == {"commbank-login.weebly.com", "netbank-login.someplumber.com.au"}
    assert all(u.startswith("https://commbank-login.weebly.com/") for u in urls["commbank-login.weebly.com"])
    assert urls["netbank-login.someplumber.com.au"] == ["https://netbank-login.someplumber.com.au/"]
    rows = reports(pg, plat)
    assert rows["registrar_abuse"]["payload"]["to"] == "abuse@weebly.com"     # the platform's own abuse desk
    h = reports(pg, hacked)
    assert "auda_dns_abuse" in h and h["registrar_abuse"]["payload"]["to"] == ""   # .au: looked up by hand
    assert "whois.auda.org.au" in h["registrar_abuse"]["payload"]["to_hint"]


def test_cloudflare_au_and_brand_specific_channels(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORT_MANUAL_CHANNELS="scamwatch,cloudflare_abuse_form,auda_dns_abuse,brand_form")
    cf = phish(["netbank-commbank.com.au"])
    q(pg, "UPDATE domains SET asn = 13335, as_name = 'CLOUDFLARENET', hosting_abuse_email = 'abuse@cloudflare.com' "
          "WHERE id = %s", (cf,))
    post = phish(["auspost-tracking-help.top"])
    linkt = phish(["linkt-toll-pay.top"])
    run_report()
    assert set(reports(pg, cf)) == {"netcraft", "registrar_abuse", "brand:commbank", "scamwatch",
                                    "cloudflare_abuse_form", "auda_dns_abuse"}
    p = reports(pg, post)["brand:auspost"]["payload"]
    assert p["to"] == "scams@auspost.com.au" and p["attach_screenshot"] is False
    assert p["facts"]["screenshot"] is False and "screenshot" not in p["body"].lower()
    lk = reports(pg, linkt)
    assert "brand_form:linkt" in lk and lk["brand_form:linkt"]["kind"] == "manual"
    assert lk["brand_form:linkt"]["payload"]["screenshot"] is True


def test_official_and_gov_au_domains_never_reported(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="auto")
    write_sandbox()
    off = phish(["commbank-login-secure.top"])                        # a reviewer confirmed it by mistake
    q(pg, "UPDATE domains SET registered_domain = 'commbank.com.au', hostnames = '{www.commbank.com.au}' "
          "WHERE id = %s", (off,))
    gov = phish(["mygov-refund-au.click"], confirm=False, final=97)
    q(pg, "UPDATE domains SET registered_domain = 'mygov-refund.nsw.gov.au', hostnames = '{mygov-refund.nsw.gov.au}' "
          "WHERE id = %s", (gov,))
    q(pg, "UPDATE pages SET url = 'https://mygov-refund.nsw.gov.au/', final_url = 'https://mygov-refund.nsw.gov.au/l' "
          "WHERE domain_id = %s", (gov,))
    out = run_report()
    assert reports(pg, off) == {} and reports(pg, gov) == {} and nc.posts == []
    assert not out.get("planned") and not out.get("auto_planned")


def test_score_floor_whatever_the_setting(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="auto", AUTO_REPORT_MIN_FINAL_SCORE="9")      # typo for 90
    write_sandbox()
    a = phish(["commbank-login-secure.top"], confirm=False, final=89)
    b = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=90)
    out = run_report()
    assert out["auto_planned"] == 1 and reports(pg, a) == {} and set(reports(pg, b)) == {"netcraft"}
    setenv(monkeypatch, AUTO_REPORT_MIN_FINAL_SCORE="101")                         # turns automatic sends off
    c = phish(["mygov-refund-au.click"], confirm=False, final=100)
    assert not run_report().get("auto_planned") and reports(pg, c) == {}


def test_bad_mode_is_review(pg, nc, monkeypatch):
    setenv(monkeypatch, REPORTING_MODE="automatic")
    write_sandbox()
    a = phish(["commbank-login-secure.top"], confirm=False)
    b = phish(["auspost-parcel-redelivery.xyz"])
    out = run_report()
    assert out["mode"] == "review" and reports(pg, a) == {} and "netcraft" in reports(pg, b)


def test_smtp_ssl_port_465(pg, nc, smtp, monkeypatch):
    setenv(monkeypatch, SMTP_PORT="465")
    did = phish(["auspost-tracking-help.top"])
    run_report()
    r = reports(pg, did)["brand:auspost"]
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({"body": r["payload"]["body"] + "\n\nEdited by the reviewer."}), r["id"]))
    run_report()
    r = reports(pg, did)["brand:auspost"]
    assert r["status"] == "sent" and r["payload"]["sent"]["attachment"] is False   # Australia Post: none
    sess = smtp.sessions[-1]
    assert sess.port == 465 and sess.tls
    msg = sess.messages[0]
    assert msg["To"] == "scams@auspost.com.au" and not list(msg.iter_attachments())
    assert "Edited by the reviewer." in msg.get_content()


def test_many_confirmed_domains_one_run(pg, nc, monkeypatch):
    """CONFIRMED_SQL with several domains; new ones (no reports yet) are planned first."""
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="0")
    hosts = ["commbank-login-secure.top", "auspost-parcel-redelivery.xyz", "mygov-refund-au.click",
             "anz-secure-login.top", "westpac-verify.top", "nab-login-verify.top", "linkt-toll-pay.top"]
    ids = [phish([h], fetch=False, judge=False) for h in hosts]
    out = run_report()
    assert out["planned"] > len(ids) and out["rate_limited"] is True
    assert all("netcraft" in reports(pg, d) for d in ids)
    assert q1(pg, "SELECT count(DISTINCT domain_id) AS n FROM reports")["n"] == len(ids)


# =====================================================================================================
# blocklist job
# =====================================================================================================

def run_blocklist(ctx) -> dict:
    return arun(blocklist_job.run_once(ctx))


def bl_dir():
    return config.settings().data_dir / "blocklist"


def read(name):
    return (bl_dir() / name).read_text(encoding="utf-8")


def body_lines(name, prefix="#"):
    return [line for line in read(name).splitlines() if line and not line.startswith(prefix)]


def test_blocklist_empty_first_build(pg):
    ctx = ctx_for()
    out = run_blocklist(ctx)
    assert out["rebuilt"] is True and out["trigger"] == "first build" and out["listed"] == 0
    assert out["files_written"] is True and blocklist.files_present(bl_dir())
    assert body_lines("domains.txt") == []
    meta = json.loads(read("blocklist.json"))
    assert meta["count"] == 0 and meta["entries"] == []
    out = run_blocklist(ctx)
    assert out["rebuilt"] is False


def test_blocklist_scope_wildcard_vs_hostnames(pg, monkeypatch):
    setenv(monkeypatch, BLOCKLIST_HOMEPAGE="https://cybercheck.example/blocklist", BLOCKLIST_DAYS="90")
    whole = phish(["commbank-login-secure.top", "www.commbank-login-secure.top", "netbank.commbank-login-secure.top"])
    auto = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=95)
    platform = phish(["commbank-login.weebly.com"])
    hacked = phish(["netbank-login.someplumber.com.au"])
    old = phish(["mygov-refund-au.click", "www.mygov-refund-au.click", "login.mygov-refund-au.click"],
                confirm=False, final=95)
    q(pg, "UPDATE domains SET registered_at = first_seen - interval '3 years' WHERE id = %s", (old,))
    idn_host = "аuspost-parcel.top".encode("idna").decode()
    idn = phish([idn_host])

    ctx = ctx_for()
    out = run_blocklist(ctx)
    assert out["rebuilt"] is True and out["listed"] == 6, out
    assert out["confirmed"] == 4 and out["automated"] == 2 and out["hostnames_only"] == 3

    domains = body_lines("domains.txt")
    assert "commbank-login-secure.top" in domains and "auspost-parcel-redelivery.xyz" in domains
    assert idn_host in domains
    assert "commbank-login.weebly.com" in domains and "weebly.com" not in domains
    assert "netbank-login.someplumber.com.au" in domains and "someplumber.com.au" not in domains
    assert "mygov-refund-au.click" not in domains
    assert {"login.mygov-refund-au.click"} <= set(domains) and "www.mygov-refund-au.click" not in domains
    hosts = body_lines("hosts.txt")
    assert "0.0.0.0 www.commbank-login-secure.top" in hosts and "0.0.0.0 commbank-login-secure.top" in hosts
    assert "||commbank-login-secure.top^" in body_lines("adguard.txt", "!")
    assert "address=/commbank-login.weebly.com/0.0.0.0" in body_lines("dnsmasq.conf")
    assert '  local-zone: "commbank-login-secure.top." always_nxdomain' in read("unbound.conf")
    rpz = read("rpz.zone")
    assert "*.commbank-login-secure.top CNAME ." in rpz and "Homepage: https://cybercheck.example/blocklist" in rpz
    serial = out["serial"]
    assert f"( {serial} 3600" in rpz
    meta = json.loads(read("blocklist.json"))
    scopes = {e["domain"]: e for e in meta["entries"]}
    assert scopes["commbank-login.weebly.com"]["scope"] == "hostname"
    assert scopes["commbank-login.weebly.com"]["registered_domain"] == "weebly.com"
    assert scopes["auspost-parcel-redelivery.xyz"]["reason"].startswith("automated detection, combined confidence 95")
    assert blocklist.hostname_only_entries(bl_dir())["mygov-refund-au.click"] == ["login.mygov-refund-au.click"]

    rows = {r["id"]: r for r in q(pg, "SELECT * FROM domains")}
    for did in (whole, auto, platform, hacked, old, idn):
        r = rows[did]
        assert r["blocklisted"] and r["blocklist_listed_at"] is not None
        assert r["blocklist_expires_at"] - r["blocklist_listed_at"] >= timedelta(days=90)
    ev = {e["domain_id"]: e["detail"] for e in q(pg, "SELECT * FROM domain_events WHERE kind = 'blocklisted'")}
    assert ev[platform]["scope"] == "hostnames" and ev[platform]["scope_note"] == "shared hosting platform"
    assert "registered" in ev[old]["scope_note"] and ev[whole]["scope"] == "domain"

    # nothing changed: no new files, same serial
    q(pg, "DELETE FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))
    blocklist_state = q1(pg, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,))["value"]
    q(pg, "UPDATE kv SET value = value || %s WHERE key = %s",
      (Jsonb({"built_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat()}), blocklist.KV_STATE))
    out = run_blocklist(ctx)
    assert out["rebuilt"] is True and out["trigger"] == "scheduled" and out["files_written"] is False
    assert out["serial"] == serial == blocklist_state["serial"]

    # a reviewer confirms the old domain: now blocked whole
    arun(_set_status(old, "confirmed"))
    out = run_blocklist(ctx)
    assert out["trigger"] == "review change" and out["files_written"] is True and out["serial"] == serial + 1
    assert "mygov-refund-au.click" in body_lines("domains.txt")


def test_blocklist_exclusions_never_and_czds_hold(pg, monkeypatch):
    fp = phish(["commbank-login-secure.top"], confirm=False, final=97)
    arun(_set_status(fp, "false_positive"))
    benign = phish(["anz-secure-login.top"])
    arun(_set_status(benign, "benign"))
    excluded = phish(["westpac-verify.top"])
    q(pg, "UPDATE domains SET blocklist_excluded = true, blocklist_excluded_at = now(), blocklist_excluded_by = %s "
          "WHERE id = %s", (REVIEWER, excluded))
    low = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=89)
    noai = phish(["mygov-refund-au.click"], confirm=False, final=95, confidence=0.5)
    czds = phish(["nab-login-verify.top"], source="czds")
    gov = phish(["linkt-toll-pay.top"])
    q(pg, "UPDATE domains SET registered_domain = 'linkt-toll.nsw.gov.au', tld = 'gov.au' WHERE id = %s", (gov,))
    ctx = ctx_for()
    out = run_blocklist(ctx)
    assert out["listed"] == 0 and out["held_czds"] == 1, out
    assert not q(pg, "SELECT id FROM domains WHERE blocklisted")

    # CZDS terms accepted: listed
    setenv(monkeypatch, BLOCKLIST_CZDS_TERMS_OK="yes")
    arun(_request())
    out = run_blocklist(ctx)
    assert out["trigger"] == "requested" and out["listed"] == 1 and out["held_czds"] == 0
    assert body_lines("domains.txt") == ["nab-login-verify.top"]
    setenv(monkeypatch, BLOCKLIST_CZDS_TERMS_OK=None)
    # a CT certificate releases it from the hold too
    arun(_store(["login.nab-login-verify.top"]))
    assert q1(pg, "SELECT source FROM domains WHERE id = %s", (czds,))["source"] == "ct"
    arun(_request())
    out = run_blocklist(ctx)
    assert out["listed"] == 1 and out["held_czds"] == 0

    # excluded after listing: removed, with an event
    q(pg, "UPDATE domains SET blocklist_excluded = true WHERE id = %s", (czds,))
    arun(_event(czds, "blocklist_excluded"))
    out = run_blocklist(ctx)
    assert out["trigger"] == "review change" and out["removed"] == 1 and out["listed"] == 0
    r = q1(pg, "SELECT blocklisted, blocklist_expires_at FROM domains WHERE id = %s", (czds,))
    assert r["blocklisted"] is False and r["blocklist_expires_at"] is None
    ev = q1(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'unblocklisted'", (czds,))
    assert ev["detail"]["reason"] == "excluded by a reviewer"
    assert body_lines("domains.txt") == []
    reasons = {r["id"]: blocklist.skip_reason(r, blocklist.BuildConfig.from_env(), watchlist())
               for r in q(pg, "SELECT * FROM domains")}
    assert reasons[fp] == "marked false positive" and reasons[benign] == "marked benign"
    assert reasons[excluded] == "excluded by a reviewer" and reasons[low] == "combined score below 90"
    assert reasons[noai] == "no AI phishing verdict" and reasons[gov] == "government domain"


async def _request(reason="test", by=REVIEWER):
    p = await db.pool()
    async with p.connection() as conn:
        await blocklist.request_rebuild(conn, reason, by)


async def _event(did, kind):
    p = await db.pool()
    async with p.connection() as conn:
        await db.add_event(conn, did, kind, {"by": REVIEWER})


def test_blocklist_expiry_and_relisting(pg, monkeypatch):
    setenv(monkeypatch, BLOCKLIST_DAYS="30")
    did = phish(["commbank-login-secure.top"])
    ctx = ctx_for()
    out = run_blocklist(ctx)
    assert out["listed"] == 1
    r = q1(pg, "SELECT * FROM domains WHERE id = %s", (did,))
    # listed today, live today: BLOCKLIST_DAYS from the listing
    assert r["blocklist_expires_at"] == r["blocklist_listed_at"] + timedelta(days=30)

    # 40 days later, nobody saw it live since: expired, removed, past expiry kept
    q(pg, "UPDATE domains SET blocklist_listed_at = blocklist_listed_at - interval '40 days', "
          "last_live_at = last_live_at - interval '40 days', first_live_at = first_live_at - interval '40 days', "
          "status_changed_at = status_changed_at - interval '40 days' WHERE id = %s", (did,))
    arun(_request())
    out = run_blocklist(ctx)
    assert out["removed"] == 1 and out["listed"] == 0
    r = q1(pg, "SELECT * FROM domains WHERE id = %s", (did,))
    assert r["blocklisted"] is False and r["blocklist_expires_at"] < datetime.now(UTC)
    ev = q1(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'unblocklisted'", (did,))
    assert ev["detail"]["reason"] == "expired"

    # not re-added while nothing new happens
    arun(_request())
    assert run_blocklist(ctx)["listed"] == 0
    # seen live again by the fetcher: listed again with a fresh listing date
    arun(_fetch_round(did))
    arun(_request())
    out = run_blocklist(ctx)
    assert out["listed"] == 1 and out["added"] == 1
    r = q1(pg, "SELECT * FROM domains WHERE id = %s", (did,))
    assert r["blocklisted"] and r["blocklist_listed_at"] > datetime.now(UTC) - timedelta(minutes=5)

    # expired again; then a reviewer confirms it again after the expiry: listed again
    q(pg, "UPDATE domains SET blocklist_listed_at = blocklist_listed_at - interval '40 days', "
          "last_live_at = last_live_at - interval '40 days', status_changed_at = status_changed_at - interval '41 days' "
          "WHERE id = %s", (did,))
    arun(_request())
    assert run_blocklist(ctx)["removed"] == 1
    arun(_request())
    assert run_blocklist(ctx)["listed"] == 0
    arun(_set_status(did, "confirmed"))
    out = run_blocklist(ctx)
    assert out["trigger"] == "review change" and out["added"] == 1
    r = q1(pg, "SELECT * FROM domains WHERE id = %s", (did,))
    assert r["blocklisted"] and r["blocklist_expires_at"] >= r["blocklist_listed_at"] + timedelta(days=30)

    # still listed and seen live later: expiry moves forward (updated, not re-added)
    first_exp = r["blocklist_expires_at"]
    q(pg, "UPDATE domains SET last_live_at = now() + interval '3 days' WHERE id = %s", (did,))
    arun(_request())
    out = run_blocklist(ctx)
    assert out["added"] == 0 and out["listed"] == 1
    assert q1(pg, "SELECT blocklist_expires_at FROM domains WHERE id = %s", (did,))["blocklist_expires_at"] > first_exp


def test_blocklist_rebuild_reasons_and_files_missing(pg):
    phish(["commbank-login-secure.top"])
    ctx = ctx_for()
    assert run_blocklist(ctx)["trigger"] == "first build"
    assert run_blocklist(ctx)["rebuilt"] is False
    (bl_dir() / "rpz.zone").unlink()
    out = run_blocklist(ctx)
    assert out["trigger"] == "files missing" and out["files_written"] is True
    assert (bl_dir() / "rpz.zone").is_file()
    assert not list(bl_dir().glob(".*.tmp"))


def test_blocklist_lock_busy_and_build_now(pg):
    phish(["commbank-login-secure.top"])
    ctx = ctx_for()
    with psycopg.connect(pg) as other:
        other.execute("SELECT pg_advisory_xact_lock(%s)", (blocklist.LOCK_KEY,))
        out = run_blocklist(ctx)
        assert out["rebuilt"] is False and out["busy"] is True
        res = arun(blocklist.build_now("rebuild by alice", REVIEWER))
        assert res == {"busy": True}
        req = q1(pg, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))
        assert req["value"] == {"reason": "rebuild by alice", "by": REVIEWER}
        other.rollback()
    res = arun(blocklist.build_now("rebuild by alice", REVIEWER))
    assert res["listed"] == 1 and res["trigger"] == "rebuild by alice"
    assert q1(pg, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_REBUILD,)) is None


def test_blocklist_concurrent_builds(pg):
    phish(["commbank-login-secure.top"])

    async def two():
        p = await db.pool()
        async with p.connection() as a, p.connection() as b:
            return await asyncio.gather(blocklist.build(a, trigger="a"), blocklist.build(b, trigger="b"))
    results = arun(two())
    done = [r for r in results if r is not None]
    assert len(done) >= 1 and all(r["listed"] == 1 for r in done)
    assert len(q(pg, "SELECT 1 FROM domain_events WHERE kind = 'blocklisted'")) == 1


def test_blocklist_review_landing_mid_build_wins(pg):
    """LIST_SQL is guarded: a false_positive that lands after the SELECT is not listed."""
    did = phish(["commbank-login-secure.top"])

    async def go():
        p = await db.pool()
        async with p.connection() as conn:
            orig = blocklist.plan

            def plan_then_review(rows, now, cfg, wl):
                out = orig(rows, now, cfg, wl)
                with psycopg.connect(pg, autocommit=True) as other:
                    other.execute("UPDATE domains SET status = 'false_positive' WHERE id = %s", (did,))
                return out
            blocklist.plan = plan_then_review
            try:
                return await blocklist.build(conn, trigger="t")
            finally:
                blocklist.plan = orig
    out = arun(go())
    assert out["added"] == 0 and out["listed"] == 0
    assert q1(pg, "SELECT blocklisted FROM domains WHERE id = %s", (did,))["blocklisted"] is False


def test_blocklist_write_failure_rolls_back_database(pg):
    """Files are written inside the build transaction: if writing fails, no domain is marked listed."""
    did = phish(["commbank-login-secure.top"])
    if bl_dir().is_dir():
        bl_dir().rmdir()
    bl_dir().write_text("not a directory")                    # the output directory cannot be created
    try:
        res = arun(blocklist.build_now("rebuild by alice", REVIEWER))
        assert "error" in res and res["error"].startswith(("FileExistsError", "NotADirectoryError"))
        r = q1(pg, "SELECT blocklisted, blocklist_listed_at FROM domains WHERE id = %s", (did,))
        assert r["blocklisted"] is False and r["blocklist_listed_at"] is None
        assert not q(pg, "SELECT 1 FROM domain_events WHERE kind = 'blocklisted'")
        assert q1(pg, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,)) is None
        assert q1(pg, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))["value"]["by"] == REVIEWER
        with pytest.raises(OSError):
            run_blocklist(ctx_for())                          # the worker job raises (recorded by the worker)
    finally:
        bl_dir().unlink()
    out = run_blocklist(ctx_for())
    assert out["listed"] == 1 and out["trigger"] == "first build"
    assert q1(pg, "SELECT blocklisted FROM domains WHERE id = %s", (did,))["blocklisted"] is True


def test_blocklist_min_score_setting(pg, monkeypatch):
    setenv(monkeypatch, BLOCKLIST_MIN_FINAL_SCORE="95")
    phish(["commbank-login-secure.top"], confirm=False, final=94)
    b = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=96)
    out = run_blocklist(ctx_for())
    assert out["listed"] == 1 and body_lines("domains.txt") == ["auspost-parcel-redelivery.xyz"]
    # the score drops after a new AI verdict: removed at the next build
    arun(_judge(b, verdict="suspicious", confidence=0.6, final=80))
    arun(_request())
    out = run_blocklist(ctx_for())
    assert out["removed"] == 1 and out["listed"] == 0
    ev = q1(pg, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'unblocklisted'", (b,))
    assert ev["detail"]["reason"] == "combined score below 95"



# ---- channel responses Postgres cannot store as they are (NUL, unpaired surrogates) -------------------

def test_netcraft_response_with_nul_and_lone_surrogates(pg, nc):
    """jsonb rejects \\u0000 and unpaired surrogates; a fake database stored them. Before the fix the attempt
    could not be recorded, the job crashed and the report stayed 'sending' (then 'outcome unknown')."""
    did = phish(["commbank-login-secure.top"])
    nc.replies = [httpx.Response(200, headers={"content-type": "application/json"}, content=(
        b'{"message": "ok\\u0000", "uuid": "0123456789ab\\u0000cdef", "invalid_urls": ["x\\ud83d"]}'))]
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["retry"] == 1 and n["status"] == "approved" and n["error"] == "Netcraft: response had no submission uuid"
    assert n["response"] == {"message": "ok", "uuid": None, "invalid_urls": ["x"], "test": False}
    att = q1(pg, "SELECT ok, http_status, response FROM report_attempts")
    assert att["ok"] is False and att["http_status"] == 200 and att["response"]["uuid"] is None

    # a uuid with a trailing newline is not a uuid either (it would end up in the status URLs)
    age_attempts(pg, 301)
    nc.replies = [httpx.Response(200, json={"message": "ok", "uuid": "0123456789abcdef\n", "invalid_urls": []})]
    run_report()
    assert reports(pg, did)["netcraft"]["status"] == "approved"

    # a real uuid with odd text around it: sent, the text stored without what jsonb cannot hold
    age_attempts(pg, 901)
    uid = uuidlib.uuid4().hex
    nc.replies = [httpx.Response(200, headers={"content-type": "application/json"}, content=(
        b'{"message": "Successfully reported \\ud83d\\ude00 \\udc00\\u0000", "uuid": "' + uid.encode() +
        b'", "invalid_urls": []}'))]
    nc.submitted.add(uid)
    nc.status[uid] = ({"state": "processing\x00\ud800", "is_archived": False},
                      {"urls": [{"url": "https://commbank-login-secure.top/netbank/logon",
                                 "url_state": "\udfff", "url_classification_reason": "kit \x00 \ud83d"}]})
    out = run_report()
    n = reports(pg, did)["netcraft"]
    assert out["sent"] == 1 and out["polled"] == 1 and n["status"] == "sent" and n["external_id"] == uid
    assert n["response"]["message"] == "Successfully reported \U0001F600"
    st = n["response"]["status"]
    assert st["state"] == "processing" and st["urls"][0]["url_classification_reason"] == "kit"
    assert len(n["response"]["status_history"]) == 1


def test_smtp_error_text_with_lone_surrogate(pg, nc, smtp):
    did = phish(["commbank-login-secure.top"])
    run_report()
    r = reports(pg, did)["registrar_abuse"]
    smtp.fail_send = ConnectionResetError("connection reset by peer \ud83d\x00")
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({}), r["id"]))
    out = run_report()
    r = reports(pg, did)["registrar_abuse"]
    assert out["retry"] == 1 and r["status"] == "approved"
    assert r["error"] == "ConnectionResetError: connection reset by peer"
    assert q1(pg, "SELECT error FROM report_attempts WHERE channel = 'registrar_abuse'")["error"] == r["error"]


# ---- verifier additions: wrong results that do not raise ---------------------------------------------

def test_auto_report_at_exact_ai_confidence_threshold(pg, nc, monkeypatch):
    """ai_confidence is real: 0.7 is stored as 0.69999999, and Postgres compares real >= 0.7 (numeric) in
    double precision, so it was false. Python reads the value back as 0.7, and evidence.auto_eligible,
    confidence.py and the blocklist all accept it: the SQL pre-filter must not drop the domain."""
    setenv(monkeypatch, REPORTING_MODE="auto")
    write_sandbox()
    edge = phish(["commbank-login-secure.top"], confirm=False, final=95, confidence=0.7)
    below = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=95, confidence=0.699)
    assert q1(pg, "SELECT ai_confidence FROM domains WHERE id = %s", (edge,))["ai_confidence"] == 0.7
    out = run_report()
    assert out["auto_planned"] == 1 and out["sent"] == 1, out
    assert reports(pg, edge)["netcraft"]["status"] == "sent" and reports(pg, below) == {}
    # the blocklist applies the same threshold to the same rows
    assert run_blocklist(ctx_for())["listed"] == 1
    assert body_lines("domains.txt") == ["commbank-login-secure.top"]


def test_busy_channel_backlog_does_not_starve_other_channels(pg, nc, smtp, monkeypatch):
    """More than one QUEUE_SQL page (50) of Netcraft items waits while Netcraft is paused (429) or inside its
    per-channel interval: a reviewer-approved email on a free channel must still go out."""
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="0")

    async def many():
        ids = []
        for i in range(engine_queue_page() + 2):
            did = await _store([f"commbank-login-secure{i}.top"])
            await _enrich(did)
            await _set_status(did, "confirmed")
            ids.append(did)
        return ids
    ids = arun(many())
    out = run_report()                                   # plans every domain, sends nothing (rate 0)
    assert out["rate_limited"] is True and out["planned"] >= len(ids)
    queued = q(pg, "SELECT id FROM reports WHERE channel = 'netcraft' AND status = 'approved'")
    assert len(queued) == len(ids)
    # the reviewer approves one email draft, of the domain planned last
    brand = reports(pg, ids[-1])["brand:commbank"]
    q(pg, APPROVE_SQL, (REVIEWER, Jsonb({}), brand["id"]))
    # Netcraft answered 429 a moment ago: paused for an hour
    q(pg, "INSERT INTO kv (key, value) VALUES (%s, %s)",
      (engine.KV_PAUSE, Jsonb({"netcraft": (datetime.now(UTC) + timedelta(hours=1)).isoformat()})))
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="10")
    out = run_report()
    assert out["sent"] == 1 and out["waiting"] >= 1, out
    r = reports(pg, ids[-1])["brand:commbank"]
    assert r["status"] == "sent" and r["sent_via"] == "smtp"
    assert nc.posts == [] and len(smtp.sessions[-1].messages) == 1
    assert q1(pg, "SELECT count(*) AS n FROM reports WHERE channel = 'netcraft' AND status = 'approved'")["n"] == len(ids)


def engine_queue_page() -> int:
    import re as _re
    return int(_re.search(r"LIMIT (\d+)", engine.QUEUE_SQL).group(1))


def test_auto_candidates_skip_domains_whose_newest_round_has_no_credentials(pg, nc, monkeypatch):
    """AUTO_CANDIDATES_SQL looks at the newest fetch round only (same rule as evidence.auto_eligible), so a
    stale high score whose kit is gone cannot fill AUTO_LIMIT and starve an eligible domain."""
    setenv(monkeypatch, REPORTING_MODE="auto")
    monkeypatch.setattr(engine, "AUTO_LIMIT", 1)
    write_sandbox()
    stale = phish(["commbank-login-secure.top"], confirm=False, final=99)
    age_pages(pg, stale, hours=3)
    arun(_fetch_round(stale, creds=False))               # newest round: the login form is gone
    errored = phish(["anz-secure-login.top"], confirm=False, final=98)
    age_pages(pg, errored, hours=3)
    arun(_fetch_round(errored, ok=False))                # newest round: the fetch failed
    good = phish(["auspost-parcel-redelivery.xyz"], confirm=False, final=95)
    out = run_report()
    assert out["auto_planned"] == 1 and out["sent"] == 1, out
    assert set(reports(pg, good)) == {"netcraft"}
    assert reports(pg, stale) == {} and reports(pg, errored) == {}


def test_queue_sends_reviewer_approved_before_automatic(pg, nc, monkeypatch):
    """QUEUE_SQL orders by r.auto (after channel availability): a confirmed domain's report goes before an
    older automatic one."""
    setenv(monkeypatch, REPORTING_MODE="auto", REPORT_RATE_PER_HOUR="0")
    write_sandbox()
    auto = phish(["commbank-login-secure.top"], confirm=False)
    assert run_report()["auto_planned"] == 1                    # queued first (lower id, earlier due time)
    human = phish(["auspost-parcel-redelivery.xyz"])
    run_report()
    a, h = reports(pg, auto)["netcraft"], reports(pg, human)["netcraft"]
    assert a["auto"] is True and h["auto"] is False and a["id"] < h["id"]
    assert a["next_attempt_at"] < h["next_attempt_at"]
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="10")
    out = run_report()                                         # one send: then Netcraft's interval applies
    assert out["sent"] == 1 and out["waiting"] == 1
    assert reports(pg, human)["netcraft"]["status"] == "sent"
    assert reports(pg, auto)["netcraft"]["status"] == "approved"
    assert "auspost-parcel-redelivery.xyz" in nc.posts[0][1]["urls"][0]["url"]


def test_poll_window_order_and_limit(pg, nc, monkeypatch):
    """POLL_DUE_SQL: sent within 31 days, least recently checked first, POLL_PER_RUN per run."""
    setenv(monkeypatch, REPORT_CHANNEL_MIN_INTERVAL_S="5")
    hosts = ["commbank-login-secure.top", "auspost-parcel-redelivery.xyz", "mygov-refund-au.click",
             "anz-secure-login.top", "westpac-verify.top", "nab-login-verify.top", "linkt-toll-pay.top"]
    ids = [phish([h], fetch=False, judge=False) for h in hosts]
    for _ in ids:                                              # one Netcraft send per run (channel interval)
        run_report()
        age_attempts(pg, 6)
    rows = q(pg, "SELECT id, external_id, checked_at FROM reports WHERE channel = 'netcraft' AND status = 'sent' "
                 "ORDER BY id")
    assert len(rows) == len(ids) and all(r["checked_at"] is not None for r in rows)   # each polled once at send
    # checked 8 h + i minutes ago (rows[0] longest ago); rows[1] was sent 40 days ago: archived, never polled
    for i, r in enumerate(rows):
        q(pg, "UPDATE reports SET checked_at = now() - make_interval(hours => 8, mins => %s) WHERE id = %s",
          (len(rows) - i, r["id"]))
    q(pg, "UPDATE reports SET sent_at = now() - interval '40 days' WHERE id = %s", (rows[1]["id"],))

    def polled_since(n):
        return [u.split("/submission/")[1].split("/")[0] for u in nc.gets[n:] if not u.split("?")[0].endswith("/urls")]
    n = len(nc.gets)
    assert run_report()["polled"] == engine.POLL_PER_RUN
    expected = [r["external_id"] for i, r in enumerate(rows) if i != 1]
    assert polled_since(n) == expected[:engine.POLL_PER_RUN]
    n = len(nc.gets)
    assert run_report()["polled"] == 1 and polled_since(n) == expected[engine.POLL_PER_RUN:]
    n = len(nc.gets)
    assert not run_report().get("polled") and nc.gets[n:] == []


def test_blocklist_review_mid_build_of_listed_domain_removed_next_run(pg):
    """EXTEND_SQL is not guarded, so a false_positive landing during a build of an already listed domain
    stays in that build's files; the status event is newer than the build's now(), so the next job run
    rebuilds ('review change') and removes it."""
    did = phish(["commbank-login-secure.top"])
    ctx = ctx_for()
    assert run_blocklist(ctx)["listed"] == 1
    q(pg, "UPDATE domains SET blocklist_listed_at = NULL WHERE id = %s", (did,))   # forces an EXTEND_SQL update

    orig = blocklist.plan

    def plan_then_review(rows, now, cfg, wl):
        out = orig(rows, now, cfg, wl)
        with psycopg.connect(pg, autocommit=True) as other:          # the dashboard, autocommit
            other.execute("UPDATE domains SET status = 'false_positive', status_changed_at = now() WHERE id = %s",
                          (did,))
            other.execute("INSERT INTO domain_events (domain_id, kind, detail) VALUES (%s, 'status', '{}')", (did,))
        return out
    blocklist.plan = plan_then_review
    try:
        arun(_request())
        out = run_blocklist(ctx)
    finally:
        blocklist.plan = orig
    assert out["listed"] == 1 and body_lines("domains.txt") == ["commbank-login-secure.top"]
    out = run_blocklist(ctx)
    assert out["rebuilt"] is True and out["trigger"] == "review change" and out["removed"] == 1
    assert body_lines("domains.txt") == []
    assert q1(pg, "SELECT blocklisted FROM domains WHERE id = %s", (did,))["blocklisted"] is False


def test_confirmed_scan_puts_unplanned_domains_first(pg, nc, monkeypatch):
    """CONFIRMED_SQL: domains without any report row come before already planned ones, whatever their
    confirmation time, so a full LIMIT of planned domains cannot hide a new confirmation."""
    setenv(monkeypatch, REPORT_RATE_PER_HOUR="0")
    monkeypatch.setattr(engine, "CONFIRMED_LIMIT", 1)
    a = phish(["commbank-login-secure.top"], fetch=False, judge=False)
    assert run_report()["planned"] > 0 and reports(pg, a)
    b = phish(["auspost-parcel-redelivery.xyz"], fetch=False, judge=False)
    arun(_set_status(b, "confirmed", days_ago=5))           # confirmed before a's latest confirmation
    arun(_set_status(a, "confirmed"))
    out = run_report()
    assert out["planned"] > 0 and "netcraft" in reports(pg, b)
    # outside REPORT_LOOKBACK_DAYS (from status_changed_at, else first_seen): never planned
    c = phish(["mygov-refund-au.click"], fetch=False, judge=False)
    q(pg, "UPDATE domains SET status_changed_at = NULL, first_seen = now() - interval '31 days' WHERE id = %s", (c,))
    monkeypatch.setattr(engine, "CONFIRMED_LIMIT", 300)
    assert not run_report().get("planned") and reports(pg, c) == {}
