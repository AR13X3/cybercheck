"""Reporting module tests (cybercheck/reporting/, jobs/report.py, web/pages_reports.py).

Offline: the database is an in-memory fake that understands the module's SQL constants, Netcraft is an
httpx.MockTransport, SMTP is a fake smtplib class, and sockets are blocked.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import re
import smtplib
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml
from psycopg.types.json import Jsonb

from cybercheck import db, scoring
from cybercheck.reporting import channels, engine, evidence, mailer, netcraft, texts
from cybercheck.reporting.common import SendResult
from cybercheck.reporting.conf import load_config
from cybercheck.scoring import Watchlist

ROOT = Path(__file__).resolve().parent.parent
UTC = timezone.utc
NOW = datetime.now(UTC).replace(microsecond=0)
MIN = timedelta(minutes=1)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
UUID = "0123456789abcdef0123456789abcdef"

WL = Watchlist({"brands": [
    {"id": "commbank", "name": "Commonwealth Bank", "keywords": ["commbank"],
     "official_domains": ["commbank.com.au", "netbank.com.au"]},
    {"id": "auspost", "name": "Australia Post", "keywords": ["auspost"], "official_domains": ["auspost.com.au"]},
    {"id": "linkt", "name": "Linkt", "keywords": ["linkt"], "official_domains": ["linkt.com.au"]},
    {"id": "centrelink", "name": "Centrelink", "keywords": ["centrelink"], "official_domains": ["servicesaustralia.gov.au"]},
]})


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("network access in a test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(scoring, "default_watchlist", lambda: WL)

    async def no_ai(conn, domain, channel, facts):
        return None
    from cybercheck.ai import api
    monkeypatch.setattr(api, "draft_report", no_ai)


def run(coro):
    return asyncio.run(coro)


def settings(**kw):
    base = dict(reporting_mode="review", auto_report_min_final_score=90, report_rate_per_hour=10,
                reporter_email="reports@cybercheck.example", netcraft_api_key="", data_dir=Path("/nonexistent"))
    base.update(kw)
    return SimpleNamespace(**base)


def cfg(env=None, **kw):
    return load_config(settings(**kw), env or {})


SMTP_ENV = {"SMTP_HOST": "smtp.example.org", "SMTP_PORT": "587", "SMTP_USER": "u", "SMTP_PASSWORD": "s3cret-pw",
            "SMTP_FROM": "reports@cybercheck.example"}


def dom(**kw) -> dict:
    d = {"id": 1, "registered_domain": "commbank-login.top", "unicode_domain": None, "tld": "top",
         "brand_id": "commbank", "score": 80, "tier": "high",
         "hostnames": ["www.commbank-login.top", "commbank-login.top"], "source": "ct", "first_seen": NOW - 3 * HOUR,
         "issuer": "Let's Encrypt R11", "ct_log": "Google Argon 2026h2", "status": "confirmed",
         "status_changed_at": NOW - HOUR, "status_by": "rev@example.org", "dns_state": "resolves",
         "ips": ["203.0.113.7"], "asn": 64500, "as_name": "EXAMPLE-HOST", "ip_country": "NL",
         "registrar": "Example Registrar", "registrar_iana_id": 9999, "registrar_abuse_email": "abuse@registrar.example",
         "hosting_abuse_email": "abuse@host.example", "registered_at": NOW - DAY, "live_state": "live",
         "ai_verdict": "phishing", "ai_confidence": 0.95, "ai_brand": "commbank", "final_score": 95,
         "reported_at": None, "takedown_at": None}
    d.update(kw)
    return d


def page(i=10, domain_id=1, ago=30 * MIN, **kw) -> dict:
    p = {"id": i, "domain_id": domain_id, "fetched_at": NOW - ago, "url": "https://www.commbank-login.top/",
         "final_url": "https://www.commbank-login.top/netbank/logon", "http_status": 200,
         "user_agent_profile": "mobile", "egress_ip": "198.51.100.1", "has_password_field": True,
         "has_otp_field": False, "has_card_field": False, "external_form_post": False,
         "screenshot_path": "screenshots/1/10.webp", "error": None}
    p.update(kw)
    return p


def sandbox_ok() -> evidence.SandboxStatus:
    return evidence.SandboxStatus(True, "ok", NOW - DAY, "198.51.100.1", "AU", 12, 1.0)


def write_sandbox(data_dir: Path, **kw) -> Path:
    data = {"verified_at": (NOW - 2 * DAY).isoformat().replace("+00:00", "Z"), "egress_ip": "198.51.100.1",
            "egress_country": "AU", "tests_passed": 12}
    data.update(kw)
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "sandbox_verified.json"
    path.write_text(json.dumps(data))
    return path


# =====================================================================================================
# research consistency: the catalogue in channels.py must match the fact-checked YAML files
# =====================================================================================================

def research(name: str) -> dict:
    data = yaml.safe_load((ROOT / "docs" / "research" / name).read_text(encoding="utf-8"))
    return {c["id"]: c for c in data["channels"]}


AU = research("au-reporting.yaml")
INTL = research("intl-reporting.yaml")


def test_brand_contacts_match_research():
    for c in channels.BRAND_CONTACTS:
        entry = AU[c.research_id]
        assert entry["address_or_url"] == c.address, c.research_id
        assert entry["brand_id"] == c.brand_id and entry["source"] == c.source
        assert entry["method"] == c.method and entry["automated_ok"] is False


def test_every_verified_brand_mailbox_is_used():
    ids = {c.research_id for c in channels.BRAND_CONTACTS}
    for rid, entry in AU.items():
        if entry["scope"] == "brand" and entry["method"] == "email":
            assert rid in ids, rid


def test_manual_channels_match_research():
    for ch in channels.MANUAL.values():
        entry = AU.get(ch.research_id) or INTL[ch.research_id]
        url = entry.get("address_or_url") or entry.get("endpoint")
        assert ch.url in str(url), ch.id
        assert entry["automated_ok"] is False and ch.automated_ok is False and ch.kind == "manual"


def test_only_netcraft_is_automated():
    nc = INTL["netcraft"]
    assert nc["automated_ok"] is True and nc["endpoint"] == channels.NETCRAFT.url
    assert netcraft.BASE + "/report/urls" == nc["endpoint"] and netcraft.TEST_BASE + "/report/urls" == nc["sandbox_endpoint"]
    assert channels.automated_channels(cfg()) == ["netcraft"]
    assert channels.REGISTRAR.automated_ok is False and channels.HOSTING.automated_ok is False
    assert INTL["registrar_abuse_contact_gtld"]["automated_ok"] is False
    assert INTL["hosting_abuse_contact"]["automated_ok"] is False
    not_used = " ".join(n for n, _, _ in channels.NOT_USED)
    for name in ("Spamhaus", "eCX", "Cloudflare Abuse Reports API", "CTIS", "Web Risk", "PhishTank"):
        assert name in not_used


@pytest.mark.parametrize("brand,expected", [
    ("commbank", "hoax@cba.com.au"), ("hsbc_au", "phishing@hsbc.com"), ("aramex_au", "scams@aramex.com.au"),
    ("centrelink", "reportascam@servicesaustralia.gov.au"), ("mygov", "reportascam@servicesaustralia.gov.au"),
    ("ato", "ReportScams@ato.gov.au"), ("linkt", "https://www.linkt.com.au/contact-us/report-scam"),
    ("vodafone_au", "https://vha.my.salesforce-sites.com/ScamLodgementForm"),
    ("coinspot", None), ("eastlink", None), ("awaresuper", None), ("ubank", None), (None, None),
])
def test_brand_contact(brand, expected):
    c = channels.brand_contact(brand)
    assert (c.address if c else None) == expected


# =====================================================================================================
# settings
# =====================================================================================================

def test_config_defaults_and_guards():
    c = cfg()
    assert c.mode == "review" and c.min_final_score == 90 and c.rate_per_hour == 10 and c.netcraft_ready
    assert c.smtp is None and "SMTP_HOST" in c.smtp_reason
    low = cfg(auto_report_min_final_score=9)
    assert low.min_final_score == 90 and any(w == "AUTO_REPORT_MIN_FINAL_SCORE" for w, _ in channels.disabled(low))
    bad = cfg(reporting_mode="yes please", reporter_email="not-an-email")
    assert bad.mode == "review" and bad.reporter_email == "" and not bad.netcraft_ready
    what = dict(channels.disabled(bad))
    assert "REPORTER_EMAIL" in what["Netcraft report API"] and what["REPORTING_MODE"]
    assert cfg(netcraft_api_key="k").netcraft_api_key_set
    assert "not used" in dict(channels.disabled(cfg(netcraft_api_key="k")))["NETCRAFT_API_KEY"]


def test_smtp_all_or_nothing():
    ok, why = mailer.smtp_from_env(SMTP_ENV)
    assert ok and ok.port == 587 and why == "" and "s3cret-pw" not in repr(ok)
    for missing in SMTP_ENV:
        env = {k: v for k, v in SMTP_ENV.items() if k != missing}
        c, why = mailer.smtp_from_env(env)
        assert c is None and missing in why
    assert mailer.smtp_from_env({**SMTP_ENV, "SMTP_PORT": "x"})[0] is None
    assert mailer.smtp_from_env({**SMTP_ENV, "SMTP_FROM": "nope"})[0] is None
    assert cfg(SMTP_ENV).smtp is not None


# =====================================================================================================
# planning
# =====================================================================================================

def chans(specs):
    return {s.channel: (s.kind, s.status, s.auto) for s in specs}


def test_plan_confirmed_review_mode():
    got = chans(channels.plan(dom(), cfg(), "confirmed"))
    assert got == {
        "netcraft": ("api", "approved", False),
        "registrar_abuse": ("email", "pending_review", False),
        "hosting_abuse": ("email", "pending_review", False),
        "brand:commbank": ("email", "pending_review", False),
        "scamwatch": ("manual", "pending_review", False),
        "google_safe_browsing": ("manual", "pending_review", False),
        "microsoft_smartscreen": ("manual", "pending_review", False),
    }


def test_plan_mode_off_and_no_reporter_identity_have_no_automated_channel():
    assert "netcraft" not in chans(channels.plan(dom(), cfg(reporting_mode="off"), "confirmed"))
    assert "netcraft" not in chans(channels.plan(dom(), cfg(reporter_email=""), "confirmed"))
    assert channels.plan(dom(), cfg(reporter_email=""), "auto") == []


def test_plan_cloudflare_au_and_brand_form():
    cf = chans(channels.plan(dom(asn=13335, as_name="CLOUDFLARENET"), cfg(), "confirmed"))
    assert "hosting_abuse" not in cf and "cloudflare_abuse_form" in cf
    au = chans(channels.plan(dom(registered_domain="commbank-login.com.au", registrar_abuse_email=None), cfg(),
                             "confirmed"))
    assert "auda_dns_abuse" in au and "registrar_abuse" in au
    linkt = chans(channels.plan(dom(brand_id="linkt"), cfg(), "confirmed"))
    assert linkt["brand_form:linkt"] == ("manual", "pending_review", False) and "brand:linkt" not in linkt
    none = chans(channels.plan(dom(brand_id="coinspot"), cfg(), "confirmed"))
    assert not any(c.startswith("brand") for c in none)


def test_plan_auto_trigger_is_automated_channels_only():
    assert chans(channels.plan(dom(status="open"), cfg(reporting_mode="auto"), "auto")) == {
        "netcraft": ("api", "approved", True)}


def test_manual_channel_setting():
    c = cfg({"REPORT_MANUAL_CHANNELS": "scamwatch, reportcyber, bogus"})
    got = chans(channels.plan(dom(brand_id="linkt"), c, "confirmed"))
    assert {k for k, v in got.items() if v[0] == "manual"} == {"scamwatch", "reportcyber"}
    assert "reportcyber" not in channels.default_manual_channels()


# =====================================================================================================
# evidence and automatic-report eligibility
# =====================================================================================================

def test_sandbox_status(tmp_path):
    path = tmp_path / "sandbox_verified.json"
    assert not evidence.sandbox_status(path).ok and "missing" in evidence.sandbox_status(path).reason
    write_sandbox(tmp_path)
    s = evidence.sandbox_status(path)
    assert s.ok and s.egress_country == "AU" and s.tests_passed == 12
    write_sandbox(tmp_path, verified_at=(NOW - 31 * DAY).isoformat())
    assert "31 days old" in evidence.sandbox_status(path).reason
    write_sandbox(tmp_path, verified_at=(NOW + DAY).isoformat())
    assert "future" in evidence.sandbox_status(path).reason
    for bad in ({"tests_passed": 0}, {"tests_passed": True}, {"egress_ip": "not an ip"}, {"verified_at": "yesterday"}):
        write_sandbox(tmp_path, **bad)
        assert not evidence.sandbox_status(path).ok, bad
    path.write_text("{not json")
    assert not evidence.sandbox_status(path).ok
    path.write_text(json.dumps({"verified_at": NOW.isoformat(), "pad": "x" * 70000}))
    assert not evidence.sandbox_status(path).ok


AUTO = dict(reporting_mode="auto")


def test_auto_eligible_happy_path():
    ok, why = evidence.auto_eligible(dom(status="open"), [page()], cfg(**AUTO), sandbox_ok())
    assert ok and why == ""


@pytest.mark.parametrize("dkw,pages,ckw,needle", [
    ({}, None, {"reporting_mode": "review"}, "not auto"),
    ({"status": "confirmed"}, None, {}, "status is confirmed"),
    ({"status": "false_positive"}, None, {}, "status is false_positive"),
    ({"status": "benign"}, None, {}, "status is benign"),
    ({"final_score": 89}, None, {}, "below 90"),
    ({"final_score": None}, None, {}, "below 90"),
    ({"ai_verdict": "suspicious"}, None, {}, "not phishing"),
    ({"ai_confidence": 0.5}, None, {}, "confidence"),
    ({"ai_confidence": float("nan")}, None, {}, "confidence"),
    ({"takedown_at": NOW}, None, {}, "taken down"),
    ({"registered_domain": "fake-ato.gov.au"}, None, {}, ".gov.au"),
    ({"registered_domain": "commbank.com.au"}, None, {}, "official"),
    ({}, [page(has_password_field=False)], {}, "does not ask"),
    ({}, [page(i=11, ago=10 * MIN, has_password_field=False, screenshot_path=None), page(ago=3 * HOUR)], {},
     "does not ask"),
    ({}, [page(http_status=404)], {}, "does not ask"),
    ({}, [page(error="timeout")], {}, "does not ask"),
    ({}, [], {}, "does not ask"),
])
def test_auto_eligible_refusals(dkw, pages, ckw, needle):
    ok, why = evidence.auto_eligible(dom(**{"status": "open", **dkw}),
                                     [page()] if pages is None else pages, cfg(**{**AUTO, **ckw}), sandbox_ok())
    assert not ok and needle in why


def test_auto_eligible_needs_valid_sandbox():
    bad = evidence.SandboxStatus(False, "sandbox not verified: data/sandbox_verified.json is missing")
    ok, why = evidence.auto_eligible(dom(status="open"), [page()], cfg(**AUTO), bad)
    assert not ok and "sandbox" in why


def test_report_urls_stay_on_the_reported_domain():
    pages = [page(final_url="https://www.commbank.com.au/netbank/"),           # kit redirects to the real bank
             page(i=11, url="https://www.commbank.com.au@commbank-login.top/x", final_url=None),
             page(i=12, url="javascript:alert(1)", final_url="https://sub.commbank-login.top/a b"),
             page(i=13, ago=5 * MIN, url="https://login.commbank-login.top/verify",
                  final_url="http://commbank-login.top.evil.top/")]                       # newest
    assert evidence.report_urls(dom(), pages) == ["https://login.commbank-login.top/verify",
                                                  "https://www.commbank-login.top/"]
    assert evidence.report_urls(dom(hostnames=["*.commbank-login.top", "pay.commbank-login.top"]), []) == [
        "https://pay.commbank-login.top/"]
    assert evidence.report_urls(dom(hostnames=[]), []) == ["https://commbank-login.top/"]


def test_best_page_prefers_credentials_then_screenshot():
    pages = [page(i=1, ago=5 * MIN, has_password_field=False), page(i=2, ago=2 * HOUR, screenshot_path=None),
             page(i=3, ago=2 * HOUR + 2 * MIN)]
    assert evidence.best_page(pages)["id"] == 3
    assert evidence.best_page([page(i=4, has_password_field=False)])["id"] == 4
    assert evidence.best_page([page(i=5, error="x")]) is None
    assert evidence.credential_page(pages) is None      # the newest run shows no credential fields


# =====================================================================================================
# report wording
# =====================================================================================================

ACCUSATORY = re.compile(r"\b(criminal|scammer|fraudster|illegal operation|guilty|definitely|certainly)\b", re.I)


def facts(**kw):
    p = page()
    return evidence.build_facts(dom(**kw), p, [p], egress_country="AU", egress_ip="198.51.100.1")


def test_email_template_is_factual_and_complete():
    body = texts.email_template("registrar_abuse", facts(), cfg())
    for needle in ("commbank-login.top", "https://www.commbank-login.top/netbank/logon", "Commonwealth Bank",
                   "commbank.com.au", "a password", "from an Australian network", "Certificate Transparency",
                   "Google Argon 2026h2", "Example Registrar", "IANA ID 9999", "203.0.113.7", "AS64500",
                   "Screenshot: captured", "confirmed it as phishing", "good faith", "No message was received",
                   "ICANN Registrar Accreditation Agreement", "reports@cybercheck.example"):
        assert needle in body, needle
    assert not ACCUSATORY.search(body)
    assert "appears to" in body
    au = texts.email_template("registrar_abuse", facts(registered_domain="commbank-login.com.au"), cfg())
    assert "2.11.16" in au and "ICANN" not in au
    host = texts.email_subject("hosting_abuse", facts())
    assert host == "Phishing site on your network: commbank-login.top (203.0.113.7)"


def test_brand_mailbox_email_says_no_message_was_received_first():
    body = texts.email_template("brand:commbank", facts(), cfg())
    first = body.splitlines()[0]
    assert first.startswith("This is a report about a website, not a forwarded message")
    assert "Certificate Transparency" in first
    assert texts.email_subject("brand:commbank", facts()) == \
        "Possible phishing site impersonating Commonwealth Bank: commbank-login.top"
    sw = texts.manual_item("scamwatch", facts(), dom())["fields"][1]["value"]
    assert "(CyberCheck; no message was received) and confirmed by a reviewer." in sw


def test_unreviewed_wording_and_netcraft_reasons():
    top, per_url = texts.netcraft_reasons(facts(status="open"))
    assert "not yet reviewed by a person" in top and "good faith" in top and "combined score 95/100" in top
    assert per_url == "Appears to impersonate Commonwealth Bank; asks for a password"
    top, _ = texts.netcraft_reasons(facts())
    assert "confirmed as phishing by a human reviewer" in top
    assert "not yet been reviewed by a person" in texts.disclosure(facts(status="open"))


def test_recipients():
    assert texts.recipient("registrar_abuse", dom())[0] == "abuse@registrar.example"
    to, hint = texts.recipient("registrar_abuse", dom(registered_domain="x-commbank.com.au",
                                                      registrar_abuse_email=None))
    assert to == "" and "whois.auda.org.au" in hint and "5.1" in hint
    assert texts.recipient("brand:commbank", dom())[0] == "hoax@cba.com.au"
    assert texts.recipient("hosting_abuse", dom(hosting_abuse_email="bad address"))[0] == ""


def test_manual_items_prefill_the_official_fields():
    f = facts()
    sw = texts.manual_item("scamwatch", f, dom())
    assert sw["url"] == "https://forms.scamwatch.gov.au/report-a-scamwebsite/"
    assert [x["label"] for x in sw["fields"]] == ["Website URL", "What makes the website a scam?"]
    assert sw["fields"][0]["value"] == "https://www.commbank-login.top/netbank/logon"
    assert "confirmed by a reviewer" in sw["fields"][1]["value"] and "rev@example.org" not in sw["fields"][1]["value"]
    ms = texts.manual_item("microsoft_smartscreen", f, dom())
    assert {"label": "Threat type", "value": "Phishing"} in ms["fields"]
    cf = texts.manual_item("cloudflare_abuse_form", evidence.build_facts(
        dom(), page(), [page(), page(i=11, final_url="https://pay.commbank-login.top/x")]), dom())
    urls = next(x["value"] for x in cf["fields"] if x["label"].startswith("URLs"))
    assert "pay.commbank-login.top" not in urls
    lk = texts.manual_item("brand_form:linkt", facts(brand_id="linkt"), dom(brand_id="linkt"))
    assert lk["url"] == "https://www.linkt.com.au/contact-us/report-scam" and "image" in lk["notes"]


def test_ai_body_always_gets_disclosure_and_signature():
    body = texts.wrap_ai_body("The site at commbank-login.top imitates the CommBank login page.", facts(), cfg())
    assert body.startswith("The site at") and "How this was found" in body and "reports@cybercheck.example" in body


# =====================================================================================================
# Netcraft client
# =====================================================================================================

ALLOWED_TOP = {"email", "reason", "skip_invalid_urls", "urls", "source", "no_submission"}
ALLOWED_URL = {"url", "country", "reason", "tags", "screenshot"}


def test_netcraft_payload_shape():
    jpeg = b"\xff\xd8fakejpeg"
    p = netcraft.build_payload("r@x.example", ["https://a.top/1", "https://a.top/2"], "why", "per url", "AU", jpeg)
    assert set(p) <= ALLOWED_TOP and p["email"] == "r@x.example" and p["skip_invalid_urls"] is True
    assert all(set(u) <= ALLOWED_URL and u["country"] == "AU" for u in p["urls"])
    assert p["urls"][0]["screenshot"] == {"base64": base64.standard_b64encode(jpeg).decode(), "ext": "jpg"}
    assert "screenshot" not in p["urls"][1]
    audit = netcraft.audit_copy(p)
    assert audit["urls"][0]["screenshot"] == {"ext": "jpg", "bytes": len(jpeg)} and "base64" not in json.dumps(audit)


def nc_client(handler, seen=None):
    def h(request):
        if seen is not None:
            seen.append(request)
        return handler(request)
    return httpx.AsyncClient(transport=httpx.MockTransport(h))


@pytest.mark.parametrize("status,body,headers,check", [
    (200, {"message": "Successfully reported", "uuid": UUID, "invalid_urls": []}, {},
     lambda r: r.ok and r.external_id == UUID and not r.permanent),
    (200, {"message": "ok", "uuid": UUID, "invalid_urls": ["https://a.top/1"]}, {},
     lambda r: not r.ok and r.permanent),
    (200, {"message": "ok"}, {}, lambda r: not r.ok and not r.permanent),
    (429, {"message": "Too many urls reported"}, {"retry-after": "120"},
     lambda r: not r.ok and r.retry_after == 120 and not r.permanent),
    (400, {"message": "bad email"}, {}, lambda r: not r.ok and r.permanent and "400" in r.error),
    (503, "busy", {}, lambda r: not r.ok and not r.permanent),
])
def test_netcraft_submit(status, body, headers, check):
    seen = []
    content = json.dumps(body).encode() if not isinstance(body, str) else body.encode()

    async def go():
        async with nc_client(lambda req: httpx.Response(status, content=content, headers=headers), seen) as c:
            payload = netcraft.build_payload("r@x.example", ["https://a.top/1"], "why", "per url")
            return await netcraft.submit(c, netcraft.base_url(False), payload)
    r = run(go())
    assert check(r)
    assert seen[0].url == "https://report.netcraft.com/api/v3/report/urls" and seen[0].method == "POST"
    assert json.loads(seen[0].content)["urls"][0]["url"] == "https://a.top/1"


def test_netcraft_timeout_and_test_endpoint():
    def boom(req):
        raise httpx.ConnectTimeout("slow")

    async def go():
        async with nc_client(boom) as c:
            return await netcraft.submit(c, netcraft.base_url(True), {"urls": []})
    r = run(go())
    assert not r.ok and not r.permanent and r.sent["endpoint"].startswith("https://report.netcraft.com/api/v3/test/")


def test_netcraft_poll():
    def handler(req):
        if req.url.path.endswith("/urls"):
            return httpx.Response(200, json={"urls": [{"url": "https://a.top/1", "url_state": "malicious",
                                                       "url_takedown_state": "resolved", "evil": "<x>"}]})
        return httpx.Response(200, json={"state": "malicious", "is_archived": False})

    async def go(h, uuid=UUID):
        async with nc_client(h) as c:
            return await netcraft.poll(c, netcraft.BASE, uuid)
    st = run(go(handler))
    assert st["state"] == "malicious" and st["final"] and st["urls"][0]["url_takedown_state"] == "resolved"
    assert "evil" not in st["urls"][0]
    assert run(go(lambda r: httpx.Response(404, json={}))) == {"archived": True, "final": True}
    assert run(go(lambda r: httpx.Response(500))) is None
    assert run(go(handler, "../../etc"))["final"] is True


# =====================================================================================================
# SMTP
# =====================================================================================================

class FakeSMTP:
    instances: list = []
    offer_tls = True

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.offer_tls and name.lower() == "starttls"

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append("login")

    def send_message(self, msg):
        self.calls.append(("send", msg["To"], msg["Subject"]))
        self.msg = msg


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    FakeSMTP.offer_tls = True
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_smtp_send_uses_starttls(fake_smtp):
    conf, _ = mailer.smtp_from_env(SMTP_ENV)
    r = run(mailer.send(conf, "abuse@registrar.example", "Subject\r\nBcc: x@evil.example", "body", "me@x.example",
                        ("shot.jpg", b"\xff\xd8x")))
    assert r.ok and r.external_id
    s = fake_smtp.instances[0]
    assert s.calls[:4] == ["ehlo", "starttls", "ehlo", "login"]
    assert s.msg["Subject"] == "Subject Bcc: x@evil.example" and s.msg["Bcc"] is None
    assert s.msg["Reply-To"] == "me@x.example"


def test_smtp_refuses_cleartext_and_bad_recipient(fake_smtp):
    conf, _ = mailer.smtp_from_env(SMTP_ENV)
    fake_smtp.offer_tls = False
    r = run(mailer.send(conf, "abuse@registrar.example", "s", "b"))
    assert not r.ok and r.permanent and "STARTTLS" in r.error
    assert all(c != "login" for c in fake_smtp.instances[-1].calls)
    r = run(mailer.send(conf, "abuse@registrar.example\nBcc: x@evil.example", "s", "b"))
    assert not r.ok and r.permanent


def test_smtp_port_465_uses_ssl(fake_smtp):
    conf, _ = mailer.smtp_from_env({**SMTP_ENV, "SMTP_PORT": "465"})
    assert run(mailer.send(conf, "a@b.example", "s", "b")).ok
    assert "starttls" not in fake_smtp.instances[-1].calls


def test_smtp_error_classification():
    assert mailer.classify_error(smtplib.SMTPAuthenticationError(535, b"no")).permanent
    assert mailer.classify_error(smtplib.SMTPResponseException(550, b"mailbox unavailable")).permanent
    assert not mailer.classify_error(smtplib.SMTPResponseException(451, b"try later")).permanent
    assert not mailer.classify_error(TimeoutError()).permanent


# =====================================================================================================
# engine with an in-memory database
# =====================================================================================================

class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchall(self):
        return self.rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None


def _o(v):
    return v.obj if isinstance(v, Jsonb) else v


DOMAIN_KEYS = [k.strip().removeprefix("d.") for k in engine.DOMAIN_COLS.replace("\n", " ").split(",")]


class FakeDB:
    """Just enough of Postgres for the reporting SQL. Keys are the module's SQL constants."""

    def __init__(self, domains=(), pages=(), attempts_last_hour=0):
        self.domains = {d["id"]: dict(d) for d in domains}
        self.pages = [dict(p) for p in pages]
        self.reports: dict[int, dict] = {}
        self.attempts: list[dict] = [{"id": -i, "report_id": 0, "channel": "old", "via": "api",
                                      "at": NOW - 10 * MIN, "ok": True} for i in range(attempts_last_hour)]
        self.events: list[tuple] = []
        self.kv: dict = {}
        self.sql: list[tuple[str, tuple]] = []
        self.ids = iter(range(100, 100000))
        from cybercheck.web import pages_reports as w
        self.w = w
        self.h = {
            engine.CANCEL_CLOSED_SQL: self.cancel_closed, engine.RECOVER_ATTEMPTS_SQL: lambda p: [],
            engine.RECOVER_SQL: lambda p: [], engine.CONFIRMED_SQL: self.confirmed,
            engine.ONE_DOMAIN_SQL: self.one_domain, engine.AUTO_CANDIDATES_SQL: self.auto_candidates,
            engine.PAGES_SQL: self.pages_for, engine.INSERT_SQL: self.insert, engine.REVIVE_SQL: self.revive,
            engine.AI_PENDING_SQL: self.ai_pending, engine.AI_SAVE_SQL: self.ai_save,
            engine.LOCK_SQL: lambda p: [{"locked": True}], engine.RATE_SQL: self.rate,
            engine.CHANNEL_BUSY_SQL: self.busy, engine.QUEUE_SQL: self.queue, engine.SKIP_SQL: self.skip,
            engine.HOLD_SQL: self.hold, engine.CLAIM_SQL: self.claim, engine.ATTEMPT_SQL: self.attempt,
            engine.SCREENSHOT_SQL: self.screenshot, engine.ATTEMPT_DONE_SQL: self.attempt_done,
            engine.SENT_SQL: self.sent, engine.REPORTED_SQL: self.reported, engine.RETRY_SQL: self.retry,
            engine.FAIL_SQL: self.fail, engine.POLL_DUE_SQL: lambda p: [], engine.POLL_SAVE_SQL: lambda p: [],
            engine.CLEAN_ATTEMPTS_SQL: lambda p: [], engine.TEST_SENT_SQL: self.test_sent,
            engine.RELEASE_TEST_SQL: self.release_test, engine.FLAGGED_CONTACT_SQL: self.flagged,
            w.SUMMARY_SQL: self.summary, w.CHANNEL_COUNTS_SQL: lambda p: [], w.UNREPORTED_SQL: self.unreported,
            w.DETAIL_SQL: lambda p: [self.joined(self.reports[p[0]])] if p[0] in self.reports else [],
            w.ATTEMPTS_SQL: lambda p: [a for a in self.attempts if a["report_id"] == p[0]],
            w.KV_SQL: lambda p: [{"key": k, "value": v, "updated_at": NOW} for k, v in self.kv.items() if k in p[0]],
            w.LOCK_SQL: self.web_lock, w.SAVE_SQL: self.web_save, w.APPROVE_SQL: self.web_approve,
            w.MARK_SENT_SQL: self.web_mark_sent, w.REJECT_SQL: self.web_reject, w.RETRY_SQL: self.web_retry,
            "SELECT domain_id, payload FROM reports WHERE id = %s":
                lambda p: [self.reports[p[0]]] if p[0] in self.reports else [],
        }
        for key, sql in w.LIST_SQL.items():
            self.h[sql] = lambda p, key=key: self.web_list(key)

    # -- plumbing --
    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, sql, params=()):
        params = tuple(_o(p) for p in (params or ()))
        self.sql.append((sql, params))
        if sql in self.h:
            return Cur(self.h[sql](params) or [])
        if sql.startswith("INSERT INTO domain_events"):
            self.events.append((params[0], params[1], params[2]))
            return Cur([])
        if sql.startswith("SELECT value FROM kv"):
            return Cur([{"value": self.kv[params[0]]}] if params[0] in self.kv else [])
        if sql.startswith("INSERT INTO kv"):
            self.kv[params[0]] = params[1]
            return Cur([])
        raise AssertionError("unexpected SQL: " + sql[:120])

    def domain_row(self, d):
        return {k: d.get(k) for k in DOMAIN_KEYS}

    @staticmethod
    def is_test(r):
        return isinstance(r.get("response"), dict) and r["response"].get("test") is True

    def with_have(self, d):
        rs = [r for r in self.reports.values() if r["domain_id"] == d["id"]]
        return {**self.domain_row(d), "have": [r["channel"] for r in rs],
                "revivable": [r["channel"] for r in rs if r["status"] == "skipped" and r["kind"] == "api"],
                "revivable_test": [r["channel"] for r in rs
                                   if r["status"] == "skipped" and r["kind"] == "api" and self.is_test(r)]}

    def joined(self, r):
        d = self.domains[r["domain_id"]]
        return {**r, "registered_domain": d["registered_domain"], "unicode_domain": d.get("unicode_domain"),
                "brand_id": d.get("brand_id"), "domain_status": d["status"], "final_score": d.get("final_score"),
                "takedown_at": d.get("takedown_at"), "live_state": d.get("live_state")}

    def by_channel(self, channel):
        return [r for r in self.reports.values() if r["channel"] == channel]

    # -- engine --
    def cancel_closed(self, p):
        out = []
        for r in self.reports.values():
            st = self.domains[r["domain_id"]]["status"]
            if st in ("false_positive", "benign") and r["status"] in ("pending_review", "approved"):
                r.update(status="skipped", error=f"domain marked {st} by a reviewer; not sent")
                out.append({"id": r["id"]})
        return out

    def confirmed(self, p):
        return [self.with_have(d) for d in self.domains.values()
                if d["status"] == "confirmed" and d.get("takedown_at") is None]

    def one_domain(self, p):
        return [self.with_have(self.domains[p[0]])] if p[0] in self.domains else []

    def auto_candidates(self, p):
        """Mirrors AUTO_CANDIDATES_SQL, including its pre-filter on the newest fetch run."""
        min_score, chans_, test_mode, limit = p
        out = []
        for d in sorted(self.domains.values(), key=lambda d: -(d.get("final_score") or 0)):
            pages_ = [x for x in self.pages if x["domain_id"] == d["id"]]
            newest = max((x["fetched_at"] for x in pages_), default=None)
            creds = newest is not None and any(
                x["error"] is None and (x["has_password_field"] or x["has_otp_field"] or x["has_card_field"])
                and (x["http_status"] in (None, 0) or 200 <= x["http_status"] <= 399)
                and x["fetched_at"] >= newest - timedelta(minutes=15) for x in pages_)
            if (d["status"] == "open" and (d.get("final_score") or 0) >= min_score and d.get("ai_verdict") == "phishing"
                    and d.get("takedown_at") is None and (d.get("ai_confidence") or 0) >= 0.7
                    and not d["registered_domain"].endswith(".gov.au") and creds
                    and not any(r["domain_id"] == d["id"] and r["channel"] in chans_
                                and (test_mode or r["status"] != "skipped" or not self.is_test(r))
                                for r in self.reports.values())):
                out.append(self.with_have(d))
        return out[:limit]

    def pages_for(self, p):
        return sorted([x for x in self.pages if x["domain_id"] == p[0]], key=lambda x: x["fetched_at"], reverse=True)

    def insert(self, p):
        domain_id, channel, status, auto, kind, payload = p
        if any(r["domain_id"] == domain_id and r["channel"] == channel for r in self.reports.values()):
            return []
        rid = next(self.ids)
        self.reports[rid] = {"id": rid, "domain_id": domain_id, "channel": channel, "status": status, "auto": auto,
                             "kind": kind, "payload": dict(payload), "created_at": NOW, "updated_at": NOW,
                             "sent_at": None, "response": None, "error": None, "external_id": None, "attempts": 0,
                             "next_attempt_at": NOW - MIN, "last_attempt_at": None, "reviewed_by": None,
                             "reviewed_at": None, "sent_via": None, "sent_by": None, "checked_at": None}
        return [{"id": rid}]

    def revive(self, p):
        auto, domain_id, chans_, allow_test, test_only = p
        out = []
        for r in self.reports.values():
            if (r["domain_id"] == domain_id and r["channel"] in chans_ and r["status"] == "skipped"
                    and r["kind"] == "api" and (allow_test or not self.is_test(r)) and (not test_only or self.is_test(r))):
                r.update(status="approved", auto=auto, error=None, attempts=0, next_attempt_at=NOW - MIN)
                out.append({"id": r["id"], "channel": r["channel"]})
        return out

    def test_sent(self, p):
        r = self.reports[p[4]]
        r.update(status="skipped", external_id=p[0], response=p[1], error=p[2])
        r["payload"].update(p[3])

    def release_test(self, p):
        rows = [r for r in self.reports.values()
                if r["channel"] == "netcraft" and r["status"] == "sent" and self.is_test(r)]
        doms = {r["domain_id"] for r in rows}
        unreported = [i for i in doms if not any(
            x["domain_id"] == i and x["status"] == "sent" and not self.is_test(x) for x in self.reports.values())]
        for r in rows:
            r.update(status="skipped", error=p[0])
        for i in unreported:
            self.domains[i]["reported_at"] = None
        return [{"released": len(rows), "unreported": len(unreported)}]

    def flagged(self, p):
        return [{"registered_domain": d["registered_domain"]} for d in self.domains.values()
                if d["registered_domain"] in p[0] and d["status"] in ("open", "confirmed")]

    def ai_pending(self, p):
        return [{"id": r["id"], "domain_id": r["domain_id"], "channel": r["channel"], "payload": r["payload"],
                 "registered_domain": self.domains[r["domain_id"]]["registered_domain"],
                 "brand_id": self.domains[r["domain_id"]]["brand_id"]}
                for r in self.reports.values()
                if r["status"] == "pending_review" and r["kind"] == "email" and r["payload"].get("ai") == "pending"]

    def ai_save(self, p):
        r = self.reports[p[1]]
        if r["status"] == "pending_review" and r["payload"].get("ai") == "pending":
            r["payload"].update(p[0])

    def rate(self, p):
        return [{"n": sum(1 for a in self.attempts if a["at"] > datetime.now(UTC) - HOUR)}]

    def busy(self, p):
        since = datetime.now(UTC) - timedelta(seconds=p[0])
        return [{"channel": c} for c in {a["channel"] for a in self.attempts if a["at"] > since}]

    def queue(self, p):
        now = datetime.now(UTC)
        rows = [r for r in self.reports.values()
                if r["status"] == "approved" and (r["next_attempt_at"] is None or r["next_attempt_at"] <= now)]
        rows.sort(key=lambda r: (r["auto"], r["next_attempt_at"] or NOW - DAY, r["id"]))
        return [{"report_id": r["id"], "channel": r["channel"], "kind": r["kind"], "auto": r["auto"],
                 "attempts": r["attempts"], "payload": r["payload"],
                 **self.domain_row(self.domains[r["domain_id"]])} for r in rows]

    def skip(self, p):
        r = self.reports[p[1]]
        if r["status"] in ("approved", "pending_review"):
            r.update(status="skipped", error=p[0])

    def hold(self, p):
        r = self.reports[p[2]]
        if r["status"] == "approved":
            r.update(next_attempt_at=datetime.now(UTC) + timedelta(seconds=p[0]), error=p[1])

    def claim(self, p):
        r = self.reports[p[0]]
        if r["status"] != "approved":
            return []
        r.update(status="sending", attempts=r["attempts"] + 1, last_attempt_at=datetime.now(UTC))
        return [{"attempts": r["attempts"]}]

    def attempt(self, p):
        aid = next(self.ids)
        self.attempts.append({"id": aid, "report_id": p[0], "channel": p[1], "via": p[2], "at": datetime.now(UTC),
                              "ok": None, "http_status": None, "error": None, "response": None})
        return [{"id": aid}]

    def screenshot(self, p):
        return [{"screenshot_path": x["screenshot_path"]} for x in self.pages if x["id"] == p[0] and x["domain_id"] == p[1]]

    def attempt_done(self, p):
        a = next(a for a in self.attempts if a["id"] == p[4])
        a.update(ok=p[0], http_status=p[1], error=p[2], response=p[3])

    def sent(self, p):
        r = self.reports[p[4]]
        r.update(status="sent", sent_at=datetime.now(UTC), sent_via=p[0], sent_by="worker", external_id=p[1],
                 response=p[2], error=None)
        r["payload"].update(p[3])

    def reported(self, p):
        d = self.domains[p[0]]
        d["reported_at"] = d.get("reported_at") or datetime.now(UTC)

    def retry(self, p):
        r = self.reports[p[4]]
        r.update(status="approved", next_attempt_at=datetime.now(UTC) + timedelta(seconds=p[0]), error=p[1],
                 response=p[2])
        r["payload"].update(p[3])

    def fail(self, p):
        r = self.reports[p[3]]
        r.update(status="failed", error=p[0], response=p[1])
        r["payload"].update(p[2])

    # -- web --
    def summary(self, p):
        rs = list(self.reports.values())
        return [{"drafts": sum(r["status"] == "pending_review" and r["kind"] == "email" for r in rs),
                 "manual": sum(r["status"] == "pending_review" and r["kind"] == "manual" for r in rs),
                 "queued": sum(r["status"] in ("approved", "sending") for r in rs),
                 "sent": sum(r["status"] == "sent" for r in rs), "sent_24h": sum(r["status"] == "sent" for r in rs),
                 "failed": sum(r["status"] == "failed" for r in rs),
                 "domains_reported": len({r["domain_id"] for r in rs if r["status"] == "sent"})}]

    def unreported(self, p):
        return [{"id": d["id"], "registered_domain": d["registered_domain"], "unicode_domain": d.get("unicode_domain"),
                 "brand_id": d.get("brand_id"), "status_changed_at": d.get("status_changed_at"),
                 "status_by": d.get("status_by"), "final_score": d.get("final_score")}
                for d in self.domains.values() if d["status"] == "confirmed" and not d.get("takedown_at")
                and not any(r["domain_id"] == d["id"] for r in self.reports.values())]

    def web_list(self, key):
        want = {"drafts": lambda r: r["status"] == "pending_review" and r["kind"] == "email",
                "manual": lambda r: r["status"] == "pending_review" and r["kind"] == "manual",
                "queued": lambda r: r["status"] in ("approved", "sending"),
                "failed": lambda r: r["status"] == "failed", "sent": lambda r: r["status"] == "sent",
                "closed": lambda r: r["status"] in ("rejected", "skipped")}[key]
        return [self.joined(r) for r in self.reports.values() if want(r)]

    def web_lock(self, p):
        if p[0] not in self.reports:
            return []
        r = self.reports[p[0]]
        d = self.domains[r["domain_id"]]
        return [{"id": r["id"], "domain_id": r["domain_id"], "channel": r["channel"], "kind": r["kind"],
                 "status": r["status"], "payload": r["payload"], "domain_status": d["status"],
                 "takedown_at": d.get("takedown_at"), "registered_domain": d["registered_domain"]}]

    def web_save(self, p):
        self.reports[p[1]]["payload"].update(p[0])

    def web_approve(self, p):
        r = self.reports[p[2]]
        r.update(status="approved", attempts=0, next_attempt_at=NOW - MIN, error=None, reviewed_by=p[0])
        r["payload"].update(p[1])

    def web_mark_sent(self, p):
        r = self.reports[p[3]]
        r.update(status="sent", sent_at=NOW, sent_via="manual", sent_by=p[0], reviewed_by=p[1], error=None)
        r["payload"].update(p[2])

    def web_reject(self, p):
        self.reports[p[2]].update(status="rejected", reviewed_by=p[0], error=p[1])

    def web_retry(self, p):
        self.reports[p[1]].update(status="approved", attempts=0, next_attempt_at=NOW - MIN, error=None,
                                  reviewed_by=p[0])


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def connection(self):
        yield self.conn


@pytest.fixture
def fake(monkeypatch):
    holder = SimpleNamespace(db=FakeDB())

    async def pool():
        return FakePool(holder.db)
    monkeypatch.setattr(db, "pool", pool)

    def setup(**kw):
        holder.db = FakeDB(**kw)
        return holder.db
    return setup


def ok_netcraft(seen):
    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"message": "Successfully reported", "uuid": UUID, "invalid_urls": []})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def job(c, client=None):
    return run(engine.run_once(SimpleNamespace(settings=None, state={}), c, client))


def test_job_module():
    from cybercheck.jobs import report
    from cybercheck.worker import Job
    assert isinstance(report.JOB, Job) and report.JOB.name == "report" and 30 <= report.JOB.interval <= 120


def test_mode_off_touches_nothing(monkeypatch):
    async def no_pool():
        raise AssertionError("database used in mode off")
    monkeypatch.setattr(db, "pool", no_pool)
    assert job(cfg(reporting_mode="off")) == {"mode": "off"}


def test_confirmed_domain_end_to_end(fake):
    f = fake(domains=[dom()], pages=[page()])
    seen = []
    out = job(cfg(), ok_netcraft(seen))
    assert out["planned"] == 7 and out["sent"] == 1
    assert {r["channel"]: r["status"] for r in f.reports.values()} == {
        "netcraft": "sent", "registrar_abuse": "pending_review", "hosting_abuse": "pending_review",
        "brand:commbank": "pending_review", "scamwatch": "pending_review", "google_safe_browsing": "pending_review",
        "microsoft_smartscreen": "pending_review"}
    (req,) = seen
    assert req.url.host == "report.netcraft.com" and req.url.path == "/api/v3/report/urls"
    body = json.loads(req.content)
    assert body["email"] == "reports@cybercheck.example"
    assert [u["url"] for u in body["urls"]] == ["https://www.commbank-login.top/netbank/logon",
                                                "https://www.commbank-login.top/"]
    assert all(u["country"] == "AU" for u in body["urls"]) and "human reviewer" in body["reason"]
    (nc,) = f.by_channel("netcraft")
    assert nc["external_id"] == UUID and nc["sent_via"] == "api" and nc["response"]["uuid"] == UUID
    assert f.domains[1]["reported_at"] is not None
    assert [(e[1], e[2]["channel"]) for e in f.events] == [("reported", "netcraft")]
    assert [a["ok"] for a in f.attempts] == [True]
    reg = f.by_channel("registrar_abuse")[0]["payload"]
    assert reg["to"] == "abuse@registrar.example" and "commbank-login.top" in reg["body"] and reg["ai"] == "unavailable"
    # second run: nothing new, nothing resent
    out = job(cfg(), ok_netcraft(seen))
    assert "planned" not in out and len(seen) == 1 and len(f.reports) == 7


def test_rate_limit_and_channel_interval_make_items_wait(fake):
    f = fake(domains=[dom(), dom(id=2, registered_domain="commbank-verify.top", hostnames=["commbank-verify.top"])],
             attempts_last_hour=9)
    seen = []
    out = job(cfg(), ok_netcraft(seen))
    assert out["sent"] == 1 and len(seen) == 1                 # 9 + 1 = the hourly limit of 10
    assert sorted(r["status"] for r in f.by_channel("netcraft")) == ["approved", "sent"]
    f.attempts = [a for a in f.attempts if a["channel"] == "netcraft"]   # hourly budget free again
    out = job(cfg(), ok_netcraft(seen))
    assert out.get("sent", 0) == 0 and out["waiting"] == 1     # Netcraft was used less than 60 s ago
    f.attempts[0]["at"] -= 2 * MIN
    assert job(cfg(), ok_netcraft(seen))["sent"] == 1
    assert [r["status"] for r in f.by_channel("netcraft")] == ["sent", "sent"]


def test_failures_back_off_then_fail(fake):
    f = fake(domains=[dom()])
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503, text="down")))
    c = cfg({"REPORT_MAX_ATTEMPTS": "2"})
    job(c, client)
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "approved" and nc["attempts"] == 1 and "503" in nc["error"]
    assert nc["next_attempt_at"] > datetime.now(UTC) + 4 * MIN       # back-off, not an immediate retry
    nc["next_attempt_at"] = NOW - MIN
    f.attempts[-1]["at"] -= 5 * MIN
    job(c, client)
    assert nc["status"] == "failed" and nc["attempts"] == 2 and f.domains[1]["reported_at"] is None
    assert f.events == []


def test_429_pauses_the_channel(fake):
    f = fake(domains=[dom()])
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(429, json={"message": "Too many urls reported"}, headers={"retry-after": "1800"})))
    job(cfg({"REPORT_MAX_ATTEMPTS": "1"}), client)
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "approved"                 # 429 never turns into 'failed': it waits
    assert nc["next_attempt_at"] > datetime.now(UTC) + 25 * MIN
    assert "netcraft" in f.kv[engine.KV_PAUSE]


def test_closed_domains_are_never_sent(fake):
    f = fake(domains=[dom()])
    job(cfg(reporting_mode="off"))            # nothing at all in mode off
    assert f.reports == {}
    f.domains[1]["status"] = "confirmed"
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    f.domains[1]["status"] = "false_positive"
    seen = []
    out = job(cfg(), ok_netcraft(seen))
    assert seen == [] and out["cancelled"] == 7
    assert {r["status"] for r in f.reports.values()} == {"skipped"}


def test_official_domains_are_never_reported(fake):
    f = fake(domains=[dom(registered_domain="commbank.com.au", hostnames=["commbank.com.au"])])
    seen = []
    job(cfg(), ok_netcraft(seen))
    assert f.reports == {} and seen == []


def test_auto_mode_reports_only_automated_channels(fake, tmp_path):
    f = fake(domains=[dom(status="open", status_changed_at=None, status_by=None)], pages=[page()])
    c = cfg(reporting_mode="auto", data_dir=tmp_path)
    seen = []
    assert job(c, ok_netcraft(seen)).get("auto_planned", 0) == 0 and seen == []     # no sandbox file yet
    write_sandbox(tmp_path)
    out = job(c, ok_netcraft(seen))
    assert out["auto_planned"] == 1 and out["sent"] == 1
    assert [(r["channel"], r["auto"], r["status"]) for r in f.reports.values()] == [("netcraft", True, "sent")]
    assert "not yet reviewed by a person" in json.loads(seen[0].content)["reason"]
    assert f.events[0][2]["reviewed_by_human"] is False
    # the reviewer confirms later: email and manual drafts follow, Netcraft is not sent twice
    f.domains[1].update(status="confirmed", status_changed_at=NOW)
    job(c, ok_netcraft(seen))
    assert len(seen) == 1 and len(f.reports) == 7


def test_auto_mode_rechecks_before_sending(fake, tmp_path):
    f = fake(domains=[dom(status="open")], pages=[page()])
    write_sandbox(tmp_path)
    c = cfg(reporting_mode="auto", data_dir=tmp_path, report_rate_per_hour=0)
    job(c)                                                   # planned, but the rate limit holds it
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "approved" and nc["auto"]
    f.pages.append(page(i=11, ago=MIN, has_password_field=False))    # newest snapshot: form gone
    seen = []
    job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    assert seen == [] and nc["status"] == "skipped" and "automatic-report rules" in nc["error"]


def test_auto_mode_never_for_false_positive_or_low_score(fake, tmp_path):
    write_sandbox(tmp_path)
    f = fake(domains=[dom(id=1, status="false_positive"), dom(id=2, registered_domain="b-commbank.top", status="open",
                                                              final_score=89), dom(id=3, registered_domain="c-commbank.top", status="benign")],
             pages=[page(domain_id=i, i=i) for i in (1, 2, 3)])
    seen = []
    job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    assert f.reports == {} and seen == []


def test_email_waits_for_smtp_and_sends_when_configured(fake, fake_smtp):
    f = fake(domains=[dom()], pages=[page()])
    run(engine.plan_for_domain(f, cfg(reporter_email=""), f.with_have(f.domains[1]), "confirmed"))
    reg = f.by_channel("registrar_abuse")[0]
    reg.update(status="approved")                            # as the dashboard's approve does
    job(cfg(reporter_email=""))
    assert reg["status"] == "approved" and "SMTP" in reg["error"] and reg["next_attempt_at"] > datetime.now(UTC)
    reg["next_attempt_at"] = NOW - MIN
    job(cfg(SMTP_ENV, reporter_email=""))
    assert reg["status"] == "sent" and reg["sent_via"] == "smtp"
    s = fake_smtp.instances[0]
    assert s.calls[1] == "starttls" and s.msg["To"] == "abuse@registrar.example"
    assert f.events[-1][2]["channel"] == "registrar_abuse"


def test_auto_flagged_email_is_never_sent(fake, fake_smtp):
    f = fake(domains=[dom()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    reg = f.by_channel("registrar_abuse")[0]
    reg.update(status="approved", auto=True)
    job(cfg(SMTP_ENV, reporter_email=""))
    assert reg["status"] == "skipped" and fake_smtp.instances == []


def test_ai_drafts(fake, monkeypatch):
    from cybercheck.ai import api
    calls = []

    async def draft(conn, domain, channel, facts_):
        calls.append((channel, sorted(facts_)))
        return "The site at commbank-login.top imitates the CommBank NetBank login page and asks for a password."
    monkeypatch.setattr(api, "draft_report", draft)
    f = fake(domains=[dom()], pages=[page()])
    out = job(cfg(reporter_email=""))
    assert out["ai_drafts"] == 3 and {c for c, _ in calls} == {"registrar_abuse", "hosting_abuse", "brand:commbank"}
    assert all("rev@example.org" not in str(k) for _, k in calls)
    body = f.by_channel("brand:commbank")[0]["payload"]["body"]
    assert body.startswith("The site at") and "How this was found" in body


def test_reviewer_edits_are_not_overwritten_by_ai(fake, monkeypatch):
    from cybercheck.ai import api
    f = fake(domains=[dom()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    for r in f.reports.values():
        if r["kind"] == "email":
            r["payload"].update(body="my text", ai="edited")

    async def draft(*a):
        raise AssertionError("AI called for an edited draft")
    monkeypatch.setattr(api, "draft_report", draft)
    job(cfg(reporter_email=""))
    assert all(r["payload"]["body"] == "my text" for r in f.reports.values() if r["kind"] == "email")


def test_netcraft_screenshot_is_attached_as_jpeg(fake, tmp_path):
    from PIL import Image
    (tmp_path / "screenshots" / "1").mkdir(parents=True)
    Image.new("RGB", (400, 800), (200, 30, 30)).save(tmp_path / "screenshots" / "1" / "10.webp", "WEBP")
    fake(domains=[dom()], pages=[page()])
    seen = []
    job(cfg(data_dir=tmp_path), ok_netcraft(seen))
    shot = json.loads(seen[0].content)["urls"][0]["screenshot"]
    assert shot["ext"] == "jpg" and base64.standard_b64decode(shot["base64"])[:2] == b"\xff\xd8"
    assert evidence.screenshot_jpeg(tmp_path, "../../etc/passwd") is None


# =====================================================================================================
# dashboard
# =====================================================================================================

@pytest.fixture
def web(monkeypatch, fake, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from cybercheck.web import pages_reports
    from cybercheck.web.common import templates

    state = SimpleNamespace(cfg=cfg(data_dir=tmp_path))
    monkeypatch.setattr(pages_reports, "load_config", lambda: state.cfg)
    hostile = dom(id=7, registered_domain="<script>alert(1)</script>.top", hostnames=["x.top"])
    f = fake(domains=[dom(), hostile, dom(id=3, registered_domain="open-commbank.top", status="open"),
                      dom(id=4, registered_domain="commbank-pay.top", hostnames=["commbank-pay.top"])],
             pages=[page(), page(i=70, domain_id=7, url="https://x.top/\"><img src=x onerror=alert(1)>",
                                 final_url=None)])
    run(engine.plan_for_domain(f, state.cfg, f.with_have(f.domains[1]), "confirmed"))
    app = FastAPI()
    nav: list = []
    pages_reports.register(app, templates, nav)
    assert nav == [("/reports", "Reports")]
    # the dashboard only answers on its own addresses (web.common.allowed_hosts): use one of them
    client = TestClient(app, base_url="http://127.0.0.1:8430")
    client.db, client.state = f, state
    return client


def rid(f, channel, domain_id=1):
    return next(r["id"] for r in f.reports.values() if r["channel"] == channel and r["domain_id"] == domain_id)


def test_page_renders_banner_and_escapes(web):
    f = web.db
    f.reports[rid(f, "scamwatch")]["payload"]["fields"][0]["value"] = "<script>alert(2)</script>"
    r = web.get("/reports?msg=created")
    assert r.status_code == 200
    t = r.text
    assert "Report drafts created." in t and "Mode:" in t and ">review<" in t
    assert "SMTP is off" in t and "Off, and why" in t
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in t and "<script>alert(2)" not in t
    assert 'action="/reports/create/4"' in t            # confirmed, not reported yet
    assert "https://forms.scamwatch.gov.au/report-a-scamwebsite/" in t
    assert 'href="https://www.commbank-login.top' not in t and "href=\"http://" not in t   # reported URLs never links
    assert "mailto:abuse%40registrar.example" not in t and "mailto:abuse@registrar.example?subject=" in t
    assert web.get("/reports?msg=<b>x</b>").status_code == 200
    assert "<b>x</b>" not in web.get("/reports?msg=<b>x</b>").text
    detail = web.get(f"/reports/{rid(f, 'netcraft')}")
    assert detail.status_code == 200 and "Netcraft report API" in detail.text
    assert web.get("/reports/999999").status_code == 404


def test_hostile_domain_name_is_escaped(web):
    f = web.db
    run(engine.plan_for_domain(f, web.state.cfg, f.with_have(f.domains[7]), "confirmed"))
    t = web.get("/reports").text
    assert "<script>alert(1)</script>" not in t and "&lt;script&gt;alert(1)&lt;/script&gt;.top" in t
    assert "<img src=x" not in t


def test_posts_require_same_origin(web):
    f = web.db
    r1 = rid(f, "registrar_abuse")
    before = {k: dict(v) for k, v in f.reports.items()}
    paths = ["/reports/create/4"] + [f"/reports/{r1}/{a}" for a in ("save", "approve", "sent", "reject", "retry")]
    for path in paths:
        assert web.post(path, headers={"origin": "https://evil.example"}, follow_redirects=False).status_code == 403
        assert web.post(path, headers={"sec-fetch-site": "cross-site"}, follow_redirects=False).status_code == 403
    assert {k: dict(v) for k, v in f.reports.items()} == before and f.events == []


def test_mark_email_sent_records_report(web):
    f = web.db
    r1 = rid(f, "registrar_abuse")
    r = web.post(f"/reports/{r1}/sent", data={"to": "abuse@registrar.example", "subject": "S", "body": "B"},
                 headers={"tailscale-user-login": "rev@example.org"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/reports?msg=sent#r{r1}"
    rep = f.reports[r1]
    assert rep["status"] == "sent" and rep["sent_via"] == "manual" and rep["sent_by"] == "rev@example.org"
    assert rep["payload"]["body"] == "B" and f.domains[1]["reported_at"] is not None
    assert f.events[-1][1] == "reported" and f.events[-1][2]["channel"] == "registrar_abuse"
    # already sent: a second click changes nothing
    assert web.post(f"/reports/{r1}/sent", data={"to": "a@b.example"}, follow_redirects=False).headers[
        "location"].startswith("/reports?msg=not_pending")
    assert len(f.events) == 1


def test_manual_item_done(web):
    f = web.db
    r1 = rid(f, "scamwatch")
    r = web.post(f"/reports/{r1}/sent", data={"back": "detail"}, follow_redirects=False)
    assert r.headers["location"] == f"/reports/{r1}?msg=done"
    assert f.reports[r1]["status"] == "sent" and f.events[-1][2]["channel"] == "scamwatch"


def test_approve_rules(web, fake_smtp):
    f = web.db
    r1 = rid(f, "registrar_abuse")
    data = {"to": "abuse@registrar.example", "subject": "S", "body": "B"}
    assert "msg=no_smtp" in web.post(f"/reports/{r1}/approve", data=data, follow_redirects=False).headers["location"]
    assert f.reports[r1]["status"] == "pending_review" and f.reports[r1]["payload"]["body"] == "B"
    web.state.cfg = cfg(SMTP_ENV, data_dir=web.state.cfg.data_dir)
    bad = {**data, "to": "abuse@registrar.example?cc=x@evil.example\n"}
    assert "msg=bad_to" in web.post(f"/reports/{r1}/approve", data=bad, follow_redirects=False).headers["location"]
    f.domains[1]["status"] = "open"
    assert "msg=not_confirmed" in web.post(f"/reports/{r1}/approve", data=data,
                                           follow_redirects=False).headers["location"]
    f.domains[1]["status"] = "confirmed"
    r = web.post(f"/reports/{r1}/approve", data=data, headers={"tailscale-user-login": "rev@example.org"},
                 follow_redirects=False)
    assert "msg=queued" in r.headers["location"]
    assert f.reports[r1]["status"] == "approved" and f.reports[r1]["reviewed_by"] == "rev@example.org"
    assert fake_smtp.instances == []                    # the web never sends: the worker does, rate-limited


def test_save_marks_ai_pending_as_edited(web):
    f = web.db
    r1 = rid(f, "brand:commbank")
    f.reports[r1]["payload"]["ai"] = "pending"
    web.post(f"/reports/{r1}/save", data={"to": "hoax@cba.com.au", "subject": "S", "body": "mine"})
    assert f.reports[r1]["payload"]["ai"] == "edited" and f.reports[r1]["payload"]["body"] == "mine"


def test_reject_and_retry(web):
    f = web.db
    r1 = rid(f, "hosting_abuse")
    web.post(f"/reports/{r1}/reject", data={"note": "wrong host"})
    assert f.reports[r1]["status"] == "rejected" and "wrong host" in f.reports[r1]["error"]
    assert "not_pending" in web.post(f"/reports/{r1}/reject", follow_redirects=False).headers["location"]
    nc = rid(f, "netcraft")
    f.reports[nc].update(status="failed", attempts=5)
    assert "msg=retry" in web.post(f"/reports/{nc}/retry", follow_redirects=False).headers["location"]
    assert f.reports[nc]["status"] == "approved" and f.reports[nc]["attempts"] == 0
    sw = rid(f, "scamwatch")
    assert "not_api" in web.post(f"/reports/{sw}/retry", follow_redirects=False).headers["location"]


def test_create_on_demand(web):
    f = web.db
    assert "msg=created" in web.post("/reports/create/4", follow_redirects=False).headers["location"]
    assert len([r for r in f.reports.values() if r["domain_id"] == 4]) == 7
    assert "msg=nothing" in web.post("/reports/create/4", follow_redirects=False).headers["location"]
    assert "not_confirmed" in web.post("/reports/create/3", follow_redirects=False).headers["location"]
    assert web.post("/reports/create/999", follow_redirects=False).status_code == 404
    f.domains[4]["takedown_at"] = NOW
    assert "taken_down" in web.post("/reports/create/4", follow_redirects=False).headers["location"]


def test_screenshot_download(web):
    from PIL import Image
    data_dir = web.state.cfg.data_dir
    (data_dir / "screenshots" / "1").mkdir(parents=True)
    Image.new("RGB", (300, 500), (10, 120, 10)).save(data_dir / "screenshots" / "1" / "10.webp", "WEBP")
    f = web.db
    r = web.get(f"/reports/{rid(f, 'scamwatch')}/screenshot.jpg")
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg" and r.content[:2] == b"\xff\xd8"
    assert r.headers["content-security-policy"] == "default-src 'none'"
    assert r.headers["content-disposition"].startswith("attachment;")
    f.reports[rid(f, "scamwatch")]["payload"]["page_id"] = 70        # a page of another domain
    assert web.get(f"/reports/{rid(f, 'scamwatch')}/screenshot.jpg").status_code == 404


def test_mailto_link_cannot_add_recipients():
    from cybercheck.web.pages_reports import mailto_link
    link = mailto_link("a?cc=x@evil.example", "Phishing report: x", "line 1\nline 2 & more")
    assert link.startswith("mailto:a%3Fcc%3Dx@evil.example?subject=Phishing%20report%3A%20x&body=line%201%0Aline")
    assert "&cc=" not in link and mailto_link("not an address", "s", "b") is None


def test_templates_never_mark_text_safe():
    for path in (ROOT / "cybercheck" / "web" / "templates").glob("reports_*.html"):
        text = path.read_text()
        assert not re.search(r"\|\s*safe\b", text) and "autoescape false" not in text, path.name
        # page scripts load from /static (script-src 'self'); never an inline <script> block
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path.name
        assert not re.search(r"<script[^>]*\bsrc=\"(?!\{\{ asset\()", text), path.name


def test_app_registers_reports_page():
    import cybercheck.web.app as app_mod
    assert ("/reports", "Reports") in app_mod.NAV
    paths = {getattr(r, "path", "") for r in app_mod.app.routes}
    assert {"/reports", "/reports/create/{domain_id}", "/reports/{report_id}/approve"} <= paths


# =====================================================================================================
# review hardening: invariants that must hold whatever state the queue is in
# =====================================================================================================

def test_auto_candidates_sql_prefilters_like_auto_eligible():
    sql = engine.AUTO_CANDIDATES_SQL
    for needle in ("d.status = 'open'", "d.ai_verdict = 'phishing'", "d.takedown_at IS NULL",
                   "COALESCE(d.ai_confidence, 0) >= 0.7", "'.gov.au'", "p.error IS NULL",
                   "p.has_password_field OR p.has_otp_field OR p.has_card_field",
                   "max(p2.fetched_at)", "interval '15 minutes'"):
        assert needle in sql
    assert "%%" not in sql and sql.count("%s") == 4          # min score, channels, NETCRAFT_TEST, limit


def test_stale_high_scores_do_not_starve_auto_reports(fake, tmp_path):
    """Domains whose newest snapshot errored keep a high final_score (the judge skips error pages): they
    must not fill the candidate LIMIT forever and block an eligible domain."""
    write_sandbox(tmp_path)
    stale = [dom(id=i, registered_domain=f"commbank-{i}.top", hostnames=[f"commbank-{i}.top"], status="open",
                 final_score=99) for i in range(1, 31)]
    pages_ = []
    for i in range(1, 31):
        pages_.append(page(i=1000 + i, domain_id=i, ago=2 * HOUR))
        pages_.append(page(i=2000 + i, domain_id=i, ago=MIN, error="timeout", http_status=None))
    good = dom(id=500, registered_domain="commbank-good.top", hostnames=["commbank-good.top"], status="open",
               final_score=91)
    pages_.append(page(i=5000, domain_id=500, url="https://commbank-good.top/",
                       final_url="https://commbank-good.top/login"))
    f = fake(domains=stale + [good], pages=pages_)
    seen = []
    out = job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    assert out["auto_planned"] == 1 and out["sent"] == 1
    assert [(r["domain_id"], r["status"]) for r in f.reports.values()] == [(500, "sent")]
    sent_urls = {u["url"] for u in json.loads(seen[0].content)["urls"]}
    assert sent_urls <= {"https://commbank-good.top/", "https://commbank-good.top/login"} and sent_urls


def test_unconfirmed_domain_is_never_sent_by_a_non_auto_row(fake):
    f = fake(domains=[dom()], pages=[page()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    f.domains[1]["status"] = "open"                      # the reviewer took the confirmation back
    seen = []
    job(cfg(reporting_mode="auto"), ok_netcraft(seen))   # even in auto mode (no sandbox file here)
    (nc,) = f.by_channel("netcraft")
    assert seen == [] and nc["status"] == "skipped" and "no longer confirmed" in nc["error"]
    assert f.attempts == [] and f.domains[1]["reported_at"] is None


def test_queued_auto_row_is_skipped_when_mode_leaves_auto(fake, tmp_path):
    write_sandbox(tmp_path)
    f = fake(domains=[dom(status="open")], pages=[page()])
    job(cfg(reporting_mode="auto", data_dir=tmp_path, report_rate_per_hour=0))
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "approved" and nc["auto"]
    seen = []
    job(cfg(reporting_mode="review", data_dir=tmp_path), ok_netcraft(seen))
    assert seen == [] and nc["status"] == "skipped" and "not auto" in nc["error"]


def test_queued_auto_row_is_skipped_when_sandbox_expires(fake, tmp_path):
    write_sandbox(tmp_path)
    f = fake(domains=[dom(status="open")], pages=[page()])
    job(cfg(reporting_mode="auto", data_dir=tmp_path, report_rate_per_hour=0))
    write_sandbox(tmp_path, verified_at=(NOW - 31 * DAY).isoformat())
    seen = []
    job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    (nc,) = f.by_channel("netcraft")
    assert seen == [] and nc["status"] == "skipped" and "days old" in nc["error"]


def test_manual_and_auto_email_rows_are_never_sent(fake, fake_smtp):
    f = fake(domains=[dom()], pages=[page()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    for r in f.reports.values():
        if r["kind"] == "manual":
            r.update(status="approved")                  # a corrupted / forged queue state
    reg = f.by_channel("registrar_abuse")[0]
    reg.update(status="approved", auto=True)
    job(cfg(reporter_email=""))                          # no SMTP: the auto email must be skipped, not held
    assert reg["status"] == "skipped" and "never sent automatically" in reg["error"]
    assert all(r["status"] == "skipped" for r in f.reports.values() if r["kind"] == "manual")
    assert fake_smtp.instances == [] and f.attempts == []


def test_rate_limit_is_global_across_channels(fake, fake_smtp):
    f = fake(domains=[dom()], pages=[page()], attempts_last_hour=9)
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    f.by_channel("registrar_abuse")[0].update(status="approved")
    seen = []
    out = job(cfg(SMTP_ENV), ok_netcraft(seen))
    assert out["sent"] == 1 and out["rate_limited"]
    assert len(seen) + len(fake_smtp.instances) == 1
    assert sorted(r["status"] for r in f.reports.values() if r["kind"] != "manual" and r["status"] != "pending_review") \
        == ["approved", "sent"]                          # the other one waits; nothing is dropped


def test_planning_twice_creates_no_duplicates(fake):
    f = fake(domains=[dom()], pages=[page()])
    c = cfg(reporting_mode="off")
    first = run(engine.plan_for_domain(f, c, f.with_have(f.domains[1]), "confirmed"))
    stale = f.with_have(f.domains[1]) | {"have": []}     # a concurrent planner that read 'have' too early
    second = run(engine.plan_for_domain(f, c, stale, "confirmed"))
    assert first and second == [] and len(f.reports) == len(first)


def test_report_urls_encode_hidden_characters():
    u = evidence.clean_url("https://www.commbank-login.top/log‮on/​?q=é", "commbank-login.top")
    assert u == "https://www.commbank-login.top/log%E2%80%AEon/%E2%80%8B?q=%C3%A9"
    assert evidence.clean_url("https://www.commbank-login.top/a%20b", "commbank-login.top").endswith("a%20b")
    assert evidence.clean_url("https://commbank.com.au‥evil.top/", "commbank-login.top") is None
    assert evidence.clean_url("https://x.top/" + "é" * 200, "x.top") is None      # too long once encoded


def test_network_country_is_claimed_only_for_the_verified_egress_ip():
    p = page(egress_ip="203.0.113.99")
    f = evidence.build_facts(dom(), p, [p], egress_country="AU", egress_ip="198.51.100.1")
    assert f["egress_country"] is None
    body = texts.email_template("registrar_abuse", f, cfg())
    assert "Australian network" not in body
    assert evidence.build_facts(dom(), page(), [page()], egress_country="AU")["egress_country"] is None
    assert evidence.build_facts(dom(), page(), [page()], egress_country="AU",
                                egress_ip="198.51.100.1")["egress_country"] == "AU"


def test_netcraft_status_history_keeps_changes_only():
    s1 = {"state": "processing", "urls": [{"url": "https://a.top/", "url_state": "processing"}]}
    h = engine.status_history({}, s1, "t1")
    assert [e["state"] for e in h] == ["processing"]
    assert engine.status_history({"status": s1, "status_history": h}, dict(s1), "t2") is None
    s2 = {"state": "malicious", "urls": [{"url": "https://a.top/", "url_state": "malicious",
                                          "url_takedown_state": "in progress"}]}
    h2 = engine.status_history({"status": s1, "status_history": h}, s2, "t3")
    assert [e["at"] for e in h2] == ["t1", "t3"] and h2[-1]["urls"][0]["url_takedown_state"] == "in progress"
    long = [{"at": str(i)} for i in range(engine.HISTORY_MAX)]
    assert len(engine.status_history({"status": s1, "status_history": long}, s2, "x")) == engine.HISTORY_MAX


def test_auto_threshold_above_100_switches_auto_sends_off():
    c = cfg(reporting_mode="auto", auto_report_min_final_score=101)
    assert c.min_final_score == 101
    ok, why = evidence.auto_eligible(dom(status="open", final_score=100), [page()], c, sandbox_ok())
    assert not ok and "below 101" in why
    assert any(w == "AUTO_REPORT_MIN_FINAL_SCORE" for w, _ in channels.disabled(c))
    assert cfg(auto_report_min_final_score=95).min_final_score == 95


def test_brand_that_wants_no_screenshot_gets_no_mention_of_one(fake):
    f = fake(domains=[dom(brand_id="auspost", registered_domain="auspost-redeliver.top",
                          hostnames=["auspost-redeliver.top"])],
             pages=[page(url="https://auspost-redeliver.top/", final_url=None)])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    ap = f.by_channel("brand:auspost")[0]["payload"]
    assert ap["to"] == "scams@auspost.com.au" and ap["attach_screenshot"] is False
    assert "Screenshot" not in ap["body"] and ap["facts"]["screenshot"] is False
    reg = f.by_channel("registrar_abuse")[0]["payload"]
    assert reg["attach_screenshot"] is True and "Screenshot: captured" in reg["body"]


# =====================================================================================================
# regressions from the security review
# =====================================================================================================

def test_auto_report_floor_is_90():
    """confidence.py caps final_score at 89 without credential evidence plus an AI verdict: a lowered
    AUTO_REPORT_MIN_FINAL_SCORE must not let name-only domains be reported automatically."""
    for configured in (9, 80, 85, 89):
        c = cfg(reporting_mode="auto", auto_report_min_final_score=configured)
        assert c.min_final_score == 90 and c.configured_min_final_score == configured
        ok, why = evidence.auto_eligible(dom(status="open", final_score=89), [page()], c, sandbox_ok())
        assert not ok and "below 90" in why
        assert dict(channels.disabled(c))["AUTO_REPORT_MIN_FINAL_SCORE"].endswith("(never below 90)")
    assert cfg(auto_report_min_final_score=150).min_final_score == 150      # still switches auto sends off


KIT = "https://netbank-commbank-login.someplumber.com.au/"
PLUMBER = dict(registered_domain="someplumber.com.au", tld="com.au",
               hostnames=["netbank-commbank-login.someplumber.com.au"], registrar_abuse_email=None)


def plumber_pages() -> list[dict]:
    """A kit on a hacked small-business site that cloaks some visitors to the business's home page."""
    return [page(i=1, ago=10 * MIN, url=KIT, final_url=KIT + "login.php"),
            # same fetch run, other browser profile: cloaked, sent to the real home page
            page(i=2, ago=12 * MIN, url=KIT, final_url="https://someplumber.com.au/", has_password_field=False,
                 screenshot_path=None),
            # same run: the real shop's own account page has a password field too
            page(i=3, ago=11 * MIN, url=KIT, final_url="https://www.someplumber.com.au/my-account",
                 screenshot_path=None),
            # an older run, cloaked
            page(i=4, ago=6 * HOUR, url=KIT, final_url="https://someplumber.com.au/", has_password_field=False)]


def test_report_urls_come_from_the_evidence_on_lookalike_hostnames_only():
    pages = plumber_pages()
    for d, chosen in ((dom(status="open", **PLUMBER), evidence.credential_page(pages)),
                      (dom(**PLUMBER), evidence.best_page(pages))):
        assert chosen["id"] == 1
        assert [p["id"] for p in evidence.evidence_pages(pages, chosen)] == [1, 3]    # 2: no form, 4: older
        assert evidence.build_facts(d, chosen, pages)["urls"] == [KIT + "login.php", KIT]
    # even given every snapshot, nothing off the hostnames seen in certificates
    assert evidence.report_urls(dom(**PLUMBER), pages) == [KIT + "login.php", KIT]
    # no page to go on: the lookalike hostname, never the business's own domain
    assert evidence.build_facts(dom(**PLUMBER), None, pages)["urls"] == [KIT]


def test_automatic_netcraft_report_never_names_the_hacked_sites_home_page(fake, tmp_path):
    write_sandbox(tmp_path)
    f = fake(domains=[dom(status="open", status_changed_at=None, **PLUMBER)], pages=plumber_pages())
    seen = []
    out = job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    assert out["sent"] == 1
    urls = [u["url"] for u in json.loads(seen[0].content)["urls"]]
    assert urls == [KIT + "login.php", KIT]
    assert not any("//someplumber.com.au" in u or "//www.someplumber.com.au" in u for u in urls)
    assert f.by_channel("netcraft")[0]["payload"]["urls"] == urls


def _age_attempts(f, by=2 * MIN):
    for a in f.attempts:
        a["at"] -= by


def test_netcraft_test_submission_is_not_a_report_and_production_follows(fake):
    f = fake(domains=[dom()], pages=[page()])
    seen = []
    test_cfg = cfg({"NETCRAFT_TEST": "true"})
    out = job(test_cfg, ok_netcraft(seen))
    assert out["test"] == 1 and out["sent"] == 0
    (req,) = seen
    assert req.url.path == "/api/v3/test/report/urls"
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "skipped" and nc["response"]["test"] is True and nc["external_id"] == UUID
    assert "NETCRAFT_TEST" in nc["error"]
    assert f.domains[1]["reported_at"] is None and not any(e[1] == "reported" for e in f.events)
    # still in test mode: never to the test endpoint twice
    _age_attempts(f)
    job(test_cfg, ok_netcraft(seen))
    assert len(seen) == 1 and nc["status"] == "skipped"
    # test mode off: the real report goes out, once
    _age_attempts(f)
    out = job(cfg(), ok_netcraft(seen))
    assert out["sent"] == 1 and seen[-1].url.path == "/api/v3/report/urls"
    assert nc["status"] == "sent" and nc["response"]["test"] is False and nc["auto"] is False
    assert f.domains[1]["reported_at"] is not None
    assert [(e[1], e[2]["channel"]) for e in f.events] == [("reported", "netcraft")]
    _age_attempts(f)
    job(cfg(), ok_netcraft(seen))
    assert len(seen) == 2


def test_netcraft_test_submission_of_an_unreviewed_domain(fake, tmp_path):
    write_sandbox(tmp_path)
    f = fake(domains=[dom(status="open", status_changed_at=None)], pages=[page()])
    seen = []
    test_cfg = cfg({"NETCRAFT_TEST": "true"}, reporting_mode="auto", data_dir=tmp_path)
    job(test_cfg, ok_netcraft(seen))
    (nc,) = f.by_channel("netcraft")
    assert nc["status"] == "skipped" and nc["auto"] and seen[0].url.path.startswith("/api/v3/test/")
    _age_attempts(f)
    job(test_cfg, ok_netcraft(seen))
    assert len(seen) == 1
    _age_attempts(f)
    out = job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen))
    assert out["auto_planned"] == 1 and out["sent"] == 1 and seen[-1].url.path == "/api/v3/report/urls"
    assert nc["status"] == "sent" and nc["auto"] is True and len(f.reports) == 1
    assert "not yet reviewed by a person" in json.loads(seen[-1].content)["reason"]
    # a test row of a domain that no longer qualifies is not revived for automatic sending
    f2 = fake(domains=[dom(status="open", final_score=80)], pages=[page()])
    run(engine.plan_for_domain(f2, cfg(reporting_mode="auto"), f2.with_have(f2.domains[1]), "auto"))
    f2.reports[next(iter(f2.reports))].update(status="skipped", response={"test": True})
    assert job(cfg(reporting_mode="auto", data_dir=tmp_path), ok_netcraft(seen)).get("auto_planned", 0) == 0


def test_old_test_submissions_recorded_as_sent_are_released(fake):
    f = fake(domains=[dom(reported_at=NOW - DAY)], pages=[page()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    nc = f.by_channel("netcraft")[0]
    nc.update(status="sent", external_id=UUID, response={"uuid": UUID, "test": True})
    released = run(engine.release_test_sends(f))
    assert released == 1 and nc["status"] == "skipped" and f.domains[1]["reported_at"] is None
    seen = []
    out = job(cfg(), ok_netcraft(seen))
    assert out["sent"] == 1 and seen[0].url.path == "/api/v3/report/urls" and nc["status"] == "sent"
    # a domain that really was reported another way keeps its reported_at
    f2 = fake(domains=[dom(reported_at=NOW - DAY)], pages=[page()])
    run(engine.plan_for_domain(f2, cfg(), f2.with_have(f2.domains[1]), "confirmed"))
    f2.by_channel("netcraft")[0].update(status="sent", response={"test": True})
    f2.by_channel("scamwatch")[0].update(status="sent")
    assert run(engine.release_test_sends(f2)) == 1 and f2.domains[1]["reported_at"] == NOW - DAY
    sql = " ".join(engine.RELEASE_TEST_SQL.split())
    assert "status = 'sent' AND response->>'test' = 'true'" in sql
    assert "COALESCE(r.response->>'test', '') <> 'true'" in sql      # the snapshot still shows test rows as sent


def test_recipient_on_the_reported_domain_is_withheld():
    for addr in ("abuse@commbank-login.top", "Abuse@Mail.Commbank-Login.TOP", "noc@www.commbank-login.top"):
        to, hint = texts.recipient("hosting_abuse", dom(hosting_abuse_email=addr))
        assert to == "" and "reported domain itself" in hint and addr in hint
        assert texts.recipient_warning("hosting_abuse", dom(hosting_abuse_email=addr)) == hint
    to, hint = texts.recipient("registrar_abuse", dom(registrar_abuse_email="abuse@commbank-login.top"))
    assert to == "" and "reported domain itself" in hint
    to, hint = texts.recipient("hosting_abuse", dom(hosting_abuse_email="noc@mx.evil-host.top"),
                               frozenset({"evil-host.top"}))
    assert to == "" and "evil-host.top, a domain CyberCheck tracks as suspicious" in hint
    # unrelated or merely similar names are fine
    assert texts.recipient("hosting_abuse", dom())[0] == "abuse@host.example"
    assert texts.contact_warning("abuse@xcommbank-login.top", dom()) == ""
    assert texts.recipient_warning("hosting_abuse", dom()) == ""
    assert texts.recipient("brand:commbank", dom())[0] == "hoax@cba.com.au"


def test_planned_drafts_are_never_addressed_to_the_attacker(fake):
    f = fake(domains=[dom(hosting_abuse_email="abuse@commbank-login.top",
                          registrar_abuse_email="abuse@shady-registrar.top"),
                      dom(id=2, registered_domain="shady-registrar.top", status="open",
                          hostnames=["shady-registrar.top"])],
             pages=[page()])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    host = f.by_channel("hosting_abuse")[0]["payload"]
    reg = f.by_channel("registrar_abuse")[0]["payload"]
    assert host["to"] == "" and "reported domain itself" in host["to_warning"]
    assert reg["to"] == "" and "shady-registrar.top" in reg["to_warning"]
    brand = f.by_channel("brand:commbank")[0]["payload"]
    assert brand["to"] == "hoax@cba.com.au" and brand["to_warning"] == ""


def test_worker_never_emails_the_reported_domain(fake, fake_smtp):
    f = fake(domains=[dom(), dom(id=2, registered_domain="shady-host.top", status="confirmed",
                                 hostnames=["shady-host.top"])])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    reg, host = f.by_channel("registrar_abuse")[0], f.by_channel("hosting_abuse")[0]
    reg["payload"]["to"] = "abuse@commbank-login.top"
    host["payload"]["to"] = "abuse@shady-host.top"
    reg.update(status="approved")
    host.update(status="approved")
    job(cfg(SMTP_ENV, reporter_email=""))
    assert reg["status"] == "skipped" and "reported domain itself" in reg["error"]
    assert host["status"] == "skipped" and "shady-host.top" in host["error"]
    assert fake_smtp.instances == []


def test_approve_refuses_an_address_that_may_be_the_attackers(web, fake_smtp):
    f = web.db
    web.state.cfg = cfg(SMTP_ENV, data_dir=web.state.cfg.data_dir)
    r1 = rid(f, "hosting_abuse")
    data = {"to": "abuse@www.commbank-login.top", "subject": "S", "body": "B"}
    r = web.post(f"/reports/{r1}/approve", data=data, follow_redirects=False)
    assert "msg=unsafe_to" in r.headers["location"] and f.reports[r1]["status"] == "pending_review"
    t = web.get(f"/reports/{r1}").text
    assert "is on the reported domain itself" in t and "mailto:abuse@www.commbank-login.top" not in t
    # open-commbank.top (domain 3) is a domain CyberCheck tracks
    r = web.post(f"/reports/{r1}/approve", data={**data, "to": "abuse@open-commbank.top"}, follow_redirects=False)
    assert "msg=unsafe_to" in r.headers["location"] and f.reports[r1]["status"] == "pending_review"
    f.reports[r1]["status"] = "failed"
    assert "msg=unsafe_to" in web.post(f"/reports/{r1}/retry", follow_redirects=False).headers["location"]
    f.reports[r1]["status"] = "pending_review"
    r = web.post(f"/reports/{r1}/approve", data={**data, "to": "abuse@host.example"}, follow_redirects=False)
    assert "msg=queued" in r.headers["location"] and f.reports[r1]["status"] == "approved"


def test_withheld_address_is_shown_as_a_warning(web):
    f = web.db
    r1 = rid(f, "hosting_abuse")
    f.reports[r1]["payload"].update(to="", to_warning="Not filled in: abuse@commbank-login.top is on the reported "
                                                       "domain itself")
    t = web.get("/reports").text
    assert "address withheld" in t and 'class="warn"' in t


def test_interrupted_send_is_failed_for_a_reviewer_not_resent():
    sql = " ".join(engine.RECOVER_SQL.split())
    assert "SET status = 'failed'" in sql and "'approved'" not in sql and "next_attempt_at" not in sql
    assert "WHERE status = 'sending'" in sql and "outcome is unknown" in sql
    assert "outcome unknown" in engine.RECOVER_ATTEMPTS_SQL


# ---- verifier regressions ---------------------------------------------------------------------------
def test_shared_platform_abuse_address_is_not_withheld(fake):
    """A kit on commbank-login-au.weebly.com is stored under weebly.com (not in the PSL). Weebly is the
    platform, not the attacker: abuse@weebly.com is the right contact, even though weebly.com is the
    'reported domain' and is itself tracked (open/confirmed) by CyberCheck."""
    kit = "commbank-login-au.weebly.com"
    weebly = dom(registered_domain="weebly.com", tld="com", hostnames=[kit], hosting_abuse_email="abuse@weebly.com")
    assert texts.contact_warning("abuse@weebly.com", weebly, frozenset({"weebly.com"})) == ""
    assert texts.recipient("hosting_abuse", weebly, frozenset({"weebly.com"}))[0] == "abuse@weebly.com"
    # an address on the tenant's own hostname is still the attacker's
    assert "reported domain itself" in texts.contact_warning(f"abuse@{kit}", weebly)
    # a hacked business is not a platform: its own domain stays refused
    plumber = dom(registered_domain="someplumber.com.au", hostnames=["netbank-login.someplumber.com.au"])
    assert "reported domain itself" in texts.contact_warning("abuse@someplumber.com.au", plumber)
    # end to end: planned draft addressed to the platform, no warning
    f = fake(domains=[weebly], pages=[page(url=f"https://{kit}/", final_url=f"https://{kit}/login")])
    run(engine.plan_for_domain(f, cfg(), f.with_have(f.domains[1]), "confirmed"))
    host = f.by_channel("hosting_abuse")[0]["payload"]
    assert host["to"] == "abuse@weebly.com" and host["to_warning"] == ""
    assert run(engine.contact_problem(f, "abuse@weebly.com", weebly)) == ""


def test_channels_table_is_not_split_by_the_abuse_address_note():
    """docs/REPORTING.md: every channel row sits inside the one Markdown table."""
    text = (Path(__file__).resolve().parent.parent / "docs" / "REPORTING.md").read_text()
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith("| Channel (`reports.channel`)"))
    end = next(i for i in range(start, len(lines)) if not lines[i].startswith("|"))
    table = "\n".join(lines[start:end])
    for channel in ("`netcraft`", "`hosting_abuse`", "`brand:<brand_id>`", "`scamwatch`", "`apwg_report`"):
        assert f"| {channel} |" in table
    assert "**Abuse addresses that may be the attacker's are never used.**" in text


def test_auto_report_needs_the_credential_form_on_the_domain_itself(tmp_path):
    """A snapshot that redirected to another site's login form (the real brand, or a kit elsewhere) is not
    auto-report evidence against the redirecting domain, and a missing final URL is not proof either."""
    write_sandbox(tmp_path)
    c = cfg(reporting_mode="auto", data_dir=tmp_path)
    d = dom(id=1, registered_domain="commbank-login.top", status="open", final_score=95)
    on = page(final_url="https://www.commbank-login.top/netbank/logon")
    off = page(final_url="https://www.commbank.com.au/netbank/logon")
    elsewhere = page(final_url="https://kit.example-host.xyz/login")
    unknown = page(final_url=None)
    assert evidence.auto_eligible(d, [on], c, sandbox_ok()) == (True, "")
    for p in (off, elsewhere, unknown):
        ok, why = evidence.auto_eligible(d, [p], c, sandbox_ok())
        assert not ok and "on the domain itself" in why
    assert evidence.credential_page([off, on], "commbank-login.top")["final_url"] == on["final_url"]
    assert evidence.credential_page([off]) is off          # without a domain: unchanged behaviour

