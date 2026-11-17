"""Every dashboard route against a real Postgres 17 (the disposable server of tests/integration/conftest.py).

Data is seeded the way the pipeline creates it: store_hit for domains (CT, CZDS, the bot and a manual add), the
fetch job's own run_once with a stub fetcher client for pages and screenshot files, the AI budget's reserve/finish
for ai_calls, the CZDS module's save_zone/add_run/store_hits, the bot's own handle_update with a stub Telegram API,
and the dashboard's own POST routes for review decisions, reports and the blocklist. Worker-side report states
(sending, sent by API, failed, skipped) use the report engine's own SQL.

Nothing here touches the network: the fetcher, Telegram, SMTP, CZDS and Anthropic are never contacted (the
dashboard only queues). The database is real.
"""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from cybercheck import config, db
from cybercheck.scoring import Hit, default_watchlist
from cybercheck.store import store_hit

BASE = "http://127.0.0.1:8430"
CHROME_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 "
             "Safari/537.36")
REVIEWER = "reviewer@example.org"

ENV = {
    "REPORTING_MODE": "review",
    "REPORTER_EMAIL": "phish-reports@cybercheck-it.example.org",
    "REPORTER_NAME": "CyberCheck IT",
    "SMTP_HOST": "smtp.cybercheck-it.invalid",
    "SMTP_PORT": "587",
    "SMTP_USER": "it-user",
    "SMTP_PASSWORD": "it-smtp-password-not-real",
    "SMTP_FROM": "phish-reports@cybercheck-it.example.org",
    "TELEGRAM_ALLOWED_CHATS": "777000,-100200300",
    "TELEGRAM_BOT_TOKEN": "123456:it-telegram-token-not-real",
    "CZDS_USERNAME": "czds-it@example.org",
    "CZDS_PASSWORD": "czds-it-password-not-real",
    "CZDS_TLDS": "top,shop,online,au,bad_tld!",
    "FETCHER_TOKEN": "it-fetcher-token-0123456789abcdef",
    "FETCH_MIN_FREE_GB": "0",
    "FETCH_CONCURRENCY": "2",
    "BLOCKLIST_HOMEPAGE": "https://blocklist.cybercheck-it.example.org",
    "BLOCKLIST_CONTACT": "blocklist@cybercheck-it.example.org",
    "AI_DAILY_BUDGET_USD": "1.60",
    "AI_MONTHLY_BUDGET_USD": "48",
}
UNSET = ("WEB_ALLOWED_HOSTS", "WEB_PUBLIC_HOSTNAME", "WEB_HOST", "WEB_PORT", "ANTHROPIC_API_KEY", "AI_ENABLED",
         "NETCRAFT_TEST", "NETCRAFT_ENABLED", "REPORT_MANUAL_CHANNELS", "REPORT_AI_DRAFTS", "BLOCKLIST_CZDS_TERMS_OK",
         "BLOCKLIST_MIN_FINAL_SCORE", "AUTO_REPORT_MIN_FINAL_SCORE", "BLOCKLIST_DAYS", "BOT_DAILY_LIMIT_PER_CHAT",
         "CZDS_WINDOW_START", "FETCH_BATCH", "FETCH_TRACK_DAYS", "SCREENSHOT_RETENTION_DAYS")

WL = default_watchlist()

# hostnames as CT certificates carry them (punycode for the IDN), by role in the tests
HOSTS = {
    "phish": "login.commbank-secure.top",          # high; confirmed, pages, AI, reports, blocklist
    "idn": "xn--commbnk-login-01k.top",            # high; commbаnk-login.top with a Cyrillic а
    "review": "mygov-au-login.com",                # review; open, nothing else (DNS resolves, page refused)
    "watch": "westpac-verify.net",                 # watch
    "fp": "anz-update.info",                       # review; marked false positive
    "benign": "telstra-billing.co",                # review; marked benign
    "auto": "auspost.parcel-redelivery.top",       # review; open, AI phishing + score 93 (automated blocklist)
    "shared": "commbank-login.weebly.com",         # shared platform: hostnames-only blocklist entry
    "down": "nab.com.au.login-secure.icu",         # confirmed, reported, taken down
    "ct_czds": "bankwest-alerts.com",              # CT first, then a CZDS zone diff
    "pending": "commbank-alert-003.top",           # review; enrich saw a possible takedown
}
FILLER = [f"auspost-track-{i:04d}.top" for i in range(205)]


# ---- harness ---------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client(it_db):
    mp = pytest.MonkeyPatch()
    for k in UNSET:
        mp.delenv(k, raising=False)
    for k, v in ENV.items():
        mp.setenv(k, v)
    config.settings.cache_clear()
    from cybercheck.web.app import app
    try:
        # `with`: the lifespan runs and every request (and call() below) uses one event loop, so the
        # psycopg pool created by the first request is shared by the routes and the seeding code
        with TestClient(app, base_url=BASE) as c:
            yield c
    finally:
        mp.undo()
        config.settings.cache_clear()


def call(c, fn, *args):
    """Run an async function on the app's event loop (same db pool as the routes)."""
    return c.portal.call(fn, *args)


async def _sql(query, params=None):
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(query, params)
        return await cur.fetchall() if cur.description else []


def sql(c, query, params=None) -> list[dict]:
    return call(c, _sql, query, params)


def one(c, query, params=None) -> dict | None:
    rows = sql(c, query, params)
    return rows[0] if rows else None


def chrome_post(page: str = "/") -> dict:
    """What Chrome sends when one of the dashboard's own forms is submitted (see tests/test_web.py)."""
    return {"origin": BASE, "referer": BASE + page, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document", "sec-fetch-user": "?1", "user-agent": CHROME_UA,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "tailscale-user-login": REVIEWER}


def post(c, path: str, data: dict | None = None, page: str = "/", headers: dict | None = None):
    return c.post(path, data=data or {}, headers={**chrome_post(page), **(headers or {})}, follow_redirects=False)


def redirect(r, path: str) -> dict:
    """Assert a 303 to `path`; returns its query string as a dict."""
    assert r.status_code == 303, (r.status_code, r.text[:500])
    loc = urlsplit(r.headers["location"])
    assert loc.path == path, r.headers["location"]
    return {k: v[0] for k, v in parse_qs(loc.query).items()}


def get(c, path: str, status: int = 200, **kw):
    r = c.get(path, follow_redirects=False, **kw)
    assert r.status_code == status, (path, r.status_code, r.text[:2000])
    return r


def hit_for(host: str) -> Hit:
    h = WL.score_hostname(host)
    assert h is not None, host
    return h


def webp(color, size=(390, 844)) -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("RGB", size, color)
    d = ImageDraw.Draw(im)
    d.rectangle((20, 300, size[0] - 20, 340), outline=(0, 0, 0), width=2)
    d.rectangle((20, 360, size[0] - 20, 400), outline=(0, 0, 0), width=2)
    buf = io.BytesIO()
    im.save(buf, "WEBP", quality=70)
    return buf.getvalue()


# ---- stub fetcher (stands in for cybercheck.fetch_client.FetchClient; contacts nothing) -----------

def _login_page(url: str, profile: str, title: str, inputs: list[dict], color) -> dict:
    host = urlsplit(url).hostname
    return {
        "ok": True, "url": url, "final_url": url, "http_status": 200, "redirect_chain": [url],
        "title": title,
        "html": "<html><head><title>" + title + "</title></head><body><form method='post' action='/auth.php'>"
                + "".join(f"<input type='{i['type']}' name='{i['name']}'>" for i in inputs) + "</form></body></html>",
        "text_excerpt": f"{title}\nLog on\nClient number\nPassword\nForgot your password?",
        "screenshot_webp_b64": base64.b64encode(webp(color if profile == "desktop" else tuple(255 - x for x in color),
                                                     (1280, 800) if profile == "desktop" else (390, 844))).decode(),
        "forms": [{"action": f"https://{host}/auth.php", "method": "post",
                   "has_password": any(i["type"] == "password" for i in inputs),
                   "has_otp": any("one-time-code" in (i.get("autocomplete") or "") for i in inputs),
                   "has_card": any("cc-" in (i.get("autocomplete") or "") for i in inputs),
                   "inputs": inputs}],
        "egress_ip": "203.0.113.45", "egress_country": "AU",
        "timings": {"navigation_ms": 1830, "total_ms": 4120}, "error": None, "fetcher_error": None,
    }


def stub_result(url: str, profile: str) -> dict:
    host = urlsplit(url).hostname
    scheme = urlsplit(url).scheme
    if host == HOSTS["phish"]:
        return _login_page(url, profile, "NetBank - Log on to NetBank", [
            {"type": "text", "name": "client_number", "autocomplete": "username", "label": "Client number"},
            {"type": "password", "name": "password", "autocomplete": "current-password", "label": "Password"}],
            (255, 204, 0))
    if host == HOSTS["idn"]:
        return _login_page(url, profile, "NetBank - Verify your identity", [
            {"type": "text", "name": "code", "autocomplete": "one-time-code", "label": "NetCode"},
            {"type": "text", "name": "cc", "autocomplete": "cc-number", "label": "Card number"}], (250, 220, 40))
    if host == HOSTS["shared"]:
        return _login_page(url, profile, "CommBank | Log on", [
            {"type": "text", "name": "user", "autocomplete": "username", "label": "Client number"},
            {"type": "password", "name": "pass", "autocomplete": "current-password", "label": "Password"}],
            (240, 200, 10))
    if host == HOSTS["auto"]:
        return _login_page(url, profile, "Australia Post - Redelivery fee", [
            {"type": "text", "name": "card", "autocomplete": "cc-number", "label": "Card number"},
            {"type": "text", "name": "exp", "autocomplete": "cc-exp", "label": "Expiry"},
            {"type": "text", "name": "cvc", "autocomplete": "cc-csc", "label": "CVC"}], (220, 30, 40))
    # everything else: connection refused, as the fetcher reports a page failure
    return {"ok": False, "url": url, "final_url": None, "http_status": None, "redirect_chain": [],
            "title": None, "html": None, "text_excerpt": None, "screenshot_webp_b64": None, "forms": [],
            "egress_ip": "203.0.113.45", "egress_country": "AU", "timings": {"total_ms": 310},
            "error": f"net::ERR_CONNECTION_REFUSED at {scheme}://{host}/", "fetcher_error": None}


class StubFetchClient:
    calls: list[tuple[str, str]] = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    configured = True

    async def health(self):
        return {"ok": True, "vpn_running": True, "egress_ip": "203.0.113.45", "egress_country": "AU",
                "browser_ok": True, "error": None}

    async def fetch(self, url: str, profile: str):
        StubFetchClient.calls.append((url, profile))
        return stub_result(url, profile)


# ---- stub Telegram API (the bot's only network boundary) -----------------------------------------

class StubTelegram:
    def __init__(self):
        self.sent: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str, reply_to=None) -> None:
        self.sent.append((chat_id, text))


def tg_update(update_id: int, chat: dict, text: str, forwarded: bool = False) -> dict:
    msg = {"message_id": 100 + update_id, "date": int(time.time()), "chat": chat,
           "from": {"id": abs(chat["id"]) % 10_000_000, "is_bot": False, "first_name": "Sam"}, "text": text}
    if forwarded:
        msg["forward_origin"] = {"type": "hidden_user", "sender_user_name": "Unknown", "date": int(time.time()) - 60}
    return {"update_id": update_id, "message": msg}


# ---- seeding ---------------------------------------------------------------------------------------

async def _seed_store() -> dict:
    """What ingest, the CZDS job and a manual add leave behind."""
    from cybercheck import czds
    ids: dict = {}
    p = await db.pool()
    async with p.connection() as conn:
        # stream counters and heartbeat, as ingest.flush_stats writes them
        for minutes_ago, certs in ((0, 1840), (3, 1712), (90, 1655), (60 * 30, 999)):
            await conn.execute(
                "INSERT INTO ingest_stats (minute, source, certs, hostnames, scored, hits) "
                "VALUES (date_trunc('minute', now()) - make_interval(mins => %s), 'ct', %s, %s, %s, %s) "
                "ON CONFLICT (minute, source) DO UPDATE SET certs = ingest_stats.certs + EXCLUDED.certs",
                (minutes_ago, certs, certs * 3, certs * 3, 2))
        await db.kv_set(conn, "ingest:heartbeat", {"at": datetime.now(timezone.utc).isoformat(),
                                                   "last_message_at": datetime.now(timezone.utc).isoformat()})
        for i, host in enumerate(FILLER):
            await store_hit(conn, hit_for(host), "ct", "R10", "Google 'Argon2026h1'")
        for key in ("phish", "idn", "review", "watch", "fp", "benign", "auto", "shared", "down", "ct_czds",
                    "pending"):
            ids[key], inserted = await store_hit(conn, hit_for(HOSTS[key]), "ct", "R11",
                                                 "Let's Encrypt 'Oak2026h2'")
            assert inserted
        # a second certificate for the phishing domain: one more hostname and sighting
        _, inserted = await store_hit(conn, hit_for("secure.commbank-secure.top"), "ct", "E6", "Sectigo 'Elephant2026'")
        assert not inserted
        # a reviewer's manual add of an official domain (reports must refuse it)
        official = Hit(hostname="netbank.commbank.com.au", registered_domain="commbank.com.au", unicode_domain=None,
                       tld="com.au", brand_id="commbank", brand_name="CommBank", score=60, tier="review",
                       reasons=[{"points": 60, "why": "added by hand for review"}], match={})
        ids["official"], _ = await store_hit(conn, official, "manual")

        # CZDS: zone rows and runs as the job writes them, hits through store_hits
        now = datetime.now(timezone.utc)
        await czds.save_zone(conn, "top", {
            "configured": True, "approved": True, "approved_at": now - timedelta(days=30),
            "download_url": "https://czds-download-api.icann.org/czds/downloads/top.zone",
            "last_head": now - timedelta(hours=5), "last_download": now - timedelta(hours=5),
            "last_processed": now - timedelta(hours=4, minutes=50), "next_due": now + timedelta(hours=19),
            "total_names": 3_912_004, "new_names": 18_220, "removed_names": 17_001, "hits": 14, "new_hits": 9,
            "soa_serial": 1763251200, "file_bytes": 412_000_000, "last_modified": "Sat, 15 Nov 2026 00:12:00 GMT",
            "status": "ok", "error": None, "fail_count": 0, "duration_s": 182.5, "state": {"etag": "abc"}})
        await czds.save_zone(conn, "shop", {
            "configured": True, "approved": True, "approved_at": now - timedelta(days=2),
            "last_download": now - timedelta(hours=1), "last_processed": now - timedelta(minutes=55),
            "next_due": now + timedelta(hours=23), "total_names": 702_118, "new_names": None, "removed_names": None,
            "hits": 0, "new_hits": 0, "soa_serial": 1763254800, "file_bytes": 61_000_000, "status": "baseline",
            "fail_count": 0, "duration_s": 31.0, "state": {}})
        await czds.save_zone(conn, "app", {"configured": False, "approved": True, "status": "not_configured",
                                           "state": {}})
        await czds.save_zone(conn, "xyz", {"configured": False, "approved": False, "status": "not_approved",
                                           "state": {}})
        await czds.add_run(conn, "top", {"status": "ok", "soa_serial": 1763251200, "file_bytes": 412_000_000,
                                         "total_names": 3_912_004, "new_names": 18_220, "removed_names": 17_001,
                                         "hits": 14, "new_hits": 9, "duration_s": 182.5})
        await czds.add_run(conn, "shop", {"status": "baseline", "file_bytes": 61_000_000, "total_names": 702_118,
                                          "duration_s": 31.0})
        await czds.add_run(conn, "top", {"status": "retrying", "error": "HTTP 503 from the download server"})
        stored, inserted = await czds.store_hits(conn, "shop", [hit_for("qantas-points.shop"),
                                                                hit_for(HOSTS["ct_czds"])], 1763254800)
        assert (stored, inserted) == (2, 1)
        ids["czds"] = (await (await conn.execute("SELECT id FROM domains WHERE registered_domain = %s",
                                                 ("qantas-points.shop",))).fetchone())["id"]
        await db.kv_set(conn, "job:czds", {"last_run": now.isoformat(), "ok": True, "duration_s": 3.2,
                                           "result": {"zones": 2, "downloaded": 1, "hits": 14}})
    return ids


async def _seed_enrich(ids: dict) -> None:
    """Columns the enrich job writes (DNS / RDAP / ASN), and its checks rows."""
    p = await db.pool()
    async with p.connection() as conn:
        for key in ("phish", "idn", "review", "auto", "shared", "pending"):
            await conn.execute(
                "UPDATE domains SET dns_state = 'resolves', ips = %s, asn = 20473, as_name = 'AS-VULTR', "
                "ip_country = 'US', registrar = 'NameSilo, LLC', registrar_iana_id = 1479, "
                "registrar_abuse_email = 'abuse@namesilo.com', hosting_abuse_email = 'abuse@vultr.com', "
                "rdap_status = ARRAY['client transfer prohibited'], registered_at = now() - interval '2 days', "
                "enriched_at = now(), check_count = check_count + 1, next_check_at = now() + interval '1 hour', "
                "enrich_state = %s WHERE id = %s",
                (["45.77.1.10"], db.jsonb({"dns": "resolves", "ip": "45.77.1.10"}), ids[key]))
            await conn.execute("INSERT INTO checks (domain_id, kind, ok, result) VALUES (%s, 'dns', true, %s)",
                               (ids[key], db.jsonb({"a": ["45.77.1.10"], "resolver": "1.1.1.1"})))
            await conn.execute("INSERT INTO checks (domain_id, kind, ok, result) VALUES (%s, 'rdap', true, %s)",
                               (ids[key], db.jsonb({"registrar": "NameSilo, LLC",
                                                    "status": ["client transfer prohibited"]})))
        # enrich saw a takedown signal once and waits for a second check
        await conn.execute("UPDATE domains SET enrich_state = enrich_state || %s WHERE id = %s",
                           (db.jsonb({"pending": {"nxdomain": {"since": datetime.now(timezone.utc).isoformat(),
                                                               "n": 1}}}),
                            ids["pending"]))
        # the taken-down domain: seen 3 days ago, enriched, gone after 20 hours
        await conn.execute(
            "UPDATE domains SET first_seen = now() - interval '3 days', dns_state = 'nxdomain', asn = 16509, "
            "as_name = 'AMAZON-02', registrar = 'GoDaddy.com, LLC', registrar_iana_id = 146, "
            "enriched_at = now() - interval '1 hour', takedown_at = now() - interval '52 hours', "
            "takedown_signal = 'nxdomain', live_state = 'down', first_live_at = now() - interval '71 hours', "
            "last_live_at = now() - interval '53 hours' WHERE id = %s", (ids["down"],))
        await db.add_event(conn, ids["down"], "taken_down", {"signal": "nxdomain"})


async def _seed_fetch() -> dict:
    """The fetch job's own run_once, with the stub fetcher client: pages rows and screenshot files."""
    from cybercheck.jobs import fetch
    from cybercheck.worker import JobContext
    mp = pytest.MonkeyPatch()
    mp.setattr(fetch, "FetchClient", StubFetchClient)
    try:
        return await fetch.run_once(JobContext(settings=config.settings(), log=logging.getLogger("it.fetch")))
    finally:
        mp.undo()


async def _seed_ai(ids: dict) -> dict:
    """AI calls through the budget's reserve/finish (the path every AI call takes), and the judge's columns."""
    from cybercheck.ai import budget
    out = {}
    p = await db.pool()
    async with p.connection() as conn:
        pages = {(r["domain_id"], r["user_agent_profile"]): r["id"] for r in await (await conn.execute(
            "SELECT id, domain_id, user_agent_profile FROM pages")).fetchall()}

        async def judged(key, profile, result, cost, tokens, status="ok", **kw):
            cid, why = await budget.reserve(conn, purpose="page_judge", model="claude-opus-5-5", estimate=0.06,
                                            domain_id=ids[key], page_id=pages[(ids[key], profile)])
            assert cid, why
            await budget.finish(conn, cid, status=status, model=kw.pop("model", "claude-opus-5-5"), cost_usd=cost,
                                tokens=tokens, result=result, duration_ms=8123, **kw)
            return cid

        verdict = {"verdict": "phishing", "confidence": 0.97, "imitated_brand": "commbank", "asks_for": ["password"],
                   "explanation": "Copies the NetBank log-on page and posts the client number and password to "
                                  "auth.php on the same host."}
        out["judge"] = await judged("phish", "desktop", verdict, 0.0312,
                                    {"input_tokens": 4210, "output_tokens": 312, "cache_read_tokens": 2900,
                                     "cache_write_tokens": 0}, stop_reason="end_turn")
        out["refusal"] = await judged("phish", "mobile", {"refusal_category": "cyber"}, 0.0041,
                                      {"input_tokens": 3900, "output_tokens": 12}, status="refusal",
                                      stop_reason="refusal", fallback_model="claude-sonnet-5")
        out["api_error"] = await judged("idn", "desktop", None, 0.0, {}, status="api_error",
                                        error="APIStatusError: 529 overloaded_error: Overloaded")
        await judged("auto", "desktop", {**verdict, "imitated_brand": "auspost", "asks_for": ["card"],
                                         "confidence": 0.92, "explanation": "Fake redelivery fee page."},
                     0.0288, {"input_tokens": 3800, "output_tokens": 280, "cache_read_tokens": 3000})
        # a reservation still in flight
        cid, why = await budget.reserve(conn, purpose="page_judge", model="claude-opus-5-5", estimate=0.05,
                                        domain_id=ids["idn"], page_id=pages[(ids["idn"], "mobile")])
        assert cid, why
        # text-only triage of a domain without a page, and a call not about any domain
        cid, why = await budget.reserve(conn, purpose="domain_triage", model="claude-opus-5-5", estimate=0.01,
                                        domain_id=ids["watch"])
        await budget.finish(conn, cid, status="ok", model="claude-opus-5-5", cost_usd=0.0021,
                            tokens={"input_tokens": 900, "output_tokens": 80}, result={
                                "assessment": "likely_phishing", "likely_target": "westpac",
                                "reason": "brand plus 'verify' on a generic TLD"})
        cid, why = await budget.reserve(conn, purpose="watchlist", model="claude-opus-5-5", estimate=0.02)
        await budget.finish(conn, cid, status="invalid", model="claude-opus-5-5", cost_usd=0.011,
                            tokens={"input_tokens": 2000, "output_tokens": 400}, error="unexpected fields")

        # what the judge job writes back
        for key, verdict_, conf, brand, score in (("phish", "phishing", 0.97, "commbank", 95),
                                                  ("auto", "phishing", 0.92, "auspost", 93)):
            await conn.execute(
                "UPDATE pages SET ai_judged_at = now(), ai_result = %s WHERE domain_id = %s",
                (db.jsonb({"verdict": verdict_, "confidence": conf}), ids[key]))
            await conn.execute(
                "UPDATE domains SET ai_verdict = %s, ai_confidence = %s, ai_brand = %s, final_score = %s, "
                "final_reasons = %s, final_score_at = now(), final_basis = 'it' WHERE id = %s",
                (verdict_, conf, brand, score, db.jsonb([
                    {"points": 60, "why": "domain name score"}, {"points": 20, "why": "asks for credentials"},
                    {"points": score - 80, "why": f"AI: {verdict_} ({conf:.0%})"}]), ids[key]))
            await db.add_event(conn, ids[key], "ai_verdict", {"verdict": verdict_, "confidence": conf})
        await conn.execute("UPDATE domains SET ai_triage = %s, ai_triaged_at = now() WHERE id = %s", (db.jsonb({
            "assessment": "likely_phishing", "likely_target": "westpac", "reason": "brand plus 'verify'",
            "ai_call_id": cid}), ids["watch"]))
    return out


@pytest.fixture(scope="module")
def world(client):
    ids = call(client, _seed_store)
    call(client, _seed_enrich, ids)
    fetched = call(client, _seed_fetch)
    ids["fetch_result"] = fetched
    ids["ai"] = call(client, _seed_ai, ids)
    ids["pages"] = {(r["domain_id"], r["user_agent_profile"]): r for r in sql(client, "SELECT * FROM pages")}
    return ids


def page_of(world, key, profile="desktop") -> dict:
    return world["pages"][(world[key], profile)]


# ---- empty database ----------------------------------------------------------------------------------

def test_every_page_renders_on_an_empty_database(client):
    """A fresh install: every GET works with empty tables and no kv rows (nothing seeded yet)."""
    assert one(client, "SELECT count(*) AS n FROM domains")["n"] == 0
    for path, text in (("/", "No suspicious domains yet"), ("/review", "Nothing here."),
                       ("/domains", "Nothing here."),
                       ("/domains?tier=high&status=open&brand=commbank&q=x", "Nothing here."),
                       ("/reports", "No email drafts waiting."), ("/blocklist", "Nothing listed yet."),
                       ("/czds", "No CZDS hits in the last 30 days."), ("/ai", "No AI calls yet."),
                       ("/bot", "chats waiting for approval"), ("/takedown", "No flagged domains yet."),
                       ("/takedown?scope=tracked", "No takedowns seen yet.")):
        r = get(client, path)
        assert text in r.text, path
        assert r.headers["x-frame-options"] == "DENY"
    j = get(client, "/api/recent").json()
    assert j["rows"] == [] and j["stats"]["total"] == 0 and j["stats"]["heartbeat"] is None
    r = get(client, "/healthz", 503)
    assert r.json() == {"ok": False, "ingest_heartbeat_age_s": None}
    get(client, "/domain/1", 404)
    get(client, "/screenshot/1", 404)
    get(client, "/reports/1", 404)
    get(client, "/reports/1/screenshot.jpg", 404)
    r = get(client, "/blocklist/files/hosts.txt", 404)
    assert "not built yet" in r.text
    get(client, "/blocklist/files/passwd", 404)
    assert get(client, "/robots.txt").text == "User-agent: *\nDisallow: /\n"
    # POSTs on ids that do not exist
    assert post(client, "/domain/999/status", {"status": "confirmed"}).status_code == 404
    assert post(client, "/reports/create/999").status_code == 404
    for action in ("save", "approve", "sent", "reject", "retry"):
        assert post(client, f"/reports/999/{action}").status_code == 404, action
    assert post(client, "/blocklist/999/exclude").status_code == 404
    assert post(client, "/blocklist/999/include").status_code == 404
    # nothing was written by any of them
    assert one(client, "SELECT count(*) AS n FROM domain_events")["n"] == 0
    assert one(client, "SELECT count(*) AS n FROM reports")["n"] == 0


def test_seeded_world_is_what_the_pipeline_makes(world, client):
    f = world["fetch_result"]
    # resolving review/high domains: phish, idn, auto load; review and pending are refused (shared is watch tier)
    assert f["due"] == 5 and f["fetched"] == 5 and f["live"] == 3, f
    assert StubFetchClient.calls and all(u.startswith(("https://", "http://")) for u, _ in StubFetchClient.calls)
    shot = page_of(world, "phish")
    assert shot["screenshot_path"] and shot["has_password_field"] and shot["http_status"] == 200
    assert (config.settings().data_dir / shot["screenshot_path"]).is_file()
    refused = page_of(world, "review")
    assert refused["screenshot_path"] is None and refused["error"].startswith("net::ERR_CONNECTION_REFUSED")
    d = one(client, "SELECT * FROM domains WHERE id = %s", (world["phish"],))
    assert d["live_state"] == "live" and d["page_score"] is not None and d["sightings"] == 2
    assert d["hostnames"] == ["login.commbank-secure.top", "secure.commbank-secure.top"]
    assert one(client, "SELECT count(*) AS n FROM ai_calls")["n"] == 7


# ---- read-only pages on the seeded data ------------------------------------------------------------

def test_overview_and_live_api(world, client):
    r = get(client, "/")
    # certificates in the last 5 minutes: the rows 0 and 3 minutes ago
    assert "3,552" in r.text
    assert HOSTS["idn"] in r.text and "commbаnk-login.top" in r.text
    top = one(client, "SELECT max(id) AS id FROM domains")["id"]
    # the live feed polls from the newest id the page was rendered with (static/overview.js reads it)
    assert f'data-max-id="{top}"' in r.text and 'data-src="/api/recent"' in r.text
    assert "let maxId" not in r.text and not re.search(r"<script(?![^>]*\bsrc=)", r.text)
    j = get(client, "/api/recent").json()
    assert len(j["rows"]) == 100 and j["rows"][0]["id"] == top
    s = j["stats"]
    assert s["certs_5m"] == 1840 + 1712 and s["certs_24h"] == 1840 + 1712 + 1655
    assert s["total"] == one(client, "SELECT count(*) AS n FROM domains")["n"]
    assert s["live"] == 3 and s["confirmed"] == 0 and datetime.fromisoformat(s["heartbeat"])
    # incremental poll: only rows after the id the page has
    j = get(client, f"/api/recent?after_id={world['idn']}").json()
    ids = [x["id"] for x in j["rows"]]
    assert ids and min(ids) > world["idn"] and world["idn"] not in ids
    row = next(x for x in get(client, f"/api/recent?after_id={world['idn'] - 1}").json()["rows"]
               if x["id"] == world["idn"])
    assert row["unicode_domain"] == "commbаnk-login.top" and row["hostname"] == HOSTS["idn"]
    assert get(client, f"/api/recent?after_id={top}").json()["rows"] == []
    assert get(client, "/api/recent?after_id=99999999999999999999").json()["rows"] == []
    get(client, "/api/recent?after_id=abc", 422)


def test_healthz_follows_the_ingest_heartbeat(world, client):
    r = get(client, "/healthz")
    assert r.json()["ok"] is True and 0 <= r.json()["ingest_heartbeat_age_s"] < 180
    sql(client, "UPDATE kv SET updated_at = now() - interval '10 minutes' WHERE key = 'ingest:heartbeat'")
    try:
        r = get(client, "/healthz", 503)
        assert r.json()["ok"] is False and r.json()["ingest_heartbeat_age_s"] > 590
    finally:
        sql(client, "UPDATE kv SET updated_at = now() WHERE key = 'ingest:heartbeat'")


def test_review_queue(world, client):
    r = get(client, "/review")
    rows = re.findall(r'<tr data-id="(\d+)">', r.text)
    queue = sql(client, "SELECT id FROM domains WHERE status = 'open' AND tier IN ('review','high') "
                        "ORDER BY (tier = 'high') DESC, COALESCE(final_score, score) DESC, first_seen DESC, id DESC "
                        "LIMIT 300")
    assert [int(x) for x in rows] == [q["id"] for q in queue]
    assert str(world["watch"]) not in rows           # watch tier is not in the queue
    assert int(rows[0]) == world["phish"]           # combined score 95 beats every name-only score
    assert "Review queue" in r.text and 'action="/review"' in r.text
    # the old order (highest combined score first) is one filter away
    rows = re.findall(r'<tr data-id="(\d+)">', get(client, "/review?sort=score").text)
    queue = sql(client, "SELECT id FROM domains WHERE status = 'open' AND tier IN ('review','high') "
                        "ORDER BY COALESCE(final_score, score) DESC, first_seen DESC LIMIT 300")
    assert [int(x) for x in rows] == [q["id"] for q in queue]


def _row_ids(html: str) -> list[int]:
    return [int(x) for x in re.findall(r'<tr data-id="(\d+)">', html)]


def test_domains_filters_and_paging(world, client):
    total = one(client, "SELECT count(*) AS n FROM domains")["n"]
    assert total > 200
    first = _row_ids(get(client, "/domains").text)
    assert len(first) == 200
    r = get(client, "/domains?page=2")
    second = _row_ids(r.text)
    assert len(second) == total - 200 and not set(first) & set(second)
    assert "Next page" not in r.text
    assert "Next page" in get(client, "/domains").text
    assert _row_ids(get(client, "/domains?page=3").text) == []
    assert _row_ids(get(client, "/domains?page=0").text) == first          # clamped to the first page
    assert _row_ids(get(client, "/domains?page=-5").text) == first
    assert _row_ids(get(client, "/domains?page=999999999999999999999").text) == []   # not a 500 (bigint OFFSET)
    for tier in ("high", "review", "watch"):
        ids = _row_ids(get(client, f"/domains?tier={tier}").text)
        want = {x["id"] for x in sql(client, "SELECT id FROM domains WHERE tier = %s", (tier,))}
        assert ids and set(ids) <= want, tier
    assert world["watch"] in _row_ids(get(client, "/domains?tier=watch").text)
    assert len(_row_ids(get(client, "/domains?tier=bogus").text)) == 200   # unknown tier: no filter
    assert world["fp"] in _row_ids(get(client, "/domains?status=open&tier=review&brand=anz").text)
    assert _row_ids(get(client, "/domains?status=confirmed").text) == []
    assert _row_ids(get(client, "/domains?status=benign").text) == []
    r = get(client, "/domains?brand=commbank")
    ids = set(_row_ids(r.text))
    assert {world["phish"], world["idn"], world["shared"], world["official"]} <= ids
    assert 'value="commbank" selected' in r.text
    assert world["auto"] not in ids
    # search: part of the registrable name, an exact hostname, the displayed unicode form, LIKE wildcards
    assert _row_ids(get(client, "/domains?q=commbank-secure").text) == [world["phish"]]
    assert _row_ids(get(client, "/domains?q=secure.commbank-secure.top").text) == [world["phish"]]
    assert _row_ids(get(client, "/domains", params={"q": "commbаnk-login"}).text) == [world["idn"]]
    assert _row_ids(get(client, "/domains", params={"q": " XN--COMMBNK-LOGIN-01K "}).text) == [world["idn"]]
    assert _row_ids(get(client, "/domains?q=%25").text) == []          # a literal %, not "everything"
    assert _row_ids(get(client, "/domains?q=_").text) == []
    assert _row_ids(get(client, "/domains?q=auspost-track-00_1").text) == []
    # LIKE's escape character itself: a literal backslash, alone, trailing or before a wildcard
    for q in ("\\", "commbank\\", "commbank\\%", "\\_"):
        assert _row_ids(get(client, "/domains", params={"q": q}).text) == [], q
    assert _row_ids(get(client, "/domains?q=auspost-track-0001").text) == [
        one(client, "SELECT id FROM domains WHERE registered_domain = 'auspost-track-0001.top'")["id"]]
    assert _row_ids(get(client, "/domains", params={"q": "'; DROP TABLE domains; --"}).text) == []
    r = get(client, "/domains?q=auspost-track&page=1")
    assert len(_row_ids(r.text)) == 200 and "q=auspost-track&amp;tier=&amp;status=&amp;brand=&amp;page=2" in r.text
    assert len(_row_ids(get(client, "/domains?q=auspost-track&page=2").text)) == 5
    get(client, "/domains?page=abc", 422)


async def _store_in_one_transaction(hosts: list[str]) -> list[int]:
    """store_hit for several hosts inside one transaction: now() is the transaction start, so every row gets the
    same first_seen. Today's writers store one hit per transaction, so ties need equal microseconds, but any
    batched writer (or a restore of tied rows) makes them common."""
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            return [(await store_hit(conn, hit_for(h), "ct", "R11", "Let's Encrypt 'Oak2026h2'"))[0] for h in hosts]


def test_domains_paging_partitions_rows_that_share_first_seen(world, client):
    """Page 2 must start where page 1 ended even when first_seen ties: ORDER BY first_seen alone lets
    Postgres return tied rows in a different order for LIMIT 200 and for LIMIT 200 OFFSET 200."""
    ids = call(client, _store_in_one_transaction, [f"auspost-track-tie-{i:03d}.top" for i in range(230)])
    try:
        assert one(client, "SELECT count(DISTINCT first_seen) AS n FROM domains WHERE id = ANY(%s)", (ids,))["n"] == 1
        p1 = _row_ids(get(client, "/domains?q=auspost-track-tie").text)
        p2 = _row_ids(get(client, "/domains?q=auspost-track-tie&page=2").text)
        assert len(p1) == 200 and len(p2) == 30
        assert not set(p1) & set(p2), sorted(set(p1) & set(p2))[:10]
        assert set(p1) | set(p2) == set(ids)
        # the same with no filter at all (the planner may take another path)
        all1 = _row_ids(get(client, "/domains").text)
        all2 = _row_ids(get(client, "/domains?page=2").text)
        assert not set(all1) & set(all2)
    finally:
        sql(client, "DELETE FROM domains WHERE id = ANY(%s)", (ids,))


def test_domain_detail_pages(world, client):
    # full page: pages with screenshots, AI calls, checks, timeline, combined score, blocklist preview
    r = get(client, f"/domain/{world['phish']}")
    t = r.text
    shot = page_of(world, "phish")
    assert f'src="/screenshot/{shot["id"]}"' in t
    assert f'src="/screenshot/{page_of(world, "phish", "mobile")["id"]}"' in t
    assert "NetBank - Log on to NetBank" in t and "password" in t
    assert "Hostnames seen (2 sightings)" in t and "secure.commbank-secure.top" in t
    assert "AI checks" in t and "phishing Copies the NetBank log-on page" in t and "$0.0312" in t
    assert "combined score" in t and "+15" in t
    assert "resolves 45.77.1.10" in t and "AS20473 AS-VULTR US" in t and "NameSilo, LLC" in t
    assert "if confirmed: the whole domain" in t
    assert "first_seen" in t and "went_live" in t and "ai_verdict" in t
    assert "Recent checks" in t and "rdap" in t
    assert "<h2>Reports</h2>" not in t
    for s, label in (("confirmed", "Confirm phishing"), ("false_positive", "False positive"),
                     ("benign", "Benign / parked"), ("open", "Reopen")):
        assert label in t
    # a bare domain: nothing fetched, judged or reported
    t = get(client, f"/domain/{world['fp']}").text
    assert "Page snapshots" not in t and "AI checks" not in t and "<h2>Reports</h2>" not in t
    assert "Recent checks" not in t and "first_seen" in t
    t = get(client, f"/domain/{world['watch']}").text
    assert "AI name triage" in t and "likely target: westpac" in t and "domain_triage" in t
    t = get(client, f"/domain/{world['review']}").text
    assert "Page snapshots" in t and "No screenshot: net::ERR_CONNECTION_REFUSED" in t
    # unicode display form, possible takedown, taken down, manual add, CZDS-found
    t = get(client, f"/domain/{world['idn']}").text
    assert "Displayed as: <span class=\"dom\">commbаnk-login.top</span>" in t and "one-time code" in t
    assert "529 overloaded_error" in t
    assert "possible takedown, confirming on next check" in get(client, f"/domain/{world['pending']}").text
    t = get(client, f"/domain/{world['down']}").text
    assert "(nxdomain)" in t and "taken_down" in t
    assert "via manual" in get(client, f"/domain/{world['official']}").text
    t = get(client, f"/domain/{world['czds']}").text
    assert "via czds" in t and "qantas" in t
    t = get(client, f"/domain/{world['ct_czds']}").text
    assert "czds_new_delegation" in t
    t = get(client, f"/domain/{world['shared']}").text
    assert "if confirmed: only these hostnames: <span class=\"dom\">commbank-login.weebly.com</span>" in t
    get(client, "/domain/99999999", 404)
    get(client, "/domain/99999999999999999999", 404)
    get(client, "/domain/abc", 422)


def test_screenshots_are_images_only_and_stay_inside_the_data_dir(world, client, tmp_path):
    data_dir = config.settings().data_dir.resolve()
    shot = page_of(world, "phish")
    r = get(client, f"/screenshot/{shot['id']}")
    assert r.headers["content-type"] == "image/webp"
    assert r.headers["content-security-policy"] == "default-src 'none'"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.content == (data_dir / shot["screenshot_path"]).read_bytes() and r.content[:4] == b"RIFF"
    # a page without a screenshot (the fetch failed)
    get(client, f"/screenshot/{page_of(world, 'review')['id']}", 404)
    get(client, "/screenshot/99999999", 404)
    # the file is gone (retention deleted it) but the row still names it
    gone = page_of(world, "idn", "mobile")
    (data_dir / gone["screenshot_path"]).unlink()
    get(client, f"/screenshot/{gone['id']}", 404)
    # rows naming a path outside the data dir: relative traversal, absolute, symlink, the data dir itself
    outside = tmp_path / "outside.webp"
    outside.write_bytes(b"RIFF....WEBPsecret")
    link = data_dir / "screenshots" / "link.webp"
    link.symlink_to(outside)
    victim = page_of(world, "review", "mobile")["id"]
    rel = os.path.relpath(outside, data_dir)
    for path in (rel, str(outside), "screenshots/link.webp", "../" * 12 + "etc/passwd", ".", "screenshots"):
        sql(client, "UPDATE pages SET screenshot_path = %s WHERE id = %s", (path, victim))
        r = client.get(f"/screenshot/{victim}")
        assert r.status_code == 404, path
        assert b"secret" not in r.content
    sql(client, "UPDATE pages SET screenshot_path = NULL WHERE id = %s", (victim,))


def test_ai_page(world, client):
    t = get(client, "/ai").text
    assert "AI not available" in t and "no API key" in t
    assert "could not read AI spend" not in t
    # spend: 0.0312 + 0.0041 + 0.0288 + 0.0021 + 0.011 + the open reservation's 0.05 estimate
    assert "$0.13" in t
    assert "page_judge" in t and "domain_triage" in t and "watchlist" in t
    assert "(fallback)" in t and ">refusal<" in t and "529 overloaded_error" in t and "unexpected fields" in t
    assert ">pending<" in t and f'href="/domain/{world["phish"]}"' in t
    assert "commbank-secure.top" in t
    # pages waiting for a check: idn's two pages (open, high tier, not judged, no error)
    assert re.search(r'<div class="n">2</div><div class="l">pages waiting for a check', t)
    assert re.search(r'<div class="n">4</div><div class="l">pages judged \(24h\)', t)
    assert re.search(r'<div class="n">1</div><div class="l">domains triaged \(24h\)', t)
    assert "The judge job has not run yet." in t
    sql(client, "INSERT INTO kv (key, value) VALUES ('job:judge', %s)", (db.jsonb(
        {"last_run": datetime.now(timezone.utc).isoformat(), "ok": True, "duration_s": 9.1,
         "result": {"judged": 4, "skipped": 1}}),))
    t = get(client, "/ai?limit=1").text                 # clamped to 10
    assert "judged" in t and "9.1s" in t
    assert len(re.findall(r'<td class="muted" title=', t)) == 7
    get(client, "/ai?limit=100000")
    get(client, "/ai?limit=x", 422)


def test_ai_queue_count_is_what_the_judge_would_pick(world, client, monkeypatch):
    """'pages waiting for a check' uses the judge's own window (AI_JUDGE_MAX_AGE_H), so it never counts a page
    the judge will not look at, and matches the judge's PENDING_SQL row for row."""
    from cybercheck.jobs import judge
    mobile = page_of(world, "idn", "mobile")["id"]
    sql(client, "UPDATE pages SET fetched_at = fetched_at - interval '5 hours' WHERE id = %s", (mobile,))
    try:
        for setting, hours, want in (("4", 4, 1), ("72", 72, 2), ("", 72, 2), ("not a number", 72, 2),
                                     ("99999999999", 100_000, 2)):
            monkeypatch.setenv("AI_JUDGE_MAX_AGE_H", setting)
            t = get(client, "/ai").text
            assert re.search(rf'<div class="n">{want}</div><div class="l">pages waiting for a check', t), setting
            picked = sql(client, judge.PENDING_SQL, (hours, 1000))
            assert len(picked) == want and {p["domain_id"] for p in picked} == {world["idn"]}, setting
    finally:
        sql(client, "UPDATE pages SET fetched_at = fetched_at + interval '5 hours' WHERE id = %s", (mobile,))


def test_czds_page(world, client):
    t = get(client, "/czds").text
    assert "CZDS credentials configured" in t
    assert ENV["CZDS_PASSWORD"] not in t and ENV["CZDS_USERNAME"] not in t
    assert ".top" in t and ".shop" in t and ".online" in t           # online: configured, not seen yet
    assert "waiting for the first CZDS check" in t and "baseline stored" in t and "processed" in t
    assert "not in CZDS</span> <span class=\"dom\">au</span>" in t
    assert "bad_tld!" in t
    assert "Also approved for this account but not in CZDS_TLDS (1)" in t and "app" in t
    assert "3,912,004" in t and "18,220" in t and "392.9 MB" in t
    assert "qantas-points.shop" in t and "ct first, then CZDS" in t and HOSTS["ct_czds"] in t
    assert "HTTP 503 from the download server" in t
    assert '"zones": 2' in t
    assert re.search(r'<div class="n">2 / 4</div><div class="l">configured zones approved', t)
    assert re.search(r'<div class="n">1</div><div class="l">domains stored by CZDS', t)
    assert re.search(r'<div class="n">1</div><div class="l">known from CT, newly delegated', t)


# ---- review decisions -------------------------------------------------------------------------------

def _status_events(c, domain_id) -> list[dict]:
    return [r["detail"] for r in sql(c, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'status' "
                                        "ORDER BY id", (domain_id,))]


def test_status_changes_in_every_direction(world, client):
    did = world["review"]
    page = f"/domain/{did}"
    before = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert before["status"] == "open" and before["notes"] is None and before["reviewed_hostnames"] is None
    assert not any(p["is_evidence"] for p in sql(client, "SELECT is_evidence FROM pages WHERE domain_id = %s", (did,)))

    # open -> confirmed, with a note: the reviewer, the hostnames shown, evidence kept
    redirect(post(client, f"/domain/{did}/status", {"status": "confirmed", "note": "Fake myGov sign-in"}, page), page)
    d = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert d["status"] == "confirmed" and d["status_by"] == REVIEWER and d["status_changed_at"] is not None
    assert d["notes"] == "Fake myGov sign-in" and d["reviewed_hostnames"] == ["mygov-au-login.com"]
    assert all(p["is_evidence"] for p in sql(client, "SELECT is_evidence FROM pages WHERE domain_id = %s", (did,)))
    assert _status_events(client, did)[-1] == {"status": "confirmed", "by": REVIEWER, "note": "Fake myGov sign-in"}
    t = get(client, page).text
    assert "evidence (kept)" in t and re.search(r'value="confirmed" disabled[^>]*>Confirm phishing', t)

    # a certificate for a new hostname after the review: hostnames grows, the decision does not cover it
    call(client, _store_one, "www.mygov-au-login.com")
    d = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert d["hostnames"] == ["mygov-au-login.com", "www.mygov-au-login.com"]
    assert d["reviewed_hostnames"] == ["mygov-au-login.com"]

    # confirmed -> false_positive: notes append on a new line, unicode kept as is
    note = "Actually Services Australia's test site ✓ — тест"
    redirect(post(client, f"/domain/{did}/status", {"status": "false_positive", "note": note}, page), page)
    d = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert d["status"] == "false_positive" and d["notes"] == "Fake myGov sign-in\n" + note
    assert d["reviewed_hostnames"] == ["mygov-au-login.com", "www.mygov-au-login.com"]
    # false_positive -> benign without a note (a client that sends no note field at all): notes unchanged
    r = client.post(f"/domain/{did}/status", data={"status": "benign"}, headers=chrome_post(page),
                    follow_redirects=False)
    redirect(r, page)
    d = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert d["status"] == "benign" and d["notes"] == "Fake myGov sign-in\n" + note
    # benign -> open: the review scope is cleared; without Tailscale the reviewer is 'local'
    h = {k: v for k, v in chrome_post(page).items() if k != "tailscale-user-login"}
    redirect(client.post(f"/domain/{did}/status", data={"status": "open", "note": ""}, headers=h,
                         follow_redirects=False), page)
    d = one(client, "SELECT * FROM domains WHERE id = %s", (did,))
    assert d["status"] == "open" and d["reviewed_hostnames"] is None and d["status_by"] == "local"
    # open -> open again: harmless, recorded
    redirect(post(client, f"/domain/{did}/status", {"status": "open"}, page), page)
    assert [e["status"] for e in _status_events(client, did)] == ["confirmed", "false_positive", "benign", "open",
                                                                   "open"]
    # evidence is never released by a later decision
    assert all(p["is_evidence"] for p in sql(client, "SELECT is_evidence FROM pages WHERE domain_id = %s", (did,)))
    # a script on the host (curl: no browser headers at all) is let through
    r = client.post(f"/domain/{did}/status", data={"status": "open", "note": "from curl"}, follow_redirects=False)
    redirect(r, page)
    assert one(client, "SELECT notes FROM domains WHERE id = %s", (did,))["notes"].endswith("\nfrom curl")


def test_status_change_refusals_write_nothing(world, client):
    did = world["watch"]
    snapshot = one(client, "SELECT status, notes, status_changed_at FROM domains WHERE id = %s", (did,))
    n_events = len(_status_events(client, did))
    assert post(client, f"/domain/{did}/status", {"status": "phishing"}).status_code == 400
    assert post(client, f"/domain/{did}/status", {}).status_code == 422
    for headers, code in (({"sec-fetch-site": "cross-site", "origin": "https://evil.example"}, 403),
                          ({"sec-fetch-site": "same-site", "origin": "https://dashboard.example.ts.net"}, 403),
                          ({"origin": "null"}, 403),
                          ({"origin": "http://127.0.0.1:8431"}, 403),
                          ({"sec-fetch-site": "none", "origin": None, "referer": None}, 403)):
        h = {k: v for k, v in {**chrome_post(), **headers}.items() if v is not None}
        r = client.post(f"/domain/{did}/status", data={"status": "confirmed"}, headers=h, follow_redirects=False)
        assert r.status_code == code, (headers, r.status_code)
    # DNS rebinding: a Host the dashboard does not answer on
    r = client.post(f"/domain/{did}/status", data={"status": "confirmed"},
                    headers={**chrome_post(), "host": "rebind.attacker.example:8430"}, follow_redirects=False)
    assert r.status_code == 400 and "not an address of this dashboard" in r.text
    assert one(client, "SELECT status, notes, status_changed_at FROM domains WHERE id = %s", (did,)) == snapshot
    assert len(_status_events(client, did)) == n_events


def test_concurrent_notes_are_all_kept(world, client):
    """Ten reviewers press a button at once: every note survives (UPDATE re-reads the row it waited for)."""
    import asyncio

    import httpx

    from cybercheck.web.app import app
    did = world["watch"]
    page = f"/domain/{did}"

    async def burst():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as ac:
            rs = await asyncio.gather(*(ac.post(f"/domain/{did}/status", headers=chrome_post(page),
                                                data={"status": "open", "note": f"note {i}"}) for i in range(10)))
        return [r.status_code for r in rs]

    n_before = len(_status_events(client, did))
    assert call(client, burst) == [303] * 10
    notes = one(client, "SELECT notes FROM domains WHERE id = %s", (did,))["notes"].split("\n")
    assert sorted(notes) == sorted(f"note {i}" for i in range(10))
    assert len(_status_events(client, did)) == n_before + 10


# Regression: set_status commits the domains UPDATE and its 'status' event in one transaction.
def test_concurrent_decisions_leave_the_timeline_in_step_with_the_status(world, client):
    """Reviewers disagreeing at the same moment: the newest 'status' event (the audit trail on the domain page)
    must be the decision the domain row actually holds, and in the order the row changed."""
    import asyncio

    import httpx

    from cybercheck.web.app import app
    did = world["watch"]
    page = f"/domain/{did}"

    async def burst(n):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as ac:
            rs = await asyncio.gather(*(ac.post(f"/domain/{did}/status", headers=chrome_post(page), data={
                "status": ("benign", "open")[i % 2], "note": f"decision {i}"}) for i in range(n)))
        return [r.status_code for r in rs]

    try:
        for _ in range(5):
            assert call(client, burst, 12) == [303] * 12
            d = one(client, "SELECT status, notes FROM domains WHERE id = %s", (did,))
            events = _status_events(client, did)
            assert events[-1]["status"] == d["status"], (events[-3:], d["status"])
            # the notes column and the events record the decisions in the same order
            tail = d["notes"].split("\n")[-12:]
            assert [e["note"] for e in events[-12:]] == tail
    finally:
        redirect(post(client, f"/domain/{did}/status", {"status": "open"}, page), page)


async def _store_one(host: str, source: str = "ct"):
    p = await db.pool()
    async with p.connection() as conn:
        return await store_hit(conn, hit_for(host), source, "R11", "Let's Encrypt 'Oak2026h2'")


def confirm(c, key_or_id, world, note: str = "") -> None:
    did = world[key_or_id] if isinstance(key_or_id, str) else key_or_id
    redirect(post(c, f"/domain/{did}/status", {"status": "confirmed", "note": note}, f"/domain/{did}"),
             f"/domain/{did}")


# ---- reports ------------------------------------------------------------------------------------------

def reports_of(c, did) -> dict[str, dict]:
    return {r["channel"]: r for r in sql(c, "SELECT * FROM reports WHERE domain_id = %s", (did,))}


def report_action(c, rid: int, action: str, data: dict | None = None, detail: bool = False) -> str:
    """POST a report form; returns the msg key of the redirect."""
    d = dict(data or {})
    if detail:
        d["back"] = "detail"
    r = post(c, f"/reports/{rid}/{action}", d, f"/reports/{rid}" if detail else "/reports")
    q = redirect(r, f"/reports/{rid}" if detail else "/reports")
    if not detail:
        assert r.headers["location"].endswith(f"#r{rid}")
    return q["msg"]


async def _worker_attempt(rid: int, channel: str, via: str, outcome: str, response: dict | None = None) -> None:
    """What the report job does around one delivery (engine.claim_next / record_result), with its SQL."""
    from cybercheck.reporting import engine
    p = await db.pool()
    async with p.connection() as conn:
        assert await (await conn.execute(engine.CLAIM_SQL, (rid,))).fetchone()
        att = (await (await conn.execute(engine.ATTEMPT_SQL, (rid, channel, via))).fetchone())["id"]
        if outcome == "in_flight":
            return
        if outcome == "sent":
            await conn.execute(engine.ATTEMPT_DONE_SQL, (True, 200, None, db.jsonb(response or {}), att))
            await conn.execute(engine.SENT_SQL, (via, (response or {}).get("uuid"), db.jsonb(response or {}),
                                                 db.jsonb({"sent": {"urls": 1}}), rid))
            row = await (await conn.execute("SELECT domain_id FROM reports WHERE id = %s", (rid,))).fetchone()
            did = row["domain_id"]
            await engine.mark_domain_reported(conn, did, {"channel": channel, "via": via, "report_id": rid})
        else:
            err = "SMTP 550 5.1.1 mailbox unavailable"
            await conn.execute(engine.ATTEMPT_DONE_SQL, (False, None, err, db.jsonb({}), att))
            await conn.execute(engine.FAIL_SQL, (err, db.jsonb({"smtp": 550}), db.jsonb({"last_error": err}), rid))


async def _cancel_closed() -> int:
    from cybercheck.reporting import engine
    p = await db.pool()
    async with p.connection() as conn:
        return await engine.cancel_closed(conn)


def test_report_creation_branches(world, client):
    # an open domain is not reported from the dashboard
    assert redirect(post(client, f"/reports/create/{world['watch']}"), "/reports")["msg"] == "not_confirmed"
    assert reports_of(client, world["watch"]) == {}
    # confirmed, but already taken down
    confirm(client, "down", world)
    assert redirect(post(client, f"/reports/create/{world['down']}"), "/reports")["msg"] == "taken_down"
    # an official brand domain cannot be confirmed from the dashboard any more ...
    did = world["official"]
    r = post(client, f"/domain/{did}/status", {"status": "confirmed"}, f"/domain/{did}")
    assert r.status_code == 400 and "official brand domain" in r.text
    assert sql(client, "SELECT status FROM domains WHERE id = %s", (did,))[0]["status"] == "open"
    # ... but a row confirmed before that rule (or by hand in SQL) must still be refused by reports
    sql(client, "UPDATE domains SET status = 'confirmed', status_changed_at = now(), status_by = 'legacy' "
                "WHERE id = %s RETURNING id", (did,))
    assert redirect(post(client, f"/reports/create/{world['official']}"), "/reports")["msg"] == "official"
    assert reports_of(client, world["down"]) == {} and reports_of(client, world["official"]) == {}
    # confirmed and live: the dashboard lists it until reports exist
    confirm(client, "phish", world, "NetBank clone, confirmed from the screenshot")
    t = get(client, "/reports").text
    assert f'action="/reports/create/{world["phish"]}"' in t
    assert f'action="/reports/create/{world["down"]}"' not in t       # taken down: not "not reported yet"
    assert redirect(post(client, f"/reports/create/{world['phish']}"), "/reports")["msg"] == "created"
    rep = reports_of(client, world["phish"])
    assert {k: (v["kind"], v["status"]) for k, v in rep.items()} == {
        "netcraft": ("api", "approved"), "registrar_abuse": ("email", "pending_review"),
        "hosting_abuse": ("email", "pending_review"), "brand:commbank": ("email", "pending_review"),
        "google_safe_browsing": ("manual", "pending_review"), "microsoft_smartscreen": ("manual", "pending_review"),
        "scamwatch": ("manual", "pending_review")}
    reg = rep["registrar_abuse"]["payload"]
    assert reg["to"] == "abuse@namesilo.com" and reg["created_by"] == REVIEWER and reg["trigger"] == "confirmed"
    assert reg["page_id"] == page_of(world, "phish", "mobile")["id"] or reg["page_id"] == page_of(world, "phish")["id"]
    assert "commbank-secure.top" in reg["body"] and reg["attach_screenshot"] is True
    assert rep["netcraft"]["auto"] is False
    # repeated: nothing new, nothing changed
    assert redirect(post(client, f"/reports/create/{world['phish']}"), "/reports")["msg"] == "nothing"
    assert reports_of(client, world["phish"]).keys() == rep.keys()
    assert f'action="/reports/create/{world["phish"]}"' not in get(client, "/reports").text


def test_confirming_while_the_judge_stores_a_verdict_cannot_deadlock(world, client, it_db):
    """The judge stores a verdict in one transaction: page row first, then its domain row (store_verdict). A
    reviewer confirming that domain at the same moment must not take the two locks in the other order."""
    from cybercheck.jobs import judge
    did = world["phish"]
    page_id = page_of(world, "phish")["id"]
    n_events = len(_status_events(client, did))
    out = {}
    with psycopg.connect(it_db, row_factory=dict_row) as judge_conn:
        with judge_conn.transaction():
            judge_conn.execute("SET LOCAL lock_timeout = '5s'")
            # what judge._mark_page / store_verdict do first: the page row
            judge_conn.execute("UPDATE pages SET ai_judged_at = ai_judged_at, ai_result = ai_result WHERE id = %s",
                               (page_id,))
            th = threading.Thread(target=lambda: out.setdefault("r", post(
                client, f"/domain/{did}/status", {"status": "confirmed", "note": "re-confirmed during a judge run"},
                f"/domain/{did}")))
            th.start()
            time.sleep(0.6)
            assert th.is_alive()                    # waiting for the page row (the evidence flag)
            # the decision itself is already committed and visible
            assert len(_status_events(client, did)) == n_events + 1
            # then the judge's domain update (SET_DOMAIN_AI_SQL): must not wait for the reviewer
            row = judge_conn.execute(judge.SET_DOMAIN_AI_SQL, {
                "verdict": "phishing", "confidence": 0.97, "brand": "commbank", "domain_id": did,
                "page_id": page_id, "fetched_at": page_of(world, "phish")["fetched_at"],
                "changed_only": True}).fetchone()
            assert row is None                      # nothing changed: same verdict
        th.join(10)
    assert not th.is_alive()
    redirect(out["r"], f"/domain/{did}")
    assert all(p["is_evidence"] for p in sql(client, "SELECT is_evidence FROM pages WHERE domain_id = %s", (did,)))
    assert one(client, "SELECT status FROM domains WHERE id = %s", (did,))["status"] == "confirmed"


def test_email_draft_lifecycle(world, client, monkeypatch):
    rep = reports_of(client, world["phish"])
    rid = rep["registrar_abuse"]["id"]
    t = get(client, f"/reports/{rid}").text
    assert 'name="back" value="detail"' in t and "abuse@namesilo.com" in t and "Approve and send (SMTP)" in t
    jpg = get(client, f"/reports/{rid}/screenshot.jpg")
    assert jpg.content[:2] == b"\xff\xd8" and jpg.headers["content-type"] == "image/jpeg"
    assert f'report-{rid}-screenshot.jpg' in jpg.headers["content-disposition"]
    get(client, f"/reports/{rep['netcraft']['id']}/screenshot.jpg", 404)        # API report: no screenshot

    body = "Hello NameSilo abuse team,\n\nhttps://login.commbank-secure.top/ is a CommBank phishing page.\n— CyberCheck"
    # save from the detail page: the edits are the reviewer's, and the AI draft may no longer replace them
    assert report_action(client, rid, "save", {"to": " abuse@namesilo.com ", "subject": "Phishing on your\r\nnetwork",
                                               "body": body}, detail=True) == "saved"
    p = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))["payload"]
    assert p["to"] == "abuse@namesilo.com" and p["subject"] == "Phishing on your network" and p["body"] == body
    assert p["ai"] == "edited" and p["edited_by"] == REVIEWER and p["template_body"] != body
    assert "Template text (before AI or edits)" in get(client, f"/reports/{rid}").text
    # approve refusals: each keeps the edits and leaves the draft waiting
    assert report_action(client, rid, "approve", {"to": "", "subject": "s", "body": body}) == "bad_to"
    assert report_action(client, rid, "approve", {"to": "abuse@login.commbank-secure.top", "subject": "s",
                                                  "body": body}) == "unsafe_to"
    # an address on another domain CyberCheck tracks as suspicious (the open .net domain)
    assert report_action(client, rid, "approve", {"to": "abuse@westpac-verify.net", "subject": "s",
                                                  "body": body}) == "unsafe_to"
    monkeypatch.delenv("SMTP_HOST")
    assert report_action(client, rid, "approve", {"to": "abuse@namesilo.com", "subject": "s",
                                                  "body": body}) == "no_smtp"
    monkeypatch.setenv("SMTP_HOST", ENV["SMTP_HOST"])
    monkeypatch.setenv("REPORTING_MODE", "off")
    config.settings.cache_clear()
    try:
        assert report_action(client, rid, "approve", {"to": "abuse@namesilo.com", "subject": "s",
                                                      "body": body}) == "mode_off"
        assert "Reporting is off" in get(client, "/reports").text
    finally:
        monkeypatch.setenv("REPORTING_MODE", "review")
        config.settings.cache_clear()
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "pending_review" and r["payload"]["subject"] == "s" and r["reviewed_by"] is None
    # approve: queued for the worker
    assert report_action(client, rid, "approve", {"to": "abuse@namesilo.com", "subject": "Phishing report",
                                                  "body": body}, detail=True) == "queued"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "approved" and r["reviewed_by"] == REVIEWER and r["attempts"] == 0
    assert r["payload"]["approved_by"] == REVIEWER and r["next_attempt_at"] is not None
    assert report_action(client, rid, "approve", {"to": "abuse@namesilo.com"}) == "not_pending"
    assert report_action(client, rid, "save", {"to": "x@y.org"}) == "not_pending"
    t = get(client, "/reports").text
    assert re.search(rf'<tr id="r{rid}">.*?queued.*?Send now', t, re.S)
    # the worker's SMTP delivery fails for good
    call(client, _worker_attempt, rid, "registrar_abuse", "smtp", "failed")
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "failed" and r["attempts"] == 1 and "550" in r["error"]
    t = get(client, f"/reports/{rid}").text
    assert "SMTP 550 5.1.1 mailbox unavailable" in t and ">failed<" in t
    assert re.search(rf'<tr id="r{rid}">.*?SMTP 550.*?Retry', get(client, "/reports").text, re.S)
    # retry: queued again with a clean slate
    assert report_action(client, rid, "retry") == "retry"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "approved" and r["attempts"] == 0 and r["error"] is None
    # cancel it after all
    assert report_action(client, rid, "reject", {"note": "Wrong registrar: the domain moved to Dynadot"}) == "rejected"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "rejected" and r["error"] == ("rejected by " + REVIEWER +
                                                       ": Wrong registrar: the domain moved to Dynadot")
    for action in ("reject", "save", "approve", "sent", "retry"):
        assert report_action(client, rid, action, {"to": "abuse@namesilo.com"}) == "not_pending", action
    assert one(client, "SELECT status FROM reports WHERE id = %s", (rid,))["status"] == "rejected"


def test_mark_sent_manual_items_and_api_sends(world, client):
    did = world["phish"]
    rep = reports_of(client, did)
    hosting = rep["hosting_abuse"]["id"]
    assert one(client, "SELECT reported_at FROM domains WHERE id = %s", (did,))["reported_at"] is None
    assert report_action(client, hosting, "sent", {"to": "not an address", "subject": "s", "body": "b"}) == "bad_to"
    assert one(client, "SELECT status FROM reports WHERE id = %s", (hosting,))["status"] == "pending_review"
    assert report_action(client, hosting, "sent", {"to": "abuse@vultr.com", "subject": "Phishing on 45.77.1.10",
                                                   "body": "Sent from my own mail client."}, detail=True) == "sent"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (hosting,))
    assert (r["status"], r["sent_via"], r["sent_by"], r["reviewed_by"]) == ("sent", "manual", REVIEWER, REVIEWER)
    assert r["payload"]["to"] == "abuse@vultr.com" and r["payload"]["marked_sent_by"] == REVIEWER
    d = one(client, "SELECT reported_at FROM domains WHERE id = %s", (did,))
    assert d["reported_at"] is not None
    ev = sql(client, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'reported'", (did,))
    assert ev[-1]["detail"]["channel"] == "hosting_abuse" and ev[-1]["detail"]["reviewed_by_human"] is True
    assert report_action(client, hosting, "sent", {"to": "abuse@vultr.com"}) == "not_pending"
    # the brand's own mailbox: rejected with a reason
    brand = rep["brand:commbank"]["id"]
    assert report_action(client, brand, "reject", {"note": "CBA already knows (their ticket 12345)"}) == "rejected"
    # manual web forms: Scamwatch filed (done), Safe Browsing not applicable, SmartScreen left waiting
    scam = rep["scamwatch"]["id"]
    t = get(client, f"/reports/{scam}").text
    assert "https://forms.scamwatch.gov.au/report-a-scamwebsite/" in t and "Mark as done" in t
    assert get(client, f"/reports/{scam}/screenshot.jpg").content[:2] == b"\xff\xd8"
    assert report_action(client, scam, "sent") == "done"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (scam,))
    assert r["status"] == "sent" and r["sent_via"] == "manual"
    gsb = rep["google_safe_browsing"]["id"]
    assert report_action(client, gsb, "retry") == "not_api"
    assert report_action(client, gsb, "reject", {"note": ""}, detail=True) == "rejected"
    assert one(client, "SELECT error FROM reports WHERE id = %s", (gsb,))["error"] == "rejected by " + REVIEWER
    # Netcraft goes out through the API (the worker), then shows its takedown state
    nc = rep["netcraft"]["id"]
    assert report_action(client, nc, "sent") == "not_pending"          # API reports are never marked by hand
    resp = {"uuid": "4c5f2bd1a9e34d7c8a1b0e9f6d3c2b1a", "test": False,
            "status": {"state": "processing", "urls": [{"url": "https://login.commbank-secure.top/",
                                                        "url_takedown_state": "not_started"}]}}
    call(client, _worker_attempt, nc, "netcraft", "api", "sent", resp)
    r = one(client, "SELECT * FROM reports WHERE id = %s", (nc,))
    assert r["status"] == "sent" and r["external_id"] == resp["uuid"] and r["sent_via"] == "api"
    assert report_action(client, nc, "retry") == "not_pending"
    t = get(client, "/reports").text
    assert "processing; takedown: not_started" in t and resp["uuid"] in t
    t = get(client, f"/reports/{nc}").text
    assert ">ok<" in t and "4c5f2bd1a9e34d7c8a1b0e9f6d3c2b1a" in t


def test_sending_skipped_and_unconfirmed_reports(world, client):
    # idn: Netcraft claimed by the worker, request in flight
    confirm(client, "idn", world)
    assert redirect(post(client, f"/reports/create/{world['idn']}"), "/reports")["msg"] == "created"
    nc = reports_of(client, world["idn"])["netcraft"]["id"]
    call(client, _worker_attempt, nc, "netcraft", "api", "in_flight")
    assert one(client, "SELECT status FROM reports WHERE id = %s", (nc,))["status"] == "sending"
    assert report_action(client, nc, "reject") == "not_pending"
    assert report_action(client, nc, "retry") == "not_pending"
    assert "in flight" in get(client, f"/reports/{nc}").text
    assert re.search(rf'<tr id="r{nc}">.*?sending', get(client, "/reports").text, re.S)

    # fp: reported, then the reviewer changes their mind; the worker cancels what was not sent yet
    confirm(client, "fp", world)
    assert redirect(post(client, f"/reports/create/{world['fp']}"), "/reports")["msg"] == "created"
    rep = reports_of(client, world["fp"])
    redirect(post(client, f"/domain/{world['fp']}/status", {"status": "false_positive", "note": "ANZ test site"}),
             f"/domain/{world['fp']}")
    email = rep["registrar_abuse"]["id"]
    assert report_action(client, email, "approve", {"to": "abuse@namesilo.com", "subject": "s",
                                                    "body": "b"}) == "closed"
    assert report_action(client, email, "sent", {"to": "abuse@namesilo.com"}) == "closed"
    assert call(client, _cancel_closed) == len(rep)
    rows = reports_of(client, world["fp"])
    assert {r["status"] for r in rows.values()} == {"skipped"}
    assert rows["netcraft"]["error"] == "domain marked false_positive by a reviewer; not sent"
    assert call(client, _cancel_closed) == 0                            # idempotent
    assert report_action(client, rows["netcraft"]["id"], "retry") == "closed"
    t = get(client, "/reports").text
    assert "domain marked false_positive by a reviewer; not sent" in t
    assert report_action(client, rows["scamwatch"]["id"], "reject") == "rejected"       # skipped -> rejected
    # confirmed again after all: "Create reports" revives the skipped API report (engine REVIVE_SQL)
    confirm(client, "fp", world, "it is phishing after all")
    assert redirect(post(client, f"/reports/create/{world['fp']}"), "/reports")["msg"] == "created"
    rows = reports_of(client, world["fp"])
    assert rows["netcraft"]["status"] == "approved" and rows["netcraft"]["error"] is None
    assert rows["registrar_abuse"]["status"] == "skipped" and rows["scamwatch"]["status"] == "rejected"
    redirect(post(client, f"/domain/{world['fp']}/status", {"status": "false_positive"}), f"/domain/{world['fp']}")
    assert call(client, _cancel_closed) == 1

    # pending: reported, then reopened: nothing may be approved or retried until it is confirmed again
    confirm(client, "pending", world)
    assert redirect(post(client, f"/reports/create/{world['pending']}"), "/reports")["msg"] == "created"
    rep = reports_of(client, world["pending"])
    redirect(post(client, f"/domain/{world['pending']}/status", {"status": "open"}), f"/domain/{world['pending']}")
    assert report_action(client, rep["registrar_abuse"]["id"], "approve",
                         {"to": "abuse@namesilo.com", "subject": "s", "body": "b"}) == "not_confirmed"
    sql(client, "UPDATE reports SET status = 'failed', error = 'HTTP 500' WHERE id = %s", (rep["netcraft"]["id"],))
    assert report_action(client, rep["netcraft"]["id"], "retry") == "not_confirmed"
    t = get(client, f"/reports/{rep['registrar_abuse']['id']}").text
    assert "no longer confirmed by a reviewer" in t and "Approve and send (SMTP)" not in t
    # an email retried after it failed must still pass the address checks
    sql(client, "UPDATE reports SET status = 'failed', payload = payload || %s WHERE id = %s",
        (db.jsonb({"to": "abuse@commbank-alert-003.top"}), rep["hosting_abuse"]["id"]))
    confirm(client, "pending", world)
    assert report_action(client, rep["netcraft"]["id"], "retry", detail=True) == "retry"
    assert one(client, "SELECT status FROM reports WHERE id = %s", (rep["netcraft"]["id"],))["status"] == "approved"
    assert report_action(client, rep["hosting_abuse"]["id"], "retry") == "unsafe_to"
    sql(client, "UPDATE reports SET payload = payload || %s WHERE id = %s",
        (db.jsonb({"to": ""}), rep["hosting_abuse"]["id"]))
    assert report_action(client, rep["hosting_abuse"]["id"], "retry") == "bad_to"


def test_report_row_lock_serialises_reviewers(world, client, it_db):
    """Two reviewers act on one draft at once: the second waits for the row lock and then sees the change."""
    rid = reports_of(client, world["phish"])["microsoft_smartscreen"]["id"]
    out = {}
    with psycopg.connect(it_db, row_factory=dict_row) as other:
        with other.transaction():
            other.execute("SELECT id FROM reports WHERE id = %s FOR UPDATE", (rid,))
            other.execute("UPDATE reports SET status = 'rejected', error = 'rejected by other@example.org', "
                          "updated_at = now() WHERE id = %s", (rid,))
            th = threading.Thread(target=lambda: out.setdefault("r", post(client, f"/reports/{rid}/sent")))
            th.start()
            time.sleep(0.6)
            assert th.is_alive()                     # blocked on FOR UPDATE OF r
        th.join(10)
    assert redirect(out["r"], "/reports")["msg"] == "not_pending"
    r = one(client, "SELECT * FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "rejected" and r["sent_at"] is None


def test_reports_page_and_details_render_every_state(world, client):
    sql(client, "INSERT INTO kv (key, value) VALUES (%s, %s), (%s, %s)", (
        "report:pause", db.jsonb({"netcraft": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
                                  "registrar_abuse": "2020-01-01T00:00:00+00:00", "bogus": "not a time"}),
        "job:report", db.jsonb({"last_run": datetime.now(timezone.utc).isoformat(), "ok": True, "duration_s": 0.4,
                                "result": {"planned": 7, "sent": 1}})))
    t = get(client, "/reports").text
    assert "Netcraft report API asked us to slow down (HTTP 429)" in t and "Registrar abuse contact asked" not in t
    assert "sent 1" in t and "planned 7" in t           # jsonb keeps its own key order
    n = one(client, "SELECT count(*) AS n FROM report_attempts")["n"]
    assert n == 3 and f"Rate limit: {n} of 10 sends" in t
    assert "SMTP for approved emails: on, from" in t and ENV["SMTP_PASSWORD"] not in t
    statuses = {r["status"] for r in sql(client, "SELECT status FROM reports")}
    assert statuses == {"pending_review", "approved", "sending", "sent", "failed", "rejected", "skipped"}
    # confirmed, live and not reported: listed with a Create button
    confirm(client, "czds", world)
    t = get(client, "/reports").text
    assert f'action="/reports/create/{world["czds"]}"' in t
    for r in sql(client, "SELECT id FROM reports ORDER BY id"):
        get(client, f"/reports/{r['id']}")
    sql(client, "UPDATE kv SET value = %s WHERE key = 'job:report'", (db.jsonb(
        {"last_run": datetime.now(timezone.utc).isoformat(), "ok": False, "error": "OperationalError: boom"}),))
    assert "<b>failed</b>: OperationalError: boom" in get(client, "/reports").text
    get(client, "/reports/99999999999999999999", 404)
    get(client, "/reports/99999999999999999999/screenshot.jpg", 404)
    assert post(client, "/reports/99999999999999999999/approve").status_code == 404


# ---- blocklist --------------------------------------------------------------------------------------

def _bl(c, did) -> dict:
    return one(c, "SELECT blocklisted, blocklist_excluded, blocklist_excluded_by, blocklist_excluded_at, "
                  "blocklist_listed_at, blocklist_expires_at FROM domains WHERE id = %s", (did,))


def _hosts_txt(c) -> str:
    return get(c, "/blocklist/files/hosts.txt").text


def test_blocklist_build_exclude_include(world, client, it_db):
    from cybercheck import blocklist
    confirm(client, "shared", world, "Weebly tenant site copying NetBank")
    t = get(client, "/blocklist").text
    assert "Nothing listed yet." in t and "not built yet" in t
    assert redirect(post(client, "/blocklist/rebuild", page="/blocklist"), "/blocklist")["msg"] == "built"
    listed = {r["registered_domain"] for r in sql(client, "SELECT registered_domain FROM domains WHERE blocklisted")}
    # confirmed (phish, idn, shared, pending, and the taken-down one: it may come back), automated (auto: open,
    # AI phishing, score 93); never the official domain, the CZDS-found one (held) or the false positive
    assert listed == {"commbank-secure.top", HOSTS["idn"], "weebly.com", "parcel-redelivery.top",
                      "commbank-alert-003.top", "login-secure.icu"}, listed
    hosts = _hosts_txt(client)
    assert "0.0.0.0 commbank-secure.top" in hosts and "0.0.0.0 commbank-login.weebly.com" in hosts
    assert "0.0.0.0 weebly.com\n" not in hosts and "commbank.com.au" not in hosts and "qantas-points.shop" not in hosts
    r = get(client, "/blocklist/files/rpz.zone")
    assert r.headers["content-security-policy"] == "default-src 'none'" and "commbank-secure.top CNAME ." in r.text
    for name in blocklist.FILES:
        get(client, f"/blocklist/files/{name}")
    get(client, "/blocklist/files/..%2Fblocklist.json", 404)
    get(client, "/blocklist/files/kv", 404)
    t = get(client, "/blocklist?msg=built").text
    assert "Blocklist rebuilt." in t and "hostnames only" in t and "commbank-login.weebly.com" in t
    assert re.search(r'<div class="n">6</div><div class="l">domains listed', t)
    assert re.search(r'<div class="n">5</div><div class="l">confirmed by a reviewer', t)
    assert re.search(r'<div class="n">1</div><div class="l">automated \(score 90\+\)', t)
    assert re.search(r'<div class="n">1</div><div class="l">held back \(CZDS terms\)', t)
    assert "score 93" in t and "listed" in t and "blocklist.cybercheck-it.example.org" in t
    assert "listed until" in get(client, f"/domain/{world['phish']}").text
    ev = sql(client, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'blocklisted'",
             (world["shared"],))
    assert ev and ev[0]["detail"]["scope"] == "hostnames"
    state = one(client, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,))["value"]
    serial = state["serial"]
    # rebuilding with no change keeps the serial and the files
    assert redirect(post(client, "/blocklist/rebuild"), "/blocklist")["msg"] == "built"
    assert one(client, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,))["value"]["serial"] == serial

    # exclude: off the list now, and stays off
    did = world["phish"]
    q = redirect(post(client, f"/blocklist/{did}/exclude", {"note": "brand asked us to wait"}, f"/domain/{did}"),
                 "/blocklist")
    assert q["msg"] == "excluded"
    b = _bl(client, did)
    assert b["blocklist_excluded"] and not b["blocklisted"] and b["blocklist_excluded_by"] == REVIEWER
    assert "commbank-secure.top" not in _hosts_txt(client)
    kinds = [r["kind"] for r in sql(client, "SELECT kind FROM domain_events WHERE domain_id = %s ORDER BY id", (did,))]
    assert kinds[-2:] == ["blocklist_excluded", "unblocklisted"]
    assert one(client, "SELECT 1 AS x FROM kv WHERE key = %s", (blocklist.KV_REBUILD,)) is None   # build consumed it
    assert one(client, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_STATE,))["value"]["serial"] != serial
    t = get(client, "/blocklist").text
    assert "Excluded by reviewers" in t
    assert f'action="/blocklist/{did}/include"' in t
    assert "brand asked us to wait" in t
    assert "excluded by " + REVIEWER in get(client, f"/domain/{did}").text
    assert redirect(post(client, f"/blocklist/{did}/exclude"), "/blocklist")["msg"] == "excluded"     # again: fine
    # include: listed again on the build it triggers
    assert redirect(post(client, f"/blocklist/{did}/include"), "/blocklist")["msg"] == "included"
    b = _bl(client, did)
    assert not b["blocklist_excluded"] and b["blocklist_excluded_by"] is None and b["blocklisted"]
    assert "0.0.0.0 commbank-secure.top" in _hosts_txt(client)
    assert post(client, f"/blocklist/{did}/include").status_code == 404         # not excluded any more
    assert post(client, f"/blocklist/{world['watch']}/include").status_code == 404
    assert post(client, f"/blocklist/{did}/exclude", headers={"origin": "https://evil.example",
                                                              "sec-fetch-site": "cross-site"}).status_code == 403
    assert not _bl(client, did)["blocklist_excluded"]

    # another build holds the lock: the dashboard asks the worker instead of waiting
    with psycopg.connect(it_db) as other:
        with other.transaction():
            other.execute("SELECT pg_advisory_xact_lock(%s)", (blocklist.LOCK_KEY,))
            assert redirect(post(client, "/blocklist/rebuild"), "/blocklist")["msg"] == "busy"
            assert redirect(post(client, f"/blocklist/{world['auto']}/exclude"), "/blocklist")["msg"] == "busy"
    req = one(client, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))
    assert req and req["value"]["by"] == REVIEWER
    assert _bl(client, world["auto"])["blocklist_excluded"] and _bl(client, world["auto"])["blocklisted"]
    assert "A rebuild was requested" in get(client, "/blocklist?msg=busy").text
    assert redirect(post(client, "/blocklist/rebuild"), "/blocklist")["msg"] == "built"
    assert not _bl(client, world["auto"])["blocklisted"]
    assert one(client, "SELECT 1 AS x FROM kv WHERE key = %s", (blocklist.KV_REBUILD,)) is None
    assert redirect(post(client, f"/blocklist/{world['auto']}/include"), "/blocklist")["msg"] == "included"
    assert _bl(client, world["auto"])["blocklisted"]


def test_blocklist_build_failure_leaves_a_request(world, client, monkeypatch):
    from cybercheck import blocklist

    async def broken(conn, **kw):
        raise OSError("No space left on device")
    monkeypatch.setattr(blocklist, "build", broken)
    sql(client, "DELETE FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))
    assert redirect(post(client, "/blocklist/rebuild"), "/blocklist")["msg"] == "failed"
    assert one(client, "SELECT value FROM kv WHERE key = %s", (blocklist.KV_REBUILD,))["value"]["by"] == REVIEWER
    assert "The build failed" in get(client, "/blocklist?msg=failed").text
    assert "Recent changes" in get(client, "/blocklist").text


# ---- Telegram bot -----------------------------------------------------------------------------------

def test_bot_chats_and_forwarded_domains(world, client):
    from cybercheck import bot as botmod
    api = StubTelegram()
    b = botmod.Bot(api, watchlist=WL, ai_on=False)
    sam = {"id": 5550001, "type": "private", "first_name": "Sam", "username": "sam_au"}
    spam = {"id": 5550002, "type": "private", "first_name": "Spammer"}
    group = {"id": -100200300, "type": "supergroup", "title": "Neighbourhood watch"}

    def handle(*updates):
        for u in updates:
            call(client, b.handle_update, u)

    t = get(client, "/bot").text
    assert "No chats yet" not in t and "777000" in t and "not seen yet" in t   # env chats, never seen
    # two strangers write: both pending, nothing checked
    handle(tg_update(1, sam, "hi"), tg_update(2, spam, "check auspost-delivery-track.xyz"))
    rows = {r["chat_id"]: r for r in sql(client, "SELECT * FROM bot_chats")}
    assert rows[sam["id"]]["status"] == "pending" and rows[spam["id"]]["status"] == "pending"
    assert one(client, "SELECT count(*) AS n FROM bot_messages")["n"] == 0
    t = get(client, "/bot").text
    assert "sam_au" in t and f'action="/bot/chat/{sam["id"]}/status"' in t
    assert re.search(r'<div class="n">2</div><div class="l">chats waiting for approval', t)
    # allow Sam, block the spammer
    redirect(post(client, f"/bot/chat/{sam['id']}/status", {"status": "allowed"}, "/bot"), "/bot")
    redirect(post(client, f"/bot/chat/{spam['id']}/status", {"status": "blocked"}, "/bot"), "/bot")
    rows = {r["chat_id"]: r for r in sql(client, "SELECT * FROM bot_chats")}
    assert rows[sam["id"]]["status"] == "allowed" and rows[sam["id"]]["status_by"] == REVIEWER
    assert rows[spam["id"]]["status"] == "blocked" and rows[sam["id"]]["status_changed_at"] is not None
    # Sam forwards a scam SMS: a new suspicious domain, a confirmed one, an official one, a shortener
    handle(tg_update(3, sam, "AusPost: your parcel is held, pay $1.99 at https://auspost-delivery-track.xyz/pay "
                             "or log in at login.commbank-secure.top / auspost.com.au / bit.ly/3xYz",
                     forwarded=True),
           tg_update(4, spam, "anz-update.info"),                          # blocked: ignored
           tg_update(5, group, "is commbаnk-login.top real?"))             # env-allowed group, IDN host
    msgs = sql(client, "SELECT * FROM bot_messages ORDER BY id")
    assert [m["chat_id"] for m in msgs] == [sam["id"], group["id"]]
    assert dict(zip(msgs[0]["registered"], msgs[0]["verdicts"])) == {
        "auspost-delivery-track.xyz": "suspicious", "commbank-secure.top": "confirmed",
        "auspost.com.au": "official", "bit.ly": "shortener"}
    assert msgs[1]["verdicts"] == ["confirmed"] and msgs[1]["registered"] == [HOSTS["idn"]]
    new = one(client, "SELECT * FROM domains WHERE registered_domain = 'auspost-delivery-track.xyz'")
    assert new["source"] == "bot" and new["tier"] == "high"
    assert one(client, "SELECT count(*) AS n FROM domain_events WHERE domain_id = %s AND kind = 'bot_forward'",
               (world["phish"],))["n"] == 1
    assert any(chat == sam["id"] for chat, _ in api.sent)
    # the env-listed chat that never wrote: blocking it creates its row
    redirect(post(client, "/bot/chat/777000/status", {"status": "blocked"}, "/bot"), "/bot")
    assert one(client, "SELECT status, status_by FROM bot_chats WHERE chat_id = 777000") == {
        "status": "blocked", "status_by": REVIEWER}
    # an allowed chat set back to pending, twice (idempotent)
    for _ in range(2):
        redirect(post(client, f"/bot/chat/{sam['id']}/status", {"status": "pending"}, "/bot"), "/bot")
    assert one(client, "SELECT status FROM bot_chats WHERE chat_id = %s", (sam["id"],))["status"] == "pending"
    redirect(post(client, f"/bot/chat/{sam['id']}/status", {"status": "allowed"}, "/bot"), "/bot")
    # refusals
    assert post(client, f"/bot/chat/{sam['id']}/status", {"status": "admin"}).status_code == 400
    assert post(client, f"/bot/chat/{2 ** 53}/status", {"status": "allowed"}).status_code == 400
    assert post(client, f"/bot/chat/{sam['id']}/status", {"status": "blocked"},
                headers={"origin": "https://evil.example"}).status_code == 403
    assert one(client, "SELECT status FROM bot_chats WHERE chat_id = %s", (sam["id"],))["status"] == "allowed"
    # the bot process reports in
    b.username = "CyberCheckItBot"
    call(client, b._housekeeping, True)
    t = get(client, "/bot").text
    assert "as @CyberCheckItBot" in t and "token set" in t and ENV["TELEGRAM_BOT_TOKEN"] not in t
    assert "auspost-delivery-track.xyz" in t and "Neighbourhood watch" in t and "not seen yet" not in t
    assert re.search(r'<div class="n">1</div><div class="l">domains with source bot', t)
    assert re.search(r'<div class="n">2</div><div class="l">checks, last 24 h', t)
    assert re.search(r'<div class="n">5</div><div class="l">domains forwarded, 30 days', t)
    assert re.search(r'<div class="n">1</div><div class="l">new suspicious domains added', t)
    assert re.search(r'<div class="n">2</div><div class="l">chats blocked', t)
    assert "in TELEGRAM_ALLOWED_CHATS, blocked here" in t
    # most forwarded: the confirmed domain first seen by Sam
    i = t.find("Most forwarded, 30 days")
    assert "commbank-secure.top" in t[i:] and f'href="/domain/{world["phish"]}"' in t[i:]
    get(client, f"/domain/{new['id']}")


def _top_forwarded(html: str) -> dict[str, tuple[int, int]]:
    """'Most forwarded' table: registrable domain -> (times, chats)."""
    i = html.find("Most forwarded, 30 days")
    rows = re.findall(r'<td class="dom">(?:<a href="/domain/\d+">)?([^<]+)(?:</a>)?</td>\s*'
                      r'<td class="num">(\d+)</td>\s*<td class="num">(\d+)</td>', html[i:])
    return {reg: (int(n), int(chats)) for reg, n, chats in rows}


def test_bot_most_forwarded_counts_messages_not_hostnames(world, client):
    """One message naming two hostnames of the same registrable domain is one forward of it, not two."""
    from cybercheck import bot as botmod
    group = {"id": -100200300, "type": "supergroup", "title": "Neighbourhood watch"}
    before = _top_forwarded(get(client, "/bot").text)
    assert before["commbank-secure.top"] == (1, 1), before
    b = botmod.Bot(StubTelegram(), watchlist=WL, ai_on=False)
    call(client, b.handle_update, tg_update(
        6, group, "two links in one scam SMS: https://login.commbank-secure.top/a and https://secure.commbank-secure.top/b",
        forwarded=True))
    m = sql(client, "SELECT * FROM bot_messages ORDER BY id DESC LIMIT 1")[0]
    assert m["chat_id"] == group["id"] and m["registered"] == ["commbank-secure.top", "commbank-secure.top"]
    top = _top_forwarded(get(client, "/bot").text)
    assert top["commbank-secure.top"] == (2, 2), top
    # every other domain keeps its count
    assert {k: v for k, v in top.items() if k != "commbank-secure.top"} == {
        k: v for k, v in before.items() if k != "commbank-secure.top"}


# ---- takedown statistics ------------------------------------------------------------------------------

def test_takedown_stats(world, client):
    # the reporting module recorded a report for the taken-down domain before it went
    sql(client, "UPDATE domains SET reported_at = takedown_at - interval '17 hours' WHERE id = %s", (world["down"],))
    t = get(client, "/takedown").text
    confirmed = one(client, "SELECT count(*) AS n FROM domains WHERE status = 'confirmed'")["n"]
    assert re.search(rf'<div class="n">{confirmed}</div><div class="l">flagged domains', t)
    assert re.search(r'<div class="n">1</div><div class="l">taken down', t)
    assert "20.0 h" in t and "17.0 h" in t and "NXDOMAIN" in t
    assert "GoDaddy.com, LLC" in t and "IANA 146" in t and "NameSilo, LLC" in t and "AS16509 AMAZON-02" in t
    assert "unknown (no RDAP data)" in t                          # the manual add was never enriched
    i = t.find("Still up")
    assert "commbank-secure.top" in t[i:] and re.search(r'<span class="pill pill--red"[^>]*>'
                                                        r'<span class="pill-glyph" aria-hidden="true">[^<]+</span>live</span>', t[i:])
    tracked = get(client, "/takedown?scope=tracked").text
    assert "parcel-redelivery.top" in tracked and "parcel-redelivery.top" not in t
    assert "anz-update.info" not in tracked                       # false positive: never tracked
    assert get(client, "/takedown?scope=everything").text.count("flagged domains") == 1
    assert 'value="confirmed" selected' in get(client, "/takedown?scope=everything").text


# ---- hostile or odd input that only a real Postgres refuses ------------------------------------------

def test_nul_and_control_characters_never_reach_postgres(world, client):
    """Postgres text and jsonb cannot hold NUL: a scripted or pasted %00 must not turn into a 500."""
    did = world["watch"]
    page = f"/domain/{did}"
    before = one(client, "SELECT notes FROM domains WHERE id = %s", (did,))["notes"]
    redirect(post(client, f"/domain/{did}/status", {"status": "open", "note": "nul\x00here\r\nbell\x07 ok\t."}, page),
             page)
    d = one(client, "SELECT notes FROM domains WHERE id = %s", (did,))
    assert d["notes"] == before + "\nnulhere\nbell ok\t."
    assert _status_events(client, did)[-1]["note"] == "nulhere\nbell ok\t."
    # a note of only control characters counts as no note
    redirect(post(client, f"/domain/{did}/status", {"status": "open", "note": "\x00\x01"}, page), page)
    assert one(client, "SELECT notes FROM domains WHERE id = %s", (did,))["notes"] == d["notes"]
    # an enormous note is capped, not stored whole
    redirect(post(client, f"/domain/{did}/status", {"status": "open", "note": "x" * 100_000}, page), page)
    assert len(one(client, "SELECT notes FROM domains WHERE id = %s", (did,))["notes"]) == len(d["notes"]) + 1 + 2000
    # blocklist exclusion note (jsonb event detail)
    auto = world["auto"]
    r = post(client, f"/blocklist/{auto}/exclude", {"note": "kit\x00 removed"})
    assert redirect(r, "/blocklist")["msg"] == "excluded"
    ev = sql(client, "SELECT detail FROM domain_events WHERE domain_id = %s AND kind = 'blocklist_excluded' "
                     "ORDER BY id DESC LIMIT 1", (auto,))[0]["detail"]
    assert ev["note"] == "kit removed"
    assert "kit removed by " + REVIEWER in get(client, "/blocklist").text
    assert redirect(post(client, f"/blocklist/{auto}/include"), "/blocklist")["msg"] == "included"
    # search and filter values
    assert _row_ids(get(client, "/domains?q=%00").text) == _row_ids(get(client, "/domains").text)
    assert world["phish"] in _row_ids(get(client, "/domains?q=commbank-secure%00").text)
    assert _row_ids(get(client, "/domains?brand=%00commbank").text) == _row_ids(
        get(client, "/domains?brand=commbank").text)
    assert _row_ids(get(client, "/domains?q=%FF%FE").text) == []        # invalid UTF-8 arrives as U+FFFD
    # report forms already clean their text (reporting.common.clean_text / clean_line)
    rid = reports_of(client, world["pending"])["registrar_abuse"]["id"]
    assert report_action(client, rid, "save", {"to": "abuse@namesilo.com\x00", "subject": "a\x00b",
                                               "body": "line\x00one"}) == "saved"
    p = one(client, "SELECT payload FROM reports WHERE id = %s", (rid,))["payload"]
    assert (p["to"], p["subject"], p["body"]) == ("abuse@namesilo.com", "a b", "lineone")
    assert report_action(client, rid, "reject", {"note": "dup\x00licate"}) == "rejected"
    assert "\x00" not in one(client, "SELECT error FROM reports WHERE id = %s", (rid,))["error"]


def test_auto_mode_banner_with_a_verified_sandbox(world, client, monkeypatch):
    import json
    data_dir = config.settings().data_dir
    (data_dir / "sandbox_verified.json").write_text(json.dumps({
        "verified_at": datetime.now(timezone.utc).isoformat(), "tests_passed": 14, "egress_ip": "203.0.113.45",
        "egress_country": "AU"}))
    monkeypatch.setenv("REPORTING_MODE", "auto")
    config.settings.cache_clear()
    try:
        t = get(client, "/reports").text
        assert "unreviewed domains with a combined score of at least 90" in t
        assert '<span class="pill t-ok">valid</span>' in t and "egress AU" in t
    finally:
        monkeypatch.setenv("REPORTING_MODE", "review")
        config.settings.cache_clear()
        (data_dir / "sandbox_verified.json").unlink()


def test_pages_before_the_module_migrations_ran(world, client):
    """/bot and /czds say what to do when their tables do not exist yet (worker not migrated)."""
    sql(client, "ALTER TABLE bot_messages RENAME TO bot_messages_hidden")
    sql(client, "ALTER TABLE bot_chats RENAME TO bot_chats_hidden")
    sql(client, "ALTER TABLE czds_zones RENAME TO czds_zones_hidden")
    try:
        t = get(client, "/bot").text
        assert "The bot tables don&#39;t exist yet" in t or "The bot tables don't exist yet" in t
        assert "777000" in t                                    # env-allowed chats are still listed
        t = get(client, "/czds").text
        assert "The CZDS tables do not exist yet" in t and "waiting for the first CZDS check" in t
    finally:
        sql(client, "ALTER TABLE bot_messages_hidden RENAME TO bot_messages")
        sql(client, "ALTER TABLE bot_chats_hidden RENAME TO bot_chats")
        sql(client, "ALTER TABLE czds_zones_hidden RENAME TO czds_zones")
    assert "The bot tables" not in get(client, "/bot").text
    assert "The CZDS tables do not exist yet" not in get(client, "/czds").text


def test_every_page_still_renders_after_the_whole_run(world, client):
    """The end state (every status, report state, listing and chat seen above) renders everywhere."""
    paths = ["/", "/review", "/domains", "/domains?page=2", "/reports", "/blocklist", "/czds", "/ai", "/bot",
             "/takedown", "/takedown?scope=tracked", "/healthz", "/api/recent"]
    paths += [f"/domain/{r['id']}" for r in sql(client, "SELECT id FROM domains WHERE NOT registered_domain LIKE "
                                                        "'auspost-track-%%'")]
    paths += [f"/reports/{r['id']}" for r in sql(client, "SELECT id FROM reports")]
    for path in paths:
        get(client, path)
    s = get(client, "/api/recent").json()["stats"]
    assert s["confirmed"] == one(client, "SELECT count(*) AS n FROM domains WHERE status = 'confirmed'")["n"] == 7


def test_every_page_follows_the_csp_and_works_without_javascript(world, client):
    """The end state again, as a browser with JavaScript off and a strict CSP would see it: the CSP header on every
    HTML page; no inline script, style or handler for the CSP to block; every script and stylesheet from /static;
    no link or image pointing at a reported domain; every POST form has a local action and a submit button."""
    from cybercheck.web import app as app_mod
    reported = {r["registered_domain"] for r in sql(client, "SELECT registered_domain FROM domains")}
    paths = ["/", "/?window=24h", "/?window=30d", "/review", "/review?tier=high&sort=newest", "/domains",
             "/domains?sort=host&dir=asc", "/reports", "/blocklist", "/czds", "/ai", "/bot", "/takedown",
             "/takedown?scope=tracked", "/live/list?show=live-phishing", "/live/list?tier=flagged&window=30d"]
    paths += [f"/domain/{r['id']}" for r in sql(client, "SELECT id FROM domains ORDER BY id LIMIT 40")]
    paths += [f"/review/evidence/{world['phish']}", f"/review/evidence/{world['idn']}"]
    paths += [f"/reports/{r['id']}" for r in sql(client, "SELECT id FROM reports")]
    forms = 0
    for path in paths:
        r = get(client, path)
        t = r.text
        assert r.headers["content-security-policy"] == app_mod.CSP, path
        assert not re.search(r"<script(?![^>]*\bsrc=)", t) and "<style" not in t, path
        assert not re.search(r"\sstyle\s*=", t) and not re.search(r"<[^>]+\son[a-z]+\s*=", t), path
        assert not re.search(r"javascript:", t, re.I), path
        for src in re.findall(r'<(?:script|link|img|iframe|source)\b[^>]*\b(?:src|href)="([^"]*)"', t):
            assert src.startswith("/") and not src.startswith("//"), (path, src)
        for href in re.findall(r'<a\b[^>]*\bhref="([^"]*)"', t):
            host = (urlsplit(href).hostname or "").lower()
            assert not host or not any(host == d or host.endswith("." + d) for d in reported), (path, href)
        for form in re.findall(r"<form\b[^>]*>.*?</form>", t, re.S):
            if re.search(r'method="post"', form, re.I):
                forms += 1
                action = re.search(r'\baction="([^"]*)"', form)
                assert action and action.group(1).startswith("/") and not action.group(1).startswith("//"), \
                    (path, form[:200])
                assert re.search(r'<button\b(?![^>]*\bdisabled\b)[^>]*>', form) or 'type="submit"' in form, \
                    (path, form[:200])
    assert forms > 20
