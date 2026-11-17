"""Integration: the Telegram bot (cybercheck/bot.py) and the CZDS job (cybercheck/czds.py, cybercheck/jobs/czds.py)
against a real Postgres 17 (tests/integration/conftest.py).

Every network boundary is stubbed, the database is real:
- Telegram: the real TelegramAPI client on an httpx.MockTransport (getMe, getUpdates, sendMessage).
- AI: the real cybercheck.ai client and budget code on the real Anthropic SDK over an httpx2.MockTransport that
  answers like the Messages API (structured JSON text plus usage numbers), so ai_calls rows are real.
- CZDS: an httpx.MockTransport playing account-api (login), czds-api (links) and czds-download-api (HEAD/GET of
  gzipped zone files). The clock of the czds module is fake so a run can span several days.
"""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import gzip
import json
import logging
import os
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anthropic
import httpx
import httpx2
import psycopg
import pytest
from psycopg.rows import dict_row

from cybercheck import bot, config, czds, db
from cybercheck.ai import budget as ai_budget
from cybercheck.ai import client as ai_client
from cybercheck.jobs import czds as czds_job
from cybercheck.scoring import default_watchlist
from cybercheck.store import store_hit
from cybercheck.worker import JobContext

UTC = timezone.utc
H = timedelta(hours=1)
DAY = timedelta(days=1)


# ---------------------------------------------------------------------------------------------------
# harness helpers
# ---------------------------------------------------------------------------------------------------

def arun(coro):
    """Run one coroutine on a fresh event loop and close the db pool on that same loop (the psycopg pool is
    bound to the loop that opened it)."""
    async def main():
        try:
            return await coro
        finally:
            await db.close()
    return asyncio.run(main())


def q(sql: str, *params) -> list[dict]:
    with db.connect_sync() as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else []


def one(sql: str, *params) -> dict | None:
    r = q(sql, *params)
    return r[0] if r else None


def run_sql(sql: str, *params) -> None:
    with db.connect_sync() as c:
        c.execute(sql, params)


@pytest.fixture(autouse=True)
def env(it_db, monkeypatch):
    assert "@127.0.0.1:55432/" in it_db                     # never a real Postgres
    for k in ("TELEGRAM_ALLOWED_CHATS", "TELEGRAM_BOT_TOKEN", "BOT_DAILY_LIMIT_PER_CHAT", "BOT_AI_DAILY_LIMIT_PER_CHAT",
              "CZDS_USERNAME", "CZDS_PASSWORD", "CZDS_TLDS", "CZDS_WINDOW_START", "CZDS_WINDOW_HOURS",
              "CZDS_STRICT_SOA", "CZDS_MAX_COUNT_CHANGE", "CZDS_KEEP_UNCONFIGURED_DAYS", "CZDS_MAX_NEW_NAMES",
              "CZDS_MAX_HITS_PER_ZONE", "JOB_CZDS_ENABLED", "AI_FALLBACKS", "AI_EFFORT", "AI_TRIAGE_MODEL",
              "WATCH_DAYS", "WATCHLIST_PATH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_MODEL", "claude-opus-5-5")
    monkeypatch.setenv("AI_DAILY_BUDGET_USD", "1.60")
    monkeypatch.setenv("AI_MONTHLY_BUDGET_USD", "48")
    monkeypatch.setenv("CZDS_MIN_FREE_GB", "0.5")
    config.settings.cache_clear()
    ai_budget._logged.clear()
    db._pool = None
    assert config.settings().database_url == it_db
    run_sql("TRUNCATE domains, domain_events, bot_chats, bot_messages, czds_zones, czds_runs, kv, ai_calls "
            "RESTART IDENTITY CASCADE")
    shutil.rmtree(config.settings().data_dir / "czds", ignore_errors=True)
    yield
    ai_client.set_client(None)
    config.settings.cache_clear()


WL = default_watchlist()


def ct_store(host: str, **kw) -> int:
    """A domain found by CT ingest (cybercheck.store.store_hit, source 'ct')."""
    hit = WL.score_hostname(host)
    assert hit is not None, host

    async def go():
        p = await db.pool()
        async with p.connection() as conn:
            return await store_hit(conn, hit, source=kw.get("source", "ct"), issuer=kw.get("issuer", "R11"),
                                   ct_log=kw.get("ct_log", "Google 'Argon2026h2'"))
    did, inserted = arun(go())
    assert inserted
    return did


def events(domain_id: int) -> list[tuple[str, dict]]:
    return [(r["kind"], r["detail"]) for r in q("SELECT kind, detail FROM domain_events WHERE domain_id = %s "
                                                  "ORDER BY id", domain_id)]


def domain(reg: str) -> dict | None:
    return one("SELECT * FROM domains WHERE registered_domain = %s", reg)


def chat_row(chat_id: int) -> dict | None:
    return one("SELECT * FROM bot_chats WHERE chat_id = %s", chat_id)


def dashboard_set_chat(chat_id: int, status: str, who: str = "reviewer@tailnet") -> None:
    """What the dashboard's POST /bot/chat/{id}/status writes (cybercheck/web/pages_bot.py)."""
    run_sql("INSERT INTO bot_chats (chat_id, status, status_changed_at, status_by) VALUES (%s, %s, now(), %s) "
            "ON CONFLICT (chat_id) DO UPDATE SET status = EXCLUDED.status, status_changed_at = now(), "
            "status_by = EXCLUDED.status_by", chat_id, status, who)


def dashboard_review(reg: str, status: str, **cols) -> None:
    """A reviewer's decision on a domains row: status plus the hostnames they were shown."""
    sets = ", ".join(f"{k} = %s" for k in cols)
    run_sql("UPDATE domains SET status = %s, status_changed_at = now(), status_by = 'reviewer', "
            "reviewed_hostnames = hostnames" + (", " + sets if sets else "") + " WHERE registered_domain = %s",
            status, *cols.values(), reg)


# ---------------------------------------------------------------------------------------------------
# fake Telegram (the real TelegramAPI client talks to it)
# ---------------------------------------------------------------------------------------------------

class Telegram:
    TOKEN = "123456789:IT-test-token-not-real"

    def __init__(self):
        self.sent: list[dict] = []
        self.updates: list[list] = []
        self.polls: list[dict] = []
        self.send_errors: list[tuple[int, dict]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.telegram.org" and request.method == "POST"
        prefix = f"/bot{self.TOKEN}/"
        assert request.url.path.startswith(prefix)
        method = request.url.path[len(prefix):]
        body = json.loads(request.content or b"{}")
        if method == "getMe":
            return httpx.Response(200, json={"ok": True, "result": {"id": 123456789, "is_bot": True,
                                                                    "first_name": "CyberCheck",
                                                                    "username": "CyberCheckTestBot"}})
        if method == "getUpdates":
            self.polls.append(body)
            return httpx.Response(200, json={"ok": True, "result": self.updates.pop(0) if self.updates else []})
        if method == "sendMessage":
            if self.send_errors:
                code, data = self.send_errors.pop(0)
                return httpx.Response(code, json=data)
            self.sent.append(body)
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 5000 + len(self.sent),
                                                                    "chat": {"id": body["chat_id"]}}})
        return httpx.Response(404, json={"ok": False, "error_code": 404, "description": "Not Found"})

    def texts(self, chat_id: int) -> list[str]:
        return [m["text"] for m in self.sent if m["chat_id"] == chat_id]


@asynccontextmanager
async def make_bot(tg: Telegram, **kw):
    async with httpx.AsyncClient(transport=httpx.MockTransport(tg.handler)) as http:
        kw.setdefault("allowed_chats", [])
        kw.setdefault("daily_limit", 20)
        kw.setdefault("ai_limit", 5)
        kw.setdefault("ai_on", False)
        b = bot.Bot(bot.TelegramAPI(tg.TOKEN, http), **kw)     # real db_repo, real default watchlist
        b.username = "CyberCheckTestBot"
        yield b


def update(uid: int, chat_id: int, text: str | None = None, *, chat_type: str = "private", title: str = "Sam",
           username: str | None = "sam_au", forwarded: bool = True, **extra) -> dict:
    chat: dict = {"id": chat_id, "type": chat_type}
    if chat_type == "private":
        chat["first_name"] = title
        if username:
            chat["username"] = username
    else:
        chat["title"] = title
    msg: dict = {"message_id": 1000 + uid, "date": 1763251200, "chat": chat,
                 "from": {"id": 4242, "is_bot": False, "first_name": "Sam", "language_code": "en"}}
    if text is not None:
        msg["text"] = text
    if forwarded:
        msg["forward_origin"] = {"type": "hidden_user", "sender_user_name": "CommBank Alerts", "date": 1763250000}
    msg.update(extra)
    return {"update_id": uid, "message": msg}


SCAM = ("CommBank: your NetBank access has been suspended due to unusual activity. Verify your identity at "
        "https://commbank-verify-account.top/login within 24 hours to avoid permanent suspension.")


# ---------------------------------------------------------------------------------------------------
# fake Anthropic Messages API (the real SDK and the real cybercheck.ai client talk to it)
# ---------------------------------------------------------------------------------------------------

class FakeClaude:
    def __init__(self):
        self.responses: list = []
        self.requests: list[dict] = []

    def __call__(self, request):
        assert request.url.path == "/v1/messages"
        self.requests.append(json.loads(request.content))
        r = self.responses.pop(0)
        return r if isinstance(r, httpx2.Response) else httpx2.Response(200, json=r)

    def install(self):
        ai_client.set_client(anthropic.AsyncAnthropic(
            api_key="sk-test-not-a-real-key", base_url="https://api.anthropic.com", max_retries=0,
            http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(self))))


def claude_message(explanation: str, *, input_tokens=1180, output_tokens=164, cache_read=1536) -> dict:
    return {"id": "msg_01ItTest", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
            "content": [{"type": "thinking", "thinking": "", "signature": "c2ln"},
                        {"type": "text", "text": json.dumps({"explanation": explanation})}],
            "stop_reason": "end_turn", "stop_sequence": None, "stop_details": None,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "cache_read_input_tokens": cache_read, "cache_creation_input_tokens": 0}}


# ===================================================================================================
# bot
# ===================================================================================================

def test_bot_new_chat_is_pending_until_allowed_then_checks_are_stored():
    tg = Telegram()

    async def unknown_chat():
        async with make_bot(tg) as b:
            await b.handle_update(update(1, 5001, SCAM))
            await b.handle_update(update(2, 5001, SCAM))
    arun(unknown_chat())
    assert tg.texts(5001) == [bot.NOT_ENABLED_TEXT]                      # once, not per message
    c = chat_row(5001)
    assert (c["status"], c["chat_type"], c["title"], c["username"]) == ("pending", "private", "Sam", "sam_au")
    assert c["day_messages"] == 0 and c["total_messages"] == 0 and c["counter_day"] is None
    assert q("SELECT * FROM domains") == [] and q("SELECT * FROM bot_messages") == []

    dashboard_set_chat(5001, "allowed")
    before = chat_row(5001)["last_seen"]

    async def allowed_chat():
        async with make_bot(tg) as b:
            await b.handle_update(update(3, 5001, SCAM))
            return b.stats
    stats = arun(allowed_chat())
    assert stats["checks"] == 1 and stats["errors"] == 0

    d = domain("commbank-verify-account.top")
    assert d["source"] == "bot" and d["brand_id"] == "commbank" and d["tier"] == "high" and d["status"] == "open"
    assert d["hostnames"] == ["commbank-verify-account.top"] and d["issuer"] is None and d["ct_log"] is None
    assert d["sightings"] == 1 and d["next_check_at"] is not None and d["watch_until"] > d["first_seen"]
    assert [k for k, _ in events(d["id"])] == ["first_seen"]
    assert events(d["id"])[0][1]["source"] == "bot"

    m = q("SELECT * FROM bot_messages")
    assert len(m) == 1
    assert (m[0]["chat_id"], m[0]["domains"], m[0]["registered"], m[0]["verdicts"], m[0]["new_domains"],
            m[0]["ai_used"]) == (5001, ["commbank-verify-account.top"], ["commbank-verify-account.top"],
                                 ["suspicious"], 1, False)
    c = chat_row(5001)
    assert c["status"] == "allowed" and c["status_by"] == "reviewer@tailnet"
    assert (c["day_messages"], c["day_ai"], c["total_messages"], c["total_domains"], c["total_ai"]) == (1, 0, 1, 1, 0)
    assert c["counter_day"] == bot.utc_today() and c["last_seen"] >= before

    reply = tg.sent[-1]
    assert reply["chat_id"] == 5001 and reply["reply_parameters"]["message_id"] == 1003
    assert reply["link_preview_options"] == {"is_disabled": True}
    assert "hxxps://commbank-verify-account[.]top" in reply["text"]
    assert "commbank-verify-account.top" not in reply["text"]
    assert "VERY SUSPICIOUS" in reply["text"] and "I've added it to our checks" in reply["text"]

    # The same domain from another chat (allowed by TELEGRAM_ALLOWED_CHATS, so the stored status stays pending):
    # found in the database, not stored again, a bot_forward event for the reviewer.
    async def env_group():
        async with make_bot(tg, allowed_chats=[-1001987654321]) as b:
            await b.handle_update(update(4, -1001987654321, "Got this too: secure.commbank-verify-account.top/verify",
                                         chat_type="supergroup", title="Family chat"))
    arun(env_group())
    g = chat_row(-1001987654321)
    assert g["status"] == "pending" and g["chat_type"] == "supergroup" and g["title"] == "Family chat"
    assert g["username"] is None and g["day_messages"] == 1
    d2 = domain("commbank-verify-account.top")
    assert d2["sightings"] == 1 and d2["hostnames"] == ["commbank-verify-account.top"]    # bot never re-stores
    assert [(k, x.get("hostname"), x.get("verdict")) for k, x in events(d["id"])][1:] == [
        ("bot_forward", "secure.commbank-verify-account.top", "suspicious")]
    msg = q("SELECT * FROM bot_messages WHERE chat_id = %s", -1001987654321)[0]
    assert msg["registered"] == ["commbank-verify-account.top"] and msg["new_domains"] == 0
    assert "I've added it" not in tg.texts(-1001987654321)[-1]
    assert "VERY SUSPICIOUS" in tg.texts(-1001987654321)[-1]


def _utf16_offset(text: str, sub: str) -> tuple[int, int]:
    i = text.index(sub)
    return len(text[:i].encode("utf-16-le")) // 2, len(sub.encode("utf-16-le")) // 2


def test_bot_mixed_message_with_idn_shortener_official_ip_and_link_trick():
    tg = Telegram()
    dashboard_set_chat(5101, "allowed")
    text = ("Australia Post: your parcel is on hold. Track it at auspost.com.au or https://bit.ly/3AuPost. "
            "Sign in via https://www.commbank.com.au/netbank or https://commbаnk-login.top/verify "   # Cyrillic а
            "(see http://example.org/help) or http://203.0.113.7/login now.")
    off, ln = _utf16_offset(text, "auspost.com.au")
    u = update(1, 5101, text, entities=[{"type": "text_link", "offset": off, "length": ln,
                                         "url": "https://auspost-parcel-redelivery.top/track?id=AU123"}])

    async def go():
        async with make_bot(tg) as b:
            await b.handle_update(u)
    arun(go())
    m = q("SELECT * FROM bot_messages WHERE chat_id = 5101")[0]
    got = dict(zip(m["domains"], m["verdicts"]))
    assert got == {"auspost.com.au": "official", "bit.ly": "shortener", "www.commbank.com.au": "official",
                   "xn--commbnk-login-01k.top": "suspicious", "example.org": "not_flagged",
                   "auspost-parcel-redelivery.top": "suspicious"}
    assert dict(zip(m["domains"], m["registered"]))["www.commbank.com.au"] == "commbank.com.au"
    assert m["new_domains"] == 2
    idn = domain("xn--commbnk-login-01k.top")
    assert idn["unicode_domain"] == "commbаnk-login.top" and idn["source"] == "bot" and idn["tier"] == "high"
    assert idn["hostnames"] == ["xn--commbnk-login-01k.top"]
    assert domain("auspost-parcel-redelivery.top")["brand_id"] == "auspost"
    for official in ("commbank.com.au", "auspost.com.au", "bit.ly", "example.org"):
        assert domain(official) is None                 # only suspicious names are stored
    assert chat_row(5101)["total_domains"] == 6
    reply = tg.texts(5101)[-1]
    assert "Trick spotted: the link text shows auspost[.]com[.]au but it really goes to " \
           "auspost-parcel-redelivery[.]top" in reply
    assert "203[.]0[.]113[.]7" in reply and "(displays as commbаnk-login[.]top)" in reply
    assert "commbank-login.top" not in reply and "auspost-parcel-redelivery.top" not in reply


def test_bot_uses_reviews_and_confirmations_from_the_database():
    tg = Telegram()
    dashboard_set_chat(5201, "allowed")
    confirmed = ct_store("login.westpac-secure-login.xyz")
    dashboard_review("westpac-secure-login.xyz", "confirmed", live_state="live")
    benign = ct_store("nab-verify.top")
    dashboard_review("nab-verify.top", "benign")
    shared = ct_store("commbank-rewards.weebly.com")           # a site builder that is not on the PSL
    dashboard_review("weebly.com", "false_positive")
    taken = ct_store("anz-login-secure.top")
    run_sql("UPDATE domains SET takedown_at = now() - interval '2 days', takedown_signal = 'nxdomain', "
            "ai_verdict = 'phishing' WHERE id = %s", taken)
    ct_found = ct_store("login.commbank.com.au.evil-site.top")
    # A row a forwarded message created from a made-up subdomain: its score must not flag the real site
    a_bot = bot_store_via_message(tg, "commbank.com.au.login.my-real-bakery.com.au/secure")

    async def go():
        async with make_bot(tg) as b:
            await b.handle_update(update(2, 5201, "Is westpac-secure-login.xyz real? And www.nab-verify.top?"))
            await b.handle_update(update(3, 5201, "Weebly links: commbank-rewards.weebly.com and "
                                                  "commbank-login-verify.weebly.com"))
            await b.handle_update(update(4, 5201, "Old one: anz-login-secure.top, and my-real-bakery.com.au"))
            await b.handle_update(update(5, 5201, "and this one: https://www.evil-site.top/"))
    arun(go())
    r2, r3, r4, r5 = tg.texts(5201)[-4:]
    assert "CONFIRMED PHISHING" in r2 and "It was online when we last checked." in r2
    assert bot.REVIEWED_NOTE in r2
    msgs = q("SELECT verdicts, domains FROM bot_messages WHERE chat_id = 5201 ORDER BY id")[-4:]
    assert msgs[0]["verdicts"] == ["confirmed", "not_flagged"]
    assert msgs[1]["verdicts"] == ["not_flagged", "suspicious"]       # reviewed hostname / not shown to reviewer
    assert msgs[2]["verdicts"] == ["suspicious", "not_flagged"]
    assert "taken down" in r4 and "judged it to be phishing" in r4
    # www.evil-site.top has no score of its own; CT found the domain, so the row's tier and reasons count
    assert msgs[3]["verdicts"] == ["suspicious"] and "VERY SUSPICIOUS" in r5
    assert "it hides the real address commbank[.]com[.]au inside a different website's address" in r5
    assert [x for k, x in events(ct_found) if k == "bot_forward"] == [{"hostname": "www.evil-site.top",
                                                                      "verdict": "suspicious"}]
    ev = {k: x for k, x in events(confirmed)}
    assert ev["bot_forward"] == {"hostname": "westpac-secure-login.xyz", "verdict": "confirmed"}
    assert [x for k, x in events(benign) if k == "bot_forward"] == [{"hostname": "www.nab-verify.top",
                                                                    "verdict": "not_flagged"}]
    fwd = [x for k, x in events(shared) if k == "bot_forward"]
    assert fwd == [{"hostname": "commbank-rewards.weebly.com", "verdict": "not_flagged"},
                   {"hostname": "commbank-login-verify.weebly.com", "verdict": "suspicious",
                    "not_covered_by_review": True}]                    # for the reviewer: look again
    assert [x for k, x in events(a_bot) if k == "bot_forward"] == [{"hostname": "my-real-bakery.com.au",
                                                                   "verdict": "not_flagged"}]
    assert domain("weebly.com")["status"] == "false_positive"     # the bot never changes a review

    # A review made before reviewed_hostnames existed (NULL) covers the row's current hostnames
    run_sql("UPDATE domains SET reviewed_hostnames = NULL, hostnames = hostnames || "
            "'{commbank-login-verify.weebly.com}'::text[] WHERE registered_domain = 'weebly.com'")

    async def again():
        async with make_bot(tg) as b:
            await b.handle_update(update(6, 5201, "commbank-login-verify.weebly.com again"))
    arun(again())
    assert q("SELECT verdicts FROM bot_messages WHERE chat_id = 5201 ORDER BY id DESC LIMIT 1")[0]["verdicts"] == \
        ["not_flagged"]
    assert bot.REVIEWED_NOTE in tg.texts(5201)[-1]


def bot_store_via_message(tg: Telegram, text: str, chat_id: int = 5299) -> int:
    dashboard_set_chat(chat_id, "allowed")

    async def go():
        async with make_bot(tg) as b:
            await b.handle_update(update(99, chat_id, text))
    arun(go())
    row = q("SELECT d.id FROM domains d JOIN domain_events e ON e.domain_id = d.id "
            "WHERE e.kind = 'first_seen' AND e.detail->>'source' = 'bot' ORDER BY e.id DESC LIMIT 1")
    return row[0]["id"]


def test_bot_daily_limit_commands_and_quiet_cases():
    tg = Telegram()
    dashboard_set_chat(5301, "allowed")
    dashboard_set_chat(-1005302, "allowed")
    today = bot.utc_today()

    async def go():
        async with make_bot(tg, daily_limit=2) as b:
            for uid, host in ((1, "commbank-login.top"), (2, "mygov-verify.top"), (3, "ato-refund.top"),
                              (4, "linkt-toll-pay.top")):
                await b.handle_update(update(uid, 5301, f"Please check {host} for me"))
            await b.handle_update(update(5, 5301, "/help", forwarded=False))
            await b.handle_update(update(6, 5301, "/privacy@CyberCheckTestBot", forwarded=False))
            await b.handle_update(update(7, 5301, "/whatever", forwarded=False))
            await b.handle_update(update(8, 5301, "/help@SomeOtherBot", forwarded=False))
            await b.handle_update(update(9, -1005302, "no links in this group message at all, just chatting",
                                         chat_type="group", title="Book club"))
            await b.handle_update(update(10, 5301, None, photo=[{"file_id": "x", "width": 90, "height": 90}]))
    arun(go())
    texts = tg.texts(5301)
    assert len(texts) == 7
    assert "SUSPICIOUS" in texts[0] and "SUSPICIOUS" in texts[1]
    assert texts[2] == bot.limit_text(2)                             # sent once; the 4th check is silent
    assert texts[3] == bot.help_text(2) and texts[4].startswith("What this bot stores")
    assert texts[5].startswith("I don't know that command")         # /help@SomeOtherBot: ignored
    assert texts[6] == bot.NO_TEXT_TEXT
    assert tg.texts(-1005302) == []
    c = chat_row(5301)
    assert (c["day_messages"], c["limit_notified"], c["total_messages"], c["counter_day"]) == (2, True, 2, today)
    assert chat_row(-1005302)["day_messages"] == 0 and chat_row(-1005302)["counter_day"] is None
    assert domain("ato-refund.top") is None and domain("linkt-toll-pay.top") is None     # over the limit
    assert {r["registered_domain"] for r in q("SELECT registered_domain FROM domains")} == {
        "commbank-login.top", "mygov-verify.top"}
    assert len(q("SELECT * FROM bot_messages WHERE chat_id = 5301")) == 2

    # The next UTC day the counters start again
    run_sql("UPDATE bot_chats SET counter_day = counter_day - 1, day_ai = 3 WHERE chat_id = 5301")

    async def next_day():
        async with make_bot(tg, daily_limit=2) as b:
            await b.handle_update(update(11, 5301, "Is this a scam? Nothing to click in it, they just want money"))
            await b.handle_update(update(12, 5301, "see ato-refund.top"))
    arun(next_day())
    c = chat_row(5301)
    assert (c["day_messages"], c["day_ai"], c["limit_notified"], c["total_messages"], c["counter_day"]) == \
        (2, 0, False, 4, today)
    empty = q("SELECT * FROM bot_messages WHERE chat_id = 5301 ORDER BY id")[2]
    assert (empty["domains"], empty["registered"], empty["verdicts"], empty["new_domains"]) == ([], [], [], 0)
    assert tg.texts(5301)[-2].startswith("I couldn't find a web address")
    assert domain("ato-refund.top")["source"] == "bot"

    # Blocked on the dashboard: silent, even when TELEGRAM_ALLOWED_CHATS lists the chat
    dashboard_set_chat(5301, "blocked")
    n = len(tg.sent)

    async def blocked():
        async with make_bot(tg, allowed_chats=[5301]) as b:
            await b.handle_update(update(13, 5301, "see westpac-secure-login.xyz"))
    arun(blocked())
    assert len(tg.sent) == n and chat_row(5301)["total_messages"] == 4 and domain("westpac-secure-login.xyz") is None


def test_bot_chat_names_with_unicode_and_control_characters():
    tg = Telegram()

    async def go():
        async with make_bot(tg) as b:
            await b.handle_update(update(1, 5401, "hello", title="Zoë ‮🦘\x00\x07", username="zoe​_k"))
            await b.handle_update(update(2, -1005402, "hi", chat_type="group", title="Grüße 家族 ✈️"))
            await b.handle_update(update(3, -1005402, "hi again", chat_type="group", title=None))
    arun(go())
    c = chat_row(5401)
    assert c["title"] == "Zoë 🦘" and c["username"] == "zoe_k"       # control/format characters dropped
    g = chat_row(-1005402)
    assert g["title"] == "Grüße 家族 ✈️"                                # a missing title keeps the stored one
    assert tg.texts(5401) == [bot.NOT_ENABLED_TEXT] and tg.texts(-1005402) == [bot.NOT_ENABLED_TEXT]


def test_bot_ai_explanation_records_cost_and_uses_the_per_chat_allowance(monkeypatch):
    tg = Telegram()
    claude = FakeClaude()
    dashboard_set_chat(5501, "allowed")
    good = ("This message pretends to be from CommBank. The link goes to commbank-verify-account.top, which is "
            "not a CommBank website. Do not sign in there; open the CommBank app yourself instead.")
    claude.responses = [
        claude_message(good),
        claude_message("This is genuine. Call CommBank on 0412 345 678 to confirm your details today."),
        httpx2.Response(400, json={"type": "error", "error": {"type": "invalid_request_error",
                                                              "message": "prompt is too long"}}),
        claude_message("Another CommBank imitation. Its address is not on the list of official CommBank sites."),
    ]
    n_ai = len(claude.responses)

    async def go():
        claude.install()
        async with make_bot(tg, ai_on=True, ai_limit=2) as b:
            for uid in range(1, 6):
                await b.handle_update(update(uid, 5501, SCAM))
            await asyncio.gather(*b._ai_tasks)
    arun(go())
    texts = tg.texts(5501)
    assert len(texts) == 5 and len(claude.requests) == n_ai
    assert "AI summary (automated, it can be wrong):" in texts[0] and "commbank-verify-account[.]top" in texts[0]
    assert "0412" not in texts[1] and "AI summary" not in texts[1]         # phone number: dropped, slot refunded
    assert "AI summary" not in texts[2]                                    # API error: refunded
    assert "AI summary" in texts[3] and "AI summary" not in texts[4]       # allowance of 2 used up
    req = claude.requests[0]
    assert req["model"] == "claude-opus-5-5" and req["output_config"]["format"]["type"] == "json_schema"
    user = req["messages"][0]["content"][0]["text"]
    assert "commbank-verify-account.top" in user and "untrusted_message" in user

    calls = q("SELECT * FROM ai_calls ORDER BY id")
    assert [(c["purpose"], c["status"]) for c in calls] == [("bot", "ok"), ("bot", "ok"), ("bot", "api_error"),
                                                            ("bot", "ok")]
    first = calls[0]
    assert (first["input_tokens"], first["output_tokens"], first["cache_read_tokens"]) == (1180, 164, 1536)
    assert 0 < float(first["cost_usd"]) < float(first["estimated_cost_usd"])
    assert first["result"]["explanation"].startswith("This message pretends")
    assert first["stop_reason"] == "end_turn" and first["duration_ms"] is not None
    assert float(calls[2]["cost_usd"]) == 0.0 and "HTTP 400" in calls[2]["error"]
    assert [m["ai_used"] for m in q("SELECT ai_used FROM bot_messages WHERE chat_id = 5501 ORDER BY id")] == \
        [True, False, False, True, False]
    c = chat_row(5501)
    assert (c["day_ai"], c["total_ai"], c["day_messages"], c["total_messages"]) == (2, 2, 5, 5)

    # Over the AI budget: no call is made, no ai_calls row is added, the reply goes out without AI text
    monkeypatch.setenv("AI_DAILY_BUDGET_USD", "0.0001")
    config.settings.cache_clear()
    dashboard_set_chat(5502, "allowed")

    async def over_budget():
        claude.install()
        async with make_bot(tg, ai_on=True, ai_limit=2) as b:
            await b.handle_update(update(6, 5502, SCAM))
    arun(over_budget())
    assert len(q("SELECT * FROM ai_calls")) == 4 and len(claude.requests) == n_ai
    assert "AI summary" not in tg.texts(5502)[-1] and chat_row(5502)["day_ai"] == 0

    # A slow AI call: the reply goes out without it, the slot stays used (the call may be billed), and the call
    # finishes in the background on its own connection and is recorded in ai_calls
    monkeypatch.setenv("AI_DAILY_BUDGET_USD", "1.60")
    config.settings.cache_clear()
    monkeypatch.setattr(bot, "AI_TIMEOUT", 0)
    dashboard_set_chat(5503, "allowed")
    claude.responses = [claude_message(good)]

    async def slow():
        claude.install()
        async with make_bot(tg, ai_on=True, ai_limit=2) as b:
            await b.handle_update(update(7, 5503, SCAM))
            sent_before = len(tg.texts(5503))
            pending = list(b._ai_tasks)
            await asyncio.gather(*pending)
            return sent_before, len(pending)
    sent_before, pending = arun(slow())
    assert sent_before == 1 and pending == 1 and "AI summary" not in tg.texts(5503)[-1]
    c = chat_row(5503)
    assert (c["day_ai"], c["total_ai"]) == (1, 0)
    assert q("SELECT ai_used FROM bot_messages WHERE chat_id = 5503")[0]["ai_used"] is False
    last = q("SELECT * FROM ai_calls ORDER BY id DESC LIMIT 1")[0]
    assert last["status"] == "ok" and last["purpose"] == "bot" and len(q("SELECT * FROM ai_calls")) == 5

    # Two chats at once: both budget reservations (advisory lock) and both explanations go through
    monkeypatch.setattr(bot, "AI_TIMEOUT", 60)
    dashboard_set_chat(5504, "allowed")
    dashboard_set_chat(5505, "allowed")
    claude.responses = [claude_message(good), claude_message(good)]

    async def two_chats():
        claude.install()
        async with make_bot(tg, ai_on=True, ai_limit=2) as b:
            await asyncio.gather(b.handle_update(update(8, 5504, SCAM)), b.handle_update(update(9, 5505, SCAM)))
    arun(two_chats())
    assert "AI summary" in tg.texts(5504)[-1] and "AI summary" in tg.texts(5505)[-1]
    assert [r["status"] for r in q("SELECT status FROM ai_calls ORDER BY id")][-2:] == ["ok", "ok"]
    assert chat_row(5504)["total_ai"] == 1 and chat_row(5505)["total_ai"] == 1


def test_bot_poll_loop_offsets_status_and_retention_clean_up():
    tg = Telegram()
    dashboard_set_chat(5601, "allowed")

    async def first_process():
        async with make_bot(tg) as b:
            await b.wait_until_ready()
            assert b.offset is None
            await b.identify()
            assert b.username == "CyberCheckTestBot"
            tg.updates = [[update(700, 5601, "check commbank-login.top"), "junk", {"update_id": "x"},
                           {"update_id": 701, "message": {"chat": "broken"}},
                           update(702, 5601, "/help", forwarded=False)]]
            assert await b.poll_once() == 3
            return b.offset, dict(b.stats)
    offset, stats = arun(first_process())
    assert offset == 703 and stats["updates"] == 3
    assert one("SELECT value FROM kv WHERE key = 'bot:offset'")["value"] == 703
    assert "offset" not in tg.polls[0] and tg.polls[0]["allowed_updates"] == ["message"]
    assert len(tg.texts(5601)) == 2

    async def restarted():
        async with make_bot(tg) as b:
            await b.wait_until_ready()
            tg.updates = [[]]
            assert await b.poll_once() == 0
            return b.offset
    assert arun(restarted()) == 703 and tg.polls[-1]["offset"] == 703

    # Retention: bot_messages older than 30 days, and pending chats silent for 30 days unless env-allowed
    for cid, status in ((5602, "pending"), (5603, "pending"), (5604, "allowed"), (5605, "blocked")):
        run_sql("INSERT INTO bot_chats (chat_id, chat_type, status, last_seen, first_seen) "
                "VALUES (%s, 'private', %s, now() - interval '31 days', now() - interval '40 days')", cid, status)
    run_sql("INSERT INTO bot_chats (chat_id, chat_type, status) VALUES (5606, 'private', 'pending')")
    run_sql("INSERT INTO bot_messages (chat_id, at, domains, registered, verdicts) VALUES "
            "(5601, now() - interval '31 days', '{old.top}', '{old.top}', '{not_flagged}'), "
            "(5602, now() - interval '35 days', '{}', '{}', '{}'), "
            "(5604, now() - interval '29 days', '{recent.top}', '{recent.top}', '{not_flagged}')")

    async def housekeeping():
        async with make_bot(tg, allowed_chats=[5603, -1001987654321, 7012345678]) as b:   # int4 and int8 ids
            b.username = "CyberCheckTestBot"
            b.stats["updates"] = 3
            await b._housekeeping(ok=True)
            first = await _kv("bot:status")
            kept = {r["chat_id"] for r in await _rows("SELECT chat_id FROM bot_chats")}
            await b._housekeeping(ok=False, error="getUpdates failed: 502 Bad Gateway")
            async with bot.db_repo() as repo:
                assert await repo.tables_ready() is True
                again = await repo.cleanup([])                      # empty keep list
            return first, kept, again
    first, kept, again = arun(housekeeping())
    assert 5602 not in kept and {5601, 5603, 5604, 5605, 5606} <= kept     # 5603 is env-allowed
    assert first["ok"] is True and first["username"] == "CyberCheckTestBot" and first["updates"] == 3
    status = one("SELECT value FROM kv WHERE key = 'bot:status'")["value"]
    assert status["ok"] is False and status["error"] == "getUpdates failed: 502 Bad Gateway"
    msgs = q("SELECT chat_id, domains FROM bot_messages ORDER BY id")
    assert [m["domains"] for m in msgs if m["chat_id"] in (5602, 5604)] == [["recent.top"]]
    assert not any(m["domains"] == ["old.top"] for m in msgs)
    assert again == {"messages": 0, "pending_chats": 1}                # 5603 is no longer protected
    assert {r["chat_id"] for r in q("SELECT chat_id FROM bot_chats")} == kept - {5603}


async def _kv(key: str):
    p = await db.pool()
    async with p.connection() as conn:
        return await db.kv_get(conn, key)


async def _rows(sql: str, *params) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        return await (await conn.execute(sql, params)).fetchall()


def test_bot_counters_hold_under_concurrent_updates(it_db):
    dashboard_set_chat(5701, "allowed")
    today = bot.utc_today()

    async def conns(n):
        return [await psycopg.AsyncConnection.connect(it_db, autocommit=True, row_factory=dict_row) for _ in range(n)]

    async def go():
        cs = await conns(12)
        try:
            slots = await asyncio.gather(*(bot.Repo(c).take_message_slot(5701, today, 5) for c in cs))
            ai = await asyncio.gather(*(bot.Repo(c).take_ai_slot(5701, today, 2) for c in cs[:6]))
            notified = await asyncio.gather(*(bot.Repo(c).mark_limit_notified(5701, today) for c in cs[:4]))
            touched = await asyncio.gather(*(bot.Repo(c).touch_chat(5799, "private", "New", None, False)
                                             for c in cs[:8]))
            await bot.Repo(cs[0]).refund_ai_slot(5701, today)
            await bot.Repo(cs[0]).refund_ai_slot(5701, today)
            await bot.Repo(cs[0]).refund_ai_slot(5701, today)        # never below zero
            return slots, ai, notified, touched
        finally:
            for c in cs:
                await c.close()
    slots, ai, notified, touched = arun(go())
    assert sum(slots) == 5 and sum(ai) == 2 and sum(notified) == 1
    assert sum(1 for _, ins in touched if ins) == 1 and {s for s, _ in touched} == {"pending"}
    c = chat_row(5701)
    assert (c["day_messages"], c["total_messages"], c["day_ai"], c["limit_notified"]) == (5, 5, 0, True)

    # Two chats forwarding the same new scam domain at the same moment: one row, one first_seen event
    tg = Telegram()
    dashboard_set_chat(5702, "allowed")
    dashboard_set_chat(5703, "allowed")

    async def race():
        async with make_bot(tg) as b:
            await asyncio.gather(b.handle_update(update(1, 5702, "see https://anz-login-secure.top/x")),
                                 b.handle_update(update(2, 5703, "see https://anz-login-secure.top/y")))
            return b.stats
    stats = arun(race())
    assert stats["errors"] == 0 and len(tg.sent) == 2
    d = domain("anz-login-secure.top")
    assert d["source"] == "bot" and [k for k, _ in events(d["id"])].count("first_seen") == 1
    assert sum(m["new_domains"] for m in q("SELECT new_domains FROM bot_messages")) == 1


# ===================================================================================================
# CZDS
# ===================================================================================================

def _jwt(exp: datetime) -> str:
    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64({'exp': int(exp.timestamp()), 'sub': 'it'})}.c2lnbmF0dXJl"


DL = "https://czds-download-api.icann.org/czds/downloads/"


def zone_text(tld: str, labels, serial: int, *, end_soa: bool = True) -> str:
    soa = f"{tld}.\t3600\tin\tsoa\tns0.nic.{tld}.\thostmaster.nic.{tld}.\t{serial}\t1800\t900\t604800\t3600"
    lines = [soa, f"{tld}.\t172800\tin\tns\ta.nic.{tld}.", f"{tld}.\t172800\tin\tns\tb.nic.{tld}.",
             f"{tld}.\t3600\tin\tdnskey\t257 3 13 AAAA"]
    for label in sorted(labels):
        lines += [f"{label}.{tld}.\t3600\tin\tns\tns1.{label}.{tld}.",
                  f"{label}.{tld}.\t3600\tin\tns\tns2.example.net.",
                  f"{label}.{tld}.\t3600\tin\tds\t12345 13 2 ABCDEF",
                  f"ns1.{label}.{tld}.\t3600\tin\ta\t192.0.2.1"]
    if end_soa:
        lines.append(soa)
    return "\n".join(lines) + "\n"


def zone_gz(tld: str, labels, serial: int, **kw) -> bytes:
    return gzip.compress(zone_text(tld, labels, serial, **kw).encode())


class CzdsServer:
    """account-api (login), czds-api (links), czds-download-api (HEAD/GET of <tld>.zone)."""

    def __init__(self, clock):
        self.clock = clock
        self.requests: list[httpx.Request] = []
        self.links = [DL + "top.zone", DL + "xn--80asehdb.zone", DL + "shop.zone"]
        self.zones: dict[str, tuple[bytes, str]] = {}
        self.tokens: set[str] = set()
        self.bad_length = False
        self.status: dict[str, int] = {}
        self.links_status = 200

    def count(self, method: str, tld: str | None = None) -> int:
        return sum(1 for r in self.requests if r.method == method and r.url.host == "czds-download-api.icann.org"
                   and (tld is None or r.url.path.endswith(f"/{tld}.zone")))

    def logins(self) -> int:
        return sum(1 for r in self.requests if r.url.host == "account-api.icann.org")

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["user-agent"] == czds.USER_AGENT
        host, path = request.url.host, request.url.path
        if host == "account-api.icann.org" and path == "/api/authenticate":
            assert json.loads(request.content) == {"username": "it-user@example.org", "password": "it-password"}
            token = _jwt(self.clock() + 24 * H) + f"-{len(self.tokens)}"
            self.tokens.add(token)
            return httpx.Response(200, json={"accessToken": token})
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return httpx.Response(401)
        if host == "czds-api.icann.org" and path == "/czds/downloads/links":
            if self.links_status != 200:
                return httpx.Response(self.links_status, text="<html>maintenance</html>")
            return httpx.Response(200, json=self.links)
        if host == "czds-download-api.icann.org" and path.startswith("/czds/downloads/"):
            tld = path.rsplit("/", 1)[-1][:-len(".zone")]
            if tld in self.status:
                return httpx.Response(self.status[tld])
            if tld not in self.zones:
                return httpx.Response(404)
            data, modified = self.zones[tld]
            headers = {"Content-Length": str(len(data) + (50 if self.bad_length else 0)), "Last-Modified": modified}
            if request.method == "HEAD":
                return httpx.Response(200, headers=headers)
            return httpx.Response(200, headers={**headers, "Content-Type": "application/x-gzip"},
                                  stream=httpx.ByteStream(data))
        return httpx.Response(403)


class CzdsJob:
    """Drives the real job entry point (cybercheck.jobs.czds.run) on a fake clock against the fake CZDS."""

    def __init__(self, monkeypatch, tlds: str = "top,xyz,онлайн"):
        monkeypatch.setenv("CZDS_USERNAME", "it-user@example.org")
        monkeypatch.setenv("CZDS_PASSWORD", "it-password")
        monkeypatch.setenv("CZDS_TLDS", tlds)
        config.settings.cache_clear()
        # a few days in the past, so the fake clock never runs ahead of the database's now()
        self.d1 = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0) - 6 * DAY
        self.now = self.d1
        self.server = CzdsServer(lambda: self.now)
        self.slept: list[float] = []

        async def fake_sleep(seconds):
            self.slept.append(seconds)
            self.now += timedelta(seconds=seconds)

        monkeypatch.setattr(czds, "utcnow", lambda: self.now)
        monkeypatch.setattr(czds, "_sleep", fake_sleep)
        monkeypatch.setattr(czds, "LOGIN_MAX_PER_WINDOW", 8)     # several simulated days in a few real seconds
        monkeypatch.setattr(czds, "make_http", lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(self.server.handler), headers={"User-Agent": czds.USER_AGENT},
            follow_redirects=False))
        self.ctx = JobContext(settings=config.settings(), log=logging.getLogger("cybercheck.job.czds"))
        self.data = config.settings().data_dir / "czds"

    def run(self, at: datetime) -> dict:
        self.now = at
        return arun(czds_job.run(self.ctx))

    def set_tlds(self, *tlds: str) -> None:
        self.ctx.settings = dataclasses.replace(self.ctx.settings, czds_tlds=list(tlds))

    def files(self, tld: str) -> list[str]:
        d = self.data / tld
        return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def zones() -> dict[str, dict]:
    return {r["tld"]: r for r in q("SELECT * FROM czds_zones")}


def runs(tld: str | None = None) -> list[dict]:
    rows = q("SELECT * FROM czds_runs ORDER BY id")
    return [r for r in rows if tld is None or r["tld"] == tld]


def test_czds_full_run_baseline_then_diff_stores_hits(monkeypatch):
    j = CzdsJob(monkeypatch)
    s, d1 = j.server, j.d1
    idn = "xn--80asehdb"                                            # .онлайн
    s.zones["top"] = (zone_gz("top", ["alpha", "beta", "commbank-login", "zeta"], 2026111200),
                      "Thu, 12 Nov 2026 05:12:00 GMT")
    s.zones[idn] = (zone_gz(idn, ["alpha", "beta"], 77), "Thu, 12 Nov 2026 05:20:00 GMT")

    # 05:00: approvals recorded; nothing is downloaded before the window opens (06:30)
    out = j.run(d1 + 5 * H)
    z = zones()
    assert set(z) == {"top", "xyz", idn, "shop"}
    assert (z["top"]["configured"], z["top"]["approved"], z["top"]["status"]) == (True, True, "approved")
    assert z["top"]["approved_at"] == d1 + 5 * H and z["top"]["download_url"] == DL + "top.zone"
    assert (z["xyz"]["configured"], z["xyz"]["approved"], z["xyz"]["status"]) == (True, False, "not_approved")
    assert (z["shop"]["configured"], z["shop"]["approved"], z["shop"]["status"]) == (False, True, "not_configured")
    assert z[idn]["status"] == "approved" and z["top"]["state"] == {} and z["top"]["fail_count"] == 0
    assert z["top"]["next_due"] == d1 + timedelta(hours=6, minutes=30) and z["xyz"]["next_due"] is None
    assert s.count("GET") == 0 and s.count("HEAD") == 0 and runs() == []
    assert out["approved"] == 2 and out["not_approved"] == ["xyz"]

    # 06:00: due within the hour, so the run waits, then stores a baseline for each zone
    out = j.run(d1 + 6 * H)
    assert j.slept == [1800.0] and s.count("GET") == 2 and s.count("HEAD") == 2
    z = zones()
    top = z["top"]
    at = d1 + timedelta(hours=6, minutes=30)
    assert top["status"] == "baseline" and top["error"] is None
    assert (top["total_names"], top["new_names"], top["removed_names"], top["hits"], top["new_hits"]) == \
        (4, None, None, 0, 0)
    assert top["soa_serial"] == 2026111200 and top["file_bytes"] == len(s.zones["top"][0])
    assert top["last_download"] == at and top["last_head"] == at and top["last_processed"] == at
    assert top["last_modified"] == "Thu, 12 Nov 2026 05:12:00 GMT" and top["retry_at"] is None
    assert top["next_due"] == czds.next_slot(at + czds.MIN_GAP, czds.load_config()) and top["duration_s"] >= 0
    st = top["state"]
    assert st["processed"] == {"last_modified": "Thu, 12 Nov 2026 05:12:00 GMT", "bytes": top["file_bytes"]}
    assert st["last_scan"]["ns_records"] == 10 and "attempts" not in st and st["download"]["bytes"] == top["file_bytes"]
    assert z[idn]["status"] == "baseline" and z[idn]["total_names"] == 2
    assert [(r["tld"], r["status"], r["total_names"], r["hits"]) for r in runs()] == [
        ("top", "baseline", 4, 0), (idn, "baseline", 2, 0)]
    assert q("SELECT * FROM domains") == []                         # a baseline has no "new" names
    assert j.files("top") == ["names.gz"] and j.files(idn) == ["names.gz"]   # raw download deleted
    assert (j.data / "top").stat().st_mode & 0o777 == 0o700
    assert out["processed"]["top"]["status"] == "baseline"

    # A name CT already found, and one a bot user forwarded
    known_ct = ct_store("commbank-verify.top")
    known_bot = ct_store("mygov-verify.top", source="bot", issuer=None, ct_log=None)

    # Later on day 1: never a second download within 24 h
    j.run(d1 + 9 * H)
    j.run(d1 + 23 * H)
    assert s.count("GET") == 2 and s.count("HEAD") == 2

    # Day 2, 06:40: new files with new names
    s.zones["top"] = (zone_gz("top", ["alpha", "commbank-login", "commbank-verify", "commbank-signin-login",
                                      "mygov-verify", "xn--commbnk-login-01k", "gamma", "zeta"], 2026111300),
                      "Fri, 13 Nov 2026 05:11:00 GMT")
    s.zones[idn] = (zone_gz(idn, ["alpha", "beta", "commbank-login"], 78), "Fri, 13 Nov 2026 05:21:00 GMT")
    out = j.run(d1 + DAY + timedelta(hours=6, minutes=40))
    assert s.count("GET") == 4 and s.logins() == 2                  # the day-old token expired
    top = zones()["top"]
    assert top["status"] == "ok" and top["error"] is None
    assert (top["total_names"], top["new_names"], top["removed_names"], top["hits"], top["new_hits"]) == \
        (8, 5, 1, 4, 2)
    assert top["soa_serial"] == 2026111300 and top["last_modified"] == "Fri, 13 Nov 2026 05:11:00 GMT"
    assert j.files("top") == ["names.gz", "names.prev.gz"]
    assert out["new_names"] == 6 and out["hits"] == 5

    new = domain("commbank-signin-login.top")
    assert (new["source"], new["brand_id"], new["tier"], new["issuer"], new["hostnames"]) == \
        ("czds", "commbank", "high", None, ["commbank-signin-login.top"])
    assert events(new["id"]) == [("first_seen", {"source": "czds", "hostname": "commbank-signin-login.top",
                                                 "score": new["score"], "tier": "high", "brand": "commbank",
                                                 "issuer": None, "ct_log": None})]
    idn_hit = domain("xn--commbnk-login-01k.top")
    assert idn_hit["source"] == "czds" and idn_hit["unicode_domain"] == "commbаnk-login.top"
    online = domain("commbank-login." + idn)
    assert online["source"] == "czds" and online["unicode_domain"] == "commbank-login.онлайн" and online["tld"] == idn
    ct_row = domain("commbank-verify.top")
    assert ct_row["source"] == "ct" and ct_row["sightings"] == 2 and ct_row["issuer"] == "R11"
    assert [k for k, _ in events(known_ct)] == ["first_seen", "czds_new_delegation"]
    assert events(known_ct)[1][1] == {"tld": "top", "serial": 2026111300}
    assert domain("mygov-verify.top")["source"] == "bot"            # a bot row stays 'bot'
    assert [k for k, _ in events(known_bot)] == ["first_seen", "czds_new_delegation"]
    assert domain("commbank-login.top") is None and domain("gamma.top") is None   # baseline name / no score
    ok = runs("top")[-1]
    assert (ok["status"], ok["new_names"], ok["removed_names"], ok["hits"], ok["new_hits"], ok["soa_serial"]) == \
        ("ok", 5, 1, 4, 2, 2026111300)
    assert zones()[idn]["new_names"] == 1 and zones()[idn]["new_hits"] == 1

    # CT later sees a certificate for a CZDS-found name: it becomes public CT data (store.py rule)
    async def ct_sighting():
        p = await db.pool()
        async with p.connection() as conn:
            return await store_hit(conn, WL.score_hostname("www.commbank-signin-login.top"), source="ct")
    assert arun(ct_sighting()) == (new["id"], False)
    assert domain("commbank-signin-login.top")["source"] == "ct"

    # Day 3: ICANN still serves the same files (same Last-Modified and size): HEAD only
    j.run(d1 + 2 * DAY + timedelta(hours=6, minutes=50))
    assert s.count("GET") == 4 and s.count("HEAD") == 6
    top = zones()["top"]
    assert top["status"] == "unchanged" and "same Last-Modified" in top["error"]
    assert top["retry_at"] == czds.next_slot(d1 + 2 * DAY + timedelta(hours=6, minutes=50) + czds.MIN_GAP,
                                             czds.load_config())
    assert runs("top")[-1]["status"] == "unchanged" and runs("top")[-1]["file_bytes"] is None

    # czds_runs older than 120 days go; newer ones stay
    run_sql("INSERT INTO czds_runs (tld, at, status) VALUES ('top', now() - interval '130 days', 'ok'), "
            "('top', now() - interval '100 days', 'ok')")
    # Day 4: the same serial served again under a new Last-Modified: downloaded, found unchanged, lists kept
    s.zones["top"] = (s.zones["top"][0], "Sun, 15 Nov 2026 05:10:00 GMT")
    before = (j.data / "top" / "names.gz").read_bytes()
    j.run(d1 + 3 * DAY + 7 * H)
    top = zones()["top"]
    assert s.count("GET", "top") == 3 and top["status"] == "unchanged" and "already processed" in top["error"]
    assert runs("top")[-1]["file_bytes"] == len(s.zones["top"][0]) and top["soa_serial"] == 2026111300
    assert (j.data / "top" / "names.gz").read_bytes() == before and j.files("top") == ["names.gz", "names.prev.gz"]
    ages = [r["at"] for r in q("SELECT at FROM czds_runs WHERE at < now() - interval '90 days'")]
    assert len(ages) == 1                                           # the 130-day-old row was deleted
    assert len(q("SELECT * FROM domains WHERE source = 'czds'")) == 2      # nothing stored twice

    # Day 5: the approval disappears from the links list (revoked or expired)
    s.links = [DL + idn + ".zone", DL + "shop.zone"]
    out = j.run(d1 + 4 * DAY + 7 * H)
    top = zones()["top"]
    assert out["revoked"] == ["top"] and top["status"] == "revoked" and top["approved"] is False
    assert top["next_due"] is None and "no longer in the CZDS approved list" in top["error"]
    assert s.count("GET", "top") == 3

    # top and xyz taken out of CZDS_TLDS, shop (approved all along) added: its zone answers 404
    j.set_tlds(idn, "shop")
    j.run(d1 + 4 * DAY + 8 * H)
    z = zones()
    assert z["top"]["configured"] is False and z["xyz"]["configured"] is False and z[idn]["configured"] is True
    assert z["xyz"]["status"] == "not_configured" and z["top"]["status"] == "not_configured"
    assert j.files("top") == ["names.gz", "names.prev.gz"]           # lists stay for the grace period
    shop = z["shop"]
    assert shop["configured"] is True and shop["status"] == "error" and shop["error"] == "HTTP 404 for this zone"
    assert shop["retry_at"] == czds.next_slot(d1 + 4 * DAY + 8 * H + czds.MIN_GAP, czds.load_config())
    assert s.count("HEAD", "shop") == 1 and s.count("GET", "shop") == 0 and runs("shop")[-1]["status"] == "error"

    # Back in CZDS_TLDS after its revocation: configured again, waiting for approval
    j.set_tlds(idn, "shop", "top")
    j.run(d1 + 4 * DAY + 9 * H)
    top = zones()["top"]
    assert top["configured"] is True and top["status"] == "pending" and top["approved"] is False


def _seed_zone(tld: str, **fields) -> None:
    async def go():
        p = await db.pool()
        async with p.connection() as conn:
            await czds.save_zone(conn, tld, fields)
    arun(go())


def _age(path: Path, days: float, ref: datetime) -> None:
    """Make a directory and its files look `days` old at `ref` (the czds module's fake clock)."""
    t = ref.timestamp() - days * 86400
    for p in [path, *path.iterdir()]:
        os.utime(p, (t, t))


def test_czds_leftovers_pending_files_and_failures(monkeypatch):
    j = CzdsJob(monkeypatch, tlds="top,xyz,shop,site")
    s, d1 = j.server, j.d1
    s.links = [DL + "top.zone", DL + "xyz.zone", DL + "shop.zone", DL + "site.zone"]
    started = d1 + timedelta(hours=6, minutes=30)
    # top: a worker died mid-download (status downloading, partial file on disk)
    _seed_zone("top", configured=True, approved=True, approved_at=d1 - DAY, download_url=DL + "top.zone",
               status="downloading", last_download=started, last_head=started, state={})
    tdir = j.data / "top"
    tdir.mkdir(parents=True)
    (tdir / czds.PART).write_bytes(b"\x1f\x8b partial")
    # xyz: downloaded, then the worker restarted before processing: processed without a new download
    raw = zone_gz("xyz", ["westpac-secure-login", "alpha"], 9)
    _seed_zone("xyz", configured=True, approved=True, download_url=DL + "xyz.zone", status="downloaded",
               last_download=started, file_bytes=len(raw),
               state={"download": {"bytes": len(raw), "last_modified": "x", "started": started.isoformat()},
                      "attempts": 0})
    (j.data / "xyz").mkdir()
    (j.data / "xyz" / czds.RAW).write_bytes(raw)
    # shop: two processing attempts already failed on this file
    _seed_zone("shop", configured=True, approved=True, download_url=DL + "shop.zone", status="processing",
               last_download=started, state={"attempts": 2, "download": {"bytes": 300}})
    (j.data / "shop").mkdir()
    (j.data / "shop" / czds.RAW).write_bytes(b"\x1f\x8b" + b"x" * 300)
    # site: marked processing, but its downloaded file is gone (data volume replaced?)
    _seed_zone("site", configured=True, approved=True, download_url=DL + "site.zone", status="processing",
               last_download=started, state={"attempts": 1})

    j.run(d1 + 8 * H)
    z = zones()
    assert z["site"]["status"] == "error" and z["site"]["error"] == "downloaded file is missing; next download tomorrow"
    assert z["top"]["status"] == "error" and "interrupted" in z["top"]["error"]
    assert not (tdir / czds.PART).exists() and s.count("GET") == 0 and s.count("HEAD") == 0
    assert z["xyz"]["status"] == "baseline" and z["xyz"]["total_names"] == 2 and j.files("xyz") == ["names.gz"]
    assert "attempts" not in z["xyz"]["state"]
    assert z["shop"]["status"] == "error" and "processing failed twice" in z["shop"]["error"]
    assert j.files("shop") == [] and "attempts" not in z["shop"]["state"]
    assert {(r["tld"], r["status"]) for r in runs()} == {("xyz", "baseline"), ("shop", "error")}

    # Next day, while the CZDS zone list is down (the stored download URLs are used): a truncated download is
    # rejected, a 409 (new terms to accept) stops a zone, a 503 is retried later with a back-off
    s.zones["top"] = (zone_gz("top", ["alpha", "beta"], 5), "Mon")
    s.zones["shop"] = (zone_gz("shop", ["alpha", "beta"], 5), "Mon")
    s.bad_length = True
    s.status["xyz"] = 409
    s.status["site"] = 503
    s.links_status = 500
    j.ctx.state.pop("links_at", None)
    out = j.run(d1 + DAY + 7 * H)
    assert out["links_error"] == "listing approved zones: HTTP 500"
    z = zones()
    site = z["site"]
    assert (site["status"], site["fail_count"], site["error"]) == ("retrying", 1, "download failed: HTTP 503")
    assert site["retry_at"] == czds.next_slot(d1 + DAY + 8 * H, czds.load_config())
    assert s.count("HEAD", "site") == 1 and s.count("GET", "site") == 1
    assert z["top"]["status"] == "invalid" and "truncated download" in z["top"]["error"]
    assert z["top"]["file_bytes"] == len(s.zones["top"][0]) and j.files("top") == []
    assert runs("top")[-1]["status"] == "invalid" and runs("top")[-1]["file_bytes"] == len(s.zones["top"][0])
    assert z["xyz"]["status"] == "terms" and z["xyz"]["retry_at"] > d1 + DAY + 7 * H
    assert s.count("GET", "xyz") == 0 and z["xyz"]["last_head"] == d1 + DAY + 7 * H

    # A zone whose access ended while its downloaded file waited: the file is deleted (T&C s1.4)
    s.bad_length = False
    _seed_zone("shop", status="downloaded", state={"download": {"bytes": 10}, "attempts": 0})
    (j.data / "shop" / czds.RAW).write_bytes(zone_gz("shop", ["a"], 1))
    s.links = [DL + "top.zone", DL + "xyz.zone", DL + "site.zone"]
    s.links_status = 200
    j.ctx.state.pop("links_at", None)                               # list approvals again on this run
    out = j.run(d1 + DAY + 9 * H)
    z = zones()
    assert out["revoked"] == ["shop"] and z["shop"]["status"] == "error" and "access ended" in z["shop"]["error"]
    assert j.files("shop") == []
    site = z["site"]                                                # still 503: back-off 1 h, then 2 h
    assert site["fail_count"] == 2 and s.count("GET", "site") == 2
    assert site["retry_at"] == czds.next_slot(d1 + DAY + 11 * H, czds.load_config())

    # Day 3: a file without its closing SOA record is rejected and the rejection is counted in the state;
    # the zone that kept failing recovers and its failure counters are reset
    s.status.clear()
    names = ["alpha", "beta", "gamma", "delta", "epsilon"]
    s.zones["top"] = (zone_gz("top", names, 6, end_soa=False), "Wed")
    s.zones["site"] = (zone_gz("site", names, 6), "Wed")
    j.run(d1 + 2 * DAY + timedelta(hours=7, minutes=10))
    z = zones()
    assert z["top"]["status"] == "invalid" and "does not end with the SOA record" in z["top"]["error"]
    assert z["top"]["state"]["tolerate"] == {"end_soa_missing": 1} and j.files("top") == []
    assert runs("top")[-1]["status"] == "invalid"
    site = z["site"]
    assert (site["status"], site["fail_count"], site["retry_at"], site["total_names"]) == ("baseline", 0, None, 5)


def test_czds_clean_up_without_credentials_or_tlds_and_when_disabled(monkeypatch):
    j = CzdsJob(monkeypatch, tlds="top")
    s, d1 = j.server, j.d1
    s.zones["top"] = (zone_gz("top", ["alpha", "beta", "gamma", "delta"], 1), "Mon")
    j.run(d1 + 7 * H)
    assert zones()["top"]["status"] == "baseline" and j.files("top") == ["names.gz"]
    # lists of a TLD taken out of CZDS_TLDS are deleted after CZDS_KEEP_UNCONFIGURED_DAYS (7)
    old = j.data / "museum"
    old.mkdir()
    (old / czds.CUR_LIST).write_bytes(b"x")
    _age(old, 8, d1 + 8 * H)

    j.set_tlds()                                                    # CZDS_TLDS emptied
    out = j.run(d1 + 8 * H)
    assert out["skipped"] == "CZDS_TLDS is empty" and out["approved"] == 3 and out["deleted_lists"] == ["museum"]
    assert zones()["top"]["configured"] is False and zones()["top"]["status"] == "baseline"
    assert j.files("top") == ["names.gz"]                           # within the grace period

    # credentials removed: no network or database at all; raw files go at once, lists after the grace period
    (j.data / "top" / czds.RAW).write_bytes(b"raw")
    (j.data / "top" / czds.PART).write_bytes(b"part")
    stale = j.data / "xyz"
    stale.mkdir()
    (stale / czds.CUR_LIST).write_bytes(b"x")
    _age(stale, 10, d1 + 9 * H)
    snapshot = q("SELECT tld, updated_at FROM czds_zones ORDER BY tld")
    n = len(s.requests)
    monkeypatch.delenv("CZDS_PASSWORD")
    config.settings.cache_clear()
    j.ctx.settings = config.settings()
    out = j.run(d1 + 9 * H)
    assert out == {"skipped": "no CZDS credentials", "deleted_lists": ["xyz"]}
    assert len(s.requests) == n and q("SELECT tld, updated_at FROM czds_zones ORDER BY tld") == snapshot
    assert j.files("top") == ["names.gz"] and not stale.exists()

    # the job turned off: the housekeeping hook does the same clean-up
    monkeypatch.setenv("CZDS_PASSWORD", "it-password")
    monkeypatch.setenv("JOB_CZDS_ENABLED", "false")
    config.settings.cache_clear()
    _age(j.data / "top", 9, j.now)
    assert czds.cleanup_if_disabled() == ["top"] and not (j.data / "top").exists()
    monkeypatch.setenv("JOB_CZDS_ENABLED", "true")
    assert czds.cleanup_if_disabled() == []


def test_czds_two_runs_at_once_only_one_works(monkeypatch):
    j = CzdsJob(monkeypatch, tlds="top")
    j.server.zones["top"] = (zone_gz("top", ["alpha", "commbank-login"], 3), "Mon")
    j.now = j.d1 + 7 * H
    other = JobContext(settings=j.ctx.settings, log=logging.getLogger("cybercheck.job.czds"))

    async def both():
        return await asyncio.gather(czds_job.run(j.ctx), czds_job.run(other))
    a, b = arun(both())
    assert b == {"skipped": "another czds run is active"} and a["processed"]["top"]["status"] == "baseline"
    assert j.server.count("GET") == 1 and len(runs()) == 1


def test_czds_database_error_while_storing_hits_keeps_the_previous_list(monkeypatch):
    j = CzdsJob(monkeypatch, tlds="top")
    s, d1 = j.server, j.d1
    base = ["alpha", "beta", "gamma", "delta", "epsilon"]
    s.zones["top"] = (zone_gz("top", base, 100), "Mon")
    j.run(d1 + 7 * H)
    assert zones()["top"]["status"] == "baseline"
    baseline_list = (j.data / "top" / czds.CUR_LIST).read_bytes()

    # A real database error on the second hit (constraint added to this test database only)
    run_sql("ALTER TABLE domains ADD CONSTRAINT it_refuse_one CHECK (registered_domain <> 'commbank-login.top') "
            "NOT VALID")
    try:
        s.zones["top"] = (zone_gz("top", base + ["commbank-verify-account", "commbank-login"], 101), "Tue")
        j.run(d1 + DAY + 7 * H)
    finally:
        run_sql("ALTER TABLE domains DROP CONSTRAINT it_refuse_one")
    top = zones()["top"]
    assert top["status"] == "error" and top["error"].startswith("storing hits failed: CheckViolation")
    assert top["soa_serial"] == 100 and top["hits"] == 0 and "attempts" not in top["state"]
    assert j.files("top") == ["names.gz"] and (j.data / "top" / czds.CUR_LIST).read_bytes() == baseline_list
    assert runs("top")[-1]["status"] == "error"
    # stores are not transactional: the hit stored before the error stays (the pipeline checks it as usual)
    assert domain("commbank-verify-account.top")["source"] == "czds" and domain("commbank-login.top") is None

    # The next file is compared with the same list again, so both names are new again; nothing is lost
    s.zones["top"] = (zone_gz("top", base + ["commbank-verify-account", "commbank-login"], 102), "Wed")
    j.run(d1 + 2 * DAY + 7 * H + timedelta(minutes=10))
    top = zones()["top"]
    assert (top["status"], top["new_names"], top["hits"], top["new_hits"], top["soa_serial"]) == ("ok", 2, 2, 1, 102)
    assert domain("commbank-login.top")["source"] == "czds"
    kinds = [k for k, _ in events(domain("commbank-verify-account.top")["id"])]
    assert kinds == ["first_seen", "czds_new_delegation"]


def test_bot_database_errors_and_missing_tables():
    tg = Telegram()
    dashboard_set_chat(5801, "allowed")
    # A real database error while recording the message: the chat gets the "try again" reply, the pooled
    # connection stays usable, the next message works
    run_sql("ALTER TABLE bot_messages ADD CONSTRAINT it_refuse CHECK (cardinality(domains) < 2) NOT VALID")
    try:
        async def failing():
            async with make_bot(tg) as b:
                await b.handle_update(update(1, 5801, "two links: commbank-login.top and mygov-verify.top"))
                await b.handle_update(update(2, 5801, "one link: ato-refund.top"))
                return b.stats
        stats = arun(failing())
    finally:
        run_sql("ALTER TABLE bot_messages DROP CONSTRAINT it_refuse")
    assert stats["errors"] == 1 and stats["checks"] == 1
    first, second = tg.texts(5801)
    assert first == bot.SORRY_TEXT and "SUSPICIOUS" in second
    assert [m["registered"] for m in q("SELECT registered FROM bot_messages WHERE chat_id = 5801")] == \
        [["ato-refund.top"]]
    c = chat_row(5801)
    assert c["day_messages"] == 2 and c["total_domains"] == 1      # the failed check still used a slot
    assert domain("commbank-login.top")["source"] == "bot"          # stored before the error

    # Tables missing (migrations not applied yet): tables_ready() says so
    run_sql("ALTER TABLE bot_messages RENAME TO it_bot_messages_away")
    try:
        async def ready():
            async with bot.db_repo() as repo:
                return await repo.tables_ready()
        assert arun(ready()) is False
    finally:
        run_sql("ALTER TABLE it_bot_messages_away RENAME TO bot_messages")


# ===================================================================================================
# verifier additions
# ===================================================================================================

def test_czds_24h_rule_holds_across_a_dst_change_in_the_session_timezone(monkeypatch):
    """psycopg returns timestamptz values in the session's time zone (a ZoneInfo). In a DST zone, adding MIN_GAP to a
    stored last_download is wall-clock arithmetic: across Sydney's October change that is 23 h 05 m of real time,
    which would break CZDS T&C s1.8 (one GET per zone per 24 h)."""
    monkeypatch.setenv("CYBERCHECK_DB_OPTIONS", "")      # turn off db.py's UTC pin: prove the code holds without it
    monkeypatch.setenv("PGTZ", "Australia/Sydney")              # libpq: session TimeZone for every connection
    j = CzdsJob(monkeypatch, tlds="top")
    s = j.server
    prev = datetime(2026, 10, 3, 7, 40, tzinfo=UTC)             # Sydney goes to AEDT at 2026-10-03 16:00 UTC
    _seed_zone("top", configured=True, approved=True, approved_at=prev - 30 * DAY, download_url=DL + "top.zone",
               status="ok", last_download=prev, last_head=prev, last_processed=prev, soa_serial=2026100300,
               total_names=3, state={"processed": {"last_modified": "Sat, 03 Oct 2026 05:10:00 GMT", "bytes": 999}})
    assert one("SHOW timezone")["TimeZone"] == "Australia/Sydney"
    s.zones["top"] = (zone_gz("top", ["alpha", "beta", "gamma", "commbank-login"], 2026100400),
                      "Sun, 04 Oct 2026 05:10:00 GMT")

    out = j.run(datetime(2026, 10, 4, 6, 50, tzinfo=UTC))       # 23 h 10 m after the last GET
    top = zones()["top"]
    assert s.count("GET") == 1 and s.count("HEAD") == 1
    assert top["last_download"] - prev >= czds.MIN_GAP and top["last_head"] - prev >= czds.MIN_GAP
    assert j.slept == [3300.0]                                  # waited until 07:45 UTC
    assert top["status"] == "baseline" and out["processed"]["top"]["status"] == "baseline"
    assert top["next_due"] - top["last_download"] >= czds.MIN_GAP


def test_bot_zero_daily_limit_tells_the_chat_once_a_day(it_db):
    """BOT_DAILY_LIMIT_PER_CHAT=0: no check is made, and the chat is told about the limit once per UTC day (the
    counters of an earlier day are reset). take_message_slot is never called then, so mark_limit_notified must
    start the day's counters itself."""
    tg = Telegram()
    dashboard_set_chat(5901, "allowed")
    today = bot.utc_today()

    async def two_messages(uid):
        async with make_bot(tg, daily_limit=0) as b:
            await b.handle_update(update(uid, 5901, "see commbank-login.top"))
            await b.handle_update(update(uid + 1, 5901, "and mygov-verify.top"))
    arun(two_messages(1))
    assert tg.texts(5901) == [bot.limit_text(0)]
    c = chat_row(5901)
    assert (c["counter_day"], c["limit_notified"], c["day_messages"], c["day_ai"], c["total_messages"]) == \
        (today, True, 0, 0, 0)
    assert q("SELECT * FROM domains") == [] and q("SELECT * FROM bot_messages") == []

    # A chat with yesterday's counters: told once more today, and yesterday's counts do not carry over
    run_sql("UPDATE bot_chats SET counter_day = counter_day - 1, day_messages = 7, day_ai = 2, limit_notified = true "
            "WHERE chat_id = 5901")
    arun(two_messages(3))
    assert tg.texts(5901) == [bot.limit_text(0)] * 2
    c = chat_row(5901)
    assert (c["counter_day"], c["limit_notified"], c["day_messages"], c["day_ai"]) == (today, True, 0, 0)

    # Raised to 2 later the same day: checks work, and the limit reply is not sent a second time today
    async def raised():
        async with make_bot(tg, daily_limit=2) as b:
            for uid, host in ((5, "ato-refund.top"), (6, "linkt-toll-pay.top"), (7, "nab-verify.top")):
                await b.handle_update(update(uid, 5901, f"see {host}"))
    arun(raised())
    assert len(tg.texts(5901)) == 4 and "SUSPICIOUS" in tg.texts(5901)[-1]
    assert chat_row(5901)["day_messages"] == 2 and domain("nab-verify.top") is None

    # Concurrent first contact of the day for a chat that never had a check: exactly one notification
    dashboard_set_chat(5902, "allowed")

    async def race():
        cs = [await psycopg.AsyncConnection.connect(it_db, autocommit=True, row_factory=dict_row) for _ in range(6)]
        try:
            return await asyncio.gather(*(bot.Repo(c).mark_limit_notified(5902, today) for c in cs))
        finally:
            for c in cs:
                await c.close()
    assert sorted(arun(race())) == [False] * 5 + [True]
    assert chat_row(5902)["counter_day"] == today


def test_bot_chat_title_with_lone_surrogates_is_stored():
    """Telegram's JSON can carry lone UTF-16 surrogates (json.loads accepts them); UTF-8 cannot encode them."""
    tg = Telegram()
    upd = json.loads('{"update_id": 1, "message": {"message_id": 7, "date": 1763251200, '
                     '"chat": {"id": 5951, "type": "private", "first_name": "Kim \\ud83d", "username": "k\\udc00m"}, '
                     '"from": {"id": 1, "is_bot": false, "first_name": "Kim"}, "text": "hello \\ud83d"}}')

    async def go():
        async with make_bot(tg) as b:
            await b.handle_update(upd)
            return b.stats
    assert arun(go())["errors"] == 0
    c = chat_row(5951)
    assert (c["title"], c["username"], c["status"]) == ("Kim ", "km", "pending")
    assert tg.texts(5951) == [bot.NOT_ENABLED_TEXT]


def test_bot_waits_for_the_database_and_the_tables_then_reads_the_saved_offset(it_db, monkeypatch, caplog):
    """wait_until_ready: a database that refuses the connection, then missing bot tables, then ready (the loop's
    60 s sleeps are replaced; each problem is logged once)."""
    async def save_offset():
        async with bot.db_repo() as repo:
            await repo.set_offset(424242)
    arun(save_offset())
    run_sql("ALTER TABLE bot_chats RENAME TO it_bot_chats_away")
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:                                    # migrations applied meanwhile
            run_sql("ALTER TABLE it_bot_chats_away RENAME TO bot_chats")

    attempts = []

    @asynccontextmanager
    async def repo_factory():
        attempts.append(1)
        if len(attempts) == 1:                                  # a real refusal from the server
            await psycopg.AsyncConnection.connect(it_db.rsplit("/", 1)[0] + "/it_no_such_database_here")
        async with bot.db_repo() as r:
            yield r

    monkeypatch.setattr(bot, "asyncio", type(asyncio)("asyncio_for_bot"))
    vars(bot.asyncio).update({k: v for k, v in vars(asyncio).items() if not k.startswith("__")}, sleep=fake_sleep)
    tg = Telegram()
    try:
        async def go():
            async with make_bot(tg, repo_factory=repo_factory) as b:
                with caplog.at_level(logging.WARNING, logger="cybercheck.bot"):
                    await b.wait_until_ready()
                return b.offset
        assert arun(go()) == 424242
    finally:
        if one("SELECT to_regclass('it_bot_chats_away') IS NOT NULL AS away")["away"]:
            run_sql("ALTER TABLE it_bot_chats_away RENAME TO bot_chats")
    assert sleeps == [60, 60, 60] and len(attempts) == 4
    waits = [r.getMessage() for r in caplog.records if r.getMessage().startswith("bot waiting")]
    assert waits == ["bot waiting: database not reachable (OperationalError)",
                     "bot waiting: bot tables are missing: run `python -m cybercheck migrate`"]


def _day(base: datetime, n: int) -> datetime:
    """Inside the window, a little later each day so every GET is more than MIN_GAP after the previous one."""
    return base + n * DAY + timedelta(hours=7, minutes=10 * n)


def test_czds_count_check_rejects_then_accepts_via_state_read_back_from_jsonb(monkeypatch):
    """The 'same level as yesterday's rejected file' rule needs state.rejected_total, which only lives in the
    czds_zones.state jsonb between runs. A fresh JobContext each day (worker restarts) proves it is read back."""
    j = CzdsJob(monkeypatch, tlds="top")
    s = j.server
    base = j.d1 - 10 * DAY
    names = [f"n{i:04d}" for i in range(1000)]
    s.zones["top"] = (zone_gz("top", names, 1), "D0")
    j.run(_day(base, 0))
    assert zones()["top"]["status"] == "baseline" and zones()["top"]["total_names"] == 1000
    baseline_list = (j.data / "top" / czds.CUR_LIST).read_bytes()

    def restart():
        j.ctx = JobContext(settings=j.ctx.settings, log=j.ctx.log)

    restart()
    s.zones["top"] = (zone_gz("top", names + [f"m{i:03d}" for i in range(500)], 2), "D1")
    j.run(_day(base, 1))
    top = zones()["top"]
    assert top["status"] == "invalid" and top["error"] == ("1500 names is 50% off the last count (1000); "
                                                           "kept the previous list")
    assert top["state"]["rejected_total"] == 1500 and "tolerate" not in top["state"] and "attempts" not in top["state"]
    assert (top["total_names"], top["soa_serial"]) == (1000, 1)                 # counters of the last good file
    assert (j.data / "top" / czds.CUR_LIST).read_bytes() == baseline_list and j.files("top") == ["names.gz"]
    assert runs("top")[-1]["status"] == "invalid" and runs("top")[-1]["total_names"] is None

    restart()
    s.zones["top"] = (zone_gz("top", names + [f"m{i:03d}" for i in range(519)] + ["commbank-login"], 3), "D2")
    j.run(_day(base, 2))
    top = zones()["top"]
    assert top["status"] == "ok" and top["error"] == ("name count moved 52% (accepted: same level as the previous "
                                                      "day's rejected file)")
    assert (top["total_names"], top["new_names"], top["removed_names"], top["hits"], top["new_hits"]) == \
        (1520, 520, 0, 1, 1)
    assert "rejected_total" not in top["state"] and top["soa_serial"] == 3
    assert domain("commbank-login.top")["source"] == "czds"
    r = runs("top")[-1]
    assert (r["status"], r["total_names"], r["new_names"], r["hits"], r["error"]) == \
        ("ok", 1520, 520, 1, top["error"])


def test_czds_missing_closing_soa_is_tolerated_after_two_days_in_a_row(monkeypatch):
    """state.tolerate counts the same rejection on consecutive days; another kind of failure resets it, and a file
    that closes with the SOA again ends the tolerance."""
    j = CzdsJob(monkeypatch, tlds="top")
    s = j.server
    base = j.d1 - 10 * DAY
    names = ["alpha", "beta", "gamma", "delta", "epsilon"]
    s.zones["top"] = (zone_gz("top", names, 10), "D0")
    j.run(_day(base, 0))
    assert zones()["top"]["status"] == "baseline"

    def day(n, data, expect_status):
        s.zones["top"] = (data, f"D{n}")
        j.run(_day(base, n))
        z = zones()["top"]
        assert z["status"] == expect_status, (n, z["status"], z["error"])
        assert runs("top")[-1]["status"] == expect_status
        return z

    z = day(1, zone_gz("top", names, 11, end_soa=False), "invalid")
    assert z["state"]["tolerate"] == {"end_soa_missing": 1}
    junk = b"<html><body>" + b"Service temporarily unavailable. " * 20 + b"</body></html>"
    z = day(2, junk, "invalid")                                 # another kind of failure: the count starts again
    assert "not a gzip file" in z["error"] and "tolerate" not in z["state"]
    z = day(3, zone_gz("top", names, 12, end_soa=False), "invalid")
    assert z["state"]["tolerate"] == {"end_soa_missing": 1}
    z = day(4, zone_gz("top", names, 13, end_soa=False), "invalid")
    assert z["state"]["tolerate"] == {"end_soa_missing": 2} and z["soa_serial"] == 10
    z = day(5, zone_gz("top", names + ["commbank-login"], 14, end_soa=False), "ok")
    assert z["error"] == "accepted without a closing SOA record (this registry's files never have one)"
    assert z["state"]["tolerate"] == {"end_soa_missing": 2}    # kept: the next file is accepted too
    assert (z["soa_serial"], z["new_names"], z["hits"], z["new_hits"]) == (14, 1, 1, 1)
    assert domain("commbank-login.top")["source"] == "czds"
    z = day(6, zone_gz("top", names + ["commbank-login", "zeta"], 15, end_soa=False), "ok")
    assert z["new_names"] == 1 and z["state"]["tolerate"] == {"end_soa_missing": 2}
    z = day(7, zone_gz("top", names + ["commbank-login", "zeta"], 16), "ok")
    assert "tolerate" not in z["state"] and z["error"] is None and z["new_names"] == 0
    assert [r["status"] for r in runs("top")] == ["baseline", "invalid", "invalid", "invalid", "invalid", "ok", "ok",
                                                  "ok"]


class _CutStream(httpx.AsyncByteStream):
    """A 200 answer whose connection drops halfway through the file."""

    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        yield self.data[: len(self.data) // 2]
        raise httpx.ReadError("connection reset by peer")

    async def aclose(self):
        pass


class FaultyCzds(CzdsServer):
    def __init__(self, clock):
        super().__init__(clock)
        self.cut: set[str] = set()
        self.head_length: dict[str, int] = {}
        self.gets: list[tuple[str, datetime]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        resp = super().handler(request)
        if request.url.host != "czds-download-api.icann.org" or resp.status_code != 200:
            return resp
        tld = request.url.path.rsplit("/", 1)[-1][:-len(".zone")]
        if request.method == "HEAD" and tld in self.head_length:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return httpx.Response(200, headers={**headers, "content-length": str(self.head_length[tld])})
        if request.method == "GET":
            self.gets.append((tld, self.clock()))
            if tld in self.cut:
                return httpx.Response(200, headers=resp.headers, stream=_CutStream(self.zones[tld][0]))
        return resp


def test_czds_fetch_failures_record_why_and_keep_the_24h_rule(monkeypatch):
    monkeypatch.setenv("CZDS_MAX_ZONE_GB", "0.01")
    j = CzdsJob(monkeypatch, tlds="top,xyz,shop,site")
    j.server = s = FaultyCzds(lambda: j.now)
    s.links = [DL + "top.zone", DL + "xyz.zone", DL + "shop.zone"]
    base = j.d1 - 10 * DAY
    for t in ("top", "xyz", "shop"):
        s.zones[t] = (zone_gz(t, ["alpha", "beta", "gamma"], 1), "Mon")
    s.cut.add("top")                                            # 200, then the connection drops
    s.status["xyz"] = 403                                       # request expired
    s.head_length["shop"] = 50_000_000                          # over CZDS_MAX_ZONE_GB (10 MB here)
    t1 = base + 7 * H
    j.run(t1)
    z = zones()
    top = z["top"]
    assert (top["status"], top["error"]) == ("error", "download interrupted (ReadError); next try tomorrow")
    assert top["last_download"] == t1 and top["retry_at"] is None and j.files("top") == []
    assert top["next_due"] == czds.next_slot(t1 + czds.MIN_GAP, czds.load_config())
    xyz = z["xyz"]
    assert (xyz["status"], xyz["retry_at"]) == ("no_access", czds.next_slot(t1 + czds.MIN_GAP, czds.load_config()))
    assert "HTTP 403" in xyz["error"] and xyz["last_download"] is None and s.count("GET", "xyz") == 0
    shop = z["shop"]
    assert (shop["status"], shop["error"]) == ("invalid", "zone file is 50000000 bytes, over CZDS_MAX_ZONE_GB")
    assert s.count("GET", "shop") == 0 and shop["state"]["head"]["length"] == 50_000_000
    assert z["site"]["status"] == "not_approved"
    assert {(r["tld"], r["status"]) for r in runs()} == {("top", "error"), ("xyz", "no_access"), ("shop", "invalid")}

    # Later that day the worker restarts (no in-memory GET times) and the zone list is down: the 24 h rule then
    # rests on czds_zones.last_download alone. A zone approved without a stored download URL (a hand-edited or
    # restored row; apply_links always writes both) is put off for an hour.
    run_sql("UPDATE czds_zones SET approved = true, approved_at = now(), status = 'approved' WHERE tld = 'site'")
    s.links_status = 503
    j.ctx = JobContext(settings=j.ctx.settings, log=j.ctx.log)
    t2 = base + 12 * H
    out = j.run(t2)
    assert out["links_error"] == "listing approved zones: HTTP 503"
    assert s.count("GET", "top") == 1 and s.count("HEAD", "top") == 1
    site = zones()["site"]
    assert (site["status"], site["error"], site["retry_at"]) == ("error", "no download URL for this zone yet", t2 + H)
    assert runs("site")[-1]["status"] == "error"

    # Next day everything works again
    s.cut.clear()
    s.status.clear()
    s.head_length.clear()
    s.links_status = 200
    t3 = base + DAY + timedelta(hours=7, minutes=10)
    j.run(t3)
    z = zones()
    assert {t: z[t]["status"] for t in ("top", "xyz", "shop")} == {"top": "baseline", "xyz": "baseline",
                                                                   "shop": "baseline"}
    assert all(z[t]["fail_count"] == 0 and z[t]["retry_at"] is None for t in ("top", "xyz", "shop"))
    top_gets = [at for t, at in s.gets if t == "top"]
    assert top_gets == [t1, t3] and t3 - t1 >= czds.MIN_GAP


def test_czds_in_memory_get_time_guards_the_24h_rule_when_the_database_write_fails(monkeypatch):
    """The GET started but recording last_download failed (a real constraint error from Postgres): the error escapes
    the zone, run_once records it, and the same worker never downloads that zone again within 24 h."""
    j = CzdsJob(monkeypatch, tlds="top")
    s = j.server
    s.zones["top"] = (zone_gz("top", ["alpha", "beta", "gamma"], 1), "Mon")
    base = j.d1 - 10 * DAY
    run_sql("ALTER TABLE czds_zones ADD CONSTRAINT it_refuse_downloading CHECK (status <> 'downloading') NOT VALID")
    try:
        out = j.run(base + 7 * H)
    finally:
        run_sql("ALTER TABLE czds_zones DROP CONSTRAINT it_refuse_downloading")
    top = zones()["top"]
    assert top["status"] == "error" and top["error"].startswith("CheckViolation: new row for relation \"czds_zones\"")
    assert top["last_download"] is None and s.count("GET") == 1 and out["processed"]["top"] == {"status": "error"}
    assert runs("top")[-1]["status"] == "error" and j.files("top") == []
    assert j.ctx.state["gets"]["top"] == base + 7 * H

    j.run(base + 12 * H)                                        # same worker process: no second GET
    top = zones()["top"]
    assert s.count("GET") == 1 and top["status"] == "error"
    assert top["next_due"] == czds.next_slot(base + 7 * H + czds.MIN_GAP, czds.load_config())

    j.run(base + DAY + timedelta(hours=7, minutes=10))
    assert s.count("GET") == 2 and zones()["top"]["status"] == "baseline"


def test_czds_processing_failure_keeps_the_list_and_the_next_file_is_compared_with_it(monkeypatch):
    j = CzdsJob(monkeypatch, tlds="top")
    s = j.server
    base = j.d1 - 10 * DAY
    names = ["alpha", "beta", "gamma", "delta", "epsilon"]
    s.zones["top"] = (zone_gz("top", names, 1), "D0")
    j.run(_day(base, 0))
    baseline_list = (j.data / "top" / czds.CUR_LIST).read_bytes()

    # `sort` dies (OOM-killed, say): the zone's run fails, the raw file goes, nothing is stored
    monkeypatch.setitem(czds._sort_cmd_cache, "cmd",
                        ["sh", "-c", "cat >/dev/null; echo 'sort: memory exhausted' >&2; exit 2", "sort"])
    s.zones["top"] = (zone_gz("top", names + ["commbank-login"], 2), "D1")
    j.run(_day(base, 1))
    top = zones()["top"]
    assert top["status"] == "error"
    assert top["error"] == "processing failed: RuntimeError: sort failed (exit 2): sort: memory exhausted"
    assert "attempts" not in top["state"] and top["soa_serial"] == 1 and top["hits"] == 0
    assert j.files("top") == ["names.gz"] and (j.data / "top" / czds.CUR_LIST).read_bytes() == baseline_list
    r = runs("top")[-1]
    assert (r["status"], r["file_bytes"], r["hits"]) == ("error", len(s.zones["top"][0]), None)
    assert domain("commbank-login.top") is None

    czds._sort_cmd_cache.pop("cmd")                             # a working sort again
    s.zones["top"] = (zone_gz("top", names + ["commbank-login"], 3), "D2")
    j.run(_day(base, 2))
    top = zones()["top"]
    assert (top["status"], top["new_names"], top["hits"], top["new_hits"], top["soa_serial"]) == ("ok", 1, 1, 1, 3)
    assert domain("commbank-login.top")["source"] == "czds"
