"""The operations pages on the new UI (AI, blocklist, CZDS, bot, takedowns): presentation helpers, the static
files they load, and each page rendered through the real app (CSP, base.html) with the database faked.
No network, no database."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cybercheck import blocklist as bl
from cybercheck import czds
from cybercheck.web import app as app_mod
from cybercheck.web import common, pages_ai, pages_blocklist, pages_bot, pages_czds, pages_takedown

LOCAL = "http://127.0.0.1:8430"
NOW = datetime.now(timezone.utc)
H = timedelta(hours=1)
XSS = "<script>alert(1)</script>"
TEMPLATES = Path(app_mod.__file__).parent / "templates"
STATIC = Path(app_mod.__file__).parent / "static"
OPS_TEMPLATES = ("ai_overview.html", "blocklist_index.html", "czds_index.html", "bot_index.html", "takedown_stats.html")


@pytest.fixture(autouse=True)
def _quiet_status_line(monkeypatch):
    """The status line never touches the (faked) database in these tests: every segment reads unknown."""
    async def unknown():
        return common.unknown_status("test")
    common.reset_status_cache()
    monkeypatch.setattr(common, "_query_status", unknown)
    yield
    common.reset_status_cache()


def client() -> TestClient:
    return TestClient(app_mod.app, base_url=LOCAL)


def assert_clean_page(html: str) -> None:
    """What every ops page must look like under the CSP: no inline style/script/handlers, its own assets."""
    assert ' style="' not in html and "<style" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", html)
    assert html.count("<h1") == 1
    assert re.search(r'<link rel="stylesheet" href="/static/ops\.css\?v=[0-9a-f]{10}">', html)
    assert re.search(r'<script src="/static/ops\.js\?v=[0-9a-f]{10}" defer></script>', html)
    assert "http://" not in html.split("<main", 1)[0] and "https://" not in html.split("<main", 1)[0]


def section(html: str, panel_id: str) -> str:
    """The HTML of one <section id=...> panel."""
    m = re.search(rf'<section class="panel[^"]*" id="{panel_id}"', html)
    assert m, panel_id
    start = m.start()
    return html[start:html.index("</section>", start)]


# ---- templates and static files ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", OPS_TEMPLATES)
def test_ops_templates_have_no_inline_script_style_or_handlers(name):
    src = re.sub(r"\{#.*?#\}", "", (TEMPLATES / name).read_text(encoding="utf-8"), flags=re.S)
    assert "style=" not in src and "<style" not in src
    assert not re.search(r"<script(?![^>]*\bsrc=)", src)
    assert not re.search(r"\son[a-z]+\s*=", src)
    assert "|safe" not in src.replace(" ", "") and "Markup" not in src
    assert '{% import "_ui.html" as ui %}' in src and "_row.html" not in src
    assert "asset('ops.css')" in src and "asset('ops.js')" in src


def test_ops_static_files_are_served_and_self_contained():
    c = client()
    css = c.get("/static/ops.css")
    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")
    js = c.get("/static/ops.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    for text in (css.text, js.text):
        assert "http://" not in text and "https://" not in text and "@import" not in text
    assert "url(" not in css.text
    # DOM is built as text only, and nothing is evaluated
    assert "innerHTML" not in js.text and "eval(" not in js.text and "new Function" not in js.text
    assert re.fullmatch(r"/static/ops\.js\?v=[0-9a-f]{10}", common.asset("ops.js"))


# ---- AI ---------------------------------------------------------------------------------------------------

def test_call_status_and_spend_tone():
    assert pages_ai.call_status("ok") == ("ok", "teal", "●")
    assert pages_ai.call_status("refusal")[1:] == ("amber", "▲")
    assert pages_ai.call_status("pending")[1] == "outline"
    assert pages_ai.call_status("api_error") == ("api error", "red", "■")
    assert pages_ai.call_status(None)[1] == "muted"
    assert pages_ai.spend_tone(0) == "violet" and pages_ai.spend_tone(69) == "violet"
    assert pages_ai.spend_tone(70) is None and pages_ai.spend_tone(100) is None   # the meter's amber / red


def test_spend_view_states_and_resets():
    now = datetime(2026, 12, 31, 22, 15, tzinfo=timezone.utc)
    s = {"spent_today": 0.8, "daily_cap": 1.6, "spent_month": 40.0, "monthly_cap": 48.0,
         "triage_spent_today": 0.5, "triage_cap": 0.4}
    day, month, triage = pages_ai.spend_view(s, now)
    assert (day["key"], day["pct"], day["state"], day["tone"]) == ("day", 50, "ok", "violet")
    assert day["left"] == pytest.approx(0.8)
    assert (month["pct"], month["state"], month["tone"]) == (83, "warn", None)
    assert (triage["pct"], triage["state"], triage["left"]) == (100, "over", 0.0)
    assert day["resets"] == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert month["resets"] == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert pages_ai._resets(datetime(2026, 2, 28, 1, tzinfo=timezone.utc))["month"] == datetime(2026, 3, 1, tzinfo=timezone.utc)
    # a cap of 0 reads as used up; missing numbers never break the page
    assert pages_ai.spend_view({"daily_cap": 0})[0]["state"] == "over"


class _Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchall(self):
        return self.rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None


class _AIConn:
    def __init__(self, calls):
        self.calls = calls

    async def execute(self, sql, params=None):
        if sql.lstrip().startswith("SELECT c.id"):
            return _Cur(self.calls)
        if "GROUP BY purpose" in sql:
            return _Cur([{"purpose": "page_judge", "calls": 3, "cost": 0.05, "refusals": 1, "errors": 1,
                          "cache_read": 300, "input": 700}])
        if "AS pages_pending" in sql:
            return _Cur([{"pages_pending": 2, "judged_24h": 4, "triaged_24h": 1}])
        return _Cur([])


def _ai_client(monkeypatch, status: dict, calls: list[dict], job=None):
    conn = _AIConn(calls)

    class _Ctx:
        async def __aenter__(self):
            return conn

        async def __aexit__(self, *exc):
            return False

    class _Pool:
        def connection(self):
            return _Ctx()

    async def pool():
        return _Pool()

    async def budget_status(c):
        return status

    async def kv_get(c, key, default=None):
        assert key == "job:judge"
        return job
    monkeypatch.setattr(pages_ai.db, "pool", pool)
    monkeypatch.setattr(pages_ai.db, "kv_get", kv_get)
    monkeypatch.setattr(pages_ai.api, "budget_status", budget_status)
    return client()


AI_STATUS = {"enabled": True, "has_key": True, "available": False, "reason": "daily AI budget used up",
             "model": "claude-opus-5-5", "effort": "low", "fallbacks": "default", "spent_today": 1.7,
             "daily_cap": 1.6, "spent_month": 12.0, "monthly_cap": 48.0, "triage_spent_today": 0.1,
             "triage_cap": 0.4, "calls_today": 9, "calls_month": 40, "refusals_today": 1, "refusals_month": 2,
             "errors_today": 1}


def _call(**kw):
    base = {"id": 1, "at": NOW, "purpose": "page_judge", "model": "claude-opus-5-5", "fallback_model": None,
            "status": "ok", "stop_reason": "end_turn", "input_tokens": 100, "output_tokens": 20,
            "cache_read_tokens": 0, "cache_write_tokens": 0, "cost_usd": 0.01, "estimated_cost_usd": 0.02,
            "duration_ms": 900, "error": None, "domain_id": 7, "page_id": 3, "registered_domain": "commbank-x.top",
            "verdict": "phishing", "refusal_category": None}
    return {**base, **kw}


def test_ai_page_renders_meters_states_and_filters(monkeypatch):
    calls = [_call(), _call(id=2, status="invalid", error=XSS, verdict=None),
             _call(id=3, status="refusal", verdict=None, refusal_category="cyber", fallback_model="claude-sonnet-5"),
             _call(id=4, status="pending", verdict=None, domain_id=None, registered_domain=None)]
    r = _ai_client(monkeypatch, AI_STATUS, calls, job={"last_run": NOW.isoformat(), "ok": False,
                                                        "error": "<b>boom</b>", "duration_s": 2.5}).get("/ai")
    assert r.status_code == 200 and r.headers["content-security-policy"] == app_mod.CSP
    t = r.text
    assert_clean_page(t)
    assert "AI checks and spend" in t and "AI not available" in t and "daily AI budget used up" in t
    # the daily meter is over its cap (red, full), the month is under (violet), triage at 25%
    assert 'class="spend-item spend-item--over" data-ai-spend="day"' in t and "Cap reached." in t
    assert '<svg class="meter meter--red"' in t and '<svg class="meter meter--violet"' in t
    assert 'width="100" height="4"/></svg>' in t and 'width="25" height="4"/></svg>' in t
    assert "$1.70" in t and "of $1.60" in t and "$12.00" in t and "of $48.00" in t
    assert re.search(r'<div class="n">2</div><div class="l">pages waiting for a check', t)
    # call states: glyph and text with each tone; problems are marked for the "refused or failed only" toggle
    assert "</span>refusal</span>" in t and "</span>pending</span>" in t and "</span>invalid</span>" in t
    assert t.count("<tr data-problem>") == 2 and 'data-filter-problems="calls-rows"' in t
    assert "refused: cyber" in t and "(fallback)" in t and "AI phishing" in t
    assert XSS not in t and "&lt;script&gt;" in t and "<b>boom</b>" not in t and "failed" in t
    assert 'href="/domain/7"' in t


def test_ai_page_with_ai_turned_off_and_no_calls(monkeypatch):
    status = {**AI_STATUS, "enabled": False, "has_key": False, "available": False, "reason": "AI_ENABLED is false",
              "spent_today": 0.0, "spent_month": 0.0, "triage_spent_today": 0.0, "calls_today": 0, "refusals_today": 0,
              "errors_today": 0}
    t = _ai_client(monkeypatch, status, []).get("/ai").text
    assert_clean_page(t)
    assert "AI not available" in t and "no API key" in t and "AI_ENABLED=false" in t
    assert "No AI calls yet." in t and "The judge job has not run yet." in t
    assert 'data-filter-for="calls-rows"' not in t                  # no filter box over an empty table


# ---- blocklist --------------------------------------------------------------------------------------------

def test_annotate_listed_and_event_labels():
    rows = pages_blocklist.annotate_listed([
        {"status": "confirmed", "blocklist_expires_at": NOW + timedelta(days=3)},
        {"status": "open", "blocklist_expires_at": NOW + timedelta(days=60)},
        {"status": "open", "blocklist_expires_at": None}], NOW)
    assert [(r["via"], r["expires_soon"]) for r in rows] == [("confirmed", True), ("score", False), ("score", False)]
    assert pages_blocklist.event_label("blocklisted") == ("listed", "teal", "●")
    assert pages_blocklist.event_label("blocklist_excluded")[1] == "amber"
    assert pages_blocklist.event_label("something_new") == ("something new", "muted", "○")
    assert set(pages_blocklist.MESSAGE_TONES) == set(pages_blocklist.MESSAGES)


def _blocklist_client(monkeypatch, tmp_path, listed, excluded=(), events=()):
    async def fake_fetchall(sql, params=()):
        if "FROM domains WHERE blocklisted\n" in sql or sql.lstrip().startswith("SELECT id, registered_domain, unicode_domain, brand_id, status, final_score"):
            return [dict(r) for r in listed]
        if "WHERE blocklist_excluded" in sql:
            return list(excluded)
        if "FROM domain_events" in sql:
            return list(events)
        raise AssertionError(sql)

    async def fake_fetchone(sql, params=()):
        if "count(*) FILTER" in sql:
            return {"listed": len(listed), "confirmed": 1, "automated": len(listed) - 1, "excluded": len(excluded),
                    "expiring": 1}
        if params == (bl.KV_STATE,):
            return {"value": {"built_at": NOW.isoformat(), "updated_at": NOW.isoformat(), "serial": 2026111601,
                              "held_czds": 2}}
        if params == (bl.KV_REBUILD,):
            return {"updated_at": NOW - timedelta(minutes=2)}
        raise AssertionError(sql)
    monkeypatch.setattr(pages_blocklist, "fetchall", fake_fetchall)
    monkeypatch.setattr(pages_blocklist, "fetchone", fake_fetchone)
    monkeypatch.setattr(bl, "out_dir", lambda: tmp_path)
    return client()


def test_blocklist_page_shows_why_each_domain_is_listed(monkeypatch, tmp_path):
    (tmp_path / "hosts.txt").write_text("0.0.0.0 x.top\n")
    listed = [{"id": 7, "registered_domain": "commbank-login.top", "unicode_domain": None, "brand_id": "commbank",
               "status": "confirmed", "final_score": None, "ai_verdict": None, "ai_confidence": None,
               "live_state": "live", "blocklist_listed_at": NOW - H, "blocklist_expires_at": NOW + timedelta(days=3)},
              {"id": 8, "registered_domain": XSS + ".top", "unicode_domain": None, "brand_id": "anz",
               "status": "open", "final_score": 93, "ai_verdict": "phishing", "ai_confidence": 0.92,
               "live_state": "unknown", "blocklist_listed_at": NOW, "blocklist_expires_at": NOW + timedelta(days=80)}]
    excluded = [{"id": 9, "registered_domain": "nab-x.top", "unicode_domain": None, "brand_id": "nab",
                 "status": "open", "blocklist_excluded_at": NOW, "blocklist_excluded_by": "rev@example.org"}]
    events = [{"at": NOW, "kind": "blocklist_excluded", "detail": {"note": "<i>wait</i>", "by": "rev@example.org"},
               "id": 9, "registered_domain": "nab-x.top"}]
    r = _blocklist_client(monkeypatch, tmp_path, listed, excluded, events).get("/blocklist?msg=failed")
    assert r.status_code == 200
    t = r.text
    assert_clean_page(t)
    assert 'class="flash flash--error" role="alert"' in t and "The build failed" in t
    # why: a reviewer's decision, or the automated rule with its score and AI verdict
    listed_html = section(t, "listed")
    assert "confirmed phishing" in listed_html and "by a reviewer" in listed_html
    assert "score 93" in listed_html and "AI phishing" in listed_html and "92%" in listed_html
    assert "soon, unless still live" in listed_html and "</span>live</span>" in listed_html
    # every POST and its fields; removing asks first (with JS), and there is no publish button
    assert 'action="/blocklist/rebuild"' in t
    assert re.search(r'<form method="post" action="/blocklist/7/exclude" class="ops-exclude">\s*'
                     r'<label class="visually-hidden" for="note-7">', t)
    assert 'name="note" maxlength="500"' in t and 'data-confirm="Remove commbank-login.top from the blocklist?"' in t
    assert 'action="/blocklist/9/include"' in t and "Allow on blocklist again" in t
    assert not re.search(r"<button[^>]*>[^<]*[Pp]ublish", t) and "publish" not in " ".join(re.findall(r'action="([^"]*)"', t))
    assert "scripts/publish-blocklist.sh" in t
    # status of the build and the files
    assert "A rebuild was requested" in t and "serial 2026111601" in t
    assert re.search(r'<div class="n">2</div><div class="l">held back \(CZDS terms\)', t)
    assert 'href="/blocklist/files/hosts.txt" download' in t and 'data-copy-path="/blocklist/files/hosts.txt"' in t
    assert "not built yet" in t                                   # the other files
    # hostile text stays text
    assert XSS not in t and "&lt;script&gt;alert(1)&lt;/script&gt;.top" in t and "<i>wait</i>" not in t
    assert "wait&lt;/i&gt; by rev@example.org" in t


def test_blocklist_page_when_nothing_is_listed(monkeypatch, tmp_path):
    t = _blocklist_client(monkeypatch, tmp_path, []).get("/blocklist").text
    assert_clean_page(t)
    assert "Nothing listed yet." in t and 'href="/review"' in t
    assert 'data-filter-for="listed-rows"' not in t and 'id="excluded"' not in t
    assert "No changes yet." in t and "not built yet" in t


# ---- CZDS -------------------------------------------------------------------------------------------------

def test_zone_state_groups_and_summary():
    assert pages_czds.zone_state("ok") == {"group": "ok", "tone": "teal", "glyph": "●", "label": "ok",
                                           "text": "processed"}
    assert pages_czds.zone_state(None)["group"] == "waiting" and pages_czds.zone_state(None)["label"] == "pending"
    assert pages_czds.zone_state("downloading")["tone"] == "outline"
    assert pages_czds.zone_state("retrying")["group"] == "warning"
    for bad in ("error", "invalid", "terms", "no_access", "low_disk", "revoked", "brand_new_state"):
        assert pages_czds.zone_state(bad)["group"] == "problem" and pages_czds.zone_state(bad)["glyph"] == "■", bad
    # every status the job writes has a description and a group
    assert set(pages_czds.STATE_GROUPS) <= set(pages_czds.STATUS_TEXT)
    summary = pages_czds.zone_summary([{"status": "ok"}, {"status": "baseline"}, {"status": "error"},
                                       {"status": "pending"}])
    assert [(g["group"], g["n"]) for g in summary] == [("problem", 1), ("waiting", 1), ("ok", 2)]
    assert pages_czds.zone_summary([]) == []


def _czds_client(monkeypatch, zones, runs=(), hits=(), has_credentials=True):
    async def fake_fetchall(sql, params=()):
        if "FROM czds_zones" in sql:
            return list(zones)
        if "FROM czds_runs" in sql:
            return list(runs)
        if "FROM domain_events" in sql:
            return list(hits)
        raise AssertionError(sql)

    async def fake_fetchone(sql, params=()):
        if "FROM kv" in sql:
            return {"value": {"ok": True, "duration_s": 3.2, "result": {"zones": 2}}, "updated_at": NOW}
        return {"stored_by_czds": 5, "new_24h": 1, "new_7d": 4, "known_7d": 2}
    cfg = czds.CzdsConfig(username="u@example.org" if has_credentials else "",
                          password="pw-not-shown" if has_credentials else "", tlds=("top", "shop", "au"))
    monkeypatch.setattr(pages_czds, "fetchall", fake_fetchall)
    monkeypatch.setattr(pages_czds, "fetchone", fake_fetchone)
    monkeypatch.setattr(czds, "load_config", lambda s=None: cfg)
    monkeypatch.setattr(czds, "disk_usage", lambda c: 1 << 30)
    return client()


def test_czds_page_zone_states_are_clear(monkeypatch):
    zones = [{**dict.fromkeys(pages_czds.ZONE_KEYS), "tld": "top", "configured": True, "approved": True,
              "status": "ok", "total_names": 1000, "new_names": 10, "hits": 2, "next_due": NOW + 5 * H,
              "last_download": NOW - H},
             {**dict.fromkeys(pages_czds.ZONE_KEYS), "tld": "shop", "configured": True, "approved": True,
              "status": "error", "error": XSS}]
    runs = [{"tld": "shop", "at": NOW, "status": "retrying", "total_names": None, "new_names": None,
             "removed_names": None, "hits": None, "new_hits": None, "file_bytes": None, "duration_s": None,
             "error": "HTTP 503"}]
    t = _czds_client(monkeypatch, zones, runs).get("/czds").text
    assert_clean_page(t)
    assert "pw-not-shown" not in t and "u@example.org" not in t
    zones_html = section(t, "zones")
    assert '<tr class="ops-row--ok">' in zones_html and '<tr class="ops-row--problem">' in zones_html
    assert "1 failing" in zones_html and "1 up to date" in zones_html
    assert "</span>ok</span>" in zones_html and "</span>error</span>" in zones_html and "processed" in zones_html
    assert XSS not in t and "&lt;script&gt;" in t
    assert re.search(r'<time datetime="[^"]+" title="[^"]+ UTC">in [45]h</time>', zones_html)
    assert '<tr class="ops-row--warning">' in section(t, "runs") and "HTTP 503" in t
    assert 'not in CZDS</span> <span class="dom">au</span>' in t
    assert '"zones": 2' in t and "No CZDS hits in the last 30 days." in t
    assert "<form" not in t.split("<main", 1)[1]                    # GET only: no forms on this page


def test_czds_page_without_credentials_shows_setup_steps(monkeypatch):
    t = _czds_client(monkeypatch, [], has_credentials=False).get("/czds").text
    assert_clean_page(t)
    assert "no CZDS credentials" in t and 'id="setup"' in t and "CZDS_PASSWORD" in t


# ---- bot --------------------------------------------------------------------------------------------------

def test_bot_helpers():
    assert pages_bot.verdict_look("confirmed") == ("confirmed", "red", "■")
    assert pages_bot.verdict_look("official")[1:] == ("teal", "✓")
    assert pages_bot.verdict_look("not_a_domain") == ("not a domain", "muted", "○")
    assert pages_bot.verdict_look(None)[0] == "unknown"
    assert pages_bot.chat_look("pending") == ("pending", "amber", "▲")
    chats = [{"chat_id": 1, "effective": "allowed"}, {"chat_id": 2, "effective": "pending"},
             {"chat_id": 3, "effective": "blocked"}, {"chat_id": 4, "effective": "pending"}]
    pending, others = pages_bot.split_chats(chats)
    assert [c["chat_id"] for c in pending] == [2, 4] and [c["chat_id"] for c in others] == [1, 3]


def _bot_client(monkeypatch, chats):
    async def fake_fetchall(sql, params=()):
        if "FROM bot_chats" in sql:
            return [dict(c) for c in chats]
        if "WITH ORDINALITY" in sql:
            return [{"id": 1, "at": NOW, "chat_id": 111, "title": "Ops", "username": None,
                     "host": "https://evil.example/login", "reg": "evil.example", "verdict": "suspicious",
                     "domain_id": None, "tier": None, "domain_status": None, "source": None}]
        return []

    async def fake_fetchone(sql, params=()):
        if "kv" in sql:
            return {"value": {"ok": False, "error": "<b>409 conflict</b>", "username": "CCBot"}, "updated_at": NOW}
        return {"checks_24h": 3, "checks_30d": 9, "domains_30d": 12, "new_30d": 2, "stored_by_bot": 4}
    monkeypatch.setattr(pages_bot, "fetchall", fake_fetchall)
    monkeypatch.setattr(pages_bot, "fetchone", fake_fetchone)
    monkeypatch.setattr(pages_bot, "settings", lambda: SimpleNamespace(
        telegram_allowed_chats=[111, 333], telegram_bot_token="", bot_daily_limit_per_chat=20))
    return client()


def _chat(chat_id, status, title):
    return {"chat_id": chat_id, "chat_type": "private", "title": title, "username": None, "status": status,
            "status_changed_at": None, "status_by": None, "first_seen": NOW, "last_seen": NOW,
            "today_messages": 0, "today_ai": 0, "total_messages": 1, "total_domains": 0, "total_ai": 0}


def test_bot_page_puts_chats_awaiting_approval_first(monkeypatch):
    chats = [_chat(999, "pending", XSS), _chat(111, "pending", "Env group"), _chat(555, "blocked", "Spam")]
    t = _bot_client(monkeypatch, chats).get("/bot").text
    assert_clean_page(t)
    pending = section(t, "pending")
    others = section(t, "chats")
    assert t.index('id="pending"') < t.index('id="chats"') < t.index('id="recent"')
    # 999 waits; 111 is pending in the table but allowed by TELEGRAM_ALLOWED_CHATS, so it is not waiting
    assert 'action="/bot/chat/999/status"' in pending and "/bot/chat/111/" not in pending
    assert 'name="status" value="allowed"' in pending and 'name="status" value="blocked"' in pending
    assert "Allow this chat" in pending and 'data-confirm="Block &lt;script&gt;alert(1)&lt;/script&gt;?"' in pending
    assert re.search(r'<a class="kpi kpi--link kpi--amber" href="#pending">\s*<div class="n">1</div><div class="l">chats waiting', t)
    assert "/bot/chat/111/status" in others and "/bot/chat/555/status" in others and "/bot/chat/333/status" in others
    assert "in TELEGRAM_ALLOWED_CHATS, not seen yet" in others
    # the process: an error, the token, and forwarded hostnames as text, never links
    assert "token not set (TELEGRAM_BOT_TOKEN)" in t and "<b>409 conflict</b>" not in t and "as @CCBot" in t
    assert 'href="https://evil.example' not in t and "https://evil.example/login" in t
    assert XSS not in t


def test_bot_page_with_nothing_waiting(monkeypatch):
    t = _bot_client(monkeypatch, [_chat(5, "allowed", "Sam")]).get("/bot").text
    assert "No chats are waiting." in section(t, "pending") and "ops-pending" not in t
    assert '<div class="kpi"><div class="n">0</div><div class="l">chats waiting for approval' in t


# ---- takedowns --------------------------------------------------------------------------------------------

def test_histogram_and_bucket_sql():
    rows = pages_takedown.histogram({"first_b0": 4, "first_b2": 2, "rep_b1": 1, "rep_b4": 3})
    assert [r["label"] for r in rows] == ["under 6 h", "6 to 24 h", "1 to 3 days", "3 to 7 days", "over 7 days"]
    assert [(r["first"], r["first_w"]) for r in rows] == [(4, 100), (0, 0), (2, 50), (0, 0), (0, 0)]
    assert [(r["rep"], r["rep_w"]) for r in rows] == [(0, 0), (1, 33), (0, 0), (0, 0), (3, 100)]
    assert all(r["first_w"] == 0 and r["rep_w"] == 0 for r in pages_takedown.histogram({}))
    sql = pages_takedown.SUMMARY_SQL
    assert "count(*) FILTER (WHERE h_first >= 0 AND h_first < 6) AS first_b0" in sql
    assert "count(*) FILTER (WHERE h_rep >= 168) AS rep_b4" in sql and "{where}" in sql
    assert pages_takedown.age_tone(None) is None and pages_takedown.age_tone(30) is None
    assert pages_takedown.age_tone(72) == "amber" and pages_takedown.age_tone(200) == "red"


def test_takedown_page(monkeypatch):
    agg = {"total": 3, "down": 2, "up": 1, "live_now": 1, "reported": 2, "med_first": 20.0, "p90_first": 70.0,
           "n_rep": 1, "med_rep": 5.5, "p90_rep": 5.5, "first_b1": 1, "first_b2": 1, "rep_b0": 1}
    seen = []

    async def fake_fetchone(sql, params=()):
        seen.append(sql)
        return dict(agg)

    async def fake_fetchall(sql, params=()):
        if "GROUP BY COALESCE" in sql:
            return [dict(agg, name=XSS, iana_id=1479)]
        if "GROUP BY asn" in sql:
            return [dict(agg, asn=13335, name="CLOUDFLARENET")]
        if "takedown_at IS NULL" in sql:
            return [{"id": 5, "registered_domain": "commbank-login.top", "unicode_domain": None, "hostname": None,
                     "brand_id": "commbank", "registrar": "NameSilo", "asn": 13335, "as_name": "CF",
                     "dns_state": "resolves", "live_state": "live", "first_seen": NOW, "reported_at": None,
                     "last_live_at": NOW, "enriched_at": NOW, "age_h": 200.0, "reported_h": None}]
        if "ORDER BY takedown_at DESC" in sql:
            return []
        raise AssertionError(sql)
    monkeypatch.setattr(pages_takedown, "fetchall", fake_fetchall)
    monkeypatch.setattr(pages_takedown, "fetchone", fake_fetchone)
    t = client().get("/takedown?scope=tracked").text
    assert_clean_page(t)
    assert any("AS first_b0" in s for s in seen)
    assert t.count("flagged domains") == 1
    assert 'value="tracked" selected' in t and 'name="scope"' in t and 'method="get" action="/takedown"' in t
    hist = section(t, "hist")
    assert hist.count('class="hbar-fill"') == 10 and 'width="100" height="8"' in hist
    still = section(t, "still-up")
    assert "</span>live</span>" in still and "tone-red" in still and "8.3 d" in still
    assert 'data-tabs' in t and 'href="#by-registrar"' in t and 'id="by-as"' in t
    assert XSS not in t and "&lt;script&gt;" in t and "No takedowns seen yet." in t
