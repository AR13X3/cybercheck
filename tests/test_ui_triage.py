"""Triage pages (/review, /review/evidence/<id>, /domain/<id>, /domains): data helpers and rendering. Offline:
no database (the page queries are replaced with canned rows), no sockets."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl

import pytest
from fastapi.testclient import TestClient

from cybercheck import db
from cybercheck.web import app as app_mod
from cybercheck.web import common

LOCAL = "http://127.0.0.1:8430"
NOW = datetime(2026, 11, 16, 14, 30, tzinfo=timezone.utc)
EVIL = '<img src=x onerror=alert(1)>'
TEMPLATES = Path(app_mod.__file__).parent / "templates"
STATIC = Path(app_mod.__file__).parent / "static"


def domain(i=5, host="commbank-secure.top", **kw):
    row = {"id": i, "registered_domain": host, "unicode_domain": None, "tld": "top", "brand_id": "commbank",
           "score": 81, "tier": "high", "reasons": [{"points": 45, "why": "brand keyword"}, {"points": 36, "why": "bait"}],
           "hostnames": ["login." + host, host], "sightings": 2, "source": "ct", "first_seen": NOW,
           "last_seen": NOW, "issuer": "R11", "ct_log": "Oak", "status": "open", "status_changed_at": None,
           "status_by": None, "notes": None, "dns_state": "resolves", "ips": ["45.77.1.10"], "asn": 20473,
           "as_name": "AS-VULTR", "ip_country": "US", "registrar": "NameSilo, LLC", "registrar_abuse_email": None,
           "hosting_abuse_email": None, "rdap_status": [], "registered_at": NOW - timedelta(days=2),
           "enriched_at": NOW, "live_state": "live", "first_live_at": NOW, "last_live_at": NOW, "page_score": 55,
           "ai_verdict": "phishing", "ai_confidence": 0.97, "ai_brand": "commbank", "final_score": 95,
           "final_reasons": [{"points": 60, "why": "domain"}, {"points": 20, "why": "creds"}, {"points": 15, "why": "AI"}],
           "final_score_at": NOW, "reported_at": None, "takedown_at": None, "takedown_signal": None,
           "next_check_at": None, "check_count": 1, "watch_until": None, "blocklisted": False,
           "blocklist_expires_at": None, "blocklist_excluded": False, "blocklist_excluded_by": None,
           "enrich_state": {}, "ai_triage": None}
    row.update(kw)
    return row


def page(i, profile="desktop", **kw):
    row = {"id": i, "domain_id": 5, "fetched_at": NOW - timedelta(minutes=i), "url": "https://login.commbank-secure.top/",
           "final_url": "https://login.commbank-secure.top/", "http_status": 200, "title": "NetBank - Log on",
           "egress_ip": "203.0.113.45", "user_agent_profile": profile, "has_password_field": True,
           "has_otp_field": False, "has_card_field": False, "form_actions": ["https://login.commbank-secure.top/auth.php"],
           "brand_mentions": ["commbank"], "features": {}, "screenshot_path": f"screenshots/{i}.webp", "error": None,
           "is_evidence": False, "retain_until": NOW + timedelta(days=60), "ai_result": None}
    row.update(kw)
    return row


# ---- pure helpers ------------------------------------------------------------------------------------

def test_review_query_cleans_every_filter():
    where, params, f = app_mod.review_query()
    assert where == app_mod.QUEUE_WHERE and params == [] and f == {"tier": "", "brand": "", "live": "", "ai": "",
                                                                     "sort": "priority"}
    where, params, f = app_mod.review_query("high", " commbank\x00 ", "yes", "phishing", "score")
    assert "tier = %s" in where and "brand_id = %s" in where and "live_state = 'live'" in where
    assert "ai_verdict = %s" in where and params == ["high", "commbank", "phishing"] and f["sort"] == "score"
    where, params, f = app_mod.review_query("watch", "", "no", "none", "bogus")     # watch is never in the queue
    assert "tier = %s" not in where and "live_state <> 'live'" in where and "ai_verdict IS NULL" in where
    assert params == [] and f == {"tier": "", "brand": "", "live": "no", "ai": "none", "sort": "priority"}
    _, params, f = app_mod.review_query(ai="'; DROP TABLE domains; --", live="maybe")
    assert params == [] and f["ai"] == "" and f["live"] == ""
    assert app_mod.filters_active(f) is False and app_mod.filters_active({"brand": "anz"}) is True
    # the default order puts high tier first, then the combined score
    assert app_mod.QUEUE_SORTS["priority"].startswith("(tier = 'high') DESC, COALESCE(final_score, score) DESC")
    assert all(s.endswith("id DESC") for s in app_mod.QUEUE_SORTS.values())


def test_page_asks_reads_the_newest_snapshot_per_profile_and_the_ai():
    pages = [page(1, "desktop"), page(2, "mobile", has_password_field=False, has_otp_field=True),
             page(3, "desktop", has_card_field=True)]            # older desktop: ignored
    asks = app_mod.page_asks(pages, {"asks_for": ["passwords", "identity", "none", "bogus"]})
    assert [(a["key"], a["label"], a["form"], a["ai"]) for a in asks] == [
        ("password", "password", True, True), ("otp", "one-time code", True, False),
        ("identity", "identity documents", False, True)]
    assert app_mod.page_asks([page(1, features={"has_identity_field": True}, has_password_field=False)]) == [
        {"key": "identity", "label": "identity documents", "form": True, "ai": False}]
    assert app_mod.page_asks([], None) == [] and app_mod.page_asks([page(1, has_password_field=None)], "x") == []


def test_evidence_picks_screenshots_and_the_ai_explanation():
    pages = [page(1, "mobile", ai_result={"verdict": "error", "explanation": "AI check failed"}),
             page(2, "desktop", ai_result={"verdict": "phishing", "confidence": 0.9}),
             page(3, "desktop", screenshot_path=None)]
    calls = [{"page_id": 99, "result": {"explanation": "other page"}},
             {"page_id": 2, "result": {"explanation": "Copies NetBank", "asks_for": ["otp"]}}]
    ev = app_mod.evidence(domain(), pages, calls)
    assert ev["shot"]["id"] == 2 and ev["shot_mobile"]["id"] == 1 and ev["latest"]["id"] == 1
    assert ev["ai_page"]["id"] == 2 and ev["ai"]["explanation"] == "Copies NetBank"     # not the error verdict
    assert [a["key"] for a in ev["asks"]] == ["password", "otp"]
    assert ev["bl_scope"] is not None and ev["bl_scope"].wildcard and ev["official"] is False
    # only a mobile capture: it is the main shot; no pages at all
    ev = app_mod.evidence(domain(), [page(4, "mobile")])
    assert ev["shot"]["id"] == 4 and ev["shot_mobile"] is None and ev["ai"] is None
    ev = app_mod.evidence(domain(registered_domain="commbank.com.au"), [])
    assert ev["shot"] is None and ev["latest"] is None and ev["asks"] == [] and ev["official"] is True
    # an invalid AI result is not a verdict
    assert app_mod.evidence(domain(), [page(5, ai_result={"verdict": "phishing", "invalid": True})])["ai"] is None


def test_queue_neighbours():
    ids = [7, 3, 9, 1]
    assert app_mod.queue_neighbours(ids, 7) == {"pos": 1, "total": 4, "prev": None, "next": 3}
    assert app_mod.queue_neighbours(ids, 9) == {"pos": 3, "total": 4, "prev": 3, "next": 1}
    assert app_mod.queue_neighbours(ids, 1) == {"pos": 4, "total": 4, "prev": 9, "next": None}
    assert app_mod.queue_neighbours(ids, 42) == {"pos": None, "total": 4, "prev": None, "next": 7}
    assert app_mod.queue_neighbours([], 42) == {"pos": None, "total": 0, "prev": None, "next": None}


def test_domains_sorting_is_whitelisted_and_stable():
    assert app_mod.domains_order() == ("first_seen DESC, id DESC", "seen", "desc")
    assert app_mod.domains_order("seen", "asc") == ("first_seen ASC, id ASC", "seen", "asc")
    sql, key, d = app_mod.domains_order("combined", "")
    assert (key, d) == ("combined", "desc") and sql == "final_score DESC NULLS LAST, first_seen DESC, id DESC"
    assert app_mod.domains_order("host", "")[0].startswith("registered_domain ASC")
    for evil in ("score; DROP TABLE domains", "id", "1"):
        assert app_mod.domains_order(evil, "sideways") == ("first_seen DESC, id DESC", "seen", "desc")


def test_domains_links_keep_the_filters_and_the_sort():
    f = {"q": "auspost-track", "tier": "", "status": "", "brand": ""}
    # the default sort adds nothing (the long-standing link format)
    assert app_mod.domains_query_string(f, 2) == "q=auspost-track&tier=&status=&brand=&page=2"
    qs = dict(parse_qsl(app_mod.domains_query_string(f, 3, "combined", "asc"), keep_blank_values=True))
    assert qs == {"q": "auspost-track", "tier": "", "status": "", "brand": "", "page": "3", "sort": "combined",
                  "dir": "asc"}
    links = app_mod.sort_links(f, "score", "desc")
    assert links["score"]["aria"] == "descending" and links["score"]["next_dir"] == "asc"
    assert "sort=score&dir=asc" in links["score"]["href"] and "page=1" in links["score"]["href"]
    assert links["host"]["aria"] is None and "sort=host&dir=asc" in links["host"]["href"]
    assert links["seen"]["href"] == "?q=auspost-track&tier=&status=&brand=&page=1"
    assert "q=a%26b%3D" in app_mod.domains_query_string({"q": "a&b="}, 1)          # values are encoded


# ---- templates ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["review.html", "domain.html", "domains.html", "_row.html"])
def test_triage_templates_have_no_inline_script_style_or_handlers(name):
    src = re.sub(r"\{#.*?#\}", "", (TEMPLATES / name).read_text(encoding="utf-8"), flags=re.S)
    assert "style=" not in src and "<style" not in src
    assert not re.search(r"<script(?![^>]*\bsrc=)", src)
    assert not re.search(r"\son[a-z]+\s*=", src)
    assert "|safe" not in src.replace(" ", "") and "Markup" not in src


def test_triage_static_files():
    js = (STATIC / "triage.js").read_text(encoding="utf-8")
    assert ".innerHTML" not in js and "outerHTML" not in js and "eval(" not in js and "http://" not in js and "https://" not in js
    assert "redirect: 'manual'" in js and "DOMParser" in js and "sanitize(" in js
    css = (STATIC / "triage.css").read_text(encoding="utf-8")
    assert "@import" not in css and "url(" not in css and "prefers-reduced-motion" in css
    r = TestClient(app_mod.app, base_url=LOCAL).get("/static/triage.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]


def test_evidence_pane_escapes_attacker_text_and_never_links_urls():
    d = domain(registered_domain="x" + EVIL + ".top", unicode_domain=EVIL, hostnames=[EVIL + ".top"],
               brand_id=EVIL, ai_triage={"assessment": EVIL, "likely_target": EVIL})
    p = page(1, final_url="https://evil.example/" + EVIL, title=EVIL,
             ai_result={"verdict": "phishing", "confidence": 0.9, "explanation": EVIL, "asks_for": ["otp"]})
    html = app_mod._EVIDENCE_PANE.render(ev=app_mod.evidence(d, [p]), statuses=app_mod.STATUSES)
    assert EVIL not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert 'href="https://' not in html and 'href="http://' not in html and "evil.example" in html
    assert re.search(r'<a [^>]*href="/screenshot/1"[^>]*data-lightbox', html)
    # the decision form: same action and field names as the domain page, Enter cannot decide
    form = html[html.index('<form method="post" action="/domain/5/status"'):]
    first = form[form.index("<button"):form.index(">", form.index("<button")) + 1]
    assert "disabled" in first and 'name="status"' not in first
    assert form.index('name="note"') < form.index('name="status"')
    for value, label in (("confirmed", "Confirm phishing"), ("false_positive", "Mark false positive"),
                         ("benign", "Mark benign / parked")):
        assert re.search(rf'name="status" value="{value}"[^>]*>{re.escape(label)}', form), value
    assert 'value="open"' not in form                     # open: nothing to reopen
    m = re.search(r'value="confirmed"[^>]*data-confirm="([^"]*)"[^>]*data-confirm-detail="([^"]*)"', form, re.S)
    assert m and "as phishing?" in m.group(1) and "report drafts" in m.group(2)


def test_official_domain_cannot_be_confirmed_from_the_pane():
    ev = app_mod.evidence(domain(registered_domain="commbank.com.au", hostnames=["netbank.commbank.com.au"]), [])
    html = app_mod._EVIDENCE_PANE.render(ev=ev, statuses=app_mod.STATUSES)
    assert re.search(r'value="confirmed" disabled aria-describedby="ev-official-5">Confirm phishing', html)
    assert "official brand domain or on the allowlist" in html and "data-confirm=" not in html
    # a decided domain offers Reopen and says who decided
    ev = app_mod.evidence(domain(status="false_positive", status_by="alex@example.org", status_changed_at=NOW), [])
    html = app_mod._EVIDENCE_PANE.render(ev=ev, statuses=app_mod.STATUSES)
    assert 'value="open" data-decide="open">Reopen' in html and "Marked false positive by alex@example.org" in html
    assert re.search(r'value="false_positive" data-decide="false_positive" disabled', html)


# ---- routes with canned rows -------------------------------------------------------------------------

class _Cur:
    async def fetchone(self):
        return None

    async def fetchall(self):
        return []


class _Conn:
    async def execute(self, sql, params=()):
        return _Cur()


@pytest.fixture
def canned(monkeypatch):
    """The page queries answer from `data`; the status line gets an empty database (never a real one)."""
    @asynccontextmanager
    async def connection():
        yield _Conn()

    class Pool:
        pass
    pool = Pool()
    pool.connection = connection

    async def get_pool():
        return pool
    monkeypatch.setattr(db, "pool", get_pool)
    common.reset_status_cache()
    data = {"queue": [], "counts": {"n": 0, "high": 0}, "domain": None, "pages": [], "calls": [], "brands": []}
    seen: list[tuple[str, tuple]] = []

    async def fetchall(sql, params=()):
        s = " ".join(sql.split())
        seen.append((s, tuple(params)))
        if s.startswith("SELECT id, registered_domain"):
            return data["queue"]
        if s.startswith("SELECT * FROM pages"):
            return data["pages"]
        if s.startswith("SELECT page_id, result FROM ai_calls"):
            return data["calls"]
        if s.startswith("SELECT brand_id"):
            return data["brands"]
        if s.startswith("SELECT id FROM domains"):
            return [{"id": r["id"]} for r in data["queue"]]
        return []

    async def fetchone(sql, params=()):
        s = " ".join(sql.split())
        seen.append((s, tuple(params)))
        if s.startswith("SELECT count(*) AS n, count(*) FILTER"):
            return data["counts"]
        if s.startswith("SELECT * FROM domains WHERE id"):
            return data["domain"] if data["domain"] and data["domain"]["id"] == params[0] else None
        return None
    monkeypatch.setattr(app_mod, "fetchall", fetchall)
    monkeypatch.setattr(app_mod, "fetchone", fetchone)
    data["seen"] = seen
    yield data
    common.reset_status_cache()


def test_review_page_empty(canned):
    r = TestClient(app_mod.app, base_url=LOCAL).get("/review")
    assert r.status_code == 200 and r.headers["content-security-policy"] == app_mod.CSP
    assert "Nothing here." in r.text and "Nothing waits for a decision." in r.text
    assert re.search(r'<link rel="stylesheet" href="/static/triage\.css\?v=\w+">', r.text)
    assert re.search(r'<script src="/static/triage\.js\?v=\w+" defer></script>', r.text)
    assert 'data-page="review"' in r.text and r.text.count("<h1") == 1
    r = TestClient(app_mod.app, base_url=LOCAL).get("/review?tier=high&ai=none")
    assert "No open domain matches these filters" in r.text and 'href="/review">Show the whole queue' in r.text


def test_review_page_with_a_queue(canned):
    q = [domain(5), domain(6, "anz-update.info", tier="review", final_score=None, ai_verdict=None, live_state="down",
                            unicode_domain=EVIL)]
    canned.update(queue=q, counts={"n": 2, "high": 1}, domain=q[0], brands=[{"brand_id": "commbank", "n": 2}],
                  pages=[page(1, ai_result={"verdict": "phishing", "confidence": 0.97, "explanation": "Copies NetBank"})])
    c = TestClient(app_mod.app, base_url=LOCAL)
    r = c.get("/review?brand=commbank&live=yes&sort=score")
    t = r.text
    assert r.status_code == 200 and EVIL not in t
    assert [int(x) for x in re.findall(r'<tr data-id="(\d+)">', t)] == [5, 6]
    assert "2 domains wait for a decision, 1 high tier (filtered)." in t
    assert 'aria-current="true">login.commbank-secure.top</a>' in t                       # the first is selected
    assert 'data-select="?brand=commbank&amp;live=yes&amp;sort=score&amp;id=6"' in t
    assert 'id="evidence" data-domain-id="5"' in t and "Copies NetBank" in t and "one-time code" not in t
    assert 'value="commbank" selected' in t and 'value="yes" selected' in t and 'value="score" selected' in t
    queue_sql, params = next((s, p) for s, p in canned["seen"] if s.startswith("SELECT id, registered_domain"))
    assert "brand_id = %s" in queue_sql and "live_state = 'live'" in queue_sql and params == ("commbank",)
    assert queue_sql.endswith("ORDER BY " + app_mod.QUEUE_SORTS["score"] + " LIMIT 300")
    # ?id= selects a domain that exists; one that does not says so
    canned["domain"] = q[1]
    assert 'id="evidence" data-domain-id="6"' in c.get("/review?id=6").text
    assert "That domain was not found." in c.get("/review?id=999").text
    assert c.get("/review?id=abc").status_code == 422
    assert c.get("/review?id=99999999999999999999").status_code in (200, 422)


def test_review_evidence_fragment(canned):
    c = TestClient(app_mod.app, base_url=LOCAL)
    assert c.get("/review/evidence/5").status_code == 404
    assert c.get("/review/evidence/0").status_code == 404
    assert c.get("/review/evidence/x").status_code == 422
    canned["domain"] = domain(5)
    r = c.get("/review/evidence/5")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.headers["content-security-policy"] == app_mod.CSP
    assert r.text.lstrip().startswith('<section class="evidence" id="evidence"') and "<html" not in r.text
    assert 'action="/domain/5/status"' in r.text


def test_domain_page_layout(canned):
    q = [domain(4, "anz-update.info"), domain(5), domain(6, "nab-login.top")]
    canned.update(queue=q, domain=q[1], pages=[page(1)])
    t = TestClient(app_mod.app, base_url=LOCAL).get("/domain/5").text
    assert "(2 of 3)" in t and 'href="/domain/4" data-shortcut="["' in t and 'href="/domain/6" data-shortcut="]"' in t
    assert 'class="verdict verdict--red"' in t and "Strong evidence of phishing" in t
    assert 'class="decision decision-bar"' in t and "Which decision fits?" in t
    assert t.index('class="verdict ') < t.index("decision-bar") < t.index("Latest screenshot") < t.index("Details")
    assert "asks for password" in t and 'class="timeline"' in t and "No events yet." in t
    assert 'data-page="domain"' in t and t.count("<h1") == 1


def test_domains_page_sort_headers(canned):
    c = TestClient(app_mod.app, base_url=LOCAL)
    t = c.get("/domains?sort=combined&dir=asc&q=x").text
    assert 'aria-sort="ascending"><a class="sort is-sorted" href="?q=x&amp;tier=&amp;status=&amp;brand=&amp;page=1&amp;sort=combined&amp;dir=desc"' in t
    assert '<input type="hidden" name="sort" value="combined"><input type="hidden" name="dir" value="asc">' in t
    assert "Nothing here." in t and "No domain matches." in t


# ---- glass layout --------------------------------------------------------------------------------------

def test_review_page_glass_pieces(canned):
    """Head stats with "/ total", filter pills (same field names and ids), score rings and glass decision pills."""
    q = [domain(5), domain(6, "anz-update.info", tier="review", final_score=None, score=64, ai_verdict=None)]
    canned.update(queue=q, counts={"n": 2, "high": 1, "live": 1, "ai_phish": 1}, domain=q[0],
                  brands=[{"brand_id": "commbank", "n": 2}], pages=[page(1)])
    t = TestClient(app_mod.app, base_url=LOCAL).get("/review?brand=nab").text
    assert re.search(r'<span class="stat-l">Live pages</span><span class="stat-n"><span class="stat-val">1</span>'
                     r'<span class="of"> / 2</span>', t)
    # filters are pills in one GET form to /review; a brand that is no longer queued stays selectable
    form = t[t.index('class="filterbar triage-filters"'):t.index("</form>", t.index('class="filterbar triage-filters"'))]
    for fid, name in (("qf-tier", "tier"), ("qf-brand", "brand"), ("qf-live", "live"), ("qf-ai", "ai"), ("qf-sort", "sort")):
        assert f'<label class="fpill-l" for="{fid}">' in form and f'id="{fid}" name="{name}"' in form
    assert '<option value="nab" selected>nab (0)</option>' in form and 'href="/review">Clear' in form
    # queue rows carry a score ring (tier colour, combined score when there is one)
    assert t.count('class="ring ring--red"') >= 2 and '<span class="ring-n">95</span>' in t
    assert 'class="ring ring--amber" title="Domain-name score"' in t and '<span class="ring-n">64</span>' in t
    # the evidence pane: verdict as a glass badge with its icon, score as a gauge, exact spelling in monospace
    pane = t[t.index('<section class="evidence" id="evidence"'):]
    assert 'class="badge badge--red badge--lg ai-badge" role="img" aria-label="AI verdict: phishing"' in pane
    assert '<use href="#i-danger"/>' in pane and 'class="gauge gauge--sm"' in pane
    assert 'aria-label="domain + page + AI: 95 of 100 (95%)"' in pane
    assert '<span class="dom dom--exact">commbank-secure.top</span>' in pane
    assert 'class="btn btn--danger btn--confirm" name="status" value="confirmed"' in pane
    assert 'class="btn btn--fp" name="status" value="false_positive"' in pane
    assert 'class="btn btn--benign" name="status" value="benign"' in pane


def test_domain_page_verdict_gauge_and_lifecycle(canned):
    d = domain(5, status="confirmed", status_by="alex@example.org", status_changed_at=NOW, reported_at=NOW,
               takedown_at=None, first_live_at=NOW - timedelta(hours=1))
    canned.update(queue=[], domain=d, pages=[page(1, ai_result={"verdict": "phishing", "confidence": 0.97})])
    t = TestClient(app_mod.app, base_url=LOCAL).get("/domain/5").text
    v = t[t.index('<section class="verdict verdict--red"'):t.index('class="decision decision-bar"')]
    assert 'aria-label="Combined score: 95 of 100 (95%)"' in v and 'aria-label="Confirmed phishing"' in v
    assert '<h2 class="verdict-line" id="verdict-h">Confirmed phishing</h2>' in v
    life = v[v.index('<ol class="life"'):v.index("</ol>")]
    steps = re.findall(r'<li class="life-step([^"]*)">.*?<span class="life-l">([^<]+)</span>', life)
    assert [s[1] for s in steps] == ["Seen in CT", "Page fetched", "Page live", "AI judged", "Confirmed", "Reported",
                                     "Taken down"]
    assert [("is-done" in s[0]) for s in steps] == [True, True, True, True, True, True, False]
    assert "life-step--red" in steps[2][0] and "life-step--violet" in steps[3][0]
    assert life.count("<time ") == 6 and "not yet" in life
    # a false positive lights the decision green; the official-domain note keeps its icon and words
    canned["domain"] = domain(5, registered_domain="commbank.com.au", status="false_positive", status_changed_at=NOW)
    t = TestClient(app_mod.app, base_url=LOCAL).get("/domain/5").text
    assert 'class="verdict verdict--teal"' in t and "life-step--green" in t and "False positive</span>" in t
    assert 'class="btn btn--reopen" name="status" value="open"' in t
    assert re.search(r'value="confirmed" disabled aria-describedby="official-note"', t)


def test_domains_decision_tiles_switch_the_status_filter(canned, monkeypatch):
    seen = []
    orig = app_mod.fetchall

    async def fetchall(sql, params=()):
        s = " ".join(sql.split())
        if s.startswith("SELECT status, count(*) AS n FROM domains"):
            seen.append((s, tuple(params)))
            return [{"status": "open", "n": 1200}, {"status": "confirmed", "n": 31}, {"status": "benign", "n": 4}]
        return await orig(sql, params)
    monkeypatch.setattr(app_mod, "fetchall", fetchall)
    c = TestClient(app_mod.app, base_url=LOCAL)
    t = c.get("/domains?q=nab&status=confirmed&sort=score&dir=asc").text
    # counted under the other filters, never the status one
    assert seen and "status = %s" not in seen[0][0] and "ILIKE" in seen[0][0] and "confirmed" not in seen[0][1]
    tiles = t[t.index('<nav class="dom-tiles"'):t.index("</nav>", t.index('<nav class="dom-tiles"'))]
    assert re.search(r'<span class="tile-val">1.2k</span><span class="of"> / 1.2k</span>', tiles)
    assert '<div class="dom-tile is-active"><a class="tile tile--red" href="?q=nab&amp;tier=&amp;status=&amp;brand=' \
           '&amp;page=1&amp;sort=score&amp;dir=asc">' in tiles                       # the active tile clears it
    assert 'href="?q=nab&amp;tier=&amp;status=benign&amp;brand=&amp;page=1&amp;sort=score&amp;dir=asc"' in tiles
    assert '<span class="tile-val">0</span>' in tiles                               # false positive: none
    # filters: a search pill and filter pills in the same GET form (field names and ids kept)
    form = t[t.index('class="filterbar domains-filters"'):]
    form = form[:form.index("</form>")]
    assert 'id="df-q" name="q" value="nab"' in form and 'data-search' in form
    for fid, name in (("df-tier", "tier"), ("df-status", "status"), ("df-brand", "brand")):
        assert f'id="{fid}" name="{name}"' in form
    assert '<option value="confirmed" selected>' in form
