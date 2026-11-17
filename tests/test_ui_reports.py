"""The /reports pages' presentation layer (cybercheck/web/pages_reports.py helpers, reports_* templates,
static/reports.css and reports.js). Network and database are mocked: the dashboard fixtures come from
tests/test_reporting.py (FakeDB). The routes' business rules are tested there, not here."""
from __future__ import annotations

import re
from datetime import timedelta
from types import SimpleNamespace

import pytest

from cybercheck.web import pages_reports as w
from test_reporting import (NOW, ROOT, SMTP_ENV, cfg, fake, fake_smtp, offline, rid, run, web)  # noqa: F401

TEMPLATES = ROOT / "cybercheck" / "web" / "templates"
STATIC = ROOT / "cybercheck" / "web" / "static"
REPORT_TEMPLATES = ("reports_index.html", "reports_detail.html", "reports_macros.html")


def row(**kw) -> dict:
    """A view() row as the templates get it."""
    r = {"id": 5, "domain_id": 1, "channel": "registrar_abuse", "kind": "email", "status": "pending_review",
         "auto": False, "registered_domain": "commbank-login.top", "domain_status": "confirmed",
         "payload": {"to": "abuse@registrar.example", "subject": "S", "body": "B"}, "error": None,
         "takedown_at": None, "next_attempt_at": None, "attempts": 0}
    r.update(kw)
    return w.view(r)


SMTP = SimpleNamespace(smtp=object(), mode="review")
NO_SMTP = SimpleNamespace(smtp=None, mode="review")
OFF = SimpleNamespace(smtp=object(), mode="off")


# ---- next_step ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kw, conf, action, tone, title", [
    ({}, SMTP, "approve", "amber", "Approve and send"),
    ({}, NO_SMTP, "mailto", "amber", "Send it from your mail client"),
    ({}, OFF, "mailto", "amber", "Send it from your mail client"),
    ({"payload": {"to": "", "subject": "S", "body": "B"}}, SMTP, "save", "amber", "Add the abuse address"),
    ({"payload": {"to": "abuse@commbank-login.top", "subject": "S", "body": "B"}}, SMTP, "save", "amber",
     "Add the abuse address"),                                         # on the reported domain: withheld
    ({"status": "failed", "error": "SMTP 550"}, SMTP, "approve", "red", "Fix it and approve again"),
    ({"domain_status": "open"}, SMTP, "domain", "amber", "Confirm the domain first"),
    ({"domain_status": "false_positive"}, SMTP, "reject", "muted", "Close this report"),
    ({"domain_status": "benign", "kind": "manual", "channel": "scamwatch"}, SMTP, "reject", "muted",
     "Close this report"),
    ({"kind": "manual", "channel": "scamwatch", "payload": {"fields": []}}, SMTP, "done", "amber",
     "File the web form"),
    ({"kind": "api", "channel": "netcraft", "status": "failed", "error": "HTTP 500"}, SMTP, "retry", "red",
     "Sending failed"),
    ({"kind": "api", "channel": "netcraft", "status": "failed", "domain_status": "open"}, SMTP, "domain", "amber",
     "Confirm the domain first"),
    ({"kind": "api", "channel": "netcraft", "status": "skipped", "error": "test"}, SMTP, "retry", "amber",
     "Skipped"),
    ({"kind": "manual", "channel": "scamwatch", "status": "skipped", "payload": {}}, SMTP, None, "muted",
     "Skipped"),
    ({"status": "approved"}, SMTP, None, "teal", "Queued for sending"),
    ({"status": "sending"}, SMTP, None, "teal", "Sending now"),
    ({"status": "sent"}, SMTP, None, "teal", "Sent"),
    ({"status": "sent", "takedown_at": NOW}, SMTP, None, "teal", "Taken down"),
    ({"status": "rejected"}, SMTP, None, "muted", "Rejected"),
])
def test_next_step(kw, conf, action, tone, title):
    s = w.next_step(row(**kw), conf)
    assert (s["action"], s["tone"], s["title"]) == (action, tone, title)
    assert s["glyph"] in "●▲■○" and s["text"].endswith(".")


def test_next_step_text_says_why():
    assert "SMTP 550" in w.next_step(row(status="failed", error="SMTP 550\nmailbox"), SMTP)["text"]
    assert "\n" not in w.next_step(row(status="failed", error="SMTP 550\nmailbox"), SMTP)["text"]
    assert "Reporting is off" in w.next_step(row(), OFF)["text"]
    assert "SMTP is not configured" in w.next_step(row(), NO_SMTP)["text"]
    assert "false positive" in w.next_step(row(domain_status="false_positive"), SMTP)["text"]


# ---- evidence_view ------------------------------------------------------------------------------------------

def test_evidence_from_email_facts():
    facts = {"urls": [f"https://x{i}.commbank-login.top/" for i in range(7)], "asks_for": ["a password"],
             "registrar": "Example\nRegistrar", "as_name": "EXAMPLE-HOST", "ip_country": "NL",
             "ips": ["203.0.113.7"], "page_seen": "2026-11-16 03:04 UTC", "page_profile": "mobile",
             "egress_country": "AU", "brand": "Commonwealth Bank", "form_posts_elsewhere": True, "screenshot": True}
    r = row(payload={"to": "a@b.example", "facts": facts, "page_id": 10, "attach_screenshot": True})
    ev = w.evidence_view(r)
    assert ev["urls"] == facts["urls"][:5] and ev["more_urls"] == 2
    assert ev["asks_for"] == ["a password"] and ev["form_posts_elsewhere"] is True
    assert ev["registrar"] == "Example Registrar" and ev["hosting"] == "EXAMPLE-HOST (NL)"
    assert ev["page_id"] == 10 and ev["egress_country"] == "AU" and ev["brand"] == "Commonwealth Bank"


def test_evidence_from_api_and_manual_payloads():
    api = row(kind="api", channel="netcraft", payload={"urls": ["https://a.top/", 7, None], "brand": "CommBank"})
    ev = w.evidence_view(api)
    assert ev["urls"] == ["https://a.top/"] and ev["brand"] == "CommBank" and ev["page_id"] is None
    manual = row(kind="manual", channel="microsoft_smartscreen", payload={"page_id": "10", "screenshot": True, "fields": [
        {"label": "URLs (one per line)", "value": "https://a.top/\n\nhttps://b.top/x"},
        {"label": "Threat type", "value": "Phishing"}]})
    ev = w.evidence_view(manual)
    assert ev["urls"] == ["https://a.top/", "https://b.top/x"] and ev["page_id"] is None   # page_id not an int
    bare = w.evidence_view(row(payload={}, as_name=None, ip_country=None, registrar=None))
    assert bare["urls"] == [] and bare["hosting"] == "" and bare["registrar"] == ""


def test_until_text_and_counts():
    assert w.until_text(None) == "now" and w.until_text(NOW - timedelta(minutes=5), NOW) == "now"
    assert w.until_text(NOW + timedelta(seconds=30), NOW) == "in 30s"
    assert w.until_text(NOW + timedelta(minutes=5), NOW) == "in 5m"
    assert w.until_text(NOW + timedelta(hours=3), NOW) == "in 3h"
    assert w.until_text(NOW.replace(tzinfo=None) + timedelta(days=2), NOW) == "in 2d"
    n = w.queue_counts({"drafts": 2, "manual": 3, "failed": 1, "queued": None}, {"closed": [{}, {}]}, [{}])
    assert n["todo"] == 7 and n["queued"] == 0 and n["closed"] == 2 and n["unreported"] == 1


def test_every_message_has_a_tone():
    assert set(w.MESSAGES) == set(w.MESSAGE_TONES)
    assert set(w.MESSAGE_TONES.values()) <= {"ok", "info", "warn", "error"}


# ---- templates and static files -------------------------------------------------------------------------

def test_report_templates_follow_the_csp_rules():
    for name in REPORT_TEMPLATES:
        src = re.sub(r"\{#.*?#\}", "", (TEMPLATES / name).read_text(encoding="utf-8"), flags=re.S)
        assert "style=" not in src and "<style" not in src, name
        assert not re.search(r"<script(?![^>]*\bsrc=)", src), name          # page script is a file
        assert not re.search(r"\son[a-z]+\s*=", src), name
        assert not re.search(r"\|\s*safe\b", src) and "Markup" not in src and "autoescape false" not in src, name


def test_static_files_use_no_unsafe_dom_apis():
    js = re.sub(r"/\*.*?\*/", "", (STATIC / "reports.js").read_text(encoding="utf-8"), flags=re.S)
    assert "innerHTML" not in js and "eval(" not in js and "document.write" not in js and "http" not in js
    css = (STATIC / "reports.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css and "box-shadow: 0" not in css


# ---- rendered pages (FakeDB) --------------------------------------------------------------------------

def test_index_groups_the_queue_by_what_to_do(web):
    f = web.db
    t = web.get("/reports").text
    assert 'href="/static/reports.css?v=' in t and 'src="/static/reports.js?v=' in t
    for tab in ("#todo", "#sending", "#done", "#closed", "#setup"):
        assert f'href="{tab}"' in t
    assert t.index('id="drafts"') < t.index('id="forms"') < t.index('id="failed"') < t.index('id="queued"')
    reg = rid(f, "registrar_abuse")
    item = t[t.index(f'id="r{reg}"'):]
    item = item[:item.index("</details>")]
    assert "Registrar abuse" in item and "abuse@registrar.example" in item and "created <time" in item
    assert "Send it from your mail client" in item                         # no SMTP in this config
    assert 'class="btn btn--primary" href="mailto:abuse@registrar.example?subject=' in item
    assert 'formaction="/reports/%d/sent"' % reg in item and "Reject draft" in item
    # Enter in a field never approves or marks anything
    assert re.search(r'<form method="post" action="/reports/%d/save"[^>]*>\s*<button type="submit" disabled hidden'
                     % reg, item)
    sw = rid(f, "scamwatch")
    item = t[t.index(f'id="r{sw}"'):]
    item = item[:item.index("</details>")]
    assert 'href="https://forms.scamwatch.gov.au/report-a-scamwebsite/" target="_blank" rel="noopener noreferrer"' in item
    assert f'data-copy-target="#f{sw}-1"' in item and f'data-copy-target="#f{sw}-2"' in item
    assert f'data-rq-copy-all="r{sw}"' in item and "File the web form" in item and "Mark as done" in item
    # KPI tiles keep the n / l structure and link to their section
    assert re.search(r'href="#drafts">\s*<div class="n">3</div>'
                     r'<div class="l">email drafts to approve', t)
    assert "SMTP for approved emails: off (" in t and "Rate limit: 0 of 10 sends" in t


def test_index_with_smtp_offers_approve_first(web):
    web.state.cfg = cfg(SMTP_ENV, data_dir=web.state.cfg.data_dir)
    f = web.db
    t = web.get("/reports").text
    reg = rid(f, "registrar_abuse")
    item = t[t.index(f'id="r{reg}"'):]
    item = item[:item.index("</details>")]
    assert re.search(r'<button type="submit" class="btn btn--primary"\s+formaction="/reports/%d/approve"' % reg, item)
    assert 'data-confirm="Queue this email for sending?"' in item
    assert item.index("Approve and send (SMTP)") < item.index("Open in my mail client") < item.index("Save draft")


def test_index_empty_states(fake, monkeypatch, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from cybercheck.web.common import templates
    fake()
    monkeypatch.setattr(w, "load_config", lambda: cfg(data_dir=tmp_path))
    app = FastAPI()
    w.register(app, templates, [])
    t = TestClient(app, base_url="http://127.0.0.1:8430").get("/reports").text
    assert "Nothing waits for you." in t and "No email drafts waiting." in t and "No web forms waiting." in t
    assert 'href="/review">Open the review queue' in t and "No failures." in t and "Nothing sent yet." in t
    assert "Confirmed, not reported yet" not in t


def test_detail_shows_the_next_step_as_the_primary_button(web):
    web.state.cfg = cfg(SMTP_ENV, data_dir=web.state.cfg.data_dir)
    f = web.db
    reg = rid(f, "registrar_abuse")
    t = web.get(f"/reports/{reg}").text
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "Approve and send" in nxt and f'form="draft-{reg}" formaction="/reports/{reg}/approve"' in nxt
    assert 'data-shortcut="a"' in nxt
    # the form keeps its fields and the secondary actions, but not a second approve button
    form = t[t.index(f'id="draft-{reg}"'):]
    form = form[:form.index("</form>")]
    for name in ('name="to"', 'name="subject"', 'name="body"', 'name="back" value="detail"', "Save draft",
                 "Mark as sent", "Open in my mail client"):
        assert name in form, name
    assert "/approve" not in form
    # the disabled default button comes before the next-step button, so Enter in a field does nothing
    assert t.index(f'form="draft-{reg}" disabled hidden') < t.index('class="rq-next')
    assert "Evidence" in t and "Record" in t and "Attempts" in t and "Stored data" in t


def test_detail_manual_and_api_reports(web):
    f = web.db
    sw = rid(f, "scamwatch")
    t = web.get(f"/reports/{sw}").text
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "Mark as done" in nxt and 'action="/reports/%d/sent"' % sw in nxt and "Open the official form" in nxt
    assert 'name="back" value="detail"' in nxt
    body = t[t.index('class="grid-aside'):]
    assert "Mark as done" not in body.split("Evidence")[0]            # once, in the next-step box
    assert "Not applicable" in body and f'data-copy-target="#f{sw}-1"' in body
    assert 'src="/screenshot/10"' in body and f'href="/reports/{sw}/screenshot.jpg" download' in body
    nc = rid(f, "netcraft")
    t = web.get(f"/reports/{nc}").text
    assert "Queued for sending" in t and "Send now" in t and "Cancel" in t
    f.reports[nc].update(status="sent", sent_at=NOW, sent_via="api", external_id="uuid-1")
    t = web.get(f"/reports/{nc}").text
    assert "Nothing to do" in t and "uuid-1" in t and "Send now" not in t


def test_detail_escapes_page_derived_text(web):
    f = web.db
    sw = rid(f, "scamwatch")
    f.reports[sw]["payload"]["fields"][0]["value"] = 'https://x.top/"><img src=x onerror=alert(1)>'
    f.reports[sw]["error"] = "<b>boom</b>"
    t = web.get(f"/reports/{sw}").text
    assert "<img src=x" not in t and "&lt;img src=x onerror=alert(1)&gt;" in t
    assert "<b>boom</b>" not in t
    assert 'href="https://x.top' not in t                               # reported URLs are text, never links


def test_flash_tone(web):
    assert 'class="flash flash--error"' in web.get("/reports?msg=bad_to").text
    assert 'class="flash flash--ok"' in web.get("/reports?msg=created").text
    assert 'class="flash flash--' not in web.get("/reports?msg=nope").text


def test_glass_pieces_on_the_queue_and_the_detail_page(web):
    f = web.db
    t = web.get("/reports").text
    # the shared tiles (ops.css, loaded before reports.css) and the rate-limit gauge
    assert t.index('href="/static/ops.css?v=') < t.index('href="/static/reports.css?v=')
    assert '<div class="kpis ops-tiles" role="group" aria-label="Report queue in numbers">' in t
    assert re.search(r'<div class="l">failed</div><svg class="ico kpi-ico"[^>]*><use href="#i-danger"/></svg>', t)
    assert 'aria-label="Sends in the last hour: 0 of 10 (0%)"' in t and "Rate limit: 0 of 10 sends" in t
    # queue items: a round icon, the next step with its tone's icon, rounded copy buttons with an icon
    reg = rid(f, "registrar_abuse")
    item = t[t.index(f'id="r{reg}"'):]
    item = item[:item.index("</details>")]
    assert '<span class="rq-sum-ico" aria-hidden="true"><svg class="ico"' in item
    assert re.search(r'<span class="rq-hint rq-hint--amber"><svg class="ico rq-hint-ico"[^>]*><use href="#i-alert"/>', item)
    assert re.search(r'<button type="button" class="btn btn--sm js-only rq-copy" hidden data-copy-target="#bo%d" '
                     r'aria-label="Copy the body"><svg class="ico"[^>]*><use href="#i-copy"/></svg>'
                     r'<span class="rq-copy-text">Copy body</span></button>' % reg, item)
    # the detail page's next step has a round badge with the tone's icon instead of a text glyph
    d = web.get(f"/reports/{reg}").text
    nxt = d[d.index('class="rq-next'):d.index('class="grid-aside')]
    assert re.search(r'<span class="rq-next-badge" aria-hidden="true"><svg class="ico"[^>]*><use href="#i-alert"/>', nxt)
    assert "rq-next-glyph" not in nxt
