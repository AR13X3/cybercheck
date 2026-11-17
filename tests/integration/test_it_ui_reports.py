"""The /reports pages' new layout against a real Postgres: the queue grouped by what the reviewer must do, the
detail page's next step and evidence summary, and that every POST still works from the new markup.

The world is seeded exactly as tests/integration/test_it_web.py seeds it (store_hit, the enrich columns, the
fetch job with a stub fetcher, the AI budget) by importing its fixtures and helpers; reports are created and
moved through their states with the dashboard's own POST routes and the report engine's SQL."""
from __future__ import annotations

import re

from test_it_web import (ENV, REVIEWER, _worker_attempt, call, client, confirm, get, one, page_of,  # noqa: F401
                         post, redirect, report_action, reports_of, sql, world)


def _item(t: str, rid: int, end: str = "</details>") -> str:
    """The markup of one queue item (details or table row) on /reports."""
    start = t.index(f'id="r{rid}"')
    return t[start:t.index(end, start)]


def _no_inline_code(t: str) -> None:
    assert "style=" not in t and "<style" not in t
    assert not re.search(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)", t)
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", t)


def test_empty_queue_says_what_to_do(client):
    assert one(client, "SELECT count(*) AS n FROM reports")["n"] == 0
    r = get(client, "/reports")
    t = r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "Nothing waits for you." in t and "No email drafts waiting." in t and "No web forms waiting." in t
    assert 'href="/review">Open the review queue' in t and "No failures." in t
    assert "Mode: " in t and "Rate limit: 0 of 10 sends" in t and "SMTP for approved emails: on, from" in t
    _no_inline_code(t)
    css = get(client, "/static/reports.css")
    js = get(client, "/static/reports.js")
    assert css.headers["content-type"].startswith("text/css") and "javascript" in js.headers["content-type"]


def test_queue_groups_reports_by_the_next_action(world, client):
    confirm(client, "phish", world, "NetBank clone")
    assert redirect(post(client, f"/reports/create/{world['phish']}"), "/reports")["msg"] == "created"
    rep = reports_of(client, world["phish"])
    t = get(client, "/reports").text
    _no_inline_code(t)
    todo = t[t.index('id="todo"'):t.index('id="sending"')]
    # three email drafts, each with channel, domain, recipient, the next step and its age
    for ch in ("registrar_abuse", "hosting_abuse", "brand:commbank"):
        item = _item(todo, rep[ch]["id"])
        assert "commbank-secure.top" in item and "created <time datetime=" in item
        assert "Approve and send" in item                                   # SMTP is configured in ENV
    reg = _item(todo, rep["registrar_abuse"]["id"])
    assert "abuse@namesilo.com" in reg and 'action="/reports/%d/save"' % rep["registrar_abuse"]["id"] in reg
    assert 'formaction="/reports/%d/approve"' % rep["registrar_abuse"]["id"] in reg
    # three web forms, grouped under the domain, with the official link and copy buttons per field
    forms = todo[todo.index('id="forms"'):todo.index('id="failed"')]
    assert forms.count('class="rq-group"') == 1 and "3 forms" in forms
    sw = rep["scamwatch"]["id"]
    item = _item(forms, sw)
    assert "https://forms.scamwatch.gov.au/report-a-scamwebsite/" in item and "File the web form" in item
    assert f'data-copy-target="#f{sw}-1"' in item and 'href="https://login.commbank-secure.top' not in item
    # Netcraft went to the sending tab, not the to-do list
    nc = rep["netcraft"]["id"]
    assert f'id="r{nc}"' not in todo
    assert re.search(rf'<tr id="r{nc}">.*?queued.*?Send now', t, re.S)
    assert re.search(r'<div class="n">3</div>'
                     r'<div class="l">email drafts to approve', t)
    assert re.search(r'<div class="n">1</div><div class="l">queued for sending', t)
    # glass: the queue tiles carry an icon and "/ to do", the hourly rate limit is a gauge ring
    assert re.search(r'<div class="l">email drafts to approve</div><svg class="ico kpi-ico"[^>]*><use href="#i-report"/>'
                     r'</svg><span class="kpi-of">', t)
    assert 'aria-label="Sends in the last hour: 0 of 10 (0%)"' in t


def test_email_detail_next_step_and_evidence(world, client):
    rep = reports_of(client, world["phish"])
    rid = rep["registrar_abuse"]["id"]
    t = get(client, f"/reports/{rid}").text
    _no_inline_code(t)
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "Approve and send" in nxt and f'form="draft-{rid}" formaction="/reports/{rid}/approve"' in nxt
    ev = t[t.index('id="p-evidence-h"'):t.index('id="p-record-h"')]
    assert "AI phishing" in ev and "97%" in ev and "confirmed phishing" in ev and "a password" in ev
    assert '<span class="url">https://login.commbank-secure.top/' in ev
    assert 'href="https://login.commbank-secure.top' not in t           # reported URLs are never links
    page_id = rep["registrar_abuse"]["payload"]["page_id"]
    assert f'src="/screenshot/{page_id}"' in ev and f'href="/reports/{rid}/screenshot.jpg" download' in ev
    assert get(client, f"/screenshot/{page_id}").headers["content-type"] == "image/webp"
    assert "NameSilo, LLC" in ev and "AS-VULTR (US)" in ev
    # the approve button outside the form still posts the form's edited fields
    body = "Edited from the next-step button.\n— CyberCheck"
    assert report_action(client, rid, "approve", {"to": "abuse@namesilo.com", "subject": "Phishing report",
                                                  "body": body}, detail=True) == "queued"
    r = one(client, "SELECT status, payload FROM reports WHERE id = %s", (rid,))
    assert r["status"] == "approved" and r["payload"]["body"] == body
    t = get(client, f"/reports/{rid}?msg=queued").text
    assert 'class="flash flash--ok"' in t and "Queued for sending" in t and "Send now" in t and "Cancel" in t
    # failed by the worker: the next step says why and offers the fix
    call(client, _worker_attempt, rid, "registrar_abuse", "smtp", "failed")
    t = get(client, f"/reports/{rid}").text
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "Fix it and approve again" in nxt and "SMTP 550 5.1.1 mailbox unavailable" in nxt
    assert re.search(rf'<tr id="r{rid}">.*?SMTP 550.*?Retry', get(client, "/reports").text, re.S)


def test_manual_detail_and_mark_done(world, client):
    rep = reports_of(client, world["phish"])
    sw = rep["scamwatch"]["id"]
    t = get(client, f"/reports/{sw}").text
    _no_inline_code(t)
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "File the web form" in nxt and "Mark as done" in nxt and 'name="back" value="detail"' in nxt
    assert 'href="https://forms.scamwatch.gov.au/report-a-scamwebsite/"' in nxt
    fields = t[t.index('class="rq-fields"'):]
    assert 'data-copy-target="#f%d-1"' % sw in fields and "Website URL" in fields
    assert "https://login.commbank-secure.top/" in fields and "Not applicable" in fields
    assert report_action(client, sw, "sent", detail=True) == "done"
    t = get(client, f"/reports/{sw}?msg=done").text
    assert "Marked as done." in t and "Nothing to do" in t and "Mark as done" not in t
    sent = get(client, "/reports").text
    assert re.search(rf'<tr id="r{sw}">.*?by hand.*?awaiting takedown', sent, re.S)


def test_sent_api_report_and_closed_states(world, client):
    rep = reports_of(client, world["phish"])
    nc = rep["netcraft"]["id"]
    resp = {"uuid": "9a8b7c6d5e4f40312a1b0c9d8e7f6a5b", "test": False,
            "status": {"state": "processing", "urls": [{"url": "https://login.commbank-secure.top/",
                                                        "url_takedown_state": "in_progress"}]}}
    call(client, _worker_attempt, nc, "netcraft", "api", "sent", resp)
    t = get(client, "/reports").text
    row = _item(t, nc, "</tr>")
    assert "processing; takedown: in_progress" in row and resp["uuid"] in row and "awaiting takedown" in row
    t = get(client, f"/reports/{nc}").text
    assert "Nothing to do" in t and ">ok<" in t and "Send now" not in t
    # the brand mailbox draft rejected from the queue page: listed under Closed with the reason
    brand = rep["brand:commbank"]["id"]
    assert report_action(client, brand, "reject", {"note": "CBA already knows"}) == "rejected"
    t = get(client, "/reports").text
    closed = t[t.index('id="closed"'):t.index('id="setup"')]
    assert re.search(rf'<tr id="r{brand}">.*?rejected.*?CBA already knows', closed, re.S)
    # a domain reopened after its reports were made: the drafts ask to confirm it first
    confirm(client, "idn", world)
    assert redirect(post(client, f"/reports/create/{world['idn']}"), "/reports")["msg"] == "created"
    idn = reports_of(client, world["idn"])
    redirect(post(client, f"/domain/{world['idn']}/status", {"status": "open"}), f"/domain/{world['idn']}")
    t = get(client, f"/reports/{idn['hosting_abuse']['id']}").text
    nxt = t[t.index('class="rq-next'):t.index('class="grid-aside')]
    assert "Confirm the domain first" in nxt and f'href="/domain/{world["idn"]}"' in nxt
    assert "Approve and send (SMTP)" not in t
    # marked false positive: the next step is to close it
    redirect(post(client, f"/domain/{world['idn']}/status", {"status": "false_positive"}),
             f"/domain/{world['idn']}")
    t = get(client, f"/reports/{idn['hosting_abuse']['id']}").text
    assert "Close this report" in t and f'form="reject-{idn["hosting_abuse"]["id"]}"' in t


def test_every_report_renders_with_the_new_layout(world, client):
    for r in sql(client, "SELECT id FROM reports ORDER BY id"):
        t = get(client, f"/reports/{r['id']}").text
        _no_inline_code(t)
        assert t.count("<h1>") == 1 and 'class="rq-next' in t
        ids = re.findall(r'\sid="([^"]+)"', t)
        assert len(ids) == len(set(ids)), (r["id"], [i for i in ids if ids.count(i) > 1])
    t = get(client, "/reports").text
    assert t.count("<h1>") == 1 and ENV["SMTP_PASSWORD"] not in t
    ids = re.findall(r'\sid="([^"]+)"', t)
    assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]
