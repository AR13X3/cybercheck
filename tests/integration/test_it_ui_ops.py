"""Integration: the operations pages on the new UI (AI, blocklist, CZDS, bot, takedowns) rendered against a real
Postgres. Seeds through store_hit and the pipeline helpers of test_it_web.py (imported, not copied), then checks
what the reviewer sees: states with glyphs and text, every POST and its fields, empty states that say what to do,
and no inline style, script or handler anywhere."""
from __future__ import annotations

import re

from cybercheck.web import app as app_mod

from test_it_web import (REVIEWER, WL, StubTelegram, call, client, confirm, get, one, post,  # noqa: F401
                         redirect, sql, tg_update, world)

OPS = ("/ai", "/blocklist", "/czds", "/bot", "/takedown", "/takedown?scope=tracked")


def clean(html: str) -> None:
    assert ' style="' not in html and "<style" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", html)
    assert html.count("<h1") == 1
    assert re.search(r'<link rel="stylesheet" href="/static/ops\.css\?v=[0-9a-f]{10}">', html)
    assert re.search(r'<script src="/static/ops\.js\?v=[0-9a-f]{10}" defer></script>', html)


def page(c, path: str) -> str:
    r = get(c, path)
    assert r.headers["content-security-policy"] == app_mod.CSP
    clean(r.text)
    return r.text


def section(html: str, panel_id: str) -> str:
    m = re.search(rf'<section class="panel[^"]*" id="{panel_id}"', html)
    assert m, panel_id
    return html[m.start():html.index("</section>", m.start())]


# ---- a fresh install ------------------------------------------------------------------------------------

def test_ops_pages_on_an_empty_database_say_what_to_do_next(client):
    assert one(client, "SELECT count(*) AS n FROM domains")["n"] == 0
    for path in OPS:
        page(client, path)
    t = page(client, "/blocklist")
    assert "Nothing listed yet." in t and 'href="/review">Open the review queue' in t
    assert "No changes yet." in t and "not built yet" in t and 'id="excluded"' not in t
    t = page(client, "/ai")
    assert "No AI calls yet." in t and "The judge job has not run yet." in t and "no API key" in t
    t = page(client, "/czds")
    assert "No CZDS hits in the last 30 days." in t and "No zone files processed yet." in t
    assert "waiting for the first CZDS check" in t                 # CZDS_TLDS zones the job has not seen
    t = page(client, "/bot")
    assert "No chats are waiting." in section(t, "pending") and "777000" in section(t, "chats")
    t = page(client, "/takedown")
    assert "No flagged domains yet." in t and "Nothing flagged is still up." in t
    assert section(t, "hist").count('class="hbar-fill" x="0" y="0" width="0"') == 10


# ---- AI ---------------------------------------------------------------------------------------------------

def test_ai_page_meters_and_calls(world, client):
    t = page(client, "/ai")
    spend = t[t.index('<section class="spend"'):t.index("</section>", t.index('<section class="spend"'))]
    # today's spend (with the open reservation's estimate) is far under the $1.60 cap: violet, with text
    assert "$0.13" in spend and "of $1.60" in spend and "of $48.00" in spend
    assert spend.count('<svg class="meter meter--violet"') == 3 and "8% used" in spend and "Resets" in spend
    assert re.search(r'<div class="n">4</div><div class="l">pages judged \(24h\)', t)
    assert re.search(r'<div class="n">1</div><div class="l">domains triaged \(24h\)', t)
    calls = section(t, "calls")
    n_calls = one(client, "SELECT count(*) AS n FROM ai_calls")["n"]
    assert calls.count('<td class="muted" title=') == n_calls
    problems = one(client, "SELECT count(*) AS n FROM ai_calls WHERE status IN "
                           "('refusal', 'api_error', 'error', 'invalid', 'abandoned')")["n"]
    assert calls.count("<tr data-problem>") == problems == 3 and f"{problems} refused or failed" in calls
    assert "</span>pending</span>" in calls and "AI phishing" in calls and "refused: cyber" in calls
    assert f'href="/domain/{world["phish"]}"' in calls
    # glass: a gauge ring per cap (violet while comfortably under it), tiles with an icon and "/ total"
    assert spend.count('class="gauge ops-ring') == 3 and spend.count("gauge--violet") == 3
    assert 'aria-label="Spent today (UTC): $0.13 of $1.60 (8%)"' in spend
    assert re.search(r'<div class="n">\d+</div><div class="l">refusals today</div><div class="kpi-hint">[^<]*</div>'
                     r'<svg class="ico kpi-ico"[^>]*><use href="#i-alert"/></svg><span class="kpi-of">', t)
    # the last 24 hours, from ai_calls: calls and spend per hour, and a dot grid row per purpose
    act = section(t, "activity")
    assert f"{n_calls} calls" in act and act.count('class="spark ') == 2 and 'class="dotgrid' in act
    grid = act[act.index('class="dg"'):]
    assert re.search(rf'aria-label="AI calls per hour by purpose, last 24 hours: {n_calls} calls, \$[0-9.]+ \(', grid)
    assert ">Page judge</span>" in grid and "3 refused or failed" in grid
    assert grid.count('class="dg-c dg-m dg-m--') >= 1                   # an hour with a refusal or failure


# ---- blocklist --------------------------------------------------------------------------------------------

def test_blocklist_page_explains_each_listing(world, client):
    for key in ("phish", "down"):
        confirm(client, key, world, "it: ops page")
    assert redirect(post(client, "/blocklist/rebuild", page="/blocklist"), "/blocklist")["msg"] == "built"
    t = page(client, "/blocklist?msg=built")
    assert 'class="flash flash--ok" role="status"' in t and "Blocklist rebuilt." in t
    listed = section(t, "listed")
    # a reviewer's decision versus the automated rule (open, AI phishing 92%, combined score 93)
    phish = listed[listed.index(f'data-href="/domain/{world["phish"]}"'):]
    assert "confirmed phishing" in phish.split("</tr>")[0] and "by a reviewer" in phish.split("</tr>")[0]
    auto = listed[listed.index(f'data-href="/domain/{world["auto"]}"'):].split("</tr>")[0]
    assert "score 93" in auto and "AI phishing" in auto and "92%" in auto and "automated, not reviewed yet" in auto
    assert f'action="/blocklist/{world["auto"]}/exclude"' in auto and 'name="note"' in auto and "data-confirm=" in auto
    # build state, files to subscribe to, and never a publish button
    build = section(t, "build")
    assert "</span>written</span>" in build and "serial" in build and "scripts/publish-blocklist.sh" in build
    files = section(t, "files")
    assert 'href="/blocklist/files/hosts.txt" download' in files and 'data-copy-path="/blocklist/files/rpz.zone"' in files
    assert not re.search(r"<button[^>]*>[^<]*[Pp]ublish", t)
    # exclude with a note: the change log shows it, and the domain moves to the excluded panel
    did = world["auto"]
    assert redirect(post(client, f"/blocklist/{did}/exclude", {"note": "kit already gone"}, "/blocklist"),
                    "/blocklist")["msg"] == "excluded"
    t = page(client, "/blocklist?msg=excluded")
    changes = section(t, "changes")
    assert "</span>excluded</span>" in changes and "kit already gone by " + REVIEWER in changes
    excluded = section(t, "excluded")
    assert f'action="/blocklist/{did}/include"' in excluded and REVIEWER in excluded
    assert f'data-href="/domain/{did}"' not in section(t, "listed")
    assert redirect(post(client, f"/blocklist/{did}/include", page="/blocklist"), "/blocklist")["msg"] == "included"
    assert 'id="excluded"' not in page(client, "/blocklist")


# ---- CZDS -------------------------------------------------------------------------------------------------

def test_czds_page_zone_states(world, client):
    t = page(client, "/czds")
    zones = section(t, "zones")
    # top processed, shop baseline (both up to date); online and au are in CZDS_TLDS but never seen (waiting)
    assert "2 up to date" in zones and "2 waiting" in zones
    assert zones.count('<tr class="ops-row--ok">') == 2 and zones.count('<tr class="ops-row--waiting">') == 2
    assert "baseline stored" in zones and "3,912,004" in zones
    runs = section(t, "runs")
    assert '<tr class="ops-row--warning">' in runs and "HTTP 503 from the download server" in runs
    hits = section(t, "hits")
    assert f'data-href="/domain/{world["czds"]}"' in hits and "ct first, then CZDS" in hits
    assert "CZDS credentials configured" in t and "czds-it-password-not-real" not in t


# ---- bot --------------------------------------------------------------------------------------------------

def test_bot_page_puts_waiting_chats_first(world, client):
    from cybercheck import bot as botmod
    b = botmod.Bot(StubTelegram(), watchlist=WL, ai_on=False)
    stranger = {"id": 6660001, "type": "private", "first_name": "Kim", "username": "kim_<b>au</b>"}
    call(client, b.handle_update, tg_update(101, stranger, "hello"))
    t = page(client, "/bot")
    pending = section(t, "pending")
    assert t.index('id="pending"') < t.index('id="chats"')
    assert f'action="/bot/chat/{stranger["id"]}/status"' in pending and "kim_&lt;b&gt;au&lt;/b&gt;" in pending
    assert 'value="allowed"' in pending and "Allow this chat" in pending and "data-confirm=" in pending
    assert "<b>au</b>" not in t
    redirect(post(client, f"/bot/chat/{stranger['id']}/status", {"status": "allowed"}, "/bot"), "/bot")
    assert one(client, "SELECT status, status_by FROM bot_chats WHERE chat_id = %s", (stranger["id"],)) == {
        "status": "allowed", "status_by": REVIEWER}
    t = page(client, "/bot")
    assert f"/bot/chat/{stranger['id']}/status" not in section(t, "pending")
    chats = section(t, "chats")
    assert f'action="/bot/chat/{stranger["id"]}/status"' in chats and "</span>allowed</span>" in chats
    redirect(post(client, f"/bot/chat/{stranger['id']}/status", {"status": "blocked"}, "/bot"), "/bot")
    assert "</span>blocked</span>" in section(page(client, "/bot"), "chats")


# ---- takedowns --------------------------------------------------------------------------------------------

def test_takedown_page_time_to_takedown(world, client):
    confirm(client, "down", world, "it: takedown")
    sql(client, "UPDATE domains SET reported_at = takedown_at - interval '17 hours' WHERE id = %s", (world["down"],))
    t = page(client, "/takedown")
    assert t.count("flagged domains") == 1
    hist = section(t, "hist")
    # taken down 20 h after first seen and 17 h after the report: both in the "6 to 24 h" bucket
    row = hist[hist.index("6 to 24 h"):].split("</tr>")[0]
    assert row.count('<span class="hbar-n">1</span>') == 2 and row.count('width="100" height="8"') == 4
    assert "20.0 h" in t and "17.0 h" in t and "</span>NXDOMAIN</span>" in section(t, "recent")
    still = section(t, "still-up")
    assert "commbank-secure.top" in still and "</span>live</span>" in still
    assert f'data-href="/domain/{world["phish"]}"' in still
    assert 'data-tabs' in t and 'id="by-registrar"' in t and "GoDaddy.com, LLC" in section(t, "by-registrar")
    assert "AS16509 AMAZON-02" in section(t, "by-as")
    assert 'value="confirmed" selected' in get(client, "/takedown?scope=nope").text
    # the tiles and the gauge: taken down out of all flagged domains
    flagged = re.search(r'<div class="n">(\d+)</div><div class="l">flagged domains', t).group(1)
    assert re.search(rf'<div class="n">1</div><div class="l">taken down</div>.*?<span class="kpi-of">'
                     rf'<span class="visually-hidden">out of</span><span aria-hidden="true">/</span> {flagged}</span>', t, re.S)
    assert f'aria-label="Gone so far: 1 of {flagged}' in t and 'class="filterbar' in t


def test_ops_pages_render_after_everything_above(world, client):
    for path in OPS:
        page(client, path)
    assert one(client, "SELECT count(*) AS n FROM domain_events WHERE kind = 'blocklist_excluded'")["n"] >= 1
