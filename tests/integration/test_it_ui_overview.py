"""The overview page, /live/list and /api/live/* against a real Postgres, on the same seeded world as
test_it_web.py (store_hit, the fetch job with a stub fetcher, the AI budget, the dashboard's own POSTs)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from cybercheck.web import pages_live
from test_it_web import HOSTS, client, get, one, post, sql, world  # noqa: F401  (fixtures used by name)


@pytest.fixture(autouse=True)
def _fresh_terrain():
    pages_live.reset_cache()          # the terrain is cached per window; every test reads the database again
    yield
    pages_live.reset_cache()


def _gauge(html: str, key: str) -> tuple[str, str, str]:
    """(href, value, total text) of a gauge."""
    box = html[html.index(f'data-gauge="{key}"'):]
    m = re.search(r'<a class="gauge[^"]*" href="([^"]+)">.*?<span class="gauge-val"[^>]*>([^<]*)</span>'
                  r'<span class="of"> / ([^<]*)</span>', box, re.S)
    assert m, key
    return m.group(1).replace("&amp;", "&"), m.group(2), m.group(3)


def _chip(html: str, key: str) -> str:
    m = re.search(r'data-kpi="%s">.*?<span class="kpi-val">([^<]*)</span>' % key, html, re.S)
    assert m, key
    return m.group(1)


def _tile(html: str, key: str) -> tuple[str, str]:
    m = re.search(r'<a class="tile [^"]*" href="([^"]+)">(?:(?!</a>).)*?id="t-%s">([^<]*)</span>' % key, html, re.S)
    assert m, key
    return m.group(1).replace("&amp;", "&"), m.group(2)


def _list_ids(html: str) -> list[int]:
    return [int(x) for x in re.findall(r'<tr data-href="/domain/(\d+)">', html)]


def test_overview_on_an_empty_database(client):
    assert one(client, "SELECT count(*) AS n FROM domains")["n"] == 0
    r = get(client, "/")
    assert "No suspicious domains yet." in r.text and 'data-max-id="0"' in r.text
    assert "The certificate stream has not reported yet." in r.text           # no heartbeat: say what to do
    assert '<span class="stat-val" id="s-certs">0</span>' in r.text and 'id="s-hits">0</span>' in r.text
    assert 'class="tf-mark ' not in r.text and not re.search(r'<circle class="tf-[wrh]\d', r.text)   # empty, no marks
    assert "No hits in the last 24 hours." in r.text and "Nothing to judge in the last 24 hours." in r.text
    assert _chip(r.text, "open_review") == "0" and _chip(r.text, "reports_waiting") == "0"
    assert _gauge(r.text, "live") == ("/live/list?show=live-phishing", "0", "0")
    assert _gauge(r.text, "queue") == ("/review", "0", "0")
    assert _tile(r.text, "phishing") == ("/live/list?verdict=phishing&tier=flagged&window=24h", "0")
    j = get(client, "/api/live/summary").json()
    assert j["open_review"] == 0 and j["total"] == 0 and j["heartbeat"] is None and j["judged"] == 0
    assert len(j["recent"]) == 15 and all(m["c"] == 0 for m in j["recent"])
    t = get(client, "/api/live/terrain").json()
    assert t["window"] == "24h" and set("".join(t["levels"])) == {"0"} and t["cells"] == [] and t["marks"] == []
    assert t["cpm_max"] == 0 and t["total"] == {"hits": 0, "high": 0, "review": 0, "certs": 0}
    p = get(client, "/api/live/pipeline?window=7d").json()
    assert p["window"] == "7d" and all(x["total"] == 0 and len(x["counts"]) == 28 for x in p["rows"])
    j = get(client, "/api/live/minute?at=" + datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")).json()
    assert j["hits"] == [] and j["certs"] == 0 and j["total"] == 0
    for show in ("live-phishing", "confirmed-week", "taken-down"):
        assert "Nothing matches this list right now." in get(client, f"/live/list?show={show}").text, show
    get(client, "/api/live/minute?at=nope", 400)


def test_overview_on_the_seeded_world(world, client):
    r = get(client, "/")
    html = r.text
    assert '<h1 id="ov-title">Threat overview</h1>' in html and "3,552" in html
    # the feed: newest first, the IDN's display form, a static list that overview.js extends
    top = one(client, "SELECT max(id) AS id FROM domains")["id"]
    assert f'data-max-id="{top}"' in html and 'data-src="/api/recent"' in html
    feed = html[html.index('<ol class="feed"'):html.index("</ol>", html.index('<ol class="feed"'))]
    ids = [int(x) for x in re.findall(r'<li class="fl [^"]*" data-id="(\d+)"', feed)]
    assert len(ids) == 100 and ids == sorted(ids, reverse=True) and ids[0] == top
    assert HOSTS["idn"] in feed and "commbаnk-login.top" in feed and HOSTS["phish"] in feed
    # the terrain's numbers are the database's: hits first seen in the window, certificates in ingest_stats
    t = get(client, "/api/live/terrain?window=24h").json()
    start, end = datetime.fromisoformat(t["start"]), datetime.fromisoformat(t["end"])
    n = one(client, "SELECT count(*) AS n, count(*) FILTER (WHERE tier = 'high') AS high FROM domains "
                    "WHERE first_seen >= %s AND first_seen < %s", (start, end))
    certs = one(client, "SELECT COALESCE(sum(certs), 0) AS c FROM ingest_stats WHERE minute >= %s AND minute < %s",
                (start, end))["c"]
    assert n["n"] > 0 and t["total"]["hits"] == n["n"] and t["total"]["high"] == n["high"]
    assert sum(c[2] for c in t["cells"]) == n["n"] and sum(t["hits"]) == n["n"]
    assert t["total"]["certs"] == certs == 1840 + 1712 + 1655                     # the row 30 h ago is outside
    assert f'id="s-hits">{n["n"]:,}</span><span class="of"> / {n["high"]} high</span>' in html
    assert any(ch != "0" for ch in "".join(t["levels"]))
    marks = {m["id"]: m for m in t["marks"]}
    assert marks[world["phish"]]["kind"] == "danger" and marks[world["phish"]]["what"].startswith("AI phishing")
    assert marks[world["phish"]]["host"] == "login.commbank-secure.top"
    assert f'class="tf-mark tf-mark--red" href="/domain/{world["phish"]}"' in html     # the no-JS fallback
    # the pipeline: distinct domains from the event log
    p = get(client, "/api/live/pipeline").json()
    rows = {x["key"]: x for x in p["rows"]}
    for key in ("went_live", "ai_verdict", "reported", "taken_down"):
        want = one(client, "SELECT count(DISTINCT domain_id) AS n FROM domain_events WHERE kind = %s AND at >= %s "
                           "AND at < %s", (key, start, end))["n"]
        assert rows[key]["total"] == want, key
    assert rows["went_live"]["total"] > 0 and rows["ct"]["total"] == certs and rows["scored"]["total"] == n["n"]
    assert 'aria-label="Pipeline by stage, last 24 hours: 5,207 certificates' in html
    # gauges and tiles, each matching the list behind it
    assert _gauge(html, "live")[:2] == ("/live/list?show=live-phishing", "2")
    lst = get(client, "/live/list?show=live-phishing").text
    assert sorted(_list_ids(lst)) == sorted([world["phish"], world["auto"]])
    assert "2 domains: an AI phishing verdict and the page was live at the last check." in lst
    judged = one(client, "SELECT count(*) AS n FROM domains WHERE ai_verdict IS NOT NULL AND ai_verdict <> 'error'")
    assert _gauge(html, "live")[2] == str(judged["n"])
    open_review = one(client, "SELECT count(*) AS n FROM domains WHERE status = 'open' AND tier IN ('review','high')")
    assert _gauge(html, "queue")[:2] == ("/review", str(open_review["n"]))
    assert _chip(html, "open_review") == str(open_review["n"])
    assert 'data-gauge="ai"' in html and "No API key, pages are not judged" in html        # no API key in this world
    href, value = _tile(html, "phishing")
    assert href == "/live/list?verdict=phishing&tier=flagged&window=24h" and value == "2"
    assert sorted(_list_ids(get(client, href).text)) == sorted([world["phish"], world["auto"]])
    for key in ("suspicious", "cleared", "unjudged"):
        href, value = _tile(html, key)
        assert len(_list_ids(get(client, href).text)) == int(value.replace(",", "")), key
    # hits by brand: the filler brand leads; its number links to exactly that list
    brand = one(client, "SELECT brand_id, count(*) AS n FROM domains WHERE first_seen > now() - interval '24 hours' "
                        "AND brand_id IS NOT NULL GROUP BY brand_id ORDER BY n DESC, brand_id LIMIT 1")
    m = re.search(r'href="/live/list\?brand=%s&amp;window=24h"[^>]*>([\d,]+)</a>' % brand["brand_id"], html)
    assert m and int(m.group(1).replace(",", "")) == brand["n"]
    # the window control changes the frame, and an unknown window falls back to 24 hours
    week = get(client, "/?window=7d").text
    assert 'href="/?window=7d" aria-current="page"' in week and "Data from the last 7 days." in week
    assert 'href="/?window=24h" aria-current="page"' in get(client, "/?window=bogus").text
    # nothing the CSP would block in the page body
    body = html[html.index("<main"):]
    assert "style=" not in body and not re.search(r"<script(?![^>]*\bsrc=)", body)


def test_lists_behind_the_numbers(world, client):
    now_min = one(client, "SELECT to_char(date_trunc('minute', first_seen) AT TIME ZONE 'UTC', "
                          "'YYYY-MM-DD\"T\"HH24:MI\"Z\"') AS t FROM domains WHERE id = %s", (world["phish"],))["t"]
    # one minute: the API and the list agree with the database
    j = get(client, f"/api/live/minute?at={now_min}").json()
    lo = datetime.fromisoformat(now_min.replace("Z", "+00:00"))
    n = one(client, "SELECT count(*) AS n FROM domains WHERE first_seen >= %s "
                    "AND first_seen < %s + interval '1 minute'", (lo, lo))["n"]
    assert j["total"] == n and world["phish"] in [h["id"] for h in j["hits"]] and j["list"].endswith(now_min)
    assert len(j["hits"]) == min(n, 20)
    lst = get(client, j["list"]).text
    assert world["phish"] in _list_ids(lst) and f"first seen {now_min[:10]} {now_min[11:16]} UTC" in lst
    # the table under the pipeline links to the list for that clock hour
    hour = now_min[:14] + "00Z"
    html = get(client, "/").text
    assert f'href="/live/list?hour={hour}&amp;tier=high">' in html
    lst = get(client, f"/live/list?hour={hour}&tier=high").text
    assert world["phish"] in _list_ids(lst)
    high_ids = {r["id"] for r in sql(client, "SELECT id FROM domains WHERE tier = 'high' AND first_seen >= %s "
                                             "AND first_seen < %s + interval '1 hour'",
                                     (lo.replace(minute=0), lo.replace(minute=0)))}
    assert set(_list_ids(lst)) == high_ids
    # hostile parameters are ignored, never an error
    r = get(client, "/live/list?show=%27%3B%20DROP%20TABLE%20domains%3B--&tier=x&verdict=%00&at=never")
    assert "<h1>Hits</h1>" in r.text
    assert one(client, "SELECT count(*) AS n FROM domains")["n"] > 0
    get(client, "/api/live/terrain?window=%27%3B--")
    get(client, "/api/live/pipeline?window=%00")


def test_numbers_follow_review_decisions(world, client):
    before = get(client, "/api/live/summary").json()
    assert before["confirmed_week"] == 0 and before["live_phishing"] == 2
    # confirm the phishing domain and the one that was taken down, through the dashboard's own form
    for key in ("phish", "down"):
        r = post(client, f"/domain/{world[key]}/status", {"status": "confirmed"}, page=f"/domain/{world[key]}")
        assert r.status_code == 303, r.text
    after = get(client, "/api/live/summary").json()
    assert after["confirmed_week"] == 2 and after["taken_down"] == 1
    assert after["decided_week"] == before["decided_week"] + 2
    assert after["open_review"] == one(client, "SELECT count(*) AS n FROM domains WHERE status = 'open' "
                                               "AND tier IN ('review', 'high')")["n"] < before["open_review"]
    html = get(client, "/").text
    assert _gauge(html, "queue")[1] == str(after["open_review"])
    assert _gauge(html, "queue")[2] == str(after["open_review"] + after["decided_week"])
    # the confirmations are in the pipeline's Confirmed row (the status events)
    p = get(client, "/api/live/pipeline").json()
    assert next(x for x in p["rows"] if x["key"] == "confirmed")["total"] >= 2
    lst = get(client, "/live/list?show=taken-down").text
    assert _list_ids(lst) == [world["down"]]
    lst = get(client, "/live/list?show=confirmed-week").text
    assert sorted(_list_ids(lst)) == sorted([world["phish"], world["down"]])
    # the takedown list uses the same scope as /takedown?scope=tracked
    assert get(client, "/takedown?scope=tracked").status_code == 200
    # reports waiting for a human: whatever the confirmations queued, as the reports page counts them
    waiting = one(client, "SELECT count(*) AS n FROM reports WHERE status = 'pending_review'")["n"]
    assert after["reports_waiting"] == waiting and _chip(html, "reports_waiting") == str(waiting)
    # the feed shows the decision
    feed = html[html.index('<ol class="feed"'):]
    line = feed[feed.index(f'data-id="{world["phish"]}"'):]
    assert "confirmed phishing" in line[:line.index("</li>")]
