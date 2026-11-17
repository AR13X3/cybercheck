"""The triage pages (/review two-pane queue, /review/evidence/<id>, /domain/<id>, /domains sorting) against a real
Postgres, seeded the way the pipeline does it (the world of test_it_web: store_hit, the fetch job with a stub
fetcher, the AI budget, the judge's columns). Decisions go through the dashboard's own POST route."""
from __future__ import annotations

import re

from cybercheck.store import store_hit
from cybercheck import db

from test_it_web import (HOSTS, call, client, get, hit_for, one, post, redirect, sql, world)  # noqa: F401 (fixtures)

EVIL = "<img src=x onerror=alert(1)>"


def _queue_ids(html: str) -> list[int]:
    return [int(x) for x in re.findall(r'<tr data-id="(\d+)">', html)]


def _expected(client, order: str, extra: str = "", params=()) -> list[int]:
    return [r["id"] for r in sql(client, "SELECT id FROM domains WHERE status = 'open' AND tier IN ('review','high') "
                                         f"{extra} ORDER BY {order} LIMIT 300", params)]


def test_review_queue_order_filters_and_counts(world, client):
    t = get(client, "/review").text
    ids = _queue_ids(t)
    assert ids == _expected(client, "(tier = 'high') DESC, COALESCE(final_score, score) DESC, first_seen DESC, id DESC")
    tiers = {r["id"]: r["tier"] for r in sql(client, "SELECT id, tier FROM domains")}
    first_review = next(i for i, x in enumerate(ids) if tiers[x] == "review")
    assert all(tiers[x] == "high" for x in ids[:first_review]) and all(tiers[x] == "review" for x in ids[first_review:])
    assert ids[0] == world["phish"] and world["watch"] not in ids
    n = one(client, "SELECT count(*) AS n, count(*) FILTER (WHERE tier = 'high') AS h FROM domains "
                    "WHERE status = 'open' AND tier IN ('review','high')")
    assert f"{n['n']:,} domains wait for a decision, {n['h']:,} high tier." in t
    # the old order is one choice away
    assert _queue_ids(get(client, "/review?sort=score").text) == _expected(
        client, "COALESCE(final_score, score) DESC, first_seen DESC, id DESC")
    # filters
    assert set(_queue_ids(get(client, "/review?tier=high").text)) == {
        x for x in ids if tiers[x] == "high"}
    assert _queue_ids(get(client, "/review?live=yes").text) == _expected(
        client, "(tier = 'high') DESC, COALESCE(final_score, score) DESC, first_seen DESC, id DESC",
        "AND live_state = 'live'")
    assert set(_queue_ids(get(client, "/review?ai=phishing").text)) == {world["phish"], world["auto"]}
    assert world["phish"] not in _queue_ids(get(client, "/review?ai=none").text)
    t = get(client, "/review?brand=auspost&tier=review")
    assert world["auto"] in _queue_ids(t.text) and world["phish"] not in _queue_ids(t.text)
    assert "(filtered)" in t.text and 'value="auspost" selected' in t.text
    t = get(client, "/review?brand=no-such-brand").text
    assert _queue_ids(t) == [] and "Nothing here." in t and "No open domain matches these filters" in t
    # hostile filter values are just values
    assert _queue_ids(get(client, "/review", params={"brand": "'; DROP TABLE domains; --", "ai": "x"}).text) == []
    get(client, "/review?id=abc", 422)


def test_review_evidence_pane(world, client):
    t = get(client, "/review").text
    pane = t[t.index('<section class="evidence" id="evidence"'):]
    assert f'data-domain-id="{world["phish"]}"' in pane[:200]
    assert f'aria-current="true">{HOSTS["phish"]}</a>' in t
    shot = world["pages"][(world["phish"], "desktop")]
    mobile = world["pages"][(world["phish"], "mobile")]
    assert f'href="/screenshot/{shot["id"]}" data-lightbox' in pane and f'src="/screenshot/{mobile["id"]}"' in pane
    # AI explanation (from the AI call: the seeded page row only has the verdict), what the page asks for, score
    assert "Copies the NetBank log-on page" in pane and "AI phishing" in pane
    assert '<span class="ask-label">password</span>' in pane
    assert "combined score" in pane and "+15" in pane and "domain score" in pane
    assert "if confirmed: the whole domain" in pane and "secure.commbank-secure.top" in pane
    assert f'action="/domain/{world["phish"]}/status"' in pane and "report drafts" in pane
    assert 'href="https://' not in pane
    # the fragment is the same pane on its own
    r = get(client, f"/review/evidence/{world['phish']}")
    assert r.headers["cache-control"] == "no-store" and r.text.lstrip().startswith('<section class="evidence"')
    assert "Copies the NetBank log-on page" in r.text and "<html" not in r.text
    # a domain without a page or a verdict, selected by id (also outside the queue: watch tier)
    t = get(client, f"/review?id={world['watch']}").text
    assert f'data-domain-id="{world["watch"]}"' in t and "No screenshot yet" in t and "No AI page verdict yet" in t
    assert "AI name triage" in t and "likely target westpac" in t
    t = get(client, f"/review/evidence/{world['review']}").text
    assert "The last fetch failed" in t and "net::ERR_CONNECTION_REFUSED" in t
    # the official domain: Confirm is disabled and says why (the server refuses it too)
    t = get(client, f"/review/evidence/{world['official']}").text
    assert re.search(r'value="confirmed" disabled aria-describedby="ev-official-\d+">Confirm phishing', t)
    assert "commbank.com.au is an official brand domain" in t
    get(client, "/review/evidence/99999999", 404)
    get(client, "/review/evidence/99999999999999999999", 404)


def test_triage_decision_and_undo_through_the_pane_form(world, client):
    """What triage.js does: post the pane's form fields to /domain/<id>/status, then status=open to undo."""
    did = world["auto"]
    before = _queue_ids(get(client, "/review").text)
    assert did in before
    page = "/review"
    redirect(post(client, f"/domain/{did}/status", {"status": "benign", "note": "parked redelivery page"}, page),
             f"/domain/{did}")
    after = _queue_ids(get(client, "/review").text)
    assert did not in after and after == [x for x in before if x != did]
    t = get(client, f"/review/evidence/{did}").text
    assert "Marked benign or parked by reviewer@example.org" in t and 'value="open" data-decide="open">Reopen' in t
    redirect(post(client, f"/domain/{did}/status", {"status": "open", "note": ""}, page), f"/domain/{did}")
    assert _queue_ids(get(client, "/review").text) == before
    d = one(client, "SELECT status, notes FROM domains WHERE id = %s", (did,))
    assert d["status"] == "open" and d["notes"] == "parked redelivery page"
    # the official domain: the server refuses a confirm with a message the pane shows
    r = post(client, f"/domain/{world['official']}/status", {"status": "confirmed"}, page)
    assert r.status_code == 400 and "official brand domain" in r.json()["detail"]


def test_domain_page_evidence_first(world, client):
    queue = _expected(client, "(tier = 'high') DESC, COALESCE(final_score, score) DESC, first_seen DESC, id DESC")
    did = queue[1]
    t = get(client, f"/domain/{did}").text
    assert f"(2 of {len(queue)})" in t
    assert f'href="/domain/{queue[0]}" data-shortcut="["' in t and f'href="/domain/{queue[2]}" data-shortcut="]"' in t
    t = get(client, f"/domain/{world['phish']}").text
    assert "Strong evidence of phishing. Waiting for your decision." in t and 'class="verdict verdict--red"' in t
    order = [t.index(x) for x in ('class="verdict ', 'class="decision decision-bar"', "Latest screenshot",
                                  "What the page asks for", "Why it was flagged", "Details", "Page snapshots",
                                  "AI checks", 'class="timeline"', "Recent checks")]
    assert order == sorted(order)
    assert re.search(r'<span class="tl-kind">first_seen</span>', t) and '<span class="tl-kind">ai_verdict</span>' in t
    assert "Copies the NetBank log-on page" in t and "asks for password" in t
    assert 'data-shortcut="c"' in t and 'data-shortcut="f"' in t and 'data-shortcut="b"' in t
    assert 'data-shortcut="n"' in t and 'value="open"' not in t[t.index("decision-bar"):t.index("decision-help")]
    # a domain outside the queue: next goes to the top of the queue
    t = get(client, f"/domain/{world['watch']}").text
    assert f'href="/domain/{queue[0]}" data-shortcut="]"' in t and 'data-shortcut="["' not in t
    t = get(client, f"/domain/{world['official']}").text
    assert re.search(r'value="confirmed" disabled aria-describedby="official-note"', t)
    t = get(client, f"/domain/{world['down']}").text
    assert "taken down" in t and "(nxdomain)" in t


def test_domains_sorting_and_paging(world, client):
    total = one(client, "SELECT count(*) AS n FROM domains")["n"]
    t = get(client, "/domains").text
    assert f"{total:,} domains. Showing 1 to 200." in t and 'aria-sort="descending"><a class="sort is-sorted"' in t
    ids = _queue_ids(get(client, "/domains?sort=combined&dir=desc").text)
    want = [r["id"] for r in sql(client, "SELECT id FROM domains ORDER BY final_score DESC NULLS LAST, "
                                         "first_seen DESC, id DESC LIMIT 200")]
    assert ids == want and ids[0] == world["phish"]
    ids = _queue_ids(get(client, "/domains?sort=host&dir=asc&q=commbank").text)
    want = [r["id"] for r in sql(client, "SELECT id FROM domains WHERE id = ANY(%s) ORDER BY registered_domain ASC, "
                                         "first_seen DESC, id DESC", (ids,))]       # the database's collation
    assert ids == want and len(ids) >= 3
    ids = _queue_ids(get(client, "/domains?sort=tier").text)
    tiers = {r["id"]: r["tier"] for r in sql(client, "SELECT id, tier FROM domains")}
    rank = {"high": 3, "review": 2, "watch": 1}
    assert [rank[tiers[i]] for i in ids] == sorted((rank[tiers[i]] for i in ids), reverse=True)
    # paging keeps the sort; pages never overlap
    r = get(client, "/domains?sort=score&dir=asc")
    assert "q=&amp;tier=&amp;status=&amp;brand=&amp;page=2&amp;sort=score&amp;dir=asc" in r.text
    p1, p2 = _queue_ids(r.text), _queue_ids(get(client, "/domains?sort=score&dir=asc&page=2").text)
    assert len(p1) == 200 and len(p1) + len(p2) == total and not set(p1) & set(p2)
    assert "Previous page" in get(client, "/domains?sort=score&dir=asc&page=2").text
    # unknown sort keys are ignored, not SQL
    assert _queue_ids(get(client, "/domains", params={"sort": "id; DROP TABLE domains", "dir": "x"}).text) == \
        _queue_ids(get(client, "/domains").text)


async def _store(host: str) -> int:
    p = await db.pool()
    async with p.connection() as conn:
        return (await store_hit(conn, hit_for(host), "ct", "R11", EVIL))[0]


def test_attacker_text_is_escaped_on_every_triage_page(world, client):
    did = call(client, _store, "commbank-netbank-verify.top")
    try:
        sql(client, "UPDATE domains SET unicode_domain = %s, brand_id = %s, notes = %s, "
                    "ai_triage = %s WHERE id = %s",
            (EVIL, "commbank", EVIL, db.jsonb({"assessment": EVIL, "likely_target": EVIL, "reason": EVIL}), did))
        for path in ("/review", f"/review?id={did}", f"/review/evidence/{did}", f"/domain/{did}", "/domains",
                     "/domains?q=commbank-netbank"):
            t = get(client, path).text
            assert EVIL not in t, path
        assert "&lt;img src=x onerror=alert(1)&gt;" in get(client, f"/domain/{did}").text
    finally:
        sql(client, "DELETE FROM domains WHERE id = %s", (did,))
