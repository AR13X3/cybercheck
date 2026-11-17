"""The glass shell (base.html top bar, status strip, icon sprite) and the shared viz macros in _ui.html:
gauge rings, sparklines, badges, tiles, dot grid, segmented control, filter pills, icon buttons.
No network, no database (the status line is faked)."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cybercheck import db
from cybercheck.web import app as app_mod
from cybercheck.web import common

LOCAL = "http://127.0.0.1:8430"
XSS = '<img src=x onerror=alert(1)>"\''
STATIC = Path(app_mod.__file__).parent / "static"


class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None

    async def fetchall(self):
        return self.rows


class FakeConn:
    async def execute(self, sql, params=()):
        return Cur([])

    @asynccontextmanager
    async def transaction(self):
        yield self


class FakePool:
    @asynccontextmanager
    async def connection(self):
        yield FakeConn()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("WEB_ALLOWED_HOSTS", raising=False)

    async def status():
        return common.build_status({"certs_5m": 2060, "heartbeat_at": None, "open_review": 7, "open_high": 2,
                                    "worker_at": None, "fetch_job": None, "fetch_at": None, "ai_today": 1.25},
                                   5.0, True)

    async def pool():
        return FakePool()
    common.reset_status_cache()
    monkeypatch.setattr(common, "_query_status", status)
    monkeypatch.setattr(db, "pool", pool)
    yield
    common.reset_status_cache()


def client() -> TestClient:
    return TestClient(app_mod.app, base_url=LOCAL)


def render(src: str, **ctx) -> str:
    return common.templates.env.from_string('{% import "_ui.html" as ui %}' + src).render(**ctx)


# ---- pure helpers ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("n, want", [(None, "-"), ("", "-"), (0, "0"), (981, "981"), (999, "999"), (1000, "1k"),
                                     (1234, "1.2k"), (7400, "7.4k"), (882_000, "882k"), (999_950, "1M"),
                                     (2_400_000, "2.4M"), (3_000_000_000, "3B"), (-1500, "-1.5k"), (12.5, "12.5"),
                                     ("nope", "nope"), (float("nan"), "-")])
def test_compact(n, want):
    assert common.compact(n) == want


def test_gauge_geometry():
    g = common.gauge_geom(1, 4)
    assert g["pct"] == 25 and g["frac"] == 0.25 and not g["empty"]
    assert g["track"].startswith("M21.72 78.28A40 40 0 1 1 ") and g["arc"].startswith("M21.72 78.28A40 40 0 0 1 ")
    # a quarter of 270 degrees from the lower left ends up left of centre, above the middle
    assert g["ex"] < 50 and g["ey"] < 50 and g["nx"] < 50
    full = common.gauge_geom(10, 4)                       # clamped
    assert full["pct"] == 100 and full["arc"].split("A")[1].split()[3] == "1"     # large-arc flag
    for empty in (common.gauge_geom(0, 0), common.gauge_geom(None, None), common.gauge_geom("x", 3)):
        assert empty["arc"] == "" and empty["pct"] == 0
    assert common.gauge_geom(0, 0)["empty"] and not common.gauge_geom(0, 5)["empty"]


def test_spark_geometry():
    s = common.spark_geom([0, 2, 4, 1], "bars")
    assert s["n"] == 4 and s["max"] == 4 and s["sum"] == 7 and s["peak_i"] == 2
    assert len(s["bars"]) == 3 and [b[4] for b in s["bars"]] == [False, True, False]
    top = [b for b in s["bars"] if b[4]][0]
    assert top[1] == 2.0 and abs(top[1] + top[3] - s["base"]) < 0.01           # the peak bar reaches the top
    p = common.spark_geom([0, 3, 0, 1], "peaks")
    assert p["path"].count("Z") == 2 and p["path"].startswith("M")
    line = common.spark_geom([1, 2], "line")
    assert len(line["points"].split()) == 2
    empty = common.spark_geom([], "bars")
    assert empty["n"] == 0 and empty["bars"] == [] and empty["peak_i"] is None
    zeros = common.spark_geom([0, 0, None, "x"], "bars")
    assert zeros["bars"] == [] and zeros["peak_i"] is None and zeros["max"] == 0


def test_nav_groups_split_primary_and_more():
    nav = [("/", "Overview"), ("/review", "Review"), ("/domains", "All domains"), ("/blocklist", "Blocklist"),
           ("/reports", "Reports"), ("/ai", "AI")]
    g = common.nav_groups("/domain/5", nav)
    assert [i["path"] for i in g["primary"]] == ["/", "/review", "/domains", "/reports"]
    assert [i["path"] for i in g["more"]] == ["/blocklist", "/ai"]
    assert [i["label"] for i in g["primary"]][2] == "Domains" and g["primary"][2]["active"]
    assert g["more_active"] is None
    g = common.nav_groups("/ai", nav)
    assert g["more_active"]["label"] == "AI" and g["more_active"]["chord"] == "g a"
    assert g["more_active"]["chord_label"] == "Go to AI" and g["primary"][1]["chord_label"] == "Go to review"


# ---- the shell -------------------------------------------------------------------------------------------

def test_top_bar_nav_status_and_sprite():
    r = client().get("/review")
    assert r.status_code == 200, r.text
    html = r.text
    head = html.split("<main", 1)[0]
    assert "http://" not in head and "https://" not in head
    # font preloaded from this origin, the stylesheet carries the hash
    assert '<link rel="preload" href="/static/fonts/Outfit-wght.ttf" as="font" type="font/ttf" crossorigin>' in head
    # segmented nav: Review is current and carries the queue count; the rest of the modules sit under More
    assert re.search(r'<a class="nav-link is-active" href="/review" aria-current="page" data-chord="g r" '
                     r'data-chord-label="Go to review"><span class="nav-label">Review</span><span class="nav-badge '
                     r'nav-badge--high" data-status-badge="queue" title="7 waiting for review">7</span></a>', head)
    assert '<details class="nav-more" data-nav-more>' in head
    more = head[head.index('data-nav-more'):head.index("</details>")]
    for path in ("/blocklist", "/takedown", "/ai", "/czds", "/bot"):
        assert f'href="{path}"' in more, path
    assert 'href="/reports"' not in more and ">Domains<" in head
    # every nav chord is declared once
    assert len(re.findall(r'data-chord="g r"', html)) == 1
    # search pill, help button (JS only), phone menu with a no-JS anchor fallback
    assert 'action="/domains" role="search"' in head and 'data-global-search' in head
    assert re.search(r'<button type="button" class="icon-btn topbar-help js-only" hidden data-help-open', head)
    assert '<a class="menu-btn" href="#cc-nav" aria-controls="cc-nav" data-menu-toggle>' in head
    assert 'class="topnav" id="cc-nav"' in head
    # the status strip keeps its contract for app.js and the tests
    bar = html[html.index('id="cc-status"'):html.index("</ul>")]
    assert bar.count('class="seg ') == 6 and "seg--red" in bar and "7 open, 2 high" in bar
    # one icon sprite with the badge shapes and the gauge gradient
    for sym in ("i-shield", "i-danger", "i-alert", "i-unknown", "i-search", "i-keyboard", "i-menu", "cc-grad-gauge"):
        assert f'id="{sym}"' in head, sym
    assert ' style="' not in html and "<style" not in html


def test_more_shows_the_current_module():
    html = client().get("/ai").text
    head = html.split("<main", 1)[0]
    assert re.search(r'<summary class="nav-link nav-more-btn is-active"><span class="nav-label">AI</span>', head)
    assert '<a class="nav-menu-link is-active" href="/ai" aria-current="page"' in head
    assert head.count('aria-current="page"') == 1


# ---- macros ----------------------------------------------------------------------------------------------

def test_gauge_macro():
    t = render('{{ ui.gauge(1.25, 5, "AI spend today", shown="$1.25", shown_total="$5", id="g-ai") }}')
    assert '<figure class="gauge">' in t and 'role="img" aria-label="AI spend today: $1.25 of $5 (25%)"' in t
    assert 'stroke="url(#cc-grad-gauge)"' in t and 'class="gauge-needle"' in t
    assert '<span class="gauge-val" id="g-ai">$1.25</span><span class="of"> / $5</span>' in t
    t = render('{{ ui.gauge(0, 0, "Queue", href="/review", tone="amber") }}')
    assert t.startswith('<a class="gauge gauge--amber" href="/review">') and 'class="gauge-arc"' not in t
    assert 'aria-label="Queue: 0 of 0"' in t
    t = render('{{ ui.gauge(882000, 992000, "Assets") }}')
    assert '>882k</span><span class="of"> / 992k</span>' in t


def test_sparkline_macro():
    t = render('{{ ui.sparkline([0, 2, 4, 1], "Hits per 10 minutes", start="24 h ago", end="now") }}')
    assert 'aria-label="Hits per 10 minutes: 4 points, peak 4, total 7"' in t
    assert t.count('class="spark-bar') == 3 and 'class="spark-bar is-peak"' in t
    assert 'stroke-dasharray="1 3"' in t and "<span>24 h ago</span><span>now</span>" in t
    t = render('{{ ui.sparkline([], "Empty", kind="peaks") }}')
    assert 'aria-label="Empty: no data"' in t and "spark-max" not in t
    t = render('{{ ui.sparkline([0, 5, 0], "High peaks", kind="peaks", tone="warm") }}')
    assert 'class="spark-fill" d="M' in t and "spark--warm" in t


def test_badges_tiles_and_tips_escape_attacker_text():
    t = render('{{ ui.badge("danger", host ~ ", AI phishing", href="/domain/5") }}', host=XSS)
    assert t.startswith('<a class="badge badge--red" href="/domain/5" aria-label="')
    assert "<img" not in t and "&lt;img" in t and 'data-tip="&lt;img' in t
    assert '<use href="#i-danger"/>' in t
    t = render('{{ ui.badge("bogus", "x") }}')
    assert 'class="badge badge--grey" role="img" aria-label="x"' in t and "tabindex" not in t
    t = render('{{ ui.tip(host, "alert") }}', host=XSS)
    assert '<span class="tip-pill">' in t and "<img" not in t and 'tip-ico--amber' in t
    t = render('{{ ui.tile("protected", "Benign or parked", 88, 340, "Judged pages", href="/live/list?v=benign") }}')
    assert t.startswith('<a class="tile tile--green" href="/live/list?v=benign">')
    assert '<span class="tile-val">88</span><span class="of"> / 340</span>' in t and "#i-shield" in t


def test_controls():
    t = render('{{ ui.icon_button("pause", "Pause live updates", pressed=False, data={"action": "pause"}, js_only=True) }}')
    assert t.startswith('<button type="button" class="icon-btn js-only" aria-label="Pause live updates" '
                        'data-tip="Pause live updates" aria-pressed="false" data-action="pause" hidden>')
    t = render('{{ ui.icon_button("clock", "Window", href="/?window=7d", text="7 d") }}')
    assert t.startswith('<a class="icon-btn icon-btn--text" href="/?window=7d"') and ">7 d</span></a>" in t
    t = render('{% call ui.fab_row("Terrain controls") %}x{% endcall %}')
    assert t == '<div class="fab-row" role="group" aria-label="Terrain controls">x</div>'
    t = render('{{ ui.segmented([("/?w=6h", "6 h"), ("/?w=24h", "24 h")], active="/?w=24h", label="Window") }}')
    assert '<nav class="tabs segmented" aria-label="Window">' in t and 'class="tab is-active" href="/?w=24h" aria-current="page"' in t
    t = render('{% call ui.filter_bar() %}{{ ui.filter_pill("Tier", "tier", ["high", "review"], selected="high", any_label="Any") }}{% endcall %}')
    assert '<label class="fpill-l" for="fp-tier">Tier</label>' in t and '<option value="high" selected>' in t
    assert '<button type="submit" class="btn btn--sm">Apply</button>' in t
    t = render('{{ ui.search_pill(value=v, label="Search hits") }}', v=XSS)
    assert 'role="search"' in t and 'value="&lt;img' in t and 'aria-label="Search hits"' in t


def test_kpi_total_and_old_markup():
    assert render('{{ ui.kpi("open", 2) }}') == '<div class="kpi"><div class="n">2</div><div class="l">open</div></div>'
    t = render('{{ ui.kpi("open", 7, total=42) }}')
    assert '<div class="n">7<span class="of"> / 42</span></div><div class="l">open</div>' in t
    t = render('{{ ui.stat("882k", "992k", "Attacked assets", id="s1") }}')
    assert '<span class="stat-val" id="s1">882k</span><span class="of"> / 992k</span>' in t


def test_dot_grid_macro():
    rows = [{"label": "Seen in CT", "total": "1,204", "cells": [{"level": 0}, {"level": 4, "title": "14:00: 300"},
                                                                {"level": None}, {"marker": "danger", "title": XSS}]}]
    t = render('{{ ui.dot_grid(rows, "Pipeline by stage", cols=["24 h ago", "now"]) }}', rows=rows)
    assert 'role="img" aria-label="Pipeline by stage"' in t
    assert '<i class="dg-c dg-l0"></i><i class="dg-c dg-l4" title="14:00: 300"></i><i class="dg-c dg-x"></i>' in t
    assert 'class="dg-c dg-m dg-m--red" title="&lt;img' in t and "#i-danger" in t
    assert '<span class="dg-total" aria-hidden="true">1,204</span>' in t and "<span>now</span>" in t


# ---- static files ----------------------------------------------------------------------------------------

def test_font_and_css_contract():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert '@font-face' in css and 'url("fonts/Outfit-wght.ttf")' in css and "font-display: swap" in css
    assert (STATIC / "fonts" / "Outfit-wght.ttf").stat().st_size > 50_000 and (STATIC / "fonts" / "Outfit-OFL.txt").exists()
    # glass degrades: blur only inside @supports, a reduced-transparency fallback, reduced motion stops animation
    assert "@supports ((-webkit-backdrop-filter: blur(1px)) or (backdrop-filter: blur(1px)))" in css
    assert css.index("backdrop-filter: blur(var(--blur))") > css.index("@supports ((-webkit-backdrop-filter")
    assert "prefers-reduced-transparency: reduce" in css and "prefers-reduced-motion: reduce" in css
    for token in ("--bg: #1c1e1f", "--teal: #2fd3a7", "--green: #8bd450", "--amber: #f39a3d", "--violet: #a79bff"):
        assert token in css, token
    # a hovered badge grows with `scale`, so a pinned badge (.pin) keeps its translate(-50%, -50%) centring, and the
    # tone classes outrank a:hover so a linked badge keeps its colour
    assert "a.badge:hover, .badge:focus-visible { scale: 1.08;" in css and "transform: scale(" not in css
    assert ".pin { position: absolute; transform: translate(-50%, -50%); }" in css
    assert ".badge.badge--red { color: var(--red); }" in css
    # filter pills keep their 32 px height (40 px on touch screens)
    assert "select.fpill-select {\n  -webkit-appearance: none; appearance: none; min-height: 32px;" in css
    assert not re.search(r"select\.fpill-select[^{]*\{[^}]*min-height: 0", css)
    r = client().get("/static/fonts/Outfit-wght.ttf")
    assert r.status_code == 200 and r.headers["content-type"] in ("font/ttf", "font/sfnt", "application/x-font-ttf",
                                                                  "application/octet-stream")


def test_app_js_exposes_the_new_helpers():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    for name in ("CC.tooltip = ", "CC.canvasDPR = ", "CC.observeSize = ", "CC.reducedMotion = ", "CC.loop = ",
                 "CC.icon = ", "CC.badge = ", "CC.compact = ", "CC.token = ", "CC.menu = "):
        assert name in js, name
    # the old API is still there
    for name in ("CC.el = ", "CC.poll = ", "CC.post = ", "CC.getJSON = ", "CC.toast = ", "CC.confirm = ",
                 "CC.shortcut = ", "CC.rows = ", "CC.data = ", "CC.lightbox = ", "CC.copy = ", "CC.busy = "):
        assert name in js, name
