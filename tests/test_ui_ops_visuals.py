"""The glass visuals of the reports and operations pages: the shared tiles and gauge ring (ops_macros.html), the
AI page's last-24-hours view (pages_ai.hourly_view and its template), and the CSS contract of ops.css /
reports.css. No network, no database: pages render through the real app with the database faked."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from cybercheck.web import common, pages_ai
from test_ui_ops import AI_STATUS, XSS, _AIConn, _ai_client, _call, _quiet_status_line  # noqa: F401

STATIC = Path(common.__file__).parent / "static"
TEMPLATES = Path(common.__file__).parent / "templates"


def render(src: str, **ctx) -> str:
    return common.templates.env.from_string('{% import "ops_macros.html" as ops %}' + src).render(**ctx)


# ---- ops_macros.html --------------------------------------------------------------------------------------

def test_tile_keeps_the_kpi_markup_and_adds_icon_and_total():
    t = render('{{ ops.tile("taken down", 3, "done", total=11, tone="teal", hint="p90 2 d", href="#x") }}')
    assert t.startswith('<a class="kpi kpi--link kpi--teal" href="#x"><div class="n">3</div><div class="l">taken down</div>')
    assert '<div class="kpi-hint">p90 2 d</div><svg class="ico kpi-ico" aria-hidden="true" focusable="false">' \
           '<use href="#i-done"/></svg>' in t
    assert t.endswith('<span class="kpi-of"><span class="visually-hidden">out of</span>'
                      '<span aria-hidden="true">/</span> 11</span></a>')
    # no tone and no link: exactly the old <div class="kpi"> start (integration tests match it)
    t = render('{{ ops.tile("chats blocked", 0, "unknown") }}')
    assert t.startswith('<div class="kpi"><div class="n">0</div><div class="l">chats blocked</div><svg')
    assert "kpi-of" not in t and "kpi-hint" not in t
    # labels and values are escaped
    t = render('{{ ops.tile(x, x, "dot", total=x) }}', x=XSS)
    assert XSS not in t and t.count("&lt;script&gt;") == 3


def test_tiles_container_and_ring():
    t = render('{% call ops.tiles("Queue") %}x{% endcall %}')
    assert t == '<div class="kpis ops-tiles" role="group" aria-label="Queue">x</div>'
    t = render('{{ ops.ring(3, 4, "Spent: $3 of $4", tone="violet", size="lg") }}')
    assert '<span class="gauge ops-ring gauge--lg gauge--violet">' in t
    assert 'role="img" aria-label="Spent: $3 of $4"' in t and 'stroke="currentColor"' in t
    t = render('{{ ops.ring(5, 4, "over") }}')
    assert 'stroke="url(#cc-grad-gauge)"' in t                      # no tone: the gradient arc
    assert 'class="gauge-arc"' not in render('{{ ops.ring(0, 0, "none") }}')
    assert "style=" not in (TEMPLATES / "ops_macros.html").read_text(encoding="utf-8")


# ---- AI: the last 24 hours ----------------------------------------------------------------------------------

def test_hourly_view_builds_rows_cells_and_totals():
    rows = [{"purpose": "page_judge", "ago_h": 0, "calls": 4, "cost": 0.04, "refusals": 0, "errors": 1},
            {"purpose": "page_judge", "ago_h": 5, "calls": 2, "cost": 0.02, "refusals": 1, "errors": 0},
            {"purpose": "domain_triage", "ago_h": 23, "calls": 1, "cost": 0.001, "refusals": 0, "errors": 0},
            {"purpose": "zz_new", "ago_h": 99, "calls": 1, "cost": 0.0, "refusals": 0, "errors": 0},
            {"purpose": "watchlist", "ago_h": "x"}]                     # unusable: skipped
    h = pages_ai.hourly_view(rows)
    assert [r["label"] for r in h["rows"]] == ["Page judge", "Domain triage", "Zz new"]
    judge = h["rows"][0]
    assert judge["total"] == "6" and len(judge["cells"]) == 24
    now, five = judge["cells"][23], judge["cells"][18]
    assert (now["level"], now["marker"]) == (4, "danger") and "this hour: 4 calls, $0.0400, 1 failed" == now["title"]
    assert (five["level"], five["marker"]) == (2, "alert") and five["title"] == "5 h ago: 2 calls, $0.0200, 1 refused"
    assert judge["cells"][0] == {"level": 0, "title": None, "marker": None}
    assert h["rows"][1]["cells"][0]["level"] == 1 and h["rows"][2]["cells"][0]["level"] == 1   # 99 h: oldest column
    assert h["calls"][23] == 4 and h["calls"][0] == 2 and sum(h["calls"]) == h["total_calls"] == 8
    assert h["cost"][23] == 0.04 and h["problems"] == 2
    assert h["label"].startswith("AI calls per hour by purpose, last 24 hours: 8 calls, $0.06 (Page judge 6")
    assert h["label"].endswith(", 2 refused or failed")
    empty = pages_ai.hourly_view([])
    assert empty["rows"] == [] and empty["total_calls"] == 0 and empty["calls"] == [0] * 24


class _HourlyConn(_AIConn):
    async def execute(self, sql, params=None):
        if "AS ago_h" in sql:
            from test_ui_ops import _Cur
            return _Cur([{"purpose": "page_judge", "ago_h": 2, "calls": 3, "cost": 0.03, "refusals": 1, "errors": 0},
                         {"purpose": XSS, "ago_h": 0, "calls": 1, "cost": 0.01, "refusals": 0, "errors": 0}])
        return await super().execute(sql, params)


def test_ai_page_shows_gauges_tiles_and_the_last_24_hours(monkeypatch):
    monkeypatch.setattr("test_ui_ops._AIConn", _HourlyConn)
    t = _ai_client(monkeypatch, AI_STATUS, [_call()]).get("/ai").text
    spend = t[t.index('<section class="spend"'):t.index("</section>", t.index('<section class="spend"'))]
    # the day is over its cap (gradient ring, red number), the month is fine (violet ring)
    assert 'aria-label="Spent today (UTC): $1.70 of $1.60 (100%)"' in spend
    assert spend.count('class="gauge ops-ring gauge--lg gauge--violet"') == 1
    assert spend.count('class="gauge ops-ring gauge--lg"') == 1        # the day: no tone, gradient arc
    assert re.search(r'<div class="n">1</div><div class="l">refusals today</div><div class="kpi-hint">2 this month</div>'
                     r'<svg class="ico kpi-ico"[^>]*><use href="#i-alert"/></svg><span class="kpi-of">', t)
    act = t[t.index('id="activity"'):]
    act = act[:act.index("</section>")]
    assert "4 calls, $0.04" in act and act.count('class="spark ') == 2 and 'class="dotgrid' in act
    assert ">Page judge</span>" in act and "1 refused or failed" in act
    assert XSS not in act and "&lt;script&gt;" in act                 # a purpose name is text


def test_ai_page_without_calls_in_the_last_day(monkeypatch):
    t = _ai_client(monkeypatch, AI_STATUS, []).get("/ai").text
    assert "No AI calls in the last 24 hours." in t and 'class="dotgrid' not in t


# ---- CSS contract -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["ops.css", "reports.css"])
def test_page_css_stays_on_the_glass_tokens(name):
    css = (STATIC / name).read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css and "http" not in css
    # the UI font everywhere: monospace only for code, drafts and addresses (the To field)
    mono = [m.start() for m in re.finditer(r"var\(--mono\)", css)]
    assert len(mono) <= 1, name
    assert not re.search(r"#[0-9a-fA-F]{6}\b", css), name          # colours come from app.css tokens
    assert "border-left: 3px" not in css                                # no terminal-style rules
