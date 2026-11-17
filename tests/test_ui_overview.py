"""Overview page ("/"), /live/list and /api/live/*: pure helpers and routes against a fake database (offline)."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from cybercheck import db
from cybercheck.web import app as app_mod
from cybercheck.web import common, pages_live

LOCAL = "http://127.0.0.1:8430"
NOW = datetime(2026, 11, 16, 14, 30, 20, tzinfo=timezone.utc)
EVIL = '<img src=x onerror=alert(1)>.top'
TEMPLATES = Path(app_mod.__file__).parent / "templates"
STATIC = Path(app_mod.__file__).parent / "static"


def domain(i, host, tier="review", **kw):
    row = {"id": i, "registered_domain": host, "unicode_domain": None, "hostnames": [host], "tier": tier,
           "score": 70, "final_score": None, "first_seen": NOW - timedelta(minutes=i), "brand_id": "commbank",
           "live_state": "unknown", "ai_verdict": None, "ai_confidence": None, "status": "open", "reasons": [],
           "sightings": 1, "source": "ct"}
    row.update(kw)
    return row


FEED = [
    domain(5, "login.commbank-secure.top", "high", final_score=95, live_state="live", ai_verdict="phishing",
           ai_confidence=0.97),
    domain(4, "xn--commbnk-login-01k.top", "high", unicode_domain="commbаnk-login.top"),
    domain(3, EVIL, "review", brand_id=None),
    domain(2, "westpac-verify.net", "watch", status="false_positive"),
]
KPI = {"certs_5m": 3552, "hosts_5m": 9000, "certs_24h": 5207, "hits_24h": 13, "high_24h": 4, "open_review": 7,
       "open_high": 2, "total": 220, "confirmed": 3, "live": 3, "live_phishing": 2, "confirmed_week": 1,
       "taken_down": 1, "taken_down_7d": 1, "judged": 9, "decided_week": 13, "reports_waiting": 4,
       "reports_failed": 1, "last_hit": NOW,
       "heartbeat": NOW, "db_now": NOW}


class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None

    async def fetchall(self):
        return self.rows


class FakeConn:
    """Answers the overview's queries by a distinctive fragment of each; records every statement."""

    def __init__(self, kpi=None, feed=None):
        self.sql: list[tuple[str, tuple]] = []
        self.kpi = KPI if kpi is None else kpi
        self.feed = FEED if feed is None else feed

    async def execute(self, sql, params=()):
        s = " ".join(sql.split())
        self.sql.append((s, params if isinstance(params, dict) else tuple(params or ())))
        m0 = NOW.replace(second=0)
        if s == "SELECT now() AS db_now":
            return Cur([{"db_now": NOW}])
        if "AS col, score" in s:                                    # terrain hits: 15:00 window start, 5-min columns
            return Cur([{"col": 282, "score": 84, "n": 2, "high": 2, "review": 0},
                        {"col": 280, "score": 66, "n": 1, "high": 0, "review": 1},
                        {"col": 10, "score": 44, "n": 3, "high": 0, "review": 0},
                        {"col": 999, "score": 50, "n": 9, "high": 0, "review": 0}])
        if "count(DISTINCT minute)" in s:
            return Cur([{"col": 282, "certs": 2000, "minutes": 5}, {"col": 281, "certs": 500, "minutes": 5}])
        if "LIMIT %(limit)s" in s:
            return Cur([dict(FEED[0], hostname=FEED[0]["hostnames"][0], takedown_at=None),
                        dict(FEED[2], hostname=FEED[2]["hostnames"][0], takedown_at=NOW, score=81)])
        if "GROUPING SETS" in s:
            return Cur([{"stage": "ai_verdict", "col": 23, "n": 2, "phishing": 1},
                        {"stage": "ai_verdict", "col": None, "n": 2, "phishing": 1},
                        {"stage": "taken_down", "col": 22, "n": 1, "phishing": 0},
                        {"stage": "taken_down", "col": None, "n": 1, "phishing": 0}])
        if "AS live_phishing" in s:
            return Cur([self.kpi] if self.kpi else [])
        if s.startswith("SELECT * FROM domains ORDER BY id DESC"):
            return Cur(self.feed)
        if "sum(certs)::bigint" in s:
            return Cur([{"minute": m0, "certs": 400}, {"minute": m0 - timedelta(minutes=1), "certs": 100}])
        if "date_trunc('minute', first_seen)" in s:
            return Cur([{"minute": m0, "review": 1, "high": 2}, {"minute": m0 - timedelta(minutes=1), "review": 1,
                                                                 "high": 0}])
        if "GROUP BY brand_id" in s:
            return Cur([{"brand_id": "commbank", "n": 10, "high": 4, "review": 5, "watch": 1},
                        {"brand_id": "<b>x</b>", "n": 5, "high": 0, "review": 0, "watch": 5}])
        if "COALESCE(ai_verdict, 'none')" in s:
            return Cur([{"verdict": "phishing", "n": 2}, {"verdict": "none", "n": 6}, {"verdict": "weird", "n": 2}])
        if "WHERE minute = %s" in s:
            return Cur([{"certs": 400}])
        if s.startswith("SELECT count(*) AS n FROM domains WHERE first_seen >="):
            return Cur([{"n": 3}])
        if "hostnames[1] AS hostname, brand_id, tier" in s:
            return Cur([dict(FEED[0], hostname=FEED[0]["hostnames"][0])])
        if s.startswith("SELECT * FROM domains WHERE"):
            return Cur(FEED[:1])
        return Cur([])


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def connection(self):
        yield self.conn


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("WEB_ALLOWED_HOSTS", raising=False)
    common.reset_status_cache()
    pages_live.reset_cache()
    yield
    common.reset_status_cache()
    pages_live.reset_cache()


def use(monkeypatch, conn):
    async def pool():
        return FakePool(conn)
    monkeypatch.setattr(db, "pool", pool)
    return conn


@pytest.fixture
def conn(monkeypatch):
    return use(monkeypatch, FakeConn())


def client() -> TestClient:
    return TestClient(app_mod.app, base_url=LOCAL)


def body(html: str) -> str:
    return html[html.index("<main"):]


# ---- pure helpers ---------------------------------------------------------------------------------------

def test_parse_minute_and_iso_minute():
    assert pages_live.parse_minute("2026-11-16T14:05Z") == datetime(2026, 11, 16, 14, 5, tzinfo=timezone.utc)
    assert pages_live.parse_minute("2026-11-16T14:05:59+00:00").minute == 5
    assert pages_live.parse_minute("2026-11-17T01:05+11:00") == datetime(2026, 11, 16, 14, 5, tzinfo=timezone.utc)
    assert pages_live.parse_minute("2026-11-16T14:05").tzinfo is not None           # naive means UTC
    for bad in ("", None, "now", "1999-01-01T00:00Z", "2026-13-01T00:00Z", "x" * 50, "'; DROP TABLE domains;--"):
        assert pages_live.parse_minute(bad) is None, bad
    assert pages_live.iso_minute(datetime(2026, 11, 17, 1, 5, 33, tzinfo=timezone(timedelta(hours=11)))) == \
        "2026-11-16T14:05Z"


def test_view_bounds_are_clock_aligned():
    v = pages_live.view_bounds(NOW, "24h")
    assert v["end"] == datetime(2026, 11, 16, 15, 0, tzinfo=timezone.utc)
    assert v["start"] == datetime(2026, 11, 15, 15, 0, tzinfo=timezone.utc)
    assert (v["cols"], v["step"], v["buckets"], v["per_bucket"]) == (288, 300, 24, 12)
    assert v["now_col"] == 282 and v["now_bucket"] == 23 and v["label"] == "last 24 hours"
    v6 = pages_live.view_bounds(NOW, "6h")
    assert v6["end"] == datetime(2026, 11, 16, 14, 45, tzinfo=timezone.utc) and v6["cols"] == 120
    assert v6["buckets"] == 24 and v6["now_bucket"] == 23          # the last bucket always holds the present
    v7 = pages_live.view_bounds(NOW, "7d")
    assert v7["end"] == datetime(2026, 11, 16, 18, 0, tzinfo=timezone.utc) and v7["cols"] == 336
    assert v7["buckets"] == 28 and v7["per_bucket"] == 12
    assert pages_live.view_bounds(NOW, "'; DROP")["window"] == "24h"         # unknown windows fall back
    naive = pages_live.view_bounds(NOW.replace(tzinfo=None), "24h")
    assert naive["end"] == v["end"]


def test_score_rows_and_smoothing():
    assert [pages_live.score_row(x) for x in (40, 41, 42, 99, 100, 0, 250, None, "x")] == [0, 0, 1, 29, 30, 0, 30, 0, 0]
    assert pages_live.SCORE_ROWS == 31
    g = pages_live.smooth({(10, 5): 1}, 30, rows=12)
    assert len(g) == 12 and len(g[0]) == 30
    assert g[5][10] == pytest.approx(1.0)                     # a lone hit has density 1 at its centre
    assert g[5][9] == pytest.approx(g[5][11]) and g[4][10] == pytest.approx(g[6][10])   # symmetric
    assert g[5][10] > g[5][12] > g[5][14] > 0 and g[5][24] == 0 and g[0][10] == 0       # bounded radius
    assert g[5][13] > g[8][10]                                # wider along time than along score
    edge = pages_live.smooth({(0, 0): 2}, 5, rows=3)          # patches clip at the grid edge
    assert edge[0][0] == pytest.approx(2.0)


def test_encode_levels_uses_an_absolute_saturating_scale():
    rows = pages_live.encode_levels([[0, 0.02, 1.0, 2.5, 100.0]])
    assert rows == ["0" + "0" + pages_live.LEVELS[12] + pages_live.LEVELS[22] + "z"]
    # one hit looks the same whatever else is on the grid (no relative normalisation)
    assert pages_live.encode_levels([[1.0, 0]])[0][0] == pages_live.encode_levels([[1.0, 50.0]])[0][0]
    assert pages_live.encode_levels([]) == []


def test_terrain_from_rows():
    v = pages_live.view_bounds(NOW, "24h")
    hits = [{"col": 282, "score": 84, "n": 2, "high": 2, "review": 0},
            {"col": 280, "score": 66, "n": 1, "high": 0, "review": 1},
            {"col": 280, "score": 67, "n": 1, "high": 0, "review": 1},       # same row as 66
            {"col": -1, "score": 50, "n": 5}, {"col": 288, "score": 50, "n": 5}, {"col": None, "score": 50, "n": 5}]
    certs = [{"col": 282, "certs": 2000}, {"col": 0, "certs": 300}, {"col": 400, "certs": 9}]
    t = pages_live.terrain(v, hits, certs, [], {}, (60, 75))
    assert len(t["levels"]) == 31 and all(len(r) == 288 for r in t["levels"])
    assert t["levels"][pages_live.score_row(84)][282] != "0" and t["levels"][0][0] == "0"
    assert t["cells"] == [[280, 13, 2], [282, 22, 2]]
    assert t["total"] == {"hits": 4, "high": 2, "review": 2, "certs": 2300}
    assert t["cpm"][282] == 400 and t["cpm"][0] == 60 and t["cpm_max"] == 400
    assert len(t["spark"]) == 144 and t["spark"][140] == 2 and t["spark"][141] == 2 and sum(t["spark"]) == 4
    assert len(t["peaks"]) == 24 and t["peaks"][23] == 2 and sum(t["peaks"]) == 2
    b = t["buckets"][23]
    assert b["t"] == "2026-11-16T14:00Z" and b["certs"] == 2000 and b["hits"] == 4 and not b["future"]
    assert (t["review_at"], t["high_at"], t["now_col"], t["start"]) == (60, 75, 282, "2026-11-15T15:00:00+00:00")
    empty = pages_live.terrain(v, [], [], [], {}, (60, 75))
    assert set("".join(empty["levels"])) == {"0"} and empty["cells"] == [] and empty["cpm_max"] == 0


def test_marks_say_what_they_are():
    v = pages_live.view_bounds(NOW, "24h")
    base = dict(FEED[0], hostname="login.commbank-secure.top", takedown_at=None)
    m = pages_live.terrain_mark(base, v, {"commbank": "CommBank"})
    assert (m["kind"], m["what"], m["brand"], m["id"]) == ("danger", "AI phishing 97%, page live", "CommBank", 5)
    assert m["time"] == "14:25 UTC" and 0.97 < m["x"] < 0.99 and m["host"] == "login.commbank-secure.top"
    assert pages_live.mark_kind(dict(base, takedown_at=NOW)) == ("protected", "taken down")
    assert pages_live.mark_kind(dict(base, status="confirmed", live_state="down")) == ("danger", "confirmed phishing")
    assert pages_live.mark_kind(dict(base, ai_verdict="suspicious", ai_confidence=None, live_state="down")) == \
        ("alert", "AI suspicious")
    assert pages_live.mark_kind(dict(base, ai_verdict=None)) == ("unknown", "page live, not judged yet")
    early = pages_live.terrain_mark(dict(base, first_seen=NOW - timedelta(days=3)), v)
    assert early["x"] == 0.0
    v7 = pages_live.view_bounds(NOW, "7d")
    assert pages_live.terrain_mark(base, v7)["time"] == "Mon 16 Nov 14:25 UTC"


def test_pipeline_rows_cells_and_markers():
    v = pages_live.view_bounds(NOW, "24h")
    t = pages_live.terrain(v, [{"col": 282, "score": 84, "n": 2, "high": 2}, {"col": 10, "score": 44, "n": 3}],
                           [{"col": 282, "certs": 2000}, {"col": 0, "certs": 1000}], [], {}, (60, 75))
    p = pages_live.pipeline(v, t, [
        {"stage": "ai_verdict", "col": 23, "n": 2, "phishing": 1}, {"stage": "ai_verdict", "col": 3, "n": 4, "phishing": 0},
        {"stage": "ai_verdict", "col": None, "n": 5, "phishing": 1},
        {"stage": "taken_down", "col": 22, "n": 1}, {"stage": "taken_down", "col": None, "n": 1},
        {"stage": "confirmed", "col": 99, "n": 7}, {"stage": "bogus", "col": 1, "n": 1}])
    rows = {r["key"]: r for r in p["rows"]}
    assert [r["label"] for r in p["rows"]] == ["Seen in CT", "Scored", "Page live", "AI judged", "Confirmed",
                                                "Reported", "Taken down"]
    assert rows["ct"]["n"] == 3000 and rows["ct"]["total"] == "3k" and rows["scored"]["total"] == "5"
    assert rows["ct"]["counts"][0] == 1000 and rows["ct"]["counts"][23] == 2000
    ai = rows["ai_verdict"]
    assert ai["n"] == 5 and ai["total"] == "5"                    # distinct domains over the window, not a sum
    assert ai["cells"][23] == {"level": 2, "marker": "danger", "title": "14:00 UTC: 2 domains judged by the AI, 1 phishing"}
    assert ai["cells"][3]["level"] == 4 and ai["cells"][3]["marker"] is None and ai["cells"][0]["level"] == 0
    assert rows["taken_down"]["cells"][22]["marker"] == "protected"
    assert rows["confirmed"]["n"] == 0 and sum(rows["confirmed"]["counts"]) == 0      # out-of-range bucket ignored
    assert p["phishing"] == 1 and p["ticks"] == ["15:00", "21:00", "03:00", "09:00", "now"]
    assert p["label"].startswith("Pipeline by stage, last 24 hours: 3,000 certificates, 5 hits stored, ")
    assert p["table"][0]["label"] == "14:00 UTC" and p["table"][0]["high"] == 2 and p["table"][0]["hour_link"]
    assert len(p["table"]) == 24 and p["table"][-1]["t"] == "2026-11-15T15:00Z"
    # the 6 h view: 15-minute buckets, no hour links in its table
    v6 = pages_live.view_bounds(NOW, "6h")
    p6 = pages_live.pipeline(v6, pages_live.terrain(v6, [], [], [], {}, (60, 75)), [])
    assert p6["rows"][0]["cells"][23] == {"level": 0, "title": "14:30 UTC: 0 certificates", "marker": None}
    assert len(p6["table"]) == 24 and not p6["table"][0]["hour_link"]


def test_verdict_tiles_and_svg_fallback():
    t = pages_live.verdict_tiles([{"verdict": "phishing", "n": 3}, {"verdict": "benign", "n": 2},
                                  {"verdict": "parked", "n": 1}, {"verdict": "error", "n": 4}, {"verdict": None, "n": 5},
                                  {"verdict": "suspicious", "n": 1}])
    assert t == {"phishing": 3, "suspicious": 1, "cleared": 3, "judged": 7, "unjudged": 9, "total": 16}
    assert pages_live.verdict_tiles([])["total"] == 0
    v = pages_live.view_bounds(NOW, "24h")
    ter = pages_live.terrain(v, [{"col": 282, "score": 84, "n": 2}, {"col": 10, "score": 44, "n": 1}], [],
                             [dict(FEED[0], hostname="x.top", takedown_at=None)], {}, (60, 75))
    svg = pages_live.terrain_svg(ter)
    assert (svg["w"], svg["h"]) == (480, 310)
    classes = {d[3] for d in svg["dots"]}
    assert any(c.startswith("tf-h") for c in classes) and any(c.startswith("tf-w") for c in classes)
    assert all(c[4] in "1234" for c in classes)
    m = svg["marks"][0]
    assert m["cx"] == round(m["x"] * 480, 1) and m["cy"] == 310 - (pages_live.score_row(70) + 0.5) * 10
    assert svg["bands"] == [(310 - 17.5 * 10 - 5, "high 75+"), (310 - 10.5 * 10 - 5, "review 60+")]
    assert 0 < svg["now_x"] <= 480


def test_svg_fallback_keeps_marks_apart_and_off_the_band_labels():
    rows = pages_live.SCORE_ROWS
    ter = {"cols": 288, "rows": rows, "levels": ["0" * 288] * rows, "high_at": 75, "review_at": 60, "now_col": 200,
           "marks": [{"id": i, "x": x, "score": s} for i, (x, s) in
                     enumerate([(0.5, 84), (0.5, 84), (0.5, 84), (0.002, 74), (0.9, 60)])]}
    svg = pages_live.terrain_svg(ter)
    pts = [(m["cx"], m["cy"]) for m in svg["marks"]]
    assert len(pts) == 5 and [m["id"] for m in svg["marks"]] == [0, 1, 2, 3, 4]
    assert pts[0] == (240.0, 310 - (pages_live.score_row(84) + 0.5) * 10)                 # the first stays put
    assert pts[1] == (240.0, pts[0][1] - 20) and pts[2] == (240.0, pts[0][1] + 20)        # the next ones step aside
    for i, a in enumerate(pts):
        for b in pts[i + 1:]:
            assert abs(a[0] - b[0]) >= 20 or abs(a[1] - b[1]) >= 20
    for y, _ in svg["bands"]:                                                              # labels stay readable
        assert not any(cx - 10 < 56 and cy + 10 > y - 15 and cy - 10 < y + 2 for cx, cy in pts)
    # with no room left at all, a mark is left out rather than drawn on top of another
    ter["marks"] = [{"id": i, "x": 0.5, "score": 70} for i in range(9)]
    assert len(pages_live.terrain_svg(ter)["marks"]) == 5


def test_recent_minutes_fill_zero_minutes():
    m0 = NOW.replace(second=0)
    out = pages_live.recent_minutes([{"minute": m0, "certs": 7}], [{"minute": m0 - timedelta(minutes=2),
                                                                   "review": 0, "high": 1}], NOW, n=4)
    assert [x["t"] for x in out] == ["2026-11-16T14:27Z", "2026-11-16T14:28Z", "2026-11-16T14:29Z",
                                     "2026-11-16T14:30Z"]
    assert out[-1] == {"t": "2026-11-16T14:30Z", "c": 7, "review": 0, "high": 0}
    assert out[1]["high"] == 1 and out[0]["c"] == 0


def test_brand_bars_and_verdict_mix():
    bars = pages_live.brand_bars([{"brand_id": "commbank", "n": 10, "high": 4, "review": 5, "watch": 1},
                                  {"brand_id": "anz", "n": 5, "high": 0, "review": 0, "watch": 5}],
                                 {"commbank": "CommBank"})
    assert bars[0]["name"] == "CommBank" and bars[1]["name"] == "anz"
    assert bars[0]["segs"] == [("high", 0, 40.0), ("review", 40.0, 50.0), ("watch", 90.0, 10.0)]
    assert bars[1]["segs"] == [("watch", 0, 50.0)]
    assert pages_live.brand_bars([]) == []

    mix = pages_live.verdict_mix([{"verdict": "phishing", "n": 2}, {"verdict": "none", "n": 6},
                                  {"verdict": "made-up", "n": 2}])
    parts = {p["key"]: p for p in mix["parts"]}
    assert [p["key"] for p in mix["parts"]] == ["phishing", "suspicious", "benign", "parked", "error", "none"]
    assert mix["total"] == 10 and mix["judged"] == 4
    assert parts["phishing"]["w"] == 20.0 and parts["error"]["n"] == 2 and parts["none"]["x"] == 40.0
    assert all(p["glyph"] for p in mix["parts"])                 # colour never alone
    assert pages_live.verdict_mix([])["total"] == 0


def test_list_filters_use_fixed_fragments_and_parameters():
    title, where, params, order, applied = pages_live.list_filters(show="live-phishing")
    assert title == "Live phishing pages" and "ai_verdict = 'phishing'" in where and params == []
    assert order.startswith("last_live_at")
    title, where, params, order, applied = pages_live.list_filters(
        tier="high", verdict="phishing", brand="commbank", window="7d")
    assert title == "Hits: high tier, AI verdict phishing, commbank, last 7 days"
    assert params == ["phishing", "commbank", 168] and "brand_id = %s" in where
    assert applied == {"tier": "high", "verdict": "phishing", "brand": "commbank", "window": "7d"}
    # hostile values never reach the SQL text
    evil = "x'; DROP TABLE domains; --"
    title, where, params, order, applied = pages_live.list_filters(
        show=evil, tier=evil, verdict=evil, brand=evil, window=evil, at=evil, hour=evil)
    assert evil not in where and "DROP" not in where and "DROP" not in order and params == [evil]
    assert where == "brand_id = %s"
    # a minute wins over an hour, which wins over a window
    _, where, params, _, applied = pages_live.list_filters(at="2026-11-16T14:05Z", hour="2026-11-16T13:00Z",
                                                           window="24h")
    assert params == [datetime(2026, 11, 16, 14, 5, tzinfo=timezone.utc),
                      datetime(2026, 11, 16, 14, 6, tzinfo=timezone.utc)] and applied == {"at": "2026-11-16T14:05Z"}
    title, _, params, _, _ = pages_live.list_filters(hour="2026-11-16T13:27Z", verdict="none", tier="flagged")
    assert params[0].minute == 0 and params[1] - params[0] == timedelta(hours=1)
    assert title == "Hits: review and high tier, no AI verdict yet, first seen 2026-11-16 13:00 to 14:00 UTC"
    assert pages_live.list_filters()[:3] == ("Hits", "true", [])
    assert pages_live.window_key("1y") == "24h" and pages_live.window_key("30d") == "30d"
    # the verdict tiles' groups are fixed fragments too
    title, where, params, _, applied = pages_live.list_filters(verdict="cleared", tier="flagged", window="6h")
    assert where == "tier IN ('review', 'high') AND ai_verdict IN ('benign', 'parked') AND " \
                    "first_seen > now() - make_interval(hours => %s)" and params == [6]
    assert title == "Hits: review and high tier, AI verdict benign or parked, last 6 hours"
    _, where, params, _, _ = pages_live.list_filters(verdict="unjudged")
    assert where == "(ai_verdict IS NULL OR ai_verdict = 'error')" and params == []


# ---- routes ---------------------------------------------------------------------------------------------

def test_root_route_is_replaced_in_place():
    gets = [r for r in app_mod.app.router.routes if isinstance(r, APIRoute) and r.path == "/"]
    assert len(gets) == 1 and gets[0].endpoint is pages_live.overview_page
    paths = [getattr(r, "path", None) for r in app_mod.app.router.routes]
    assert paths.index("/") < paths.index("/api/recent") < paths.index("/live/list")
    assert {"/live/list", "/api/live/summary", "/api/live/minute", "/api/live/terrain", "/api/live/pipeline"} <= set(paths)
    assert ("/", "Overview") in app_mod.NAV and not any(p.startswith("/live") for p, _ in app_mod.NAV)


def test_overview_renders_every_section(conn):
    r = client().get("/")
    assert r.status_code == 200, r.text
    assert r.headers["content-security-policy"] == app_mod.CSP
    html = r.text
    b = body(html)
    assert "<title>CyberCheck · Overview</title>" in html and '<h1 id="ov-title">Threat overview</h1>' in b
    assert "Data from the last 24 hours. Times are UTC." in b
    assert re.search(r'<link rel="stylesheet" href="/static/overview\.css\?v=[0-9a-f]{10}">', html)
    assert re.search(r'<script src="/static/overview\.js\?v=[0-9a-f]{10}" defer></script>', html)
    # the top bar's segmented nav marks Overview as the current page
    assert re.search(r'class="nav-link is-active" href="/" aria-current="page"', html)
    # left column: big numbers (the integration test looks for the 5-minute certificate count), sparklines
    assert '<span class="stat-val" id="s-certs">3,552</span>' in b
    assert '<span class="stat-val" id="s-hits">6</span><span class="of"> / 2 high</span>' in b
    assert 'href="/live/list?window=24h"' in b
    spark = b[b.index('id="sp-hits"'):b.index("</figure>", b.index('id="sp-hits"'))]
    assert 'aria-label="Hits per 10 minutes, last 24 hours: 144 points, peak 3, total 6"' in spark
    assert "spark--peaks" in b[b.index('id="sp-high"') - 80:b.index('id="sp-high"')]
    assert 'aria-label="High-tier hits per hour, last 24 hours: 24 points, peak 2, total 2"' in b
    # what waits: links with their counts
    assert re.search(r'<a class="ov-chip ov-chip--red" href="/review" data-kpi="open_review">.*?'
                     r'<span class="kpi-val">7</span> <span class="ov-chip-l">wait for review, 2 high</span>', b, re.S)
    assert '<span class="kpi-val">4</span> <span class="ov-chip-l">reports to send, 1 failed to send</span>' in b
    # the terrain: canvas (hidden until JS draws it), the JSON source, the SVG fallback with linked marks
    stage = b[b.index('id="terrain"'):b.index('class="ov-right"')]
    assert 'data-src="/api/live/terrain?window=24h"' in stage and "<canvas" in stage and " hidden role=\"img\"" in stage
    assert 'aria-label="Threat terrain, last 24 hours: 6 hits by first-seen time and domain-name score, 2 high tier' in stage
    assert 'viewBox="0 0 480 310"' in stage and 'fill="url(#tf-grid)"' in stage and "<circle class=\"tf-h" in stage
    assert 'class="tf-mark tf-mark--red" href="/domain/5"' in stage and 'class="tf-mark tf-mark--green" href="/domain/3"' in stage
    assert "&lt;img src=x onerror=alert(1)&gt;.top: taken down" in stage                      # escaped in the fallback
    assert 'href="/?window=7d"' in stage and 'text="' not in stage                           # the window chip cycles
    assert 'data-layer="hits"' in stage and 'data-action="pause"' in stage and 'data-action="tier"' in stage
    assert 'aria-label="Terrain controls"' in stage
    # right column: the window control and three gauges, each a link to the list behind it
    right = b[b.index('class="ov-right"'):b.index('class="ov-bottom"')]
    assert 'href="/?window=24h" aria-current="page"' in right
    assert re.search(r'<a class="gauge" href="/live/list\?show=live-phishing">.*?aria-label="Live phishing pages: 2 of 9 \(22%\)"'
                     r'.*?<span class="gauge-val" id="g-live">2</span><span class="of"> / 9</span>', right, re.S)
    assert re.search(r'<a class="gauge" href="/review">.*?<span class="gauge-val" id="g-queue">7</span>'
                     r'<span class="of"> / 20</span>.*?13 decided in 7 days', right, re.S)
    assert 'data-gauge="ai"' in right and 'href="/ai"' in right
    # pipeline grid and verdict tiles
    pipe = b[b.index('id="pipeline"'):b.index('id="verdicts"')]
    assert 'role="img" aria-label="Pipeline by stage, last 24 hours: 2,500 certificates, 6 hits stored, 0 pages went live, ' \
           '2 domains judged by the AI, 0 confirmed phishing, 0 reported, 1 taken down."' in pipe
    for label in ("Seen in CT", "Scored", "Page live", "AI judged", "Confirmed", "Reported", "Taken down"):
        assert f'<span class="dg-label" aria-hidden="true">{label}</span>' in pipe, label
    assert 'class="dg-c dg-m dg-m--red" title="14:00 UTC: 2 domains judged by the AI, 1 phishing"' in pipe
    assert 'class="dg-c dg-m dg-m--green" title="13:00 UTC: 1 taken down"' in pipe
    assert 'href="/live/list?hour=2026-11-16T14:00Z&amp;tier=high">2</a>' in pipe            # the table under it
    assert "login.commbank-secure.top: AI phishing 97%, page live" in pipe                      # the newest notable one
    tiles = b[b.index('id="verdicts"'):b.index('class="ov-lower"')]
    for kind, label, href in (("red", "Phishing", "verdict=phishing"), ("amber", "Suspicious", "verdict=suspicious"),
                              ("green", "Benign or parked", "verdict=cleared"), ("grey", "Not judged", "verdict=unjudged")):
        assert re.search(r'<a class="tile tile--%s" href="/live/list\?%s&amp;tier=flagged&amp;window=24h">.*?%s'
                         % (kind, href, label), tiles, re.S), label
    assert '<span class="tile-val" id="t-phishing">2</span><span class="of"> / 2</span>' in tiles
    assert '<span class="tile-val" id="t-unjudged">8</span><span class="of"> / 10</span>' in tiles
    # the same split as one bar: SVG attributes only, the numbers in its label, empty parts left out
    assert ('role="img" aria-label="Of 10 review and high tier hits: 2 phishing, 0 suspicious, 0 benign or parked, '
            '8 not judged"') in tiles
    assert '<rect class="ov-mix-red" x="0.00" y="0" width="19.40" height="6" rx="1"/>' in tiles
    assert '<rect class="ov-mix-grey" x="20.00" y="0" width="79.40" height="6" rx="1"/>' in tiles
    assert "ov-mix-amber" not in tiles.split("ov-mix-legend")[0] and "style=" not in tiles
    assert "20% phishing" in tiles and "80% not judged" in tiles
    # live feed: newest first, max id for polling, polite live region, escaped hostile text, IDN display form
    feed = b[b.index('<ol class="feed"'):b.index("</ol>", b.index('<ol class="feed"'))]
    assert 'data-max-id="5"' in feed and 'data-src="/api/recent"' in feed
    assert [int(x) for x in re.findall(r'<li class="fl [^"]*" data-id="(\d+)"', feed)] == [5, 4, 3, 2]
    assert EVIL not in html and "&lt;img src=x onerror=alert(1)&gt;.top" in feed
    assert "commbаnk-login.top" in feed and 'href="/domain/4"' in feed
    assert "AI phishing" in feed and ">live<" in feed and "false positive" in feed
    state = b[b.index('id="feed-state"') - 80:b.index('id="feed-state"') + 80]
    assert 'role="status"' in state and 'aria-live="polite"' in state
    # brands: bars as SVG attributes, links carry the window
    assert 'href="/live/list?brand=commbank&amp;window=24h"' in b and "&lt;b&gt;x&lt;/b&gt;" in b
    assert '<rect class="bar-high" x="0" y="0" width="40.0" height="4"/>' in b
    # one query each, bounded by the window
    assert next(p for s, p in conn.sql if "GROUP BY brand_id" in s) == (24,)
    hits_sql = next(p for s, p in conn.sql if "AS col, score" in s)
    assert hits_sql == {"start": datetime(2026, 11, 15, 15, tzinfo=timezone.utc),
                        "end": datetime(2026, 11, 16, 15, tzinfo=timezone.utc), "step": 300}
    assert next(p for s, p in conn.sql if "GROUPING SETS" in s)["step"] == 3600
    assert next(p for s, p in conn.sql if "LIMIT %(limit)s" in s)["limit"] == pages_live.MARKS_LIMIT
    # nothing the CSP would block, nothing external, no attacker URL as a link
    assert "style=" not in b and "<style" not in html and not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+\s*=", html.replace("&lt;img src=x onerror=alert(1)&gt;", ""))
    assert "http://" not in b and "https://" not in b


def test_overview_window_parameter(conn):
    html = client().get("/?window=7d").text
    assert next(p for s, p in conn.sql if "GROUP BY brand_id" in s) == (168,)
    assert next(p for s, p in conn.sql if "AS col, score" in s)["step"] == 1800
    assert 'href="/?window=7d" aria-current="page"' in html and "Data from the last 7 days." in html
    assert 'href="/?window=6h"' in html[html.index('id="tf-window"') - 200:html.index('id="tf-window"')]
    conn.sql.clear()
    pages_live.reset_cache()
    r = client().get("/?window=%27%3B--")
    assert r.status_code == 200 and next(p for s, p in conn.sql if "GROUP BY brand_id" in s) == (24,)
    conn.sql.clear()
    client().get("/?window=30d")                                  # list-only windows fall back to 24 h here
    assert next(p for s, p in conn.sql if "GROUP BY brand_id" in s) == (24,)
    # the terrain is cached per window: a second render does not query it again
    assert not any("AS col, score" in s for s, _ in conn.sql)


def test_overview_on_an_empty_database(monkeypatch):
    conn = use(monkeypatch, FakeConn(kpi={}, feed=[]))
    conn.execute_orig = conn.execute

    async def empty(sql, params=()):
        cur = await conn.execute_orig(sql, params)
        s = " ".join(sql.split())
        if any(x in s for x in ("AS col, score", "count(DISTINCT minute)", "LIMIT %(limit)s", "GROUPING SETS",
                                "GROUP BY brand_id", "COALESCE(ai_verdict, 'none')")):
            return Cur([])
        return cur
    conn.execute = empty
    r = client().get("/")
    assert r.status_code == 200, r.text
    b = body(r.text)
    assert "No suspicious domains yet." in b and 'data-max-id="0"' in b
    assert '<span class="kpi-val">0</span> <span class="ov-chip-l">wait for review</span>' in b
    assert '<span class="stat-val" id="s-certs">0</span>' in b
    assert "Nothing to judge in the last 24 hours." in b and "No hits in the last 24 hours." in b
    assert "tf-mark" not in b and "ov-latest" not in b
    assert 'aria-label="Live phishing pages: 0 of 0"' in b                      # an empty ring, no percentage


def test_overview_template_works_with_the_app_py_contract():
    """app.py's own "/" handler passes only stats and rows: the page still renders (the numbers and the feed)."""
    t = common.templates.env.get_template("overview.html")
    stats = {k: KPI[k] for k in ("certs_5m", "certs_24h", "hits_24h", "high_24h", "open_review", "total",
                                 "confirmed", "live", "last_hit")}
    stats["heartbeat"] = NOW
    html = t.render(stats=stats, rows=FEED)
    assert "3,552" in html and 'data-max-id="5"' in html and "terrain" not in html.split("<main")[-1]
    assert 'data-kpi="open_review"' in html and "&lt;img src=x" in html and "<h1>Threat overview</h1>" in html
    assert "No suspicious domains yet." in t.render(stats=stats, rows=[])


def test_overview_template_has_no_inline_script_style_or_handlers():
    src = re.sub(r"\{#.*?#\}", "", (TEMPLATES / "overview.html").read_text(encoding="utf-8"), flags=re.S)
    assert "style=" not in src and "<style" not in src
    assert not re.search(r"<script(?![^>]*\bsrc=)", src)
    assert not re.search(r"\son[a-z]+\s*=", src)
    assert "|safe" not in src.replace(" ", "") and "Markup" not in src
    js = (STATIC / "overview.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "eval(" not in js and "http" not in js.replace("https://", "")
    css = (STATIC / "overview.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css


def test_overview_static_files_are_served(conn):
    c = client()
    r = c.get("/static/overview.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"] and "/api/recent" in r.text
    r = c.get("/static/overview.css")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css")


def test_live_list_route(conn):
    r = client().get("/live/list", params={"show": "live-phishing", "brand": "commbank", "window": "24h"})
    assert r.status_code == 200, r.text
    assert "<h1>Live phishing pages: commbank, last 24 hours</h1>" in r.text and 'href="/domain/5"' in r.text
    assert "an AI phishing verdict and the page was live at the last check." in r.text
    assert 'href="/">Back to the overview</a>' in r.text and "<tbody id=\"rows\" data-rows>" in r.text
    assert "style=" not in body(r.text) and "AI phishing" in r.text
    sql, params = next((s, p) for s, p in conn.sql if s.startswith("SELECT * FROM domains WHERE"))
    assert "ai_verdict = 'phishing' AND live_state = 'live'" in sql and sql.endswith("LIMIT 300")
    assert "ORDER BY last_live_at DESC NULLS LAST, id DESC" in sql and params == ("commbank", 24)
    conn.sql.clear()
    r = client().get("/live/list", params={"show": "x' OR 1=1 --", "tier": "high; DELETE", "at": "bad"})
    assert r.status_code == 200
    sql, params = next((s, p) for s, p in conn.sql if s.startswith("SELECT * FROM domains WHERE"))
    assert sql.startswith("SELECT * FROM domains WHERE true ORDER BY first_seen DESC") and params == ()


def test_api_summary(conn):
    r = client().get("/api/live/summary")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    j = r.json()
    for k in ("open_review", "open_high", "live_phishing", "confirmed_week", "taken_down", "taken_down_7d",
              "reports_waiting", "reports_failed", "certs_5m", "certs_24h", "hits_24h", "high_24h"):
        assert isinstance(j[k], int), k
    assert j["live_phishing"] == 2 and j["heartbeat"] == NOW.isoformat()
    assert len(j["recent"]) == pages_live.HEAT_RECENT_MIN and j["recent"][-1] == {
        "t": "2026-11-16T14:30Z", "c": 400, "review": 1, "high": 2}
    assert "ai" in j and "ai_spent_today" in j
    # /api is not a page: the status line cache is not refreshed by the middleware (the route asks for it)
    assert sum("ai_today" in s for s, _ in conn.sql) == 1


def test_api_minute(conn):
    c = client()
    assert c.get("/api/live/minute").status_code == 400
    assert c.get("/api/live/minute", params={"at": "yesterday"}).status_code == 400
    r = c.get("/api/live/minute", params={"at": "2026-11-16T14:30Z"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    j = r.json()
    assert j["t"] == "2026-11-16T14:30Z" and j["certs"] == 400 and j["total"] == 3
    assert j["list"] == "/live/list?at=2026-11-16T14:30Z"
    assert j["hits"][0]["id"] == 5 and j["hits"][0]["host"] == "login.commbank-secure.top"
    sql, params = next((s, p) for s, p in conn.sql if "hostnames[1] AS hostname, brand_id, tier" in s)
    assert params[1] - params[0] == timedelta(minutes=1) and params[2] == pages_live.MINUTE_HITS_LIMIT


def test_api_terrain(conn):
    r = client().get("/api/live/terrain", params={"window": "24h"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    j = r.json()
    assert (j["window"], j["cols"], j["rows"], j["step"], j["now_col"]) == ("24h", 288, 31, 300, 282)
    assert j["start"] == "2026-11-15T15:00:00+00:00" and j["end"] == "2026-11-16T15:00:00+00:00"
    assert len(j["levels"]) == 31 and all(len(x) == 288 and set(x) <= set(pages_live.LEVELS) for x in j["levels"])
    assert [282, 22, 2] in j["cells"] and j["cpm"][282] == 400 and j["total"]["hits"] == 6
    assert j["buckets"][23]["start"] == "2026-11-16T14:00:00+00:00"
    marks = {m["id"]: m for m in j["marks"]}
    assert marks[5]["kind"] == "danger" and marks[3]["kind"] == "protected" and marks[3]["host"] == EVIL
    # an unknown window falls back; the hits query only ever gets parameters
    j = client().get("/api/live/terrain", params={"window": "x'; DROP TABLE domains;--"}).json()
    assert j["window"] == "24h"
    assert all("DROP" not in s for s, _ in conn.sql)


def test_api_pipeline(conn):
    r = client().get("/api/live/pipeline", params={"window": "6h"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    j = r.json()
    assert j["window"] == "6h" and j["bucket"] == 900 and len(j["rows"]) == 7
    assert [x["key"] for x in j["rows"]] == ["ct", "scored", "went_live", "ai_verdict", "confirmed", "reported", "taken_down"]
    assert all(len(x["counts"]) == 24 and len(x["markers"]) == 24 for x in j["rows"])
    assert j["label"].startswith("Pipeline by stage, last 6 hours: ")
    ev = next(p for s, p in conn.sql if "GROUPING SETS" in s)
    assert ev["step"] == 900 and ev["end"] - ev["start"] == timedelta(hours=6)


def test_new_routes_sit_behind_the_host_allowlist(conn):
    c = TestClient(app_mod.app, base_url="http://rebind.attacker.example:8430")
    for path in ("/", "/live/list", "/api/live/summary", "/api/live/minute?at=2026-11-16T14:30Z",
                 "/api/live/terrain", "/api/live/pipeline", "/static/overview.js"):
        assert c.get(path).status_code == 400, path
    assert conn.sql == []
