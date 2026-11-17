"""The overview page ("/"): the threat terrain, gauges, pipeline grid, AI verdict tiles and the live hit feed.

Routes (all GET, read-only):
- "/"                    the overview. It replaces app.py's "/" route in place (register() below), with the same
                         template contract plus a `live` dict, so app.py's own handler still renders the page if
                         this module is ever left out (the template degrades to the numbers and the feed).
- /live/list             the list behind every number on the overview (LIST_TEMPLATE below).
- /api/live/summary      KPI and gauge values, polled by static/overview.js.
- /api/live/terrain      the threat terrain: hits by first-seen time and domain-name score, kernel-smoothed, over
                         the certificate rate, plus the notable domains to pin on it (overview.js draws it).
- /api/live/pipeline     domains per pipeline stage and time bucket (seen, scored, live, judged, confirmed, ...).
- /api/live/minute?at=   one minute: certificates and the hits first seen in it.

Request input never reaches SQL text: filters pick fixed fragments by key and pass values as parameters. Every
query is bounded by an indexed time range (domains.first_seen, ingest_stats.minute, domain_events (kind, at)),
and the terrain and pipeline are cached for TERRAIN_TTL_S per window.
"""
from __future__ import annotations

import logging
import math
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import db
from .common import clean_param, compact, refresh_status

log = logging.getLogger(__name__)
_templates = None          # set by register()

HEAT_RECENT_MIN = 15       # minutes /api/live/summary returns as "recent" (certificates and hits a minute)
FEED_LIMIT = 100
LIST_LIMIT = 300
MINUTE_HITS_LIMIT = 20

# List windows (/live/list?window=): key -> (hours, label)
WINDOWS = {"6h": (6, "last 6 hours"), "24h": (24, "last 24 hours"), "7d": (24 * 7, "last 7 days"),
           "30d": (24 * 30, "last 30 days")}
DEFAULT_WINDOW = "24h"

# Overview windows: key -> (hours, terrain column seconds, pipeline bucket seconds, label, short label).
# The sparkline bucket is two terrain columns. The window ends at the next pipeline-bucket boundary, so buckets
# are clock-aligned (whole UTC hours for 24 h) and the last one is partly in the future.
VIEWS = {
    "6h": (6, 180, 900, "last 6 hours", "6 h"),
    "24h": (24, 300, 3600, "last 24 hours", "24 h"),
    "7d": (24 * 7, 1800, 6 * 3600, "last 7 days", "7 d"),
}
SCORE_MIN, SCORE_MAX, SCORE_STEP = 40, 100, 2      # terrain rows: domain-name score 40..100, two points a row
SCORE_ROWS = (SCORE_MAX - SCORE_MIN) // SCORE_STEP + 1
LEVELS = "0123456789abcdefghijklmnopqrstuvwxyz"    # terrain intensity, one character a cell (0 = none)
# Gaussian smoothing in (columns, rows). A column is a few pixels wide and a row about twenty, so the column sigma is
# larger: the blobs come out round on screen, not as vertical streaks.
KERNEL_SIGMA = (5.0, 1.3)
KERNEL_RADIUS = (13, 3)
HITS_SCALE = 2.5                                   # density (hits) at which the terrain is ~63 % bright
MARKS_LIMIT = 16
TERRAIN_TTL_S = 20.0

# Fixed WHERE fragments for the KPIs and their lists: key -> (title, SQL, ORDER BY, explanation)
PRESETS = {
    "live-phishing": (
        "Live phishing pages",
        "ai_verdict = 'phishing' AND live_state = 'live' AND status NOT IN ('false_positive', 'benign')",
        "last_live_at DESC NULLS LAST, id DESC",
        "an AI phishing verdict and the page was live at the last check"),
    "confirmed-week": (
        "Confirmed this week",
        "status = 'confirmed' AND status_changed_at > now() - interval '7 days'",
        "status_changed_at DESC, id DESC",
        "confirmed as phishing by a reviewer in the last 7 days"),
    # the same scope as /takedown?scope=tracked (pages_takedown.SCOPES["tracked"]), so the counts agree
    "taken-down": (
        "Taken down",
        "takedown_at IS NOT NULL AND status NOT IN ('false_positive', 'benign') AND "
        "(status = 'confirmed' OR reported_at IS NOT NULL OR ai_verdict = 'phishing')",
        "takedown_at DESC, id DESC",
        "confirmed, reported or judged phishing, and now gone"),
}
# Verdict groups for the overview's verdict tiles (fixed fragments, like PRESETS)
VERDICT_GROUPS = {"cleared": ("ai_verdict IN ('benign', 'parked')", "AI verdict benign or parked"),
                  "unjudged": ("(ai_verdict IS NULL OR ai_verdict = 'error')", "not judged by the AI")}
TIERS = {"high": "tier = 'high'", "review": "tier = 'review'", "watch": "tier = 'watch'",
         "flagged": "tier IN ('review', 'high')"}
TIER_WORDS = {"high": "high tier", "review": "review tier", "watch": "watch tier", "flagged": "review and high tier"}
# AI verdicts in display order: (key, label, tone, glyph). Colour is never alone: glyph and text go with it.
VERDICTS = [("phishing", "phishing", "red", "■"), ("suspicious", "suspicious", "amber", "▲"),
            ("benign", "benign", "teal", "✓"), ("parked", "parked", "muted", "–"),
            ("error", "could not judge", "muted", "!"), ("none", "not judged yet", "muted", "?")]
VERDICT_KEYS = {v[0] for v in VERDICTS}

KPI_SQL = f"""
SELECT
  (SELECT COALESCE(sum(certs), 0) FROM ingest_stats WHERE minute > now() - interval '5 minutes') AS certs_5m,
  (SELECT COALESCE(sum(hostnames), 0) FROM ingest_stats WHERE minute > now() - interval '5 minutes') AS hosts_5m,
  (SELECT COALESCE(sum(certs), 0) FROM ingest_stats WHERE minute > now() - interval '24 hours') AS certs_24h,
  (SELECT count(*) FROM domains WHERE first_seen > now() - interval '24 hours') AS hits_24h,
  (SELECT count(*) FROM domains WHERE first_seen > now() - interval '24 hours' AND tier = 'high') AS high_24h,
  (SELECT count(*) FROM domains WHERE status = 'open' AND tier IN ('review', 'high')) AS open_review,
  (SELECT count(*) FROM domains WHERE status = 'open' AND tier = 'high') AS open_high,
  (SELECT count(*) FROM domains) AS total,
  (SELECT count(*) FROM domains WHERE status = 'confirmed') AS confirmed,
  (SELECT count(*) FROM domains WHERE live_state = 'live') AS live,
  (SELECT count(*) FROM domains WHERE {PRESETS['live-phishing'][1]}) AS live_phishing,
  (SELECT count(*) FROM domains WHERE {PRESETS['confirmed-week'][1]}) AS confirmed_week,
  (SELECT count(*) FROM domains WHERE {PRESETS['taken-down'][1]}) AS taken_down,
  (SELECT count(*) FROM domains WHERE {PRESETS['taken-down'][1]}
     AND takedown_at > now() - interval '7 days') AS taken_down_7d,
  (SELECT count(*) FROM domains WHERE ai_verdict IS NOT NULL AND ai_verdict <> 'error') AS judged,
  (SELECT count(*) FROM domains WHERE status <> 'open' AND tier IN ('review', 'high')
     AND status_changed_at > now() - interval '7 days') AS decided_week,
  (SELECT count(*) FROM reports WHERE status = 'pending_review') AS reports_waiting,
  (SELECT count(*) FROM reports WHERE status = 'failed') AS reports_failed,
  (SELECT max(first_seen) FROM domains) AS last_hit,
  (SELECT updated_at FROM kv WHERE key = 'ingest:heartbeat') AS heartbeat,
  now() AS db_now
"""
KPI_KEYS = ("certs_5m", "hosts_5m", "certs_24h", "hits_24h", "high_24h", "open_review", "open_high", "total",
            "confirmed", "live", "live_phishing", "confirmed_week", "taken_down", "taken_down_7d",
            "judged", "decided_week", "reports_waiting", "reports_failed")

FEED_SQL = "SELECT * FROM domains ORDER BY id DESC LIMIT %s"
HEAT_CERTS_SQL = ("SELECT minute, sum(certs)::bigint AS certs FROM ingest_stats "
                  "WHERE minute >= %s AND minute <= %s GROUP BY minute")
HEAT_HITS_SQL = ("SELECT date_trunc('minute', first_seen) AS minute, "
                 "count(*) FILTER (WHERE tier = 'review') AS review, count(*) FILTER (WHERE tier = 'high') AS high "
                 "FROM domains WHERE first_seen >= %s AND tier IN ('review', 'high') GROUP BY 1")
BRANDS_SQL = """
SELECT brand_id, count(*) AS n, count(*) FILTER (WHERE tier = 'high') AS high,
       count(*) FILTER (WHERE tier = 'review') AS review, count(*) FILTER (WHERE tier = 'watch') AS watch
FROM domains WHERE first_seen > now() - make_interval(hours => %s) AND brand_id IS NOT NULL
GROUP BY brand_id ORDER BY n DESC, brand_id LIMIT 10
"""
VERDICT_SQL = """
SELECT COALESCE(ai_verdict, 'none') AS verdict, count(*) AS n FROM domains
WHERE first_seen > now() - make_interval(hours => %s) AND tier IN ('review', 'high')
GROUP BY 1
"""
MINUTE_SQL = """
SELECT id, registered_domain, unicode_domain, hostnames[1] AS hostname, brand_id, tier, score, final_score, status,
       ai_verdict, live_state, first_seen
FROM domains WHERE first_seen >= %s AND first_seen < %s
ORDER BY COALESCE(final_score, score) DESC, id DESC LIMIT %s
"""
MINUTE_CERTS_SQL = "SELECT COALESCE(sum(certs), 0) AS certs FROM ingest_stats WHERE minute = %s"
MINUTE_COUNT_SQL = "SELECT count(*) AS n FROM domains WHERE first_seen >= %s AND first_seen < %s"

# ---- terrain and pipeline (all bounded by an indexed time range; %(start)s/%(end)s/%(step)s are parameters) ----
NOW_SQL = "SELECT now() AS db_now"
# hits by terrain column and domain-name score (domains_first_seen_idx)
TERRAIN_HITS_SQL = """
SELECT floor(extract(epoch FROM (first_seen - %(start)s)) / %(step)s)::int AS col, score,
       count(*) AS n, count(*) FILTER (WHERE tier = 'high') AS high, count(*) FILTER (WHERE tier = 'review') AS review
FROM domains WHERE first_seen >= %(start)s AND first_seen < %(end)s
GROUP BY 1, 2
"""
# certificates by terrain column (ingest_stats primary key: minute, source)
TERRAIN_CERTS_SQL = """
SELECT floor(extract(epoch FROM (minute - %(start)s)) / %(step)s)::int AS col, sum(certs)::bigint AS certs,
       count(DISTINCT minute) AS minutes
FROM ingest_stats WHERE minute >= %(start)s AND minute < %(end)s
GROUP BY 1
"""
# notable domains to pin on the terrain: taken down, confirmed, AI phishing or suspicious, or live and not judged
TERRAIN_MARKS_SQL = """
SELECT id, registered_domain, unicode_domain, hostnames[1] AS hostname, brand_id, tier, score, final_score, status,
       ai_verdict, ai_confidence, live_state, first_seen, takedown_at
FROM domains
WHERE first_seen >= %(start)s AND first_seen < %(end)s AND status NOT IN ('false_positive', 'benign')
  AND (takedown_at IS NOT NULL OR status = 'confirmed' OR ai_verdict IN ('phishing', 'suspicious')
       OR (live_state = 'live' AND (ai_verdict IS NULL OR ai_verdict = 'error')))
ORDER BY CASE WHEN ai_verdict = 'phishing' AND live_state = 'live' THEN 0 WHEN status = 'confirmed' THEN 1
              WHEN ai_verdict = 'phishing' THEN 2 WHEN takedown_at IS NOT NULL THEN 3
              WHEN ai_verdict = 'suspicious' THEN 4 ELSE 5 END,
         COALESCE(final_score, score) DESC, id DESC
LIMIT %(limit)s
"""
# pipeline stages from the event log (domain_events_kind_idx: kind, at). Distinct domains per bucket, and per
# stage over the whole window (the grouping set with col NULL).
PIPELINE_EVENTS_SQL = """
SELECT CASE WHEN kind = 'status' THEN 'confirmed' ELSE kind END AS stage,
       floor(extract(epoch FROM (at - %(start)s)) / %(step)s)::int AS col,
       count(DISTINCT domain_id) AS n,
       count(DISTINCT domain_id) FILTER (WHERE kind = 'ai_verdict' AND detail->>'verdict' = 'phishing') AS phishing
FROM domain_events
WHERE at >= %(start)s AND at < %(end)s
  AND (kind IN ('went_live', 'ai_verdict', 'reported', 'taken_down')
       OR (kind = 'status' AND detail->>'status' = 'confirmed'))
GROUP BY GROUPING SETS ((1, 2), (1))
"""


# ---- pure helpers (unit-tested without a database) ---------------------------------------------------------

def iso_minute(ts: datetime) -> str:
    """A minute as the compact UTC text the heatmap and /live/list use: 2026-11-16T14:05Z."""
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def parse_minute(value: str | None) -> datetime | None:
    """'2026-11-16T14:05Z' (or any ISO time; naive means UTC) -> that minute, tz-aware UTC. None when invalid."""
    s = (value or "").strip()
    if not s or len(s) > 40:
        return None
    try:
        ts = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(timezone.utc)
    if not 2000 <= ts.year <= 2200:
        return None
    return ts.replace(second=0, microsecond=0)


def window_key(value: str | None) -> str:
    return value if value in WINDOWS else DEFAULT_WINDOW


def _minute(ts) -> datetime | None:
    try:
        ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
    except AttributeError:
        return None


def recent_minutes(cert_rows, hit_rows, end: datetime, n: int = HEAT_RECENT_MIN) -> list[dict]:
    """The newest n minutes up to `end`, zeros included, for overview.js to repaint the newest dots."""
    end = _minute(end)
    certs, hits = {}, {}
    for r in cert_rows or ():
        k = _minute(r.get("minute"))
        if k is not None:
            certs[k] = certs.get(k, 0) + int(r.get("certs") or 0)
    for r in hit_rows or ():
        k = _minute(r.get("minute"))
        if k is not None:
            rv, hi = hits.get(k, (0, 0))
            hits[k] = (rv + int(r.get("review") or 0), hi + int(r.get("high") or 0))
    out = []
    for i in range(n - 1, -1, -1):
        k = end - timedelta(minutes=i)
        rv, hi = hits.get(k, (0, 0))
        out.append({"t": iso_minute(k), "c": certs.get(k, 0), "review": rv, "high": hi})
    return out


def brand_bars(rows, names: dict | None = None) -> list[dict]:
    """Top brands as bar segments in a 0-100 viewBox (SVG attributes, never style=): the longest bar is 100."""
    names = names or {}
    rows = [dict(r) for r in rows or ()]
    top = max((int(r.get("n") or 0) for r in rows), default=0)
    out = []
    for r in rows:
        n = int(r.get("n") or 0)
        hi, rv, wa = (int(r.get(k) or 0) for k in ("high", "review", "watch"))
        scale = 100.0 / top if top else 0
        w_hi, w_rv, w_wa = round(hi * scale, 2), round(rv * scale, 2), round(wa * scale, 2)
        out.append({"brand_id": r.get("brand_id"), "name": names.get(r.get("brand_id")) or r.get("brand_id"),
                    "n": n, "high": hi, "review": rv, "watch": wa,
                    "segs": [s for s in (("high", 0, w_hi), ("review", w_hi, w_rv), ("watch", w_hi + w_rv, w_wa))
                             if s[2] > 0]})
    return out


def verdict_mix(rows) -> dict:
    """AI verdict counts in display order, with x/width in a 0-100 viewBox for one stacked bar."""
    counts = {}
    for r in rows or ():
        v = r.get("verdict") or "none"
        v = v if v in VERDICT_KEYS else "error"
        counts[v] = counts.get(v, 0) + int(r.get("n") or 0)
    total = sum(counts.values())
    items, x = [], 0.0
    for key, label, tone, glyph in VERDICTS:
        n = counts.get(key, 0)
        w = round(100.0 * n / total, 2) if total else 0
        pct = round(100.0 * n / total) if total else 0
        items.append({"key": key, "label": label, "tone": tone, "glyph": glyph, "n": n, "pct": pct,
                      "x": round(x, 2), "w": w})
        x += w
    judged = total - counts.get("none", 0)
    return {"parts": items, "total": total, "judged": judged}


def kpi_values(row: dict | None) -> dict:
    out = {k: int((row or {}).get(k) or 0) for k in KPI_KEYS}
    for k in ("last_hit", "heartbeat", "db_now"):
        out[k] = (row or {}).get(k)
    return out


# ---- terrain, pipeline, verdict tiles (pure; unit-tested) ---------------------------------------------------

STAGES = [("ct", "Seen in CT", "certificates"), ("scored", "Scored", "hits stored"),
          ("went_live", "Page live", "pages went live"), ("ai_verdict", "AI judged", "domains judged by the AI"),
          ("confirmed", "Confirmed", "confirmed phishing"), ("reported", "Reported", "reported"),
          ("taken_down", "Taken down", "taken down")]


def view_key(value: str | None) -> str:
    return value if value in VIEWS else DEFAULT_WINDOW


def _aware(ts: datetime | None) -> datetime:
    ts = ts or datetime.now(timezone.utc)
    return (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def view_bounds(now: datetime | None, window: str = DEFAULT_WINDOW) -> dict:
    """The overview's time frame: the window ends at the next pipeline-bucket boundary after now (UTC), so the
    buckets are clock-aligned. cols terrain columns of step seconds; buckets pipeline buckets of bucket seconds."""
    key = view_key(window)
    hours, step, bucket, label, short = VIEWS[key]
    now = _aware(now)
    end = datetime.fromtimestamp((math.floor(now.timestamp() / bucket) + 1) * bucket, timezone.utc)
    start = end - timedelta(hours=hours)
    cols = hours * 3600 // step
    now_col = max(0, min(cols - 1, int((now - start).total_seconds() // step)))
    return {"window": key, "hours": hours, "label": label, "short": short, "start": start, "end": end, "now": now,
            "step": step, "bucket": bucket, "cols": cols, "now_col": now_col, "per_bucket": bucket // step,
            "buckets": hours * 3600 // bucket, "now_bucket": now_col // (bucket // step)}


def score_row(score) -> int:
    """Terrain row of a domain-name score: 0 is SCORE_MIN (40), SCORE_ROWS - 1 is 100. Out of range clamps."""
    try:
        s = int(score)
    except (TypeError, ValueError):
        s = SCORE_MIN
    s = max(SCORE_MIN, min(SCORE_MAX, s))
    return (s - SCORE_MIN) // SCORE_STEP


def tier_thresholds() -> tuple[int, int]:
    """(review, high) domain-name score thresholds from the settings, for the terrain's colour bands."""
    try:
        from .. import config
        st = config.settings()
        return int(st.review_threshold), int(st.high_threshold)
    except Exception:
        return 60, 75


def smooth(counts: dict, cols: int, rows: int = SCORE_ROWS, sigma=KERNEL_SIGMA, radius=KERNEL_RADIUS) -> list:
    """Gaussian kernel density of sparse counts {(col, row): n} on a rows x cols grid (list of rows of floats).
    Sparse: each non-zero cell adds its kernel patch, so the cost follows the number of hits, not the grid."""
    sc, sr = sigma
    rc, rr = radius
    kc = [math.exp(-(d * d) / (2 * sc * sc)) for d in range(-rc, rc + 1)]
    kr = [math.exp(-(d * d) / (2 * sr * sr)) for d in range(-rr, rr + 1)]
    grid = [[0.0] * cols for _ in range(rows)]
    for (c, r), n in counts.items():
        if not n:
            continue
        for j, wr in enumerate(kr):
            y = r + j - rr
            if not 0 <= y < rows:
                continue
            line = grid[y]
            for i, wc in enumerate(kc):
                x = c + i - rc
                if 0 <= x < cols:
                    line[x] += n * wr * wc
    return grid


def encode_levels(grid: list, scale: float = HITS_SCALE, floor: float = 0.03) -> list[str]:
    """Each row of a density grid as one character a cell from LEVELS (0 = nothing, z = saturated).

    The scale is absolute, not relative to the busiest spot: intensity = 1 - exp(-density / scale), where one hit
    has density 1 at its centre. So a lone hit always shows (about a third), a handful of hits in one place
    saturates, and the same picture means the same thing in every window. Densities under floor count as none."""
    top = len(LEVELS) - 1
    out = []
    for line in grid:
        chars = []
        for v in line:
            chars.append("0" if v < floor else LEVELS[max(1, min(top, int(round(top * (1 - math.exp(-v / scale))))))])
        out.append("".join(chars))
    return out


def _n(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def mark_kind(m: dict) -> tuple[str, str]:
    """(badge kind, short label) of a notable domain. Taken down wins, then confirmed, then the AI verdict."""
    live = ", page live" if m.get("live_state") == "live" else ""
    if m.get("takedown_at"):
        return "protected", "taken down"
    if m.get("status") == "confirmed":
        return "danger", "confirmed phishing" + live
    v, conf = m.get("ai_verdict"), m.get("ai_confidence")
    pct = f" {round(float(conf) * 100)}%" if conf is not None else ""
    if v == "phishing":
        return "danger", "AI phishing" + pct + live
    if v == "suspicious":
        return "alert", "AI suspicious" + pct + live
    return "unknown", "page live, not judged yet"


def terrain_mark(m: dict, view: dict, names: dict | None = None) -> dict:
    """A notable domain for the terrain: where it sits (x 0..1 across the window, score) and what it is. host,
    unicode and brand are attacker-controlled: overview.js puts them in the page as text only."""
    names = names or {}
    kind, what = mark_kind(m)
    seen = _aware(m.get("first_seen"))
    span = (view["end"] - view["start"]).total_seconds() or 1
    return {"id": _n(m.get("id")), "host": m.get("hostname") or m.get("registered_domain") or "",
            "unicode": m.get("unicode_domain") or None, "brand": names.get(m.get("brand_id")) or m.get("brand_id"),
            "tier": m.get("tier"), "score": _n(m.get("score")), "final": m.get("final_score"), "kind": kind,
            "what": what, "t": seen.isoformat(),
            "time": seen.strftime("%a %d %b %H:%M UTC" if view["hours"] > 24 else "%H:%M UTC"),
            "x": round(max(0.0, min(1.0, (seen - view["start"]).total_seconds() / span)), 4)}


def terrain(view: dict, hit_rows, cert_rows, mark_rows=(), names: dict | None = None,
            thresholds: tuple[int, int] = (60, 75)) -> dict:
    """The threat terrain for one window, as overview.js and the no-JS SVG draw it.

    hit_rows: [{"col", "score", "n", "high", "review"}] (TERRAIN_HITS_SQL); cert_rows: [{"col", "certs"}].
    Returns levels (one string a score row, row 0 = score 40, see encode_levels), cells (the raw counts as
    [col, row, n]), cpm (certificates a minute per column), per-column hits, sparkline and peak series, the
    per-bucket summary and the marks."""
    cols, step = view["cols"], view["step"]
    counts: dict = {}
    hits, high, review = [0] * cols, [0] * cols, [0] * cols
    for r in hit_rows or ():
        c = r.get("col")
        if c is None or not 0 <= int(c) < cols:
            continue
        c, n = int(c), _n(r.get("n"))
        key = (c, score_row(r.get("score")))
        counts[key] = counts.get(key, 0) + n
        hits[c] += n
        high[c] += _n(r.get("high"))
        review[c] += _n(r.get("review"))
    certs = [0] * cols
    for r in cert_rows or ():
        c = r.get("col")
        if c is not None and 0 <= int(c) < cols:
            certs[int(c)] += _n(r.get("certs"))
    per_min = step / 60.0
    cpm = [int(round(v / per_min)) for v in certs]
    per = view["per_bucket"]
    buckets = []
    for b in range(view["buckets"]):
        sl = slice(b * per, (b + 1) * per)
        start = view["start"] + timedelta(seconds=b * view["bucket"])
        buckets.append({"t": iso_minute(start), "start": start, "certs": sum(certs[sl]), "hits": sum(hits[sl]),
                        "high": sum(high[sl]), "review": sum(review[sl]), "future": b > view["now_bucket"]})
    spark = [sum(hits[i:i + 2]) for i in range(0, cols, 2)]
    review_t, high_t = thresholds
    return {
        "window": view["window"], "label": view["label"], "short": view["short"],
        "start": view["start"].isoformat(), "end": view["end"].isoformat(), "now": view["now"].isoformat(),
        "step": step, "cols": cols, "now_col": view["now_col"],
        "rows": SCORE_ROWS, "score_min": SCORE_MIN, "score_step": SCORE_STEP,
        "review_at": review_t, "high_at": high_t,
        "levels": encode_levels(smooth(counts, cols)),
        "cells": sorted([c, r, n] for (c, r), n in counts.items() if n),
        "cpm": cpm, "cpm_max": max(cpm, default=0), "hits": hits,
        "total": {"hits": sum(hits), "high": sum(high), "review": sum(review), "certs": sum(certs)},
        "spark": spark, "spark_step": step * 2,
        "peaks": [b["high"] for b in buckets],
        "buckets": buckets,
        "marks": [terrain_mark(m, view, names) for m in (mark_rows or ())],
    }


def bucket_label(view: dict, b: int) -> str:
    start = view["start"] + timedelta(seconds=b * view["bucket"])
    if view["hours"] > 24:
        return start.strftime("%a %d %b %H:00 UTC")
    return start.strftime("%H:%M UTC")


def pipeline(view: dict, ter: dict, event_rows) -> dict:
    """Domains per pipeline stage and bucket for ui.dot_grid: rows Seen in CT .. Taken down, one dot a bucket
    sized by its share of the row's busiest bucket, an empty ring for buckets still in the future, and markers on
    buckets with an AI phishing verdict (danger) or a takedown (protected)."""
    nb, now_b = view["buckets"], view["now_bucket"]
    series = {"ct": [b["certs"] for b in ter["buckets"]], "scored": [b["hits"] for b in ter["buckets"]]}
    totals = {"ct": ter["total"]["certs"], "scored": ter["total"]["hits"]}
    phishing = [0] * nb
    for key, _label, _noun in STAGES[2:]:
        series[key] = [0] * nb
        totals[key] = 0
    for r in event_rows or ():
        stage = r.get("stage")
        if stage not in series or stage in ("ct", "scored"):
            continue
        col = r.get("col")
        if col is None:
            totals[stage] = _n(r.get("n"))
        elif 0 <= int(col) < nb:
            series[stage][int(col)] += _n(r.get("n"))
            if stage == "ai_verdict":
                phishing[int(col)] += _n(r.get("phishing"))
    rows = []
    for key, label, noun in STAGES:
        vals = series[key]
        peak = max(vals, default=0)
        cells = []
        for b, v in enumerate(vals):
            if b > now_b:
                cells.append({"level": None, "title": None, "marker": None})
                continue
            level = 0 if v <= 0 or peak <= 0 else max(1, min(4, -(-4 * v // peak)))
            marker = None
            extra = ""
            if key == "ai_verdict" and phishing[b]:
                marker, extra = "danger", f", {phishing[b]:,} phishing"
            elif key == "taken_down" and v:
                marker = "protected"
            cells.append({"level": level, "marker": marker, "title": f"{bucket_label(view, b)}: {v:,} {noun}{extra}"})
        total = totals[key]
        rows.append({"key": key, "label": label, "noun": noun, "n": total, "counts": vals, "cells": cells,
                     "total": compact(total) if key == "ct" else f"{total:,}"})
    fmt = "%a %H:%M" if view["hours"] > 24 else "%H:%M"
    span = view["end"] - view["start"]
    ticks = [(view["start"] + span * i / 4).strftime(fmt) for i in range(4)] + ["now"]
    summary = ", ".join(f"{r['n']:,} {r['noun']}" for r in rows)
    # the same numbers per bucket, newest first, for the table under the grid (buckets in the future left out)
    table = []
    for b in range(min(now_b, nb - 1), -1, -1):
        bk = ter["buckets"][b]
        table.append({"t": bk["t"], "start": bk["start"], "label": bucket_label(view, b), "certs": bk["certs"],
                      "hits": bk["hits"], "review": bk["review"], "high": bk["high"],
                      "live": series["went_live"][b], "judged": series["ai_verdict"][b], "phishing": phishing[b],
                      "confirmed": series["confirmed"][b], "hour_link": view["bucket"] == 3600})
    return {"rows": rows, "ticks": ticks, "phishing": sum(phishing), "table": table,
            "label": f"Pipeline by stage, {view['label']}: {summary}."}


def verdict_tiles(rows) -> dict:
    """Counts for the four verdict tiles: phishing, suspicious, cleared (benign or parked), unjudged (no verdict
    or an error), judged (the first three) and total."""
    counts: dict = {}
    for r in rows or ():
        v = r.get("verdict") or "none"
        counts[v] = counts.get(v, 0) + _n(r.get("n"))
    total = sum(counts.values())
    out = {"phishing": counts.get("phishing", 0), "suspicious": counts.get("suspicious", 0),
           "cleared": counts.get("benign", 0) + counts.get("parked", 0)}
    out["judged"] = out["phishing"] + out["suspicious"] + out["cleared"]
    out["unjudged"] = total - out["judged"]
    out["total"] = total
    return out


def list_filters(show: str = "", tier: str = "", verdict: str = "", brand: str = "", window: str = "",
                 at: str = "", hour: str = "") -> tuple[str, str, list, str, dict]:
    """The /live/list query from its parameters: (title, WHERE sql, params, ORDER BY, applied filters).
    Unknown values are ignored (like /domains); values only ever travel as parameters."""
    where, params, words = [], [], []
    applied: dict = {}
    order = "first_seen DESC, id DESC"
    title = "Hits"
    if show in PRESETS:
        title, frag, order, _why = PRESETS[show]
        where.append(frag)
        applied["show"] = show
    if tier in TIERS:
        where.append(TIERS[tier])
        words.append(TIER_WORDS[tier])
        applied["tier"] = tier
    if verdict in VERDICT_GROUPS:
        frag, word = VERDICT_GROUPS[verdict]
        where.append(frag)
        words.append(word)
        applied["verdict"] = verdict
    elif verdict in VERDICT_KEYS:
        if verdict == "none":
            where.append("ai_verdict IS NULL")
            words.append("no AI verdict yet")
        else:
            where.append("ai_verdict = %s")
            params.append(verdict)
            words.append(f"AI verdict {dict((v[0], v[1]) for v in VERDICTS)[verdict]}")
        applied["verdict"] = verdict
    brand = clean_param(brand, 100)
    if brand:
        where.append("brand_id = %s")
        params.append(brand)
        words.append(brand)
        applied["brand"] = brand
    minute, hr = parse_minute(at), parse_minute(hour)
    if minute is not None:
        where.append("first_seen >= %s AND first_seen < %s")
        params += [minute, minute + timedelta(minutes=1)]
        words.append(f"first seen {minute.strftime('%Y-%m-%d %H:%M')} UTC")
        applied["at"] = iso_minute(minute)
    elif hr is not None:
        hr = hr.replace(minute=0)
        where.append("first_seen >= %s AND first_seen < %s")
        params += [hr, hr + timedelta(hours=1)]
        words.append(f"first seen {hr.strftime('%Y-%m-%d %H:00')} to {(hr + timedelta(hours=1)).strftime('%H:00')} UTC")
        applied["hour"] = iso_minute(hr)
    elif window in WINDOWS:
        where.append("first_seen > now() - make_interval(hours => %s)")
        params.append(WINDOWS[window][0])
        words.append(WINDOWS[window][1])
        applied["window"] = window
    if words:
        title = f"{title}: {', '.join(words)}"
    return title, " AND ".join(where) or "true", params, order, applied


def _brand_names() -> dict:
    try:
        from ..scoring import default_watchlist
        return {b.id: b.name for b in default_watchlist().brands.values()}
    except Exception:
        log.exception("watchlist unavailable")
        return {}


# ---- data ------------------------------------------------------------------------------------------------

async def _all(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchall()


async def _one(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchone()


_cache: dict = {}        # window -> (end, expires (monotonic), view, terrain, pipeline)


def reset_cache() -> None:
    _cache.clear()


async def view_data(conn, window: str, now: datetime | None) -> tuple[dict, dict, dict]:
    """(view, terrain, pipeline) for a window, cached for TERRAIN_TTL_S (and until the window moves on)."""
    view = view_bounds(now, window)
    hit = _cache.get(view["window"])
    if hit and hit[0] == view["end"] and hit[1] > time.monotonic():
        return hit[2], hit[3], hit[4]
    params = {"start": view["start"], "end": view["end"], "step": view["step"]}
    hit_rows = await _all(conn, TERRAIN_HITS_SQL, params)
    cert_rows = await _all(conn, TERRAIN_CERTS_SQL, params)
    marks = await _all(conn, TERRAIN_MARKS_SQL, {**params, "limit": MARKS_LIMIT})
    events = await _all(conn, PIPELINE_EVENTS_SQL, {**params, "step": view["bucket"]})
    ter = terrain(view, hit_rows, cert_rows, marks, _brand_names(), tier_thresholds())
    pipe = pipeline(view, ter, events)
    _cache[view["window"]] = (view["end"], time.monotonic() + TERRAIN_TTL_S, view, ter, pipe)
    return view, ter, pipe


def terrain_svg(ter: dict, cols_out: int = 48, pitch: int = 10) -> dict:
    """A coarse SVG version of the terrain for the page without JS: one dot per (column group, score row) at
    level 1-4 (max-pooled), the score bands, and the marks as links. Coordinates in a W x H viewBox."""
    cols, rows = ter["cols"], ter["rows"]
    g = max(1, -(-cols // cols_out))
    n = -(-cols // g)
    w, h = n * pitch, rows * pitch
    val = {ch: i for i, ch in enumerate(LEVELS)}
    top = len(LEVELS) - 1
    dots = []
    for r, line in enumerate(ter["levels"]):
        score = SCORE_MIN + r * SCORE_STEP
        band = "h" if score >= ter["high_at"] else ("r" if score >= ter["review_at"] else "w")
        y = h - (r + 0.5) * pitch
        for i in range(n):
            v = max((val.get(ch, 0) for ch in line[i * g:(i + 1) * g]), default=0)
            if v:
                lvl = min(4, 1 + 4 * v // (top + 1))
                dots.append((round((i + 0.5) * pitch, 1), round(y, 1), round(0.9 + 0.6 * lvl, 2), f"tf-{band}{lvl}"))

    def y_of(score):
        return round(h - (score_row(score) + 0.5) * pitch, 1)
    bands = [(y_of(ter["high_at"]) - pitch / 2, f"high {ter['high_at']}+"),
             (y_of(ter["review_at"]) - pitch / 2, f"review {ter['review_at']}+")]
    # place the marks (r = 9) clear of the band labels and of each other: nudge up or down, else leave one out
    # (the list under the terrain and /live/list still have every domain)
    blocked = [(0, y - 15, 56, y + 2) for y, _ in bands]
    marks, placed = [], []
    for m in ter["marks"]:
        cx, cy0 = round(m["x"] * w, 1), y_of(m["score"])
        for dy in (0, -20, 20, -40, 40):
            cy = cy0 + dy
            if not 9 <= cy <= h - 9:
                continue
            if any(cx + 10 > x0 and cx - 10 < x1 and cy + 10 > y0 and cy - 10 < y1 for x0, y0, x1, y1 in blocked):
                continue
            if any(abs(cx - px) < 20 and abs(cy - py) < 20 for px, py in placed):
                continue
            placed.append((cx, cy))
            marks.append({**m, "cx": cx, "cy": round(cy, 1)})
            break
    now_x = round((ter["now_col"] + 1) / g * pitch, 1)
    return {"w": w, "h": h, "dots": dots, "marks": marks, "now_x": min(w, now_x), "bands": bands}


async def overview_data(window: str = DEFAULT_WINDOW) -> dict:
    """Everything the overview template renders, from one pooled connection."""
    window = view_key(window)
    hours = VIEWS[window][0]
    p = await db.pool()
    async with p.connection() as conn:
        k = kpi_values(await _one(conn, KPI_SQL))
        rows = await _all(conn, FEED_SQL, (FEED_LIMIT,))
        view, ter, pipe = await view_data(conn, window, k["db_now"])
        brands = await _all(conn, BRANDS_SQL, (hours,))
        verdicts = await _all(conn, VERDICT_SQL, (hours,))
    stats = {key: k[key] for key in ("certs_5m", "hosts_5m", "certs_24h", "hits_24h", "high_24h", "open_review",
                                     "total", "confirmed", "live", "last_hit", "heartbeat")}
    return {"stats": stats, "rows": rows, "live": {
        "k": k, "view": view, "ter": ter, "pipe": pipe, "svg": terrain_svg(ter),
        "brands": brand_bars(brands, _brand_names()), "tiles": verdict_tiles(verdicts),
        "window": window, "window_label": view["label"], "views": VIEWS,
        "presets": {key: v[3] for key, v in PRESETS.items()}}}


def _jsonable(v):
    return v.isoformat() if isinstance(v, datetime) else v


# ---- routes ----------------------------------------------------------------------------------------------

async def overview_page(request: Request, window: str = DEFAULT_WINDOW):
    ctx = await overview_data(window)
    return _templates.TemplateResponse(request, "overview.html", ctx)


# The list page behind the overview's numbers. Kept here (not in templates/) so this module stays self-contained;
# it uses only base.html and the _ui.html macros. No inline style, script or handlers (CSP).
LIST_TEMPLATE = """{% extends "base.html" %}
{% import "_ui.html" as ui %}
{% block title %}CyberCheck · {{ title }}{% endblock %}
{% block page_id %}live-list{% endblock %}
{% block body %}
{% call ui.page_head(title, sub=sub, back="/", back_label="the overview") %}
  {{ ui.link_button("Filter all domains", "/domains", kind="quiet") }}
{% endcall %}
{% call ui.table(["Seen", "Tier", ("Score", "num"), "Hostname", "Brand", "Checks", "Decision"], label=title, id="rows",
                 tall=True, rows=True) %}
  {%- for r in rows %}
  {%- set host = r.hostnames[0] if r.hostnames else r.registered_domain %}
  <tr data-href="/domain/{{ r.id }}">
    <td class="nowrap">{{ ui.ago(r.first_seen) }}</td>
    <td>{{ ui.tier_pill(r.tier) }}</td>
    <td class="num">{{ r.score }}{% if r.final_score is not none %} <span class="muted">/ {{ r.final_score }}</span>{% endif %}</td>
    <td>{{ ui.dom(host, r.unicode_domain, "/domain/" ~ r.id) }}</td>
    <td>{{ r.brand_id or "-" }}</td>
    <td>{% if r.live_state and r.live_state != "unknown" %}{{ ui.live_pill(r.live_state) }} {% endif %}{% if r.ai_verdict %}{{ ui.verdict_pill(r.ai_verdict, r.ai_confidence) }}{% endif %}</td>
    <td>{{ ui.status_pill(r.status) }}</td>
  </tr>
  {%- else %}
  {{ ui.empty_row(7, "Nothing matches this list right now.", "/", "Back to the overview") }}
  {%- endfor %}
{% endcall %}
{% if total > rows | length %}<p class="muted">Showing the first {{ "{:,}".format(rows | length) }} of {{ "{:,}".format(total) }}. Use All domains to search and page through the rest.</p>{% endif %}
{% endblock %}
"""
_list_template = None


async def live_list(request: Request, show: str = "", tier: str = "", verdict: str = "", brand: str = "",
                    window: str = "", at: str = "", hour: str = ""):
    title, where, params, order, _applied = list_filters(show, tier, verdict, brand, window, at, hour)
    p = await db.pool()
    async with p.connection() as conn:
        total = await _one(conn, f"SELECT count(*) AS n FROM domains WHERE {where}", params)
        rows = await _all(conn, f"SELECT * FROM domains WHERE {where} ORDER BY {order} LIMIT {LIST_LIMIT}", params)
    n = int((total or {}).get("n") or 0)
    why = PRESETS[show][3] if show in PRESETS else None
    count = f"{n:,} {'domain' if n == 1 else 'domains'}"
    sub = f"{count}: {why}." if why else f"{count}."
    html = _list_template.render(request=request, rows=rows, title=title, sub=sub, total=n)
    return HTMLResponse(html)


async def api_summary():
    """KPI values and the newest heatmap minutes for overview.js (every 30 s). No-store."""
    p = await db.pool()
    async with p.connection() as conn:
        k = kpi_values(await _one(conn, KPI_SQL))
        end = k["db_now"] or datetime.now(timezone.utc)
        start = end.replace(second=0, microsecond=0) - timedelta(minutes=HEAT_RECENT_MIN - 1)
        cert_rows = await _all(conn, HEAT_CERTS_SQL, (start, end))
        hit_rows = await _all(conn, HEAT_HITS_SQL, (start,))
    st = await refresh_status()
    body = {key: _jsonable(v) for key, v in k.items()}
    body.update(ai=st.get("ai"), ai_spent_today=st.get("ai_spent_today"), ai_daily_cap=st.get("ai_daily_cap"),
                ai_pct=st.get("ai_pct"), recent=recent_minutes(cert_rows, hit_rows, end))
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


async def api_minute(at: str = ""):
    """One heatmap minute: its certificate count and the hits first seen in it (all tiers, best first)."""
    minute = parse_minute(at)
    if minute is None:
        raise HTTPException(400, "at must be a minute in ISO form, for example 2026-11-16T14:05Z")
    nxt = minute + timedelta(minutes=1)
    p = await db.pool()
    async with p.connection() as conn:
        certs = await _one(conn, MINUTE_CERTS_SQL, (minute,))
        total = await _one(conn, MINUTE_COUNT_SQL, (minute, nxt))
        rows = await _all(conn, MINUTE_SQL, (minute, nxt, MINUTE_HITS_LIMIT))
    hits = [{"id": r["id"], "host": r.get("hostname") or r.get("registered_domain"),
             "registered_domain": r.get("registered_domain"), "unicode_domain": r.get("unicode_domain"),
             "brand_id": r.get("brand_id"), "tier": r.get("tier"), "score": r.get("score"),
             "final_score": r.get("final_score"), "status": r.get("status"), "ai_verdict": r.get("ai_verdict"),
             "live_state": r.get("live_state"), "first_seen": _jsonable(r.get("first_seen"))} for r in rows]
    return JSONResponse({"t": iso_minute(minute), "certs": int((certs or {}).get("certs") or 0),
                         "total": int((total or {}).get("n") or 0), "hits": hits,
                         "list": f"/live/list?at={iso_minute(minute)}"}, headers={"Cache-Control": "no-store"})


async def _now(conn) -> datetime | None:
    row = await _one(conn, NOW_SQL)
    return (row or {}).get("db_now")


def _terrain_json(ter: dict) -> dict:
    out = {k: v for k, v in ter.items() if k != "buckets"}
    out["buckets"] = [{**b, "start": b["start"].isoformat()} for b in ter["buckets"]]
    return out


async def api_terrain(window: str = DEFAULT_WINDOW):
    """The threat terrain for overview.js (polled every minute). Cached server-side for TERRAIN_TTL_S."""
    p = await db.pool()
    async with p.connection() as conn:
        _view, ter, _pipe = await view_data(conn, view_key(window), await _now(conn))
    return JSONResponse(_terrain_json(ter), headers={"Cache-Control": "no-store"})


async def api_pipeline(window: str = DEFAULT_WINDOW):
    """Domains per pipeline stage and bucket (the dot grid's numbers). Cached with the terrain."""
    p = await db.pool()
    async with p.connection() as conn:
        view, _ter, pipe = await view_data(conn, view_key(window), await _now(conn))
    rows = [{"key": r["key"], "label": r["label"], "total": r["n"], "counts": r["counts"],
             "markers": [c["marker"] for c in r["cells"]]} for r in pipe["rows"]]
    return JSONResponse({"window": view["window"], "start": view["start"].isoformat(),
                         "end": view["end"].isoformat(), "bucket": view["bucket"], "now_bucket": view["now_bucket"],
                         "ticks": pipe["ticks"], "label": pipe["label"], "rows": rows},
                        headers={"Cache-Control": "no-store"})


def register(app, templates, nav) -> None:
    """Add the /live and /api/live routes, and serve "/" from overview_page.

    app.py declares "/" first; its route is replaced at the same position in the router, so route order (and so
    matching) is otherwise unchanged. app.py's handler keeps working with the same template if called."""
    global _templates, _list_template
    _templates = templates
    _list_template = templates.env.from_string(LIST_TEMPLATE)
    from fastapi.routing import APIRoute
    app.add_api_route("/live/list", live_list, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/api/live/summary", api_summary, methods=["GET"])
    app.add_api_route("/api/live/minute", api_minute, methods=["GET"])
    app.add_api_route("/api/live/terrain", api_terrain, methods=["GET"])
    app.add_api_route("/api/live/pipeline", api_pipeline, methods=["GET"])
    app.add_api_route("/", overview_page, methods=["GET"], response_class=HTMLResponse, name="overview_live")
    routes = app.router.routes
    mine = routes.pop()
    for i, r in enumerate(routes):
        if isinstance(r, APIRoute) and r.path == "/" and "GET" in (r.methods or ()):
            routes[i] = mine
            break
    else:
        routes.append(mine)
