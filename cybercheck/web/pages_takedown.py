"""Dashboard page /takedown: how fast flagged domains get taken down, per registrar and per hosting network.

Numbers only cover domains CyberCheck flagged and tracked (the page says so). Takedown times come from
the enrich job (cybercheck/enrich.py). GET only; no forms.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import HTMLResponse

from ..enrich import load_config
from .common import fetchall, fetchone

# Fixed SQL fragments chosen by key; request input never reaches the SQL text.
SCOPES = {
    "confirmed": ("Confirmed by a reviewer", "status = 'confirmed'"),
    "tracked": ("Confirmed, reported or judged phishing by the AI",
                "status NOT IN ('false_positive', 'benign') AND "
                "(status = 'confirmed' OR reported_at IS NOT NULL OR ai_verdict = 'phishing')"),
}

BASE = """
WITH t AS (
  SELECT registrar, registrar_iana_id, asn, as_name, live_state, reported_at, takedown_at,
         (extract(epoch FROM takedown_at - first_seen) / 3600.0)::float8 AS h_first,
         CASE WHEN takedown_at >= reported_at
              THEN (extract(epoch FROM takedown_at - reported_at) / 3600.0)::float8 END AS h_rep
  FROM domains WHERE {where}
)
"""

AGG = """
  count(*) AS total,
  count(takedown_at) AS down,
  count(*) FILTER (WHERE takedown_at IS NULL) AS up,
  count(*) FILTER (WHERE takedown_at IS NULL AND live_state = 'live') AS live_now,
  count(reported_at) AS reported,
  percentile_cont(0.5) WITHIN GROUP (ORDER BY h_first) AS med_first,
  percentile_cont(0.9) WITHIN GROUP (ORDER BY h_first) AS p90_first,
  count(h_rep) AS n_rep,
  percentile_cont(0.5) WITHIN GROUP (ORDER BY h_rep) AS med_rep,
  percentile_cont(0.9) WITHIN GROUP (ORDER BY h_rep) AS p90_rep
"""

# Time-to-takedown histogram buckets, in hours: (key, label, from, to). Fixed text, never request input.
BUCKETS = (("b0", "under 6 h", 0, 6), ("b1", "6 to 24 h", 6, 24), ("b2", "1 to 3 days", 24, 72),
           ("b3", "3 to 7 days", 72, 168), ("b4", "over 7 days", 168, None))


def _bucket_sql(col: str, prefix: str) -> str:
    parts = []
    for key, _label, lo, hi in BUCKETS:
        cond = f"{col} >= {lo}" + (f" AND {col} < {hi}" if hi is not None else "")
        parts.append(f"count(*) FILTER (WHERE {cond}) AS {prefix}_{key}")
    return ", ".join(parts)


SUMMARY_SQL = (BASE + "SELECT " + AGG + ", " + _bucket_sql("h_first", "first") + ", " + _bucket_sql("h_rep", "rep")
               + " FROM t")

BY_REGISTRAR_SQL = BASE + """
SELECT max(registrar) AS name, max(registrar_iana_id) AS iana_id, """ + AGG + """
FROM t
GROUP BY COALESCE('iana:' || registrar_iana_id::text, 'name:' || lower(registrar), '')
ORDER BY total DESC, name NULLS LAST
LIMIT 100
"""

BY_AS_SQL = BASE + """
SELECT asn, max(as_name) AS name, """ + AGG + """
FROM t
GROUP BY asn
ORDER BY total DESC, asn NULLS LAST
LIMIT 100
"""

STILL_UP_SQL = """
SELECT id, registered_domain, unicode_domain, hostnames[1] AS hostname, brand_id, registrar, asn, as_name,
       dns_state, live_state, first_seen, reported_at, last_live_at, enriched_at,
       (extract(epoch FROM now() - first_seen) / 3600.0)::float8 AS age_h,
       (extract(epoch FROM now() - reported_at) / 3600.0)::float8 AS reported_h
FROM domains
WHERE ({where}) AND takedown_at IS NULL
ORDER BY first_seen
LIMIT 200
"""

RECENT_SQL = """
SELECT id, registered_domain, unicode_domain, hostnames[1] AS hostname, brand_id, registrar, asn, as_name,
       takedown_at, takedown_signal,
       (extract(epoch FROM takedown_at - first_seen) / 3600.0)::float8 AS h_first,
       CASE WHEN takedown_at >= reported_at
            THEN (extract(epoch FROM takedown_at - reported_at) / 3600.0)::float8 END AS h_rep
FROM domains
WHERE ({where}) AND takedown_at IS NOT NULL
ORDER BY takedown_at DESC
LIMIT 50
"""

_templates = None   # set by register()

SIGNALS = {"nxdomain": "NXDOMAIN", "rdap_hold": "registry hold", "http_gone": "page gone",
           "content_removed": "content removed"}


def fmt_hours(h) -> str:
    """12.5 -> '12.5 h', 50 -> '2.1 d', None -> '-'."""
    if h is None:
        return "-"
    h = float(h)
    if h < 0:
        return "-"
    if h < 1:
        return f"{h * 60:.0f} min"
    if h < 48:
        return f"{h:.1f} h"
    return f"{h / 24:.1f} d"


def age_tone(h) -> str | None:
    """Still-up domains: amber after 3 days, red after 7 (the page pairs the tone with a glyph)."""
    if h is None:
        return None
    return "red" if h >= 168 else ("amber" if h >= 72 else None)


def histogram(summary: dict) -> list[dict]:
    """Rows for the "how long until takedown" chart: [{'label', 'first', 'rep', 'first_w', 'rep_w'}].
    Widths are 0-100, relative to the largest bucket of the same series. Missing counts read as 0."""
    rows = [{"label": label, "first": int(summary.get(f"first_{key}") or 0), "rep": int(summary.get(f"rep_{key}") or 0)}
            for key, label, _lo, _hi in BUCKETS]
    for series in ("first", "rep"):
        top = max(r[series] for r in rows) or 1
        for r in rows:
            r[series + "_w"] = round(100 * r[series] / top) if r[series] else 0
    return rows


def _agg_row(r: dict) -> dict:
    r = dict(r)
    for k in ("med_first", "p90_first", "med_rep", "p90_rep"):
        r[k + "_s"] = fmt_hours(r.get(k))
    return r


async def takedown_page(request: Request, scope: str = "confirmed"):
    if scope not in SCOPES:
        scope = "confirmed"
    label, where = SCOPES[scope]
    summary = await fetchone(SUMMARY_SQL.format(where=where))
    by_registrar = await fetchall(BY_REGISTRAR_SQL.format(where=where))
    by_as = await fetchall(BY_AS_SQL.format(where=where))
    still_up = await fetchall(STILL_UP_SQL.format(where=where))
    recent = await fetchall(RECENT_SQL.format(where=where))
    for r in still_up:
        r["age_s"] = fmt_hours(r.get("age_h"))
        r["reported_s"] = fmt_hours(r.get("reported_h")) if r.get("reported_at") else "-"
        r["age_tone"] = age_tone(r.get("age_h"))
    for r in recent:
        r["h_first_s"] = fmt_hours(r.get("h_first"))
        r["h_rep_s"] = fmt_hours(r.get("h_rep"))
        r["signal_s"] = SIGNALS.get(r.get("takedown_signal"), r.get("takedown_signal") or "-")
    return _templates.TemplateResponse(request, "takedown_stats.html", {
        "scope": scope, "scopes": SCOPES, "scope_options": [(k, v[0]) for k, v in SCOPES.items()], "scope_label": label, "track_days": load_config().track_days,
        "summary": _agg_row(summary or {}), "histogram": histogram(summary or {}), "by_registrar": [_agg_row(r) for r in by_registrar],
        "by_as": [_agg_row(r) for r in by_as], "still_up": still_up, "recent": recent})


def register(app, templates, nav) -> None:
    global _templates
    _templates = templates
    app.add_api_route("/takedown", takedown_page, methods=["GET"], response_class=HTMLResponse)
    if ("/takedown", "Takedowns") not in nav:
        nav.append(("/takedown", "Takedowns"))
