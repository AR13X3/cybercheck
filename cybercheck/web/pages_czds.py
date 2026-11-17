"""Dashboard page /czds: whether CZDS credentials are configured, per-zone status, recent runs and recent CZDS hits.

Zone data is licensed (CZDS T&C s1.6): this page shows counters and CyberCheck's own scored hits only, never
zone contents or name lists, and never the CZDS username or password. GET only; no forms.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import psycopg
from fastapi import Request
from fastapi.responses import HTMLResponse

from .. import czds
from .common import fetchall, fetchone

log = logging.getLogger("cybercheck.web.czds")

ZONES_SQL = """
SELECT tld, configured, approved, approved_at, last_head, last_download, last_processed, next_due, retry_at,
       total_names, new_names, removed_names, hits, new_hits, soa_serial, file_bytes, status, error, fail_count,
       duration_s, updated_at
FROM czds_zones
ORDER BY configured DESC, tld
LIMIT 3000
"""
ZONE_KEYS = tuple(k.strip() for k in ZONES_SQL.split("SELECT", 1)[1].split("FROM", 1)[0].split(","))

RUNS_SQL = """
SELECT tld, at, status, total_names, new_names, removed_names, hits, new_hits, file_bytes, duration_s, error
FROM czds_runs
ORDER BY at DESC, id DESC
LIMIT 60
"""

# Domains CZDS found first (first_seen event with source czds) plus domains already known from CT that a
# zone diff showed as newly delegated (czds_new_delegation events), last 30 days.
HITS_SQL = """
SELECT d.id, d.registered_domain, d.unicode_domain, d.hostnames, d.brand_id, d.score, d.tier, d.status,
       d.first_seen, d.live_state, d.dns_state, d.ai_verdict, d.final_score, d.source, e.at AS czds_at
FROM (
    SELECT domain_id, max(at) AS at
    FROM domain_events
    WHERE at > now() - interval '30 days'
      AND (kind = 'czds_new_delegation' OR (kind = 'first_seen' AND detail->>'source' = 'czds'))
    GROUP BY domain_id
    ORDER BY max(at) DESC
    LIMIT 200
) e
JOIN domains d ON d.id = e.domain_id
ORDER BY e.at DESC, d.id DESC
"""

STATS_SQL = """
SELECT
  (SELECT count(*) FROM domains WHERE source = 'czds') AS stored_by_czds,
  (SELECT count(*) FROM domains WHERE source = 'czds' AND first_seen > now() - interval '24 hours') AS new_24h,
  (SELECT count(*) FROM domains WHERE source = 'czds' AND first_seen > now() - interval '7 days') AS new_7d,
  (SELECT count(*) FROM domain_events WHERE kind = 'czds_new_delegation' AND at > now() - interval '7 days') AS known_7d
"""

JOB_SQL = "SELECT value, updated_at FROM kv WHERE key = %s"

STATUS_TEXT = {
    "pending": "waiting for the first CZDS check",
    "not_approved": "not approved for this account (yet)",
    "approved": "approved; first download in the next window",
    "not_configured": "approved, but not in CZDS_TLDS",
    "revoked": "no longer approved",
    "downloading": "downloading",
    "downloaded": "downloaded, waiting to be processed",
    "processing": "processing",
    "ok": "processed",
    "baseline": "baseline stored (first list; nothing counted as new)",
    "rebaseline": "too many new names; stored as a new baseline",
    "unchanged": "same file as before; skipped",
    "invalid": "file rejected by a check",
    "retrying": "download failed; retrying",
    "error": "error",
    "terms": "new Terms & Conditions to accept in the CZDS portal",
    "no_access": "CZDS refused access (HTTP 403)",
    "low_disk": "not enough free disk",
}
STATUS_CLASS = {
    "ok": "t-ok", "baseline": "t-ok", "unchanged": "t-ok",
    "pending": "t-watch", "approved": "t-watch", "not_approved": "t-watch", "not_configured": "t-watch",
    "downloading": "t-review", "downloaded": "t-review", "processing": "t-review", "retrying": "t-review",
    "rebaseline": "t-review",
}


# Zone states grouped for the page: (group, pill tone, glyph). The group decides the summary chips and the row
# marker; tone and glyph always travel together so colour is never the only signal.
STATE_GROUPS = {
    "ok": ("ok", "teal", "●"), "baseline": ("ok", "teal", "●"), "unchanged": ("ok", "teal", "●"),
    "pending": ("waiting", "muted", "○"), "approved": ("waiting", "muted", "○"),
    "not_approved": ("waiting", "muted", "○"), "not_configured": ("waiting", "muted", "○"),
    "downloading": ("working", "outline", "◌"), "downloaded": ("working", "outline", "◌"),
    "processing": ("working", "outline", "◌"),
    "retrying": ("warning", "amber", "▲"), "rebaseline": ("warning", "amber", "▲"),
}
GROUP_TEXT = {"ok": "up to date", "waiting": "waiting", "working": "in progress", "warning": "needs a look",
              "problem": "failing"}
GROUP_ORDER = ("problem", "warning", "working", "waiting", "ok")


def zone_state(status) -> dict:
    """How a zone status is shown: {'group', 'tone', 'glyph', 'label', 'text'}. Unknown states count as problems."""
    st = status or "pending"
    group, tone, glyph = STATE_GROUPS.get(st, ("problem", "red", "■"))
    return {"group": group, "tone": tone, "glyph": glyph, "label": st.replace("_", " "),
            "text": STATUS_TEXT.get(st, "")}


def zone_summary(zones) -> list[dict]:
    """[{'group', 'n', 'text', 'tone', 'glyph'}] for the groups present, worst first."""
    counts: dict[str, int] = {}
    looks: dict[str, tuple[str, str]] = {}
    for z in zones:
        s = zone_state(z.get("status"))
        counts[s["group"]] = counts.get(s["group"], 0) + 1
        looks.setdefault(s["group"], (s["tone"], s["glyph"]))
    return [{"group": g, "n": counts[g], "text": GROUP_TEXT[g], "tone": looks[g][0], "glyph": looks[g][1]}
            for g in GROUP_ORDER if g in counts]


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def fmt_int(n) -> str:
    return "-" if n is None else f"{int(n):,}"


def fmt_until(ts) -> str:
    """Future time as 'in 3h' (past times as 'now')."""
    if ts is None:
        return "-"
    secs = (ts - datetime.now(timezone.utc)).total_seconds()
    if secs <= 60:
        return "now"
    if secs < 3600:
        return f"in {int(secs // 60)}m"
    if secs < 86400:
        return f"in {secs / 3600:.0f}h"
    return f"in {secs / 86400:.1f}d"


def status_class(status) -> str:
    return STATUS_CLASS.get(status or "", "t-high")


async def czds_page(request: Request):
    cfg = czds.load_config()
    try:
        zones = await fetchall(ZONES_SQL)
        runs = await fetchall(RUNS_SQL)
        migrated = True
    except psycopg.errors.UndefinedTable:   # until the worker has applied migrations/060_czds.sql
        zones, runs, migrated = [], [], False
    hits = await fetchall(HITS_SQL)
    stats = await fetchone(STATS_SQL) or {}
    job_row = await fetchone(JOB_SQL, ("job:czds",))
    try:
        disk = await asyncio.to_thread(czds.disk_usage, cfg)
    except Exception:          # the page must not fail over a disk read
        log.exception("czds disk usage")
        disk = None

    configured = [z for z in zones if z["configured"]]
    known = {z["tld"] for z in configured}
    # TLDs in CZDS_TLDS that the job has not recorded yet (no run since they were added)
    for tld in cfg.tlds:
        if tld not in known:
            configured.append({**dict.fromkeys(ZONE_KEYS), "tld": tld, "configured": True, "status": "pending"})
    configured.sort(key=lambda z: z["tld"])
    other_approved = [z["tld"] for z in zones if not z["configured"] and z["approved"]]
    cctlds = [t for t in cfg.tlds if len(t) == 2]   # every two-letter TLD is a ccTLD: not in CZDS

    return _templates.TemplateResponse(request, "czds_index.html", {
        "has_credentials": cfg.has_credentials, "tlds": cfg.tlds, "bad_tlds": cfg.bad_tlds, "cctlds": cctlds,
        "window": cfg.window_label, "zones": configured, "other_approved": other_approved, "runs": runs,
        "hits": hits, "stats": stats, "job": job_row["value"] if job_row else None,
        "job_at": job_row["updated_at"] if job_row else None, "disk": disk, "migrated": migrated,
        "status_text": STATUS_TEXT, "status_class": status_class, "zone_state": zone_state,
        "zone_summary": zone_summary(configured),
        "fmt_bytes": fmt_bytes, "fmt_int": fmt_int, "fmt_until": fmt_until,
    })


_templates = None   # set by register()


def register(app, templates, nav) -> None:
    global _templates
    _templates = templates
    app.add_api_route("/czds", czds_page, methods=["GET"], response_class=HTMLResponse)
    if ("/czds", "CZDS") not in nav:
        nav.append(("/czds", "CZDS"))
