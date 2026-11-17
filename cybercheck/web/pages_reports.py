"""Dashboard page /reports: the human side of reporting (cybercheck/reporting/, worker job "report").

- Mode banner: REPORTING_MODE, the auto-report threshold, the rate limit, the sandbox verification
  file, and every channel that is off with the reason.
- Email drafts (registrar, hosting provider, the brand's verified mailbox): edit, then approve (sent by
  the worker over SMTP, inside the rate limit) or send from your own mail client (mailto link and
  copyable text) and mark as sent. Reject.
- Manual web-form checklist (Scamwatch, Google Safe Browsing, ...): official link, prefilled text, the
  screenshot as a JPEG download, mark as done.
- Queue, failures (retry / reject), sent log, per-channel counts, confirmed domains not yet reported
  (POST /reports/create/{domain_id} creates their drafts now).

Every POST calls same_origin(). Report text contains page-derived values: the templates autoescape it,
never mark it safe, and never turn a reported URL into a link. Nothing here contacts a reported site.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from urllib.parse import quote, urlencode, urlsplit

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .. import db
from ..reporting import channels, engine, evidence, texts
from ..reporting.common import aware, clean_line, clean_text, json_safe, utcnow, valid_email
from ..reporting.conf import load_config
from .common import reviewer, same_origin

MESSAGES = {
    "created": "Report drafts created.",
    "nothing": "Nothing new to create: every channel that applies already has a report for this domain.",
    "official": "That is an official brand domain: nothing is reported.",
    "not_confirmed": "Only domains a reviewer confirmed as phishing are reported from here.",
    "taken_down": "The site was already taken down: no reports were created.",
    "saved": "Draft saved.",
    "queued": "Approved. The worker sends it within a few minutes, inside the hourly rate limit.",
    "sent": "Marked as sent.",
    "done": "Marked as done.",
    "rejected": "Rejected: it will not be sent or created again.",
    "retry": "Queued again.",
    "bad_to": "Enter a valid recipient email address first.",
    "unsafe_to": ("Not queued: that address is on the reported domain, or on another domain CyberCheck tracks as "
                  "suspicious, so it may belong to the attacker. Find the provider's real abuse contact."),
    "no_smtp": "SMTP is not configured: send it from your mail client, then mark it as sent.",
    "mode_off": "REPORTING_MODE=off: the worker sends nothing. Send it by hand and mark it as sent.",
    "not_pending": "That report is no longer waiting for this action (it may have changed meanwhile).",
    "closed": "The domain is marked false positive or benign: nothing is sent.",
    "not_api": "Only API and email reports can be queued again.",
}

# Flash tone for each message (ui.flash: ok | info | warn | error). Presentation only.
MESSAGE_TONES = {
    "created": "ok", "saved": "ok", "queued": "ok", "sent": "ok", "done": "ok", "rejected": "ok", "retry": "ok",
    "nothing": "info", "no_smtp": "info", "mode_off": "info",
    "official": "warn", "not_confirmed": "warn", "taken_down": "warn", "not_pending": "warn", "closed": "warn",
    "not_api": "warn", "bad_to": "error", "unsafe_to": "error",
}

MAILTO_BODY_MAX = 6000
LIST_LIMIT = 100

REPORT_COLS = """r.id, r.domain_id, r.channel, r.kind, r.status, r.auto, r.created_at, r.updated_at, r.sent_at,
       r.payload, r.response, r.error, r.external_id, r.attempts, r.next_attempt_at, r.last_attempt_at,
       r.reviewed_by, r.reviewed_at, r.sent_via, r.sent_by, r.checked_at,
       d.registered_domain, d.unicode_domain, d.brand_id, d.status AS domain_status, d.final_score,
       d.takedown_at, d.live_state"""

SUMMARY_SQL = """
SELECT count(*) FILTER (WHERE status = 'pending_review' AND kind = 'email') AS drafts,
       count(*) FILTER (WHERE status = 'pending_review' AND kind = 'manual') AS manual,
       count(*) FILTER (WHERE status IN ('approved', 'sending')) AS queued,
       count(*) FILTER (WHERE status = 'sent') AS sent,
       count(*) FILTER (WHERE status = 'sent' AND sent_at > now() - interval '24 hours') AS sent_24h,
       count(*) FILTER (WHERE status = 'failed') AS failed,
       count(DISTINCT domain_id) FILTER (WHERE status = 'sent') AS domains_reported
FROM reports
"""

CHANNEL_COUNTS_SQL = """
SELECT channel, max(kind) AS kind,
       count(*) FILTER (WHERE status = 'pending_review') AS pending,
       count(*) FILTER (WHERE status IN ('approved', 'sending')) AS queued,
       count(*) FILTER (WHERE status = 'sent') AS sent,
       count(*) FILTER (WHERE status = 'failed') AS failed,
       count(*) FILTER (WHERE status = 'rejected') AS rejected,
       count(*) FILTER (WHERE status = 'skipped') AS skipped,
       count(*) AS total, max(sent_at) AS last_sent
FROM reports GROUP BY channel ORDER BY count(*) DESC, channel LIMIT 200
"""

LIST_SQL = {
    "drafts": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                  WHERE r.status = 'pending_review' AND r.kind = 'email' ORDER BY r.created_at, r.id LIMIT %s""",
    "manual": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                  WHERE r.status = 'pending_review' AND r.kind = 'manual' ORDER BY r.domain_id DESC, r.channel
                  LIMIT %s""",
    "queued": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                  WHERE r.status IN ('approved', 'sending') ORDER BY r.next_attempt_at NULLS FIRST, r.id LIMIT %s""",
    "failed": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                  WHERE r.status = 'failed' ORDER BY r.updated_at DESC LIMIT %s""",
    "sent": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                WHERE r.status = 'sent' ORDER BY r.sent_at DESC NULLS LAST LIMIT %s""",
    "closed": f"""SELECT {REPORT_COLS} FROM reports r JOIN domains d ON d.id = r.domain_id
                  WHERE r.status IN ('rejected', 'skipped') ORDER BY r.updated_at DESC LIMIT %s""",
}
LIST_LIMITS = {"closed": 30}

UNREPORTED_SQL = """
SELECT d.id, d.registered_domain, d.unicode_domain, d.brand_id, d.status_changed_at, d.status_by, d.final_score
FROM domains d
WHERE d.status = 'confirmed' AND d.takedown_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.domain_id = d.id)
ORDER BY d.status_changed_at DESC NULLS LAST
LIMIT 50
"""

# the detail page also shows the domain's evidence summary (read-only columns)
DETAIL_SQL = f"""SELECT {REPORT_COLS}, d.ai_verdict, d.ai_confidence, d.tier, d.first_seen, d.registrar,
       d.as_name, d.ip_country
FROM reports r JOIN domains d ON d.id = r.domain_id WHERE r.id = %s"""

ATTEMPTS_SQL = """
SELECT id, at, via, ok, http_status, error, response FROM report_attempts
WHERE report_id = %s ORDER BY at DESC LIMIT 50
"""

KV_SQL = "SELECT key, value, updated_at FROM kv WHERE key = ANY(%s)"

LOCK_SQL = """
SELECT r.id, r.domain_id, r.channel, r.kind, r.status, r.payload, d.status AS domain_status, d.takedown_at,
       d.registered_domain
FROM reports r JOIN domains d ON d.id = r.domain_id
WHERE r.id = %s
FOR UPDATE OF r
"""

SAVE_SQL = "UPDATE reports SET payload = payload || %s, updated_at = now() WHERE id = %s"

APPROVE_SQL = """
UPDATE reports SET status = 'approved', attempts = 0, next_attempt_at = now(), error = NULL,
       reviewed_by = %s, reviewed_at = now(), updated_at = now(), payload = payload || %s
WHERE id = %s
"""

MARK_SENT_SQL = """
UPDATE reports SET status = 'sent', sent_at = now(), sent_via = 'manual', sent_by = %s, reviewed_by = %s,
       reviewed_at = now(), error = NULL, updated_at = now(), payload = payload || %s
WHERE id = %s
"""

REJECT_SQL = """
UPDATE reports SET status = 'rejected', reviewed_by = %s, reviewed_at = now(), error = %s, updated_at = now()
WHERE id = %s
"""

RETRY_SQL = """
UPDATE reports SET status = 'approved', attempts = 0, next_attempt_at = now(), error = NULL,
       reviewed_by = %s, reviewed_at = now(), updated_at = now()
WHERE id = %s
"""

SCREENSHOT_SQL = "SELECT screenshot_path FROM pages WHERE id = %s AND domain_id = %s"

CLOSED_STATUSES = ("false_positive", "benign")

_templates = None   # set by register()


# ---- pure helpers (tested) -------------------------------------------------------------------------

def _parse_ts(value):
    try:
        return aware(datetime.fromisoformat(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def mailto_link(to: str, subject: str, body: str) -> str | None:
    """mailto: URL for a reviewer's own mail client. The address is percent-encoded too, so a hostile
    address like 'a?cc=x@y' can never add headers or recipients."""
    if not valid_email(to):
        return None
    query = urlencode({"subject": clean_line(subject, 200), "body": clean_text(body, MAILTO_BODY_MAX)},
                      quote_via=quote)
    return f"mailto:{quote(to, safe='@')}?{query}"


def official_link(row: dict) -> str | None:
    """Official web form for a manual item, from the channel catalogue (never from page data)."""
    ch = row.get("channel") or ""
    url = None
    if ch in channels.MANUAL:
        url = channels.MANUAL[ch].url
    elif ch.startswith(channels.BRAND_FORM + ":"):
        c = channels.brand_contact(ch.split(":", 1)[1])
        url = c.address if c and c.method == "web_form" else None
    if url and urlsplit(url).scheme == "https":
        return url
    return None


def netcraft_summary(response) -> str:
    """'malicious; takedown: in progress' from a polled Netcraft submission, or ''."""
    if not isinstance(response, dict):
        return ""
    st = response.get("status")
    if not isinstance(st, dict):
        return "test endpoint" if response.get("test") else ""
    if st.get("archived"):
        return "archived by Netcraft (30 days)"
    parts = []
    if st.get("state"):
        parts.append(clean_line(st["state"], 40))
    takedown = sorted({clean_line(u.get("url_takedown_state"), 40) for u in (st.get("urls") or [])
                       if isinstance(u, dict) and u.get("url_takedown_state")})
    if takedown:
        parts.append("takedown: " + ", ".join(takedown))
    return "; ".join(parts)


def view(row: dict) -> dict:
    """A report row plus what the templates show for it."""
    r = dict(row)
    p = r.get("payload") if isinstance(r.get("payload"), dict) else {}
    r["payload"] = p
    r["label"] = channels.channel_label(r.get("channel") or "")
    r["closed_domain"] = r.get("domain_status") in CLOSED_STATUSES
    r["confirmed"] = r.get("domain_status") == "confirmed"
    page_id = p.get("page_id")
    has_shot = bool(p.get("screenshot") or p.get("attach_screenshot") or (p.get("facts") or {}).get("screenshot"))
    r["screenshot_url"] = f"/reports/{r['id']}/screenshot.jpg" if has_shot and isinstance(page_id, int) else None
    if r.get("kind") == "email":
        r["to"] = p.get("to") or ""
        r["subject"] = p.get("subject") or ""
        r["body"] = p.get("body") or ""
        # an address on the reported domain itself (typed in, or from an older draft) gets no mail link
        live = texts.contact_warning(r["to"], {"registered_domain": r.get("registered_domain")})
        r["to_warning"] = live or ("" if r["to"] else (p.get("to_warning") or ""))
        r["mailto"] = None if live else mailto_link(r["to"], r["subject"], r["body"])
        r["ai_note"] = {"used": "written by the AI from the facts below, then checked by you",
                        "pending": "AI draft pending; this is the template text",
                        "unavailable": "template text (AI unavailable)",
                        "edited": "edited by a reviewer",
                        "off": "template text"}.get(p.get("ai"), "")
    elif r.get("kind") == "manual":
        r["form_url"] = official_link(r)
        r["fields"] = [f for f in (p.get("fields") or []) if isinstance(f, dict)]
        r["notes"] = p.get("notes") or ""
    r["netcraft"] = netcraft_summary(r.get("response")) if r.get("channel") == channels.NETCRAFT.id else ""
    return r


def banner(cfg, sandbox) -> dict:
    disabled = channels.disabled(cfg)
    if cfg.mode == "auto" and not sandbox.ok:
        disabled.insert(0, ("Automatic reports for unreviewed domains", sandbox.reason))
    text = {
        "off": "Reporting is off. The worker creates and sends nothing.",
        "review": "Reports are made only for domains a reviewer confirmed. Automated channels "
                  "(Netcraft) are sent for them; emails and web forms wait for you here.",
        "auto": f"Domains a reviewer confirmed are reported as in review mode. In addition, unreviewed domains "
                f"with a combined score of at least {cfg.min_final_score}, an AI 'phishing' verdict and a newest "
                f"snapshot that asks for a password, one-time code or card details are sent to automated "
                f"channels only (while the sandbox verification is valid).",
    }[cfg.mode]
    return {"text": text, "disabled": disabled}


# ---- presentation helpers (tested; no effect on what is sent, when, or to whom) ------------------------

MAILTO_SOFT_MAX = 1800      # longer mailto bodies are cut by some mail clients: the page suggests copying instead
EVIDENCE_URLS = 5
_TONE_GLYPH = {"teal": "●", "amber": "▲", "red": "■", "muted": "○"}


def _step(action, tone, title, text):
    return {"action": action, "tone": tone, "glyph": _TONE_GLYPH.get(tone, "○"), "title": title, "text": text}


def next_step(r: dict, cfg) -> dict:
    """What the reviewer should do next with one report (a view() row): the primary button on the detail page
    and the hint on the queue. action is one of approve | mailto | save | done | retry | reject | domain | None.
    It only chooses which existing button to highlight: the POST routes still decide what is allowed."""
    kind, status = r.get("kind"), r.get("status")
    confirmed, closed = bool(r.get("confirmed")), bool(r.get("closed_domain"))
    error = clean_line(r.get("error"), 300)
    if status == "sent":
        if r.get("takedown_at"):
            return _step(None, "teal", "Taken down", "The site is gone. Nothing to do.")
        return _step(None, "teal", "Sent", "Nothing to do. CyberCheck keeps checking the site and records the "
                                           "takedown when it happens.")
    if status == "sending":
        return _step(None, "teal", "Sending now", "The worker is delivering it. Nothing to do.")
    if status == "rejected":
        return _step(None, "muted", "Rejected", "It will not be sent or created again.")
    if status == "approved":
        return _step(None, "teal", "Queued for sending", "The worker sends it within a few minutes, inside the "
                                                         "hourly rate limit. Cancel it if it should not go out.")
    if status == "skipped":
        why = f"Not sent: {error}." if error else "Not sent."
        if kind in ("api", "email") and confirmed:
            return _step("retry", "amber", "Skipped", why + " Retry it if it should go out after all.")
        return _step(None, "muted", "Skipped", why)
    if status not in ("pending_review", "failed"):
        return _step(None, "muted", status or "Unknown", "Nothing to do here.")
    # waiting for the reviewer, or failed
    if closed:
        label = "false positive" if r.get("domain_status") == "false_positive" else "benign"
        return _step("reject", "muted", "Close this report",
                     f"The domain is marked {label}, so nothing is sent. Reject this report to close it.")
    if not confirmed:
        return _step("domain", "amber", "Confirm the domain first",
                     "The domain is no longer confirmed by a reviewer, so this report cannot be sent. Confirm it "
                     "again on the domain page, or reject this report.")
    failed = status == "failed"
    if kind == "api":
        if failed:
            return _step("retry", "red", "Sending failed",
                         (f"{error}. " if error else "") + "Retry it, or reject it if the channel refused it for "
                                                           "a good reason.")
        return _step(None, "muted", "Waiting", "The worker handles this channel. Nothing to do.")
    if kind == "manual":
        return _step("done", "amber", "File the web form", "Open the official form, paste each field below, "
                                                          "submit it, then mark this report as done.")
    if kind != "email":
        return _step(None, "muted", "Nothing to do", "This report needs no action from you.")
    prefix = f"The last send failed: {error}. " if failed and error else ("The last send failed. " if failed else "")
    tone = "red" if failed else "amber"
    if not valid_email(r.get("to") or "") or not r.get("mailto"):
        return _step("save", tone, "Add the abuse address",
                     prefix + "Enter the provider's real abuse address in To, then save the draft.")
    if cfg.smtp and cfg.mode != "off":
        return _step("approve", tone, "Approve and send" if not failed else "Fix it and approve again",
                     prefix + "Check every fact against the domain page, then approve. The worker sends it over "
                              "SMTP within a few minutes, inside the hourly rate limit.")
    why = "Reporting is off" if cfg.mode == "off" else "SMTP is not configured"
    return _step("mailto", tone, "Send it from your mail client",
                 prefix + f"{why}, so CyberCheck does not send it. Open it in your mail client, send it, then "
                          "press Mark as sent.")


def _strings(values) -> list[str]:
    return [v for v in (values or []) if isinstance(v, str) and v.strip()]


def evidence_view(r: dict) -> dict:
    """The evidence summary on the detail page, from the report's stored facts and the domain row. Every
    value here is shown as text (URLs too: never as links)."""
    p = r.get("payload") if isinstance(r.get("payload"), dict) else {}
    facts = p.get("facts") if isinstance(p.get("facts"), dict) else {}
    urls = _strings(facts.get("urls")) or _strings(p.get("urls"))
    if not urls:
        for f in r.get("fields") or []:
            label = str(f.get("label") or "").lower()
            if ("url" in label or "link" in label) and isinstance(f.get("value"), str):
                urls += [u.strip() for u in f["value"].splitlines() if u.strip()]
    hosting = " ".join(x for x in (clean_line(facts.get("as_name") or r.get("as_name"), 120),
                                    f"({clean_line(facts.get('ip_country') or r.get('ip_country'), 8)})"
                                    if (facts.get("ip_country") or r.get("ip_country")) else "") if x)
    return {
        "urls": urls[:EVIDENCE_URLS], "more_urls": max(0, len(urls) - EVIDENCE_URLS),
        "asks_for": _strings(facts.get("asks_for")),
        "form_posts_elsewhere": bool(facts.get("form_posts_elsewhere")),
        "registrar": clean_line(facts.get("registrar") or r.get("registrar"), 120),
        "hosting": hosting,
        "ips": _strings(facts.get("ips"))[:5],
        "page_seen": clean_line(facts.get("page_seen"), 40),
        "page_profile": clean_line(facts.get("page_profile"), 20),
        "egress_country": clean_line(facts.get("egress_country"), 8),
        "brand": clean_line(facts.get("brand") or p.get("brand") or r.get("brand_id"), 80),
        "page_id": p.get("page_id") if r.get("screenshot_url") and isinstance(p.get("page_id"), int) else None,
    }


def until_text(ts, now: datetime | None = None) -> str:
    """'now' or 'in 5m' for a next-attempt time (the shared ago filter is for the past)."""
    ts = aware(ts) if isinstance(ts, datetime) else None
    if ts is None:
        return "now"
    secs = (ts - (now or utcnow())).total_seconds()
    if secs <= 0:
        return "now"
    if secs < 60:
        return f"in {int(secs)}s"
    if secs < 3600:
        return f"in {int(secs // 60)}m"
    if secs < 86400:
        return f"in {int(secs // 3600)}h"
    return f"in {int(secs // 86400)}d"


def queue_counts(summary: dict, lists: dict, unreported: list) -> dict:
    """Counts for the KPI tiles and tabs. 'todo' is everything that waits for the reviewer."""
    n = {k: int(summary.get(k) or 0) for k in ("drafts", "manual", "queued", "sent", "sent_24h", "failed",
                                                "domains_reported")}
    n["unreported"] = len(unreported or [])
    n["closed"] = len(lists.get("closed") or [])
    n["todo"] = n["drafts"] + n["manual"] + n["failed"] + n["unreported"]
    return n


# ---- pages -----------------------------------------------------------------------------------------

async def _all(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchall()


async def _one(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchone()


async def reports_page(request: Request, msg: str = ""):
    cfg = load_config()
    sandbox = engine.current_sandbox(cfg)
    p = await db.pool()
    async with p.connection() as conn:
        summary = await _one(conn, SUMMARY_SQL) or {}
        used = (await _one(conn, engine.RATE_SQL) or {}).get("n", 0)
        lists = {k: [view(r) for r in await _all(conn, sql, (LIST_LIMITS.get(k, LIST_LIMIT),))]
                 for k, sql in LIST_SQL.items()}
        per_channel = [dict(r, label=channels.channel_label(r["channel"])) for r in await _all(conn, CHANNEL_COUNTS_SQL)]
        unreported = await _all(conn, UNREPORTED_SQL)
        kv = {r["key"]: r for r in await _all(conn, KV_SQL, ([engine.KV_PAUSE, "job:report"],))}
    now = utcnow()
    paused = {}
    pause = (kv.get(engine.KV_PAUSE) or {}).get("value")
    for ch, until in (pause.items() if isinstance(pause, dict) else ()):
        ts = _parse_ts(until)
        if ts and ts > now:
            paused[channels.channel_label(ch)] = ts
    job = (kv.get("job:report") or {}).get("value") or {}
    for rows in lists.values():
        for r in rows:
            r["step"] = next_step(r, cfg)
            r["next_try"] = until_text(r.get("next_attempt_at"), now)
    return _templates.TemplateResponse(request, "reports_index.html", {
        "cfg": cfg, "sandbox": sandbox, "banner": banner(cfg, sandbox), "summary": summary, "used": used,
        "lists": lists, "per_channel": per_channel, "unreported": unreported, "paused": paused, "job": job,
        "not_used": channels.NOT_USED, "message": MESSAGES.get(msg), "message_tone": MESSAGE_TONES.get(msg, "info"),
        "limit": LIST_LIMIT, "counts": queue_counts(summary, lists, unreported),
        "mailto_soft_max": MAILTO_SOFT_MAX})


async def report_detail(request: Request, report_id: int, msg: str = ""):
    cfg = load_config()
    p = await db.pool()
    async with p.connection() as conn:
        row = await _one(conn, DETAIL_SQL, (report_id,))
        if not row:
            raise HTTPException(404)
        attempts = await _all(conn, ATTEMPTS_SQL, (report_id,))
    r = view(row)
    payload = {k: v for k, v in r["payload"].items() if k not in ("body", "template_body", "ai_body")}
    r["step"] = next_step(r, cfg)
    r["next_try"] = until_text(r.get("next_attempt_at"))
    return _templates.TemplateResponse(request, "reports_detail.html", {
        "r": r, "cfg": cfg, "attempts": attempts, "payload": payload, "message": MESSAGES.get(msg),
        "message_tone": MESSAGE_TONES.get(msg, "info"), "evidence": evidence_view(r),
        "mailto_soft_max": MAILTO_SOFT_MAX,
        "template_body": r["payload"].get("template_body") or "", "ai_body": r["payload"].get("ai_body") or ""})


async def report_screenshot(report_id: int):
    """The stored screenshot as a JPEG to attach by hand (Linkt's form needs jpeg/png). Image only."""
    cfg = load_config()
    p = await db.pool()
    async with p.connection() as conn:
        row = await _one(conn, "SELECT domain_id, payload FROM reports WHERE id = %s", (report_id,))
        page_id = ((row or {}).get("payload") or {}).get("page_id") if row else None
        if not row or not isinstance(page_id, int):
            raise HTTPException(404)
        page = await _one(conn, SCREENSHOT_SQL, (page_id, row["domain_id"]))
    if not page or not page.get("screenshot_path"):
        raise HTTPException(404)
    jpeg = await asyncio.to_thread(evidence.screenshot_jpeg, cfg.data_dir, page["screenshot_path"])
    if not jpeg:
        raise HTTPException(404)
    return Response(jpeg, media_type="image/jpeg", headers={
        "Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="report-{int(report_id)}-screenshot.jpg"',
        "Cache-Control": "no-store"})


# ---- actions ---------------------------------------------------------------------------------------

def _back(msg: str, report_id: int | None = None, detail: bool = False) -> RedirectResponse:
    if detail and report_id is not None:
        return RedirectResponse(f"/reports/{int(report_id)}?msg={msg}", status_code=303)
    anchor = f"#r{int(report_id)}" if report_id is not None else ""
    return RedirectResponse(f"/reports?msg={msg}{anchor}", status_code=303)


def _edits(to: str, subject: str, body: str, who: str, row: dict) -> dict:
    out = {"to": clean_line(to, 254), "subject": clean_line(subject, 200),
           "body": clean_text(body, texts.DRAFT_MAX), "edited_by": who, "edited_at": utcnow().isoformat()}
    if (row.get("payload") or {}).get("ai") == "pending":
        out["ai"] = "edited"          # the worker's AI draft must never overwrite a reviewer's text
    return out


async def create_reports(request: Request, domain_id: int):
    same_origin(request)
    who = reviewer(request)
    cfg = load_config()
    p = await db.pool()
    async with p.connection() as conn:
        d = await _one(conn, engine.ONE_DOMAIN_SQL, (domain_id,))
        if not d:
            raise HTTPException(404)
        d = dict(d)
        if d.get("status") != "confirmed":
            return _back("not_confirmed")
        if d.get("takedown_at"):
            return _back("taken_down")
        if evidence.is_official(d):
            return _back("official")
        created = await engine.plan_for_domain(conn, cfg, d, "confirmed", by=who)
    return _back("created" if created else "nothing")


async def save_draft(request: Request, report_id: int, to: str = Form(""), subject: str = Form(""),
                     body: str = Form(""), back: str = Form("")):
    same_origin(request)
    who = reviewer(request)
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            row = await _one(conn, LOCK_SQL, (report_id,))
            if not row:
                raise HTTPException(404)
            if row["kind"] != "email" or row["status"] not in ("pending_review", "failed"):
                return _back("not_pending", report_id, back == "detail")
            await conn.execute(SAVE_SQL, (db.jsonb(json_safe(_edits(to, subject, body, who, row))), report_id))
    return _back("saved", report_id, back == "detail")


async def approve_draft(request: Request, report_id: int, to: str = Form(""), subject: str = Form(""),
                        body: str = Form(""), back: str = Form("")):
    """Queue an email draft for the worker to send over SMTP (rate-limited). Only for confirmed domains."""
    same_origin(request)
    who = reviewer(request)
    cfg = load_config()
    detail = back == "detail"
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            row = await _one(conn, LOCK_SQL, (report_id,))
            if not row:
                raise HTTPException(404)
            if row["kind"] != "email" or row["status"] not in ("pending_review", "failed"):
                return _back("not_pending", report_id, detail)
            edits = _edits(to, subject, body, who, row)
            await conn.execute(SAVE_SQL, (db.jsonb(json_safe(edits)), report_id))   # keep the edits either way
            if row["domain_status"] in CLOSED_STATUSES:
                return _back("closed", report_id, detail)
            if row["domain_status"] != "confirmed":
                return _back("not_confirmed", report_id, detail)
            if not valid_email(edits["to"]):
                return _back("bad_to", report_id, detail)
            if await engine.contact_problem(conn, edits["to"], row):
                return _back("unsafe_to", report_id, detail)
            if cfg.mode == "off":
                return _back("mode_off", report_id, detail)
            if not cfg.smtp:
                return _back("no_smtp", report_id, detail)
            await conn.execute(APPROVE_SQL, (who, db.jsonb({"approved_by": who}), report_id))
    return _back("queued", report_id, detail)


async def mark_sent(request: Request, report_id: int, to: str = Form(""), subject: str = Form(""),
                    body: str = Form(""), back: str = Form("")):
    """A reviewer sent the email from their own client, or filed the web form: record it."""
    same_origin(request)
    who = reviewer(request)
    detail = back == "detail"
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            row = await _one(conn, LOCK_SQL, (report_id,))
            if not row:
                raise HTTPException(404)
            if row["kind"] not in ("email", "manual") or row["status"] not in ("pending_review", "approved", "failed"):
                return _back("not_pending", report_id, detail)
            if row["domain_status"] in CLOSED_STATUSES:
                return _back("closed", report_id, detail)
            update: dict = {"marked_sent_by": who}
            if row["kind"] == "email":
                edits = _edits(to, subject, body, who, row)
                await conn.execute(SAVE_SQL, (db.jsonb(json_safe(edits)), report_id))
                if not valid_email(edits["to"]):
                    return _back("bad_to", report_id, detail)
            await conn.execute(MARK_SENT_SQL, (who, who, db.jsonb(update), report_id))
            await engine.mark_domain_reported(conn, row["domain_id"], {
                "channel": row["channel"], "via": "manual", "report_id": report_id, "by": who,
                "reviewed_by_human": True})
    return _back("sent" if row["kind"] == "email" else "done", report_id, detail)


async def reject_report(request: Request, report_id: int, note: str = Form(""), back: str = Form("")):
    same_origin(request)
    who = reviewer(request)
    detail = back == "detail"
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            row = await _one(conn, LOCK_SQL, (report_id,))
            if not row:
                raise HTTPException(404)
            if row["status"] not in ("pending_review", "approved", "failed", "skipped"):
                return _back("not_pending", report_id, detail)
            reason = "rejected by " + clean_line(who, 80) + (": " + clean_line(note, 300) if note.strip() else "")
            await conn.execute(REJECT_SQL, (who, reason, report_id))
    return _back("rejected", report_id, detail)


async def retry_report(request: Request, report_id: int, back: str = Form("")):
    """Queue a failed (or held / skipped) API or email report again. Only for confirmed domains."""
    same_origin(request)
    who = reviewer(request)
    cfg = load_config()
    detail = back == "detail"
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            row = await _one(conn, LOCK_SQL, (report_id,))
            if not row:
                raise HTTPException(404)
            if row["kind"] not in ("api", "email"):
                return _back("not_api", report_id, detail)
            if row["status"] not in ("failed", "approved", "skipped"):
                return _back("not_pending", report_id, detail)
            if row["domain_status"] in CLOSED_STATUSES:
                return _back("closed", report_id, detail)
            if row["domain_status"] != "confirmed":
                return _back("not_confirmed", report_id, detail)
            if row["kind"] == "email":
                to = (row["payload"] or {}).get("to") or ""
                if not valid_email(to):
                    return _back("bad_to", report_id, detail)
                if await engine.contact_problem(conn, to, row):
                    return _back("unsafe_to", report_id, detail)
                if not cfg.smtp:
                    return _back("no_smtp", report_id, detail)
            await conn.execute(RETRY_SQL, (who, report_id))
    return _back("retry", report_id, detail)


def register(app, templates, nav) -> None:
    global _templates
    _templates = templates
    app.add_api_route("/reports", reports_page, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/reports/create/{domain_id}", create_reports, methods=["POST"])
    app.add_api_route("/reports/{report_id}", report_detail, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/reports/{report_id}/screenshot.jpg", report_screenshot, methods=["GET"])
    app.add_api_route("/reports/{report_id}/save", save_draft, methods=["POST"])
    app.add_api_route("/reports/{report_id}/approve", approve_draft, methods=["POST"])
    app.add_api_route("/reports/{report_id}/sent", mark_sent, methods=["POST"])
    app.add_api_route("/reports/{report_id}/reject", reject_report, methods=["POST"])
    app.add_api_route("/reports/{report_id}/retry", retry_report, methods=["POST"])
    if ("/reports", "Reports") not in nav:
        nav.append(("/reports", "Reports"))
