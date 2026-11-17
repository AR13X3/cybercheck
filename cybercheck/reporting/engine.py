"""Report planning, the send queue and result bookkeeping (worker job "report", cybercheck/jobs/report.py).

Each run (REPORTING_MODE off: nothing at all):
1. Pending or queued reports of domains a reviewer marked false_positive / benign are skipped.
2. Trigger 1, reviewer-confirmed domains (confirmed within REPORT_LOOKBACK_DAYS, not taken down): one row
   per applicable channel (UNIQUE (domain_id, channel) dedupes). Automated channels (Netcraft) are queued;
   email drafts (registrar, host, the brand's verified mailbox) and manual web-form checklist items wait
   for a reviewer on /reports.
3. Trigger 2, REPORTING_MODE=auto only: open domains with final_score >= AUTO_REPORT_MIN_FINAL_SCORE
   (never below 90), AI verdict phishing, a newest snapshot that asks for a password / one-time code /
   card details, and a valid data/sandbox_verified.json (at most 30 days old): automated channels only.
   Email and manual drafts wait until a reviewer confirms the domain.
4. AI drafts (cybercheck.ai.api.draft_report) replace the template text of a few email drafts.
5. The send queue: at most REPORT_RATE_PER_HOUR delivery attempts per hour across all channels, at least
   REPORT_CHANNEL_MIN_INTERVAL_S between attempts on one channel. Items over the limit wait; nothing is
   dropped. Eligibility is checked again just before sending. Failures retry with back-off, then 'failed'.
   A send interrupted mid-way (worker killed, database lost) has an unknown outcome: after 15 minutes it
   becomes 'failed' for a reviewer to check and retry, never re-sent automatically.
6. Netcraft submissions are polled for their state until archived (30 days).

On the first successful send of a domain (or when a reviewer marks an email / manual report as sent),
domains.reported_at is set; every success adds a 'reported' event with the channel.

NETCRAFT_TEST=true sends to Netcraft's test endpoint. Such a submission is not a report: the row becomes
'skipped' (response.test = true) and reported_at is not set. It is not sent to the test endpoint again, and
once NETCRAFT_TEST is off it is queued for production (confirmed domains, and unreviewed domains that still
meet the automatic-report rules).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .. import db
from . import channels, evidence, mailer, netcraft, texts
from .channels import API, EMAIL, NETCRAFT
from .common import SendResult, aware, clean_line, json_safe, utcnow, valid_email
from .conf import SANDBOX_MAX_AGE_DAYS, ReportConfig, load_config

log = logging.getLogger("cybercheck.reporting")

LOCK_KEY = 7_303_000_040          # pg_try_advisory_xact_lock: one claimer at a time
MAX_SENDS_PER_RUN = 10
BACKOFF_S = (300, 900, 3600, 3 * 3600, 12 * 3600)
HOLD_S = 900                      # re-check a held item (channel not configured yet) after this long
CONFIRMED_LIMIT = 300
AUTO_LIMIT = 20
POLL_EVERY_S = 6 * 3600
POLL_PER_RUN = 5
HOUSEKEEP_EVERY_S = 6 * 3600
ATTEMPT_RETENTION_DAYS = 180
KV_PAUSE = "report:pause"         # {channel: ISO time} set when a channel answers 429

DOMAIN_COLS = """d.id, d.registered_domain, d.unicode_domain, d.tld, d.brand_id, d.score, d.tier, d.hostnames,
       d.source, d.first_seen, d.issuer, d.ct_log, d.status, d.status_changed_at, d.status_by, d.dns_state,
       d.ips, d.asn, d.as_name, d.ip_country, d.registrar, d.registrar_iana_id, d.registrar_abuse_email,
       d.hosting_abuse_email, d.registered_at, d.live_state, d.ai_verdict, d.ai_confidence, d.ai_brand,
       d.final_score, d.reported_at, d.takedown_at"""

HAVE_COLS = """COALESCE((SELECT array_agg(r.channel) FROM reports r WHERE r.domain_id = d.id), ARRAY[]::text[]) AS have,
       COALESCE((SELECT array_agg(r.channel) FROM reports r WHERE r.domain_id = d.id AND r.status = 'skipped'
                 AND r.kind = 'api'), ARRAY[]::text[]) AS revivable,
       COALESCE((SELECT array_agg(r.channel) FROM reports r WHERE r.domain_id = d.id AND r.status = 'skipped'
                 AND r.kind = 'api' AND r.response->>'test' = 'true'), ARRAY[]::text[]) AS revivable_test"""

CONFIRMED_SQL = f"""
SELECT {DOMAIN_COLS},
       {HAVE_COLS}
FROM domains d
WHERE d.status = 'confirmed' AND d.takedown_at IS NULL
  AND COALESCE(d.status_changed_at, d.first_seen) > now() - make_interval(days => %s)
ORDER BY (NOT EXISTS (SELECT 1 FROM reports r WHERE r.domain_id = d.id)) DESC, d.status_changed_at DESC NULLS LAST
LIMIT %s
"""

ONE_DOMAIN_SQL = f"""
SELECT {DOMAIN_COLS},
       {HAVE_COLS}
FROM domains d WHERE d.id = %s
"""

# The SQL pre-filters on the same rules evidence.auto_eligible() checks (which stays the authority), so
# domains that fail them (typically: the newest snapshot errored or no longer asks for credentials while
# final_score is still high) cannot fill the LIMIT forever and starve eligible ones.
# Params: min score, automated channels, NETCRAFT_TEST on, limit. A row that only went to Netcraft's test
# endpoint does not count as reported once test mode is off (plan_for_domain then queues it again).
AUTO_CANDIDATES_SQL = f"""
SELECT {DOMAIN_COLS},
       {HAVE_COLS}
FROM domains d
WHERE d.status = 'open' AND d.final_score >= %s AND d.ai_verdict = 'phishing' AND d.takedown_at IS NULL
  -- ai_confidence is real: compared with the numeric 0.7 it is widened to double precision, and a stored 0.7
  -- (0.69999999) would fail, although Python (auto_eligible, confidence.py, the blocklist) reads it as 0.7
  AND COALESCE(d.ai_confidence, 0) >= 0.7::real
  AND right(d.registered_domain, 7) <> '.gov.au'
  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.domain_id = d.id AND r.channel = ANY(%s)
                  AND (%s OR r.status <> 'skipped' OR COALESCE(r.response->>'test', '') <> 'true'))
  AND EXISTS (SELECT 1 FROM pages p
              WHERE p.domain_id = d.id AND p.error IS NULL
                AND (p.has_password_field OR p.has_otp_field OR p.has_card_field)
                AND (p.http_status IS NULL OR p.http_status = 0 OR p.http_status BETWEEN 200 AND 399)
                AND p.fetched_at >= (SELECT max(p2.fetched_at) FROM pages p2 WHERE p2.domain_id = d.id)
                                    - interval '15 minutes')
ORDER BY d.final_score DESC, d.first_seen DESC
LIMIT %s
"""

PAGES_SQL = """
SELECT id, domain_id, fetched_at, url, final_url, http_status, user_agent_profile, egress_ip,
       has_password_field, has_otp_field, has_card_field, external_form_post, screenshot_path, error
FROM pages WHERE domain_id = %s ORDER BY fetched_at DESC, id DESC LIMIT 12
"""

INSERT_SQL = """
INSERT INTO reports (domain_id, channel, status, auto, kind, payload, next_attempt_at, updated_at)
VALUES (%s, %s, %s, %s, %s, %s, now(), now())
ON CONFLICT (domain_id, channel) DO NOTHING
RETURNING id
"""

# Params: auto, domain id, channels, test rows allowed (NETCRAFT_TEST off), test rows only (trigger auto).
REVIVE_SQL = """
UPDATE reports SET status = 'approved', auto = %s, error = NULL, attempts = 0, next_attempt_at = now(),
       updated_at = now()
WHERE domain_id = %s AND channel = ANY(%s) AND status = 'skipped' AND kind = 'api'
  AND (%s OR COALESCE(response->>'test', '') <> 'true')
  AND (NOT %s OR response->>'test' = 'true')
RETURNING id, channel
"""

TEST_NOTE = ("test submission (NETCRAFT_TEST): sent to Netcraft's test endpoint, not reported to production; "
             "queued again for production once NETCRAFT_TEST is off")

# Before this rule existed, test submissions were recorded as 'sent'. Turn them into test rows, and clear
# reported_at where nothing real was sent (the CTEs share one snapshot: test rows still look 'sent' there).
RELEASE_TEST_SQL = """
WITH t AS (
    UPDATE reports SET status = 'skipped', error = %s, updated_at = now()
    WHERE channel = 'netcraft' AND status = 'sent' AND response->>'test' = 'true'
    RETURNING id, domain_id
), d AS (
    UPDATE domains SET reported_at = NULL
    WHERE id IN (SELECT domain_id FROM t)
      AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.domain_id = domains.id AND r.status = 'sent'
                      AND COALESCE(r.response->>'test', '') <> 'true')
    RETURNING id
)
SELECT (SELECT count(*) FROM t) AS released, (SELECT count(*) FROM d) AS unreported
"""

# Abuse contacts on a domain CyberCheck itself tracks as suspicious are not pre-filled or sent to.
FLAGGED_CONTACT_SQL = """
SELECT registered_domain FROM domains WHERE registered_domain = ANY(%s) AND status IN ('open', 'confirmed')
"""

CANCEL_CLOSED_SQL = """
UPDATE reports r SET status = 'skipped', error = 'domain marked ' || d.status || ' by a reviewer; not sent',
       updated_at = now()
FROM domains d
WHERE d.id = r.domain_id AND d.status IN ('false_positive', 'benign') AND r.status IN ('pending_review', 'approved')
RETURNING r.id
"""

# The channel may have accepted it before the worker died: never re-send blindly (duplicate submissions or
# emails). 'failed' waits for a reviewer, who can check and use Retry on the dashboard.
RECOVER_SQL = """
UPDATE reports SET status = 'failed',
       error = 'interrupted while sending: the outcome is unknown (it may have been delivered); check Netcraft '
               || 'or the mailbox before using Retry',
       updated_at = now()
WHERE status = 'sending' AND last_attempt_at < now() - interval '15 minutes'
RETURNING id
"""

RECOVER_ATTEMPTS_SQL = """
UPDATE report_attempts SET ok = false, error = 'interrupted (outcome unknown)'
WHERE ok IS NULL AND at < now() - interval '15 minutes'
"""

AI_PENDING_SQL = """
SELECT r.id, r.domain_id, r.channel, r.payload, d.registered_domain, d.brand_id
FROM reports r JOIN domains d ON d.id = r.domain_id
WHERE r.status = 'pending_review' AND r.kind = 'email' AND r.payload->>'ai' = 'pending'
ORDER BY r.created_at
LIMIT %s
"""

AI_SAVE_SQL = """
UPDATE reports SET payload = payload || %s, updated_at = now()
WHERE id = %s AND status = 'pending_review' AND payload->>'ai' = 'pending'
"""

LOCK_SQL = "SELECT pg_try_advisory_xact_lock(%s) AS locked"

RATE_SQL = "SELECT count(*) AS n FROM report_attempts WHERE at > now() - interval '1 hour'"

CHANNEL_BUSY_SQL = """
SELECT DISTINCT channel FROM report_attempts WHERE at > now() - make_interval(secs => %s)
"""

# Param: the channels that cannot send right now (per-channel interval, 429 pause). Their items go last, so
# a backlog of more than LIMIT of them (Netcraft paused for hours) cannot hide items on free channels.
QUEUE_SQL = f"""
SELECT r.id AS report_id, r.channel, r.kind, r.auto, r.attempts, r.payload, {DOMAIN_COLS}
FROM reports r JOIN domains d ON d.id = r.domain_id
WHERE r.status = 'approved' AND (r.next_attempt_at IS NULL OR r.next_attempt_at <= now())
ORDER BY r.channel = ANY(%s::text[]), r.auto, r.next_attempt_at NULLS FIRST, r.id
LIMIT 50
FOR UPDATE OF r SKIP LOCKED
"""

SKIP_SQL = """
UPDATE reports SET status = 'skipped', error = %s, updated_at = now()
WHERE id = %s AND status IN ('approved', 'pending_review')
"""

HOLD_SQL = """
UPDATE reports SET next_attempt_at = now() + make_interval(secs => %s), error = %s, updated_at = now()
WHERE id = %s AND status = 'approved'
"""

CLAIM_SQL = """
UPDATE reports SET status = 'sending', attempts = attempts + 1, last_attempt_at = now(), updated_at = now()
WHERE id = %s AND status = 'approved'
RETURNING attempts
"""

ATTEMPT_SQL = "INSERT INTO report_attempts (report_id, channel, via) VALUES (%s, %s, %s) RETURNING id"

SCREENSHOT_SQL = "SELECT screenshot_path FROM pages WHERE id = %s AND domain_id = %s"

ATTEMPT_DONE_SQL = """
UPDATE report_attempts SET ok = %s, http_status = %s, error = %s, response = %s WHERE id = %s
"""

SENT_SQL = """
UPDATE reports SET status = 'sent', sent_at = now(), sent_via = %s, sent_by = 'worker', external_id = %s,
       response = %s, error = NULL, updated_at = now(), payload = payload || %s
WHERE id = %s
"""

TEST_SENT_SQL = """
UPDATE reports SET status = 'skipped', external_id = %s, response = %s, error = %s, updated_at = now(),
       payload = payload || %s
WHERE id = %s
"""

REPORTED_SQL = "UPDATE domains SET reported_at = COALESCE(reported_at, now()) WHERE id = %s"

RETRY_SQL = """
UPDATE reports SET status = 'approved', next_attempt_at = now() + make_interval(secs => %s), error = %s,
       response = %s, updated_at = now(), payload = payload || %s
WHERE id = %s
"""

FAIL_SQL = """
UPDATE reports SET status = 'failed', error = %s, response = %s, updated_at = now(), payload = payload || %s
WHERE id = %s
"""

POLL_DUE_SQL = """
SELECT id, external_id, response FROM reports
WHERE channel = 'netcraft' AND status = 'sent' AND external_id IS NOT NULL
  AND sent_at > now() - interval '31 days'
  AND (checked_at IS NULL OR checked_at < now() - make_interval(secs => %s))
  AND COALESCE(response->'status'->>'final', 'false') <> 'true'
ORDER BY checked_at NULLS FIRST
LIMIT %s
"""

POLL_SAVE_SQL = """
UPDATE reports SET checked_at = now(), response = COALESCE(response, '{}'::jsonb) || %s WHERE id = %s
"""

CLEAN_ATTEMPTS_SQL = "DELETE FROM report_attempts WHERE at < now() - make_interval(days => %s)"


async def _all(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchall()


async def _one(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchone()


async def mark_domain_reported(conn, domain_id: int, detail: dict) -> None:
    """A report went out (sent by the worker, or a reviewer marked an email / form as sent): set
    domains.reported_at the first time and add a 'reported' event naming the channel."""
    await conn.execute(REPORTED_SQL, (domain_id,))
    await db.add_event(conn, domain_id, "reported", json_safe(detail))


async def load_pages(conn, domain_id: int) -> list[dict]:
    return [dict(p) for p in await _all(conn, PAGES_SQL, (domain_id,))]


def current_sandbox(cfg: ReportConfig) -> evidence.SandboxStatus:
    return evidence.sandbox_status(cfg.sandbox_file, max_age_days=SANDBOX_MAX_AGE_DAYS)


def _parents(host: str) -> list[str]:
    labels = host.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


async def flagged_contact_domains(conn, addresses) -> frozenset[str]:
    """Registrable domains of these addresses that CyberCheck tracks as suspicious (open or confirmed)."""
    cands = sorted({p for a in addresses if valid_email(a) for p in _parents(a.rsplit("@", 1)[1])})
    if not cands:
        return frozenset()
    return frozenset(r["registered_domain"] for r in await _all(conn, FLAGGED_CONTACT_SQL, (cands,)))


async def contact_problem(conn, address: str, domain: dict) -> str:
    """Why an email must not go to `address` for this domain ('' = fine): see texts.contact_warning."""
    return texts.contact_warning(address, domain, await flagged_contact_domains(conn, [address]))


# ---- planning ----------------------------------------------------------------------------------------

def build_report_payload(spec: channels.Planned, facts: dict, domain: dict, cfg: ReportConfig,
                         trigger: str, by: str, flagged: frozenset = frozenset()) -> dict:
    """flagged: registrable domains CyberCheck tracks as suspicious, among the abuse contacts' domains."""
    base = {"kind": spec.kind, "trigger": trigger, "created_by": by, "label": channels.channel_label(spec.channel)}
    if spec.kind == API:
        return json_safe({**base, "urls": facts.get("urls"), "brand": facts.get("brand")})
    if spec.kind == EMAIL:
        to, hint = texts.recipient(spec.channel, domain, flagged)
        warning = texts.recipient_warning(spec.channel, domain, flagged)
        contact = channels.brand_contact(spec.channel.split(":", 1)[1]) if spec.channel.startswith("brand:") else None
        attach = bool(facts.get("screenshot")) and (contact.screenshots if contact else True)
        if facts.get("screenshot") and not attach:
            facts = {**facts, "screenshot": False}   # the recipient asks for none: do not mention one either
        body = texts.email_template(spec.channel, facts, cfg)
        return json_safe({**base, "to": to, "to_hint": hint, "to_warning": warning,
                          "subject": texts.email_subject(spec.channel, facts),
                          "body": body, "template_body": body,
                          "ai": "pending" if cfg.ai_drafts and cfg.ai_drafts_per_run > 0 and cfg.mode != "off"
                          else "off",
                          "facts": facts, "page_id": facts.get("page_id"), "attach_screenshot": attach})
    item = texts.manual_item(spec.channel, facts, domain)
    return json_safe({**base, **item, "page_id": facts.get("page_id"), "screenshot": facts.get("screenshot")})


async def plan_for_domain(conn, cfg: ReportConfig, domain: dict, trigger: str, *, pages: list[dict] | None = None,
                          sandbox: evidence.SandboxStatus | None = None, by: str = "worker") -> list[str]:
    """Create the missing report rows for one domain. Returns the channels created (or revived)."""
    if evidence.is_official(domain):
        return []
    specs = channels.plan(domain, cfg, trigger)
    have = set(domain.get("have") or [])
    missing = [s for s in specs if s.channel not in have]
    revivable = set(domain.get("revivable") or [])
    test_only = set(domain.get("revivable_test") or [])   # went to Netcraft's test endpoint only
    auto = trigger == "auto"
    if cfg.netcraft_test:
        revivable -= test_only        # never to the test endpoint twice
    if auto:
        revivable &= test_only        # unreviewed domains: only a test-only submission is queued again
    revive = [s.channel for s in specs if s.kind == API and s.channel in revivable]
    done: list[str] = []
    if revive:
        done += [r["channel"] for r in await _all(conn, REVIVE_SQL, (auto, domain["id"], revive,
                                                                     not cfg.netcraft_test, auto))]
    if not missing:
        return done
    if pages is None:
        pages = await load_pages(conn, domain["id"])
    page = (evidence.credential_page(pages, domain.get("registered_domain") or "") if trigger == "auto"
            else evidence.best_page(pages))
    sandbox = sandbox or current_sandbox(cfg)
    facts = evidence.build_facts(domain, page, pages, egress_country=sandbox.egress_country,
                                 egress_ip=sandbox.egress_ip)
    flagged = frozenset()
    if any(s.kind == EMAIL for s in missing):
        flagged = await flagged_contact_domains(conn, [domain.get("registrar_abuse_email"),
                                                       domain.get("hosting_abuse_email")])
    for spec in missing:
        payload = build_report_payload(spec, facts, domain, cfg, trigger, by, flagged)
        row = await _one(conn, INSERT_SQL, (domain["id"], spec.channel, spec.status, spec.auto, spec.kind,
                                            db.jsonb(payload)))
        if row:
            done.append(spec.channel)
    if done:
        log.info("planned reports for %s (%s): %s", domain.get("registered_domain"), trigger, ", ".join(done))
    return done


async def plan_confirmed(conn, cfg: ReportConfig, sandbox: evidence.SandboxStatus) -> int:
    n = 0
    for d in await _all(conn, CONFIRMED_SQL, (cfg.lookback_days, CONFIRMED_LIMIT)):
        n += len(await plan_for_domain(conn, cfg, dict(d), "confirmed", sandbox=sandbox))
    return n


async def plan_auto(conn, cfg: ReportConfig, sandbox: evidence.SandboxStatus) -> int:
    chans = channels.automated_channels(cfg)
    if cfg.mode != "auto" or not chans or not sandbox.ok:
        return 0
    n = 0
    for d in await _all(conn, AUTO_CANDIDATES_SQL, (cfg.min_final_score, chans, cfg.netcraft_test, AUTO_LIMIT)):
        d = dict(d)
        pages = await load_pages(conn, d["id"])
        ok, why = evidence.auto_eligible(d, pages, cfg, sandbox)
        if not ok:
            log.debug("not auto-reporting %s: %s", d.get("registered_domain"), why)
            continue
        n += len(await plan_for_domain(conn, cfg, d, "auto", pages=pages, sandbox=sandbox))
    return n


async def cancel_closed(conn) -> int:
    return len(await _all(conn, CANCEL_CLOSED_SQL))


async def recover_stuck(conn) -> int:
    await conn.execute(RECOVER_ATTEMPTS_SQL)
    rows = await _all(conn, RECOVER_SQL)
    if rows:
        log.warning("reports %s were interrupted while sending: marked failed (outcome unknown)",
                    ", ".join(str(r["id"]) for r in rows))
    return len(rows)


async def release_test_sends(conn) -> int:
    """Older test-endpoint submissions recorded as 'sent': make them test rows (see RELEASE_TEST_SQL)."""
    row = await _one(conn, RELEASE_TEST_SQL, (TEST_NOTE,))
    n = int((row or {}).get("released") or 0)
    if n:
        log.warning("%d Netcraft test submission(s) were recorded as sent; now queued for production", n)
    return n


async def refresh_ai_drafts(conn, cfg: ReportConfig) -> int:
    if not cfg.ai_drafts or cfg.ai_drafts_per_run <= 0:
        return 0
    rows = await _all(conn, AI_PENDING_SQL, (cfg.ai_drafts_per_run,))
    if not rows:
        return 0
    from ..ai import api
    n = 0
    for r in rows:
        payload = r["payload"] or {}
        facts = payload.get("facts") or {}
        domain = {"id": r["domain_id"], "registered_domain": r["registered_domain"], "brand_id": r["brand_id"]}
        try:
            text = await api.draft_report(conn, domain, r["channel"], evidence.ai_facts(facts))
        except Exception:  # noqa: BLE001 - the template stays; AI is optional
            log.exception("AI draft failed for report %s", r["id"])
            text = None
        if text:
            update = {"body": texts.wrap_ai_body(text, facts, cfg), "ai": "used", "ai_body": text}
            n += 1
        else:
            update = {"ai": "unavailable"}
        await conn.execute(AI_SAVE_SQL, (db.jsonb(json_safe(update)), r["id"]))
    return n


# ---- sending -----------------------------------------------------------------------------------------

@dataclass
class Claim:
    item: dict
    attempts: int
    attempt_id: int
    via: str
    pages: list[dict] = field(default_factory=list)
    screenshot_rel: str | None = None
    egress_country: str | None = None
    egress_ip: str | None = None


def precheck(item: dict, cfg: ReportConfig) -> tuple[str, str]:
    """('send' | 'skip' | 'hold', reason) from the domain row alone (no pages needed)."""
    status = item.get("status")
    if status in ("false_positive", "benign"):
        return "skip", f"domain marked {status} by a reviewer; not sent"
    if item.get("takedown_at"):
        return "skip", "the site was taken down before this was sent"
    if evidence.is_official(item):
        return "skip", "official brand domain; never reported"
    kind = item.get("kind")
    if kind == API:
        if item.get("channel") != NETCRAFT.id:
            return "skip", f"no sender for channel {item.get('channel')}"
        if not cfg.netcraft_ready:
            return "hold", "waiting: Netcraft " + cfg.netcraft_reason()
    elif kind == EMAIL:
        if item.get("auto"):
            return "skip", "email reports are never sent automatically"
        if not cfg.smtp:
            return "hold", "waiting: " + (cfg.smtp_reason or "SMTP is off")
    else:
        return "skip", "manual items are not sent by the worker"
    if status != "confirmed" and not item.get("auto"):
        return "skip", "the domain is no longer confirmed by a reviewer"
    return "send", ""


async def _paused(conn) -> dict:
    value = await db.kv_get(conn, KV_PAUSE, {}) or {}
    now = utcnow()
    out = {}
    for ch, until in (value.items() if isinstance(value, dict) else []):
        ts = aware(_parse(until))
        if ts and ts > now:
            out[ch] = ts
    return out


def _parse(value):
    try:
        return datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


async def claim_next(conn, cfg: ReportConfig, sandbox: evidence.SandboxStatus, stats: dict) -> Claim | None:
    """In one transaction: rate limits, eligibility, then mark one queued report 'sending'."""
    async with conn.transaction():
        if not (await _one(conn, LOCK_SQL, (LOCK_KEY,)))["locked"]:
            return None
        used = (await _one(conn, RATE_SQL))["n"]
        if used >= cfg.rate_per_hour:
            stats["rate_limited"] = True
            return None
        busy = {r["channel"] for r in await _all(conn, CHANNEL_BUSY_SQL, (cfg.channel_min_interval_s,))}
        busy |= set(await _paused(conn))
        for item in await _all(conn, QUEUE_SQL, (sorted(busy),)):
            item = dict(item)
            rid = item["report_id"]
            action, why = precheck(item, cfg)
            if action == "skip":
                await conn.execute(SKIP_SQL, (why, rid))
                stats["skipped"] += 1
                continue
            if action == "hold":
                await conn.execute(HOLD_SQL, (HOLD_S, why, rid))
                stats["held"] += 1
                continue
            if item["channel"] in busy:
                stats["_waiting"].add(rid)
                continue
            pages: list[dict] = []
            shot = None
            if item["kind"] == API:
                pages = await load_pages(conn, item["id"])
                if item.get("status") != "confirmed":
                    ok, why = evidence.auto_eligible(item, pages, cfg, sandbox)
                    if not ok:
                        await conn.execute(SKIP_SQL, ("no longer meets the automatic-report rules: " + why, rid))
                        stats["skipped"] += 1
                        continue
            else:
                problem = await contact_problem(conn, (item.get("payload") or {}).get("to") or "", item)
                if problem:
                    await conn.execute(SKIP_SQL, ("not sent: " + problem, rid))
                    stats["skipped"] += 1
                    continue
                if (item.get("payload") or {}).get("attach_screenshot") and (item.get("payload") or {}).get("page_id"):
                    row = await _one(conn, SCREENSHOT_SQL, (item["payload"]["page_id"], item["id"]))
                    shot = row["screenshot_path"] if row else None
            claimed = await _one(conn, CLAIM_SQL, (rid,))
            if not claimed:
                continue
            via = "api" if item["kind"] == API else "smtp"
            attempt = await _one(conn, ATTEMPT_SQL, (rid, item["channel"], via))
            return Claim(item=item, attempts=claimed["attempts"], attempt_id=attempt["id"], via=via, pages=pages,
                         screenshot_rel=shot, egress_country=sandbox.egress_country,
                         egress_ip=sandbox.egress_ip)
    return None


async def deliver(cfg: ReportConfig, claim: Claim, client) -> SendResult:
    item = claim.item
    if item["kind"] == API and item["channel"] == NETCRAFT.id:
        pages = claim.pages
        confirmed = item.get("status") == "confirmed"
        page = (evidence.best_page(pages) if confirmed
                else evidence.credential_page(pages, item.get("registered_domain") or ""))
        facts = evidence.build_facts(item, page, pages, egress_country=claim.egress_country,
                                     egress_ip=claim.egress_ip)
        if not facts["urls"]:
            return SendResult(ok=False, permanent=True, error="no URL on the domain to report")
        jpeg = None
        if page and page.get("screenshot_path"):
            jpeg = await asyncio.to_thread(evidence.screenshot_jpeg, cfg.data_dir, page["screenshot_path"])
        reason, url_reason = texts.netcraft_reasons(facts)
        # country: where the site is known to be reachable. The targets are Australians (research: use AU).
        payload = netcraft.build_payload(cfg.reporter_email, facts["urls"], reason, url_reason, "AU", jpeg)
        return await netcraft.submit(client, netcraft.base_url(cfg.netcraft_test), payload)
    if item["kind"] == EMAIL and cfg.smtp:
        p = item.get("payload") or {}
        attachment = None
        if claim.screenshot_rel:
            jpeg = await asyncio.to_thread(evidence.screenshot_jpeg, cfg.data_dir, claim.screenshot_rel)
            if jpeg:
                attachment = (f"screenshot-{item.get('registered_domain') or 'site'}.jpg", jpeg)
        return await mailer.send(cfg.smtp, p.get("to") or "", p.get("subject") or "", p.get("body") or "",
                                 reply_to=cfg.reporter_email or None, attachment=attachment)
    return SendResult(ok=False, permanent=True, error=f"no sender for channel {item['channel']}")


async def record_result(conn, cfg: ReportConfig, claim: Claim, result: SendResult, stats: dict) -> None:
    item = claim.item
    rid, domain_id = item["report_id"], item["id"]
    response = json_safe(result.response or {})
    sent = db.jsonb(json_safe({"sent": result.sent})) if result.sent else db.jsonb({})
    error = clean_line(result.error, 500) or None
    async with conn.transaction():
        await conn.execute(ATTEMPT_DONE_SQL, (result.ok, result.http_status, error, db.jsonb(response),
                                              claim.attempt_id))
        if result.ok and response.get("test"):
            # Netcraft's test endpoint: nothing was reported. Not 'sent', no reported_at, and the
            # production submission follows once NETCRAFT_TEST is off (plan_for_domain revives it).
            await conn.execute(TEST_SENT_SQL, (result.external_id, db.jsonb(response), TEST_NOTE, sent, rid))
            stats["test"] = stats.get("test", 0) + 1
            return
        if result.ok:
            await conn.execute(SENT_SQL, (claim.via, result.external_id, db.jsonb(response), sent, rid))
            await mark_domain_reported(conn, domain_id, {
                "channel": item["channel"], "via": claim.via, "report_id": rid, "external_id": result.external_id,
                "by": "worker", "reviewed_by_human": item.get("status") == "confirmed"})
            stats["sent"] += 1
            return
        if result.http_status == 429:
            until = utcnow() + timedelta(seconds=result.retry_after or 900)
            pause = await db.kv_get(conn, KV_PAUSE, {}) or {}
            pause = pause if isinstance(pause, dict) else {}
            pause[item["channel"]] = until.isoformat()
            await db.kv_set(conn, KV_PAUSE, pause)
        if result.permanent or (claim.attempts >= cfg.max_attempts and result.http_status != 429):
            await conn.execute(FAIL_SQL, (error or "failed", db.jsonb(response), sent, rid))
            stats["failed"] += 1
            log.warning("report %s (%s) failed: %s", rid, item["channel"], error)
            return
        delay = BACKOFF_S[min(claim.attempts, len(BACKOFF_S)) - 1]
        if result.retry_after:
            delay = max(delay, int(result.retry_after))
        await conn.execute(RETRY_SQL, (delay, error, db.jsonb(response), sent, rid))
        stats["retry"] += 1


async def send_due(cfg: ReportConfig, sandbox: evidence.SandboxStatus, client) -> dict:
    stats = {"sent": 0, "test": 0, "retry": 0, "failed": 0, "skipped": 0, "held": 0, "waiting": 0,
             "rate_limited": False, "_waiting": set()}
    if cfg.rate_per_hour <= 0:
        stats["rate_limited"] = True
        stats["waiting"] = len(stats.pop("_waiting"))
        return stats
    pool = await db.pool()
    for _ in range(MAX_SENDS_PER_RUN):
        async with pool.connection() as conn:
            claim = await claim_next(conn, cfg, sandbox, stats)
        if claim is None:
            break
        try:
            result = await deliver(cfg, claim, client)
        except Exception as e:  # noqa: BLE001 - recorded as a failed attempt, retried with back-off
            log.exception("sending report %s failed", claim.item["report_id"])
            result = SendResult(ok=False, error=f"{type(e).__name__}: {clean_line(e, 200)}")
        async with pool.connection() as conn:
            await record_result(conn, cfg, claim, result, stats)
    stats["waiting"] = len(stats.pop("_waiting"))
    return stats


HISTORY_MAX = 40


def _state_key(status: dict) -> list:
    urls = status.get("urls") if isinstance(status.get("urls"), list) else []
    return [status.get("state"), bool(status.get("archived")),
            sorted((str(u.get("url")), str(u.get("url_state")), str(u.get("url_takedown_state")))
                   for u in urls if isinstance(u, dict))]


def status_history(old_response: dict, status: dict, at: str) -> list | None:
    """Netcraft state changes over time (the research asks to keep every url_state / url_takedown_state
    change before the 30-day archive). Returns the new list, or None when nothing changed."""
    history = old_response.get("status_history") if isinstance(old_response.get("status_history"), list) else []
    prev = old_response.get("status") if isinstance(old_response.get("status"), dict) else None
    if prev is not None and _state_key(prev) == _state_key(status):
        return None
    entry = {"at": at, "state": status.get("state"), "archived": bool(status.get("archived")),
             "urls": [{k: u.get(k) for k in ("url", "url_state", "url_takedown_state") if u.get(k) is not None}
                      for u in (status.get("urls") or [])[:20] if isinstance(u, dict)]}
    return (history + [entry])[-HISTORY_MAX:]


async def poll_netcraft(cfg: ReportConfig, client) -> int:
    if not cfg.netcraft_enabled:
        return 0
    pool = await db.pool()
    async with pool.connection() as conn:
        rows = await _all(conn, POLL_DUE_SQL, (POLL_EVERY_S, POLL_PER_RUN))
    n = 0
    for r in rows:
        old = r["response"] if isinstance(r["response"], dict) else {}
        test = bool(old.get("test"))
        status = await netcraft.poll(client, netcraft.base_url(test), r["external_id"])
        now = utcnow().isoformat()
        if status is not None:
            update = {"status": {**status, "checked_at": now}}
            history = status_history(old, status, now)
            if history is not None:
                update["status_history"] = history
        else:
            update = {"status_error": f"status check failed at {now}"}
        async with pool.connection() as conn:
            await conn.execute(POLL_SAVE_SQL, (db.jsonb(json_safe(update)), r["id"]))
        n += status is not None
    return n


async def run_once(ctx, cfg: ReportConfig | None = None, client=None) -> dict:
    cfg = cfg or load_config(getattr(ctx, "settings", None))
    if cfg.mode == "off":
        return {"mode": "off"}
    sandbox = current_sandbox(cfg)
    out: dict = {"mode": cfg.mode, "sandbox_ok": sandbox.ok}
    pool = await db.pool()
    async with pool.connection() as conn:
        out["cancelled"] = await cancel_closed(conn)
        out["recovered"] = await recover_stuck(conn)
        state = getattr(ctx, "state", None)
        if isinstance(state, dict) and ("housekept" not in state
                                        or time.monotonic() - state["housekept"] > HOUSEKEEP_EVERY_S):
            await conn.execute(CLEAN_ATTEMPTS_SQL, (ATTEMPT_RETENTION_DAYS,))
            out["test_released"] = await release_test_sends(conn)   # before planning, which re-queues them
            state["housekept"] = time.monotonic()
        out["planned"] = await plan_confirmed(conn, cfg, sandbox)
        out["auto_planned"] = await plan_auto(conn, cfg, sandbox)
        out["ai_drafts"] = await refresh_ai_drafts(conn, cfg)
    own = client is None
    client = client or netcraft.new_client()
    try:
        out.update(await send_due(cfg, sandbox, client))
        out["polled"] = await poll_netcraft(cfg, client)
    finally:
        if own:
            await client.aclose()
    return {k: v for k, v in out.items() if v or k in ("mode", "sent", "sandbox_ok")}


__all__ = ["run_once", "plan_for_domain", "mark_domain_reported", "ONE_DOMAIN_SQL", "RATE_SQL", "KV_PAUSE",
           "load_config", "current_sandbox"]
