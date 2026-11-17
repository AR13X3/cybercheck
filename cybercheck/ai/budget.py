"""AI configuration and the spending cap.

Every call is reserved before it is made: under a Postgres advisory lock the caller checks
spent_today + estimate against AI_DAILY_BUDGET_USD and spent_month + estimate against
AI_MONTHLY_BUDGET_USD (UTC day / month, summed from ai_calls), then inserts a 'pending' ai_calls
row whose cost_usd is the estimate. The lock is held only for that check+insert, so concurrent
callers (worker, bot, dashboard, other processes) always see each other's reservations and cannot
overspend together. When the call returns, the row is updated with the real cost from usage.
A row left 'pending' by a crashed process keeps its (conservative) estimate.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from ..config import settings

log = logging.getLogger("cybercheck.ai")

# pg_advisory_xact_lock key for the AI budget (any constant bigint unique within this database)
BUDGET_LOCK_KEY = 7_303_000_030

TRIAGE_PURPOSE = "domain_triage"


def _env(name: str, default: str) -> str:
    return (os.environ.get(name) or "").strip() or default


def _float_env(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class AIConfig:
    api_key: str
    enabled: bool
    model: str
    triage_model: str
    daily_cap: float
    monthly_cap: float
    triage_fraction: float
    effort: str
    fallbacks: str          # "default" | "off"
    timeout_s: float


def config() -> AIConfig:
    s = settings()
    fallbacks = _env("AI_FALLBACKS", "default").lower()
    effort = _env("AI_EFFORT", "low").lower()
    return AIConfig(
        api_key=s.anthropic_api_key,
        enabled=s.ai_enabled,
        model=s.ai_model or "claude-opus-5-5",
        triage_model=_env("AI_TRIAGE_MODEL", s.ai_model or "claude-opus-5-5"),
        daily_cap=max(0.0, float(s.ai_daily_budget_usd)),
        monthly_cap=max(0.0, float(s.ai_monthly_budget_usd)),
        triage_fraction=min(1.0, max(0.0, _float_env("AI_TRIAGE_BUDGET_FRACTION", 0.25))),
        effort=effort if effort in ("low", "medium", "high", "xhigh", "max") else "low",
        fallbacks="off" if fallbacks in ("off", "none", "false", "0", "no") else "default",
        timeout_s=_float_env("AI_TIMEOUT_S", 120.0),
    )


def unavailable_reason(cfg: AIConfig | None = None) -> str | None:
    """Why AI can't be used at all (independent of spend), or None."""
    cfg = cfg or config()
    if not cfg.enabled:
        return "AI_ENABLED is false"
    if not cfg.api_key:
        return "ANTHROPIC_API_KEY is not set"
    if cfg.daily_cap <= 0 or cfg.monthly_cap <= 0:
        return "AI budget is set to 0"
    return None


_logged: set[str] = set()


def log_once(key: str, msg: str, *args, level: int = logging.WARNING) -> None:
    """Log a message once per process per key (keys can include the UTC day to repeat daily)."""
    if key in _logged:
        return
    if len(_logged) > 1000:
        _logged.clear()
    _logged.add(key)
    log.log(level, msg, *args)


SPENT_SQL = """
SELECT
  COALESCE(sum(cost_usd) FILTER (WHERE at >= date_trunc('day', now(), 'UTC')), 0) AS today,
  COALESCE(sum(cost_usd), 0) AS month,
  COALESCE(sum(cost_usd) FILTER (WHERE at >= date_trunc('day', now(), 'UTC') AND purpose = %s), 0) AS triage_today,
  count(*) FILTER (WHERE at >= date_trunc('day', now(), 'UTC')) AS calls_today,
  count(*) AS calls_month,
  count(*) FILTER (WHERE at >= date_trunc('day', now(), 'UTC') AND status = 'refusal') AS refusals_today,
  count(*) FILTER (WHERE status = 'refusal') AS refusals_month,
  count(*) FILTER (WHERE at >= date_trunc('day', now(), 'UTC') AND status IN ('api_error', 'error', 'invalid')) AS errors_today
FROM ai_calls
WHERE at >= date_trunc('month', now(), 'UTC')
"""


async def spent(conn) -> dict:
    row = await (await conn.execute(SPENT_SQL, (TRIAGE_PURPOSE,))).fetchone()
    row = dict(row or {})
    for k in ("today", "month", "triage_today"):
        row[k] = float(row.get(k) or 0)
    for k in ("calls_today", "calls_month", "refusals_today", "refusals_month", "errors_today"):
        row[k] = int(row.get(k) or 0)
    return row


def _over(spend: dict, estimate: float, cfg: AIConfig, purpose: str) -> str | None:
    if spend["today"] + estimate > cfg.daily_cap:
        return f"daily AI budget reached (${spend['today']:.2f} of ${cfg.daily_cap:.2f} spent today, next call up to ${estimate:.3f})"
    if spend["month"] + estimate > cfg.monthly_cap:
        return f"monthly AI budget reached (${spend['month']:.2f} of ${cfg.monthly_cap:.2f} spent this month)"
    if purpose == TRIAGE_PURPOSE:
        cap = cfg.daily_cap * cfg.triage_fraction
        if spend["triage_today"] + estimate > cap:
            return f"daily triage share reached (${spend['triage_today']:.2f} of ${cap:.2f})"
    return None


def _in_transaction(conn) -> bool:
    info = getattr(conn, "info", None)
    status = getattr(info, "transaction_status", None)
    if status is None:
        return False
    try:
        from psycopg import pq
        return status != pq.TransactionStatus.IDLE
    except Exception:  # pragma: no cover
        return False


async def reserve(conn, *, purpose: str, model: str, estimate: float, domain_id: int | None = None,
                  page_id: int | None = None, cfg: AIConfig | None = None) -> tuple[int | None, str | None]:
    """Check the caps and record a pending call atomically. Returns (ai_call_id, None) or (None, reason)."""
    cfg = cfg or config()
    if _in_transaction(conn):
        # Inside a caller's transaction the reservation (and the lock) would only become visible
        # to other callers when that transaction commits, after the API call: concurrent calls
        # could then overspend. Refuse rather than weaken the cap.
        log_once("reserve:in-transaction", "AI call refused: it was made inside an open database transaction")
        return None, "AI calls must not be made inside an open database transaction"
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(%s)", (BUDGET_LOCK_KEY,))
        spend = await spent(conn)
        reason = _over(spend, estimate, cfg, purpose)
        if reason:
            return None, reason
        row = await (await conn.execute(
            "INSERT INTO ai_calls (purpose, domain_id, page_id, model, cost_usd, estimated_cost_usd, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'pending') RETURNING id",
            (purpose, domain_id, page_id, model, estimate, estimate))).fetchone()
    return int(row["id"]), None


async def finish(conn, call_id: int, *, status: str, model: str, cost_usd: float, tokens: dict | None = None,
                 stop_reason: str | None = None, result=None, error: str | None = None,
                 duration_ms: int | None = None, fallback_model: str | None = None) -> None:
    from ..db import jsonb
    t = tokens or {}
    await conn.execute(
        "UPDATE ai_calls SET status = %s, model = %s, cost_usd = %s, input_tokens = %s, output_tokens = %s, "
        "cache_read_tokens = %s, cache_write_tokens = %s, stop_reason = %s, result = %s, error = %s, "
        "duration_ms = %s, fallback_model = %s WHERE id = %s",
        (status, model, round(float(cost_usd), 6), int(t.get("input_tokens", 0)), int(t.get("output_tokens", 0)),
         int(t.get("cache_read_tokens", 0)), int(t.get("cache_write_tokens", 0)), stop_reason,
         jsonb(result) if result is not None else None, (error or None) and error[:1000], duration_ms,
         fallback_model, call_id))


async def status(conn) -> dict:
    """Budget status for budget_status() and the dashboard."""
    cfg = config()
    out = {"enabled": cfg.enabled, "spent_today": 0.0, "spent_month": 0.0, "daily_cap": cfg.daily_cap,
           "monthly_cap": cfg.monthly_cap, "available": False, "reason": "", "model": cfg.model,
           "has_key": bool(cfg.api_key), "triage_spent_today": 0.0,
           "triage_cap": round(cfg.daily_cap * cfg.triage_fraction, 4), "effort": cfg.effort,
           "fallbacks": cfg.fallbacks, "calls_today": 0, "calls_month": 0, "refusals_today": 0,
           "refusals_month": 0, "errors_today": 0}
    try:
        spend = await spent(conn)
    except Exception as e:  # dashboard and callers keep working without the numbers
        log.exception("could not read AI spend")
        out["reason"] = f"could not read AI spend: {type(e).__name__}"
        return out
    out.update(spent_today=round(spend["today"], 6), spent_month=round(spend["month"], 6),
               triage_spent_today=round(spend["triage_today"], 6),
               **{k: spend[k] for k in ("calls_today", "calls_month", "refusals_today", "refusals_month", "errors_today")})
    reason = unavailable_reason(cfg)
    if reason is None:
        reason = _over(spend, 0.0, cfg, "") or ("daily AI budget used up" if spend["today"] >= cfg.daily_cap else None) \
            or ("monthly AI budget used up" if spend["month"] >= cfg.monthly_cap else None)
    out["available"] = reason is None
    out["reason"] = reason or "ok"
    return out


def utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")
