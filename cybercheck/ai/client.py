"""One structured Claude call with availability check, budget reservation and cost recording.

Request shape (per the Claude API docs for claude-opus-5-5):
- no tools; the model only returns JSON constrained by `output_config.format` (json_schema)
- thinking can't be disabled on Opus 5.5, so `thinking` is omitted and cost is controlled with
  `output_config.effort` (AI_EFFORT, default "low")
- the stable system prompt is the first block and carries `cache_control` (prompt caching)
- server-side refusal fallback (`fallbacks: "default"`, beta server-side-fallback-2026-07-01) on the
  models that support it; `stop_reason` is checked for "refusal" before content is read
- the SDK's automatic retries are off; unbilled failures (HTTP 408/409/429/5xx/529, failed connects)
  are retried here under the same reservation, while a timeout or a connection lost after sending
  is recorded at the reserved estimate, since it may have been billed
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

import anthropic

from . import budget, pricing

log = logging.getLogger("cybercheck.ai")

FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that take server-side refusal fallbacks (Haiku 5.5 has none: a fallbacks list is a 400 there)
FALLBACK_MODELS = ("claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-2", "claude-fable-5-1")
# Where "default" fallbacks may route a refusal; used only for the worst-case cost bound
FALLBACK_TARGETS = ("claude-opus-5", "claude-opus-4-8")

SCHEMA_OVERHEAD_TOKENS = 400   # structured-output format instructions + message framing (estimate)

# The SDK's own retries are off: it also retries timeouts, and a timed-out request may have been
# processed and billed, which would put unrecorded spend past the cap. HTTP error responses
# (429 / 5xx / 529) and failed connects are not billed, so they are retried here instead, under the
# same reservation.
RETRY_STATUS = (408, 409, 429, 500, 502, 503, 504, 529)
MAX_ATTEMPTS = 3
RETRY_WAIT_MAX_S = 20.0
_sleep = asyncio.sleep          # patched in tests


@dataclass
class Outcome:
    status: str                    # ok | unavailable | over_budget | refusal | invalid | api_error | error
    data: Any = None
    http_status: int | None = None  # for api_error: the HTTP status (None for timeouts / network errors)
    call_id: int | None = None
    error: str | None = None
    retryable: bool = False
    category: str | None = None    # refusal category from stop_details
    cost_usd: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"


_client: anthropic.AsyncAnthropic | None = None
_client_key: tuple | None = None
_injected = False


def get_client(cfg: budget.AIConfig) -> anthropic.AsyncAnthropic:
    global _client, _client_key
    if _injected:
        return _client
    key = (cfg.api_key, cfg.timeout_s)
    if _client is None or _client_key != key:
        _client = anthropic.AsyncAnthropic(api_key=cfg.api_key, timeout=cfg.timeout_s, max_retries=0)
        _client_key = key
    return _client


def set_client(client) -> None:
    """Install a client (tests). None goes back to a lazily created real client."""
    global _client, _client_key, _injected
    _client, _client_key, _injected = client, None, client is not None


def supports_fallbacks(model: str) -> bool:
    m = model.lower()
    return any(m == f or m.startswith(f + "-") for f in FALLBACK_MODELS)


def _text_tokens(text: str) -> int:
    """Upper estimate: ~3 ASCII characters per token, and up to 2 tokens per non-ASCII character
    (CJK, Cyrillic, emoji and escaped look-alike characters tokenise far worse than English)."""
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    return (len(text) - non_ascii) // 3 + 2 * non_ascii + 1


def estimate_input_tokens(system: str, content: list[dict], image_tokens: int = 0) -> int:
    """Rough upper estimate of the prompt size."""
    n = _text_tokens(system) + SCHEMA_OVERHEAD_TOKENS + image_tokens
    for block in content:
        if block.get("type") == "text":
            n += _text_tokens(block.get("text", "")) + 10
    return n


def _short(e: Exception) -> str:
    msg = getattr(e, "message", None) or str(e)
    return " ".join(str(msg).split())[:300]


async def _finish(conn, call_id: int, **kw) -> None:
    try:
        await budget.finish(conn, call_id, **kw)
    except Exception:
        log.exception("could not record AI call %s (it stays pending at its estimated cost)", call_id)


def _text_of(resp) -> str | None:
    """Text of the attempt that produced the message: with a server-side fallback, blocks before the
    last `fallback` block belong to the declined attempt."""
    texts: list[str] = []
    for b in resp.content or []:
        kind = getattr(b, "type", None)
        if kind == "fallback":
            texts = []
        elif kind == "text":
            texts.append(b.text or "")
    return "".join(texts) if texts else None


def _sent(e: Exception) -> bool:
    """False when the connection failed before the request was sent (nothing can have been billed)."""
    try:
        import httpx2
        connect_errors: tuple = (httpx2.ConnectError, httpx2.ConnectTimeout)
    except Exception:  # pragma: no cover
        connect_errors = ()
    cause = e.__cause__ or e.__context__
    return not (connect_errors and isinstance(cause, connect_errors))


def _retry_after(e: Exception, attempt: int) -> float:
    wait = 2.0 * (3 ** attempt)
    try:
        hdr = e.response.headers.get("retry-after")  # type: ignore[attr-defined]
        if hdr:
            wait = float(hdr)
    except Exception:
        pass
    return max(0.0, min(RETRY_WAIT_MAX_S, wait))


async def call(conn, *, purpose: str, system: str, content: list[dict], schema: dict, max_tokens: int,
               validate: Callable[[Any], Any], model: str | None = None, domain_id: int | None = None,
               page_id: int | None = None, image_tokens: int = 0,
               record: Callable[[Any], Any] | None = None) -> Outcome:
    cfg = budget.config()
    reason = budget.unavailable_reason(cfg)
    if reason:
        budget.log_once(f"unavailable:{reason}", "AI features off: %s", reason, level=logging.INFO)
        return Outcome("unavailable", error=reason)

    model = model or cfg.model
    use_fallbacks = cfg.fallbacks == "default" and supports_fallbacks(model)
    est_in = estimate_input_tokens(system, content, image_tokens)
    estimate = pricing.max_call_cost(model, est_in, max_tokens, FALLBACK_TARGETS if use_fallbacks else ())
    if not pricing.is_known(model):
        budget.log_once(f"price:{model}", "no price for model %s; using the most expensive rate for the cap", model)

    try:
        call_id, why = await budget.reserve(conn, purpose=purpose, model=model, estimate=estimate,
                                            domain_id=domain_id, page_id=page_id, cfg=cfg)
    except Exception as e:  # no reservation, no call: the cap can't be checked
        log.exception("AI budget check failed; skipping the %s call", purpose)
        return Outcome("error", error=f"budget check failed: {type(e).__name__}")
    if call_id is None:
        budget.log_once(f"budget:{budget.utc_day()}:{purpose}:{(why or '').split(' (')[0]}",
                        "AI call (%s) skipped: %s", purpose, why)
        return Outcome("over_budget", error=why)

    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": content}],
        "output_config": {"effort": cfg.effort, "format": {"type": "json_schema", "schema": schema}},
    }
    if use_fallbacks:
        kwargs["betas"] = [FALLBACK_BETA]
        kwargs["fallbacks"] = "default"

    started = time.monotonic()

    def elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    resp = None
    for attempt in range(MAX_ATTEMPTS):
        last = attempt == MAX_ATTEMPTS - 1
        try:
            resp = await get_client(cfg).beta.messages.create(**kwargs)
            break
        except anthropic.APIStatusError as e:
            code = int(getattr(e, "status_code", 0) or 0)
            retry = code in RETRY_STATUS
            err = f"HTTP {code}: {_short(e)}"
            if retry and not last:
                log.info("AI call %s (%s): %s; retrying", call_id, purpose, err)
                await _sleep(_retry_after(e, attempt))
                continue
            log.warning("AI call %s (%s) failed: %s", call_id, purpose, err)
            await _finish(conn, call_id, status="api_error", model=model, cost_usd=0.0, error=err,
                          duration_ms=elapsed())
            return Outcome("api_error", call_id=call_id, error=err, retryable=retry, http_status=code)
        except anthropic.APIConnectionError as e:   # includes APITimeoutError
            timeout = isinstance(e, anthropic.APITimeoutError)
            sent = _sent(e)
            err = ("timeout" if timeout else f"connection error: {_short(e)}") + ("" if sent else " (before sending)")
            if not sent and not last:
                await _sleep(_retry_after(e, attempt))
                continue
            # once the request was sent it may have been processed and billed: keep the estimate as its cost
            cost = estimate if sent else 0.0
            log.warning("AI call %s (%s) failed: %s", call_id, purpose, err)
            await _finish(conn, call_id, status="api_error", model=model, cost_usd=cost, error=err,
                          duration_ms=elapsed())
            return Outcome("api_error", call_id=call_id, error=err, retryable=True, cost_usd=cost)
        except Exception as e:
            log.exception("AI call %s (%s) failed unexpectedly", call_id, purpose)
            err = f"{type(e).__name__}: {_short(e)}"
            await _finish(conn, call_id, status="error", model=model, cost_usd=estimate, error=err,
                          duration_ms=elapsed())
            return Outcome("error", call_id=call_id, error=err, cost_usd=estimate)

    duration_ms = int((time.monotonic() - started) * 1000)
    served = getattr(resp, "model", None) or model
    try:
        cost, tokens, fallback_model = pricing.usage_cost(model, served, getattr(resp, "usage", None))
    except Exception:
        log.exception("could not price AI call %s; recording the estimate", call_id)
        cost, tokens, fallback_model = estimate, {}, None
    for m in (served, fallback_model):
        if m and not pricing.is_known(m):
            budget.log_once(f"price:{m}", "no price for model %s; costed at the most expensive rate", m)
    done = {"model": served, "cost_usd": cost, "tokens": tokens, "duration_ms": duration_ms,
            "fallback_model": fallback_model, "stop_reason": getattr(resp, "stop_reason", None)}

    stop = getattr(resp, "stop_reason", None)
    if stop == "refusal":
        details = getattr(resp, "stop_details", None)
        category = getattr(details, "category", None) if details is not None else None
        err = f"model declined the request (refusal, category {category or 'none'})"
        log.warning("AI call %s (%s): %s", call_id, purpose, err)
        await _finish(conn, call_id, status="refusal", error=err, result={"refusal_category": category}, **done)
        return Outcome("refusal", call_id=call_id, error=err, category=category, cost_usd=cost)

    text = _text_of(resp)
    if stop == "max_tokens":
        err = "output cut off at max_tokens"
    elif text is None:
        err = f"no text in response (stop_reason {stop})"
    else:
        err = None
    data = None
    if err is None:
        try:
            data = validate(json.loads(text))
        except (ValueError, TypeError, KeyError) as e:
            err = f"output did not match the schema: {_short(e)}"
    if err is not None:
        log.warning("AI call %s (%s): %s", call_id, purpose, err)
        await _finish(conn, call_id, status="invalid", error=err, **done)
        return Outcome("invalid", call_id=call_id, error=err, cost_usd=cost)

    stored = record(data) if record else data
    await _finish(conn, call_id, status="ok", result=stored, **done)
    return Outcome("ok", data=data, call_id=call_id, cost_usd=cost)
