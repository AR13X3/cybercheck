"""Model prices and cost calculation from API usage (USD per million tokens).

Prices are from the Claude API skill docs (cached 2026-11). Cache writes cost 1.25x the input price
for the default 5-minute TTL and 2x for the 1-hour TTL. Unknown models are priced at the most
expensive rate below so the spending cap errs on the safe side.
"""
from __future__ import annotations

from dataclasses import dataclass

CACHE_WRITE_5M = 1.25
CACHE_WRITE_1H = 2.0


@dataclass(frozen=True)
class Price:
    input: float
    output: float
    cache_read: float
    long_prompt_tokens: int | None = None   # above this prompt size a higher rate card applies
    long_multiplier: float = 1.0


PRICES: dict[str, Price] = {
    "claude-opus-5-5": Price(4.00, 20.00, 0.20),
    "claude-opus-5": Price(5.00, 25.00, 0.50),
    "claude-opus-4-8": Price(5.00, 25.00, 0.50),     # possible server-side refusal fallback target
    "claude-sonnet-5-5": Price(2.00, 10.00, 0.10),
    "claude-sonnet-5": Price(2.00, 10.00, 0.20),
    "claude-haiku-5-5": Price(0.10, 0.50, 0.01, long_prompt_tokens=100_000, long_multiplier=5.0),
    "claude-fable-5-2": Price(8.00, 40.00, 0.20),
}
UNKNOWN = Price(10.00, 50.00, 1.00)


def price_for(model: str | None) -> Price:
    """Longest-prefix match so dated or suffixed ids resolve to their family."""
    m = (model or "").strip().lower()
    best = None
    for key in PRICES:
        if m == key or m.startswith(key + "-") or m.startswith(key + "@"):
            if best is None or len(key) > len(best):
                best = key
    return PRICES[best] if best else UNKNOWN


def is_known(model: str | None) -> bool:
    return price_for(model) is not UNKNOWN


def tokens_cost(model: str | None, input_tokens: int = 0, output_tokens: int = 0, cache_read: int = 0,
                cache_write_5m: int = 0, cache_write_1h: int = 0) -> float:
    p = price_for(model)
    mult = 1.0
    prompt = input_tokens + cache_read + cache_write_5m + cache_write_1h
    if p.long_prompt_tokens and prompt > p.long_prompt_tokens:
        mult = p.long_multiplier
    cost = (input_tokens * p.input
            + output_tokens * p.output
            + cache_read * p.cache_read
            + cache_write_5m * p.input * CACHE_WRITE_5M
            + cache_write_1h * p.input * CACHE_WRITE_1H) * mult
    return cost / 1_000_000


def _n(obj, name: str) -> int:
    v = getattr(obj, name, None)
    if v is None and isinstance(obj, dict):
        v = obj.get(name)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _entry_cost(model: str | None, u) -> tuple[float, dict]:
    write = _n(u, "cache_creation_input_tokens")
    cc = getattr(u, "cache_creation", None) if not isinstance(u, dict) else u.get("cache_creation")
    w1h = _n(cc, "ephemeral_1h_input_tokens") if cc else 0
    w5m = max(0, write - w1h)
    t = {"input_tokens": _n(u, "input_tokens"), "output_tokens": _n(u, "output_tokens"),
         "cache_read_tokens": _n(u, "cache_read_input_tokens"), "cache_write_tokens": write}
    return tokens_cost(model, t["input_tokens"], t["output_tokens"], t["cache_read_tokens"], w5m, w1h), t


def usage_cost(requested_model: str, served_model: str | None, usage) -> tuple[float, dict, str | None]:
    """Cost of one Messages API response.

    With server-side refusal fallbacks, `usage.iterations` is the per-attempt record (each attempt
    billed at its own model's rate) and the top-level usage covers only the attempt that produced
    the message, so iterations are summed when present. Returns (cost_usd, token totals,
    fallback model that served the response or None).
    """
    totals = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0}
    if usage is None:
        return 0.0, totals, None
    iters = getattr(usage, "iterations", None) or []
    entries = [it for it in iters if getattr(it, "type", None) in ("message", "fallback_message")]
    fallback_model = None
    cost = 0.0
    if entries:
        for it in entries:
            model = getattr(it, "model", None) or (requested_model if it.type == "message" else served_model)
            if it.type == "fallback_message":
                fallback_model = model
            c, t = _entry_cost(model, it)
            cost += c
            for k in totals:
                totals[k] += t[k]
    else:
        cost, totals = _entry_cost(served_model or requested_model, usage)
    return round(cost, 6), totals, fallback_model


def max_call_cost(model: str, input_tokens: int, max_tokens: int, fallback_models: tuple[str, ...] = ()) -> float:
    """Upper bound for one call: every input token written to cache at the 5-minute rate plus the
    full max_tokens of output, on the priciest model in the chain. With fallbacks, the declined
    attempt on the primary model is added on top: a decline mid-output is billed at normal rates,
    so that attempt can cost its input plus up to max_tokens of output too."""
    chain = (model, *fallback_models)
    worst = max(tokens_cost(m, cache_write_5m=input_tokens, output_tokens=max_tokens) for m in chain)
    if fallback_models:
        worst += tokens_cost(model, cache_write_5m=input_tokens, output_tokens=max_tokens)
    return round(worst, 6)
