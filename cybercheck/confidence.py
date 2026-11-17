"""Combined confidence (final_score) from domain score, page evidence and the AI verdict.

The domain-name score is the starting point; page evidence and the AI verdict move it up or down.
Rules that always hold:
- Page evidence counts only from a snapshot whose final URL (where CyberCheck's browser ended up) is on
  the domain's own registered domain. Credential fields on a page reached by a redirect to another
  domain are shown as context but are not evidence against the redirecting domain; a redirect to a
  watchlist brand's official site is a weak benign signal (W_REDIRECT_OFFICIAL).
- Without credential-collecting evidence on the domain's own page (a password, one-time-code or card
  field) AND an AI 'phishing' verdict with confidence >= 0.7, the result is at most NO_EVIDENCE_CAP (89),
  a fixed value that no setting changes. The blocklist and auto-report floors (>= 90) rely on it.
- Below that, the cap also follows AUTO_REPORT_MIN_FINAL_SCORE: missing evidence keeps the score at or
  below threshold - 1, with the threshold clamped to 80..90 (a value above 90, including the "> 100
  switches automatic sends off" setting, never lifts the cap; cybercheck.reporting.conf never sends
  automatically below 90 anyway). So the AI verdict alone can never push a domain over the auto-report
  threshold.
- An AI 'benign' (or 'parked') verdict alone can't take a page on a brand-matching domain that collects
  credentials or identity details (Medicare, TFN, licence, passport, date of birth) below 70 (or below
  the score it had before the AI verdict, if that was lower).
- With credential evidence, reaching the auto-report threshold also needs an AI 'phishing' verdict
  with confidence >= 0.7 (CONFIDENCE_REQUIRE_AI, default true), so two independent signals agree
  before anything is reported automatically. Without AI the score stays just under the threshold and
  a human decides. CONFIDENCE_REQUIRE_AI=false only matters for a threshold below 90: the fixed cap
  still applies.
- Output is an int 0-100; reasons are [{'points': int, 'why': str}] and their points add up to it.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from urllib.parse import urlsplit

NO_EVIDENCE_CAP = 89         # fixed: never raised by any setting (blocklist / auto-report floors are >= 90)
MIN_AUTO_THRESHOLD = 80      # lowest threshold the cap follows (so the cap is never below 79)
SCORE_VERSION = 2            # bump when the rules change, so the judge job recomputes stored scores
BENIGN_FLOOR = 70
AI_CONFIRM_CONFIDENCE = 0.7

W_PASSWORD = 15
W_OTP = 10
W_CARD = 15
CAP_CREDENTIALS = 25
W_BRAND_MENTION = 8          # page text mentions the brand the domain name matched
W_OTHER_BRAND_MENTION = 5    # page mentions some other watchlist brand
W_EXTERNAL_POST = 5
PAGE_SCORE_RANGE = 10        # page_score 0..100 maps to -10..+10
W_EMPTY_PAGE = -10           # live page with no forms and no brand mentions
W_REDIRECT_OFFICIAL = -5     # the browser was sent to a brand's official site: weak benign signal only
AI_WEIGHTS = {"phishing": 15, "suspicious": 5, "benign": -30, "parked": -25}
W_AI_SAME_BRAND = 5

_NORM = re.compile(r"[^a-z0-9]")
_HOST_SHOWN = re.compile(r"[^a-z0-9.\-_]")
_ASKS = (("has_password_field", "a password"), ("has_otp_field", "a one-time code"),
         ("has_card_field", "card details"), ("has_identity_field", "identity details"))


def _threshold() -> int:
    try:
        return int((os.environ.get("AUTO_REPORT_MIN_FINAL_SCORE") or "").strip() or 90)
    except ValueError:
        return 90


def evidence_cap() -> int:
    """Cap for scores without full evidence: just under the auto-report threshold, clamped so it is never
    above NO_EVIDENCE_CAP (whatever AUTO_REPORT_MIN_FINAL_SCORE says) nor below MIN_AUTO_THRESHOLD - 1."""
    return max(MIN_AUTO_THRESHOLD, min(_threshold(), NO_EVIDENCE_CAP + 1)) - 1


def _require_ai() -> bool:
    v = (os.environ.get("CONFIDENCE_REQUIRE_AI") or "").strip().lower()
    return True if not v else v in ("1", "true", "yes", "on")


def basis_tag() -> str:
    """Rule version and the settings that change results; part of the judge job's recompute basis, so
    stored scores are recomputed after an upgrade or a settings change."""
    return f"v{SCORE_VERSION}:{evidence_cap()}:{int(_require_ai())}"


# ---- where the snapshot was served from ---------------------------------------------------------

def url_host(url) -> str | None:
    """Lower-case host of an http(s) URL, or None (not a string, unparseable, other scheme). A blob: URL
    (a page the site generated in the browser) counts as its origin: blob:https://host/<id> -> host."""
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()
    if url[:5].lower() == "blob:":
        url = url[5:]
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    host = host.rstrip(".").lower()
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return host or None


def host_under(host: str | None, registered: str | None) -> bool:
    if not isinstance(host, str) or not isinstance(registered, str):
        return False
    host = host.strip().lower().rstrip(".")
    registered = registered.strip().lower().rstrip(".")
    return bool(host and registered) and (host == registered or host.endswith("." + registered))


def final_host(page: dict | None) -> str | None:
    """Host of the snapshot's final URL: where CyberCheck's own browser ended up after redirects."""
    return url_host((page or {}).get("final_url"))


def snapshot_on_domain(page: dict | None, registered_domain: str | None) -> bool:
    """True only when the snapshot's final URL is on the registered domain itself (or a subdomain).
    A missing or unparseable final URL is not proof, so it counts as off the domain."""
    return host_under(final_host(page), registered_domain)


def official_brand(host: str | None) -> str | None:
    """Brand id when host is one of a watchlist brand's official domains (or under one). Entries that
    are only on the extra allowlist (link pages, proxies) don't count: anyone can publish there."""
    if not host:
        return None
    try:
        from .scoring import default_watchlist
        brands = default_watchlist().brands
    except Exception:
        return None
    official = {d.lower(): b.id for b in brands.values() for d in b.official_domains}
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        bid = official.get(".".join(labels[i:]))
        if bid:
            return bid
    return None


def _brand_name(brand_id: str) -> str:
    try:
        from .scoring import default_watchlist
        b = default_watchlist().brands.get(brand_id)
        return b.name if b else brand_id
    except Exception:
        return brand_id


def _shown(host: str) -> str:
    return _HOST_SHOWN.sub("", host.lower())[:120]


def _norm(s) -> str:
    return _NORM.sub("", str(s or "").lower())


@lru_cache(maxsize=256)
def _brand_terms(brand_id: str) -> frozenset[str]:
    terms = {_norm(brand_id)}
    try:
        from .scoring import default_watchlist
        b = default_watchlist().brands.get(brand_id)
        if b:
            terms.add(_norm(b.name))
            terms.update(_norm(k) for k in b.keywords if len(k) >= 4)
    except Exception:
        pass
    return frozenset(t for t in terms if t)


def _int(v, default=None):
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _ai_fields(ai: dict | None) -> tuple[str | None, float | None, str | None]:
    if not ai:
        return None, None, None
    verdict = ai.get("verdict", ai.get("ai_verdict"))
    conf = ai.get("confidence", ai.get("ai_confidence"))
    brand = ai.get("imitated_brand", ai.get("ai_brand"))
    try:
        conf = None if conf is None else min(1.0, max(0.0, float(conf)))
    except (TypeError, ValueError):
        conf = None
    if conf is not None and conf != conf:  # NaN
        conf = None
    return (verdict if isinstance(verdict, str) else None), conf, (brand if isinstance(brand, str) else None)


def _page_loaded(page: dict) -> bool:
    status = _int(page.get("http_status"))
    return not page.get("error") and (status is None or status == 0 or 200 <= status < 400)


def _offsite(add, page: dict, host: str | None) -> None:
    """Reason for a snapshot that ended up off the domain: its content is context, not evidence."""
    asked = [w for k, w in _ASKS if page.get(k)]
    context = ("; the page there asks for " + " and ".join(asked)) if asked else ""
    if not host:
        add(0, "latest page snapshot has no usable final address, so its content is not counted as evidence")
        return
    bid = official_brand(host)
    if bid:
        add(W_REDIRECT_OFFICIAL, f"the browser was redirected to {_shown(host)}, an official {_brand_name(bid)} "
                                 f"site{context}: not evidence against this domain")
    else:
        add(0, f"the browser was redirected to another domain ({_shown(host)}){context}: its content is not "
               "evidence about this domain")


def compute_final_score(domain: dict, page: dict | None, ai: dict | None) -> tuple[int, list[dict]]:
    """Returns (final_score 0-100, reasons [{'points': int, 'why': str}]).
    domain needs 'registered_domain' for page evidence to count; page needs 'final_url'."""
    domain = domain or {}
    cap = evidence_cap()
    reasons: list[dict] = []

    def add(points: float, why: str) -> None:
        reasons.append({"points": int(round(points)), "why": why})

    def total() -> int:
        return sum(r["points"] for r in reasons)

    add(min(100, max(0, _int(domain.get("score"), 0))), "domain name score")
    brand_id = domain.get("brand_id") or None
    credentials = False      # password / one-time code / card field on the domain's own page
    identity = False         # identity-document fields on the domain's own page (floor only, not evidence)
    page_ok = bool(page) and _page_loaded(page)

    if page_ok and not snapshot_on_domain(page, domain.get("registered_domain")):
        _offsite(add, page, final_host(page))
    elif page_ok:
        pw, otp, card = (bool(page.get(k)) for k in ("has_password_field", "has_otp_field", "has_card_field"))
        credentials = pw or otp or card
        identity = bool(page.get("has_identity_field"))
        if credentials:
            what = [w for w, on in (("a password", pw), ("a one-time code", otp), ("card details", card)) if on]
            add(min(CAP_CREDENTIALS, W_PASSWORD * pw + W_OTP * otp + W_CARD * card),
                "page asks for " + " and ".join(what))
        mentions = [m for m in (page.get("brand_mentions") or []) if m]
        if mentions:
            terms = _brand_terms(brand_id) if brand_id else frozenset()
            if terms and any(_norm(m) in terms for m in mentions):
                add(W_BRAND_MENTION, f"page mentions the brand the name imitates ({brand_id})")
            else:
                add(W_OTHER_BRAND_MENTION, "page mentions watchlist brands: " + ", ".join(str(m) for m in mentions[:5]))
        if page.get("external_form_post"):
            add(W_EXTERNAL_POST, "a form on the page posts to another domain")
        ps = _int(page.get("page_score"), _int(domain.get("page_score")))
        if ps is not None:
            adj = (min(100, max(0, ps)) - 50) * PAGE_SCORE_RANGE / 50
            if round(adj):
                add(adj, f"page features score {ps}/100")
        if not credentials and not identity and not mentions and not (page.get("form_actions") or []) \
                and not page.get("external_form_post"):
            add(W_EMPTY_PAGE, "page is live but has no forms and no brand mentions")
    elif page:
        status = page.get("http_status")
        add(0, "latest page snapshot did not load" + (f" (HTTP {status})" if status else "") + ": no page evidence")
    else:
        add(0, "no page snapshot yet")

    before_ai = total()
    verdict, conf, ai_brand = _ai_fields(ai)
    if verdict in AI_WEIGHTS:
        c = 0.5 if conf is None else conf
        add(AI_WEIGHTS[verdict] * c, f"AI page check: {verdict} ({c:.0%} confident)")
        if verdict in ("phishing", "suspicious") and brand_id and ai_brand and _norm(ai_brand) == _norm(brand_id):
            add(W_AI_SAME_BRAND, f"AI confirms the page imitates {brand_id}")
    elif verdict == "error":
        add(0, "AI could not judge the page")

    score = total()
    if score > 100:
        add(100 - score, "limited to 100")
    elif score < 0:
        add(-score, "limited to 0")

    # An AI benign/parked verdict alone can't clear a page on a brand-matching domain that collects
    # credentials or identity details
    if (credentials or identity) and brand_id and verdict in ("benign", "parked"):
        floor = min(BENIGN_FLOOR, max(0, before_ai), cap)
        what = "credentials" if credentials else "identity details"
        if total() < floor:
            add(floor - total(), f"kept at {floor}: the page collects {what} on a domain imitating "
                                 f"{brand_id}, so an AI '{verdict}' verdict alone can't clear it")

    confirmed = verdict == "phishing" and conf is not None and conf >= AI_CONFIRM_CONFIDENCE
    if not credentials:
        limit = cap
        why = f"capped at {cap}: no credential-collecting page evidence on the domain's own page (auto-report needs it)"
    elif not confirmed:
        limit = cap if _require_ai() else NO_EVIDENCE_CAP
        why = (f"capped at {limit}: auto-report level needs an AI 'phishing' verdict "
               f"(>= {AI_CONFIRM_CONFIDENCE:.0%}) confirming the page evidence")
    else:
        limit = 100
    if total() > limit:
        add(limit - total(), why)
    return total(), reasons
