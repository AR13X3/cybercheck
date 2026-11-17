"""Turn one fetch result (from the sandboxed fetcher) into page features and a page_score.

Pure functions, no I/O and no network: the only input is the JSON the fetcher returned, plus the
domain row and the brand watchlist. Everything here treats the fetch result as hostile input taken
from a phishing page: strings are length-capped, URLs are parsed defensively, and nothing is executed.

What it computes for one snapshot:
  - credential fields the page asks for: a password, a one-time code (OTP), card details
    (number / CVV / expiry), and Australian identity details (Medicare, TFN, licence, passport)
  - whether a form posts to a different registrable domain (external_form_post) and the domains it posts to
  - watchlist brands mentioned in the title, visible text and form labels (brand_mentions)
  - whether the page looks parked / blank / a decoy (CAPTCHA gate, redirect to the real brand): these
    are inconclusive, never evidence that the domain is benign
  - page_score 0-100 with reasons, and an `inconclusive` flag the caller uses to avoid treating an
    empty or decoy snapshot as a real "nothing phishing here" result.

page_score is "how credential-phishing-like the page content is". cybercheck.confidence folds the
credential booleans, brand_mentions and page_score into the combined final_score, so the booleans are
the load-bearing signal; page_score only nudges it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from publicsuffixlist import PublicSuffixList

_psl = PublicSuffixList()

TEXT_CAP = 20000
TITLE_CAP = 300
MAX_FORMS = 50
MAX_INPUTS = 200
MAX_ACTIONS = 10

_WORD = re.compile(r"[a-z0-9]+")
_NONALNUM = re.compile(r"[^a-z0-9]+")

# ---- credential-field keyword sets (matched against input name / id / autocomplete / nearby label) ----
# Each set has WORDS (matched as whole tokens of the name/label, after splitting on punctuation and
# camelCase) and LONG (matched as substrings of the squashed name/label; only words long enough that a
# substring hit is not an accident). Short words such as "pan", "dob", "otp", "tfn" are token-only, so
# "company", "adobe" or "footprint" never count. "token" is deliberately absent: every Laravel/Rails
# form carries a hidden CSRF "_token" / "authenticity_token".
_PW_AUTOCOMPLETE = {"current-password", "new-password"}
_PW_WORDS = {"password", "passwd", "pwd", "pass", "pword", "passw"}
_PW_LONG = ("password", "passwd")
# One-time code / OTP / 2FA. 'security code' is deliberately NOT here (it is a card CVV).
_OTP_AUTOCOMPLETE = {"one-time-code"}
_OTP_WORDS = {"otp", "2fa", "mfa", "smscode", "passcode", "onetime", "pin", "otc"}
_OTP_LONG = ("onetimecode", "onetimepassword", "onetimepin", "onetimepasscode", "smscode", "smsotp",
             "verificationcode", "verifycode", "authcode", "authenticationcode", "mfacode", "twofactor",
             "securitytoken", "otpcode", "netcode", "passcode")
# Card details.
_CARD_AUTOCOMPLETE = {"cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-name"}
_CARD_WORDS = {"pan", "cvv", "cvc", "cvv2", "cvc2", "csc", "ccv", "expiry", "exp", "ccnum", "ccno",
               "cardno", "cardnum"}
_CARD_LONG = ("cardnumber", "ccnumber", "creditcard", "debitcard", "cardverification", "securitycode",
              "cardsecuritycode", "expirydate", "expiration", "expdate", "cardexpiry", "nameoncard",
              "cardholder", "cardnum")
# Card-number words that identity documents use too (Medicare card number, licence card number).
_CARD_GENERIC_WORDS = {"cardno", "cardnum"}
_CARD_GENERIC_LONG = ("cardnumber", "cardnum")
# Australian identity details phishing kits harvest.
_ID_WORDS = {"medicare", "tfn", "licence", "license", "passport", "crn", "dob", "birthdate",
             "birthday", "irn"}
_ID_LONG = ("medicare", "taxfilenumber", "taxfileno", "licencenumber", "licensenumber", "driverslicence",
            "driverlicence", "driverlicense", "driverslicense", "drivinglicence", "passportnumber",
            "customerreferencenumber", "dateofbirth", "birthdate", "centrelink")
# Same, as phrases in the visible page text. Counted only when the page also has a text-entry field
# (an article that merely mentions Medicare is not asking for a Medicare number).
_ID_TEXT = ("medicare number", "medicare card", "tax file number", "driver's licence", "drivers licence",
            "driver licence", "licence number", "passport number", "centrelink crn",
            "customer reference number", "date of birth")
# Input types that never "ask the user" for a credential.
_SKIP_TYPES = {"hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file", "range",
               "color", "fieldset", "output", "object"}

_CAMEL = re.compile(r"([a-z])([A-Z])")

# ---- parked / decoy detection -----------------------------------------------------------------------
_PARKED_TEXT = ("domain is for sale", "this domain is for sale", "buy this domain", "domain for sale",
                "parked free", "parked domain", "domain parking", "is parked", "related searches",
                "this domain may be for sale", "purchase this domain", "domain is parked",
                "sedoparking", "parkingcrew", "godaddy", "hugedomains", "dan.com", "afternic",
                "renew this domain", "the domain has expired", "domain has expired", "courtesy page",
                "default web page", "it works!", "apache2 default", "nginx default",
                "welcome to nginx", "test page for", "index of /", "coming soon")
_CAPTCHA_TEXT = ("verify you are human", "verifying you are human", "checking your browser",
                 "i'm not a robot", "im not a robot", "recaptcha", "hcaptcha", "cloudflare",
                 "please complete the security check", "enable javascript and cookies to continue",
                 "ddos protection by", "just a moment", "attention required")


def _norm(s) -> str:
    return _NONALNUM.sub("", str(s or "").lower())


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def registrable(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    try:
        return _psl.privatesuffix(host) or None
    except Exception:
        return None


def page_loaded(result: dict | None) -> bool:
    """A navigation that actually returned a page (so the domain is live), parked/decoy included."""
    if not result or not result.get("ok") or result.get("error"):
        return False
    status = result.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    if status is not None and not (200 <= status < 400):
        return False
    return bool(result.get("title") or result.get("text_excerpt") or result.get("html")
                or result.get("forms") or status is not None)


def _name_tokens(s) -> set[str]:
    """Tokens of an input name / label: split camelCase and punctuation ("cardNumber" -> card, number)."""
    s = _CAMEL.sub(r"\1 \2", str(s or "")[:200])
    return set(_WORD.findall(s.lower()))


def _input_class(inp: dict) -> set[str]:
    """Which credential kinds one form input asks for. Hidden / button / checkbox inputs ask for nothing."""
    kinds: set[str] = set()
    itype = str(inp.get("type") or "").strip().lower()
    if itype in _SKIP_TYPES:
        return kinds
    auto = str(inp.get("autocomplete") or "").strip().lower()
    auto_tokens = set(auto.split())
    raw_name, raw_label = inp.get("name"), inp.get("label")
    toks = _name_tokens(raw_name) | _name_tokens(raw_label)
    squashed = _norm(raw_name) + " " + _norm(raw_label)

    def hit(words, long_words) -> bool:
        return bool(toks & words) or any(w in squashed for w in long_words)

    if itype == "password" or auto_tokens & _PW_AUTOCOMPLETE or hit(_PW_WORDS, _PW_LONG):
        kinds.add("password")
    if auto_tokens & _OTP_AUTOCOMPLETE or hit(_OTP_WORDS, _OTP_LONG):
        kinds.add("otp")
    identity = bool(auto_tokens & {"bday", "bday-day", "bday-month", "bday-year"} or hit(_ID_WORDS, _ID_LONG))
    if identity:
        kinds.add("identity")
    # "card number" alone is ambiguous: Medicare cards and driver licences have card numbers too. On an input
    # that already reads as an identity document, only unambiguous payment-card signals count.
    generic_card = (any(w in squashed for w in _CARD_GENERIC_LONG) or bool(toks & _CARD_GENERIC_WORDS)
                    or bool({"card", "credit", "debit"} & toks and {"number", "no", "num"} & toks))
    strong_card = (bool(auto_tokens & _CARD_AUTOCOMPLETE) or bool(toks & (_CARD_WORDS - _CARD_GENERIC_WORDS))
                   or any(w in squashed for w in _CARD_LONG if w not in _CARD_GENERIC_LONG)
                   or bool({"credit", "debit"} & toks))
    if strong_card or (generic_card and not identity):
        kinds.add("card")
    return kinds


def _is_text_entry(inp: dict) -> bool:
    return str(inp.get("type") or "").strip().lower() not in _SKIP_TYPES


@dataclass
class PageFeatures:
    has_password_field: bool = False
    has_otp_field: bool = False
    has_card_field: bool = False
    has_identity_field: bool = False
    external_form_post: bool = False
    form_actions: list[str] = field(default_factory=list)   # distinct registrable domains forms post to
    brand_mentions: list[str] = field(default_factory=list)  # watchlist brand ids mentioned on the page
    parked: bool = False
    captcha: bool = False
    blank: bool = False
    decoy: bool = False
    inconclusive: bool = False
    page_score: int = 0
    reasons: list[dict] = field(default_factory=list)
    # credential fields seen on the real brand's own site after a redirect: context, never evidence
    offsite_credentials: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "has_password_field": self.has_password_field, "has_otp_field": self.has_otp_field,
            "has_card_field": self.has_card_field, "has_identity_field": self.has_identity_field,
            "external_form_post": self.external_form_post, "form_actions": self.form_actions,
            "brand_mentions": self.brand_mentions, "parked": self.parked, "captcha": self.captcha,
            "blank": self.blank, "decoy": self.decoy, "inconclusive": self.inconclusive,
            "page_score": self.page_score, "reasons": self.reasons,
            "offsite_credentials": self.offsite_credentials,
        }


def _brand_mentions(text_blob: str, tokens: set[str], joined: str, watchlist) -> list[str]:
    if watchlist is None:
        return []
    out: list[str] = []
    try:
        brands = watchlist.brands
    except AttributeError:
        return []
    for bid, brand in brands.items():
        hit = False
        name_norm = _norm(getattr(brand, "name", ""))
        if len(name_norm) >= 5 and name_norm in joined:
            hit = True
        if not hit:
            for kw in getattr(brand, "keywords", []) or []:
                if len(kw) >= 4 and kw in tokens:
                    hit = True
                    break
                if len(kw) >= 6 and kw in joined:
                    hit = True
                    break
        if hit:
            out.append(bid)
        if len(out) >= 12:
            break
    return out


def _form_targets(forms: list, final_url: str | None, registered: str | None) -> tuple[list[str], bool]:
    targets: list[str] = []
    external = False
    base = final_url if isinstance(final_url, str) else ""     # urljoin raises TypeError on a non-str
    for form in forms[:MAX_FORMS]:
        if not isinstance(form, dict):
            continue
        action = form.get("action")
        if not isinstance(action, str) or not action.strip():
            continue
        try:
            resolved = urljoin(base, action.strip())
            parts = urlsplit(resolved)
        except ValueError:
            continue
        if parts.scheme not in ("", "http", "https"):
            continue
        host = (parts.hostname or "").lower()
        reg = registrable(host)
        if reg and reg not in targets:
            targets.append(reg)
        if reg and registered and reg != registered.lower():
            external = True
    return targets[:MAX_ACTIONS], external


def extract(result: dict, domain: dict | None = None, watchlist=None) -> PageFeatures:
    """Compute PageFeatures for a single loaded snapshot. Call page_loaded() first; a result that did
    not load returns an inconclusive, all-false PageFeatures."""
    f = PageFeatures()
    domain = domain or {}
    registered = (domain.get("registered_domain") or "").lower() or None
    brand_id = domain.get("brand_id") or None

    if not page_loaded(result):
        f.inconclusive = True
        f.reasons.append({"points": 0, "why": "page did not load (no content to judge)"})
        return f

    title = str(result.get("title") or "")[:TITLE_CAP]
    text = str(result.get("text_excerpt") or "")[:TEXT_CAP]
    forms = result.get("forms") if isinstance(result.get("forms"), list) else []

    # ---- credential fields, from form inputs and the fetcher's own per-form flags ----
    label_blob = []
    n_inputs = 0
    n_text_inputs = 0
    has_any_form = bool(forms)
    for form in forms[:MAX_FORMS]:
        if not isinstance(form, dict):
            continue
        inputs = [i for i in (form.get("inputs") or [])[:MAX_INPUTS] if isinstance(i, dict)] \
            if isinstance(form.get("inputs"), list) else []
        if not inputs:
            # No input list to judge: fall back to the fetcher's own per-form flags.
            if form.get("has_password"):
                f.has_password_field = True
            if form.get("has_otp"):
                f.has_otp_field = True
            if form.get("has_card"):
                f.has_card_field = True
        for inp in inputs:
            if n_inputs >= MAX_INPUTS:
                break
            n_inputs += 1
            if _is_text_entry(inp):
                n_text_inputs += 1
            if inp.get("label"):
                label_blob.append(str(inp.get("label"))[:120])
            kinds = _input_class(inp)
            if "password" in kinds:
                f.has_password_field = True
            if "otp" in kinds:
                f.has_otp_field = True
            if "card" in kinds:
                f.has_card_field = True
            if "identity" in kinds:
                f.has_identity_field = True

    blob_for_terms = " ".join([title, text, " ".join(label_blob)])
    low = blob_for_terms.lower()
    tokens = _tokens(blob_for_terms)
    joined = _norm(blob_for_terms)
    if not f.has_identity_field and n_text_inputs and any(t in low for t in _ID_TEXT):
        f.has_identity_field = True

    # ---- forms: where they post ----
    f.form_actions, f.external_form_post = _form_targets(forms, result.get("final_url") or result.get("url"),
                                                         registered)

    # ---- brand mentions ----
    f.brand_mentions = _brand_mentions(blob_for_terms, tokens, joined, watchlist)

    # ---- parked / decoy / blank ----
    text_len = len(text.strip())
    f.captcha = any(s in low for s in _CAPTCHA_TEXT)
    f.parked = any(s in low for s in _PARKED_TEXT)
    f.blank = not has_any_form and not f.brand_mentions and text_len < 40
    # redirect to the real brand's own site is a decoy (cloaking), not a benign result
    final_reg = registrable(urlsplit(str(result.get("final_url") or "")).hostname)
    redirected_off = bool(final_reg and registered and final_reg != registered and _is_official(final_reg, watchlist))
    f.decoy = f.captcha or redirected_off
    if redirected_off:
        # The browser ended on the impersonated brand's real site (cloaking): its genuine login form says
        # nothing about this domain, so it must not count as credential fields here (pages columns, page
        # score, report evidence). Keep what was seen as context only.
        f.offsite_credentials = [w for w, on in (("password", f.has_password_field), ("otp", f.has_otp_field),
                                                 ("card", f.has_card_field), ("identity", f.has_identity_field)) if on]
        f.has_password_field = f.has_otp_field = f.has_card_field = f.has_identity_field = False
        f.external_form_post = False

    credentials = f.has_password_field or f.has_otp_field or f.has_card_field or f.has_identity_field
    f.inconclusive = (f.parked or f.blank or f.decoy) and not credentials

    # ---- page_score 0-100 with reasons ----
    def add(points: int, why: str) -> None:
        f.reasons.append({"points": int(points), "why": why})

    score = 0
    cred_pts = 0
    if f.has_password_field:
        cred_pts += 30
    if f.has_otp_field:
        cred_pts += 20
    if f.has_card_field:
        cred_pts += 30
    if f.has_identity_field:
        cred_pts += 20
    cred_pts = min(60, cred_pts)
    if cred_pts:
        what = [w for w, on in (("a password", f.has_password_field), ("a one-time code", f.has_otp_field),
                                ("card details", f.has_card_field), ("identity details", f.has_identity_field)) if on]
        add(cred_pts, "page asks for " + ", ".join(what))
        score += cred_pts

    if f.brand_mentions:
        if brand_id and brand_id in f.brand_mentions:
            add(15, f"page text mentions the brand the name imitates ({brand_id})")
            score += 15
        else:
            add(8, "page text mentions watchlist brands: " + ", ".join(f.brand_mentions[:5]))
            score += 8

    if f.external_form_post:
        add(10, "a form posts to another registrable domain: " + ", ".join(f.form_actions[:3]))
        score += 10
    if f.has_password_field or f.has_otp_field or f.has_card_field:
        add(10, "the page carries a login / payment form")
        score += 10

    if f.inconclusive:
        why = ("CAPTCHA / bot gate" if f.captcha else "redirect to the real brand site" if f.decoy
               else "parked or for-sale page" if f.parked else "blank or near-empty page")
        add(0, f"inconclusive: {why} (no credential form seen; not treated as benign)")

    f.page_score = max(0, min(100, score))
    if not f.reasons:
        add(0, "page loaded but shows no phishing signals")
    return f


def _is_official(reg: str, watchlist) -> bool:
    if watchlist is None or not reg:
        return False
    try:
        return watchlist.is_official(reg) or reg in getattr(watchlist, "official", {})
    except Exception:
        return False


def combine(features: list[PageFeatures]) -> int:
    """Domain page_score for a fetch round: the highest score among the round's loaded snapshots.
    Kits often show the form to only one profile, so the credential snapshot wins."""
    scores = [f.page_score for f in features if not f.inconclusive]
    if not scores:
        scores = [f.page_score for f in features] or [0]
    return max(scores)


__all__ = ["PageFeatures", "extract", "combine", "page_loaded", "registrable"]
