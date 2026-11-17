"""Evidence for reports: page snapshots, URLs, the sandbox verification file and the facts dict.

Pure functions apart from reading files under the data directory. Nothing here contacts the
suspicious site: everything comes from what the sandboxed fetcher already stored.
Page-derived values (URLs, form actions) are attacker-controlled: they are cleaned, length-capped and
only URLs on the reported domain itself are used, so a kit that redirects to the real brand site can
never get the brand's own site reported. Reports name only URLs from the snapshots that are the evidence
(the fetch run of the chosen snapshot; when it asks for credentials, only the snapshots that do too), on
hostnames seen in certificates: a kit on a hacked site that cloaks by redirecting to the site's own home
page can never get the real business reported.
"""
from __future__ import annotations

import io
import ipaddress
import json
import logging
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit

from .common import UTC, aware, clean_line, fmt_date, fmt_ts, utcnow

log = logging.getLogger("cybercheck.reporting")

CRED_FIELDS = (("has_password_field", "a password"), ("has_otp_field", "a one-time code"),
               ("has_card_field", "card details"))
ROUND_WINDOW = timedelta(minutes=15)     # desktop + mobile snapshots of one fetch run
AI_CONFIRM_CONFIDENCE = 0.7              # same level cybercheck.confidence requires for auto-report scores
MAX_URLS = 10
MAX_URL_LEN = 500
_HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
_URL_SAFE = "".join(chr(i) for i in range(33, 127))   # printable ASCII is kept as is (incl. existing %XX)

# screenshot conversion (Netcraft takes gif/png/jpg; brand mailboxes get an attachment)
MAX_SOURCE_BYTES = 15_000_000
MAX_SOURCE_PIXELS = 25_000_000
MAX_HEIGHT = 2400
MAX_WIDTH = 1280
MAX_JPEG_BYTES = 2_000_000


# ---- pages ------------------------------------------------------------------------------------------

def page_ok(p: dict) -> bool:
    status = p.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    return not p.get("error") and (status is None or status == 0 or 200 <= status < 400)


def asks_for(p: dict | None) -> list[str]:
    if not p:
        return []
    return [label for key, label in CRED_FIELDS if p.get(key)]


def _ts(p: dict) -> datetime:
    return aware(p.get("fetched_at")) or datetime.min.replace(tzinfo=UTC)


def latest_round(pages: list[dict]) -> list[dict]:
    """Snapshots of the newest fetch run (pages fetched within ROUND_WINDOW of the newest one)."""
    if not pages:
        return []
    ordered = sorted(pages, key=_ts, reverse=True)
    newest = _ts(ordered[0])
    return [p for p in ordered if newest - _ts(p) <= ROUND_WINDOW]


def _prefer_screenshot(pages: list[dict]) -> dict | None:
    for p in pages:
        if p.get("screenshot_path"):
            return p
    return pages[0] if pages else None


def credential_page(pages: list[dict], registered_domain: str | None = None) -> dict | None:
    """Auto-report evidence: a snapshot from the newest fetch run that loaded and asks for credentials.
    With registered_domain, only snapshots whose final URL is on that domain count (a redirect to another
    site's form is not evidence against this one; same rule as confidence.snapshot_on_domain)."""
    creds = [p for p in latest_round(pages) if page_ok(p) and asks_for(p)]
    if registered_domain is not None:
        from ..confidence import snapshot_on_domain
        creds = [p for p in creds if snapshot_on_domain(p, registered_domain)]
    return _prefer_screenshot(creds)


def evidence_pages(pages: list[dict], page: dict | None) -> list[dict]:
    """The snapshots a report may take URLs from: the chosen page first, then the other snapshots of its fetch
    run that loaded and, when the chosen page asks for credentials, ask for them too. Older runs (a cloaked
    snapshot that redirected elsewhere, a page that has since changed) are never evidence."""
    if not page:
        return []
    latest = latest_round(pages)
    if any(p is page for p in latest):
        run = latest
    else:
        t = _ts(page)
        run = [p for p in pages if abs(_ts(p) - t) <= ROUND_WINDOW]
    creds = bool(asks_for(page))
    return [page] + [p for p in run if p is not page and page_ok(p) and (asks_for(p) or not creds)]


def best_page(pages: list[dict]) -> dict | None:
    """For a reviewer-confirmed domain: the newest credential-collecting snapshot, else the newest that loaded."""
    ordered = sorted(pages, key=_ts, reverse=True)
    for want_creds in (True, False):
        ok = [p for p in ordered if page_ok(p) and (bool(asks_for(p)) or not want_creds)]
        if ok:
            # same fetch run as the chosen page, preferring a snapshot with a screenshot
            first = _ts(ok[0])
            return _prefer_screenshot([p for p in ok if first - _ts(p) <= ROUND_WINDOW]) or ok[0]
    return None


# ---- URLs -------------------------------------------------------------------------------------------

def host_under(host: str, registered: str) -> bool:
    host, registered = host.lower().rstrip("."), registered.lower().rstrip(".")
    return bool(registered) and (host == registered or host.endswith("." + registered))


def clean_url(url, registered: str) -> str | None:
    """An http(s) URL on the reported domain itself, or None."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url or any(ord(c) < 33 or ord(c) == 127 for c in url):
        return None
    # Page-derived: percent-encode anything outside printable ASCII, so bidi overrides, zero-width and
    # lookalike characters in the path or query never reach a report as text.
    url = quote(url, safe=_URL_SAFE)
    if len(url) > MAX_URL_LEN:
        return None
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        _ = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or parts.username or parts.password or "@" in parts.netloc:
        return None
    if not _HOST_RE.match(host) or not host_under(host, registered):
        return None
    return url


def _seen_hosts(domain: dict, registered: str) -> list[str]:
    """Hostnames seen in certificates (they all scored as brand lookalikes), or the registered domain when
    none is on file."""
    hosts = [h.strip().lower().rstrip(".") for h in (domain.get("hostnames") or []) if isinstance(h, str)]
    hosts = [h for h in hosts if h and "*" not in h and host_under(h, registered)]
    return hosts or [registered]


def report_urls(domain: dict, pages: list[dict], limit: int = MAX_URLS) -> list[str]:
    """URLs to report: fetched URLs and their final URLs, newest first, when they are on (or under) a hostname
    seen for this domain; else its hostnames. On a hacked site or a shared platform the registered domain
    itself is someone else's (someplumber.com.au, weebly.com), so only the lookalike hostnames count."""
    registered = (domain.get("registered_domain") or "").lower()
    seen = _seen_hosts(domain, registered)
    out: list[str] = []
    for p in sorted(pages, key=_ts, reverse=True):
        for u in (p.get("final_url"), p.get("url")):
            c = clean_url(u, registered)
            if c and c not in out and any(host_under(urlsplit(c).hostname or "", h) for h in seen):
                out.append(c)
    if not out:
        for h in (domain.get("hostnames") or [])[:5]:
            if isinstance(h, str) and "*" not in h:
                c = clean_url(f"https://{h.strip().lower()}/", registered)
                if c and c not in out:
                    out.append(c)
    if not out and registered:
        c = clean_url(f"https://{registered}/", registered)
        if c:
            out.append(c)
    return out[:limit]


# ---- sandbox verification (written by scripts/verify-sandbox.sh) ------------------------------------

@dataclass(frozen=True)
class SandboxStatus:
    ok: bool
    reason: str
    verified_at: datetime | None = None
    egress_ip: str | None = None
    egress_country: str | None = None
    tests_passed: int | None = None
    age_days: float | None = None


def sandbox_status(path: Path, now: datetime | None = None, max_age_days: int = 30) -> SandboxStatus:
    """Automatic reporting requires data/sandbox_verified.json, written only when every isolation test
    of the fetcher passed, to exist and be at most max_age_days old."""
    now = now or utcnow()
    try:
        if not path.is_file():
            return SandboxStatus(False, "sandbox not verified: data/sandbox_verified.json is missing "
                                        "(run scripts/verify-sandbox.sh)")
        if path.stat().st_size > 65536:
            return SandboxStatus(False, "sandbox_verified.json is too large to be valid")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return SandboxStatus(False, "sandbox_verified.json could not be read")
    if not isinstance(data, dict):
        return SandboxStatus(False, "sandbox_verified.json is not a JSON object")
    raw = data.get("verified_at")
    try:
        ts = datetime.fromisoformat(raw.strip().replace("Z", "+00:00")) if isinstance(raw, str) else None
    except ValueError:
        ts = None
    if ts is None:
        return SandboxStatus(False, "sandbox_verified.json has no valid verified_at")
    ts = aware(ts)
    tests = data.get("tests_passed")
    ip = data.get("egress_ip")
    country = data.get("egress_country")
    try:
        ip = str(ipaddress.ip_address(ip)) if isinstance(ip, str) else None
    except ValueError:
        ip = None
    country = clean_line(country, 8).upper() if isinstance(country, str) else None
    tests = tests if isinstance(tests, int) and not isinstance(tests, bool) else None
    age = (now - ts).total_seconds() / 86400
    base = dict(verified_at=ts, egress_ip=ip, egress_country=country, tests_passed=tests, age_days=age)
    if tests is None or tests < 1:
        return SandboxStatus(False, "sandbox_verified.json: tests_passed is missing or 0", **base)
    if ip is None:
        return SandboxStatus(False, "sandbox_verified.json: egress_ip is missing or invalid", **base)
    if age < -1 / 24:
        return SandboxStatus(False, "sandbox_verified.json: verified_at is in the future", **base)
    if age > max_age_days:
        return SandboxStatus(False, f"sandbox verification is {age:.0f} days old (max {max_age_days}); "
                                    "run scripts/verify-sandbox.sh again", **base)
    return SandboxStatus(True, f"verified {age:.1f} days ago ({tests} isolation tests passed)", **base)


# ---- eligibility --------------------------------------------------------------------------------------

def is_official(domain: dict) -> bool:
    """The domain (or a parent) is an official domain of a watchlist brand. Unreadable watchlist: True."""
    name = (domain.get("registered_domain") or "").lower()
    try:
        from ..scoring import default_watchlist
        return default_watchlist().is_official(name)
    except Exception:
        log.exception("watchlist unavailable: treating %s as official (no report)", name)
        return True


def auto_eligible(domain: dict, pages: list[dict], cfg, sandbox: SandboxStatus) -> tuple[bool, str]:
    """REPORTING_MODE=auto rules for a domain no reviewer has confirmed. (ok, reason when not ok)."""
    from .channels import is_gov_au
    if cfg.mode != "auto":
        return False, f"REPORTING_MODE is {cfg.mode}, not auto"
    if domain.get("status") != "open":
        return False, f"domain status is {domain.get('status')}"
    if domain.get("takedown_at"):
        return False, "already taken down"
    fs = domain.get("final_score")
    if fs is None or fs < cfg.min_final_score:
        return False, f"combined score {fs} is below {cfg.min_final_score}"
    if domain.get("ai_verdict") != "phishing":
        return False, f"AI verdict is {domain.get('ai_verdict') or 'missing'}, not phishing"
    conf = domain.get("ai_confidence")
    if conf is None or not isinstance(conf, (int, float)) or math.isnan(conf) or conf < AI_CONFIRM_CONFIDENCE:
        return False, "AI confidence is below 0.7"
    if not sandbox.ok:
        return False, sandbox.reason
    if is_gov_au(domain):
        return False, ".gov.au domains are never reported automatically"
    if is_official(domain):
        return False, "official brand domain"
    if not credential_page(pages, domain.get("registered_domain") or ""):
        return False, ("the newest page snapshot on the domain itself does not ask for a password, "
                       "one-time code or card details")
    return True, ""


# ---- facts -----------------------------------------------------------------------------------------

def brand_info(brand_id: str | None) -> tuple[str, list[str]]:
    if not brand_id:
        return "an Australian brand", []
    try:
        from ..scoring import default_watchlist
        b = default_watchlist().brands.get(brand_id)
        if b:
            return b.name, list(b.official_domains[:3])
    except Exception:
        pass
    return brand_id, []


def snapshot_country(page: dict | None, egress_country: str | None, egress_ip: str | None) -> str | None:
    """The network country a report may claim for a snapshot: only when the snapshot's recorded egress IP
    is the one scripts/verify-sandbox.sh verified (and geolocated). Otherwise nothing is claimed."""
    if not page or not egress_country or not egress_ip:
        return None
    try:
        seen = str(ipaddress.ip_address(str(page.get("egress_ip") or "").strip()))
    except ValueError:
        return None
    return egress_country if seen == egress_ip else None


def build_facts(domain: dict, page: dict | None, pages: list[dict], *, egress_country: str | None = None,
                egress_ip: str | None = None) -> dict:
    """Everything a report states, as plain JSON-able values. reviewed_by_human reflects the domain now.
    egress_country / egress_ip: from the sandbox verification file (see snapshot_country)."""
    brand, official = brand_info(domain.get("brand_id"))
    urls = report_urls(domain, evidence_pages(pages, page))
    ips = [str(i) for i in (domain.get("ips") or [])[:5]]
    reviewed = domain.get("status") == "confirmed"
    return {
        "domain": domain.get("registered_domain"),
        "displayed_as": domain.get("unicode_domain") or None,
        "urls": urls,
        "hostnames": [h for h in (domain.get("hostnames") or [])[:10] if isinstance(h, str)],
        "brand_id": domain.get("brand_id"),
        "brand": brand,
        "official_sites": official,
        "first_seen": fmt_ts(domain.get("first_seen")),
        "source": domain.get("source") or "ct",
        "found_via": {"ct": "a Certificate Transparency log", "czds": "a newly registered domain (zone file)",
                      "bot": "a message forwarded to CyberCheck", "manual": "a manual submission"}.get(
                          domain.get("source") or "ct", "monitoring"),
        "ct_log": clean_line(domain.get("ct_log"), 120) or None,
        "issuer": clean_line(domain.get("issuer"), 120) or None,
        "registered": fmt_date(domain.get("registered_at")),
        "registrar": clean_line(domain.get("registrar"), 120) or None,
        "registrar_iana_id": domain.get("registrar_iana_id"),
        "ips": ips,
        "asn": domain.get("asn"),
        "as_name": clean_line(domain.get("as_name"), 120) or None,
        "ip_country": clean_line(domain.get("ip_country"), 8) or None,
        "page_seen": fmt_ts(page.get("fetched_at")) if page else None,
        "page_profile": (clean_line(page.get("user_agent_profile"), 20) or None) if page else None,
        "asks_for": asks_for(page),
        "form_posts_elsewhere": bool(page.get("external_form_post")) if page else False,
        "screenshot": bool(page and page.get("screenshot_path")),
        "page_id": page.get("id") if page else None,
        "egress_country": snapshot_country(page, egress_country, egress_ip),
        "ai_verdict": domain.get("ai_verdict"),
        "final_score": domain.get("final_score"),
        "reviewed_by_human": reviewed,
        "reviewed_on": fmt_date(domain.get("status_changed_at")) if reviewed else None,
    }


def ai_facts(facts: dict) -> dict:
    """The subset given to cybercheck.ai.api.draft_report (wrapped there as untrusted data)."""
    keys = ("domain", "displayed_as", "urls", "brand", "official_sites", "first_seen", "found_via", "registered",
            "registrar", "ips", "asn", "as_name", "ip_country", "page_seen", "asks_for", "form_posts_elsewhere",
            "screenshot", "reviewed_by_human")
    return {k: facts.get(k) for k in keys}


# ---- screenshot ------------------------------------------------------------------------------------

def screenshot_path(data_dir: Path, rel: str | None) -> Path | None:
    if not rel:
        return None
    base = Path(data_dir).resolve()
    path = (base / rel).resolve()
    if base not in path.parents or not path.is_file():
        return None
    return path


def screenshot_jpeg(data_dir: Path, rel: str | None) -> bytes | None:
    """The stored (WebP) screenshot as a bounded JPEG, or None. Blocking: call in a thread."""
    path = screenshot_path(data_dir, rel)
    if path is None:
        return None
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return None
        from PIL import Image
        with Image.open(io.BytesIO(path.read_bytes())) as im:
            w, h = im.size
            if w < 16 or h < 16 or w * h > MAX_SOURCE_PIXELS:
                return None
            out = im.convert("RGB")
            if h > MAX_HEIGHT:
                out = out.crop((0, 0, w, MAX_HEIGHT))
                h = MAX_HEIGHT
            if w > MAX_WIDTH:
                out = out.resize((MAX_WIDTH, max(1, round(h * MAX_WIDTH / w))), Image.Resampling.LANCZOS)
            for quality in (80, 65, 50):
                buf = io.BytesIO()
                out.save(buf, format="JPEG", quality=quality, optimize=True)
                if buf.tell() <= MAX_JPEG_BYTES:
                    return buf.getvalue()
    except Exception as e:  # noqa: BLE001 - a broken image just means no screenshot in the report
        log.warning("screenshot could not be converted: %s", type(e).__name__)
    return None
