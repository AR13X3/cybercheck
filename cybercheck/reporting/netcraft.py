"""Netcraft Report API v3 (the one channel built for automated phishing reports; research 2026-11-15).

POST {base}/report/urls with {"email", "reason", "urls": [{"url", "country", "reason", "screenshot"}]}.
No API key: the report endpoint declares no security. Production base https://report.netcraft.com/api/v3,
development base .../api/v3/test (NETCRAFT_TEST=true). 200 returns {message, uuid, invalid_urls}; 429
means too many reports (back off). Status: GET {base}/submission/{uuid} and /submission/{uuid}/urls;
submissions are archived after 30 days. URLs of one domain go in one submission (Netcraft may reject
URLs when one domain gets many separate submissions).

Only Netcraft's own servers are contacted here, never the reported site.
"""
from __future__ import annotations

import base64
import json
import re

import httpx

from .common import SendResult, clean_line

BASE = "https://report.netcraft.com/api/v3"
TEST_BASE = "https://report.netcraft.com/api/v3/test"
USER_AGENT = "CyberCheck-report/1.0 (phishing reports for Australian brands)"
TIMEOUT_S = 30.0
MAX_URLS = 1000
REASON_MAX = 10000
MAX_RESPONSE_BYTES = 256 * 1024
UUID_RE = re.compile(r"[0-9A-Fa-f][0-9A-Fa-f-]{7,63}")      # use fullmatch: "$" would accept a trailing "\n"
PERMANENT_STATUSES = {400, 401, 403, 404, 405, 409, 410, 413, 415, 422}
MAX_RETRY_AFTER_S = 6 * 3600


def base_url(test: bool) -> str:
    return TEST_BASE if test else BASE


def build_payload(email: str, urls: list[str], reason: str, url_reason: str, country: str = "AU",
                  screenshot_jpeg: bytes | None = None) -> dict:
    """Request body for POST /report/urls (ReportURLs has additionalProperties: false)."""
    items = []
    for i, u in enumerate(urls[:MAX_URLS]):
        item = {"url": u, "country": country, "reason": url_reason[:REASON_MAX]}
        if i == 0 and screenshot_jpeg:
            item["screenshot"] = {"base64": base64.standard_b64encode(screenshot_jpeg).decode("ascii"), "ext": "jpg"}
        items.append(item)
    return {"email": email, "reason": reason[:REASON_MAX], "skip_invalid_urls": True, "urls": items}


def audit_copy(payload: dict) -> dict:
    """The payload without the base64 screenshot (stored in reports.payload['sent'])."""
    out = {k: v for k, v in payload.items() if k != "urls"}
    out["urls"] = []
    for item in payload.get("urls", []):
        it = {k: v for k, v in item.items() if k != "screenshot"}
        if "screenshot" in item:
            it["screenshot"] = {"ext": item["screenshot"].get("ext"),
                                "bytes": len(base64.standard_b64decode(item["screenshot"]["base64"]))}
        out["urls"].append(it)
    return out


def _retry_after(resp: httpx.Response) -> float | None:
    v = resp.headers.get("retry-after")
    try:
        return max(0.0, min(float(v), MAX_RETRY_AFTER_S)) if v else None
    except ValueError:
        return None


def _json(resp: httpx.Response):
    body = resp.content[:MAX_RESPONSE_BYTES]
    try:
        return json.loads(body)
    except ValueError:
        return None


def _short(value, limit=300) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value)[:limit]
    return clean_line(value, limit)


async def submit(client: httpx.AsyncClient, base: str, payload: dict) -> SendResult:
    sent = audit_copy(payload)
    sent["endpoint"] = f"{base}/report/urls"
    try:
        resp = await client.post(f"{base}/report/urls", json=payload, timeout=TIMEOUT_S)
    except httpx.TimeoutException:
        return SendResult(ok=False, error="Netcraft: request timed out", sent=sent)
    except httpx.HTTPError as e:
        return SendResult(ok=False, error=f"Netcraft: {type(e).__name__}", sent=sent)
    data = _json(resp)
    status = resp.status_code
    if status == 200 and isinstance(data, dict):
        uuid = data.get("uuid")
        uuid = uuid if isinstance(uuid, str) and UUID_RE.fullmatch(uuid) else None   # stored and put in URLs
        invalid = [clean_line(u, 500) for u in (data.get("invalid_urls") or [])[:50] if isinstance(u, str)]
        response = {"message": _short(data.get("message"), 300), "uuid": uuid,
                    "invalid_urls": invalid, "test": base == TEST_BASE}
        if uuid is None:
            return SendResult(ok=False, http_status=status, response=response, sent=sent,
                              error="Netcraft: response had no submission uuid")
        if invalid and len(invalid) >= len(payload.get("urls") or []):
            return SendResult(ok=False, permanent=True, http_status=status, response=response, sent=sent,
                              error="Netcraft rejected every URL as invalid")
        return SendResult(ok=True, http_status=status, external_id=uuid, response=response, sent=sent)
    detail = _short(data if data is not None else resp.text, 300)
    response = {"http_status": status, "detail": detail}
    if status == 429:
        return SendResult(ok=False, http_status=status, retry_after=_retry_after(resp) or 900, response=response,
                          sent=sent, error="Netcraft: too many reports (HTTP 429); backing off")
    if status in PERMANENT_STATUSES:
        return SendResult(ok=False, permanent=True, http_status=status, response=response, sent=sent,
                          error=f"Netcraft: HTTP {status}: {detail}")
    return SendResult(ok=False, http_status=status, response=response, sent=sent,
                      error=f"Netcraft: HTTP {status}")


URL_STATE_KEYS = ("url", "url_state", "url_takedown_state", "incident_report_url", "ip", "country_code",
                  "url_classification_reason")


async def poll(client: httpx.AsyncClient, base: str, uuid: str) -> dict | None:
    """Submission state and per-URL states, or None on a transient error. {'archived': True} after 30 days."""
    if not UUID_RE.fullmatch(uuid or ""):
        return {"final": True, "error": "invalid uuid"}
    out: dict = {}
    try:
        r1 = await client.get(f"{base}/submission/{uuid}", timeout=TIMEOUT_S)
        r2 = await client.get(f"{base}/submission/{uuid}/urls", params={"count": 1000}, timeout=TIMEOUT_S)
    except httpx.HTTPError:
        return None
    if r1.status_code == 404 or r2.status_code == 404:
        return {"archived": True, "final": True}
    if r1.status_code != 200 or r2.status_code != 200:
        return None
    d1, d2 = _json(r1), _json(r2)
    if isinstance(d1, dict):
        out["state"] = _short(d1.get("state"), 40) or None
        out["is_archived"] = bool(d1.get("is_archived"))
    urls = d2.get("urls") if isinstance(d2, dict) else d2 if isinstance(d2, list) else None
    states = []
    for u in (urls or [])[:50]:
        if isinstance(u, dict):
            states.append({k: _short(u.get(k), 500) for k in URL_STATE_KEYS if u.get(k) is not None})
    out["urls"] = states
    out["final"] = bool(out.get("is_archived")) or (
        bool(states) and all(s.get("url_takedown_state") == "resolved" for s in states))
    return out


def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT_S, follow_redirects=False, headers={"User-Agent": USER_AGENT})
