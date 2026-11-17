"""Worker-side client for the sandboxed fetcher API (fetcher/app.py).

The fetcher is the only component that visits suspicious sites, and it runs inside the VPN network
namespace. The worker never talks to a flagged domain itself: it asks the fetcher over its local API
(FETCHER_URL, default http://127.0.0.1:8432) with a bearer FETCHER_TOKEN, and the fetcher returns
JSON only. If the fetcher is unreachable (the VPN profile is not up, or it is failing closed because
the egress is not the expected country), the methods here return None and the fetch job skips quietly.

A failure that only concerns one request (HTTP 500 for this URL, a read timeout, a body that is too
large or not a JSON object) is ambiguous: /health is asked again, and if the fetcher is healthy the
request is returned as a fetcher_error result for that URL (it says nothing about the page, and the
job backs the domain off), otherwise None. So a page that breaks the fetcher's response cannot keep
its domain at the head of the queue, and it cannot be recorded as the page being down either.

Nothing here parses or renders the HTML it receives; it only passes the JSON back to the caller, which
treats it as hostile input. It does make every value storable first (_storable): Postgres refuses NUL in
text and \\u0000, NaN and Infinity in jsonb, and psycopg cannot encode a lone surrogate, so one such value
would make every save of the domain fail (the fetcher strips most of them, but this side must not depend on
that).
"""
from __future__ import annotations

import logging
import math

import httpx

from .config import settings

log = logging.getLogger("cybercheck.fetch_client")

# Largest /fetch body accepted. The fetcher keeps its JSON under 8 MB (fetcher/app.py
# MAX_RESPONSE_BYTES: html <= 2 MB of UTF-8, at most doubled by JSON escaping, plus the screenshot).
MAX_RESPONSE_BYTES = 10_000_000
HTML_CAP = 2_100_000        # kept for callers: the fetcher caps html at ~2 MB of UTF-8
TEXT_CAP = 20_000
UNAVAILABLE_STATUS = (401, 403, 429, 503)   # token problem / rate limit / failing closed (no VPN)


def _storable(value):
    """value (parsed JSON) with what Postgres text / jsonb cannot hold removed: NUL characters dropped, lone
    surrogates replaced by '?', NaN and +-Infinity replaced by None. Raises RecursionError when nested
    deeper than Python can walk."""
    if isinstance(value, str):
        if "\x00" in value:
            value = value.replace("\x00", "")
        if not value.isascii():
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                value = value.encode("utf-8", "replace").decode("utf-8")
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, list):
        return [_storable(v) for v in value]
    if isinstance(value, dict):
        return {_storable(k): _storable(v) for k, v in value.items()}
    return value


class FetchClient:
    """Thin async HTTP client. One instance per fetch run; close() when done."""

    def __init__(self, base_url: str | None = None, token: str | None = None,
                 connect_timeout: float = 5.0, read_timeout: float = 70.0) -> None:
        s = settings()
        self.base_url = (base_url or s.fetcher_url or "http://127.0.0.1:8432").rstrip("/")
        self.token = token if token is not None else s.fetcher_token
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "FetchClient":
        self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False,
                                         headers={"Authorization": f"Bearer {self.token}"},
                                         limits=httpx.Limits(max_connections=4, max_keepalive_connections=2))
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def configured(self) -> bool:
        return bool(self.token)

    async def health(self) -> dict | None:
        """{'ok', 'vpn_running', 'egress_ip', 'egress_country'} or None if the fetcher is unreachable."""
        if self._client is None or not self.token:
            return None
        try:
            resp = await self._client.get(f"{self.base_url}/health")
        except (httpx.HTTPError, OSError):
            return None
        if resp.status_code != 200:
            # 503 means the fetcher is up but failing closed (no VPN / wrong country); 401 means the
            # token is wrong. Surface the detail, but "ok" is always False here, whatever the body says.
            body: dict = {}
            try:
                if resp.headers.get("content-type", "").startswith("application/json"):
                    j = resp.json()
                    body = j if isinstance(j, dict) else {}
            except ValueError:
                body = {}
            keep = {k: body.get(k) for k in ("vpn_running", "egress_country", "error", "detail") if k in body}
            return {**keep, "ok": False, "http_status": resp.status_code}
        try:
            data = _storable(resp.json())
        except (ValueError, RecursionError):
            return None
        return data if isinstance(data, dict) else None

    async def fetch(self, url: str, profile: str = "mobile") -> dict | None:
        """POST /fetch. Returns the fetcher's JSON (which may itself carry ok=False and an error), a
        fetcher_error result when this one request failed but the fetcher is healthy, or None if the
        fetcher could not be reached or is not fetching (503 failing closed, 401/403 token)."""
        if self._client is None or not self.token:
            return None
        if profile not in ("mobile", "desktop"):
            profile = "mobile"
        try:
            resp = await self._client.post(f"{self.base_url}/fetch", json={"url": url, "profile": profile})
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
            log.debug("fetcher unreachable for %s: %s: %s", url, type(e).__name__, e)
            return None
        except (httpx.HTTPError, OSError) as e:
            # Sent, but no usable answer (read timeout, connection dropped mid-response): the fetcher
            # may have died, or this page hung it.
            return await self._fault_if_healthy(url, profile, f"fetcher request failed: {type(e).__name__}")
        if resp.status_code in UNAVAILABLE_STATUS:
            log.debug("fetcher returned HTTP %s for %s", resp.status_code, url)
            return None
        if resp.status_code >= 500:
            return await self._fault_if_healthy(url, profile, f"fetcher HTTP {resp.status_code}")
        if resp.status_code != 200:
            # 400: the fetcher refused the URL. Nothing about the page either.
            return self._fault(url, profile, f"fetcher HTTP {resp.status_code}")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            return self._fault(url, profile, "fetcher response too large")
        try:
            data = _storable(resp.json())
        except (ValueError, RecursionError):
            return self._fault(url, profile, "fetcher returned non-JSON")
        if not isinstance(data, dict):
            return self._fault(url, profile, "fetcher returned non-object")
        if not isinstance(data.get("url"), str) or not data["url"]:
            data["url"] = url                  # pages.url is NOT NULL: a null / missing url is the requested one
        data.setdefault("profile", profile)
        return data

    @staticmethod
    def _fault(url: str, profile: str, error: str) -> dict:
        """A result that says nothing about the page: never counts towards live_state 'down'."""
        return {"ok": False, "fetcher_error": True, "error": error, "final_url": None, "http_status": None,
                "url": url, "profile": profile}

    async def _fault_if_healthy(self, url: str, profile: str, error: str) -> dict | None:
        """One request failed ambiguously. If /health is fine, the failure belongs to this URL (a
        fetcher_error result); otherwise the fetcher is unavailable (None)."""
        health = await self.health()
        if not health or not health.get("ok"):
            log.debug("fetcher unavailable after %s for %s", error, url)
            return None
        log.info("fetcher failed one request (%s) for %s but is healthy", error, url)
        return self._fault(url, profile, error)


__all__ = ["FetchClient"]
