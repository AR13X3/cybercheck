"""CyberCheck sandboxed page fetcher.

This is the ONLY component that visits suspicious sites, and it runs inside the gluetun VPN network
namespace (fetcher/compose.yaml), so every request it makes leaves through the VPN or not at all. It
exposes a tiny HTTP API to the worker on the host and returns JSON only; it never stores anything and
never renders a page. Page content is hostile input.

Endpoints (Bearer FETCHER_TOKEN, constant-time compared; any request carrying an Origin header is
refused, because only the local worker, which sends none, may call this API):
  GET  /health            -> {ok, vpn_running, egress_ip, egress_country, browser_ok, error}
  POST /fetch {url, profile:"mobile"|"desktop"}
        -> {ok, final_url, http_status, redirect_chain, title, html, text_excerpt,
            screenshot_webp_b64, forms, egress_ip, egress_country, timings, error, fetcher_error}

Fail-closed egress gate. Before every fetch (cached IP_CACHE_TTL seconds) it asks the gluetun control
server for the VPN status and the public IP/country, and returns 503 unless ALL hold:
  - GLUETUN_API_KEY is set (>= 16 chars) and the control server REJECTS a request without it (401),
    so a misconfigured control server (no auth: page JS could restart the VPN) disables fetching;
  - the VPN status is "running" and the public IP is known;
  - the country matches FETCH_EXPECTED_COUNTRY (default "AU"; empty disables that one check).

Watchdog. If gluetun restarts on its own, this container is left in the old, dead network namespace
(only loopback, nothing reachable, so nothing leaks) and the host's published port points at the new
one. A background check notices that the control server has been unreachable for FETCH_WATCHDOG_S
(default 300 s) and exits, so Docker's restart policy re-joins the fresh namespace.

Browser: Chromium sandbox on, a fresh context per fetch, service workers blocked, downloads off, no
permissions, dialogs dismissed, WebRTC limited to proxied UDP (i.e. none), only http/https, and a route
handler (HTTP and WebSocket) that aborts requests to localhost and to any non-public IP literal. These
are defence in depth: gluetun's firewall, post-rules and DNS filtering are the real boundary.

`fetcher_error: true` marks a result where the fetcher itself failed (browser crash, hard timeout,
internal error): it says nothing about the page, and the worker does not count it as the page being down.

Two more cases answer 503 (the worker then changes nothing for the domain and stops its run):
  - Chromium cannot be started. After LAUNCH_FAIL_EXIT launch failures in a row the process exits, so
    Docker restarts the container with a fresh Playwright driver; /health also reports browser_ok.
  - A navigation failed and a forced egress re-check shows the VPN dropped or changed exit during the
    fetch, so the failure says nothing about the page.
Every string in a /fetch result comes from the hostile page, so it is rebuilt in Python (str only,
lone surrogates replaced, C0 control characters dropped, capped) and the JSON body is kept under
MAX_RESPONSE_BYTES; a result that still cannot be encoded becomes a fetcher_error result, never a 500.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import time
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from playwright.async_api import Browser, async_playwright

log = logging.getLogger("fetcher")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or "").strip() or default


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


FETCHER_TOKEN = _env("FETCHER_TOKEN")
GLUETUN_API_KEY = _env("GLUETUN_API_KEY")
GLUETUN_CONTROL_URL = _env("GLUETUN_CONTROL_URL", "http://127.0.0.1:8000").rstrip("/")
# "" disables the country check. Unset means AU. (os.environ distinguishes the two.)
EXPECTED_COUNTRY = (os.environ.get("FETCH_EXPECTED_COUNTRY", "AU") or "").strip().upper()
MAX_PAGES = max(1, _int("FETCH_MAX_PAGES", 200))     # recycle the browser after this many pages
MAX_CONCURRENCY = max(1, min(4, _int("FETCH_CONCURRENCY", 2)))
PAGE_TIMEOUT_MS = _int("FETCH_PAGE_TIMEOUT_MS", 25000)
HARD_TIMEOUT_MS = _int("FETCH_HARD_TIMEOUT_MS", 45000)
HTML_CAP = _int("FETCH_HTML_CAP", 2_000_000)
TEXT_CAP = _int("FETCH_TEXT_CAP", 20_000)
SCREENSHOT_MAX_HEIGHT = _int("FETCH_SCREENSHOT_MAX_HEIGHT", 2400)
WEBP_QUALITY = max(1, min(100, _int("FETCH_WEBP_QUALITY", 60)))
WATCHDOG_S = _int("FETCH_WATCHDOG_S", 300)          # 0 disables the stale-namespace watchdog
IP_CACHE_TTL = 60.0
MIN_SECRET_LEN = 16
MAX_FRAMES = 10                                      # frames scanned for forms
MAX_FORMS = 50                                       # forms returned, all frames together
MAX_FORM_INPUTS = 200                                # inputs per form
MAX_INPUTS_TOTAL = 500                               # inputs over all forms (pagefeatures reads 200)
MAX_RESPONSE_BYTES = 8_000_000                       # JSON body; the worker accepts up to 10 MB
LAUNCH_FAIL_EXIT = 3                                 # Chromium launch failures in a row before exiting
# A launch that has not finished by then counts as a failure. It must end inside a fetch's own budget
# (HARD_TIMEOUT_MS + 5 s, BrowserPool.fetch), or a hung Playwright driver would only ever produce
# "hard timeout" results, never be counted, and /health would stay 200. Playwright's own launch
# timeout (30 s) normally fires first.
LAUNCH_TIMEOUT_S = min(40.0, max(1.0, HARD_TIMEOUT_MS / 1000 - 5))
CHROME_MAJOR = _env("FETCH_CHROME_MAJOR", "159")     # reduced UA major (bundled Chromium is 159.x)

# Explicit ranges on top of "not ipaddress.is_global" (which already covers loopback, RFC1918,
# CGNAT/tailnet 100.64/10, link-local + metadata 169.254/16, ULA, 0/8, documentation, benchmark...).
_BLOCKED_NETS = [ipaddress.ip_network(c) for c in (
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "224.0.0.0/3", "::1/128", "::/128", "fc00::/7", "fe80::/10", "fd7a:115c:a1e0::/48",
)]
_LEGACY_V4 = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$")
_UA_BUILD = re.compile(r"Chrome/\d+\.\d+\.\d+\.\d+")
# C0 controls other than tab / LF / CR: JSON escapes each one as \u00XX (6 bytes), and they carry
# nothing a reviewer or the scorer needs.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Used if the Playwright device registry is unavailable for some reason (values of Playwright 1.65's
# "Pixel 7" descriptor), so the mobile profile never silently degrades to a desktop one.
_PIXEL7_FALLBACK = {
    "user_agent": ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/159.0.8154.6 Mobile Safari/537.36"),
    "viewport": {"width": 412, "height": 839}, "screen": {"width": 412, "height": 915},
    "device_scale_factor": 2.625, "is_mobile": True, "has_touch": True,
}


def _ip_of(host: str):
    """The IP a URL host denotes, including legacy IPv4 spellings (127.1, 0x7f000001); else None."""
    h = host.strip().strip("[]").lower().rstrip(".")
    try:
        return ipaddress.ip_address(h.split("%", 1)[0])
    except ValueError:
        pass
    if _LEGACY_V4.match(h):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(h))
        except (OSError, ValueError):
            return None
    return None


def _blocked_host(host: str | None) -> bool:
    """True for localhost names and any IP literal that is not a public unicast address."""
    if not host:
        return True
    h = host.strip().strip("[]").lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(".localhost"):
        return True
    ip = _ip_of(h)
    if ip is None:
        return False                      # a hostname: the DNS filter and firewall decide
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if mapped is not None:
            ip = mapped
    if not ip.is_global or ip.is_multicast:
        return True
    return any(ip.version == net.version and ip in net for net in _BLOCKED_NETS)


# Backwards-compatible name used by earlier code and tests.
_blocked_ip = _blocked_host


def _reduced_ua(ua: str) -> str:
    return _UA_BUILD.sub(f"Chrome/{CHROME_MAJOR}.0.0.0", ua)


# ---- page data -> JSON-safe values -------------------------------------------------------------------
# Everything below comes from the hostile page, which runs in the main world and can replace builtins
# (String.prototype.slice returning NaN, getters returning objects, lone UTF-16 surrogates). Values are
# rebuilt here into a fixed shape so the response always encodes and always fits the worker's cap.

def _text(value, max_chars: int) -> str | None:
    """A str from page data, or None: lone surrogates replaced, C0 controls dropped, capped."""
    if not isinstance(value, str):
        return None
    v = value[: max_chars * 2]                   # bound the work before cleaning
    v = v.encode("utf-8", "replace").decode("utf-8")
    return _CTRL.sub("", v)[:max_chars]


def _html(value) -> str | None:
    """The page HTML capped at HTML_CAP *bytes* of UTF-8 (the old cap counted characters, so 2M
    four-byte characters made an 8 MB body), without C0 controls and lone surrogates."""
    if not isinstance(value, str) or not value:
        return None
    v = _CTRL.sub("", value[:HTML_CAP])           # a character is >= 1 byte, so this keeps every byte we keep
    raw = v.encode("utf-8", "replace")[:HTML_CAP]
    return raw.decode("utf-8", "ignore") or None  # "ignore" drops a character cut in half


def _flag(value) -> bool:
    return value is True                          # NaN, "yes" and objects are not True


def _clean_forms(raw, budget: dict) -> list:
    """Rebuild forms from _FORMS_JS into {action, method, has_*, inputs:[{type, name, autocomplete,
    label}]}, all strings, at most MAX_FORMS forms (budget["forms"]) and MAX_INPUTS_TOTAL inputs
    (budget["inputs"]) over all frames. A form whose inputs were cut keeps its per-form flags."""
    out: list = []
    if not isinstance(raw, list):
        return out
    for f in raw:
        if budget["forms"] <= 0:
            break
        if not isinstance(f, dict):
            continue
        inputs: list = []
        raw_inputs = f.get("inputs")
        if isinstance(raw_inputs, list):
            for i in raw_inputs[:MAX_FORM_INPUTS]:
                if budget["inputs"] <= 0:
                    break
                if not isinstance(i, dict):
                    continue
                budget["inputs"] -= 1
                inputs.append({"type": (_text(i.get("type"), 30) or "").lower(),
                               "name": _text(i.get("name"), 120) or "",
                               "autocomplete": _text(i.get("autocomplete"), 60) or "",
                               "label": _text(i.get("label"), 120) or ""})
        budget["forms"] -= 1
        out.append({"action": _text(f.get("action"), 2000) or "",
                    "method": (_text(f.get("method"), 10) or "").lower(),
                    "has_password": _flag(f.get("has_password")), "has_otp": _flag(f.get("has_otp")),
                    "has_card": _flag(f.get("has_card")), "inputs": inputs})
    return out


def _render(result: dict) -> bytes:
    """The JSON body exactly as the worker will receive it (Starlette's JSONResponse settings)."""
    return json.dumps(result, ensure_ascii=False, allow_nan=False, indent=None,
                      separators=(",", ":")).encode("utf-8")


def _country_matches(country: str | None) -> bool:
    if not EXPECTED_COUNTRY:
        return True
    if not country:
        return False
    c = country.strip().upper()
    # gluetun reports a name ("Australia"); accept the ISO code too
    return c == EXPECTED_COUNTRY or (EXPECTED_COUNTRY == "AU" and c in ("AUSTRALIA", "AUS"))


# ---- gluetun control server (egress gate + watchdog) ------------------------------------------------

class Egress:
    """Cached VPN status / public IP / country from the gluetun control server, failing closed."""

    def __init__(self) -> None:
        self._at = 0.0
        self._data: dict = self._closed("not checked yet")
        self._lock = asyncio.Lock()
        self.started = time.monotonic()
        self.unreachable_since: float | None = None

    @staticmethod
    def _closed(error: str, **kw) -> dict:
        out = {"ok": False, "vpn_running": False, "egress_ip": None, "egress_country": None, "error": error}
        out.update(kw)
        return out

    async def _query(self) -> dict:
        if len(GLUETUN_API_KEY) < MIN_SECRET_LEN:
            return self._closed("GLUETUN_API_KEY is missing or too short")
        headers = {"X-API-Key": GLUETUN_API_KEY}
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as client:
            try:
                probe = await client.get(f"{GLUETUN_CONTROL_URL}/v1/vpn/status")
            except (httpx.HTTPError, OSError) as e:
                self.unreachable_since = self.unreachable_since or time.monotonic()
                log.warning("gluetun control server unreachable: %s", type(e).__name__)
                return self._closed("gluetun control server unreachable")
            self.unreachable_since = None
            if probe.status_code != 401:
                # Without auth a page could drive the VPN (the v3.41 no-auth public role). Refuse.
                log.error("gluetun control server answered %s WITHOUT an API key: refusing to fetch "
                          "(set HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE)", probe.status_code)
                return self._closed("gluetun control server does not require the API key")
            try:
                r = await client.get(f"{GLUETUN_CONTROL_URL}/v1/vpn/status", headers=headers)
                j = r.json() if r.status_code == 200 else {}
                running = isinstance(j, dict) and j.get("status") == "running"
            except (httpx.HTTPError, ValueError, OSError):
                return self._closed("vpn status check failed")
            if r.status_code == 401:
                return self._closed("GLUETUN_API_KEY rejected by the control server")
            if not running:
                return self._closed("VPN is not running")
            try:
                r = await client.get(f"{GLUETUN_CONTROL_URL}/v1/publicip/ip", headers=headers)
                j = r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError, OSError):
                return self._closed("public IP check failed", vpn_running=True)
        ip = j.get("public_ip") if isinstance(j, dict) else None
        country = (j.get("country") or "").strip() if isinstance(j, dict) and isinstance(j.get("country"), str) else ""
        try:
            ip = str(ipaddress.ip_address(ip)) if isinstance(ip, str) and ip else None
        except ValueError:
            ip = None
        out = {"ok": False, "vpn_running": True, "egress_ip": ip, "egress_country": country or None, "error": None}
        if not ip:
            out["error"] = "public IP unknown"
        elif not _country_matches(country):
            out["error"] = f"egress country {country or 'unknown'!r} is not {EXPECTED_COUNTRY}"
        else:
            out["ok"] = True
        return out

    async def get(self, force: bool = False) -> dict:
        async with self._lock:
            if force or time.monotonic() - self._at > IP_CACHE_TTL:
                try:
                    self._data = await self._query()
                except Exception as e:     # never let a surprise here open the gate
                    log.warning("egress check failed: %s", type(e).__name__)
                    self._data = self._closed("egress check failed")
                self._at = time.monotonic()
            return dict(self._data)

    def watchdog_expired(self) -> bool:
        if WATCHDOG_S <= 0 or self.unreachable_since is None:
            return False
        now = time.monotonic()
        return now - self.started > WATCHDOG_S and now - self.unreachable_since > WATCHDOG_S


# ---- page scripts -------------------------------------------------------------------------------------

# Runs inside the (hostile) page. Reads attributes with getAttribute (form.action can be clobbered by
# an <input name="action">), and also reports inputs that are not inside any <form>, because many kits
# submit with JavaScript and have no form element at all.
_FORMS_JS = r"""
() => {
  const cap = 50, icap = 200;
  const attr = (el, n) => { try { return String(el.getAttribute(n) || ''); } catch (e) { return ''; } };
  const abs = (raw) => { try { return raw ? new URL(raw, document.baseURI).href : ''; } catch (e) { return ''; } };
  const describe = (el) => {
    const type = (attr(el, 'type') || el.tagName || '').toLowerCase().slice(0, 30);
    const name = (attr(el, 'name') || attr(el, 'id')).slice(0, 120);
    const autocomplete = attr(el, 'autocomplete').slice(0, 60);
    let label = '';
    try {
      const id = attr(el, 'id');
      if (id) { const l = document.querySelector('label[for="' + CSS.escape(id) + '"]'); if (l) label = l.textContent || ''; }
      if (!label) { const l = el.closest('label'); if (l) label = l.textContent || ''; }
      if (!label) label = attr(el, 'placeholder') || attr(el, 'aria-label');
    } catch (e) {}
    return {type, name, autocomplete, label: String(label || '').replace(/\s+/g, ' ').trim().slice(0, 120)};
  };
  const summarise = (inputs, action, method) => ({
    action: String(action).slice(0, 2000), method: String(method).slice(0, 10),
    has_password: inputs.some(i => i.type === 'password' || /(^|\s)(current|new)-password(\s|$)/.test(i.autocomplete)),
    has_otp: inputs.some(i => /(^|\s)one-time-code(\s|$)/.test(i.autocomplete)),
    has_card: inputs.some(i => /(^|\s)cc-(number|csc|exp)/.test(i.autocomplete)),
    inputs,
  });
  const out = [];
  try {
    for (const f of Array.from(document.querySelectorAll('form')).slice(0, cap)) {
      const inputs = Array.from(f.querySelectorAll('input, select, textarea')).slice(0, icap).map(describe);
      out.push(summarise(inputs, abs(attr(f, 'action')), (attr(f, 'method') || 'get').toLowerCase()));
    }
    const orphans = Array.from(document.querySelectorAll('input, select, textarea'))
      .filter(el => !el.closest('form')).slice(0, icap).map(describe);
    if (orphans.length) out.push(summarise(orphans, '', 'script'));
  } catch (e) {}
  return out;
}
"""


# ---- browser pool -----------------------------------------------------------------------------------

class BrowserUnavailable(Exception):
    """Chromium could not be started: the fetcher cannot fetch anything (answer 503, not a result)."""


def _exit(code: int) -> None:
    os._exit(code)                               # a function so tests can replace it


class BrowserPool:
    """One shared Chromium; recycled after MAX_PAGES pages (without killing fetches still running on
    the old one) or on a crash."""

    def __init__(self) -> None:
        self._pw = None
        self._browser: Browser | None = None
        self._pages = 0
        self._inflight: dict[int, int] = {}          # id(browser) -> fetches using it
        self._retired: dict[int, Browser] = {}       # old browsers waiting for their last fetch
        self._lock = asyncio.Lock()
        self.sem = asyncio.Semaphore(MAX_CONCURRENCY)
        self.devices: dict = {}
        self.launch_failures = 0                     # Chromium launch failures in a row
        self.launch_error: str | None = None

    async def start(self) -> None:
        self._pw = await async_playwright().start()
        try:
            self.devices = dict(self._pw.devices)
        except Exception:
            self.devices = {}

    async def _launch(self) -> Browser:
        assert self._pw is not None
        # chromium_sandbox=True: without it Playwright adds --no-sandbox. channel="chromium": new
        # headless (the real browser). No --disable-features here: Playwright already passes one list.
        return await self._pw.chromium.launch(
            chromium_sandbox=True, channel="chromium",
            args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])

    @staticmethod
    async def _close(b: Browser | None) -> None:
        if b is None:
            return
        try:
            await asyncio.wait_for(b.close(), 15)
        except Exception:
            pass

    async def _launch_counted(self) -> Browser:
        """_launch, counting failures in a row. A dead Playwright driver or a Chromium that aborts
        (no usable sandbox) fails every launch and nothing in-process recovers it, so after
        LAUNCH_FAIL_EXIT failures the process exits and Docker restarts the container."""
        try:
            b = await asyncio.wait_for(self._launch(), LAUNCH_TIMEOUT_S)
        except Exception as e:
            self.launch_failures += 1
            self.launch_error = (f"launch did not finish within {LAUNCH_TIMEOUT_S:g} s"
                                 if isinstance(e, asyncio.TimeoutError) else f"{type(e).__name__}: {e}"[:300])
            log.error("Chromium failed to start (%d in a row): %s", self.launch_failures, self.launch_error)
            if self.launch_failures >= LAUNCH_FAIL_EXIT:
                log.error("Chromium failed to start %d times in a row: exiting so Docker restarts the "
                          "container with a fresh Playwright driver", self.launch_failures)
                _exit(71)
            raise BrowserUnavailable(self.launch_error) from e
        self.launch_failures = 0
        self.launch_error = None
        return b

    async def _ensure_locked(self) -> Browser:
        """The current browser, (re)launched if needed. Caller holds self._lock."""
        b = self._browser
        if b is None or not b.is_connected() or self._pages >= MAX_PAGES:
            self._browser = await self._launch_counted()
            self._pages = 0
            if b is not None:
                if self._inflight.get(id(b), 0) > 0 and b.is_connected():
                    self._retired[id(b)] = b             # close when its last fetch finishes
                else:
                    asyncio.get_running_loop().create_task(self._close(b))
        return self._browser

    async def acquire(self) -> Browser:
        async with self._lock:
            b = await self._ensure_locked()            # may raise BrowserUnavailable
            self._pages += 1
            self._inflight[id(b)] = self._inflight.get(id(b), 0) + 1
            return b

    async def ensure(self) -> bool:
        """True if a browser is (or could now be) running. Used by /health after a launch failure, so
        the failure count keeps moving (towards the restart) while the worker is not fetching."""
        async with self._lock:
            try:
                await self._ensure_locked()
                return True
            except BrowserUnavailable:
                return False

    async def release(self, b: Browser) -> None:
        async with self._lock:
            n = self._inflight.get(id(b), 1) - 1
            if n > 0:
                self._inflight[id(b)] = n
                return
            self._inflight.pop(id(b), None)
            old = self._retired.pop(id(b), None)
        if old is not None:
            await self._close(old)

    async def recycle(self) -> None:
        """Crash / hard timeout: drop the current browser now (fetches on it fail, as they would)."""
        async with self._lock:
            b, self._browser, self._pages = self._browser, None, 0
            retired = list(self._retired.values())
            self._retired.clear()
        await self._close(b)
        for old in retired:
            await self._close(old)

    async def stop(self) -> None:
        await self.recycle()
        if self._pw is not None:
            with contextlib.suppress(Exception):
                await self._pw.stop()
            self._pw = None

    def _context_kwargs(self, profile: str) -> dict:
        base = dict(locale="en-AU", timezone_id="Australia/Sydney", service_workers="block",
                    accept_downloads=False, permissions=[], ignore_https_errors=True,
                    java_script_enabled=True)
        if profile == "desktop":
            base.update(user_agent=(f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                    f"(KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"),
                        viewport={"width": 1366, "height": 768}, screen={"width": 1366, "height": 768},
                        is_mobile=False, has_touch=False, device_scale_factor=1)
        else:
            dev = dict(self.devices.get("Pixel 7") or _PIXEL7_FALLBACK)
            dev.pop("default_browser_type", None)
            if dev.get("user_agent"):
                dev["user_agent"] = _reduced_ua(dev["user_agent"])
            base.update(dev)
        return base

    async def fetch(self, url: str, profile: str) -> dict:
        async with self.sem:
            return await asyncio.wait_for(self._fetch(url, profile), HARD_TIMEOUT_MS / 1000 + 5)

    async def _fetch(self, url: str, profile: str) -> dict:
        t0 = time.monotonic()
        out: dict = {"ok": False, "final_url": None, "http_status": None, "redirect_chain": [],
                     "title": None, "html": None, "text_excerpt": None, "screenshot_webp_b64": None,
                     "forms": [], "timings": {}, "error": None, "fetcher_error": False}
        browser = await self.acquire()
        context = None
        crashed = {"v": False}
        try:
            context = await browser.new_context(**self._context_kwargs(profile))
            context.set_default_timeout(PAGE_TIMEOUT_MS)
            context.set_default_navigation_timeout(PAGE_TIMEOUT_MS)

            async def route(r):
                try:
                    parts = urlsplit(r.request.url)
                    if parts.scheme not in ("http", "https") or _blocked_host(parts.hostname):
                        await r.abort("blockedbyclient")
                        return
                    await r.continue_()
                except Exception:
                    with contextlib.suppress(Exception):
                        await r.abort()

            async def ws_route(ws):
                try:
                    parts = urlsplit(ws.url)
                    if parts.scheme not in ("ws", "wss") or _blocked_host(parts.hostname):
                        res = ws.close()
                        if asyncio.iscoroutine(res):
                            await res
                        return
                    res = ws.connect_to_server()
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    with contextlib.suppress(Exception):
                        res = ws.close()
                        if asyncio.iscoroutine(res):
                            await res

            await context.route("**/*", route)
            route_ws = getattr(context, "route_web_socket", None)
            if route_ws is not None:
                await route_ws(re.compile(r".*"), ws_route)

            page = await context.new_page()
            redirects: list[str] = []
            page.on("dialog", lambda d: asyncio.ensure_future(_dismiss(d)))
            page.on("response", lambda resp: _note_redirect(resp, page, redirects))
            page.on("framenavigated", lambda fr: _note_navigation(fr, page, redirects))
            page.on("crash", lambda _p: crashed.__setitem__("v", True))

            t_nav = time.monotonic()
            try:
                resp = await asyncio.wait_for(
                    page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS),
                    HARD_TIMEOUT_MS / 1000)
            except Exception as e:
                out["error"] = _text(f"{type(e).__name__}: {e}", 300)
                resp = None
                if crashed["v"] or _is_browser_failure(e):
                    out["fetcher_error"] = True
            out["timings"]["nav_ms"] = int((time.monotonic() - t_nav) * 1000)
            with contextlib.suppress(Exception):
                out["final_url"] = _text(str(page.url), 2000)
            if resp is not None:
                out["http_status"] = resp.status
                out["ok"] = True
            out["redirect_chain"] = [u for u in (_text(r, 2000) for r in redirects[:20]) if u]
            with contextlib.suppress(Exception):
                out["title"] = _text(await page.title(), 500)
            with contextlib.suppress(Exception):
                out["html"] = _html(await page.content())
            with contextlib.suppress(Exception):
                text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                out["text_excerpt"] = _text(text, TEXT_CAP) or ""
            out["forms"] = await _all_forms(page)
            try:
                shot = await page.screenshot(type="webp", quality=WEBP_QUALITY, full_page=False,
                                             clip=_clip(page), timeout=PAGE_TIMEOUT_MS)
                out["screenshot_webp_b64"] = base64.b64encode(shot).decode("ascii")
            except Exception as e:
                log.info("screenshot failed: %s", type(e).__name__)
            # A JS redirect after DOMContentLoaded can move the page while forms and the screenshot are
            # collected. Record where the browser is NOW, so the forms are judged against the address they
            # actually came from (an off-domain address never counts as evidence for this domain).
            with contextlib.suppress(Exception):
                now_url = _text(str(page.url), 2000)
                if now_url and now_url != out["final_url"]:
                    if out["final_url"] and len(out["redirect_chain"]) < 20:
                        out["redirect_chain"].append(out["final_url"])
                    out["final_url"] = now_url
                    out["url_changed_during_capture"] = True
            if crashed["v"]:
                out["fetcher_error"] = True
                out["error"] = out["error"] or "page crashed"
        except Exception as e:
            out["error"] = out["error"] or _text(f"{type(e).__name__}: {e}", 300)
            out["fetcher_error"] = True
            await self.recycle()
        finally:
            if context is not None:
                try:
                    await asyncio.wait_for(context.close(), 15)
                except Exception:
                    await self.recycle()
            await self.release(browser)
        out["timings"]["total_ms"] = int((time.monotonic() - t0) * 1000)
        return out


def _is_browser_failure(e: Exception) -> bool:
    m = str(e).lower()
    return any(s in m for s in ("target crashed", "page crashed", "browser has been closed",
                                "target page, context or browser has been closed", "browser closed",
                                "connection closed"))


async def _all_forms(page) -> list:
    forms: list = []
    budget = {"forms": MAX_FORMS, "inputs": MAX_INPUTS_TOTAL}
    try:
        frames = list(page.frames)[:MAX_FRAMES]
    except Exception:
        frames = []
    for fr in frames:
        if budget["forms"] <= 0:
            break
        try:
            got = await asyncio.wait_for(fr.evaluate(_FORMS_JS), 5)
        except Exception:
            continue
        # The script runs in the page's world, so its output is page-controlled: rebuild it.
        forms.extend(_clean_forms(got, budget))
    return forms


async def _dismiss(dialog) -> None:
    with contextlib.suppress(Exception):
        await dialog.dismiss()


def _note_redirect(resp, page, redirects: list[str]) -> None:
    try:
        if resp.request.frame == page.main_frame and 300 <= resp.status < 400 and len(redirects) < 20:
            redirects.append(resp.url[:2000])
    except Exception:
        pass


def _note_navigation(frame, page, redirects: list[str]) -> None:
    """Main-frame navigations catch JavaScript / meta-refresh redirects that are not HTTP 3xx."""
    try:
        if frame == page.main_frame and len(redirects) < 20:
            u = str(frame.url)[:2000]
            if u and u != "about:blank" and (not redirects or redirects[-1] != u):
                redirects.append(u)
    except Exception:
        pass


def _clip(page) -> dict:
    try:
        vp = page.viewport_size or {"width": 1280, "height": 800}
    except Exception:
        vp = {"width": 1280, "height": 800}
    return {"x": 0, "y": 0, "width": vp["width"], "height": min(vp["height"], SCREENSHOT_MAX_HEIGHT)}


# ---- app ------------------------------------------------------------------------------------------

pool = BrowserPool()
egress = Egress()


async def _watchdog() -> None:
    while True:
        await asyncio.sleep(60)
        with contextlib.suppress(Exception):
            await egress.get(force=True)
        if egress.watchdog_expired():
            log.error("gluetun control server unreachable for over %ss: this container is probably in a "
                      "stale network namespace after a gluetun restart. Exiting so Docker restarts it.",
                      WATCHDOG_S)
            os._exit(70)


@contextlib.asynccontextmanager
async def lifespan(_app):
    if len(FETCHER_TOKEN) < MIN_SECRET_LEN:
        log.error("FETCHER_TOKEN is missing or shorter than %d chars: the API rejects every request",
                  MIN_SECRET_LEN)
    await pool.start()
    task = asyncio.get_running_loop().create_task(_watchdog())
    try:
        yield
    finally:
        task.cancel()
        await pool.stop()


app = FastAPI(title="CyberCheck fetcher", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def _auth(request: Request, authorization: str | None) -> None:
    # Page JavaScript inside the shared namespace always sends an Origin on cross-origin requests;
    # the worker never does.
    if request.headers.get("origin") is not None:
        raise HTTPException(status_code=403, detail="origin not allowed")
    expected = f"Bearer {FETCHER_TOKEN}".encode()
    given = (authorization or "").encode("utf-8", "replace")
    if len(FETCHER_TOKEN) < MIN_SECRET_LEN or not hmac.compare_digest(given, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


def _failed(error: str) -> dict:
    return {"ok": False, "error": error, "fetcher_error": True, "final_url": None, "http_status": None,
            "redirect_chain": [], "title": None, "html": None, "text_excerpt": None,
            "screenshot_webp_b64": None, "forms": [], "timings": {}}


@app.get("/health")
async def health(request: Request, authorization: str | None = Header(default=None)):
    _auth(request, authorization)
    e = await egress.get()
    # After a Chromium launch failure, try again here: the worker stops fetching while this is 503,
    # so without it the failure count would never reach the restart (LAUNCH_FAIL_EXIT).
    browser_ok = pool.launch_failures == 0 or await pool.ensure()
    ok = bool(e["ok"]) and browser_ok
    error = e.get("error") or (None if browser_ok else _text(f"browser failed to start: {pool.launch_error}", 300))
    return JSONResponse({"ok": ok, "vpn_running": bool(e["vpn_running"]),
                         "egress_ip": e["egress_ip"], "egress_country": e["egress_country"],
                         "browser_ok": browser_ok, "error": error},
                        status_code=200 if ok else 503)


@app.post("/fetch")
async def fetch(request: Request, authorization: str | None = Header(default=None)):
    _auth(request, authorization)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid body")
    url = body.get("url")
    profile = body.get("profile", "mobile")
    if profile not in ("mobile", "desktop"):
        profile = "mobile"
    if not isinstance(url, str) or len(url) > 2048:
        raise HTTPException(status_code=400, detail="bad url")
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise HTTPException(status_code=400, detail="bad url")
    if parts.scheme not in ("http", "https") or not host:
        raise HTTPException(status_code=400, detail="only http/https")
    if _blocked_host(host):
        raise HTTPException(status_code=400, detail="target not allowed")

    e = await egress.get()
    if not e["ok"]:
        return JSONResponse({"ok": False, "error": "fetcher failing closed: " + str(e.get("error") or "egress not verified"),
                             "vpn_running": e["vpn_running"], "egress_country": e["egress_country"]},
                            status_code=503)
    try:
        result = await pool.fetch(url, profile)
    except BrowserUnavailable as e2:
        # Not a result about the page: 503 makes the worker change nothing and stop its run.
        return JSONResponse({"ok": False, "error": _text(f"browser unavailable: {e2}", 300),
                             "fetcher_error": True, "browser_ok": False}, status_code=503)
    except asyncio.TimeoutError:
        await pool.recycle()
        result = _failed("hard timeout")
    except Exception as e2:
        await pool.recycle()
        result = _failed(_text(f"{type(e2).__name__}: {e2}", 300) or "internal error")
    if not result.get("ok") and not result.get("fetcher_error"):
        # The navigation failed. The egress was checked from a 60 s cache before a fetch that can take
        # ~50 s, so re-check it now: if the VPN dropped or changed exit meanwhile, the failure says
        # nothing about the page and must not count towards live_state 'down'.
        e2 = await egress.get(force=True)
        if not e2["ok"] or e2["egress_ip"] != e["egress_ip"]:
            return JSONResponse({"ok": False, "error": "fetcher failing closed: egress lost during the fetch ("
                                 + str(e2.get("error") or "egress IP changed") + ")",
                                 "vpn_running": e2["vpn_running"], "egress_country": e2["egress_country"]},
                                status_code=503)
    result["egress_ip"] = e["egress_ip"]
    result["egress_country"] = _text(e["egress_country"], 64)
    result["profile"] = profile
    result["url"] = _text(url, 2048)
    return _respond(result)


def _respond(result: dict) -> Response:
    """Encode a /fetch result. Never a 500 and never over MAX_RESPONSE_BYTES: an oversized result loses
    its HTML first; one that still cannot be sent becomes a fetcher_error result."""
    try:
        body = _render(result)
        if len(body) > MAX_RESPONSE_BYTES and result.get("html"):
            log.warning("fetch result is %d bytes: dropping its HTML", len(body))
            result = {**result, "html": None}
            body = _render(result)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"fetch result is {len(body)} bytes")
    except (TypeError, ValueError, RecursionError) as e:      # NaN, lone surrogate, odd type, too large
        log.warning("unencodable fetch result: %s: %s", type(e).__name__, str(e)[:200])
        failed = _failed("unencodable result")
        for k in ("egress_ip", "egress_country", "profile", "url"):
            failed[k] = _text(result.get(k), 2048)
        body = _render(failed)
    return Response(content=body, media_type="application/json")
