"""ICANN CZDS feed: daily gTLD zone files -> newly delegated names -> brand scoring -> domains.

Runs as the worker job "czds" (cybercheck/jobs/czds.py), hourly. Rules and sources: docs/research/czds.md;
operator guide: docs/CZDS.md.

Per configured TLD and day:
  1. HEAD the zone at most once per 24 h. If Last-Modified and Content-Length are those of the file already
     processed, wait for the next day.
  2. GET it at most once per 24 h (CZDS T&C s1.8), streamed to data_dir/czds/<tld>/zone.gz.part with a size
     cap and a free-disk check. Downloads happen one zone at a time, inside a daily window that opens after
     ICANN's collection (00:00-06:00 UTC).
  3. In a worker thread: read the gzip master file as a stream, check it (gzip CRC and length, the apex SOA
     first and last, a newer SOA serial, a plausible name count), keep the owner names of NS records directly
     under the TLD, sort them uniquely with bounded memory (`sort -u -S` with LC_ALL=C, or a Python external
     sort), merge against the previous list to find the new names, and score each new name.
  4. Store hits with store_hit(source='czds'), keep only the current and the previous list, delete the raw
     download. The first successful run for a TLD only stores the baseline list.

Zone data is licensed (CZDS T&C s1.4, s1.6, s1.7): it stays in data_dir/czds (mode 700), only two lists per
TLD are kept, and nothing from it is published or served by the dashboard. Postgres only gets per-zone
counters (czds_zones, czds_runs) and the scored hits, which then go through the normal pipeline; only
CyberCheck's own verdicts reach the public blocklist.

Settings: CZDS_USERNAME, CZDS_PASSWORD, CZDS_TLDS (config.py), plus these, read here:
  CZDS_WINDOW_START          UTC time the daily download window opens (default 06:30)
  CZDS_WINDOW_HOURS          length of the window in hours (8)
  CZDS_SORT_BUFFER           memory for `sort -S` (128M)
  CZDS_MAX_ZONE_GB           refuse zone files larger than this (8)
  CZDS_MIN_FREE_GB           disk that must stay free after a download (3)
  CZDS_MAX_COUNT_CHANGE      reject a file whose name count moved more than this fraction (0.2)
  CZDS_MAX_NEW_NAMES         above this many new names a day, store a new baseline instead (1000000)
  CZDS_MAX_HITS_PER_ZONE     keep at most this many hits per zone and day, best scores first (2000)
  CZDS_STRICT_SOA            require the same SOA record at the start and end of the file (true). A zone whose
                             files never close with the SOA is accepted after TOLERATE_AFTER days in a row, and so
                             is a registry that resets its SOA serial.
  CZDS_KEEP_UNCONFIGURED_DAYS  delete lists of TLDs removed from CZDS_TLDS after this many days (7); the same
                             applies to every list once the credentials are removed (cleanup_inactive)
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import dataclasses
import fcntl
import functools
import gzip
import heapq
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Iterator
from urllib.parse import urljoin, urlsplit

import httpx

from . import db
from .config import settings
from .scoring import Hit, default_watchlist
from .store import store_hit

log = logging.getLogger("cybercheck.czds")

UTC = timezone.utc

AUTH_URL = "https://account-api.icann.org/api/authenticate"
LINKS_URL = "https://czds-api.icann.org/czds/downloads/links"
# The spec requires a real "<product>/<version> <comment>" User-Agent (else: maintenance page).
USER_AGENT = "CyberCheck-czds/1.0 (anti-phishing research; newly delegated domain monitoring)"

MIN_GAP = timedelta(hours=24, minutes=5)       # between two GETs (and two HEADs) of one zone: T&C s1.8 + margin
TOKEN_MAX_LIFE = timedelta(hours=24)           # spec v1.0.9: tokens expire 24 h after creation
TOKEN_MARGIN = timedelta(minutes=15)
LOGIN_WINDOW_S = 300.0
LOGIN_MAX_PER_WINDOW = 3                       # ICANN allows 8 per 5 minutes per IP; stay well under
LOGIN_FAIL_BACKOFF = timedelta(hours=6)        # after HTTP 401 (wrong username/password); a restart retries
LOGIN_429_BACKOFF = timedelta(minutes=6)       # rest of ICANN's 5-minute cycle
LINKS_MAX_AGE = timedelta(hours=12)            # notice new approvals and revocations twice a day
LINKS_MAX_AGE_BEFORE_DOWNLOAD = timedelta(hours=2)
RETRY_BACKOFF = (timedelta(hours=1), timedelta(hours=2), timedelta(hours=4))
TERMS_RETRY = timedelta(hours=6)               # after HTTP 409 (new T&C to accept in the portal)
MAX_WAIT_S = 3500.0                            # a run may wait this long for the next zone to come due
MAX_REDIRECTS = 3
MAX_LINKS = 5000
MAX_JSON_BYTES = 4 << 20
MIN_ZONE_BYTES = 200                           # known failures: 20-byte and 39-byte files
WRITE_BUF = 4 << 20
DISK_CHECK_EVERY = 256 << 20
DISK_ABORT_FREE = 1 << 30
CHUNK_NAMES = 500_000                          # Python external sort: names per sorted chunk file
MERGE_FANIN = 64
RUNS_KEEP_DAYS = 120
MAX_PROCESS_ATTEMPTS = 2
COUNT_CHECK_MIN = 1000                         # the count check applies from this many names
TOLERATE_AFTER = 2                             # same rejection (old serial / no closing SOA) this many days in a row
MAX_TOTAL_WAIT_S = 3500.0                      # a run sleeps at most this long in total waiting for zones
MAX_LINE = 1 << 20                             # longest zone file line read (RRSIG/TXT lines are a few KB at most)
SCAN_DISK_CHECK_LINES = 1 << 21                # check free disk this often while parsing (sort spills to disk)

# Files in data_dir/czds/<tld>/
PART, RAW = "zone.gz.part", "zone.gz"
CUR_LIST, PREV_LIST, NEW_LIST = "names.gz", "names.prev.gz", "names.new.gz"
TMP_DIR = "tmp"
LOCK_FILE = ".lock"

_TLD_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LABEL_B = re.compile(rb"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SIZE_RE = re.compile(r"[1-9][0-9]{0,5}[KMG]?\Z")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{20,8192}\Z")
_CLASSES = frozenset((b"in", b"ch", b"hs", b"cs"))


def utcnow() -> datetime:
    return datetime.now(UTC)


async def _sleep(seconds: float) -> None:   # replaced in tests
    await asyncio.sleep(seconds)


def valid_tld(tld: str) -> bool:
    return bool(isinstance(tld, str) and _TLD_RE.match(tld) and not tld.isdigit())


def clean_text(value, limit: int = 300) -> str | None:
    if value is None:
        return None
    v = _CTRL_RE.sub(" ", str(value)).strip()
    return v[:limit] or None


# ---------------------------------------------------------------------------------------------------
# configuration

@dataclass(frozen=True)
class CzdsConfig:
    username: str = ""
    password: str = field(default="", repr=False)
    tlds: tuple[str, ...] = ()
    bad_tlds: tuple[str, ...] = ()
    data_dir: Path = Path("data") / "czds"
    window_start_min: int = 6 * 60 + 30
    window_hours: float = 8.0
    sort_buffer: str = "128M"
    max_zone_bytes: int = 8 << 30
    min_free_bytes: int = 3 << 30
    max_count_change: float = 0.2
    max_new_names: int = 1_000_000
    max_hits: int = 2000
    strict_soa: bool = True
    keep_unconfigured_days: int = 7

    @property
    def has_credentials(self) -> bool:
        return bool(self.username and self.password)

    @property
    def window_label(self) -> str:
        h, m = divmod(self.window_start_min, 60)
        end = (self.window_start_min + int(self.window_hours * 60)) % (24 * 60)
        return f"{h:02d}:{m:02d}-{end // 60:02d}:{end % 60:02d} UTC"


def normalise_tlds(raw: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    good: list[str] = []
    bad: list[str] = []
    for t in raw or ():
        t = str(t).strip().lower().strip(".")
        if not t:
            continue
        if not t.isascii():
            try:
                t = t.encode("idna").decode("ascii")
            except UnicodeError:
                bad.append(clean_text(t, 64) or "?")
                continue
        if valid_tld(t):
            if t not in good:
                good.append(t)
        else:
            bad.append(clean_text(t, 64) or "?")
    return tuple(good), tuple(bad)


def load_config(s=None) -> CzdsConfig:
    s = s or settings()

    def env(name: str) -> str:
        return os.environ.get(name, "").strip()

    def num(name: str, default, cast, lo, hi):
        v = env(name)
        try:
            x = cast(v) if v else default
        except ValueError:
            log.warning("ignoring bad %s=%r", name, v)
            x = default
        return min(hi, max(lo, x))

    start = 6 * 60 + 30
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", env("CZDS_WINDOW_START"))
    if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
        start = int(m.group(1)) * 60 + int(m.group(2))
    elif env("CZDS_WINDOW_START"):
        log.warning("ignoring bad CZDS_WINDOW_START (use HH:MM, UTC)")
    buf = env("CZDS_SORT_BUFFER").upper() or "128M"
    if not _SIZE_RE.match(buf):
        log.warning("ignoring bad CZDS_SORT_BUFFER=%r", buf)
        buf = "128M"
    strict = env("CZDS_STRICT_SOA").lower()
    tlds, bad = normalise_tlds(getattr(s, "czds_tlds", ()) or ())
    return CzdsConfig(
        username=(getattr(s, "czds_username", "") or "").strip(),
        password=getattr(s, "czds_password", "") or "",
        tlds=tlds, bad_tlds=bad,
        data_dir=Path(s.data_dir) / "czds",
        window_start_min=start,
        window_hours=num("CZDS_WINDOW_HOURS", 8.0, float, 1.0, 20.0),
        sort_buffer=buf,
        max_zone_bytes=int(num("CZDS_MAX_ZONE_GB", 8.0, float, 0.01, 64.0) * (1 << 30)),
        min_free_bytes=int(num("CZDS_MIN_FREE_GB", 3.0, float, 0.5, 1000.0) * (1 << 30)),
        max_count_change=num("CZDS_MAX_COUNT_CHANGE", 0.2, float, 0.01, 10.0),
        max_new_names=num("CZDS_MAX_NEW_NAMES", 1_000_000, int, 1, 50_000_000),
        max_hits=num("CZDS_MAX_HITS_PER_ZONE", 2000, int, 1, 100_000),
        strict_soa=strict not in ("0", "false", "no", "off"),
        keep_unconfigured_days=num("CZDS_KEEP_UNCONFIGURED_DAYS", 7, int, 1, 3650),
    )


# ---------------------------------------------------------------------------------------------------
# schedule: at most one GET (and one HEAD) per zone per 24 h, inside the daily window

def window_bounds(day: date, cfg: CzdsConfig) -> tuple[datetime, datetime]:
    start = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(minutes=cfg.window_start_min)
    return start, start + timedelta(hours=cfg.window_hours)


def next_slot(earliest: datetime, cfg: CzdsConfig) -> datetime:
    """First moment >= earliest that lies inside a daily download window."""
    day = earliest.astimezone(UTC).date() - timedelta(days=1)
    for _ in range(3):
        start, end = window_bounds(day, cfg)
        if earliest < end:
            return max(earliest, start)
        day += timedelta(days=1)
    raise AssertionError("unreachable")


def zone_due(z: dict, now: datetime, cfg: CzdsConfig, pending: bool = False) -> datetime | None:
    """When this zone may next be fetched (>= now), or None if it is not configured and approved.
    pending: a downloaded file is waiting to be processed (no network needed)."""
    if not (z.get("configured") and z.get("approved")):
        return None
    if pending:
        return now
    gate = now
    if z.get("last_download"):
        gate = max(gate, z["last_download"] + MIN_GAP)
    if z.get("retry_at"):
        gate = max(gate, z["retry_at"])
    return next_slot(gate, cfg)


def head_allowed(z: dict, now: datetime) -> bool:
    return not z.get("last_head") or now >= z["last_head"] + MIN_GAP


def retry_delay(fail_count: int) -> timedelta:
    return RETRY_BACKOFF[min(max(fail_count, 1), len(RETRY_BACKOFF)) - 1]


# ---------------------------------------------------------------------------------------------------
# CZDS API client

class CzdsError(Exception):
    pass


class CzdsAuthError(CzdsError):
    pass


class CzdsHttpError(CzdsError):
    def __init__(self, status: int, what: str):
        self.status = status
        super().__init__(f"{what}: HTTP {status}")


class LowDisk(CzdsError):
    pass


class ZoneInvalid(CzdsError):
    """The file failed a check. Yesterday's list stays; the next try is the next day.
    reason: '' or one of 'old_serial', 'end_soa_missing', 'end_soa_mismatch', 'count' (used for the
    per-zone tolerance of a registry that resets its serial or never closes its file with the SOA)."""

    def __init__(self, msg: str, total: int | None = None, reason: str = ""):
        self.total = total
        self.reason = reason
        super().__init__(msg)


class ZoneUnchanged(CzdsError):
    """Same SOA serial as the list already stored (the same file served again)."""


@dataclass
class TokenCache:
    """Kept in the job's ctx.state between runs; never written to disk or the database."""
    token: str | None = field(default=None, repr=False)
    expires_at: datetime | None = None
    logins: deque = field(default_factory=deque)
    blocked_until: datetime | None = None
    blocked_reason: str = ""

    def invalidate(self) -> None:
        self.token = None
        self.expires_at = None


@dataclass
class HeadInfo:
    status: int
    length: int | None
    last_modified: str | None
    at: datetime


@dataclass
class DownloadInfo:
    bytes: int
    content_length: int | None
    last_modified: str | None
    started: datetime


def jwt_expiry(token: str) -> datetime | None:
    """The `exp` claim of a JWT (not verified: only used to know when to log in again)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        exp = data.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            return None
        return datetime.fromtimestamp(exp, UTC)
    except (IndexError, ValueError, TypeError, AttributeError, OverflowError, OSError, binascii.Error):
        return None


def _allowed_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and port in (None, 443) and (host == "icann.org" or host.endswith(".icann.org"))


def zone_url_tld(url) -> str | None:
    """TLD of a download URL from /czds/downloads/links, or None if the URL is not one we would fetch."""
    if not isinstance(url, str) or len(url) > 300 or not _allowed_url(url):
        return None
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        return None
    name = parts.path.rsplit("/", 1)[-1]
    if not name.endswith(".zone"):
        return None
    tld = name[:-5].lower()
    return tld if valid_tld(tld) else None


def parse_links(data) -> dict[str, str]:
    if not isinstance(data, list):
        raise CzdsError("zone list is not a JSON array")
    out: dict[str, str] = {}
    for url in data[:MAX_LINKS]:
        tld = zone_url_tld(url)
        if tld:
            out[tld] = url
        else:
            log.warning("ignoring unexpected entry in the CZDS zone list: %r", clean_text(url, 120))
    return out


def _int_header(resp: httpx.Response, name: str) -> int | None:
    v = resp.headers.get(name, "").strip()
    return int(v) if v.isdigit() and len(v) < 20 else None


async def _read_capped(resp: httpx.Response, cap: int) -> bytes:
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        buf += chunk
        if len(buf) > cap:
            raise CzdsError("response too large")
    return bytes(buf)


def make_http() -> httpx.AsyncClient:
    # IPv4 only: the CZDS spec documents IPv4 transport (the hosts now also publish AAAA records).
    return httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(local_address="0.0.0.0"),
        timeout=httpx.Timeout(60.0, read=300.0),
        headers={"User-Agent": USER_AGENT}, follow_redirects=False, trust_env=False)


class CzdsApi:
    def __init__(self, cfg: CzdsConfig, tokens: TokenCache, http: httpx.AsyncClient):
        self.cfg, self.tokens, self.http = cfg, tokens, http

    async def token(self) -> str:
        t = self.tokens
        if t.token and t.expires_at and utcnow() < t.expires_at:
            return t.token
        return await self._login()

    async def _login(self) -> str:
        t = self.tokens
        now = utcnow()
        if t.blocked_until and now < t.blocked_until:
            raise CzdsAuthError(f"{t.blocked_reason}; next login attempt after {t.blocked_until:%H:%M} UTC")
        mono = time.monotonic()
        while t.logins and mono - t.logins[0] > LOGIN_WINDOW_S:
            t.logins.popleft()
        if len(t.logins) >= LOGIN_MAX_PER_WINDOW:
            raise CzdsAuthError("too many CZDS logins in 5 minutes (CyberCheck's own limit); trying again later")
        t.logins.append(mono)
        req = self.http.build_request("POST", AUTH_URL, headers={"Accept": "application/json"},
                                      json={"username": self.cfg.username, "password": self.cfg.password})
        try:
            resp = await self.http.send(req, stream=True)
        except httpx.HTTPError as e:
            raise CzdsAuthError(f"CZDS login failed: {type(e).__name__}") from None
        try:
            if resp.status_code == 401:
                t.blocked_until, t.blocked_reason = now + LOGIN_FAIL_BACKOFF, "CZDS rejected the username or password (HTTP 401)"
                raise CzdsAuthError(t.blocked_reason)
            if resp.status_code == 429:
                t.blocked_until, t.blocked_reason = now + LOGIN_429_BACKOFF, "CZDS login rate limit reached (HTTP 429)"
                raise CzdsAuthError(t.blocked_reason)
            if resp.status_code != 200:
                raise CzdsAuthError(f"CZDS login failed: HTTP {resp.status_code}")
            body = await _read_capped(resp, 64 << 10)
        except httpx.HTTPError as e:
            raise CzdsAuthError(f"CZDS login failed: {type(e).__name__}") from None
        finally:
            await resp.aclose()
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        token = data.get("accessToken") if isinstance(data, dict) else None
        if not isinstance(token, str) or not _TOKEN_RE.match(token):
            raise CzdsAuthError("CZDS login answer had no usable accessToken")
        expires = now + TOKEN_MAX_LIFE
        exp = jwt_expiry(token)
        if exp is not None:
            expires = min(expires, exp)
        t.token, t.expires_at = token, max(expires - TOKEN_MARGIN, now + timedelta(minutes=1))
        t.blocked_until, t.blocked_reason = None, ""
        log.info("logged in to CZDS; token valid until %s", t.expires_at.isoformat())
        return token

    async def _send(self, method: str, url: str, *, stream: bool = False, accept: str = "*/*") -> httpx.Response:
        resp = None
        for attempt in range(2):
            token = await self.token()
            resp = await self._follow(method, url, token, stream, accept)
            if resp.status_code == 401 and attempt == 0:
                await resp.aclose()
                self.tokens.invalidate()      # expired or revoked token: log in once more
                continue
            return resp
        return resp

    async def _follow(self, method: str, url: str, token: str, stream: bool, accept: str) -> httpx.Response:
        for _ in range(MAX_REDIRECTS + 1):
            if not _allowed_url(url):
                raise CzdsError(f"refusing to contact {clean_text(urlsplit(url).hostname, 80) or '?'} (not an ICANN host)")
            # identity: the zone file is already gzip; the raw bytes are written to disk as they arrive
            req = self.http.build_request(method, url, headers={"Authorization": f"Bearer {token}", "Accept": accept,
                                                                "Accept-Encoding": "identity"})
            resp = await self.http.send(req, stream=stream)
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                await resp.aclose()
                url = urljoin(url, resp.headers["location"])
                continue
            return resp
        raise CzdsError("too many redirects")

    async def links(self) -> dict[str, str]:
        resp = await self._send("GET", LINKS_URL, stream=True, accept="application/json")
        try:
            if resp.status_code != 200:
                raise CzdsHttpError(resp.status_code, "listing approved zones")
            body = await _read_capped(resp, MAX_JSON_BYTES)
        finally:
            await resp.aclose()
        try:
            data = json.loads(body)
        except ValueError:
            raise CzdsError("zone list is not JSON") from None
        return parse_links(data)

    async def head(self, url: str) -> HeadInfo:
        at = utcnow()
        resp = await self._send("HEAD", url)
        await resp.aclose()
        return HeadInfo(status=resp.status_code, length=_int_header(resp, "content-length"),
                        last_modified=clean_text(resp.headers.get("last-modified"), 64), at=at)

    async def download(self, url: str, dest: Path, *, max_bytes: int,
                       on_start: Callable[[datetime], Awaitable[None]]) -> DownloadInfo:
        started = utcnow()
        resp = await self._send("GET", url, stream=True)
        try:
            if resp.status_code != 200:
                raise CzdsHttpError(resp.status_code, "zone download")
            await on_start(started)
            length = _int_header(resp, "content-length")
            if length is not None and length > max_bytes:
                raise ZoneInvalid(f"zone file is {length} bytes, over CZDS_MAX_ZONE_GB")
            written = since_check = 0
            with open(dest, "wb") as f:
                buf = bytearray()
                async for chunk in resp.aiter_raw():
                    written += len(chunk)
                    if written > max_bytes:
                        raise ZoneInvalid("zone file is over CZDS_MAX_ZONE_GB; download stopped")
                    buf += chunk
                    if len(buf) >= WRITE_BUF:
                        data = bytes(buf)
                        buf.clear()
                        await asyncio.to_thread(f.write, data)
                        since_check += len(data)
                        if since_check >= DISK_CHECK_EVERY:
                            since_check = 0
                            if shutil.disk_usage(dest.parent).free < DISK_ABORT_FREE:
                                raise LowDisk("disk nearly full; download stopped")
                if buf:
                    await asyncio.to_thread(f.write, bytes(buf))
            return DownloadInfo(bytes=written, content_length=length,
                                last_modified=clean_text(resp.headers.get("last-modified"), 64), started=started)
        finally:
            await resp.aclose()


# ---------------------------------------------------------------------------------------------------
# zone file parsing (synchronous; runs in a worker thread)

def serial_newer(new: int, old: int) -> bool:
    """RFC 1982 serial number arithmetic."""
    d = (new - old) % (1 << 32)
    return 0 < d < (1 << 31)


def _norm_record(line: bytes) -> bytes:
    return b" ".join(line.split()).lower()


def _second_level(owner: bytes, suffix: bytes) -> bytes | None:
    """'example.top.' -> b'example' for suffix b'.top.'; None for the apex, deeper names and non-LDH labels."""
    owner = owner.lower()
    if not owner.endswith(b"."):
        owner += b"."
    if not owner.endswith(suffix):
        return None
    label = owner[: -len(suffix)]
    if not label or b"." in label or not _LABEL_B.match(label):
        return None
    return label


def _rr_type(parts: list[bytes]) -> bytes | None:
    """Type field of a record split on whitespace, with TTL and class in any order or missing."""
    for tok in parts[1:4]:
        t = tok.lower()
        if t.isdigit() or t in _CLASSES:
            continue
        return t
    return None


@dataclass
class ZoneScan:
    tld: str
    serial: int | None = None
    lines: int = 0
    ns_records: int = 0
    names: int = 0          # NS owner names passed on (consecutive duplicates removed)
    skipped: int = 0        # NS owners that are not second-level LDH names (deeper delegations, junk)
    strict: bool = True     # file follows the Spec 4 one-tab layout
    end_soa: str = ""       # same | missing | mismatch: the last record compared with the opening SOA


def _check_soa(line: bytes, apex: bytes, stats: ZoneScan) -> None:
    fields = line.rstrip(b"\r\n").split(b"\t", 4)      # RDATA may use spaces or tabs between its own fields
    if len(fields) == 5 and fields[3] == b"soa":
        owner, rdata = fields[0], fields[4]
    else:
        stats.strict = False
        parts = line.split(None, 4)
        if len(parts) < 3 or _rr_type(parts) != b"soa":
            raise ZoneInvalid("the file does not start with the zone's SOA record (failed or empty transfer?)")
        owner = parts[0]
        words = line.split()
        idx = next(i for i in range(1, 4) if words[i].lower() == b"soa")
        rdata = b" ".join(words[idx + 1:])
    owner = owner.lower()
    if not owner.endswith(b"."):
        owner += b"."
    if owner != apex:
        raise ZoneInvalid("the SOA record is for another zone")
    tokens = rdata.split()
    if len(tokens) >= 3 and tokens[2].isdigit() and int(tokens[2]) < (1 << 32):
        stats.serial = int(tokens[2])


def _end_soa(first: bytes, last: bytes) -> str:
    if _norm_record(last) == _norm_record(first):
        return "same"
    parts = last.split(None, 4)
    return "mismatch" if len(parts) >= 3 and _rr_type(parts) == b"soa" else "missing"


def scan_zone(path: Path, tld: str, stats: ZoneScan, *, prev_serial: int | None = None,
              strict_soa: bool = True, allow_older_serial: bool = False,
              allow_missing_end_soa: bool = False) -> Iterator[bytes]:
    """Stream the gzip master file and yield the label of every NS owner name directly under the TLD
    (file order, consecutive duplicates removed). Raises ZoneInvalid / ZoneUnchanged.

    The checks finish before this generator is exhausted, and both sort paths read their whole input before
    they return the first name, so a rejected file never reaches the diff or the scorer."""
    with open(path, "rb") as f:
        if f.read(2) != b"\x1f\x8b":
            raise ZoneInvalid("not a gzip file (error page or failed transfer?)")
    apex = tld.encode("ascii") + b"."
    suffix = b"." + apex
    n = ns = names = skipped = 0
    disk_dir = path.parent

    def too_long() -> ZoneInvalid:
        return ZoneInvalid(f"line {n} of the zone file is longer than {MAX_LINE >> 10} KB (not a zone file?)")

    def low_disk() -> None:
        if shutil.disk_usage(disk_dir).free < DISK_ABORT_FREE:
            raise LowDisk("disk nearly full while processing the zone; stopped")

    try:
        with gzip.open(path, "rb") as gz:
            # readline with a cap: a hostile or corrupt file with no newlines must not be read into memory whole
            lines = iter(functools.partial(gz.readline, MAX_LINE), b"")
            first = None
            for line in lines:
                n += 1
                if len(line) >= MAX_LINE and not line.endswith(b"\n"):
                    raise too_long()
                if line.strip():
                    first = line
                    break
            if first is None:
                raise ZoneInvalid("the zone file is empty")
            _check_soa(first, apex, stats)
            if prev_serial is not None and stats.serial is not None:
                if stats.serial == prev_serial:
                    raise ZoneUnchanged(f"SOA serial {stats.serial} is the one already processed")
                if not serial_newer(stats.serial, prev_serial) and not allow_older_serial:
                    raise ZoneInvalid(f"SOA serial {stats.serial} is older than the last one ({prev_serial})",
                                      reason="old_serial")
            last = first
            prev_owner = None
            if stats.strict:
                for n, line in enumerate(lines, n + 1):
                    if len(line) > 2:
                        last = line
                        if len(line) >= MAX_LINE and not line.endswith(b"\n"):
                            raise too_long()
                    if not n % SCAN_DISK_CHECK_LINES:
                        low_disk()
                    if b"\tns\t" not in line:
                        continue
                    p = line.split(b"\t", 4)
                    if len(p) < 5 or p[3] != b"ns":
                        continue
                    ns += 1
                    if p[0] == prev_owner:
                        continue
                    prev_owner = p[0]
                    label = _second_level(prev_owner, suffix)
                    if label is None:
                        skipped += 1
                        continue
                    names += 1
                    yield label
            else:
                for n, line in enumerate(lines, n + 1):
                    if len(line) > 2:
                        last = line
                        if len(line) >= MAX_LINE and not line.endswith(b"\n"):
                            raise too_long()
                    if not n % SCAN_DISK_CHECK_LINES:
                        low_disk()
                    p = line.split(None, 4)
                    if len(p) < 3 or _rr_type(p) != b"ns":
                        continue
                    ns += 1
                    if p[0] == prev_owner:
                        continue
                    prev_owner = p[0]
                    label = _second_level(prev_owner, suffix)
                    if label is None:
                        skipped += 1
                        continue
                    names += 1
                    yield label
            stats.end_soa = _end_soa(first, last)
            if strict_soa and stats.end_soa == "mismatch":
                raise ZoneInvalid("the file ends with a different SOA record than it starts with", reason="end_soa_mismatch")
            if strict_soa and stats.end_soa == "missing" and not allow_missing_end_soa:
                raise ZoneInvalid("the file does not end with the SOA record it starts with (truncated at the source?)",
                                  reason="end_soa_missing")
    except (OSError, EOFError, zlib.error) as e:     # gzip.BadGzipFile is an OSError
        raise ZoneInvalid(f"gzip data is corrupt or truncated ({type(e).__name__})") from None
    finally:
        stats.lines, stats.ns_records, stats.names, stats.skipped = n, ns, names, skipped


# ---------------------------------------------------------------------------------------------------
# bounded-memory sort -u

_sort_cmd_cache: dict[str, list[str] | None] = {}
_SORT_SAMPLE = [b"b", b"a-b", b"a", b"ab", b"a", b"xn--80ak6aa92e", b"0a", b"z-", b"a0", b"-", b"zz", b"a"]


def _sort_env(tmpdir: Path) -> dict[str, str]:
    return {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TMPDIR": str(tmpdir)}


def system_sort_cmd(tmpdir: Path) -> list[str] | None:
    """`sort -u` command (without -S/-T) that orders bytes exactly like Python, or None.
    Checked once per process with a sample, so a sort with other ordering or flags is never used."""
    if "cmd" in _sort_cmd_cache:
        return _sort_cmd_cache["cmd"]
    cmd = None
    exe = shutil.which("sort")
    if exe:
        nice = shutil.which("nice")
        prefix = [nice, "-n", "10"] if nice else []
        compress = shutil.which("zstd") or shutil.which("gzip")
        variants = ([[exe, "-u", "--parallel=2", f"--compress-program={compress}"]] if compress else []) + \
            [[exe, "-u", "--parallel=2"]]
        want = sorted(set(_SORT_SAMPLE))
        for v in variants:
            try:
                out = subprocess.run(prefix + v + ["-S", "1M", "-T", str(tmpdir)], input=b"\n".join(_SORT_SAMPLE) + b"\n",
                                     capture_output=True, env=_sort_env(tmpdir), timeout=20)
            except (OSError, subprocess.SubprocessError):
                continue
            if out.returncode == 0 and out.stdout.split(b"\n")[:-1] == want:
                cmd = prefix + v
                break
    if cmd is None:
        log.info("no suitable system sort; using the Python external sort")
    _sort_cmd_cache["cmd"] = cmd
    return cmd


def _system_sort_unique(labels: Iterable[bytes], tmpdir: Path, cmd: list[str], buffer: str) -> Iterator[bytes]:
    with tempfile.TemporaryFile(dir=tmpdir) as errf:
        proc = subprocess.Popen(cmd + ["-S", buffer, "-T", str(tmpdir)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=errf, env=_sort_env(tmpdir))
        try:
            batch: list[bytes] = []
            for label in labels:
                batch.append(label)
                if len(batch) >= 16384:
                    proc.stdin.write(b"\n".join(batch) + b"\n")
                    batch.clear()
            if batch:
                proc.stdin.write(b"\n".join(batch) + b"\n")
            proc.stdin.close()
            for line in proc.stdout:
                yield line.rstrip(b"\n")
            if proc.wait() != 0:
                errf.seek(0)
                raise RuntimeError(f"sort failed (exit {proc.returncode}): {clean_text(errf.read(300).decode('utf-8', 'replace'))}")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            for pipe in (proc.stdin, proc.stdout):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass


def _write_lines(path: Path, items: Iterable[bytes]) -> None:
    with open(path, "wb", buffering=1 << 16) as f:
        batch: list[bytes] = []
        for x in items:
            batch.append(x)
            if len(batch) >= 16384:
                f.write(b"\n".join(batch) + b"\n")
                batch.clear()
        if batch:
            f.write(b"\n".join(batch) + b"\n")


def _read_lines(path: Path) -> Iterator[bytes]:
    with open(path, "rb", buffering=1 << 16) as f:
        for line in f:
            yield line[:-1]


def _dedupe(items: Iterable[bytes]) -> Iterator[bytes]:
    last = None
    for x in items:
        if x != last:
            yield x
            last = x


def _python_sort_unique(labels: Iterable[bytes], tmpdir: Path) -> Iterator[bytes]:
    files: list[Path] = []
    buf: list[bytes] = []
    seq = 0
    for label in labels:
        buf.append(label)
        if len(buf) >= CHUNK_NAMES:
            path = tmpdir / f"chunk-{seq}"
            seq += 1
            _write_lines(path, sorted(set(buf)))
            files.append(path)
            buf = []
    if not files:
        yield from sorted(set(buf))
        return
    if buf:
        path = tmpdir / f"chunk-{seq}"
        seq += 1
        _write_lines(path, sorted(set(buf)))
        files.append(path)
    del buf
    while len(files) > MERGE_FANIN:          # merge in passes so few files are open at once
        merged = []
        for i in range(0, len(files), MERGE_FANIN):
            group = files[i:i + MERGE_FANIN]
            path = tmpdir / f"chunk-{seq}"
            seq += 1
            _write_lines(path, _dedupe(heapq.merge(*(_read_lines(p) for p in group))))
            for p in group:
                p.unlink()
            merged.append(path)
        files = merged
    yield from _dedupe(heapq.merge(*(_read_lines(p) for p in files)))


def sorted_unique(labels: Iterable[bytes], tmpdir: Path, buffer: str = "128M",
                  use_system: bool | None = None) -> Iterator[bytes]:
    """Byte-ordered unique names with bounded memory (spills to files in tmpdir)."""
    cmd = system_sort_cmd(tmpdir) if use_system is not False else None
    if cmd:
        return _system_sort_unique(labels, tmpdir, cmd, buffer)
    if use_system:
        raise RuntimeError("no suitable system sort")
    return _python_sort_unique(labels, tmpdir)


# ---------------------------------------------------------------------------------------------------
# streaming diff against the previous list

class ListCorrupt(Exception):
    pass


def read_list(path: Path) -> Iterator[bytes]:
    last = None
    with gzip.open(path, "rb") as f:
        for line in f:
            name = line.rstrip(b"\n")
            if last is not None and name <= last:
                raise ListCorrupt("names out of order")
            last = name
            yield name


@dataclass
class MergeStats:
    total: int = 0
    new: int = 0
    removed: int = 0
    prev_total: int = 0
    baseline: bool = False      # nothing to compare with (first run, or the previous list was unreadable)
    prev_error: str | None = None


def merge_lists(current: Iterable[bytes], prev_path: Path | None, out_path: Path,
                on_new: Callable[[bytes], None]) -> MergeStats:
    """Write the sorted unique `current` names to out_path (gzip) and call on_new for each name that is
    not in the previous list. One pass over both lists; memory does not grow with the zone."""
    st = MergeStats(baseline=prev_path is None)
    prev_it = read_list(prev_path) if prev_path else None
    p = None

    def advance() -> None:
        nonlocal p, prev_it
        try:
            p = next(prev_it, None)
        except (OSError, EOFError, zlib.error, ListCorrupt) as e:
            st.baseline, st.prev_error = True, f"previous list unreadable ({type(e).__name__})"
            prev_it, p = None, None
            return
        if p is not None:
            st.prev_total += 1

    if prev_it is not None:
        advance()
    last = None
    batch: list[bytes] = []
    with gzip.open(out_path, "wb", compresslevel=1) as out:
        for c in current:
            if last is not None and c <= last:
                raise RuntimeError("sorted name stream is out of order")
            last = c
            st.total += 1
            batch.append(c)
            if len(batch) >= 16384:
                out.write(b"\n".join(batch) + b"\n")
                batch.clear()
            if prev_it is None:
                continue
            while p is not None and p < c:
                st.removed += 1
                advance()
            if prev_it is None:
                continue
            if p == c:
                advance()
            else:
                st.new += 1
                on_new(c)
        if batch:
            out.write(b"\n".join(batch) + b"\n")
    while prev_it is not None and p is not None:
        st.removed += 1
        advance()
    if st.baseline:
        st.new = st.removed = 0
    return st


# ---------------------------------------------------------------------------------------------------
# one zone file -> new list + hits

@dataclass
class ZoneResult:
    tld: str
    serial: int | None
    total: int
    new: int | None
    removed: int | None
    baseline: bool
    rebaseline: bool
    hits: list[Hit]
    hits_dropped: int
    scored: int
    lines: int
    ns_records: int
    skipped: int
    seconds: float
    note: str | None = None
    end_soa: str = "same"


def list_to_compare(zdir: Path) -> Path | None:
    for name in (CUR_LIST, PREV_LIST):
        if (zdir / name).is_file():
            return zdir / name
    return None


def process_zone(raw: Path, zdir: Path, tld: str, *, cfg: CzdsConfig, watchlist, prev_serial: int | None = None,
                 prev_total: int | None = None, rejected_total: int | None = None,
                 allow_older_serial: bool = False, allow_missing_end_soa: bool = False,
                 use_system_sort: bool | None = None) -> ZoneResult:
    """Parse, check, sort and diff one downloaded zone file. Writes zdir/names.new.gz on success (the caller
    rotates it in after storing the hits). Raises ZoneInvalid / ZoneUnchanged.

    Memory stays bounded whatever the zone size: names stream from the gzip file into the external sort,
    the sorted stream is merged with the previous list one name at a time, and only the best
    cfg.max_hits hits are kept (a heap)."""
    t0 = time.monotonic()
    tmpdir = zdir / TMP_DIR
    shutil.rmtree(tmpdir, ignore_errors=True)
    tmpdir.mkdir(mode=0o700)
    new_list = zdir / NEW_LIST
    prev_path = list_to_compare(zdir)
    stats = ZoneScan(tld)
    heap: list = []
    scored = dropped = seq = 0

    def on_new(label: bytes) -> None:
        nonlocal scored, dropped, seq
        if scored >= cfg.max_new_names:
            return
        scored += 1
        hit = watchlist.score_hostname(label.decode("ascii") + "." + tld)
        if hit is None:
            return
        seq += 1
        item = (hit.score, -seq, hit)
        if len(heap) < cfg.max_hits:
            heapq.heappush(heap, item)
        else:
            dropped += 1
            heapq.heappushpop(heap, item)

    try:
        labels = scan_zone(raw, tld, stats, prev_serial=prev_serial if prev_path else None, strict_soa=cfg.strict_soa,
                           allow_older_serial=allow_older_serial, allow_missing_end_soa=allow_missing_end_soa)
        merged = merge_lists(sorted_unique(labels, tmpdir, cfg.sort_buffer, use_system_sort), prev_path, new_list, on_new)
        if merged.total == 0:
            raise ZoneInvalid("no delegated names found in the zone file")
        base = merged.prev_total if prev_path and not merged.baseline else prev_total
        note = merged.prev_error
        if base and base >= COUNT_CHECK_MIN:
            change = abs(merged.total - base) / base
            if change > cfg.max_count_change:
                if rejected_total and abs(merged.total - rejected_total) / rejected_total <= cfg.max_count_change:
                    note = f"name count moved {change:.0%} (accepted: same level as the previous day's rejected file)"
                else:
                    raise ZoneInvalid(f"{merged.total} names is {change:.0%} off the last count ({base}); "
                                      "kept the previous list", total=merged.total, reason="count")
    except BaseException:
        new_list.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    rebaseline = not merged.baseline and merged.new > cfg.max_new_names
    hits = [] if merged.baseline or rebaseline else [h for _, _, h in sorted(heap, reverse=True)]
    if rebaseline:
        note = (f"{merged.new} new names is more than CZDS_MAX_NEW_NAMES ({cfg.max_new_names}); "
                "stored as a new baseline without scoring")
    elif dropped and hits:
        note = f"{len(hits) + dropped} hits; kept the best {len(hits)} (CZDS_MAX_HITS_PER_ZONE)"
    if stats.end_soa == "missing" and cfg.strict_soa:
        note = "; ".join(x for x in (note, "accepted without a closing SOA record (this registry's files never have one)") if x)
    return ZoneResult(
        tld=tld, serial=stats.serial, total=merged.total,
        new=None if merged.baseline else merged.new, removed=None if merged.baseline else merged.removed,
        baseline=merged.baseline, rebaseline=rebaseline, hits=hits, hits_dropped=dropped if hits else 0,
        scored=0 if merged.baseline else scored, lines=stats.lines, ns_records=stats.ns_records,
        skipped=stats.skipped, seconds=round(time.monotonic() - t0, 1), note=note, end_soa=stats.end_soa)


def rotate_lists(zdir: Path) -> None:
    """names.new.gz becomes the current list; the old current list becomes the previous one."""
    if (zdir / CUR_LIST).is_file():
        os.replace(zdir / CUR_LIST, zdir / PREV_LIST)
    os.replace(zdir / NEW_LIST, zdir / CUR_LIST)


def cleanup_zone_dir(zdir: Path, keep_raw: bool = False) -> None:
    for name in (PART, NEW_LIST) + (() if keep_raw else (RAW,)):
        (zdir / name).unlink(missing_ok=True)
    shutil.rmtree(zdir / TMP_DIR, ignore_errors=True)


def zone_dir(cfg: CzdsConfig, tld: str) -> Path:
    if not valid_tld(tld):
        raise ValueError("bad tld")
    path = cfg.data_dir / tld
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def disk_usage(cfg: CzdsConfig) -> int:
    total = 0
    try:
        for root, _dirs, files in os.walk(cfg.data_dir):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def cleanup_unconfigured(cfg: CzdsConfig, now: datetime | None = None,
                         reason: str = "no longer in CZDS_TLDS") -> list[str]:
    """Delete name lists of TLDs that were removed from CZDS_TLDS (T&C s1.4: copy only what is needed)."""
    removed = []
    cutoff = (now or utcnow()).timestamp() - cfg.keep_unconfigured_days * 86400
    try:
        entries = list(cfg.data_dir.iterdir())
    except OSError:
        return removed
    for entry in entries:
        if entry.name in cfg.tlds or not valid_tld(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        try:   # before the clean-up below, whose deletions would reset the directory's mtime
            newest = max([entry.stat().st_mtime] + [p.stat().st_mtime for p in entry.iterdir()
                                                    if p.name not in (RAW, PART, TMP_DIR)])
        except OSError:
            continue
        cleanup_zone_dir(entry)        # raw downloads and temp files go at once; the lists after the grace period
        if newest < cutoff:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
            log.info("deleted CZDS lists of %s (%s)", entry.name, reason)
    return removed


# ---------------------------------------------------------------------------------------------------
# database (czds_zones, czds_runs; migrations/060_czds.sql)

ZONE_COLUMNS = frozenset({
    "configured", "approved", "approved_at", "download_url", "last_head", "last_download", "last_processed",
    "next_due", "retry_at", "total_names", "new_names", "removed_names", "hits", "new_hits", "soa_serial",
    "file_bytes", "last_modified", "status", "error", "fail_count", "duration_s", "state"})
RUN_COLUMNS = ("status", "soa_serial", "file_bytes", "total_names", "new_names", "removed_names", "hits",
               "new_hits", "duration_s", "error")


async def load_zones(conn) -> dict[str, dict]:
    rows = await (await conn.execute("SELECT * FROM czds_zones ORDER BY tld")).fetchall()
    # timestamptz values arrive in the session's time zone (a ZoneInfo). Adding MIN_GAP to one of those is wall-clock
    # arithmetic: across a DST change (TimeZone=Australia/Sydney, say) it would be 23 h 05 m of real time. UTC only.
    return {r["tld"]: {k: v.astimezone(UTC) if isinstance(v, datetime) else v for k, v in r.items()} for r in rows}


async def save_zone(conn, tld: str, fields: dict) -> None:
    bad = set(fields) - ZONE_COLUMNS
    if bad:
        raise ValueError(f"unknown czds_zones columns: {sorted(bad)}")
    cols = list(fields)
    values = [db.jsonb(fields[c]) if c == "state" else fields[c] for c in cols]
    # Column names come only from ZONE_COLUMNS above; values are parameters.
    sql = ("INSERT INTO czds_zones (tld" + "".join(", " + c for c in cols) + ", updated_at) VALUES (%s"
           + ", %s" * len(cols) + ", now()) ON CONFLICT (tld) DO UPDATE SET "
           + "".join(f"{c} = EXCLUDED.{c}, " for c in cols) + "updated_at = now()")
    await conn.execute(sql, [tld, *values])


async def add_run(conn, tld: str, fields: dict) -> None:
    vals = [fields.get(c) for c in RUN_COLUMNS]
    await conn.execute("INSERT INTO czds_runs (tld, " + ", ".join(RUN_COLUMNS) + ") VALUES (%s"
                       + ", %s" * len(RUN_COLUMNS) + ")", [tld, *vals])


async def store_hits(conn, tld: str, hits: list[Hit], serial: int | None) -> tuple[int, int]:
    stored = inserted = 0
    for hit in hits:
        domain_id, is_new = await store_hit(conn, hit, source="czds")
        stored += 1
        if is_new:
            inserted += 1
        else:   # already known (usually from CT): note that it is now delegated
            await db.add_event(conn, domain_id, "czds_new_delegation", {"tld": tld, "serial": serial})
    return stored, inserted


# ---------------------------------------------------------------------------------------------------
# the job

def _lock(cfg: CzdsConfig):
    cfg.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    f = open(cfg.data_dir / LOCK_FILE, "a+b")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def _unlock(f) -> None:
    try:
        fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        f.close()


def _cleanup_quietly(cfg: CzdsConfig, reason: str = "no longer in CZDS_TLDS") -> list[str]:
    try:
        return cleanup_unconfigured(cfg, reason=reason) if cfg.data_dir.is_dir() else []
    except Exception:          # never fail a run over clean-up
        log.exception("czds: cleaning up old lists failed")
        return []


def cleanup_inactive(cfg: CzdsConfig, reason: str = "CZDS credentials removed") -> list[str]:
    """CZDS is not in use any more (no credentials, or the job is turned off): delete raw and partial downloads
    of every zone at once, and every TLD's lists CZDS_KEEP_UNCONFIGURED_DAYS after they were last updated,
    whether or not the TLD is still in CZDS_TLDS (T&C s1.4). No network or database; never raises. Skipped
    while a czds run in another process holds the lock. Returns the TLDs whose lists were deleted."""
    if not cfg.data_dir.is_dir():
        return []
    try:
        lock = _lock(cfg)
    except OSError:
        log.exception("czds: could not lock %s for clean-up", cfg.data_dir)
        return []
    if lock is None:
        return []
    try:
        return _cleanup_quietly(dataclasses.replace(cfg, tlds=()), reason)
    finally:
        _unlock(lock)


def cleanup_if_disabled(s=None) -> list[str]:
    """Clean-up for a code path that still runs when JOB_CZDS_ENABLED=false (the czds job itself then never
    runs, so it cannot). Does nothing while the czds job is enabled: its own hourly runs clean up then.
    Never raises, so a caller (such as the housekeeping job) never fails over it."""
    try:
        from .jobs.czds import JOB      # here, not at the top: cybercheck.jobs.czds imports this module
        from .worker import job_enabled
        if job_enabled(JOB):
            return []
        return cleanup_inactive(load_config(s), "the czds job is turned off")
    except Exception:
        log.exception("czds: clean-up while the job is turned off failed")
        return []


def _err(e: BaseException) -> str:
    return clean_text(f"{type(e).__name__}: {e}" if not isinstance(e, CzdsError) else str(e), 300) or type(e).__name__


class ZoneRunner:
    """Fetches and processes the zones that are due; one instance per job run."""

    def __init__(self, ctx, cfg: CzdsConfig, api: CzdsApi, pool, watchlist):
        self.ctx, self.cfg, self.api, self.pool, self.wl = ctx, cfg, api, pool, watchlist
        self.gets: dict[str, datetime] = ctx.state.setdefault("gets", {})     # in-memory copy of last GET times

    async def save(self, z: dict, **fields) -> None:
        z.update(fields)
        async with self.pool.connection() as conn:
            await save_zone(conn, z["tld"], fields)

    async def finish(self, z: dict, status: str, error: str | None = None, run: dict | None = None, **fields) -> dict:
        fields.update(status=status, error=error)
        await self.save(z, **fields)
        async with self.pool.connection() as conn:
            await add_run(conn, z["tld"], {"status": status, "error": error, **(run or {})})
        if status in ("ok", "baseline", "rebaseline", "unchanged"):
            log.info("czds %s: %s%s", z["tld"], status, f" ({error})" if error else "")
        else:
            log.warning("czds %s: %s: %s", z["tld"], status, error)
        return {"status": status, **{k: (run or {}).get(k) for k in ("new_names", "hits") if (run or {}).get(k)}}

    def next_day(self, now: datetime) -> datetime:
        return next_slot(now + MIN_GAP, self.cfg)

    async def run_zone(self, z: dict) -> dict:
        tld = z["tld"]
        zdir = zone_dir(self.cfg, tld)
        raw = zdir / RAW
        state = dict(z.get("state") or {})
        pending = z.get("status") in ("downloaded", "processing") and raw.is_file()
        if pending and state.get("attempts", 0) >= MAX_PROCESS_ATTEMPTS:
            cleanup_zone_dir(zdir)
            state.pop("attempts", None)
            return await self.finish(z, "error", "processing failed twice; waiting for the next download", state=state)
        cleanup_zone_dir(zdir, keep_raw=pending)
        if pending:
            dl = state.get("download") or {}
        else:
            got = await self.fetch(z, zdir, state)
            if isinstance(got, dict) and "status" in got and "download" not in got:
                return got
            dl = got["download"]
        return await self.process(z, zdir, state, dl)

    async def fetch(self, z: dict, zdir: Path, state: dict) -> dict:
        tld, url = z["tld"], z.get("download_url")
        if not url or zone_url_tld(url) != tld:
            return await self.finish(z, "error", "no download URL for this zone yet", retry_at=utcnow() + timedelta(hours=1))
        now = utcnow()
        head = None
        if head_allowed(z, now):
            await self.save(z, last_head=now)
            try:
                head = await self.api.head(url)
            except CzdsAuthError:
                raise
            except (httpx.HTTPError, CzdsError) as e:
                log.warning("czds %s: HEAD failed (%s); downloading without it", tld, type(e).__name__)
            if head is not None:
                if head.status == 200:
                    state["head"] = {"at": head.at.isoformat(), "length": head.length, "last_modified": head.last_modified}
                    done = state.get("processed") or {}
                    if head.last_modified and head.length is not None and \
                            done.get("last_modified") == head.last_modified and done.get("bytes") == head.length:
                        return await self.finish(
                            z, "unchanged", "ICANN still serves the file already processed (same Last-Modified and "
                            "size); next check tomorrow", retry_at=self.next_day(now), state=state)
                elif head.status in (403, 404, 409):
                    return await self.http_stop(z, head.status, now, state)
                else:
                    log.warning("czds %s: HEAD returned HTTP %s; downloading without it", tld, head.status)
                    head = None
        expected = head.length if head else (state.get("download") or {}).get("bytes")
        if expected and expected > self.cfg.max_zone_bytes:
            return await self.finish(z, "invalid", f"zone file is {expected} bytes, over CZDS_MAX_ZONE_GB",
                                     retry_at=self.next_day(now), state=state)
        free = shutil.disk_usage(zdir).free
        if free < int((expected or 0) * 1.6) + self.cfg.min_free_bytes:
            return await self.finish(z, "low_disk", f"only {free >> 20} MB free on the data disk; not downloading",
                                     retry_at=next_slot(now + timedelta(hours=1), self.cfg), state=state)
        started: list[datetime] = []

        async def on_start(at: datetime) -> None:
            started.append(at)
            self.gets[tld] = at                       # kept even if the database write fails
            await self.save(z, last_download=at, status="downloading", error=None)

        part = zdir / PART
        try:
            dl = await self.api.download(url, part, max_bytes=self.cfg.max_zone_bytes, on_start=on_start)
        except CzdsAuthError:
            part.unlink(missing_ok=True)
            raise
        except CzdsHttpError as e:
            part.unlink(missing_ok=True)
            if e.status in (403, 404, 409):
                return await self.http_stop(z, e.status, now, state)
            return await self.transient(z, f"download failed: HTTP {e.status}", now, state)
        except (ZoneInvalid, LowDisk) as e:
            part.unlink(missing_ok=True)
            return await self.finish(z, "low_disk" if isinstance(e, LowDisk) else "invalid", str(e),
                                     retry_at=self.next_day(now), state=state)
        except (httpx.HTTPError, CzdsError, OSError) as e:
            part.unlink(missing_ok=True)
            if started:      # the day's download was used; ICANN allows one per 24 h
                return await self.finish(z, "error", f"download interrupted ({type(e).__name__}); next try tomorrow",
                                         state=state)
            return await self.transient(z, f"download failed ({type(e).__name__})", now, state)
        want = dl.content_length if dl.content_length is not None else (head.length if head else None)
        problem = None
        if want is not None and dl.bytes != want:
            problem = f"truncated download: {dl.bytes} of {want} bytes"
        elif dl.bytes < MIN_ZONE_BYTES:
            problem = f"zone file is only {dl.bytes} bytes (failed transfer?)"
        if problem:
            part.unlink(missing_ok=True)
            return await self.finish(z, "invalid", problem, file_bytes=dl.bytes, state=state,
                                     run={"file_bytes": dl.bytes})
        os.replace(part, zdir / RAW)
        state["download"] = {"bytes": dl.bytes, "last_modified": dl.last_modified, "started": dl.started.isoformat()}
        state["attempts"] = 0
        await self.save(z, status="downloaded", file_bytes=dl.bytes, fail_count=0, retry_at=None, state=state)
        return {"download": state["download"]}

    async def http_stop(self, z: dict, status: int, now: datetime, state: dict) -> dict:
        if status == 409:
            return await self.finish(z, "terms", "HTTP 409: accept the new Terms & Conditions in the CZDS portal",
                                     retry_at=next_slot(now + TERMS_RETRY, self.cfg), state=state)
        if status == 403:
            return await self.finish(z, "no_access", "HTTP 403: no permission for this zone (request expired or revoked?)",
                                     retry_at=self.next_day(now), state=state)
        return await self.finish(z, "error", f"HTTP {status} for this zone", retry_at=self.next_day(now), state=state)

    async def transient(self, z: dict, error: str, now: datetime, state: dict) -> dict:
        fails = int(z.get("fail_count") or 0) + 1
        return await self.finish(z, "retrying", error, fail_count=fails,
                                 retry_at=next_slot(now + retry_delay(fails), self.cfg), state=state)

    async def process(self, z: dict, zdir: Path, state: dict, dl: dict) -> dict:
        tld = z["tld"]
        raw = zdir / RAW
        state["attempts"] = int(state.get("attempts", 0)) + 1
        await self.save(z, status="processing", state=state)
        run = {"file_bytes": dl.get("bytes")}
        # A registry that resets its SOA serial, or whose files never end with the SOA record, would otherwise
        # be rejected every day: after TOLERATE_AFTER rejections in a row for that reason, accept it.
        tolerate = state.get("tolerate") or {}
        try:
            res = await asyncio.to_thread(
                process_zone, raw, zdir, tld, cfg=self.cfg, watchlist=self.wl, prev_serial=z.get("soa_serial"),
                prev_total=z.get("total_names"), rejected_total=state.get("rejected_total"),
                allow_older_serial=tolerate.get("old_serial", 0) >= TOLERATE_AFTER,
                allow_missing_end_soa=tolerate.get("end_soa_missing", 0) >= TOLERATE_AFTER)
        except ZoneUnchanged as e:
            state.pop("attempts", None)
            return await self.finish(z, "unchanged", f"{e}; kept the current list", state=state, run=run)
        except ZoneInvalid as e:
            state.pop("attempts", None)
            if e.total:
                state["rejected_total"] = e.total
            if e.reason in ("old_serial", "end_soa_missing"):
                state["tolerate"] = {e.reason: int(tolerate.get(e.reason, 0)) + 1}
            else:
                state.pop("tolerate", None)
            return await self.finish(z, "invalid", str(e), state=state, run=run)
        except LowDisk as e:
            state.pop("attempts", None)
            return await self.finish(z, "low_disk", str(e), state=state, run=run)
        except Exception as e:
            log.exception("czds %s: processing failed", tld)
            state.pop("attempts", None)
            return await self.finish(z, "error", f"processing failed: {_err(e)}", state=state, run=run)
        finally:
            raw.unlink(missing_ok=True)
        try:
            stored = inserted = 0
            if res.hits:
                async with self.pool.connection() as conn:
                    stored, inserted = await store_hits(conn, tld, res.hits, res.serial)
            rotate_lists(zdir)
        except Exception as e:
            log.exception("czds %s: storing hits failed", tld)
            (zdir / NEW_LIST).unlink(missing_ok=True)
            state.pop("attempts", None)
            return await self.finish(z, "error", f"storing hits failed: {_err(e)}", state=state, run=run)
        for k in ("attempts", "rejected_total"):
            state.pop(k, None)
        # keep tolerating a registry whose files never close with the SOA; anything else starts afresh
        if res.end_soa == "missing" and tolerate.get("end_soa_missing"):
            state["tolerate"] = {"end_soa_missing": tolerate["end_soa_missing"]}
        else:
            state.pop("tolerate", None)
        state["processed"] = {"last_modified": dl.get("last_modified"), "bytes": dl.get("bytes")}
        state["last_scan"] = {"lines": res.lines, "ns_records": res.ns_records, "skipped": res.skipped,
                              "scored": res.scored, "seconds": res.seconds}
        status = "baseline" if res.baseline else "rebaseline" if res.rebaseline else "ok"
        run.update(soa_serial=res.serial, total_names=res.total, new_names=res.new, removed_names=res.removed,
                   hits=stored, new_hits=inserted, duration_s=res.seconds)
        return await self.finish(
            z, status, res.note, run=run, last_processed=utcnow(), total_names=res.total, new_names=res.new,
            removed_names=res.removed, hits=stored, new_hits=inserted, soa_serial=res.serial,
            last_modified=dl.get("last_modified"), duration_s=res.seconds, fail_count=0, retry_at=None, state=state)


# Statuses that only say where a zone stands with CZDS (no download result to keep showing).
WAITING_STATUSES = frozenset({"pending", "not_approved", "approved", "revoked", "not_configured"})


async def apply_links(conn, zones: dict[str, dict], links: dict[str, str], cfg: CzdsConfig, now: datetime) -> list[str]:
    """Record which zones are approved. Returns configured TLDs that disappeared from the list (an expired or
    revoked request, or a CZDS fault like the .top revocation of January 2026)."""
    revoked = []
    for tld in sorted(set(links) | set(zones)):
        configured = tld in cfg.tlds
        z = zones.get(tld)
        if z is None:
            z = zones[tld] = {"tld": tld, "configured": configured, "approved": False, "status": "pending"}
        fields: dict = {}
        if tld in links:
            if z.get("download_url") != links[tld]:
                fields["download_url"] = links[tld]
            if not z.get("approved"):
                fields.update(approved=True, approved_at=now)
                if not z.get("status") or z["status"] in WAITING_STATUSES:
                    fields.update(status="approved" if configured else "not_configured", error=None)
        elif z.get("approved"):
            fields["approved"] = False
            if configured:
                revoked.append(tld)
                fields.update(status="revoked", error="no longer in the CZDS approved list (expired or revoked?); "
                                                      "check the request in the CZDS portal")
        elif configured and z.get("status") in (None, "pending", "approved"):
            fields.update(status="not_approved", error=None)
        if fields:
            await save_zone(conn, tld, fields)
            z.update(fields)
    for tld in revoked:
        log.warning("CZDS access to .%s is gone from the approved list (revoked or expired?)", tld)
    return revoked


async def sync_configured(conn, zones: dict[str, dict], cfg: CzdsConfig) -> None:
    """Mirror CZDS_TLDS into czds_zones.configured."""
    for tld in cfg.tlds:
        z = zones.get(tld)
        if z is None:
            zones[tld] = {"tld": tld, "configured": True, "approved": False, "status": "pending"}
            await save_zone(conn, tld, {"configured": True, "status": "pending"})
        elif not z.get("configured"):
            fields: dict = {"configured": True}
            if z.get("status") == "not_configured":
                fields["status"] = "approved" if z.get("approved") else "pending"
            await save_zone(conn, tld, fields)
            z.update(fields)
    for tld, z in zones.items():
        if z.get("configured") and tld not in cfg.tlds:
            fields = {"configured": False, "next_due": None}
            if not z.get("status") or z["status"] in WAITING_STATUSES:
                fields["status"] = "not_configured"
            await save_zone(conn, tld, fields)
            z.update(fields)


def _summary(cfg: CzdsConfig, zones: dict[str, dict], now: datetime, done: dict | None = None, **extra) -> dict:
    dues = [d for t in cfg.tlds if t in zones and (d := zone_due(zones[t], now, cfg))]
    out = {"zones": len(cfg.tlds), "approved": sum(1 for t in cfg.tlds if zones.get(t, {}).get("approved"))}
    waiting = [t for t in cfg.tlds if not zones.get(t, {}).get("approved")]
    if waiting:
        out["not_approved"] = waiting[:20]
    if done:
        out["processed"] = done
        out["new_names"] = sum(v.get("new_names") or 0 for v in done.values())
        out["hits"] = sum(v.get("hits") or 0 for v in done.values())
    if dues:
        out["next_due"] = min(dues).isoformat()
    out.update(extra)
    return out


async def run_once(ctx) -> dict:
    s = ctx.settings or settings()
    cfg = load_config(s)
    if not cfg.has_credentials:
        # no network or database. CZDS is no longer in use, so every zone's raw files go at once and every
        # list after the grace period, also for TLDs still in CZDS_TLDS (T&C s1.4)
        out: dict = {"skipped": "no CZDS credentials"}
        removed = await asyncio.to_thread(cleanup_inactive, cfg)
        if removed:
            out["deleted_lists"] = removed
        return out
    lock = _lock(cfg)
    if lock is None:
        return {"skipped": "another czds run is active"}
    try:
        async with make_http() as http:
            return await _run(ctx, cfg, http)
    finally:
        _unlock(lock)


async def _run(ctx, cfg: CzdsConfig, http: httpx.AsyncClient) -> dict:
    tokens = ctx.state.setdefault("tokens", TokenCache())
    links_at: datetime | None = ctx.state.get("links_at")
    api = CzdsApi(cfg, tokens, http)
    pool = await ctx.pool()
    now = utcnow()
    async with pool.connection() as conn:
        zones = await load_zones(conn)
        await sync_configured(conn, zones, cfg)
    for tld, at in ctx.state.get("gets", {}).items():   # never trust the database alone for the 24 h rule
        if tld in zones and (not zones[tld].get("last_download") or zones[tld]["last_download"] < at):
            zones[tld]["last_download"] = at

    def pending(tld: str) -> bool:
        return zones[tld].get("status") in ("downloaded", "processing") and (cfg.data_dir / tld / RAW).is_file()

    soon = [t for t in cfg.tlds if (d := zone_due(zones[t], now, cfg, pending(t))) and
            (d - now).total_seconds() <= MAX_WAIT_S]
    extra: dict = {}
    if links_at is None or now - links_at > LINKS_MAX_AGE or (soon and now - links_at > LINKS_MAX_AGE_BEFORE_DOWNLOAD):
        try:
            links = await api.links()
        except CzdsAuthError:
            raise
        except CzdsHttpError as e:
            if e.status == 401:
                raise CzdsAuthError("CZDS refused the login token (HTTP 401)") from None
            if not any(z.get("download_url") for z in zones.values()):
                raise
            extra["links_error"] = str(e)
            log.warning("czds: could not list approved zones (%s); using the last known list", e)
        except (httpx.HTTPError, CzdsError) as e:
            if not any(z.get("download_url") for z in zones.values()):
                raise CzdsError(f"could not list approved zones: {_err(e)}") from None
            extra["links_error"] = _err(e)
            log.warning("czds: could not list approved zones (%s); using the last known list", extra["links_error"])
        else:
            ctx.state["links_at"] = now
            async with pool.connection() as conn:
                revoked = await apply_links(conn, zones, links, cfg, now)
            if revoked:
                extra["revoked"] = revoked
    if not cfg.tlds:
        out = {"skipped": "CZDS_TLDS is empty", "approved": sum(1 for z in zones.values() if z.get("approved"))}
        removed = await asyncio.to_thread(_cleanup_quietly, cfg)
        if removed:
            out["deleted_lists"] = removed
        return out

    for tld in cfg.tlds:            # left over from a run that died (this run holds the lock, so none is active)
        z = zones[tld]
        fix = None
        if z.get("status") in ("downloaded", "processing") and not pending(tld):
            fix = "downloaded file is missing; next download tomorrow"
        elif not z.get("approved") and any((cfg.data_dir / tld / f).is_file() for f in (RAW, PART)):
            # access ended (revoked or expired) before a downloaded file was processed: T&C s1.4
            fix = "access ended before the downloaded file was processed; file deleted"
            cleanup_zone_dir(cfg.data_dir / tld)
        elif z.get("status") == "downloading":
            fix = "download interrupted (worker restarted?); next download tomorrow"
            (cfg.data_dir / tld / PART).unlink(missing_ok=True)
        if fix:
            async with pool.connection() as conn:
                await save_zone(conn, tld, {"status": "error", "error": fix})
            z.update(status="error", error=fix)

    # One zone at a time (no published concurrency limit; ICANN blamed past faults on load). A zone that comes
    # due within the hour is waited for here, so each day's download stays close to the previous one instead
    # of slipping by up to a job interval every day.
    done: dict[str, dict] = {}
    runner: ZoneRunner | None = None
    slept = 0.0
    for _ in range(2 * len(cfg.tlds) + 1):
        now = utcnow()
        upcoming = sorted((d, t) for t in cfg.tlds if t not in done
                          and (d := zone_due(zones[t], now, cfg, pending(t))))
        if not upcoming:
            break
        due, tld = upcoming[0]
        wait = (due - now).total_seconds()
        if wait > 0:
            if wait > MAX_WAIT_S or slept + wait > MAX_TOTAL_WAIT_S:
                break
            await _sleep(wait)
            slept += wait
            continue
        if runner is None:
            runner = ZoneRunner(ctx, cfg, api, pool, default_watchlist())
        try:
            done[tld] = await runner.run_zone(zones[tld])
        except CzdsAuthError:
            raise
        except Exception as e:      # one zone never stops the others
            log.exception("czds %s failed", tld)
            done[tld] = await runner.finish(zones[tld], "error", _err(e))
    now = utcnow()
    async with pool.connection() as conn:
        for tld in cfg.tlds:
            due = zone_due(zones[tld], now, cfg, pending(tld))
            if zones[tld].get("next_due") != due:
                await save_zone(conn, tld, {"next_due": due})
                zones[tld]["next_due"] = due
        await conn.execute("DELETE FROM czds_runs WHERE at < now() - make_interval(days => %s::int)", (RUNS_KEEP_DAYS,))
    removed = await asyncio.to_thread(_cleanup_quietly, cfg)
    if removed:
        extra["deleted_lists"] = removed
    return _summary(cfg, zones, now, done, **extra)
