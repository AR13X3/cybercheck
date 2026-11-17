"""Enrichment: DNS, RDAP and IP->ASN lookups, the re-check schedule, and takedown detection.

Runs as the worker job "enrich" (cybercheck/jobs/enrich.py). Each run picks up to ENRICH_BATCH_SIZE due
domains (high tier first) and checks them with bounded concurrency.

Ground rules this module keeps (docs/ARCHITECTURE.md):
- It never connects to a flagged domain or its IPs. DNS queries go only to settings().dns_resolvers,
  RDAP goes to the registry / RIR servers named in the IANA bootstrap files (redirects are followed only
  to hosts in those files), and IP->ASN uses Team Cymru's DNS zone through the same resolvers.
- Registry answers are treated as untrusted text: lengths are capped and emails validated.
- Network lookups happen without holding a database connection; each domain's results are written in one
  short transaction.

Settings (read from the environment here, not in config.py):
  ENRICH_BATCH_SIZE          domains per run (default 50)
  ENRICH_CONCURRENCY         domains checked at once (default 10)
  ENRICH_TRACK_DAYS          hourly checks of confirmed / reported / AI-phishing domains for this many days (30);
                             the fetch job's 2-hourly re-fetches of those domains use the same window (track_end)
  ENRICH_RDAP_REFRESH_HOURS  RDAP refresh interval for other domains (24; tracked domains: hourly)
  ENRICH_DNS_TIMEOUT         seconds per DNS query (3)
"""
from __future__ import annotations

import asyncio
import email.utils
import ipaddress
import json
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import httpx

from . import db
from .config import settings

log = logging.getLogger("cybercheck.enrich")

UTC = timezone.utc
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

# Back-off from first_seen; after the last step, daily until watch_until.
BACKOFF = (timedelta(minutes=10), timedelta(minutes=30), HOUR, timedelta(hours=3), timedelta(hours=6),
           timedelta(hours=12))
MIN_GAP = timedelta(minutes=5)          # never schedule the next check closer than this
RETRY_SOON = timedelta(minutes=10)      # after a DNS error, or when RDAP is still missing
CLOSED_STATUSES = ("false_positive", "benign")
HOLD_STATUSES = {"clienthold", "serverhold"}

IANA_BOOTSTRAP = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
BOOTSTRAP_TTL_S = 24 * 3600
BOOTSTRAP_RETRY_S = 3600
IP_CACHE_TTL_S = 7 * 24 * 3600
IP_CACHE_PARTIAL_TTL_S = 6 * 3600       # cached IP info whose RDAP part failed
IP_MEM_CACHE_MAX = 1000
RDAP_MIN_INTERVAL_S = 1.0               # at most ~1 request/s per RDAP host
RDAP_MAX_QUEUE_S = 20.0                 # skip RDAP this run rather than queue longer than this per host
RDAP_MAX_BYTES = 512 * 1024
BOOTSTRAP_MAX_BYTES = 2 * 1024 * 1024
HOUSEKEEP_EVERY_S = 300
KV_CLEAN_EVERY_S = 6 * 3600
DOMAIN_TIMEOUT_S = 120
PG_INT_MAX = 2**31 - 1
USER_AGENT ="CyberCheck-enrich/1.0 (phishing domain research; RDAP client)"

_NAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})+$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
# json.loads turns a "\ud800" escape in an RDAP answer into a lone surrogate: not encodable for a text column and
# rejected by jsonb, so the domain's whole write would fail on every run
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


# ---------------------------------------------------------------------------------------------------
# config and small helpers

@dataclass(frozen=True)
class EnrichConfig:
    batch_size: int = 50
    concurrency: int = 10
    track_days: int = 30
    rdap_refresh_hours: float = 24.0
    dns_timeout: float = 3.0


def load_config() -> EnrichConfig:
    def num(name: str, default, cast):
        v = os.environ.get(name, "").strip()
        try:
            return cast(v) if v else default
        except ValueError:
            log.warning("ignoring bad %s=%r", name, v)
            return default
    return EnrichConfig(
        batch_size=max(1, num("ENRICH_BATCH_SIZE", 50, int)),
        concurrency=max(1, num("ENRICH_CONCURRENCY", 10, int)),
        track_days=min(3650, max(1, num("ENRICH_TRACK_DAYS", 30, int))),   # int4 for make_interval
        rdap_refresh_hours=max(1.0, num("ENRICH_RDAP_REFRESH_HOURS", 24.0, float)),
        dns_timeout=min(30.0, max(0.5, num("ENRICH_DNS_TIMEOUT", 3.0, float))),
    )


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).isoformat() if ts else None


def parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    if not (1985 <= ts.year <= 2200):
        return None
    return ts


def clean_text(value, limit: int = 200) -> str | None:
    if not isinstance(value, str):
        return None
    v = _SURROGATE_RE.sub("\ufffd", _CTRL_RE.sub(" ", value)).strip()
    return v[:limit] or None


def clean_email(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.lower().startswith("mailto:"):
        v = v[7:]
    v = v.strip().strip("<>").strip()
    if len(v) > 254 or not _EMAIL_RE.match(v):
        return None
    local, _, domain = v.rpartition("@")
    return f"{local}@{domain.lower()}"


def hours_between(later: datetime | None, earlier: datetime | None) -> float | None:
    if not later or not earlier:
        return None
    return round((later - earlier).total_seconds() / 3600, 1)


def is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------------------------------
# schedule

def is_tracked(d: dict) -> bool:
    """Confirmed, reported or AI-phishing domains get hourly checks and takedown detection."""
    if d.get("status") in CLOSED_STATUSES:
        return False
    return d.get("status") == "confirmed" or d.get("reported_at") is not None or d.get("ai_verdict") == "phishing"


def track_anchor(d: dict) -> datetime | None:
    """Start of the hourly tracking window: the latest of first_seen, reported_at and (if confirmed)
    status_changed_at. Same rule as the revive query in housekeeping() and the fetch job's due query
    (GREATEST(first_seen, reported_at, CASE WHEN status = 'confirmed' THEN status_changed_at END))."""
    points = [d.get("first_seen"), d.get("reported_at")]
    if d.get("status") == "confirmed":
        points.append(d.get("status_changed_at"))
    points = [t for t in points if t]
    return max(points) if points else None


def track_end(d: dict, track_days: int) -> datetime | None:
    """When tracking of a tracked domain ends (track_anchor + track_days), or None if it is not tracked.

    One rule for both jobs: enrich checks tracked domains hourly until then, and the fetch job
    re-fetches them every FETCH_TRACK_INTERVAL_H until then. Enrich is the only job that records a
    takedown, so the fetch job must not keep fetching a domain that enrich no longer watches."""
    if not is_tracked(d):
        return None
    anchor = track_anchor(d)
    return anchor + timedelta(days=track_days) if anchor else None


def backoff_point(first_seen: datetime, now: datetime) -> datetime:
    """Next point of first_seen + 10m, 30m, 1h, 3h, 6h, 12h, 1d, 2d, ... at least MIN_GAP from now."""
    earliest = now + MIN_GAP
    for off in BACKOFF:
        t = first_seen + off
        if t >= earliest:
            return t
    t = first_seen + DAY * ((earliest - first_seen) // DAY)
    return t if t >= earliest else t + DAY


def next_check(d: dict, now: datetime, cfg: EnrichConfig, retry_soon: bool = False) -> datetime | None:
    """When to check this domain next; None stops checking (store_hit re-arms it on a new certificate)."""
    candidates = []
    wu = d.get("watch_until")
    if wu and now < wu:
        t = backoff_point(d["first_seen"], now)
        if t < wu:
            candidates.append(t)
    end = track_end(d, cfg.track_days)
    if end is not None and now < end:
        candidates.append(min(now + HOUR, end))
    if not candidates:
        return None
    t = min(candidates)
    if retry_soon:
        t = min(t, now + RETRY_SOON)
    return t


def rdap_due(d: dict, st: dict, now: datetime, cfg: EnrichConfig) -> bool:
    """RDAP on first enrichment, then every ENRICH_RDAP_REFRESH_HOURS, hourly for tracked domains."""
    fails = int(st.get("rdap_fail") or 0)
    fail_at = parse_ts(st.get("rdap_fail_at"))
    if fails and fail_at:
        wait = min(HOUR * (2 ** (fails - 1)), DAY)
        if now < fail_at + wait:
            return False
    last = parse_ts(st.get("rdap_at"))
    if last is None:
        return True
    interval = HOUR if is_tracked(d) else timedelta(hours=cfg.rdap_refresh_hours)
    return now >= last + interval - MIN_GAP


# ---------------------------------------------------------------------------------------------------
# DNS

def make_resolver(cfg: EnrichConfig) -> dns.asyncresolver.Resolver:
    """A resolver that only ever asks the configured public resolvers (never /etc/resolv.conf)."""
    servers = []
    for s in settings().dns_resolvers:
        try:
            servers.append(str(ipaddress.ip_address(s.strip())))
        except ValueError:
            log.warning("ignoring DNS resolver %r (not an IP address)", s)
    if not servers:
        raise RuntimeError("DNS_RESOLVERS has no usable resolver IPs")
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = servers
    r.timeout = min(2.0, cfg.dns_timeout)
    r.lifetime = cfg.dns_timeout
    r.cache = None
    return r


def nxdomain_verified(exc: dns.resolver.NXDOMAIN) -> bool:
    """True when the NXDOMAIN answer carries the zone's SOA in its authority section.

    A real negative answer includes the SOA (RFC 2308). Filtering resolvers (Quad9 9.9.9.9, which is a
    default DNS_RESOLVERS entry and is tried when 1.1.1.1 times out) answer NXDOMAIN with an empty
    authority section for domains on their threat feeds, which are exactly the phishing domains tracked
    here. Counting those as NXDOMAIN would record false takedowns, so they are treated as inconclusive.
    """
    responses = (getattr(exc, "kwargs", None) or {}).get("responses") or {}
    for resp in responses.values():
        for rrset in getattr(resp, "authority", None) or []:
            if getattr(rrset, "rdtype", None) == dns.rdatatype.SOA:
                return True
    return False


async def query_addresses(resolver, name: str, rdtype: str) -> tuple[str, list[str], str | None]:
    """One A or AAAA query: (state, addresses, error)."""
    try:
        ans = await resolver.resolve(dns.name.from_text(name), rdtype, search=False)
        return "resolves", [r.address for r in ans if hasattr(r, "address")], None
    except dns.resolver.NXDOMAIN as e:
        if not nxdomain_verified(e):
            return "error", [], "nxdomain_without_soa"
        return "nxdomain", [], None
    except dns.resolver.NoAnswer:
        return "no_answer", [], None
    except dns.exception.Timeout:
        return "error", [], "timeout"
    except dns.resolver.NoNameservers:
        return "error", [], "servfail"
    except dns.exception.DNSException as e:
        return "error", [], type(e).__name__
    except Exception as e:  # never let one odd answer kill the run
        log.warning("DNS %s %s failed: %s", name, rdtype, e)
        return "error", [], type(e).__name__


def combine_types(a: tuple, aaaa: tuple) -> dict:
    """Combine the A and AAAA answers for one name."""
    states = {a[0], aaaa[0]}
    if "resolves" in states:
        state = "resolves"
    elif "nxdomain" in states:
        state = "nxdomain"
    elif "error" in states:
        state = "error"
    else:
        state = "no_answer"
    out = {"state": state, "a": a[1][:10], "aaaa": aaaa[1][:10]}
    errs = [e for e in (a[2], aaaa[2]) if e]
    if errs:
        out["error"] = ",".join(sorted(set(errs)))
    return out


async def resolve_name(resolver, name: str) -> dict:
    a, aaaa = await asyncio.gather(query_addresses(resolver, name, "A"), query_addresses(resolver, name, "AAAA"))
    return combine_types(a, aaaa)


@dataclass
class DnsResult:
    state: str                      # resolves | nxdomain | no_answer | error
    reg_state: str                  # state of the registered domain itself
    ips: list[str]
    names: dict

    def as_json(self) -> dict:
        return {"state": self.state, "registered_state": self.reg_state, "ips": self.ips, "names": self.names}


def combine_names(registered: str, reg: dict, hostname: str | None, host: dict | None) -> DnsResult:
    names = {registered: reg}
    if hostname and host is not None:
        names[hostname] = host
    ips: list[str] = []
    for part in ([host] if host else []) + [reg]:       # the phishing hostname's IPs first
        for ip in part["a"] + part["aaaa"]:
            if ip not in ips:
                ips.append(ip)
    host_state = host["state"] if host else None
    if reg["state"] == "resolves" or host_state == "resolves":
        state = "resolves"
    elif reg["state"] == "nxdomain":
        state = "nxdomain"
    elif "error" in (reg["state"], host_state):
        state = "error"
    else:
        state = "no_answer"
    return DnsResult(state=state, reg_state=reg["state"], ips=ips[:10], names=names)


def valid_name(name: str | None) -> bool:
    return bool(name) and bool(_NAME_RE.match(name))


async def dns_check(resolver, registered: str, hostname: str | None) -> DnsResult:
    registered = str(registered or "").lower().rstrip(".")
    if hostname:
        hostname = hostname.lower().rstrip(".")
        if hostname.startswith("*."):
            hostname = hostname[2:]
    if not valid_name(registered):
        bad = {"state": "error", "a": [], "aaaa": [], "error": "invalid name"}
        return DnsResult("error", "error", [], {str(registered)[:253]: bad})
    if hostname == registered or not valid_name(hostname) or not hostname.endswith("." + registered):
        hostname = None
    if hostname:
        reg, host = await asyncio.gather(resolve_name(resolver, registered), resolve_name(resolver, hostname))
    else:
        reg, host = await resolve_name(resolver, registered), None
    return combine_names(registered, reg, hostname, host)


# ---------------------------------------------------------------------------------------------------
# RDAP parsing (pure functions; registry data is untrusted text)

def vcard_props(entity: dict) -> dict:
    """{'fn': str|None, 'email': [str]} from an RDAP entity's jCard."""
    out = {"fn": None, "email": []}
    va = entity.get("vcardArray") if isinstance(entity, dict) else None
    if not (isinstance(va, list) and len(va) >= 2 and isinstance(va[1], list)):
        return out
    for prop in va[1][:100]:
        if not (isinstance(prop, list) and len(prop) >= 4 and isinstance(prop[0], str)):
            continue
        name, value = prop[0].lower(), prop[3]
        if isinstance(value, list):
            value = next((v for v in value if isinstance(v, str) and v), None)
        if name == "fn" and out["fn"] is None:
            out["fn"] = clean_text(value)
        elif name == "email":
            e = clean_email(value)
            if e and e not in out["email"]:
                out["email"].append(e)
    return out


def roles_of(entity: dict) -> set[str]:
    roles = entity.get("roles") if isinstance(entity, dict) else None
    return {r.lower() for r in roles if isinstance(r, str)} if isinstance(roles, list) else set()


def walk_entities(obj: dict, depth: int = 0, max_depth: int = 4):
    """Yield every entity under obj (depth-first, depth-limited)."""
    ents = obj.get("entities") if isinstance(obj, dict) else None
    if not isinstance(ents, list) or depth >= max_depth:
        return
    for ent in ents[:50]:
        if isinstance(ent, dict):
            yield ent
            yield from walk_entities(ent, depth + 1, max_depth)


def abuse_email_in(obj: dict) -> str | None:
    for ent in walk_entities(obj):
        if "abuse" in roles_of(ent):
            emails = vcard_props(ent)["email"]
            if emails:
                return emails[0]
    return None


def parse_domain_rdap(data: dict) -> dict:
    """Registrar name, IANA id, registrar abuse email, status list and registration date."""
    out = {"registrar": None, "iana_id": None, "abuse_email": None, "status": [], "registered_at": None}
    registrar = None
    entities = data.get("entities") if isinstance(data.get("entities"), list) else []
    for ent in entities[:50]:
        if isinstance(ent, dict) and "registrar" in roles_of(ent):
            registrar = ent
            break
    if registrar is not None:
        out["registrar"] = vcard_props(registrar)["fn"]
        for pid in registrar.get("publicIds") or []:
            if not isinstance(pid, dict):
                continue
            typ = str(pid.get("type") or "").lower()
            ident = str(pid.get("identifier") or "").strip()
            if "iana" in typ and ident.isdigit() and len(ident) <= 9:
                out["iana_id"] = int(ident)
                break
        # No fallback to the entity handle: ccTLD registries use their own numeric registrar handles, which
        # would merge unrelated registrars under one "IANA id" on the takedown page.
        out["abuse_email"] = abuse_email_in(registrar)
    if out["abuse_email"] is None:
        out["abuse_email"] = abuse_email_in(data)
    status = data.get("status")
    if isinstance(status, list):
        out["status"] = [s for s in (clean_text(x, 60) for x in status[:20]) if s]
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and str(ev.get("eventAction", "")).lower() == "registration":
            out["registered_at"] = parse_ts(ev.get("eventDate"))
            if out["registered_at"]:
                break
    return out


def parse_ip_rdap(data: dict) -> dict:
    return {"abuse_email": abuse_email_in(data), "network": clean_text(data.get("name"), 100),
            "country": clean_text(data.get("country"), 2), "handle": clean_text(data.get("handle"), 100)}


def has_hold(statuses) -> bool:
    return any(re.sub(r"[\s_-]", "", s.lower()) in HOLD_STATUSES for s in statuses or [] if isinstance(s, str))


def parse_dns_bootstrap(doc: dict) -> dict[str, str]:
    """IANA dns.json -> {tld: base_url} (https only)."""
    out = {}
    for svc in doc.get("services") or []:
        if not (isinstance(svc, list) and len(svc) >= 2):
            continue
        base = next((u for u in svc[1] if isinstance(u, str) and u.startswith("https://")), None)
        if not base:
            continue
        for tld in svc[0]:
            if isinstance(tld, str):
                out[tld.lower().strip(".")] = base
    return out


def parse_ip_bootstrap(doc: dict) -> list[tuple]:
    """IANA ipv4.json / ipv6.json -> [(network, base_url)], most specific first."""
    out = []
    for svc in doc.get("services") or []:
        if not (isinstance(svc, list) and len(svc) >= 2):
            continue
        base = next((u for u in svc[1] if isinstance(u, str) and u.startswith("https://")), None)
        if not base:
            continue
        for cidr in svc[0]:
            try:
                out.append((ipaddress.ip_network(cidr, strict=False), base))
            except (ValueError, TypeError):
                continue
    out.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return out


def bootstrap_hosts(doc: dict) -> set[str]:
    hosts = set()
    for svc in doc.get("services") or []:
        if isinstance(svc, list) and len(svc) >= 2:
            for u in svc[1]:
                if isinstance(u, str) and u.startswith("https://"):
                    h = urlsplit(u).hostname
                    if h:
                        hosts.add(h.lower())
    return hosts


_icann_psl = None


def icann_registrable(name: str) -> str | None:
    """Registrable domain per the ICANN section of the PSL (pages.dev for foo.pages.dev). Loaded lazily."""
    global _icann_psl
    if name.count(".") == 1:
        return name                      # label + TLD: private PSL entries all have two or more labels
    if _icann_psl is None:
        from publicsuffixlist import PublicSuffixList
        _icann_psl = PublicSuffixList(only_icann=True)
    return _icann_psl.privatesuffix(name)


# ---------------------------------------------------------------------------------------------------
# HTTP: RDAP client with IANA bootstrap, per-host rate limit, 429 back-off and safe redirects

class TooLarge(Exception):
    pass


class RdapClient:
    """Long-lived state (bootstrap maps, per-host pacing) lives here; the httpx client is per run."""

    def __init__(self, min_interval: float = RDAP_MIN_INTERVAL_S, max_queue: float = RDAP_MAX_QUEUE_S):
        self.min_interval = min_interval
        self.max_queue = max_queue
        self.client: httpx.AsyncClient | None = None
        self.next_slot: dict[str, float] = {}
        self.backoff_until: dict[str, float] = {}
        self.backoff_s: dict[str, float] = {}
        self.dns_map: dict[str, str] = {}
        self.ip_maps: dict[str, list] = {"ipv4": [], "ipv6": []}
        self.loaded_at: dict[str, float] = {}
        self.attempt_at: dict[str, float] = {}
        self.allowed_hosts: set[str] = {"data.iana.org"}

    # -- pacing
    def reserve(self, host: str) -> float | None:
        """Seconds to wait before a request to host, or None to skip it this run (back-off or long queue)."""
        now = time.monotonic()
        if self.backoff_until.get(host, 0.0) > now:
            return None
        slot = max(self.next_slot.get(host, 0.0), now)
        if slot - now > self.max_queue:
            return None
        self.next_slot[host] = slot + self.min_interval
        return slot - now

    def note_429(self, host: str, retry_after: str | None) -> None:
        secs = None
        if retry_after:
            ra = retry_after.strip()
            if ra.isdigit():
                secs = float(ra)
            else:
                try:
                    when = email.utils.parsedate_to_datetime(ra)
                    secs = (when - utcnow()).total_seconds()
                except (TypeError, ValueError):
                    secs = None
        if secs is None:
            secs = min(3600.0, self.backoff_s.get(host, 30.0) * 2)
        secs = min(3600.0, max(5.0, secs))
        self.backoff_s[host] = secs
        self.backoff_until[host] = time.monotonic() + secs
        log.info("RDAP host %s returned 429; backing off %.0fs", host, secs)

    def redirect_ok(self, url: str) -> bool:
        parts = urlsplit(url)
        return parts.scheme == "https" and (parts.hostname or "").lower() in self.allowed_hosts

    async def get_json(self, url: str, max_bytes: int = RDAP_MAX_BYTES) -> dict:
        """GET a JSON document. Returns {'state': ok|not_found|deferred|error, ...}."""
        if self.client is None:
            return {"state": "error", "error": "no http client"}
        for _ in range(4):
            host = (urlsplit(url).hostname or "").lower()
            delay = self.reserve(host)
            if delay is None:
                return {"state": "deferred", "host": host}
            if delay > 0:
                await asyncio.sleep(delay)
                if self.backoff_until.get(host, 0.0) > time.monotonic():
                    # a request queued ahead of this one got a 429 while this one waited
                    return {"state": "deferred", "host": host}
            try:
                async with self.client.stream("GET", url) as r:
                    status = r.status_code
                    if status in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location")
                        nxt = urljoin(url, loc) if loc else None
                        if not nxt or not self.redirect_ok(nxt):
                            return {"state": "error", "http_status": status, "host": host,
                                    "error": "redirect to unknown host refused"}
                        url = nxt
                        continue
                    if status == 429:
                        self.note_429(host, r.headers.get("retry-after"))
                        return {"state": "deferred", "http_status": 429, "host": host}
                    if status == 404:
                        return {"state": "not_found", "http_status": 404, "host": host}
                    if status != 200:
                        return {"state": "error", "http_status": status, "host": host}
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > max_bytes:
                            raise TooLarge()
            except TooLarge:
                return {"state": "error", "host": host, "error": "response too large"}
            except httpx.HTTPError as e:
                return {"state": "error", "host": host, "error": type(e).__name__}
            self.backoff_s.pop(host, None)
            try:
                data = json.loads(bytes(buf))
            except ValueError:
                return {"state": "error", "host": host, "http_status": 200, "error": "invalid JSON"}
            if not isinstance(data, dict):
                return {"state": "error", "host": host, "http_status": 200, "error": "unexpected JSON"}
            return {"state": "ok", "host": host, "http_status": 200, "data": data}
        return {"state": "error", "error": "too many redirects"}

    # -- bootstrap
    def _apply_bootstrap(self, kind: str, doc: dict, fetched_at: float) -> None:
        if kind == "dns":
            self.dns_map = parse_dns_bootstrap(doc)
        else:
            self.ip_maps[kind] = parse_ip_bootstrap(doc)
        self.allowed_hosts |= bootstrap_hosts(doc)
        self.loaded_at[kind] = fetched_at

    async def ensure_bootstrap(self, kind: str) -> None:
        """Keep the IANA bootstrap file fresh: memory, then kv (24 h), then IANA. Stale data beats none."""
        now = time.time()
        if now - self.loaded_at.get(kind, 0.0) < BOOTSTRAP_TTL_S:
            return
        key = f"enrich:rdap_bootstrap:{kind}"
        if kind not in self.loaded_at:
            try:
                p = await db.pool()
                async with p.connection() as conn:
                    cached = await db.kv_get(conn, key)
                if isinstance(cached, dict) and isinstance(cached.get("doc"), dict):
                    self._apply_bootstrap(kind, cached["doc"], float(cached.get("fetched_at") or 0))
                    if now - self.loaded_at[kind] < BOOTSTRAP_TTL_S:
                        return
            except Exception:
                log.exception("could not read cached RDAP bootstrap %s", kind)
        if now - self.attempt_at.get(kind, 0.0) < BOOTSTRAP_RETRY_S:
            return
        self.attempt_at[kind] = now
        res = await self.get_json(IANA_BOOTSTRAP[kind], max_bytes=BOOTSTRAP_MAX_BYTES)
        if res["state"] != "ok":
            if res["state"] == "deferred":
                self.attempt_at.pop(kind, None)
            log.warning("RDAP bootstrap %s fetch failed: %s", kind, res)
            return
        doc = {"services": res["data"].get("services") or []}
        if not doc["services"]:
            log.warning("RDAP bootstrap %s has no services", kind)
            return
        self._apply_bootstrap(kind, doc, now)
        try:
            p = await db.pool()
            async with p.connection() as conn:
                await db.kv_set(conn, key, {"fetched_at": now, "doc": doc})
        except Exception:
            log.exception("could not cache RDAP bootstrap %s", kind)

    def base_for_domain(self, name: str) -> str | None:
        labels = name.split(".")
        for i in range(1, len(labels)):
            base = self.dns_map.get(".".join(labels[i:]))
            if base:
                return base
        return None

    def base_for_ip(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, base in self.ip_maps["ipv4" if addr.version == 4 else "ipv6"]:
            if addr in net:
                return base
        return None

    # -- lookups
    async def lookup_domain(self, name: str) -> dict:
        """RDAP for a registered domain. state: ok | not_found | unsupported | platform | deferred | error."""
        name = name.lower().rstrip(".")
        if not valid_name(name):
            return {"state": "error", "error": "invalid name"}
        try:
            icann = icann_registrable(name)
        except Exception:
            icann = name
        if icann and icann != name:
            # under a hosting platform's suffix (foo.pages.dev): the registry knows only the platform's domain
            return {"state": "platform", "parent": icann}
        if name == "au" or name.endswith(".au"):
            # auDA's Licensing Rule 2.18.14 / WHOIS Policy 5.1 prohibit automated querying of .au
            # (docs/research/au-reporting.md). Keep .au registrar contacts by hand instead.
            return {"state": "unsupported", "tld": "au"}
        if not self.dns_map:
            return {"state": "deferred", "error": "no bootstrap"}
        base = self.base_for_domain(name)
        if not base:
            return {"state": "unsupported", "tld": name.rsplit(".", 1)[-1]}
        res = await self.get_json(base.rstrip("/") + "/domain/" + name)
        out = {k: v for k, v in res.items() if k != "data"}
        if res["state"] != "ok":
            return out
        data = res["data"]
        if data.get("objectClassName") not in (None, "domain"):
            return {**out, "state": "error", "error": "not a domain object"}
        ldh = str(data.get("ldhName") or "").lower().rstrip(".")
        if ldh and ldh != name:
            return {**out, "state": "error", "error": "answer is for another domain"}
        return {**out, **parse_domain_rdap(data)}

    async def lookup_ip(self, ip: str) -> dict:
        if not self.ip_maps["ipv4" if ":" not in ip else "ipv6"]:
            return {"state": "deferred", "error": "no bootstrap"}
        base = self.base_for_ip(ip)
        if not base:
            return {"state": "unsupported"}
        res = await self.get_json(base.rstrip("/") + "/ip/" + str(ipaddress.ip_address(ip)))
        out = {k: v for k, v in res.items() if k != "data"}
        if res["state"] != "ok":
            return out
        return {**out, **parse_ip_rdap(res["data"])}


# ---------------------------------------------------------------------------------------------------
# IP -> ASN (Team Cymru DNS) and hosting abuse contact (IP RDAP), cached per IP

def cymru_origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    return ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"


def parse_cymru_origin(records: list[str]) -> dict | None:
    """'13335 | 104.16.0.0/13 | US | arin | 2014-03-28' -> most specific prefix wins."""
    best = None
    for rec in records:
        parts = [p.strip() for p in rec.split("|")]
        if len(parts) < 3:
            continue
        asn_tok = parts[0].split()[0] if parts[0].split() else ""
        if not asn_tok.isdigit() or not (0 < int(asn_tok) <= PG_INT_MAX):
            continue                  # domains.asn is a Postgres int; a bigger value would fail the UPDATE
        try:
            net = ipaddress.ip_network(parts[1], strict=False)
        except ValueError:
            continue
        cand = {"asn": int(asn_tok), "prefix": str(net), "country": clean_text(parts[2], 2),
                "rir": clean_text(parts[3], 20) if len(parts) > 3 else None}
        if best is None or net.prefixlen > ipaddress.ip_network(best["prefix"]).prefixlen:
            best = cand
    return best


def parse_cymru_asname(records: list[str]) -> str | None:
    """'13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US' -> the name."""
    for rec in records:
        parts = [p.strip() for p in rec.split("|")]
        if len(parts) >= 5 and parts[4]:
            return clean_text(parts[4], 200)
    return None


async def query_txt(resolver, name: str) -> tuple[str, list[str]]:
    try:
        ans = await resolver.resolve(dns.name.from_text(name), "TXT", search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "none", []
    except dns.exception.DNSException as e:
        return "error", [type(e).__name__]
    except Exception as e:
        log.warning("TXT %s failed: %s", name, e)
        return "error", [type(e).__name__]
    out = []
    for r in list(ans)[:10]:
        strings = getattr(r, "strings", ())
        out.append(b"".join(strings).decode("utf-8", "replace")[:500])
    return "ok", out


async def cymru_lookup(resolver, ip: str) -> dict:
    state, recs = await query_txt(resolver, cymru_origin_name(ip))
    if state != "ok":
        return {"state": state}
    origin = parse_cymru_origin(recs)
    if not origin:
        return {"state": "none"}
    st2, recs2 = await query_txt(resolver, f"AS{origin['asn']}.asn.cymru.com")
    origin["as_name"] = parse_cymru_asname(recs2) if st2 == "ok" else None
    return {"state": "ok", **origin}


class IpInfoCache:
    """Small in-process LRU in front of kv['enrich:ip:<ip>']."""

    def __init__(self, maxsize: int = IP_MEM_CACHE_MAX):
        self.maxsize = maxsize
        self.items: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def get(self, ip: str) -> dict | None:
        hit = self.items.get(ip)
        if not hit:
            return None
        if hit[0] < time.time():
            self.items.pop(ip, None)
            return None
        self.items.move_to_end(ip)
        return hit[1]

    def put(self, ip: str, info: dict, expires: float) -> None:
        self.items[ip] = (expires, info)
        self.items.move_to_end(ip)
        while len(self.items) > self.maxsize:
            self.items.popitem(last=False)


def ip_info_ttl(info: dict) -> int:
    return IP_CACHE_PARTIAL_TTL_S if info.get("partial") else IP_CACHE_TTL_S


async def ip_info(env: "Env", ip: str) -> dict:
    """ASN, AS name, country and hosting abuse email for one IP; 'cached' says whether a lookup ran."""
    hit = env.ip_cache.get(ip)
    if hit is not None:
        return {**hit, "cached": True}
    key = f"enrich:ip:{ip}"
    try:
        async with env.db_sem:
            p = await db.pool()
            async with p.connection() as conn:
                row = await (await conn.execute("SELECT value, updated_at FROM kv WHERE key = %s", (key,))).fetchone()
        if row and isinstance(row["value"], dict):
            expires = row["updated_at"].timestamp() + ip_info_ttl(row["value"])
            if expires > time.time():
                env.ip_cache.put(ip, row["value"], expires)
                return {**row["value"], "cached": True}
    except Exception:
        log.exception("could not read IP cache for %s", ip)

    cym, rd = await asyncio.gather(cymru_lookup(env.resolver, ip), env.rdap.lookup_ip(ip))
    info = {"ip": ip, "asn": cym.get("asn"), "as_name": cym.get("as_name"), "prefix": cym.get("prefix"),
            "country": cym.get("country") or rd.get("country"), "rir": cym.get("rir"),
            "abuse_email": rd.get("abuse_email"), "network": rd.get("network"),
            "asn_state": cym.get("state"), "rdap_state": rd.get("state"), "at": iso(utcnow())}
    # partial: one half failed transiently; cache it only briefly so the missing part is retried soon
    info["partial"] = rd.get("state") in ("error", "deferred") or cym.get("state") == "error"
    if info["asn"] is not None or info["abuse_email"]:
        env.ip_cache.put(ip, info, time.time() + ip_info_ttl(info))
        try:
            async with env.db_sem:
                p = await db.pool()
                async with p.connection() as conn:
                    await db.kv_set(conn, key, info)
        except Exception:
            log.exception("could not cache IP info for %s", ip)
    return {**info, "cached": False}


def primary_ip(ips: list[str]) -> str | None:
    """First global IPv4 (the phishing hostname's come first), else first global IPv6."""
    glob = [ip for ip in ips if is_global_ip(ip)]
    v4 = [ip for ip in glob if ":" not in ip]
    return (v4 or glob or [None])[0]


# ---------------------------------------------------------------------------------------------------
# decision: what to write for one domain (pure, so it can be tested without network or database)

@dataclass
class Update:
    cols: dict = field(default_factory=dict)
    checks: list = field(default_factory=list)       # (kind, ok, result)
    events: list = field(default_factory=list)       # (kind, detail)
    state: dict = field(default_factory=dict)
    next_check_at: datetime | None = None
    takedown: tuple | None = None                    # (signal, at)


def evaluate_takedown(d: dict, st: dict, dns_res: DnsResult, rdap_res: dict | None, now: datetime,
                      page_down_at: datetime | None = None) -> tuple[dict, tuple | None]:
    """Returns (pending signals to remember, (signal, first_observed_at) or None).

    nxdomain and http_gone must be seen on two consecutive checks; an RDAP hold counts at once. A domain
    must have been up (resolved or served a page) before; holds on never-used registrations don't count.
    """
    if not is_tracked(d) or d.get("takedown_at"):
        return {}, None
    if not (st.get("resolved_at") or d.get("first_live_at")):
        return {}, None
    pending = st.get("pending") if isinstance(st.get("pending"), dict) else {}
    seen = set()
    new: dict = {}
    if dns_res.state != "resolves" and dns_res.reg_state == "nxdomain":
        seen.add("nxdomain")
    elif dns_res.state == "error" and "nxdomain" in pending:
        new["nxdomain"] = pending["nxdomain"]        # inconclusive lookup: neither confirms nor clears
    if d.get("live_state") == "down" and d.get("first_live_at"):
        seen.add("http_gone")
    for sig in sorted(seen):
        prev = pending.get(sig) if isinstance(pending.get(sig), dict) else None
        new[sig] = {"since": prev.get("since") if prev and prev.get("since") else iso(now),
                    "n": int(prev.get("n") or 1) + 1 if prev else 1}

    found = []
    for sig, p in new.items():
        if sig in seen and p["n"] >= 2:
            since = parse_ts(p["since"]) or now
            if sig == "http_gone" and page_down_at:
                last_live = d.get("last_live_at") or d.get("first_live_at")
                if (last_live is None or page_down_at >= last_live) and page_down_at < since:
                    since = page_down_at              # the fetcher saw it gone before we did
            found.append((since, sig))
    if rdap_res is not None and rdap_res.get("state") == "ok":
        if has_hold(rdap_res.get("status")):
            found.append((now, "rdap_hold"))
    elif has_hold(d.get("rdap_status")) and dns_res.state != "resolves":
        # No fresh answer this time: a hold seen on the last good lookup still counts, from when it was seen,
        # but only if that lookup came after the domain was first seen up. Otherwise it may be a hold from
        # before the domain went live (e.g. pending registrant verification) that has since been lifted.
        seen_at = parse_ts(st.get("rdap_at"))
        ups = [t for t in (parse_ts(st.get("resolved_at")), parse_ts(d.get("first_live_at"))) if t]
        if seen_at and ups and seen_at >= min(ups):
            found.append((seen_at, "rdap_hold"))
    if found:
        at, sig = min(found)
        return {}, (sig, at)
    return new, None


def decide(d: dict, dns_res: DnsResult, rdap_res: dict | None, ipinfo: dict | None, now: datetime,
           cfg: EnrichConfig, page_down_at: datetime | None = None) -> Update:
    st = dict(d.get("enrich_state") or {})
    up = Update()
    prev_def = st.get("dns")
    had_resolved = bool(st.get("resolved_at"))

    # DNS
    up.checks.append(("dns", dns_res.state != "error", dns_res.as_json()))
    if dns_res.state == "error":
        st["dns_err"] = int(st.get("dns_err") or 0) + 1
        if d.get("dns_state") in (None, "unknown", "error"):
            up.cols["dns_state"] = "error"     # otherwise keep the last real answer (fetch relies on it)
    else:
        st["dns_err"] = 0
        st["dns"] = dns_res.state
        up.cols["dns_state"] = dns_res.state
        if dns_res.state == "resolves":
            up.cols["ips"] = dns_res.ips
            if prev_def != "resolves":
                up.events.append(("dns_resolves", {"ips": dns_res.ips[:5], "first": not st.get("resolved_at")}))
            if not st.get("resolved_at"):
                st["resolved_at"] = iso(now)
        else:
            up.cols["ips"] = []
            # stopped resolving: resolves -> nxdomain, or resolves -> no_answer -> nxdomain
            if dns_res.state == "nxdomain" and prev_def in ("resolves", "no_answer") and had_resolved:
                up.events.append(("nxdomain", {"previous_ips": list(d.get("ips") or [])[:5]}))

    # RDAP
    retry_soon = dns_res.state == "error" and st["dns_err"] <= 2
    if rdap_res is not None:
        state = rdap_res.get("state")
        first = not st.get("rdap_at")
        result = {k: (iso(v) if isinstance(v, datetime) else v) for k, v in rdap_res.items()}
        if state == "ok":
            up.checks.append(("rdap", True, result))
            st["rdap_at"] = iso(now)
            st.pop("rdap_fail", None)
            st.pop("rdap_fail_at", None)
            for src, col in (("registrar", "registrar"), ("iana_id", "registrar_iana_id"),
                             ("abuse_email", "registrar_abuse_email"), ("registered_at", "registered_at")):
                if rdap_res.get(src) is not None:
                    up.cols[col] = rdap_res[src]
            up.cols["rdap_status"] = list(rdap_res.get("status") or [])
        elif state in ("not_found", "unsupported", "platform"):
            if first or state == "not_found":
                up.checks.append(("rdap", False, result))
            st["rdap_at"] = iso(now)
            st.pop("rdap_fail", None)
            st.pop("rdap_fail_at", None)
        elif state == "error":
            up.checks.append(("rdap", False, result))
            st["rdap_fail"] = int(st.get("rdap_fail") or 0) + 1
            st["rdap_fail_at"] = iso(now)
        elif state == "deferred" and first:
            retry_soon = True                  # rate-limited this run; get the registrar soon

    # IP -> ASN / hosting abuse contact
    if ipinfo is not None:
        ip = ipinfo.get("ip")
        changed_ip = ip != st.get("ip")
        if not ipinfo.get("cached") or changed_ip:
            up.checks.append(("asn", ipinfo.get("asn") is not None,
                              {k: v for k, v in ipinfo.items() if k != "at"}))
        if ipinfo.get("asn") is not None:
            up.cols["asn"] = ipinfo["asn"]
            up.cols["as_name"] = ipinfo.get("as_name")
            up.cols["ip_country"] = ipinfo.get("country")
        if ipinfo.get("abuse_email"):
            up.cols["hosting_abuse_email"] = ipinfo["abuse_email"]
        elif changed_ip and not ipinfo.get("partial"):
            up.cols["hosting_abuse_email"] = None
        st["ip"] = ip

    # takedown
    pending, td = evaluate_takedown(d, st, dns_res, rdap_res, now, page_down_at)
    if pending:
        st["pending"] = pending
    else:
        st.pop("pending", None)
    if td:
        sig, at = td
        up.takedown = td
        up.cols["takedown_at"] = at
        up.cols["takedown_signal"] = sig
        up.events.append(("taken_down", {
            "signal": sig, "observed_at": iso(at), "detected_at": iso(now),
            "hours_from_first_seen": hours_between(at, d.get("first_seen")),
            "hours_from_first_live": hours_between(at, d.get("first_live_at")),
            "hours_from_reported": hours_between(at, d.get("reported_at")),
        }))
        up.next_check_at = None
    else:
        up.next_check_at = next_check(d, now, cfg, retry_soon=retry_soon)
    up.state = st
    return up


# ---------------------------------------------------------------------------------------------------
# database

DUE_SQL = """
SELECT id, registered_domain, tld, hostnames[1] AS hostname, tier, status, status_changed_at, first_seen,
       watch_until, dns_state, ips, asn, rdap_status, live_state, first_live_at, last_live_at, ai_verdict,
       reported_at, takedown_at, enriched_at, enrich_state, last_seen
FROM domains
WHERE next_check_at <= now() AND takedown_at IS NULL
  AND status NOT IN ('false_positive', 'benign')
  AND (watch_until > now() OR status = 'confirmed' OR reported_at IS NOT NULL OR ai_verdict = 'phishing')
ORDER BY CASE tier WHEN 'high' THEN 0 WHEN 'review' THEN 1 ELSE 2 END, next_check_at
LIMIT %s
"""

# Domains that are due but no longer eligible: stop scheduling them (keeps the due scan short).
EXPIRE_SQL = """
UPDATE domains SET next_check_at = NULL
WHERE next_check_at <= now() AND (
      takedown_at IS NOT NULL OR status IN ('false_positive', 'benign')
   OR (COALESCE(watch_until, '-infinity'::timestamptz) <= now() AND status <> 'confirmed'
       AND reported_at IS NULL AND ai_verdict IS DISTINCT FROM 'phishing'))
"""

# Re-arm checks: a domain became confirmed / reported / AI-phishing after its schedule ended (or is
# confirmed but its next check is far off), or a reviewer reopened it inside its watch window.
REVIVE_SQL = """
UPDATE domains SET next_check_at = now()
WHERE takedown_at IS NULL AND status NOT IN ('false_positive', 'benign') AND (
      ((status = 'confirmed' OR reported_at IS NOT NULL OR ai_verdict = 'phishing')
       AND (next_check_at IS NULL OR next_check_at > now() + interval '1 hour')
       AND GREATEST(first_seen, reported_at, CASE WHEN status = 'confirmed' THEN status_changed_at END)
           > now() - make_interval(days => %s))
   OR (next_check_at IS NULL AND watch_until > now()
       AND status_changed_at > COALESCE(enriched_at, '-infinity'::timestamptz)))
"""

UPDATABLE = {"dns_state": "", "ips": "::text[]", "asn": "", "as_name": "", "ip_country": "",
             "hosting_abuse_email": "", "registrar": "", "registrar_iana_id": "", "registrar_abuse_email": "",
             "rdap_status": "::text[]", "registered_at": "", "takedown_at": "", "takedown_signal": ""}


def build_update_sql(cols: dict) -> tuple[str, list]:
    sets, params = [], []
    for col, value in cols.items():
        if col not in UPDATABLE:              # column names come only from this module's whitelist
            raise ValueError(f"enrich may not write {col}")
        sets.append(f"{col} = %s{UPDATABLE[col]}")
        params.append(value)
    sets += ["enriched_at = now()", "check_count = check_count + 1", "next_check_at = %s", "enrich_state = %s"]
    return "UPDATE domains SET " + ", ".join(sets) + " WHERE id = %s", params


_UNSET = object()


async def write_update(conn, domain_id: int, up: Update, read_last_seen=_UNSET) -> None:
    """Write one check's result. read_last_seen is domains.last_seen as DUE_SQL read it: when a new certificate
    arrived during the (slow, networked) check, store_hit has already moved next_check_at forward and cleared
    any takedown, and this check's view is stale, so it must not undo either."""
    cols, events, next_at = dict(up.cols), list(up.events), up.next_check_at
    async with conn.transaction():
        if read_last_seen is not _UNSET:
            cur = await (await conn.execute(
                "SELECT last_seen, next_check_at FROM domains WHERE id = %s FOR UPDATE", (domain_id,))).fetchone()
            if cur and cur.get("last_seen") != read_last_seen:
                for col in ("takedown_at", "takedown_signal"):
                    cols.pop(col, None)
                events = [(k, dt) for k, dt in events if k != "taken_down"]
                if cur.get("next_check_at") is not None and (next_at is None or cur["next_check_at"] < next_at):
                    next_at = cur["next_check_at"]
                up.takedown = None
        sql, params = build_update_sql(cols)
        params += [next_at, db.jsonb(up.state), domain_id]
        for kind, ok, result in up.checks:
            await conn.execute("INSERT INTO checks (domain_id, kind, ok, result) VALUES (%s, %s, %s, %s)",
                               (domain_id, kind, ok, db.jsonb(json.loads(db.dumps(result)))))
        await conn.execute(sql, params)
        for kind, detail in events:
            await db.add_event(conn, domain_id, kind, json.loads(db.dumps(detail)))


async def housekeeping(state: dict, cfg: EnrichConfig) -> dict:
    now = time.monotonic()
    out = {}
    if now - state.get("housekeep_at", -1e9) < HOUSEKEEP_EVERY_S:
        return out
    state["housekeep_at"] = now
    p = await db.pool()
    async with p.connection() as conn:
        out["expired"] = (await conn.execute(EXPIRE_SQL)).rowcount
        out["revived"] = (await conn.execute(REVIVE_SQL, (cfg.track_days,))).rowcount
        if now - state.get("kv_clean_at", -1e9) >= KV_CLEAN_EVERY_S:
            state["kv_clean_at"] = now
            await conn.execute("DELETE FROM kv WHERE key LIKE %s AND updated_at < now() - interval '7 days'",
                               ("enrich:ip:%",))
    return out


# ---------------------------------------------------------------------------------------------------
# per-domain processing and the job entry point

@dataclass
class Env:
    cfg: EnrichConfig
    resolver: object
    rdap: RdapClient
    ip_cache: IpInfoCache
    db_sem: asyncio.Semaphore


async def page_down_time(env: Env, domain_id: int) -> datetime | None:
    """When the fetch module recorded the page as gone (its 'page_down' event), if it did."""
    async with env.db_sem:
        p = await db.pool()
        async with p.connection() as conn:
            row = await (await conn.execute(
                "SELECT max(at) AS at FROM domain_events WHERE domain_id = %s AND kind = 'page_down'",
                (domain_id,))).fetchone()
    return row["at"] if row else None


async def process_domain(env: Env, d: dict) -> Update:
    now = utcnow()
    st = d.get("enrich_state") or {}
    dns_res = await dns_check(env.resolver, d["registered_domain"], d.get("hostname"))
    rdap_res = None
    if rdap_due(d, st, now, env.cfg):
        rdap_res = await env.rdap.lookup_domain(d["registered_domain"])
    info = None
    ip = primary_ip(dns_res.ips) if dns_res.state == "resolves" else None
    if ip:
        info = await ip_info(env, ip)
    page_down_at = None
    if is_tracked(d) and d.get("live_state") == "down" and d.get("first_live_at"):
        page_down_at = await page_down_time(env, d["id"])
    up = decide(d, dns_res, rdap_res, info, now, env.cfg, page_down_at)
    async with env.db_sem:
        p = await db.pool()
        async with p.connection() as conn:
            await write_update(conn, d["id"], up, d.get("last_seen"))
    if up.takedown:
        log.info("takedown detected: %s (%s)", d["registered_domain"], up.takedown[0])
    return up


async def postpone(domain_id: int, minutes: int = 30) -> None:
    """After an unexpected failure, push the domain back so one bad row can't hog every run."""
    try:
        p = await db.pool()
        async with p.connection() as conn:
            await conn.execute("UPDATE domains SET next_check_at = now() + make_interval(mins => %s) "
                               "WHERE id = %s AND next_check_at <= now()", (minutes, domain_id))
    except Exception:
        log.exception("could not postpone domain %s", domain_id)


async def run_once(ctx) -> dict:
    cfg = load_config()
    state = ctx.state
    result = {"due": 0, "checked": 0, "failed": 0, "rdap": 0, "takedowns": 0}
    try:
        result.update(await housekeeping(state, cfg))
    except Exception:
        ctx.log.exception("enrich housekeeping failed")

    p = await db.pool()
    async with p.connection() as conn:
        rows = await (await conn.execute(DUE_SQL, (cfg.batch_size,))).fetchall()
    result["due"] = len(rows)
    if not rows:
        return result

    rdap = state.get("rdap")
    if rdap is None:
        rdap = state["rdap"] = RdapClient()
    cache = state.get("ip_cache")
    if cache is None:
        cache = state["ip_cache"] = IpInfoCache()
    env = Env(cfg=cfg, resolver=make_resolver(cfg), rdap=rdap, ip_cache=cache, db_sem=asyncio.Semaphore(2))
    sem = asyncio.Semaphore(cfg.concurrency)

    async def one(d: dict) -> None:
        async with sem:
            try:
                up = await asyncio.wait_for(process_domain(env, d), DOMAIN_TIMEOUT_S)
            except Exception as e:
                result["failed"] += 1
                ctx.log.warning("enrich %s failed: %s: %s", d.get("registered_domain"), type(e).__name__, e,
                                exc_info=not isinstance(e, asyncio.TimeoutError))
                await postpone(d["id"])
                return
            result["checked"] += 1
            result["rdap"] += any(c[0] == "rdap" for c in up.checks)
            result["takedowns"] += 1 if up.takedown else 0

    headers = {"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"}
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), headers=headers, follow_redirects=False,
                                 limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)) as client:
        rdap.client = client
        try:
            for kind in ("dns", "ipv4", "ipv6"):
                try:
                    await rdap.ensure_bootstrap(kind)
                except Exception:
                    ctx.log.exception("RDAP bootstrap %s failed", kind)
            await asyncio.gather(*(one(d) for d in rows))
        finally:
            rdap.client = None
    return result
