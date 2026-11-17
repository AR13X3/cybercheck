"""DNS blocklist: picks the domains to block and writes hosts / AdGuard / dnsmasq / unbound / RPZ / JSON files.

Selection, re-evaluated on every build:
  listed   status 'confirmed', or status 'open' with final_score >= BLOCKLIST_MIN_FINAL_SCORE (never below
           90: cybercheck/confidence.py caps final_score at NO_EVIDENCE_CAP = 89 unless the domain's own page
           asks for credentials and the AI says phishing) and an AI 'phishing' verdict with confidence >= 0.7
  never    status false_positive / benign, the manual exclusion flag (domains.blocklist_excluded, set on
           the /blocklist page), official domains on the watchlist, *.gov.au, public suffixes, anything
           that is not a plain ASCII DNS name (the files are read by DNS software), and domains found in
           ICANN CZDS zone files unless BLOCKLIST_CZDS_TERMS_OK=yes (CZDS terms s1.6, see below)
  scope    the whole registrable domain (every subdomain too) only when the registrable name itself
           impersonates a brand. Otherwise only the hostnames seen in certificates are listed, never the
           registrable domain itself:
             - the brand appears only in a subdomain (commbank-login.weebly.com, a kit on a hacked site
               such as netbank-login.someplumber.com.au): blocking weebly.com or someplumber.com.au would
               block every other site on the platform, or a real business and its mail;
             - the registrable domain is a shared hosting platform (SHARED_PLATFORMS), PSL or not;
             - for automated (unreviewed) listings only: RDAP says it was registered more than
               OLD_DOMAIN_DAYS before CyberCheck first saw it (an established site, possibly compromised).
               Once a reviewer confirms it, a domain whose own name impersonates a brand is blocked whole.
           "Its own name impersonates a brand": the bare registrable name, re-scored with the watchlist,
           matches a brand in the registrable label (see brand_in_name).
           Bare infrastructure names (www, mail, cpanel, ...) of such a domain are left out too. With no
           hostname left, the domain is not listed at all.
  expiry   blocklist_expires_at = max(day last seen live, listed since) + BLOCKLIST_DAYS. A site that is
           still live keeps its entry, but a 'live' flag only counts for LIVE_FRESH_DAYS after the last
           live sighting (a flag nobody re-checks must not keep an entry forever). An expired entry
           comes back only if the site is seen live again or a reviewer confirms it again after the expiry.

Files go to <data_dir>/blocklist, each written atomically (temp file + rename), and only when the list
changes, so the RPZ serial and the published git history move only on real changes.

Settings (env): BLOCKLIST_MIN_FINAL_SCORE, BLOCKLIST_DAYS (read by core config) and, read here:
  BLOCKLIST_HOMEPAGE        homepage shown in the file headers (default empty)
  BLOCKLIST_CONTACT         contact for false-positive reports shown in the headers (default empty)
  BLOCKLIST_LICENSE         license line in the headers (default "not yet decided")
  BLOCKLIST_BUILD_INTERVAL  seconds between scheduled full builds (default 600); review changes and
                            the dashboard buttons trigger a build sooner
  BLOCKLIST_CZDS_TERMS_OK   "yes" lists domains whose source is CZDS. The CZDS terms (s1.6) allow
                            redistributing zone-derived names only in a value-added product whose licence
                            forbids recipients the s1.1 uses (marketing, high-volume queries to registries
                            and registrars). Set it only once BLOCKLIST_LICENSE says so. Default: CZDS
                            domains are held back, and the build summary counts them (held_czds).
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from . import db
from .config import settings

log = logging.getLogger("cybercheck.blocklist")

TITLE = "CyberCheck Australian phishing blocklist"
DESCRIPTION = "Phishing domains impersonating Australian brands, found in Certificate Transparency logs."
FILES = ("hosts.txt", "adguard.txt", "domains.txt", "dnsmasq.conf", "unbound.conf", "rpz.zone", "blocklist.json")
FILE_INFO = {
    "hosts.txt": "hosts file (0.0.0.0), also lists known subdomains",
    "adguard.txt": "AdGuard Home / Pi-hole adlist (ABP syntax, blocks subdomains)",
    "domains.txt": "plain list, one domain per line (blocks subdomains too)",
    "dnsmasq.conf": "dnsmasq address= rules (IPv4 and IPv6)",
    "unbound.conf": "unbound local-zone rules (NXDOMAIN)",
    "rpz.zone": "DNS response policy zone for BIND / Knot / PowerDNS / Unbound",
    "blocklist.json": "metadata for each entry",
}
KV_STATE = "blocklist:state"          # last build: serial, digest, built_at, updated_at, counts
KV_REBUILD = "blocklist:rebuild"      # set to ask for a build soon (dashboard, other modules)
LOCK_KEY = 0x43430B10                 # pg advisory lock: one build at a time across processes
TRIGGER_EVENTS = ["status", "blocklist_excluded", "blocklist_included"]
NEVER_STATUSES = ("false_positive", "benign")
DEFAULT_LICENSE = "not yet decided"
MAX_HOSTS_PER_DOMAIN = 50
LIVE_FRESH_DAYS = 7                   # a 'live' flag older than this (since last_live_at) is not "still live"
# Contract with cybercheck/confidence.py: NO_EVIDENCE_CAP = 89 is the most a domain can score without
# credential fields on its own page plus an AI phishing verdict. Hard-coded (not imported) on purpose: no
# setting, and no change elsewhere, may let a name-only score onto the list.
SCORE_FLOOR = 90
AI_MIN_CONFIDENCE = 0.7               # same level cybercheck.confidence and automatic reports use
OLD_DOMAIN_DAYS = 365                 # registered this long before first seen: an established (compromised?) site
CZDS_REASON = "found in CZDS zone data (set BLOCKLIST_CZDS_TERMS_OK=yes once the licence forbids CZDS s1.1 uses)"

# Registrable domains whose subdomains belong to many unrelated customers. Blocking one of these as a whole
# would block every site on it, so only the hostnames seen are listed. Several are not in the PSL private
# section (then the registrable domain is the platform itself); the ones that are would normally be refused
# as public suffixes, and are listed in case the PSL copy in use lacks them.
SHARED_PLATFORMS = frozenset("""
    pages.dev workers.dev r2.dev github.io gitlab.io github.dev vercel.app now.sh netlify.app netlify.com
    firebaseapp.com web.app appspot.com herokuapp.com glitch.me repl.co replit.app replit.dev onrender.com
    fly.dev railway.app surge.sh ngrok.io ngrok-free.app ngrok.app trycloudflare.com cloudfront.net
    amplifyapp.com azurewebsites.net azureedge.net azurestaticapps.net web.core.windows.net
    blob.core.windows.net s3.amazonaws.com storage.googleapis.com firebasestorage.googleapis.com
    blogspot.com blogger.com wixsite.com wix.com wixstudio.io weebly.com weeblysite.com wordpress.com
    wpcomstaging.com sharepoint.com godaddysites.com site123.me zohosites.com zohosites.com.au
    hostingersite.com mystrikingly.com strikingly.com jimdosite.com jimdofree.com jimdo.com
    squarespace.com square.site webflow.io framer.app framer.website carrd.co notion.site tilda.ws
    yolasite.com webnode.page webnode.com ukit.me ucoz.net 000webhostapp.com byethost.com epizy.com
    infinityfreeapp.com rf.gd great-site.net cprapid.com typedream.app gitbook.io glide.page canva.site
    my.canva.site mailchimpsites.com business.site duckdns.org ddns.net hopto.org zapto.org
    sytes.net myftp.org no-ip.org no-ip.biz freeddns.org dynu.net ipfs.io dweb.link fleek.co
""".split())
# A bare one of these under a hostname-only domain is the site's own infrastructure, not a phishing host.
INFRA_LABELS = frozenset("""
    www mail webmail email smtp imap pop pop3 mx autodiscover autoconfig cpanel whm webdisk cpcalendars
    cpcontacts ftp ns1 ns2 ns3 ns4 vpn remote owa
""".split())

_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


# ---- settings ---------------------------------------------------------------------------------
def _clean(value: str, limit: int = 200) -> str:
    """One printable line (env values end up in comment headers)."""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


def out_dir() -> Path:
    return settings().data_dir / "blocklist"


def build_interval() -> float:
    try:
        return max(60.0, float(os.environ.get("BLOCKLIST_BUILD_INTERVAL", "600")))
    except ValueError:
        return 600.0


@dataclass(frozen=True)
class BuildConfig:
    min_final_score: int = SCORE_FLOOR
    days: int = 90
    homepage: str = ""
    contact: str = ""
    license: str = DEFAULT_LICENSE
    out_dir: Path = Path("data/blocklist")
    czds_ok: bool = False             # BLOCKLIST_CZDS_TERMS_OK=yes

    def __post_init__(self):
        # never below the floor, however the config was made (a value above 100 lists confirmed domains only)
        object.__setattr__(self, "min_final_score", max(SCORE_FLOOR, int(self.min_final_score)))

    @classmethod
    def from_env(cls) -> "BuildConfig":
        s = settings()
        return cls(min_final_score=s.blocklist_min_final_score, days=max(1, s.blocklist_days),
                   homepage=_clean(os.environ.get("BLOCKLIST_HOMEPAGE", "")),
                   contact=_clean(os.environ.get("BLOCKLIST_CONTACT", "")),
                   license=_clean(os.environ.get("BLOCKLIST_LICENSE", "")) or DEFAULT_LICENSE,
                   out_dir=out_dir(),
                   czds_ok=os.environ.get("BLOCKLIST_CZDS_TERMS_OK", "").strip().lower() == "yes")


# ---- rules ------------------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _psl():
    from . import scoring
    existing = getattr(scoring, "_psl", None)   # reuse the instance scoring already loaded
    if existing is not None:
        return existing
    from publicsuffixlist import PublicSuffixList
    return PublicSuffixList()


def valid_name(name) -> bool:
    """Lower-case ASCII hostname with at least two labels: safe to write into any of the formats."""
    if not isinstance(name, str) or not name or len(name) > 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_LABEL.fullmatch(label) for label in labels)


def is_public_suffix(name: str) -> bool:
    return _psl().privatesuffix(name) is None


_official_parents: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def covers_official(name: str, watchlist) -> bool:
    """True if blocking `name` would also block an official domain: the name is official itself, sits
    under an official domain, or an official domain sits under it (e.g. official secure.host.com and
    candidate host.com: the AdGuard/dnsmasq/RPZ rules block every subdomain)."""
    if watchlist.is_official(name):
        return True
    try:
        parents = _official_parents[watchlist]
    except (KeyError, TypeError):
        parents = set()
        for official in getattr(watchlist, "official", {}) or {}:
            labels = official.split(".")
            parents.update(".".join(labels[i:]) for i in range(1, len(labels)))
        with contextlib.suppress(TypeError):
            _official_parents[watchlist] = parents
    return name in parents


def skip_reason(row: dict, cfg: BuildConfig, watchlist) -> str | None:
    """Why this domain must not be on the list right now (None = it qualifies)."""
    name = row.get("registered_domain") or ""
    status = row.get("status") or "open"
    if status in NEVER_STATUSES:
        return f"marked {status.replace('_', ' ')}"
    if row.get("blocklist_excluded"):
        return "excluded by a reviewer"
    if not valid_name(name):
        return "not a plain DNS name"
    if is_public_suffix(name):
        return "public suffix"
    if name == "gov.au" or name.endswith(".gov.au"):
        return "government domain"
    if covers_official(name, watchlist):
        return "official domain on the watchlist"
    if row.get("source") == "czds" and not cfg.czds_ok:
        return CZDS_REASON
    if status == "confirmed":
        return None
    if status != "open":
        return f"status {status}"
    floor = max(SCORE_FLOOR, cfg.min_final_score)
    score = row.get("final_score")
    if score is None or score < floor:
        return f"combined score below {floor}"
    conf = row.get("ai_confidence")
    if row.get("ai_verdict") != "phishing" or not isinstance(conf, (int, float)) or not conf >= AI_MIN_CONFIDENCE:
        return "no AI phishing verdict"   # defence in depth: confidence.py already caps such scores at 89
    return None


@dataclass(frozen=True)
class Scope:
    """What to block for a domain that qualifies."""
    wildcard: bool                    # True: the registrable domain and every name under it
    hosts: tuple[str, ...] = ()       # wildcard: extra hostnames for hosts.txt; else the only names listed
    why: str = ""                     # why only hostnames are listed


def brand_in_name(name: str, watchlist) -> bool:
    """The registrable name on its own impersonates a brand (commbank-login.top), as opposed to the brand
    showing up only in a subdomain (commbank-login.weebly.com, netbank.someplumber.com.au).

    Deliberately the bare name only: when it does not score alone (nab.top, mygov.top, bendigo-plumbing.com.au,
    whose short or common brand words need bait or AU context that only a subdomain supplied), the registrable
    domain may well belong to someone else (nab.org, a Bendigo business), and an attacker on a hacked site
    must not get the whole of it blocked by choosing a subdomain name. Only the hostnames seen are listed."""
    try:
        hit = watchlist.score_hostname(name)
    except Exception:  # noqa: BLE001 - unknown means hostnames only, the safe side
        log.exception("could not score %s; listing hostnames only", name)
        return False
    return hit is not None and (getattr(hit, "match", None) or {}).get("location") == "reg"


def registered_long_before_seen(row: dict) -> int | None:
    """Days between the RDAP registration date and CyberCheck's first sighting, when that is more than
    OLD_DOMAIN_DAYS (None when it is not, or the dates are unknown, e.g. .au, which is never queried)."""
    registered, first = row.get("registered_at"), row.get("first_seen")
    if not isinstance(registered, datetime) or not isinstance(first, datetime):
        return None
    try:
        days = (first - registered).days
    except TypeError:  # naive and aware timestamps mixed
        return None
    return days if days > OLD_DOMAIN_DAYS else None


def scope(row: dict, watchlist) -> Scope:
    name = row["registered_domain"]
    seen = _hostnames(row, name)
    if name in SHARED_PLATFORMS:
        why = "shared hosting platform"
    elif not brand_in_name(name, watchlist):
        why = "the brand appears only in a subdomain (shared or compromised site)"
    # Automated listings only. A domain whose own name impersonates a brand and that a reviewer confirmed is
    # blocked whole however old it is: lookalikes held for years, or bought aged, are common, and listing
    # only its subdomains would leave the apex (where the kit usually sits) unblocked.
    elif row.get("status") != "confirmed" and (days := registered_long_before_seen(row)) is not None:
        why = f"registered {days} days before it was first seen (an established site, possibly compromised)"
    else:
        return Scope(True, tuple(seen))
    hosts = tuple(h for h in seen if h[: -len(name) - 1] not in INFRA_LABELS)
    return Scope(False, hosts, why)


def _day(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def is_live(row: dict) -> bool:
    """The fetcher saw it live and nothing since says it is gone."""
    takedown, last_live = row.get("takedown_at"), row.get("last_live_at")
    if row.get("live_state") != "live" or row.get("dns_state") == "nxdomain" or last_live is None:
        return False
    return not (takedown and takedown >= last_live)


def expiry(row: dict, listed_at: datetime, now: datetime, days: int) -> datetime:
    """Day granularity for the live times: the fetcher updates last_live_at on every check, and the
    files (RPZ serial, published git history) should not change each time it does."""
    last_live = row.get("last_live_at")
    refs = [listed_at]
    if last_live is not None:
        refs.append(_day(last_live))
        if is_live(row):  # still up: keep it, but a flag nobody re-checks only counts for LIVE_FRESH_DAYS
            refs.append(_day(min(now, last_live + timedelta(days=LIVE_FRESH_DAYS))))
    return max(refs) + timedelta(days=days)


def _relist_after_expiry(row: dict, prev_expires: datetime) -> bool:
    # Not is_live(): a stale 'live' flag would re-add the entry with a fresh listing on every build.
    # A site that really is live gets a new last_live_at from the fetcher, which counts here.
    last_live, changed = row.get("last_live_at"), row.get("status_changed_at")
    return ((last_live is not None and last_live > prev_expires)
            or (row.get("status") == "confirmed" and changed is not None and changed > prev_expires))


@dataclass
class Entry:
    id: int
    name: str
    brand: str
    first_seen: datetime | None
    listed_since: datetime
    expires: datetime
    via: str                 # confirmed | score
    final_score: int | None
    hostnames: list[str] = field(default_factory=list)
    wildcard: bool = True    # False: only `hostnames` are listed, never the registrable domain itself
    scope_note: str = ""     # why only hostnames

    @property
    def reason(self) -> str:
        if self.via == "confirmed":
            return "confirmed phishing by a human reviewer"
        return f"automated detection, combined confidence {self.final_score}/100"

    @property
    def names(self) -> list[str]:
        """Names blocked with their subdomains (AdGuard, dnsmasq, unbound, RPZ, domains.txt)."""
        return [self.name] if self.wildcard else list(self.hostnames)


@dataclass
class Plan:
    entries: list[Entry] = field(default_factory=list)                         # the new list
    added: list[Entry] = field(default_factory=list)
    updated: list[Entry] = field(default_factory=list)                         # still listed, new expiry
    removed: list[tuple[dict, str, datetime | None]] = field(default_factory=list)  # row, reason, expiry to keep
    held_czds: int = 0                                                         # qualify, but CZDS terms not set


def _brand_name(watchlist, brand_id) -> str:
    brand = getattr(watchlist, "brands", {}).get(brand_id) if brand_id else None
    return brand.name if brand is not None else (brand_id or "")


def _hostnames(row: dict, name: str) -> list[str]:
    out = {h for h in (row.get("hostnames") or [])[:MAX_HOSTS_PER_DOMAIN]
           if isinstance(h, str) and h != name and h.endswith("." + name) and valid_name(h)}
    return sorted(out)


def plan(rows, now: datetime, cfg: BuildConfig, watchlist) -> Plan:
    p = Plan()
    for row in rows:
        listed = bool(row.get("blocklisted"))
        why_not = skip_reason(row, cfg, watchlist)
        sc = None
        if not why_not:
            sc = scope(row, watchlist)
            if not sc.wildcard and not sc.hosts:
                why_not = f"{sc.why}: no hostname of its own to list"
        if why_not:
            p.held_czds += why_not == CZDS_REASON
            if listed:
                p.removed.append((row, why_not, None))
            continue
        if listed:
            listed_at = row.get("blocklist_listed_at") or now
        else:
            prev = row.get("blocklist_expires_at")
            if prev is not None and prev <= now and not _relist_after_expiry(row, prev):
                continue  # expired earlier and nothing new since
            listed_at = now
        expires = expiry(row, listed_at, now, cfg.days)
        if expires <= now:
            if listed:
                p.removed.append((row, "expired", expires))
            continue
        name = row["registered_domain"]
        entry = Entry(id=row["id"], name=name, brand=_brand_name(watchlist, row.get("brand_id")),
                      first_seen=row.get("first_seen"), listed_since=listed_at, expires=expires,
                      via="confirmed" if row.get("status") == "confirmed" else "score",
                      final_score=row.get("final_score"), hostnames=list(sc.hosts), wildcard=sc.wildcard,
                      scope_note=sc.why)
        p.entries.append(entry)
        if not listed:
            p.added.append(entry)
        elif row.get("blocklist_listed_at") is None or row.get("blocklist_expires_at") != expires:
            p.updated.append(entry)
    p.entries.sort(key=lambda e: e.name)
    return p


# ---- rendering --------------------------------------------------------------------------------
def _iso(ts: datetime | None) -> str | None:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def next_serial(prev, now: datetime) -> int:
    """SOA serial YYYYMMDDNN, always increasing (more than 99 changes in a day spill into the next number)."""
    base = int(now.astimezone(timezone.utc).strftime("%Y%m%d")) * 100 + 1
    try:
        prev = int(prev)
    except (TypeError, ValueError):
        return base
    return max(base, prev + 1)


def _header(mark: str, fmt: str, cfg: BuildConfig, updated: datetime, count: int, extra=()) -> list[str]:
    lines = [f"Title: {TITLE}", DESCRIPTION, f"Format: {fmt}",
             f"Updated: {updated.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S} UTC", f"Entries: {count}",
             f"Homepage: {cfg.homepage}", f"Contact: {cfg.contact}", f"License: {cfg.license}",
             f"Entries expire {cfg.days} days after the site was last seen live or listed.", *extra]
    return [f"{mark} {line}".rstrip() for line in lines]


def _text(header: list[str], body: list[str]) -> str:
    return "\n".join(header + [""] + body) + "\n"


def render(entries: list[Entry], cfg: BuildConfig, updated: datetime, serial: int) -> dict[str, str]:
    """Wildcard entries block the registrable domain and all its subdomains. Hostname-only entries block
    just the hostnames seen (and names under them), so the registrable domain itself is never in a file."""
    entries = sorted(entries, key=lambda e: e.name)
    names = sorted({x for e in entries for x in e.names})
    n = len(names)
    hosts = sorted({h for e in entries for h in ((e.name, *e.hostnames) if e.wildcard else e.hostnames)})
    files = {
        "hosts.txt": _text(_header("#", "hosts", cfg, updated, n, [
            f"Hosts lines: {len(hosts)} (each domain plus subdomains seen in certificates; "
            "hosts files cannot block other subdomains)"]), [f"0.0.0.0 {h}" for h in hosts]),
        "adguard.txt": _text(_header("!", "Adblock-style (AdGuard Home, Pi-hole)", cfg, updated, n),
                             [f"||{x}^" for x in names]),
        "domains.txt": _text(_header("#", "plain domains (block subdomains too)", cfg, updated, n), names),
        "dnsmasq.conf": _text(_header("#", "dnsmasq", cfg, updated, n),
                              [line for x in names for line in (f"address=/{x}/0.0.0.0", f"address=/{x}/::")]),
        "unbound.conf": _text(_header("#", "unbound (include from unbound.conf)", cfg, updated, n),
                              ["server:"] + [f'  local-zone: "{x}." always_nxdomain' for x in names]),
        "rpz.zone": _text(_header(";", "RPZ zone file (load under any zone name, e.g. rpz.cybercheck)", cfg, updated, n),
                          ["$TTL 300",
                           f"@ IN SOA localhost. hostmaster.localhost. ( {serial} 3600 600 604800 300 )",
                           "@ IN NS localhost.", ""]
                          + [line for x in names for line in (f"{x} CNAME .", f"*.{x} CNAME .")]),
    }
    meta = {
        "title": TITLE, "description": DESCRIPTION, "updated": _iso(updated), "count": n,
        "homepage": cfg.homepage, "contact": cfg.contact, "license": cfg.license, "expiry_days": cfg.days,
        "entries": [{"domain": x, **({"scope": "domain"} if e.wildcard else
                                     {"scope": "hostname", "registered_domain": e.name}),
                     "brand": e.brand, "first_seen": _iso(e.first_seen), "listed_since": _iso(e.listed_since),
                     "expires": _iso(e.expires), "reason": e.reason}
                    for e in entries for x in e.names],
    }
    files["blocklist.json"] = json.dumps(meta, indent=1, ensure_ascii=False) + "\n"
    return files


def digest(entries: list[Entry], cfg: BuildConfig) -> str:
    data = [cfg.homepage, cfg.contact, cfg.license, cfg.days] + [
        [e.name, e.brand, _iso(e.first_seen), _iso(e.listed_since), _iso(e.expires), e.reason, e.hostnames,
         e.wildcard]
        for e in sorted(entries, key=lambda e: e.name)]
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def hostname_only_entries(directory: Path) -> dict[str, list[str]]:
    """{registered_domain: [hostnames]} for the entries the last build listed by hostname only (from
    blocklist.json; {} when it is missing or unreadable). For the dashboard."""
    out: dict[str, list[str]] = {}
    try:
        meta = json.loads((directory / "blocklist.json").read_text(encoding="utf-8"))
        for item in meta.get("entries") or []:
            if isinstance(item, dict) and item.get("scope") == "hostname":
                out.setdefault(str(item.get("registered_domain")), []).append(str(item.get("domain")))
    except (OSError, ValueError, AttributeError):
        return {}
    return out


def files_present(directory: Path) -> bool:
    return all((directory / name).is_file() for name in FILES)


def write_files(directory: Path, files: dict[str, str]) -> None:
    """Write each file atomically: temp file in the same directory, fsync, rename over the old one."""
    unknown = set(files) - set(FILES)
    if unknown:
        raise ValueError(f"not a blocklist file: {sorted(unknown)}")
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob(".*.tmp"):   # left over from a crash
        with contextlib.suppress(OSError):
            stale.unlink()
    for name, text in files.items():
        fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, directory / name)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


# ---- database ---------------------------------------------------------------------------------
SELECT_SQL = """
SELECT id, registered_domain, brand_id, status, status_changed_at, final_score, ai_verdict, ai_confidence,
       source, first_seen, registered_at, hostnames, live_state, last_live_at, dns_state, takedown_at,
       blocklisted, blocklist_expires_at, blocklist_listed_at, blocklist_excluded
FROM domains
WHERE blocklisted
   OR (NOT blocklist_excluded AND (status = 'confirmed' OR (status = 'open' AND final_score >= %(min)s)))
ORDER BY id
"""

# Guarded: a review or exclusion that lands while we build must win over a new listing.
LIST_SQL = ("UPDATE domains SET blocklisted = true, blocklist_listed_at = %s, blocklist_expires_at = %s "
            "WHERE id = %s AND NOT blocklist_excluded AND status NOT IN ('false_positive', 'benign') RETURNING id")
EXTEND_SQL = "UPDATE domains SET blocklist_listed_at = %s, blocklist_expires_at = %s WHERE id = %s"
UNLIST_SQL = "UPDATE domains SET blocklisted = false, blocklist_expires_at = %s WHERE id = %s"


def parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


async def request_rebuild(conn, reason: str = "", by: str | None = None) -> None:
    """Ask for a build soon (the worker checks every minute). Safe to call from any module."""
    await db.kv_set(conn, KV_REBUILD, {"reason": _clean(reason or ""), "by": by})


async def rebuild_reason(conn, cfg: BuildConfig, interval: float) -> str | None:
    """Cheap check (two small queries) whether a build is due; None = nothing to do."""
    row = await (await conn.execute(
        "SELECT now() AS now, (SELECT value FROM kv WHERE key = %s) AS state, "
        "(SELECT updated_at FROM kv WHERE key = %s) AS requested", (KV_STATE, KV_REBUILD))).fetchone()
    built = parse_ts((row["state"] or {}).get("built_at"))
    if built is None:
        return "first build"
    if row["requested"] is not None:
        return "requested"
    if (row["now"] - built).total_seconds() >= interval:
        return "scheduled"
    if not files_present(cfg.out_dir):
        return "files missing"
    ev = await (await conn.execute(
        "SELECT EXISTS (SELECT 1 FROM domain_events WHERE kind = ANY(%s) AND at > %s) AS changed",
        (TRIGGER_EVENTS, built))).fetchone()
    return "review change" if ev["changed"] else None


async def build(conn, *, cfg: BuildConfig | None = None, watchlist=None, trigger: str = "manual") -> dict | None:
    """Rebuild the list in one transaction. Returns a summary, or None if another build holds the lock.

    The database is only updated if the files were written, so the two never disagree for long.
    """
    cfg = cfg or BuildConfig.from_env()
    if watchlist is None:  # an unreadable watchlist raises here: never publish without the official check
        from .scoring import default_watchlist
        watchlist = await asyncio.to_thread(default_watchlist)   # first load is slow: keep the loop free
    async with conn.transaction():
        lock = await (await conn.execute("SELECT pg_try_advisory_xact_lock(%s) AS locked, now() AS now",
                                         (LOCK_KEY,))).fetchone()
        if not lock["locked"]:
            return None
        now = lock["now"]
        state = await db.kv_get(conn, KV_STATE, None) or {}
        rows = await (await conn.execute(SELECT_SQL, {"min": max(SCORE_FLOOR, cfg.min_final_score)})).fetchall()
        p = plan(rows, now, cfg, watchlist)
        del rows

        skipped: set[int] = set()
        for e in p.added:
            ok = await (await conn.execute(LIST_SQL, (e.listed_since, e.expires, e.id))).fetchone()
            if not ok:
                skipped.add(e.id)
                continue
            detail = {"reason": e.reason, "via": e.via, "final_score": e.final_score,
                      "expires": _iso(e.expires), "trigger": trigger,
                      "scope": "domain" if e.wildcard else "hostnames"}
            if not e.wildcard:
                detail.update(hostnames=e.hostnames[:10], scope_note=e.scope_note)
            await db.add_event(conn, e.id, "blocklisted", detail)
        for e in p.updated:
            await conn.execute(EXTEND_SQL, (e.listed_since, e.expires, e.id))
        for row, reason, keep_expiry in p.removed:
            await conn.execute(UNLIST_SQL, (keep_expiry, row["id"]))
            await db.add_event(conn, row["id"], "unblocklisted", {"reason": reason, "trigger": trigger})
        entries = [e for e in p.entries if e.id not in skipped]

        dig = digest(entries, cfg)
        rewrite = dig != state.get("digest") or not files_present(cfg.out_dir)
        serial, updated_at = state.get("serial"), state.get("updated_at")
        if rewrite:
            serial = next_serial(serial, now)
            files = render(entries, cfg, now, serial)
            await asyncio.to_thread(write_files, cfg.out_dir, files)
            updated_at = now.isoformat()
        summary = {
            "listed": len(entries), "confirmed": sum(e.via == "confirmed" for e in entries),
            "automated": sum(e.via == "score" for e in entries),
            "added": len(p.added) - len(skipped), "removed": len(p.removed),
            "hostnames_only": sum(not e.wildcard for e in entries), "held_czds": p.held_czds,
            "files_written": rewrite, "serial": serial, "trigger": trigger,
        }
        await db.kv_set(conn, KV_STATE, {**summary, "digest": dig, "built_at": now.isoformat(),
                                         "updated_at": updated_at})
        # clear a rebuild request made before this build started (a later one stays for the next run)
        await conn.execute("DELETE FROM kv WHERE key = %s AND updated_at <= %s", (KV_REBUILD, now))
    if summary["added"] or summary["removed"]:
        log.info("blocklist: %d listed (+%d, -%d), serial %s", summary["listed"], summary["added"],
                 summary["removed"], serial)
    return summary


async def build_now(trigger: str, by: str | None = None) -> dict:
    """Build from the dashboard. Never raises: on failure or a busy lock it leaves a rebuild request
    for the worker and says so in the result ({'busy': True} or {'error': ...})."""
    try:
        p = await db.pool()
        async with p.connection() as conn:
            result = await build(conn, trigger=trigger)
            if result is None:
                await request_rebuild(conn, trigger, by)
                return {"busy": True}
            return result
    except Exception as e:
        log.exception("blocklist build failed")
        with contextlib.suppress(Exception):
            p = await db.pool()
            async with p.connection() as conn:
                await request_rebuild(conn, trigger, by)
        return {"error": f"{type(e).__name__}: {e}"[:300]}
