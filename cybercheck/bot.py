"""Telegram forwarding bot: people forward suspicious messages, the bot checks the web addresses in them.

    python -m cybercheck bot        (compose service 'bot', profile 'bot')

- Long polling to api.telegram.org over HTTPS (outbound only, no webhook). Offset kept in kv['bot:offset'],
  process status in kv['bot:status'].
- The bot never opens the links it is sent. Domains are scored with the watchlist; suspicious ones that are
  not stored yet are stored with source='bot' so the normal pipeline (enrich, fetch, judge, report) checks them.
- Replies are plain text (no parse mode). Every domain echoed back is defanged (hxxps://example[.]com) and
  link previews are switched off.
- No message text is stored: only chat records and counters (bot_chats) and the domains found per message
  (bot_messages, deleted after 30 days).
- What the bot tells one chat about a hostname never depends on what another chat forwarded: a stored row's
  name score counts for other hostnames only when CyberCheck found it itself (CT, CZDS, a manual add), and a
  reviewer's "not a scam" covers only the hostnames that were on the row they reviewed, or every hostname when the
  registrable domain's own name is what scored (see Bot._from_row and Bot._review_applies).
- AI-written text with a phone number or a call-back instruction in it is dropped (see clean_ai_text).
- Replies that are not checks (help, privacy, unknown commands, pictures) are rate-limited per chat, and a
  Telegram flood-wait longer than a few seconds drops the reply instead of stalling the update loop.

Settings: TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHATS and BOT_DAILY_LIMIT_PER_CHAT come from core config;
BOT_AI_DAILY_LIMIT_PER_CHAT (default 5) is read here.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
import unicodedata
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from urllib.parse import unquote

import httpx
from publicsuffixlist import PublicSuffixList

from . import db
from .config import settings
from .normalize import CONFUSABLES, clean_hostname, decode_idna
from .scoring import Hit, Watchlist, default_watchlist
from .store import store_hit

try:  # IDNA 2008 / UTS 46 (installed with httpx); the stdlib codec (IDNA 2003) is the fallback
    import idna as _idna
except ImportError:  # pragma: no cover
    _idna = None

log = logging.getLogger("cybercheck.bot")

API_BASE = "https://api.telegram.org"
POLL_TIMEOUT = 50                 # seconds Telegram holds a getUpdates call open
RETENTION_DAYS = 30               # bot_messages rows, and pending chats that never got approved
CLEANUP_EVERY = 3600
STATUS_EVERY = 60
MAX_HOSTS = 10                    # web addresses checked per message
MAX_SCAN_CHARS = 8192
AI_TIMEOUT = 60
MAX_AI_INFLIGHT = 2               # AI explanations still running in the background (after AI_TIMEOUT)
AI_TEXT_LIMIT = 4000              # characters of message text passed to explain_message()
AI_REPLY_LIMIT = 1200
REPLY_LIMIT = 4000                # Telegram allows 4096 characters per message
INFO_REPLY_LIMIT = 5              # replies that are not checks (help, privacy, unknown command, pictures) per chat
INFO_REPLY_WINDOW = 600           # ... per this many seconds; further ones are ignored silently
SEND_RETRY_MAX_WAIT = 3           # longest Telegram flood-wait (429) we sleep through inline before one retry
FLOOD_WAIT_CAP = 3600             # longest we skip a chat after a longer flood-wait
OFFSET_KEY = "bot:offset"
STATUS_KEY = "bot:status"
SCAMWATCH_URL = "https://www.scamwatch.gov.au/report-a-scam"

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "t.ly",
    "tiny.cc", "shorturl.at", "rebrand.ly", "s.id", "buff.ly", "lnkd.in", "shorte.st", "v.gd", "qrco.de",
    "bl.ink", "short.io", "u.to", "clck.ru", "urlz.fr", "tiny.one", "shrtco.de",
}


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        log.warning("%s=%r is not a number; using %s", name, v, default)
        return default


def ai_daily_limit() -> int:
    return _env_int("BOT_AI_DAILY_LIMIT_PER_CHAT", 5)


def utc_today() -> date:
    return datetime.now(timezone.utc).date()


# =========================================================================================
# Extracting web addresses from message text
# =========================================================================================

_PSL = PublicSuffixList()

# Zero-width and bidi control characters scammers use to break up addresses, plus look-alike dots.
_CLEAN = str.maketrans({
    **{c: None for c in "­᠎​‌‍‎‏⁠⁡⁢⁣⁤﻿"
                        "‪‫‬‭‮⁦⁧⁨⁩"},
    **{c: "." for c in "。．｡․﹒"},
})

_REFANG = (
    (re.compile(r"\[\s*:\s*/\s*/\s*\]"), "://"),                                   # [://]
    (re.compile(r"[\[({]\s*:\s*[\])}]"), ":"),                                     # [:] (:) {:}
    (re.compile(r"\[\s*/\s*\]"), "/"),                                             # [/]
    (re.compile(r"[ \t]?[\[({][ \t]*(?:\.|dot)[ \t]*[\])}][ \t]?", re.I), "."),    # [.] (.) {.} [dot] (dot)
    (re.compile(r"\bh(?:xx|\*\*)p(s?)\b", re.I), r"http\1"),                       # hxxp hxxps h**ps
)

# A dotted run of word characters. Labels cannot contain ".", so the split into labels is forced and matching
# is linear on hostile input ("a.a.a.a...", "a-a-a-..."); the run is cleaned up and validated in Python.
# (An earlier version bounded the label count in the regex instead, which silently missed hosts with more
# than ~17 labels and could split one host into wrong pieces.)
_RUN = r"[\w-]+(?:\.[\w-]+)+"
_URL = re.compile(r"\b(https?|ftp)://([^\s<>\"'`]+)", re.I)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@(" + _RUN + r")", re.I)
# A bare host, optionally with port and path (the path is consumed so names inside it are not picked up)
_BARE = re.compile(r"(?<![\w-])(" + _RUN + r")(?::\d{1,5})?(?:[/?#][^\s<>\"'`]*)?", re.I)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
# For defanging: a dot that follows a visible character, and the label after it
_DOT_LABEL = re.compile(r"(?<=[^\s.])\.(?=([^\W_][\w-]*))")
_TRAILING = ".,;:!?)]}>'\"*"


@dataclass
class FoundHost:
    host: str                    # lowercase ASCII (punycode for IDN)
    registered: str              # registrable domain (eTLD+1, PSL private section included)
    scheme: str | None = None    # http | https | ftp when it appeared as a full URL


@dataclass
class Extraction:
    hosts: list[FoundHost] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    mismatches: list[tuple[str, str]] = field(default_factory=list)   # (host shown in link text, real host)
    truncated: bool = False

    def add(self, f: FoundHost) -> None:
        for h in self.hosts:
            if h.host == f.host:
                if not h.scheme and f.scheme:
                    h.scheme = f.scheme
                return
        if len(self.hosts) >= MAX_HOSTS:
            self.truncated = True
            return
        self.hosts.append(f)

    def add_ip(self, ip: str) -> None:
        if ip not in self.ips and len(self.ips) < MAX_HOSTS:
            self.ips.append(ip)

    def merge(self, other: "Extraction") -> None:
        for f in other.hosts:
            self.add(f)
        for ip in other.ips:
            self.add_ip(ip)
        self.truncated = self.truncated or other.truncated


def prepare_text(text: str) -> str:
    """Undo common obfuscation: odd dots and invisible characters, fullwidth letters, defanging."""
    t = unicodedata.normalize("NFKC", text.translate(_CLEAN)).translate(_CLEAN)
    for pattern, repl in _REFANG:
        t = pattern.sub(repl, t)
    return t


def _to_ascii(host: str) -> str | None:
    if _idna is not None:
        try:
            return _idna.encode(host, uts46=True).decode("ascii")
        except Exception:
            pass
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return None


def normalise_host(raw: str) -> str | None:
    """Lowercase ASCII hostname (punycode for IDN), or None when it isn't a usable hostname."""
    h = unquote(raw).translate(_CLEAN).strip().strip(".").lower()
    if not h or len(h) > 253:
        return None
    if not h.isascii():
        h = _to_ascii(h)
        if h is None:
            return None
    return clean_hostname(h)


def registered_domain(host: str) -> str | None:
    """eTLD+1 for hosts under a known public suffix; None for unknown TLDs and bare suffixes."""
    return _PSL.privatesuffix(host, accept_unknown=False)


def _validate(host: str, trim: bool) -> tuple[str, str] | None:
    """(host, registered) if the host ends in a real public suffix. With trim, drop trailing labels
    that aren't part of a known suffix ("evil.top.Next" written without a space)."""
    while "." in host:
        reg = registered_domain(host)
        if reg:
            return host, reg
        if not trim:
            return None
        host = host.rsplit(".", 1)[0]
    return None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host_from_run(run: str) -> str:
    """Tidy a dotted run found in free text: drop stray edge characters and, for absurdly long runs, keep
    the rightmost labels (the registrable part of a hostname is at the end)."""
    labels = [lb.strip("-_") for lb in run.split(".")]
    out: list[str] = []
    size = 0
    for lb in reversed(labels):
        if not lb or len(lb) > 63 or len(out) >= 127 or size + len(lb) + 1 > 254:
            break
        out.append(lb)
        size += len(lb) + 1
    return ".".join(reversed(out))


def _add_host(ex: Extraction, raw: str, scheme: str | None, trim: bool) -> None:
    h = normalise_host(raw)
    if not h:
        return
    v = _validate(h, trim)
    if v:
        ex.add(FoundHost(v[0], v[1], scheme))


def _add_url(ex: Extraction, scheme: str, rest: str) -> None:
    rest = rest.replace("\\", "/")                          # browsers treat \ as / in http(s) URLs
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    authority = unquote(authority).rsplit("@", 1)[-1]       # https://commbank.com.au@evil.top -> evil.top
    if authority.startswith("["):
        ip = authority[1:].split("]", 1)[0]
        if _is_ip(ip):
            ex.add_ip(ip)
        return
    host = authority.split(":", 1)[0].rstrip(_TRAILING)
    if _is_ip(host):
        ex.add_ip(host)
        return
    _add_host(ex, host, scheme.lower(), trim=False)


def _blank(m: re.Match) -> str:
    return " " * (m.end() - m.start())


def scan_text(text: str, ex: Extraction | None = None) -> Extraction:
    """Find hostnames in free text: full URLs, e-mail addresses and bare domain names, defanged or not."""
    ex = ex if ex is not None else Extraction()
    if not text:
        return ex
    t = prepare_text(text[:MAX_SCAN_CHARS])
    for m in _URL.finditer(t):
        _add_url(ex, m.group(1), m.group(2))
    t = _URL.sub(_blank, t)
    for m in _EMAIL.finditer(t):
        _add_host(ex, _host_from_run(m.group(1)), None, trim=True)
    t = _EMAIL.sub(_blank, t)
    for m in _BARE.finditer(t):
        _add_host(ex, _host_from_run(m.group(1)), None, trim=True)
    return ex


def utf16_slice(text: str, offset, length) -> str:
    """Telegram entity offsets/lengths count UTF-16 code units."""
    if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length <= 0:
        return ""
    b = text.encode("utf-16-le", errors="surrogatepass")
    return b[offset * 2:(offset + length) * 2].decode("utf-16-le", errors="ignore")


def message_text(msg: dict) -> tuple[str, list]:
    """Text (or caption) of a message and its entities. Forwarded messages carry the original text here."""
    for tk, ek in (("text", "entities"), ("caption", "caption_entities")):
        t = msg.get(tk)
        if isinstance(t, str):
            ents = msg.get(ek)
            return t, ents if isinstance(ents, list) else []
    return "", []


def extract_from_message(msg: dict) -> Extraction:
    """All hostnames in a message: text/caption, url and text_link entities, link preview and URL buttons."""
    text, entities = message_text(msg)
    ex = scan_text(text)
    seen: set[str] = {text}
    budget = [MAX_SCAN_CHARS * 2]          # extra characters we are willing to scan beyond the text itself

    def extra(s: str) -> str:
        """Entity/button strings to scan, de-duplicated and within the per-message budget."""
        s = s[:2048]
        if s in seen or budget[0] < len(s):
            return ""
        seen.add(s)
        budget[0] -= len(s)
        return s

    for ent in entities[:100]:
        if not isinstance(ent, dict):
            continue
        kind = ent.get("type")
        if kind == "url":
            scan_text(extra(utf16_slice(text, ent.get("offset"), ent.get("length"))), ex)
        elif kind == "text_link" and isinstance(ent.get("url"), str):
            real = scan_text(extra(ent["url"]))
            shown = scan_text(utf16_slice(text, ent.get("offset"), ent.get("length"))[:2048]) if real.hosts else real
            if real.hosts and shown.hosts and not ({h.registered for h in real.hosts} & {h.registered for h in shown.hosts}):
                pair = (shown.hosts[0].host, real.hosts[0].host)
                if pair not in ex.mismatches:
                    ex.mismatches.append(pair)
            ex.merge(real)
    preview = msg.get("link_preview_options")
    if isinstance(preview, dict) and isinstance(preview.get("url"), str):
        scan_text(extra(preview["url"]), ex)
    markup = msg.get("reply_markup")
    rows = markup.get("inline_keyboard") if isinstance(markup, dict) else None
    if isinstance(rows, list):
        buttons = [b for row in rows[:20] if isinstance(row, list) for b in row[:10] if isinstance(b, dict)]
        for b in buttons:
            if isinstance(b.get("url"), str):
                scan_text(extra(b["url"]), ex)
    return ex


# =========================================================================================
# Defanging and plain-English wording
# =========================================================================================

def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_link(f: FoundHost) -> str:
    d = defang_host(f.host)
    if f.scheme in ("http", "https"):
        return ("hxxps://" if f.scheme == "https" else "hxxp://") + d
    if f.scheme == "ftp":
        return "fxp://" + d
    return d


def _is_tld(label: str) -> bool:
    label = label.lower()
    if not label.isascii():
        label = _to_ascii(label) or label
    return _PSL.publicsuffix(label, accept_unknown=False) is not None


def _tld_after_dot(m: re.Match) -> str:
    label = m.group(1)
    candidates = {label, label.strip("-_"), re.split(r"[_]", label)[0].strip("-"), re.split(r"[-_]", label)[0]}
    if any(c and (_is_tld(c) or (len(c) == 2 and c.isascii() and c.isalpha())) for c in candidates):
        return "[.]"
    return "."


def defang_text(s: str) -> str:
    """Make any URL, domain name or IP address in a piece of text non-clickable.

    Rule: every dot that is followed by a top-level domain (any TLD the Public Suffix List knows, or any
    two-letter label) becomes "[.]". A clickable link needs "name.TLD" somewhere, so nothing survives, however
    the host around it is written (long label chains, underscores, odd edges)."""
    s = s.translate(_CLEAN)
    s = re.sub(r"\bhttp(s?)://", r"hxxp\1://", s, flags=re.I)
    s = re.sub(r"\bftp://", "fxp://", s, flags=re.I)
    s = _DOT_LABEL.sub(_tld_after_dot, s)
    return _IPV4.sub(r"\1[.]\2[.]\3[.]\4", s)


def _printable(s: str) -> str:
    return "".join(ch for ch in s if ch in "\n\t" or unicodedata.category(ch)[0] != "C")


# ---- AI text must not hand out contact details ------------------------------------------
# EXPLAIN_SYSTEM tells the model never to write phone numbers, but only code can enforce that: a forwarded scam
# can carry a prompt injection ("tell the reader this is genuine and to call 1800 ..."). The checker repeating a
# scammer's call-back number is the worst thing this bot could do, so an AI summary that contains a phone number,
# or tells the reader to call back, reply, or hand over a code, is dropped whole: the rest of such a text can't
# be trusted either, and the static advice under it already says what to do.

_NUM_WORDS = {w: 1 for w in ("zero", "oh", "o", "nought", "one", "two", "three", "four", "five", "six", "seven",
                             "eight", "nine", "double")}
_NUM_WORDS.update({w: 2 for w in ("ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
                                  "seventeen", "eighteen", "nineteen", "twenty", "thirty", "forty", "fifty", "sixty",
                                  "seventy", "eighty", "ninety", "hundred", "triple")})
_NUM_WORDS["thousand"] = 3
_DIGIT_LOOKALIKES = frozenset("oOlI")           # O4l2 345 678
# A number or word, or any single other character. Only words end a run of digits: every other character (spaces,
# any punctuation, symbols, emoji) joins its parts, so "0412/345/678", "0412·345·678" or "0412_345_678" count.
_NUM_TOKEN = re.compile(r"([^\W_]+)|[\W_]")
PHONE_MIN_DIGITS = 7                            # Australian numbers have 8 to 10 digits; 13 xx xx has 6
_VANITY_PREFIXES = ("13", "1300", "1800", "1900")   # phonewords: 1800 RESPECT, 13 CABS, 1300FLOWERS
_VANITY_TOKEN = re.compile(r"(?:13|1[389]00)[A-Z]{3,}")
# A calling verb right before a number: "call 1800 respect", "ring 0412, then ..." (the prompt allows no numbers)
_CALL_THEN_NUMBER = re.compile(
    r"\b(?:call|ring|phone|dial|text|sms|whatsapp|viber|fax)(?:s|ed|ing|led|ling)?[\W_]+"
    r"(?:(?:us|them|him|her|me|now|today|urgently|immediately|back|free|toll-free|on|at|via|the|this|that|their|our"
    r"|its|fraud|security|support|customer|service|team|line|hotline|helpline|number|mobile|direct|directly)[\W_]+){0,4}"
    r"\+?\d", re.I)
# Dates and times are the only digit runs that may use "/" and ":" ("by 16/11/2026", "at 10:30")
_DATE_TIME_ITEM = re.compile(
    r"(?P<d1>\d{1,2})(?P<sep>[/.-])(?P<d2>\d{1,2})(?:(?P=sep)(?P<y>\d{4}|\d{2}))?(?!\d)"
    r"|(?P<iy>\d{4})-(?P<im>\d{1,2})-(?P<id>\d{1,2})(?!\d)"
    r"|(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?(?!\d)")
_DATE_TIME_SEP = re.compile(r"[\s,–—-]*")
_INVISIBLE = frozenset(("Mn", "Me", "Cf", "Co", "Cn", "Cs"))
_BLANK_CHARS = frozenset("\u2800\u3164\u115f\u1160\uffa0")      # render as blank space but are not whitespace


def _reader_view(s: str) -> str:
    """The text as a reader sees it, for the contact-detail checks: compatibility forms folded (fullwidth and
    styled digits), invisible characters and combining marks dropped ("0412", U+034F, "345"), letters from other
    scripts that look like Latin ones mapped to them ("саll"), and blank-looking characters made spaces."""
    out = []
    for ch in unicodedata.normalize("NFKD", s):
        if unicodedata.category(ch) in _INVISIBLE:
            continue
        if ch in _BLANK_CHARS:
            out.append(" ")
            continue
        low = ch.lower()
        mapped = CONFUSABLES.get(low)
        out.append(ch if mapped is None else mapped if ch == low else mapped.upper())
    return "".join(out)


def _date_or_time(run: str) -> bool:
    """True when a run of digits is only dates and times ("16/11/2026", "10:30", "16/11/2026, 10:30")."""
    pos, items = 0, 0
    while pos < len(run) and items < 4:
        m = _DATE_TIME_ITEM.match(run, pos)
        if not m:
            return False
        g = {k: int(v) for k, v in m.groupdict().items() if v is not None and k != "sep"}
        if "h" in g:
            ok = g["h"] <= 24 and g["mi"] <= 59 and g.get("s", 0) <= 59
        elif "iy" in g:
            ok = 1900 <= g["iy"] <= 2099 and 1 <= g["im"] <= 12 and 1 <= g["id"] <= 31
        else:
            a, b, y = g["d1"], g["d2"], g.get("y")
            ok = (1 <= a <= 31 and 1 <= b <= 31 and min(a, b) <= 12
                  and (y is None or y < 100 or 1900 <= y <= 2099))
        if not ok:
            return False
        items += 1
        pos = _DATE_TIME_SEP.match(run, m.end()).end()
    return pos >= len(run)


def _phone_run(run: str, count: int, plus: bool, lead: str) -> bool:
    if (count >= 6 and plus) or (count == 6 and lead.startswith("13")):
        return True                              # "+61 ...", "13 22 21", and "13/12/21": a 13 number shaped as a date
    return count >= PHONE_MIN_DIGITS and not _date_or_time(run)


def _vanity_word(t: str) -> bool:
    return len(t) >= 3 and t.isalpha() and t.isupper()


def _digit_count(token: str) -> int:
    if any(ch.isdecimal() for ch in token):
        if all(ch.isdecimal() or ch in _DIGIT_LOOKALIKES for ch in token):
            return len(token)
        return sum(ch.isdecimal() for ch in token)
    return _NUM_WORDS.get(token.lower(), 0)


def has_phone_number(s: str) -> bool:
    """True when the text has a run of digits or number words long enough to be a phone number, however it is
    spaced, punctuated or spelt ("+61 412 345 678", "(02) 9123 4567", "0412/345/678", "13 22 21",
    "oh four one two ...", "1800 RESPECT"), or a number right after a calling verb ("call 1800 respect")."""
    t = _reader_view(s)
    if _CALL_THEN_NUMBER.search(t):
        return True
    count, plus, lead, digits, start, end = 0, False, "", "", -1, -1
    for m in _NUM_TOKEN.finditer(t):
        tok = m.group()
        if m.group(1) is None:                   # a single non-word character: it joins the run
            plus = plus or (tok == "+" and not count)
            continue
        if _VANITY_TOKEN.fullmatch(tok):
            return True
        n = _digit_count(tok)
        if n:
            if start < 0:
                start, lead = m.start(), tok
            count += n
            digits += "".join(ch for ch in tok if ch.isdecimal())
            end = m.end()
            continue
        # a word ends the run
        if digits in _VANITY_PREFIXES and count == len(digits) and _vanity_word(tok):
            return True
        if _phone_run(t[start:end], count, plus, lead):
            return True
        count, plus, lead, digits, start, end = 0, False, "", "", -1, -1
    return _phone_run(t[start:end], count, plus, lead)


_W = r"[\w'-]+\s+"                                # one word and the space after it
_SRC = r"(?:message|text|sms|email|e-mail|mail|letter|voicemail|alert|notice)"
_CALLBACK = re.compile(r"""\b(?:
    (?:call|ring|phone|text|message|contact)\s+(?:""" + _W + r"""){0,3}?back\b             # call them back
  | (?:call|ring)-?back\b                                                                     # callback the number
  | give\s+(?:them|him|her|us|(?:the|this|that)\s+(?:sender|caller|scammer|agent|number)s?)\s+a\s+
    (?:call|ring|bell|buzz|text)\b                                                            # give them a call
  | return\s+(?:the|their|this|that|a|his|her)\s+(?:missed\s+)?calls?\b                       # return the call
  | (?:call|ring|phone|dial|text|sms|message|contact|use|email|whatsapp|reply\s+to|respond\s+to|write\s+to
      |get\s+in\s+touch\s+with|reach\s+out\s+to|reach|speak\s+(?:to|with)|talk\s+to)\s+
    (?:""" + _W + r"""){0,5}?
    (?:(?:this|that|these|those)\s+(?:phone\s+|mobile\s+)?(?:numbers?|lines?)                 # this number
      |(?:numbers?|details|contacts?|lines?)\s+(?:(?:given|provided|listed|shown|included|mentioned|quoted|supplied
          |written|left|sent)\s+)?(?:in|from|within|inside|on)\s+(?:the|this|that|their|its|your)\s+""" + _SRC + r"""
                                                                                              # the number in the text
      |(?:numbers?|details|contacts?)\s+(?:they|he|she|it|the\s+(?:sender|caller|scammer|agent|""" + _SRC + r"""))
          \s+(?:sent|sends|gave|gives|left|provided|included|mentioned|quoted|supplied|shared|listed)  # number they gave
      |(?:numbers?|details)\s+(?:given|provided|listed|shown|included|mentioned|quoted|supplied|left)\b
          (?!\s+(?:by|on|at)\b)                                                               # the number provided
      |(?:numbers?|details)\s+(?:above|below)
      |(?:the|this|that)\s+(?:sender|caller|scammer|agent)s?)\b                                # the sender
  | (?:reply|respond)\s+(?:back\s+)?with\b                                                    # reply with the code
  | (?:reply|respond|text|sms)\s+(?:back\s+)?["'“”]?(?:yes|y|ok|okay|stop|confirm)\b          # reply "YES"
  | (?:reply|respond)\s+to\s+(?:the|this|that|their|its)\s+(?:message|text|sms|email|e-mail|mail|sender)\b
  | (?:reply|respond|write)\s+(?:back\s+)?to\s+(?:them|him|her|it)\b                          # reply to them
  | follow\s+(?:""" + _W + r"""){0,2}?(?:instructions|steps|directions|prompts)\s+(?:in|from|within|on)\s+
    (?:the|this|that|their|its|your)\s+""" + _SRC + r"""\b                                  # follow the instructions
  | (?:share|send|give|tell|read|forward|provide)\s+(?:""" + _W + r"""){0,3}?
    (?:codes?|pins?|otps?|passcodes?|passwords?|one-time)\b                                  # give them the code
)""", re.I | re.X)
# A cue is not an instruction when it is negated ("don't call them back"), describes the scam ("it asks you to
# reply with a code") or is a noun ("the phone number in the message"). A pivot after a negation ends it
# ("don't click the link, just call back"); "don't worry" and "not a scam" don't negate anything.
_NEGATOR = re.compile(
    r"\b(?:don't|dont|do\s+not|never|avoid|shouldn't|should\s+not|mustn't|must\s+not|can't|cannot|not|nor"
    r"|no\s+need\s+to|instead\s+of|rather\s+than|without|refuse\s+to)\b"
    r"(?!\s+(?:worry|worried|panic|hesitate|delay|wait|forget|ignore|be\s+(?:afraid|scared|worried|alarmed|nervous|shy)"
    r"|an?\s+(?:scam|problem|issue|trick|fake)|scam|fake|suspicious|phishing|fraud|dangerous|risky|harmful)\b)", re.I)
_PIVOT = re.compile(
    r"\b(?:so|but|instead(?!\s+of)|however|just|simply|please|then|go\s+ahead|feel\s+free"
    r"|you\s+(?:can|could|should|may|must|need\s+to)(?!\s+not)|(?:it's|it\s+is|is)\s+(?:safe|fine|ok|okay|best))\b", re.I)
_DESCRIBES = re.compile(
    r"\b(?:(?:ask|want|tell|told|urge|pressure|instruct|invite|expect|encourage|direct|prompt|get|got|getting|try|tries"
    r"|tried|claim|pretend|persuade|convince|lure|push|trick|say|said)(?:s|d|ed|ing)?|(?:if|when|once|unless)\s+you"
    r"|scammers?|criminals?|fraudsters?)\b", re.I)
_NOUN_BEFORE = frozenset((
    "a", "an", "the", "this", "that", "these", "those", "their", "its", "your", "my", "our", "his", "her", "any", "some",
    "every", "each", "another", "same", "fake", "scam", "suspicious", "real", "genuine", "official", "missed",
    "phone", "mobile", "text", "sms", "email", "voice", "automated", "recorded"))
_CLAUSE = re.compile(r"[.!?;:\n]+|\s[-–—]+\s")


def _last(pattern: re.Pattern, s: str) -> int:
    ends = [m.end() for m in pattern.finditer(s)]
    return ends[-1] if ends else -1


def has_callback_instruction(s: str) -> bool:
    """True when the text tells the reader to call back, use the message's own contact details, reply, or hand over
    a code (rather than warning them not to)."""
    t = _reader_view(s).replace("’", "'").replace("‘", "'")
    for clause in _CLAUSE.split(t):
        for m in _CALLBACK.finditer(clause):
            before = clause[:m.start()]
            # a noun use only when the word sits right before the cue ("the phone number"; not "a real text, reply")
            word = re.search(r"([\w']+)[ \t]*$", before)
            if word and word.group(1).lower() in _NOUN_BEFORE:
                continue
            pivot = _last(_PIVOT, before)
            if _last(_NEGATOR, before) > pivot or _last(_DESCRIBES, before) > pivot:
                continue
            return True
    return False


def clean_ai_text(s: str) -> str:
    """AI-written text made safe to send: no control characters, nothing clickable, no Telegram mentions. Returns
    "" (so the reply goes out without it) when it contains a phone number or a call-back instruction."""
    s = _printable(s.translate(_CLEAN)).strip()
    if len(s) > AI_REPLY_LIMIT:
        s = s[:AI_REPLY_LIMIT].rsplit(" ", 1)[0] + "..."
    if has_phone_number(s) or has_callback_instruction(s):      # checked on exactly what would be sent
        log.warning("dropped an AI explanation: it contained a phone number or a call-back instruction")
        return ""
    s = re.sub(r"\n{3,}", "\n\n", defang_text(s))
    # "@SomeSupportDesk" would become a clickable Telegram mention (a scammer's account): break it up
    s = re.sub(r"(?<![\w.+-])@(?=\w)", "@ ", s)
    return s.strip()


_R_KEYWORD = re.compile(r"brand keyword '([^']+)' in (?:domain name|subdomain)(.*)")
_R_TYPO = re.compile(r"typo of brand keyword '([^']+)'")
_R_SHORT = re.compile(r"short brand token '([^']+)'")
_R_BAIT = re.compile(r"bait words: (.+)")
_R_OFFICIAL = re.compile(r"official domain '([^']+)' written into the hostname")
_R_TLD = re.compile(r"high-abuse suffix \.?(\S+)")


def describe_reasons(reasons, brand: str | None) -> list[str]:
    """Turn scoring reasons ({'points', 'why'}) into short plain-English bullet points."""
    brand = brand or "the brand"
    out: list[str] = []
    for r in reasons if isinstance(reasons, list) else []:
        why = str(r.get("why", "")) if isinstance(r, dict) else ""
        if m := _R_KEYWORD.match(why):
            kw, rest = m.group(1), m.group(2)
            if "Unicode" in rest:
                out.append(f'it spells "{kw}" with look-alike letters from another alphabet')
            elif "look-alike characters" in rest:
                out.append(f'it spells "{kw}" with look-alike characters (such as 0 for o)')
            else:
                out.append(f'the address contains "{kw}", but it is not an official {brand} website')
        elif m := _R_TYPO.match(why):
            out.append(f'it uses a misspelling of "{m.group(1)}"')
        elif m := _R_SHORT.match(why):
            out.append(f'it uses "{m.group(1)}" together with words scammers like to use')
        elif m := _R_BAIT.match(why):
            out.append(f"it includes words common in scams: {m.group(1)}")
        elif why.startswith("Australian context"):
            out.append('it adds "au" or "gov-au" to look Australian')
        elif m := _R_OFFICIAL.match(why):
            out.append(f"it hides the real address {m.group(1)} inside a different website's address")
        elif m := _R_TLD.match(why):
            out.append(f"it ends in .{m.group(1)}, an ending often used by scam sites")
        elif why.startswith("deep subdomain"):
            out.append("it has an unusually long chain of sub-addresses")
        elif why.startswith("mixed scripts") and not any("alphabet" in o for o in out):
            out.append("it mixes letters from different alphabets")
        elif why.startswith("exact brand name on another suffix"):
            out.append("it is the brand name on a different ending (it may also be registered by the brand itself)")
    return [defang_text(o) for o in dict.fromkeys(out)][:5]


# =========================================================================================
# Per-domain verdicts and the reply
# =========================================================================================

@dataclass
class Check:
    found: FoundHost
    verdict: str                     # confirmed | suspicious | official | shortener | not_flagged
    brand: str | None = None
    strength: str | None = None      # watch | review | high (suspicious only)
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    domain_id: int | None = None
    new: bool = False


_TIER_ORDER = {"watch": 0, "review": 1, "high": 2}
REVIEWED_NOTE = "Our team has reviewed this domain and did not class it as a scam site."


def _site(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def review_covers(host: str, row: dict) -> bool:
    """Whether a reviewer's decision on a domains row was about this hostname: the registrable domain itself or
    one of the hostnames the reviewer was shown (with or without a leading "www."). reviewed_hostnames is the
    row's hostnames at decision time; hostnames added later by new certificates are not covered. Rows reviewed
    before that column existed (NULL) fall back to the current hostnames."""
    shown = row.get("reviewed_hostnames")
    names = [row.get("registered_domain"), *(shown if shown is not None else (row.get("hostnames") or []))]
    return _site(host) in {_site(n) for n in names if isinstance(n, str)}


def _stronger(a: str | None, b: str | None) -> str | None:
    if not a or not b:
        return a or b
    return a if _TIER_ORDER.get(a, 0) >= _TIER_ORDER.get(b, 0) else b


def _headline(c: Check) -> str:
    brand = defang_text(c.brand) if c.brand else None
    if c.verdict == "confirmed":
        return (f"CONFIRMED PHISHING. Our team has confirmed this is a scam website"
                f"{f' imitating {brand}' if brand else ''}. Do not open it.")
    if c.verdict == "suspicious":
        who = brand or "a well-known brand"
        head = {"high": f"VERY SUSPICIOUS. It looks like a fake {who} website.",
                "review": f"SUSPICIOUS. It looks like it imitates {who}.",
                }.get(c.strength or "", f"SOME WARNING SIGNS. It may be imitating {who}.")
        return head + (" Why:" if c.reasons else "")
    if c.verdict == "official":
        return (f"Official {brand or 'brand'} website (on our list of genuine addresses). Scammers sometimes "
                "include real links or fake the sender, so still be careful with the rest of the message.")
    if c.verdict == "shortener":
        return ("Link shortener. I can't see where it really leads without opening it, and I never open links. "
                "Treat it with caution.")
    return "Not flagged. It doesn't look like it imitates an Australian brand on our watchlist."


ADVICE_DANGER = (
    "What to do:\n"
    "- Don't open the link, reply, or call any number in the message.\n"
    "- If it claims to be from your bank, myGov, the ATO, Australia Post or another organisation, contact them "
    "through their official app or a phone number you look up yourself (their official website or the back of "
    "your card), not the details in the message.\n"
    "- If you've already entered details or paid, contact your bank straight away, then IDCARE on "
    "1800 595 160 for free help.\n"
    f"- Report it to Scamwatch: {SCAMWATCH_URL}"
)
ADVICE_CLEAR = (
    "Not flagged does not mean safe: I only check whether a web address imitates an Australian brand we watch, "
    "and new scam sites appear every day.\n"
    "- If the message rushes you or asks you to log in, pay, or confirm personal or card details, treat it as a scam.\n"
    "- Contact the organisation through its official app or a phone number you look up yourself.\n"
    f"- Report scams to Scamwatch: {SCAMWATCH_URL}"
)
ADVICE_NONE = (
    "If the message rushes you or asks you to log in, pay, or confirm personal or card details, treat it as a "
    "scam and contact the organisation through its official app or a phone number you look up yourself.\n"
    f"Report scams to Scamwatch: {SCAMWATCH_URL}"
)


def compose_reply(checks: list[Check], ex: Extraction, ai_text: str | None = None) -> str:
    """Plain-text reply. Every echoed domain is defanged; only the static advice links are clickable."""
    confirmed = any(c.verdict == "confirmed" for c in checks)
    strong = any(c.verdict == "suspicious" and c.strength in ("review", "high") for c in checks)
    weak = any(c.verdict == "suspicious" for c in checks)
    danger = confirmed or weak or bool(ex.mismatches) or bool(ex.ips)
    if confirmed:
        lines = ["Warning: this message links to a confirmed phishing (scam) website."]
    elif strong:
        n = sum(1 for c in checks if c.verdict == "suspicious")
        lines = [f"Warning: this message contains {n} suspicious links." if n > 1
                 else "Warning: this message contains a suspicious link."]
    elif weak or ex.mismatches or ex.ips:
        lines = ["Be careful: a link in this message has warning signs."]
    elif checks:
        lines = ["I didn't find any known or likely scam websites in this message. That does not mean it is safe."]
    else:
        lines = ["I couldn't find a web address in this message. Forward or paste the message that contains "
                 "the link and I'll check it (I never open links)."]
    lines.append("")
    for shown, real in ex.mismatches:
        lines.append(f"Trick spotted: the link text shows {defang_host(shown)} but it really goes to "
                     f"{defang_host(real)}.")
    for ip in ex.ips:
        lines.append(f"A link goes straight to an internet (IP) address, {defang_text(ip)}, instead of a "
                     "website name. Genuine banks and government services don't do this.")
    if ex.mismatches or ex.ips:
        lines.append("")
    for i, c in enumerate(checks, 1):
        line = f"{i}. {defang_link(c.found)}"
        if "xn--" in c.found.host:
            shown = _printable(decode_idna(c.found.host))
            if shown != c.found.host:
                line += f" (displays as {defang_text(shown)})"
        lines.append(line)
        lines.append("   " + _headline(c))
        lines += [f"   - {r}" for r in c.reasons]
        lines += [f"   {n}" for n in c.notes]
        if c.new:
            lines.append("   I've added it to our checks so it can be investigated and blocked.")
        lines.append("")
    if ex.truncated:
        lines += [f"(I only checked the first {MAX_HOSTS} addresses.)", ""]
    # The advice (with "not flagged does not mean safe") must survive the length cap: drop the AI summary
    # first, then shorten the per-address section.
    advice = ADVICE_DANGER if danger else ADVICE_CLEAR if checks else ADVICE_NONE
    ai_block = "AI summary (automated, it can be wrong):\n" + ai_text + "\n\n" if ai_text else ""
    body = "\n".join(lines) + "\n"
    if len(body) + len(ai_block) + len(advice) > REPLY_LIMIT:
        ai_block = ""
    room = REPLY_LIMIT - len(advice) - len(ai_block)
    if len(body) > room:
        body = body[:max(room - 6, 0)].rsplit("\n", 1)[0] + "\n...\n\n"
    return body + ai_block + advice


def help_text(daily_limit: int) -> str:
    return (
        "Hi! I'm the CyberCheck bot. I check web addresses in suspicious messages for fake websites that imitate "
        "Australian banks, government services (myGov, ATO, Centrelink, Medicare), Australia Post, toll roads, "
        "telcos and other brands.\n\n"
        "How to use me: forward a suspicious text, email or message to me, or paste it in. I'll tell you if a "
        "link in it is a known or likely scam. I never open the links myself.\n\n"
        f"Each chat can make up to {daily_limit} checks a day (the count resets at midnight UTC, "
        "10 or 11 am in eastern Australia).\n\n"
        "/help - how to use this bot\n"
        "/privacy - what I store\n\n"
        "I'm a helper, not a guarantee: not flagged does not mean safe.\n"
        f"Report scams to Scamwatch: {SCAMWATCH_URL}"
    )


def privacy_text(ai_on: bool) -> str:
    ai = ("\n\nIf AI explanations are switched on, the text of a message you send may be passed to our AI "
          "provider (Anthropic) to write a short explanation for that one check. We keep that explanation "
          "(for cost and quality records), not your message."
          if ai_on else "")
    return (
        "What this bot stores:\n"
        "- This chat's Telegram ID, its name or username, whether the bot is enabled for it, and how many "
        "checks it has made (per day and in total).\n"
        f"- For each checked message: the chat ID, the time, the domain names found in it and my verdicts. "
        f"These are deleted after {RETENTION_DAYS} days.\n"
        "- Suspicious domain names are added to CyberCheck's database of scam sites so they can be checked, "
        "blocked and reported for takedown. That database doesn't record who sent them.\n\n"
        "What it doesn't store: the text of your messages, attachments, or anything about who wrote the "
        f"message you forwarded.{ai}\n\n"
        "The bot never opens the links you send. Chats waiting for approval are forgotten if they haven't "
        f"written for {RETENTION_DAYS} days."
    )


NOT_ENABLED_TEXT = (
    "Hi! The CyberCheck scam-link checker isn't enabled for this chat yet. I've noted the request so the "
    "operator can approve it; until then I won't check messages here. I've stored only this chat's ID and "
    "name for that.\n\n"
    f"In the meantime, you can report scams to Scamwatch: {SCAMWATCH_URL}"
)
NO_TEXT_TEXT = ("I can only check text and links, not pictures or files. Forward the message itself, or copy "
                "and paste its text, and I'll check the links in it.")
SORRY_TEXT = "Sorry, I couldn't check that just now. Please try again in a few minutes."


def limit_text(limit: int) -> str:
    return (f"This chat has reached today's limit of {limit} checks. The count resets at midnight UTC "
            "(10 or 11 am in eastern Australia).\n"
            "Until then: don't click links in messages you're unsure about, contact the organisation through "
            f"its official app or number, and report scams to Scamwatch: {SCAMWATCH_URL}")


# =========================================================================================
# Database access (one connection per update)
# =========================================================================================

class Repo:
    def __init__(self, conn):
        self.conn = conn

    async def _one(self, sql: str, params=()):
        return await (await self.conn.execute(sql, params)).fetchone()

    async def tables_ready(self) -> bool:
        row = await self._one("SELECT to_regclass('bot_chats') IS NOT NULL AND "
                              "to_regclass('bot_messages') IS NOT NULL AS ok")
        return bool(row and row["ok"])

    async def touch_chat(self, chat_id: int, chat_type: str, title: str | None, username: str | None,
                         env_allowed: bool) -> tuple[str, bool]:
        """Record that a chat talked to us. Returns (stored status, newly inserted).

        The stored status is only what the dashboard decided (pending until a human allows or blocks it).
        TELEGRAM_ALLOWED_CHATS is applied by the caller at run time and never written here, so taking a
        chat out of that list really revokes it. env_allowed is accepted for interface stability only."""
        row = await self._one(
            "INSERT INTO bot_chats (chat_id, chat_type, title, username, status) "
            "VALUES (%(id)s, %(type)s, %(title)s, %(username)s, 'pending') "
            "ON CONFLICT (chat_id) DO UPDATE SET chat_type = EXCLUDED.chat_type, "
            "  title = COALESCE(EXCLUDED.title, bot_chats.title), username = EXCLUDED.username, last_seen = now() "
            "RETURNING status, (xmax = 0) AS inserted",
            {"id": chat_id, "type": chat_type, "title": title, "username": username})
        return row["status"], bool(row["inserted"])

    async def take_message_slot(self, chat_id: int, day: date, limit: int) -> bool:
        """Count one check against today's limit; False when the limit is reached."""
        row = await self._one(
            "UPDATE bot_chats SET "
            "  day_messages = CASE WHEN counter_day = %(day)s THEN day_messages + 1 ELSE 1 END, "
            "  day_ai = CASE WHEN counter_day = %(day)s THEN day_ai ELSE 0 END, "
            "  limit_notified = CASE WHEN counter_day = %(day)s THEN limit_notified ELSE false END, "
            "  counter_day = %(day)s, total_messages = total_messages + 1 "
            "WHERE chat_id = %(id)s AND (counter_day IS DISTINCT FROM %(day)s OR day_messages < %(limit)s) "
            "RETURNING day_messages",
            {"id": chat_id, "day": day, "limit": limit})
        return row is not None

    async def mark_limit_notified(self, chat_id: int, day: date) -> bool:
        """True the first time today (so the 'limit reached' reply is sent once per day). With a daily limit of 0
        take_message_slot is never called, so a chat's first refusal of the day also starts the day's counters."""
        row = await self._one(
            "UPDATE bot_chats SET limit_notified = true, "
            "  day_messages = CASE WHEN counter_day = %(day)s THEN day_messages ELSE 0 END, "
            "  day_ai = CASE WHEN counter_day = %(day)s THEN day_ai ELSE 0 END, counter_day = %(day)s "
            "WHERE chat_id = %(id)s AND (counter_day IS DISTINCT FROM %(day)s OR NOT limit_notified) RETURNING chat_id",
            {"id": chat_id, "day": day})
        return row is not None

    async def take_ai_slot(self, chat_id: int, day: date, limit: int) -> bool:
        row = await self._one("UPDATE bot_chats SET day_ai = day_ai + 1 WHERE chat_id = %s AND counter_day = %s "
                              "AND day_ai < %s RETURNING day_ai", (chat_id, day, limit))
        return row is not None

    async def refund_ai_slot(self, chat_id: int, day: date) -> None:
        await self.conn.execute("UPDATE bot_chats SET day_ai = GREATEST(day_ai - 1, 0) "
                                "WHERE chat_id = %s AND counter_day = %s", (chat_id, day))

    async def lookup(self, registered: list[str]) -> dict[str, dict]:
        if not registered:
            return {}
        rows = await (await self.conn.execute(
            "SELECT id, registered_domain, brand_id, score, tier, status, reasons, ai_verdict, live_state, takedown_at, "
            "source, hostnames, reviewed_hostnames FROM domains WHERE registered_domain = ANY(%s::text[])",
            (registered,))).fetchall()
        return {r["registered_domain"]: r for r in rows}

    async def store_hit(self, hit: Hit) -> tuple[int, bool]:
        return await store_hit(self.conn, hit, source="bot")

    async def add_forward_event(self, domain_id: int, detail: dict) -> None:
        await db.add_event(self.conn, domain_id, "bot_forward", detail)

    async def record_message(self, chat_id: int, checks: list[Check], ai_used: bool) -> None:
        await self.conn.execute(
            "INSERT INTO bot_messages (chat_id, domains, registered, verdicts, new_domains, ai_used) "
            "VALUES (%s, %s::text[], %s::text[], %s::text[], %s, %s)",
            (chat_id, [c.found.host for c in checks], [c.found.registered for c in checks],
             [c.verdict for c in checks], sum(1 for c in checks if c.new), ai_used))
        await self.conn.execute("UPDATE bot_chats SET total_domains = total_domains + %s, total_ai = total_ai + %s "
                                "WHERE chat_id = %s", (len(checks), 1 if ai_used else 0, chat_id))

    async def cleanup(self, keep_chats: list[int]) -> dict:
        age = timedelta(days=RETENTION_DAYS)
        m = await self.conn.execute("DELETE FROM bot_messages WHERE at < now() - %s", (age,))
        c = await self.conn.execute("DELETE FROM bot_chats WHERE status = 'pending' AND last_seen < now() - %s "
                                    "AND NOT (chat_id = ANY(%s::bigint[]))", (age, keep_chats))
        return {"messages": m.rowcount, "pending_chats": c.rowcount}

    async def get_offset(self) -> int | None:
        v = await db.kv_get(self.conn, OFFSET_KEY)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    async def set_offset(self, offset: int) -> None:
        await db.kv_set(self.conn, OFFSET_KEY, offset)

    async def set_status(self, status: dict) -> None:
        await db.kv_set(self.conn, STATUS_KEY, status)


@asynccontextmanager
async def db_repo():
    p = await db.pool()
    async with p.connection() as conn:
        yield Repo(conn)


# =========================================================================================
# Telegram Bot API client
# =========================================================================================

class TelegramError(Exception):
    def __init__(self, code: int, description: str, retry_after: int | None = None):
        super().__init__(f"{code}: {description}")
        self.code, self.description, self.retry_after = code, description, retry_after


class TelegramNetworkError(Exception):
    pass


class TelegramAPI:
    def __init__(self, token: str, client: httpx.AsyncClient, base: str = API_BASE):
        self._token = token
        self._client = client
        self._base = base

    def _scrub(self, s: str) -> str:
        return s.replace(self._token, "<token>") if self._token else s

    async def call(self, method: str, payload: dict | None = None, timeout: float | None = None):
        url = f"{self._base}/bot{self._token}/{method}"
        kwargs = {"json": payload or {}}
        if timeout is not None:
            kwargs["timeout"] = httpx.Timeout(15.0, read=timeout)
        try:
            r = await self._client.post(url, **kwargs)
        except Exception as e:   # the message may contain the URL (and so the token): scrub it. This also
            # covers httpx.InvalidURL (raised for a malformed token), which is not an httpx.HTTPError.
            raise TelegramNetworkError(self._scrub(f"{type(e).__name__}: {e}")[:300]) from None
        try:
            data = r.json()
        except ValueError:
            raise TelegramError(r.status_code, f"non-JSON response (HTTP {r.status_code})") from None
        if not isinstance(data, dict) or not data.get("ok"):
            data = data if isinstance(data, dict) else {}
            params = data.get("parameters") if isinstance(data.get("parameters"), dict) else {}
            retry = params.get("retry_after")
            code = data.get("error_code")
            raise TelegramError(code if isinstance(code, int) else r.status_code,
                                self._scrub(str(data.get("description") or ""))[:300],
                                retry if isinstance(retry, int) else None)
        return data.get("result")

    async def get_me(self) -> dict:
        return await self.call("getMe")

    async def get_updates(self, offset: int | None) -> list:
        payload = {"timeout": POLL_TIMEOUT, "limit": 50, "allowed_updates": ["message"]}
        if offset is not None:
            payload["offset"] = offset
        result = await self.call("getUpdates", payload, timeout=POLL_TIMEOUT + 20)
        return result if isinstance(result, list) else []

    async def send_message(self, chat_id: int, text: str, reply_to: int | None = None) -> None:
        payload = {"chat_id": chat_id, "text": text[:4096], "link_preview_options": {"is_disabled": True}}
        if reply_to is not None:
            payload["reply_parameters"] = {"message_id": reply_to, "allow_sending_without_reply": True}
        await self.call("sendMessage", payload)


# =========================================================================================
# The bot
# =========================================================================================

def _chat_title(chat: dict) -> str | None:
    t = chat.get("title") or chat.get("first_name")
    return _printable(t)[:100] if isinstance(t, str) else None


def _chat_username(chat: dict) -> str | None:
    u = chat.get("username")
    return _printable(u)[:64] if isinstance(u, str) else None


_MEDIA_KEYS = ("photo", "document", "video", "voice", "audio", "sticker", "animation", "video_note", "contact")


class Bot:
    def __init__(self, api: TelegramAPI, repo_factory=db_repo, watchlist: Watchlist | None = None,
                 allowed_chats=None, daily_limit: int | None = None, ai_limit: int | None = None,
                 ai_on: bool | None = None):
        s = settings()
        self.api = api
        self.repo = repo_factory
        self.wl = watchlist or default_watchlist()
        self.allowed_env = set(s.telegram_allowed_chats if allowed_chats is None else allowed_chats)
        self.daily_limit = s.bot_daily_limit_per_chat if daily_limit is None else daily_limit
        self.ai_limit = ai_daily_limit() if ai_limit is None else ai_limit
        self.ai_on = (s.ai_enabled and bool(s.anthropic_api_key)) if ai_on is None else ai_on
        self.username: str | None = None
        self.offset: int | None = None
        self.stats = {"started": datetime.now(timezone.utc).isoformat(), "updates": 0, "checks": 0, "errors": 0}
        self._next_cleanup = 0.0
        self._next_status = 0.0
        self._ai_tasks: set[asyncio.Task] = set()
        self.clock = time.monotonic
        self._info_replies: dict[int, list[float]] = {}    # chat -> times of recent replies that were not checks
        self._flood_until: dict[int, float] = {}           # chat -> end of a Telegram flood-wait

    # ---- replies -------------------------------------------------------------------------
    def take_info_reply(self, chat_id: int) -> bool:
        """Count a reply that is not a check (help, privacy, unknown command, picture, error) against the
        per-chat allowance; False when the chat has had INFO_REPLY_LIMIT of them in INFO_REPLY_WINDOW."""
        now = self.clock()
        recent = [t for t in self._info_replies.get(chat_id, ()) if now - t < INFO_REPLY_WINDOW]
        ok = len(recent) < INFO_REPLY_LIMIT
        if ok:
            recent.append(now)
        self._info_replies[chat_id] = recent
        return ok

    def _prune_reply_state(self) -> None:
        now = self.clock()
        self._info_replies = {c: ts for c, ts in self._info_replies.items() if ts and now - ts[-1] < INFO_REPLY_WINDOW}
        self._flood_until = {c: t for c, t in self._flood_until.items() if t > now}

    async def send(self, chat_id: int, text: str, reply_to=None) -> bool:
        """Send a reply. Updates are handled one at a time, so a Telegram flood-wait is never slept through for
        more than SEND_RETRY_MAX_WAIT seconds: a longer one drops this reply and skips the chat until it ends."""
        reply_to = reply_to if isinstance(reply_to, int) and not isinstance(reply_to, bool) else None
        if self._flood_until.get(chat_id, 0.0) > self.clock():
            log.warning("not replying to chat %s: Telegram asked us to wait (flood limit)", chat_id)
            return False
        for attempt in (1, 2):
            try:
                await self.api.send_message(chat_id, text, reply_to)
                return True
            except TelegramError as e:
                if e.code == 429:
                    wait = e.retry_after if isinstance(e.retry_after, int) and e.retry_after >= 0 else SEND_RETRY_MAX_WAIT
                    if attempt == 1 and wait <= SEND_RETRY_MAX_WAIT:
                        await asyncio.sleep(wait)
                        continue
                    self._flood_until[chat_id] = self.clock() + min(max(wait, 1), FLOOD_WAIT_CAP)
                    log.warning("sendMessage to chat %s dropped: Telegram flood-wait of %ss", chat_id, wait)
                    return False
                if attempt == 1 and e.code == 400 and reply_to is not None:
                    reply_to = None          # the original message may be gone; send without replying
                    continue
                log.warning("sendMessage to chat %s failed: %s %s", chat_id, e.code, e.description)
                return False
            except TelegramNetworkError as e:
                if attempt == 1:
                    await asyncio.sleep(2)
                    continue
                log.warning("sendMessage to chat %s failed: %s", chat_id, e)
                return False
        return False

    def parse_command(self, text: str) -> str | None:
        """'help' for '/help' or '/help@ThisBot'; '' for a command addressed to another bot; None if not a command."""
        if not text.startswith("/"):
            return None
        first = text.split(maxsplit=1)[0][1:]
        name, _, target = first.partition("@")
        if target and (not self.username or target.lower() != self.username.lower()):
            return ""
        return name.lower()[:32]

    def command_reply(self, cmd: str, private: bool) -> str | None:
        if cmd in ("start", "help"):
            return help_text(self.daily_limit)
        if cmd == "privacy":
            return privacy_text(self.ai_on and self.ai_limit > 0)
        return "I don't know that command. Send /help to see what I can do." if private else None

    # ---- one update ----------------------------------------------------------------------
    async def handle_update(self, upd: dict) -> None:
        msg = upd.get("message")
        if not isinstance(msg, dict):
            return
        chat = msg.get("chat") if isinstance(msg.get("chat"), dict) else {}
        chat_id = chat.get("id")
        if not isinstance(chat_id, int) or isinstance(chat_id, bool):
            return
        chat_type = str(chat.get("type") or "")[:20]
        sender = msg.get("from") if isinstance(msg.get("from"), dict) else {}
        if chat_type == "channel" or sender.get("is_bot"):
            return
        text, _ = message_text(msg)
        forwarded = any(k in msg for k in ("forward_origin", "forward_date", "forward_from", "forward_from_chat"))
        cmd = None if forwarded else self.parse_command(text)   # a forwarded "/..." text is content to check
        if cmd == "":
            return
        allowed = False
        try:
            async with self.repo() as repo:
                env = chat_id in self.allowed_env
                status, inserted = await repo.touch_chat(chat_id, chat_type, _chat_title(chat), _chat_username(chat), env)
                if status == "blocked":
                    return
                if status != "allowed" and not env:
                    if inserted:
                        log.info("new chat %s (%s) is pending approval on the dashboard", chat_id, chat_type)
                        await self.send(chat_id, NOT_ENABLED_TEXT)
                    return
                allowed = True
                private = chat_type == "private"
                if cmd is not None:
                    # commands don't use a check slot, so they have their own (small) allowance
                    reply = self.command_reply(cmd, private)
                    if reply and self.take_info_reply(chat_id):
                        await self.send(chat_id, reply, msg.get("message_id"))
                    return
                await self.check_message(repo, msg, chat_id, private, text)
        except Exception:
            self.stats["errors"] += 1
            log.exception("handling update %s failed", upd.get("update_id"))
            if allowed and self.take_info_reply(chat_id):
                await self.send(chat_id, SORRY_TEXT, msg.get("message_id"))

    async def check_message(self, repo: Repo, msg: dict, chat_id: int, private: bool, text: str) -> None:
        reply_to = msg.get("message_id")
        ex = extract_from_message(msg)
        if not ex.hosts and not ex.ips:
            if not private:
                return                       # stay quiet in groups unless there is something to check
            if not text.strip():
                if any(k in msg for k in _MEDIA_KEYS) and self.take_info_reply(chat_id):
                    await self.send(chat_id, NO_TEXT_TEXT, reply_to)
                return
        today = utc_today()
        if self.daily_limit <= 0 or not await repo.take_message_slot(chat_id, today, self.daily_limit):
            if await repo.mark_limit_notified(chat_id, today):
                await self.send(chat_id, limit_text(max(self.daily_limit, 0)), reply_to)
            return
        checks = await self.check_hosts(repo, ex)
        ai_text = None
        if text.strip() and (checks or ex.ips or len(text.strip()) >= 20):
            ai_text = await self.ai_explain(repo, chat_id, text, checks, today)
        await repo.record_message(chat_id, checks, ai_used=ai_text is not None)
        self.stats["checks"] += 1
        await self.send(chat_id, compose_reply(checks, ex, ai_text), reply_to)

    # ---- domain checks -------------------------------------------------------------------
    def _brand_name(self, brand_id) -> str | None:
        b = self.wl.brands.get(brand_id) if isinstance(brand_id, str) else None
        return b.name if b else None

    def _official_brand(self, host: str) -> str | None:
        if host == "gov.au" or host.endswith(".gov.au"):
            return "Australian government (.gov.au)"
        labels = host.split(".")
        for i in range(len(labels) - 1):
            bid = self.wl.official.get(".".join(labels[i:]))
            if bid:
                return self._brand_name(bid)       # None for the generic allowlist (not a brand)
        return None

    def _own_check(self, f: FoundHost, hit: Hit | None, domain_id: int | None = None) -> Check:
        """The verdict from this hostname alone: its own watchlist score, the official list, the shortener list."""
        if hit is not None:
            return Check(f, "suspicious", brand=hit.brand_name, strength=hit.tier,
                         reasons=describe_reasons(hit.reasons, hit.brand_name), domain_id=domain_id)
        if (official := self._official_brand(f.host)) is not None:
            return Check(f, "official", brand=official, domain_id=domain_id)
        if f.registered in SHORTENERS:
            return Check(f, "shortener", domain_id=domain_id)
        return Check(f, "not_flagged", domain_id=domain_id)

    def _review_applies(self, f: FoundHost, row: dict) -> bool:
        """Whether a reviewer's "not a scam" on a domains row covers this hostname: always for the hostnames on the
        row, and for any hostname when the registrable domain's own name scores ("tickets.westpac-stadium.com.au":
        the reviewer judged that name, and its one owner runs every subdomain). When only subdomains score
        ("<anything>.weebly.com"), the sites under it can belong to unrelated people, so a new one isn't covered."""
        if review_covers(f.host, row):
            return True
        reg = row.get("registered_domain")
        return isinstance(reg, str) and self.wl.score_hostname(reg) is not None

    def _from_row(self, f: FoundHost, row: dict, hit: Hit | None) -> Check:
        """Verdict for a hostname whose registrable domain has a domains row. Only CyberCheck's own evidence is
        shared between chats: reviewer decisions, page checks, and name scores CyberCheck found itself."""
        did = row.get("id")
        status = row.get("status")
        official = self._official_brand(f.host)
        if official is not None and not (f.host == "gov.au" or f.host.endswith(".gov.au")):
            # A brand's own official address is never reported as phishing, whatever a row says (the dashboard
            # refuses to confirm one, but rows from before that rule, or a manual add, must not slip through).
            return Check(f, "official", brand=official, domain_id=did)
        if status in ("false_positive", "benign"):
            if self._review_applies(f, row):
                return Check(f, "not_flagged", domain_id=did, notes=[REVIEWED_NOTE])
            # The reviewer cleared the hostnames they were shown, not this one: unrelated sites can share one
            # registrable domain (site builders that aren't on the public suffix list), so judge it on its own.
            return self._own_check(f, hit, did)
        notes = []
        if row.get("takedown_at"):
            notes.append("It appears to have been taken down, but copies often pop up elsewhere.")
        elif row.get("live_state") == "live":
            notes.append("It was online when we last checked.")
        row_brand = self._brand_name(row.get("brand_id"))
        if status == "confirmed":
            return Check(f, "confirmed", brand=row_brand or (hit.brand_name if hit else None), notes=notes,
                         domain_id=did)
        ai_phishing = row.get("ai_verdict") == "phishing"
        if row.get("source") == "bot":
            # The row was scored from a hostname somebody forwarded, and anyone can write any domain into a
            # made-up subdomain ("commbank.com.au.login.<real-site>"). Its tier, brand and reasons must not
            # change what the bot says about other hostnames, so this one is judged on its own score.
            if hit is None and not ai_phishing:
                return self._own_check(f, None, did)
            brand = hit.brand_name if hit else row_brand
            strength = hit.tier if hit else row.get("tier")
            reasons = describe_reasons(hit.reasons, brand) if hit else []
        else:                         # found by CT, CZDS or a manual add: CyberCheck's own evidence
            brand = row_brand or (hit.brand_name if hit else None)
            strength = _stronger(row.get("tier"), hit.tier if hit else None)
            reasons = describe_reasons(hit.reasons if hit else row.get("reasons"), brand)
        if ai_phishing:
            notes.insert(0, "Our automated check of the page also judged it to be phishing.")
        return Check(f, "suspicious", brand=brand, strength=strength, reasons=reasons, notes=notes, domain_id=did)

    async def check_hosts(self, repo: Repo, ex: Extraction) -> list[Check]:
        rows = await repo.lookup(list(dict.fromkeys(f.registered for f in ex.hosts)))
        stored_now: set[str] = set()
        checks = []
        for f in ex.hosts:
            hit = self.wl.score_hostname(f.host)
            reg = hit.registered_domain if hit else f.registered
            row = rows.get(reg) or rows.get(f.registered)
            if row is not None:
                c = self._from_row(f, row, hit)
                if reg not in stored_now and row.get("id"):
                    detail = {"hostname": f.host, "verdict": c.verdict}
                    if row.get("status") in ("false_positive", "benign") and c.verdict == "suspicious":
                        detail["not_covered_by_review"] = True      # for the reviewer: look at this domain again
                    try:
                        await repo.add_forward_event(row["id"], detail)
                    except Exception:
                        log.exception("could not record bot_forward event")
            elif hit is not None:
                domain_id, inserted = await repo.store_hit(hit)
                stored_now.add(reg)
                rows[reg] = {"id": domain_id, "registered_domain": reg, "status": "open", "brand_id": hit.brand_id,
                             "tier": hit.tier, "reasons": hit.reasons, "source": "bot", "hostnames": [hit.hostname]}
                if inserted:
                    log.info("stored %s (score %s, %s) from a bot message", reg, hit.score, hit.brand_id)
                c = self._own_check(f, hit, domain_id)
                c.new = inserted
            else:
                c = self._own_check(f, None)
            checks.append(c)
        return checks

    async def _explain(self, text: str, findings: list[dict], chat_id: int):
        from .ai import api as ai_api
        async with self.repo() as r:          # its own connection: see ai_explain
            return await ai_api.explain_message(r.conn, text, findings, chat_id)

    def _ai_task_done(self, task: asyncio.Task) -> None:
        self._ai_tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            log.error("explain_message failed", exc_info=task.exception())

    async def ai_explain(self, repo: Repo, chat_id: int, text: str, checks: list[Check], today: date) -> str | None:
        """Optional AI explanation. The call is never cancelled: the AI module reserves budget and records the
        cost in ai_calls on its connection, and cancelling it mid-query would leave that connection (and the
        cost record) in an unknown state. It runs on its own connection; after AI_TIMEOUT the reply goes out
        without it and the call finishes in the background."""
        if not self.ai_on or self.ai_limit <= 0 or len(self._ai_tasks) >= MAX_AI_INFLIGHT:
            return None
        if not await repo.take_ai_slot(chat_id, today, self.ai_limit):
            return None
        findings = [{"hostname": c.found.host, "registered_domain": c.found.registered, "verdict": c.verdict,
                     "brand": c.brand, "strength": c.strength, "reasons": c.reasons} for c in checks]
        task = asyncio.create_task(self._explain(text[:AI_TEXT_LIMIT], findings, chat_id))
        self._ai_tasks.add(task)
        task.add_done_callback(self._ai_task_done)
        done, _ = await asyncio.wait({task}, timeout=AI_TIMEOUT)
        if task not in done:
            log.warning("explain_message is taking longer than %ss; replying without it", AI_TIMEOUT)
            return None                       # the slot stays used: the call may still be billed
        out = None
        if task.exception() is None:
            out = task.result()
        cleaned = clean_ai_text(out) if isinstance(out, str) else ""
        if not cleaned:
            await repo.refund_ai_slot(chat_id, today)
            return None
        return cleaned

    # ---- loop ----------------------------------------------------------------------------
    async def wait_until_ready(self) -> None:
        warned = None
        while True:
            try:
                async with self.repo() as repo:
                    if await repo.tables_ready():
                        self.offset = await repo.get_offset()
                        return
                problem = "bot tables are missing: run `python -m cybercheck migrate`"
            except Exception as e:
                problem = f"database not reachable ({type(e).__name__})"
            if problem != warned:
                log.warning("bot waiting: %s", problem)
                warned = problem
            await asyncio.sleep(60)

    async def identify(self) -> None:
        delay = 5
        while True:
            try:
                me = await self.api.get_me()
                self.username = me.get("username") if isinstance(me, dict) else None
                log.info("Telegram bot @%s is polling for messages", self.username)
                return
            except TelegramError as e:
                if e.code == 401:
                    log.error("Telegram rejected TELEGRAM_BOT_TOKEN (401); retrying in an hour")
                    await asyncio.sleep(3600)
                    continue
                log.warning("getMe failed: %s %s", e.code, e.description)
            except TelegramNetworkError as e:
                log.warning("getMe failed: %s", e)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 300)

    async def _housekeeping(self, ok: bool, error: str | None = None) -> None:
        now = time.monotonic()
        try:
            if now >= self._next_cleanup:
                self._next_cleanup = now + CLEANUP_EVERY
                self._prune_reply_state()
                async with self.repo() as repo:
                    removed = await repo.cleanup(sorted(self.allowed_env))
                if any(removed.values()):
                    log.info("retention clean-up: %s", removed)
            if now >= self._next_status or not ok:
                self._next_status = now + STATUS_EVERY
                async with self.repo() as repo:
                    await repo.set_status({**self.stats, "ok": ok, "error": error, "username": self.username,
                                           "last_poll": datetime.now(timezone.utc).isoformat()})
        except Exception:
            log.exception("bot housekeeping failed")

    async def _save_offset(self) -> None:
        try:
            async with self.repo() as repo:
                await repo.set_offset(self.offset)
        except Exception:
            log.warning("could not save the update offset (continuing with it in memory)")

    async def poll_once(self) -> int:
        """One getUpdates round. Returns the number of updates handled."""
        updates = await self.api.get_updates(self.offset)
        n = 0
        for upd in updates:
            if not isinstance(upd, dict) or not isinstance(upd.get("update_id"), int):
                continue
            # at-most-once: move past the update before handling it, so a bad update can't wedge the bot
            self.offset = max(self.offset or 0, upd["update_id"] + 1)
            await self._save_offset()
            self.stats["updates"] += 1
            await self.handle_update(upd)
            n += 1
        return n

    async def run_forever(self) -> None:
        await self.wait_until_ready()
        await self.identify()
        backoff = 1
        while True:
            await self._housekeeping(ok=True)
            try:
                await self.poll_once()
                backoff = 1
                continue
            except TelegramError as e:
                err = f"{e.code} {e.description}"
                if e.code == 401:
                    log.error("Telegram rejected TELEGRAM_BOT_TOKEN (401); retrying in an hour")
                    wait = 3600
                elif e.code == 409:
                    log.warning("getUpdates conflict (409): another bot process or a webhook uses this token")
                    wait = 30
                elif e.code == 429:
                    wait = min(e.retry_after or 5, 300)
                else:
                    log.warning("getUpdates failed: %s", err)
                    wait = backoff
            except TelegramNetworkError as e:
                err = str(e)
                log.warning("getUpdates failed: %s", err)
                wait = backoff
            except Exception as e:
                err = type(e).__name__
                log.exception("bot poll loop error")
                wait = backoff
            await self._housekeeping(ok=False, error=err[:300])
            await asyncio.sleep(wait)
            backoff = min(backoff * 2, 60)


async def run() -> None:
    s = settings()
    if not s.telegram_bot_token:
        log.warning("TELEGRAM_BOT_TOKEN is not set, so the Telegram bot is idle. Set it in .env and restart "
                    "the bot service.")
        while True:
            await asyncio.sleep(3600)
    client = httpx.AsyncClient(timeout=httpx.Timeout(15.0, read=POLL_TIMEOUT + 20),
                               headers={"User-Agent": "cybercheck-bot"},
                               limits=httpx.Limits(max_connections=4, max_keepalive_connections=2))
    try:
        await Bot(TelegramAPI(s.telegram_bot_token, client)).run_forever()
    finally:
        await client.aclose()
        await db.close()
