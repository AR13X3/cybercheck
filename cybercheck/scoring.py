"""Score hostnames against the brand watchlist.

score_hostname() is a pure function of (hostname, watchlist). It is called for every hostname in
the CT stream (~1,000/s), so the no-match path is kept cheap: Aho-Corasick automatons find brand
keywords, typo variants and bait words in one pass each.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import ahocorasick
import yaml
from publicsuffixlist import PublicSuffixList

from .normalize import clean_hostname, decode_idna, folds, scripts_in, skeleton

# ---- weights (0-100 scale) -------------------------------------------------------------
W_KEYWORD_REG = 45        # brand keyword in the registered label (commbank-login.top)
W_KEYWORD_SUB = 35        # brand keyword only in a subdomain (commbank.secure-host.xyz)
W_TYPO_REG = 40           # one-edit typo of a keyword in the registered label (westpak.com)
W_TYPO_SUB = 30
W_HOMOGLYPH_BONUS = 10    # keyword only visible after mapping look-alike Unicode letters
W_LOOKALIKE_BONUS = 5     # keyword only visible after folding digits / rn->m
W_SHORT_REG = 38          # short token with context (anz-verify.top, nablogin.xyz)
W_SHORT_SUB = 28
W_NO_CONTEXT = 20         # needs_context brand matched without bait or AU context
W_OFFICIAL_EMBED = 15     # official domain written into the hostname (commbank.com.au.x.top)
W_BAIT_STRONG = 12
W_BAIT_WEAK = 5
CAP_BAIT = 25
W_AU_CONTEXT = 8
W_SUSPICIOUS_TLD = 12
W_DEEP_SUB = 8            # 4+ subdomain labels
W_MANY_HYPHENS = 5        # 3+ hyphens in one label
W_MIXED_SCRIPT = 10       # Latin mixed with Cyrillic/Greek in one label

# Short tokens that end ordinary English words ("parceltracking", "onlinebanking"): whole token only at the end.
NO_GLUE_END = {"ing", "amp", "ato"}

_SPLIT = re.compile(r"[^a-z0-9]+")
_TLD_MIMIC = re.compile(r"(gov|com|net|org)[.-]au([.-]|$)")

_psl = PublicSuffixList()


@dataclass
class Brand:
    id: str
    name: str
    category: str
    priority: int
    keywords: list[str]
    short_tokens: list[str]
    official_domains: list[str]
    needs_context: bool = False
    short_requires_au: bool = False   # short tokens of this brand need AU context, a bait word is not enough
    exclude: list[str] = field(default_factory=list)


@dataclass
class Hit:
    hostname: str
    registered_domain: str
    unicode_domain: str | None
    tld: str
    brand_id: str
    brand_name: str
    score: int
    tier: str
    reasons: list[dict]
    match: dict


def _nohyphen(s: str) -> str:
    return s.replace("-", "").replace(".", "")


_NEAR = {  # QWERTY neighbours + visual and sound-alike confusions (c/k/s, i/y), used for typo variants
    "a": "qszo", "b": "vghnd", "c": "xdfveks", "d": "serfcxb", "e": "wrdsc", "f": "drtgvc",
    "g": "ftyhbvq", "h": "gyujnb", "i": "uojkl1y", "j": "huikmn", "k": "jiolmcq", "l": "kopi1",
    "m": "njkn", "n": "bhjmu", "o": "iklpa0", "p": "ol", "q": "wag", "r": "edft", "s": "awedxz5c",
    "t": "rfgy", "u": "yhjiv", "v": "cfgbu", "w": "qase", "x": "zsdc", "y": "tghui", "z": "asx",
}


def typo_variants(keyword: str) -> set[str]:
    """One-edit variants: deletion, transposition, doubled letter, near-key/visual substitution."""
    out: set[str] = set()
    n = len(keyword)
    for i in range(n):
        out.add(keyword[:i] + keyword[i + 1:])
        out.add(keyword[:i] + keyword[i] + keyword[i:])
        for r in _NEAR.get(keyword[i], ""):
            out.add(keyword[:i] + r + keyword[i + 1:])
    for i in range(n - 1):
        out.add(keyword[:i] + keyword[i + 1] + keyword[i] + keyword[i + 2:])
    out.discard(keyword)
    return {v for v in out if len(v) >= 6}


class Watchlist:
    def __init__(self, data: dict, store_threshold: int = 40, review_threshold: int = 60, high_threshold: int = 75):
        self.store_threshold = store_threshold
        self.review_threshold = review_threshold
        self.high_threshold = high_threshold
        self.brands: dict[str, Brand] = {}
        for b in data["brands"]:
            brand = Brand(
                id=b["id"], name=b["name"], category=b.get("category", "other"), priority=int(b.get("priority", 3)),
                keywords=[_nohyphen(k.lower()) for k in (b.get("keywords") or [])],
                short_tokens=[k.lower() for k in (b.get("short_tokens") or [])],
                official_domains=[d.lower() for d in (b.get("official_domains") or [])],
                needs_context=bool(b.get("needs_context", False)),
                short_requires_au=bool(b.get("short_requires_au", False)),
                exclude=[e.lower() for e in (b.get("exclude") or [])],
            )
            self.brands[brand.id] = brand

        self.official: dict[str, str] = {}
        for brand in self.brands.values():
            for d in brand.official_domains:
                self.official[d] = brand.id
        for d in data.get("extra_allowlist") or []:
            self.official[d.lower()] = "_allowlist"

        self.kw_auto = ahocorasick.Automaton()
        self.typo_auto = ahocorasick.Automaton()
        exact_keys: set[str] = set()
        for brand in self.brands.values():
            for kw in brand.keywords:
                exact_keys.add(kw)
                self.kw_auto.add_word(kw, (brand.id, kw))
        for brand in self.brands.values():
            for kw in brand.keywords:
                if len(kw) < 6:
                    continue
                for v in typo_variants(kw):
                    if v in exact_keys or self.typo_auto.exists(v):
                        continue
                    self.typo_auto.add_word(v, (brand.id, kw, len(v)))
        self.kw_auto.make_automaton()
        if len(self.typo_auto):
            self.typo_auto.make_automaton()

        self.short: dict[str, str] = {}
        for brand in self.brands.values():
            for t in brand.short_tokens:
                self.short[t] = brand.id
        self.short_by_len = sorted(self.short, key=len, reverse=True)

        bait = data.get("bait_words") or {}
        self.au_context = {t.lower() for t in (data.get("au_context_tokens") or [])}
        self.bait_strong = {_nohyphen(w.lower()) for w in bait.get("strong", [])}
        self.bait_weak = {_nohyphen(w.lower()) for w in bait.get("weak", [])} - self.bait_strong - self.au_context - {""}
        self.bait_auto = ahocorasick.Automaton()
        for w in self.bait_strong | self.bait_weak:
            if len(w) >= 4:
                self.bait_auto.add_word(w, w)
        if not len(self.bait_auto):
            # pyahocorasick cannot iterate an empty automaton; a NUL never occurs in a cleaned hostname
            self.bait_auto.add_word("\x00", "\x00")
        self.bait_auto.make_automaton()
        self._glue_words = sorted(w for w in self.bait_strong | self.bait_weak | self.au_context if len(w) >= 2)
        self.suspicious_tlds = {t.lower().lstrip(".") for t in (data.get("suspicious_tlds") or [])}

    # ---------------------------------------------------------------------------------
    def tier_for(self, score: int) -> str:
        if score >= self.high_threshold:
            return "high"
        if score >= self.review_threshold:
            return "review"
        return "watch"

    def is_official(self, hostname: str) -> bool:
        labels = hostname.split(".")
        for i in range(len(labels) - 1):
            if ".".join(labels[i:]) in self.official:
                return True
        return False

    def _short_hits(self, part: str) -> list[tuple[str, str, str, str]]:
        """Short tokens used as whole tokens or glued to bait words. Returns (brand_id, token, how, label)."""
        out = []
        for label in part.split("."):
            tokens = [t for t in _SPLIT.split(label) if t]
            for t in tokens:
                if t in self.short:
                    out.append((self.short[t], t, "token", label))
            flat = label.replace("-", "")
            for s in self.short_by_len:
                if len(flat) <= len(s) or s not in flat:
                    continue
                if flat.startswith(s):
                    rest = flat[len(s):]
                    if self._starts_with_bait(rest):
                        out.append((self.short[s], s, "glued", label))
                        continue
                if flat.endswith(s) and s not in NO_GLUE_END:
                    rest = flat[: -len(s)]
                    if rest in ("my", "the") or self._ends_with_strong_bait(rest):
                        out.append((self.short[s], s, "glued", label))
        return out

    def _edge_ok(self, unit: str, kw: str) -> bool:
        i = unit.find(kw)
        while i != -1:
            before, rest = unit[:i], unit[i + len(kw):]
            if (not before and (not rest or self._starts_with_bait(rest))) or \
               (not rest and (before in ("my", "the") or self._ends_with_strong_bait(before))) or \
               (self._ends_with_strong_bait(before) and self._starts_with_bait(rest)):
                return True
            i = unit.find(kw, i + 1)
        return False

    def _starts_with_bait(self, s: str) -> bool:
        return any(s.startswith(w) for w in self._glue_words)

    def _ends_with_strong_bait(self, s: str) -> bool:
        return any(s.endswith(w) for w in self.bait_strong if len(w) >= 4)

    # ---------------------------------------------------------------------------------
    def score_hostname(self, raw: str) -> Hit | None:
        host = clean_hostname(raw)
        if host is None or host.endswith(".gov.au") or host == "gov.au":
            return None
        suffix = _psl.publicsuffix(host)
        registered = _psl.privatesuffix(host)
        if not registered or not suffix:
            return None
        if self.is_official(host):
            return None

        reg_label = registered[: -len(suffix) - 1]
        sub = host[: -len(registered) - 1] if len(host) > len(registered) else ""
        unicode_host = decode_idna(host)
        is_idn = unicode_host != host

        # Candidate strings per location. kind: exact | homoglyph | lookalike
        cands: list[tuple[str, str, str]] = []  # (location, kind, text)
        for loc, part in (("reg", reg_label), ("sub", sub)):
            if not part:
                continue
            flat = _nohyphen(part)
            cands.append((loc, "exact", flat))
            if is_idn:
                uni_part = decode_idna(part)
                if uni_part != part:
                    sk = _nohyphen(skeleton(uni_part))
                    if sk and sk != flat:
                        cands.append((loc, "homoglyph", sk))
                        for f in folds(sk):
                            cands.append((loc, "homoglyph", f))
            for f in folds(flat):
                cands.append((loc, "lookalike", f))

        # Brand keyword / typo matches. best[brand_id] = (points, description, match dict)
        found: dict[str, tuple[int, str, dict]] = {}

        def consider(bid: str, pts: int, why: str, match: dict) -> None:
            if bid not in found or pts > found[bid][0]:
                found[bid] = (pts, why, match)

        units_cache: dict[tuple[str, str], list[str]] = {}

        def units(loc: str, kind: str) -> list[str]:
            """Tokens and adjacent token pairs ("my"+"gov") of a part, in the given normalisation."""
            key = (loc, kind)
            if key not in units_cache:
                part = reg_label if loc == "reg" else sub
                if kind != "exact" and is_idn:
                    part = skeleton(decode_idna(part))
                out: list[str] = []
                for label in part.split("."):
                    toks = [t for t in _SPLIT.split(label) if t]
                    variants = [toks] + ([[f for t in toks for f in (folds(t)[:1] or [t])]] if kind == "lookalike" else [])
                    for tl in variants:
                        out += tl
                        out += [a + b for a, b in zip(tl, tl[1:])]
                units_cache[key] = out
            return units_cache[key]

        for loc, kind, text in cands:
            for end, (bid, kw) in self.kw_auto.iter(text):
                # Short keywords (<= 6 letters: optus, mygov, payid) must sit at a word edge or be glued
                # to a bait word; long ones are distinctive enough to match anywhere.
                if len(kw) <= 6 and not any(self._edge_ok(u, kw) for u in units(loc, kind)):
                    continue
                base = W_KEYWORD_REG if loc == "reg" else W_KEYWORD_SUB
                bonus = W_HOMOGLYPH_BONUS if kind == "homoglyph" else W_LOOKALIKE_BONUS if kind == "lookalike" else 0
                where = "domain name" if loc == "reg" else "subdomain"
                how = {"exact": "", "homoglyph": " (look-alike Unicode letters)", "lookalike": " (look-alike characters)"}[kind]
                consider(bid, base + bonus, f"brand keyword '{kw}' in {where}{how}",
                         {"keyword": kw, "kind": kind, "location": loc})

        # Typos only count when they sit at a token edge ("westpak-online", "commbnklogin"), so that
        # one-edit variants hidden inside ordinary words ("onli[nebank]ing") don't match.
        if len(self.typo_auto):
            for loc, part in (("reg", reg_label), ("sub", sub)):
                if not part:
                    continue
                part_sk = skeleton(decode_idna(part)) if is_idn else part
                for tok in _SPLIT.split(part_sk):
                    if len(tok) < 5:
                        continue
                    for end, (bid, kw, vlen) in self.typo_auto.iter(tok):
                        start = end - vlen + 1
                        rest, before = tok[end + 1:], tok[:start]
                        # whole token, or glued only to bait words ("westpaklogin", "mywestpak")
                        if not ((start == 0 and (not rest or self._starts_with_bait(rest)))
                                or (not rest and (before in ("my", "the") or self._ends_with_strong_bait(before)))):
                            continue
                        base = W_TYPO_REG if loc == "reg" else W_TYPO_SUB
                        bonus = W_HOMOGLYPH_BONUS if part_sk != part else 0
                        where = "domain name" if loc == "reg" else "subdomain"
                        consider(bid, base + bonus, f"typo of brand keyword '{kw}' in {where}",
                                 {"keyword": kw, "kind": "typo", "location": loc})

        nonsuffix = host[: -len(suffix) - 1]
        nonsuffix_sk = skeleton(decode_idna(nonsuffix)) if is_idn else nonsuffix
        tokens = {t for t in _SPLIT.split(nonsuffix_sk) if t}

        # Bait words: whole tokens plus words glued into labels (commbanklogin)
        bait_tokens = (tokens & self.bait_strong) | (tokens & self.bait_weak)
        glued = {w for _, w in self.bait_auto.iter(_nohyphen(nonsuffix_sk))}

        for bid, tok, how, label in self._short_hits(nonsuffix_sk):
            loc = "reg" if tok in reg_label.replace("-", "") or tok in _nohyphen(skeleton(decode_idna(reg_label))) else "sub"
            consider(bid, -1, f"short brand token '{tok}' ({'whole token' if how == 'token' else 'joined to a bait word'})",
                     {"keyword": tok, "kind": "short_" + how, "location": loc, "label": label})

        if not found:
            return None

        # AU context from the name itself. An .au suffix alone is not context: real Australian
        # businesses named after places (bendigo-plumbing.com.au) live there.
        au_ctx = bool(tokens & self.au_context) or bool(_TLD_MIMIC.search(nonsuffix_sk))
        best: Hit | None = None
        for bid, (pts, why, match) in found.items():
            brand = self.brands[bid]
            if any(e in host for e in brand.exclude):
                continue
            kw = match["keyword"]
            bait_hits = sorted({w for w in bait_tokens | glued if w not in kw and kw not in w})
            strong = [w for w in bait_hits if w in self.bait_strong]
            weak = [w for w in bait_hits if w in self.bait_weak]
            context = bool(strong) or au_ctx
            reasons: list[dict] = []

            if match["kind"].startswith("short_"):
                # anz/nab/ato alone is far too ambiguous: need AU context, or a strong bait word
                # with the token in the registered name (not buried in a long subdomain)
                # the strong bait word must be in the same label as the token ("nab-login", not "login.nab-abzar")
                lab = match.get("label", "")
                lab_strong = {t for t in _SPLIT.split(lab) if t in self.bait_strong} | \
                             {w for _, w in self.bait_auto.iter(lab.replace("-", "")) if w in self.bait_strong and kw not in w}
                if brand.short_requires_au and not au_ctx:
                    continue
                if not (au_ctx or (lab_strong and match["location"] == "reg")):
                    continue
                pts = W_SHORT_REG if match["location"] == "reg" else W_SHORT_SUB
            elif brand.needs_context and not context:
                pts = W_NO_CONTEXT
                why += " (common word / other-country brand, no bait or AU context)"
            reasons.append({"points": pts, "why": why})
            score = pts

            bait_pts = min(CAP_BAIT, W_BAIT_STRONG * len(strong) + W_BAIT_WEAK * len(weak))
            if bait_pts:
                words = ", ".join(strong + weak)
                reasons.append({"points": bait_pts, "why": f"bait words: {words}"})
                score += bait_pts
            if au_ctx:
                reasons.append({"points": W_AU_CONTEXT, "why": "Australian context (au / gov-au / com-au)"})
                score += W_AU_CONTEXT
            # name the longest one, so auspost.com.au-x.info says auspost.com.au, not auspost.com
            for od in sorted(brand.official_domains, key=len, reverse=True):
                if od in host or od.replace(".", "-") in host:
                    reasons.append({"points": W_OFFICIAL_EMBED, "why": f"official domain '{od}' written into the hostname"})
                    score += W_OFFICIAL_EMBED
                    break
            if suffix in self.suspicious_tlds or suffix.split(".")[-1] in self.suspicious_tlds:
                reasons.append({"points": W_SUSPICIOUS_TLD, "why": f"high-abuse suffix .{suffix}"})
                score += W_SUSPICIOUS_TLD
            if sub and sub.count(".") >= 3:
                reasons.append({"points": W_DEEP_SUB, "why": f"deep subdomain ({sub.count('.') + 1} labels)"})
                score += W_DEEP_SUB
            if any(label.count("-") >= 3 for label in host.split(".")):
                reasons.append({"points": W_MANY_HYPHENS, "why": "3+ hyphens in one label"})
                score += W_MANY_HYPHENS
            if is_idn:
                for label in unicode_host.split("."):
                    sc = scripts_in(label)
                    if "LATIN" in sc and len(sc) > 1:
                        reasons.append({"points": W_MIXED_SCRIPT, "why": f"mixed scripts in '{label}'"})
                        score += W_MIXED_SCRIPT
                        break
            if match["location"] == "reg" and reg_label.replace("-", "") == kw and not bait_hits:
                reasons.append({"points": 0, "why": "exact brand name on another suffix (may be a defensive registration)"})

            score = min(100, score)
            if best is None or score > best.score:
                best = Hit(
                    hostname=host, registered_domain=registered,
                    unicode_domain=decode_idna(registered) if is_idn else None,
                    tld=suffix, brand_id=bid, brand_name=brand.name, score=score,
                    tier=self.tier_for(score), reasons=reasons, match=match,
                )
        if best is None or best.score < self.store_threshold:
            return None
        return best


def load_watchlist(path: str | Path, **thresholds) -> Watchlist:
    with open(path, encoding="utf-8") as f:
        return Watchlist(yaml.safe_load(f), **thresholds)


@lru_cache(maxsize=1)
def default_watchlist() -> Watchlist:
    from .config import settings
    return load_watchlist(settings().watchlist_path, store_threshold=settings().store_threshold,
                          review_threshold=settings().review_threshold, high_threshold=settings().high_threshold)
