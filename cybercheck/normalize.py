"""Hostname normalisation: punycode decoding, homoglyph skeletons and lookalike folding."""
from __future__ import annotations

import re
import unicodedata

# Characters that look like ASCII letters. NFKC handles fullwidth forms and NFKD+strip handles
# accented Latin letters; this table covers other scripts and special Latin letters.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "к": "k", "м": "m", "н": "h", "т": "t", "ь": "b", "п": "n", "г": "r", "ү": "y", "ө": "o",
    "ӧ": "o", "ԍ": "g", "ɡ": "g", "ꞵ": "b", "ѡ": "w", "ԋ": "h", "ӑ": "a", "ӓ": "a", "ӗ": "e",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "γ": "y", "ω": "w", "η": "n", "μ": "u", "ϲ": "c", "ϳ": "j", "ς": "c",
    "ί": "i", "ό": "o", "ά": "a", "έ": "e", "ύ": "u", "ώ": "w",
    # Armenian
    "օ": "o", "ս": "u", "ո": "n", "հ": "h", "ց": "g", "զ": "q", "ա": "w", "ք": "p",
    # Latin specials / IPA / small caps
    "ı": "i", "ł": "l", "ɑ": "a", "ɩ": "i", "ʟ": "l", "ɴ": "n", "ᴏ": "o", "ʀ": "r", "ᴄ": "c",
    "ᴅ": "d", "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ᴋ": "k", "ᴍ": "m", "ᴘ": "p", "ꜱ": "s", "ᴛ": "t",
    "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z", "ƅ": "b", "ɓ": "b", "ƈ": "c", "ɗ": "d",
    "ɛ": "e", "ƒ": "f", "ɦ": "h", "ɨ": "i", "ʝ": "j", "ƙ": "k", "ɱ": "m", "ɲ": "n", "ɵ": "o",
    "ƥ": "p", "ʠ": "q", "ɽ": "r", "ʂ": "s", "ƭ": "t", "ʋ": "v", "ⱳ": "w", "ƴ": "y", "ȥ": "z",
    "ø": "o", "đ": "d", "ħ": "h", "ŧ": "t", "ß": "ss", "æ": "ae", "œ": "oe", "þ": "p",
}

# Digit / multi-letter lookalikes used *after* skeletonising (commbank vs c0mmbank, comrnbank)
_DIGIT_FOLD = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})
_DIGIT_FOLD_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

_VALID_HOST = re.compile(r"^[a-z0-9_.*-]+$")


def clean_hostname(raw: str) -> str | None:
    """Lowercase, strip wildcard and trailing dot. Returns None for things that aren't hostnames."""
    h = raw.strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if not h or "." not in h or len(h) > 253 or not _VALID_HOST.match(h) or "*" in h:
        return None
    return h


def decode_idna(hostname: str) -> str:
    """Decode xn-- labels to Unicode, leaving labels that fail to decode as they are."""
    if "xn--" not in hostname:
        return hostname
    out = []
    for label in hostname.split("."):
        if label.startswith("xn--"):
            try:
                u = label[4:].encode("ascii").decode("punycode")
                # Not valid IDNA, so no browser shows it: lone surrogates, control and other non-printing
                # characters. Keep the xn-- form rather than score (and store) a name nobody can see.
                if u and all(unicodedata.category(ch) not in ("Cs", "Cc", "Co", "Cn") for ch in u):
                    out.append(u)
                    continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def skeleton(text: str) -> str:
    """Map a Unicode string to its closest ASCII look-alike."""
    s = unicodedata.normalize("NFKC", text).lower()
    s = "".join(CONFUSABLES.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = "".join(CONFUSABLES.get(ch, ch) for ch in s)
    return "".join(ch if ("a" <= ch <= "z" or "0" <= ch <= "9" or ch in ".-") else "" for ch in s)


def scripts_in(text: str) -> set[str]:
    """Rough set of scripts used by the letters in text (LATIN, CYRILLIC, GREEK, ...)."""
    found = set()
    for ch in text:
        if ch.isalpha():
            try:
                found.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                found.add("UNKNOWN")
    return found


def folds(ascii_text: str) -> list[str]:
    """Lookalike folds of an ASCII string (digits->letters, rn->m...). Excludes the input itself."""
    out = []
    for table in (_DIGIT_FOLD, _DIGIT_FOLD_I):
        f = ascii_text.translate(table)
        for a, b in _MULTI:
            f = f.replace(a, b)
        if f != ascii_text and f not in out:
            out.append(f)
    return out
