"""cybercheck.normalize: hostname clean-up, punycode decoding, look-alike skeletons and folds.

Every hostname here is made up (`.example` names), and nothing is looked up or contacted.
"""
from __future__ import annotations

import pytest

from cybercheck.normalize import clean_hostname, decode_idna, folds, scripts_in, skeleton

CYRILLIC_A = "а"     # 'а', looks like Latin 'a'
GREEK_OMICRON = "ο"  # 'ο', looks like Latin 'o'
# "commbаnk-login.example" with a Cyrillic 'а', as it appears in a certificate (punycode)
CYRILLIC_HOST = f"commb{CYRILLIC_A}nk-login.example".encode("idna").decode("ascii")


@pytest.mark.parametrize("raw,expected", [
    ("COMMBANK-LOGIN.Example", "commbank-login.example"),       # hostnames are case-insensitive
    ("commbank-login.example.", "commbank-login.example"),      # fully qualified form
    ("commbank-login.example..", "commbank-login.example"),
    ("*.commbank-login.example", "commbank-login.example"),     # wildcard certificate
    ("  commbank-login.example\n", "commbank-login.example"),   # stray whitespace from a feed
    ("secure.login.commbank-verify.example", "secure.login.commbank-verify.example"),
    ("commbank_login.example", "commbank_login.example"),       # underscores occur in certificate names
    (CYRILLIC_HOST.upper(), CYRILLIC_HOST),                      # punycode is lowercased too
])
def test_clean_hostname_normalises(raw, expected):
    assert clean_hostname(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "*.", "a.*.example", "bad host.example", "https://commbank-login.example/",
    "commbank-login.example:443",
    # Unicode is refused: certificates carry the punycode (xn--) form, and the bot encodes Unicode names
    # to punycode before calling clean_hostname
    f"commb{CYRILLIC_A}nk.example",
])
def test_clean_hostname_rejects_what_is_not_a_hostname(raw):
    assert clean_hostname(raw) is None


def test_clean_hostname_length_limit_is_253():
    longest = ".".join(["a" * 63] * 3 + ["a" * 61])     # 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
    assert len(longest) == 253
    assert clean_hostname(longest) == longest
    assert clean_hostname("a" + longest) is None


def test_decode_idna_decodes_only_punycode_labels():
    assert decode_idna(CYRILLIC_HOST) == f"commb{CYRILLIC_A}nk-login.example"
    assert decode_idna("www." + CYRILLIC_HOST) == f"www.commb{CYRILLIC_A}nk-login.example"
    assert decode_idna("commbank-login.example") == "commbank-login.example"


def test_decode_idna_keeps_an_empty_punycode_label():
    assert decode_idna("xn--.example") == "xn--.example"


@pytest.mark.parametrize("text,expected", [
    (f"commb{CYRILLIC_A}nk", "commbank"),
    (f"c{GREEK_OMICRON}mmbank", "commbank"),
    ("ｃｏｍｍｂａｎｋ", "commbank"),   # fullwidth letters
    ("cömmbänk", "commbank"),                                   # accented Latin letters
    ("COMMBANK", "commbank"),
    ("straße", "strasse"),                                           # ß becomes two letters
    ("comm bank!", "commbank"),                                           # other characters are dropped
    ("login.commbank-verify", "login.commbank-verify"),                   # dots and hyphens are kept
])
def test_skeleton_maps_lookalikes_to_ascii(text, expected):
    assert skeleton(text) == expected


@pytest.mark.parametrize("text,expected", [
    (f"commb{CYRILLIC_A}nk", {"LATIN", "CYRILLIC"}),
    (f"c{GREEK_OMICRON}mmbank", {"LATIN", "GREEK"}),
    ("commbank", {"LATIN"}),
    ("123-.", set()),                                                     # only letters count
])
def test_scripts_in(text, expected):
    assert scripts_in(text) == expected


@pytest.mark.parametrize("text,fold", [
    ("c0mmbank", "commbank"),      # zero for o
    ("cornmbank", "commbank"),     # rn for m
    ("we5tpac", "westpac"),        # 5 for s
    ("auspo5t", "auspost"),
])
def test_folds_undo_lookalike_characters(text, fold):
    assert fold in folds(text)


def test_folds_try_both_readings_of_1():
    assert {"nabl", "nabi"} <= set(folds("nab1"))


def test_folds_leave_out_the_input_itself():
    assert folds("commbank") == []
    assert "c0mmbank" not in folds("c0mmbank")
