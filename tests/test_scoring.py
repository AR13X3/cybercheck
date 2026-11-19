from pathlib import Path

import pytest

from cybercheck.scoring import load_watchlist

WL = load_watchlist(Path(__file__).resolve().parent.parent / "config" / "watchlist.yaml")


def score(host):
    hit = WL.score_hostname(host)
    return (hit.brand_id, hit.tier, hit.score) if hit else None


@pytest.mark.parametrize("host,brand,min_tier", [
    ("commbank-login.top", "commbank", "review"),
    ("commbank-verify-account.top", "commbank", "high"),
    ("netbank-secure-update.xyz", "commbank", "high"),
    ("www.commbank.com.au.secure-check.top", "commbank", "high"),
    ("c0mmbank-login.com", "commbank", "review"),
    ("comrnbank-login.com", "commbank", "review"),
    ("westpak-online-banking.com", "westpac", "review"),
    ("anz-verify.top", "anz", "review"),
    ("nablogin.xyz", "nab", "review"),
    ("mygov-au-refund.cfd", "mygov", "high"),
    ("my-gov-login.sbs", "mygov", "review"),
    ("ato-gov-au-refund.com", "ato", "review"),
    ("auspost-redelivery.top", "auspost", "high"),
    ("auspost.com.au-track.info", "auspost", "high"),
    ("linkt-toll-payment.top", "linkt", "review"),
    ("linkttoll.com", "linkt", "watch"),
    ("telstra-account-suspended.online", "telstra", "high"),
    ("centrelink-payment.xyz", "centrelink", "review"),
    ("medicare-rebate-au.top", "medicare", "high"),
    ("optus-verify.top", "optus", "review"),
    ("myoptus-login.top", "optus", "review"),
    ("secureoptusupdate.top", "optus", "review"),
    ("payid-pending-transfer.top", "payid", "high"),
    ("ing-au-login.top", "ing", "review"),
    ("nab-secure-login.top", "nab", "review"),
    ("toll-linkt-vip-au.top", "linkt", "high"),
    ("www.bendigo-web-logon.ph", "bendigo", "review"),
    ("online-mygovau.pages.dev", None, None),
    ("xn--commbnk-0ug.top", None, None),  # placeholder, replaced below
])
def test_flags(host, brand, min_tier):
    if brand is None:
        pytest.skip("placeholder")
    res = score(host)
    assert res is not None, host
    got_brand, tier, _ = res
    assert got_brand == brand, (host, res)
    order = ["watch", "review", "high"]
    assert order.index(tier) >= order.index(min_tier), (host, res)


def test_homoglyph_cyrillic():
    # "commbаnk" with a Cyrillic 'а'
    host = "commbаnk-login.top".encode("idna").decode("ascii")
    res = WL.score_hostname(host)
    assert res is not None and res.brand_id == "commbank"
    assert res.match["kind"] == "homoglyph"


@pytest.mark.parametrize("host", [
    "commbank.com.au", "www.commbank.com.au", "netbank.commbank.com.au", "my.gov.au", "login.my.gov.au",
    "ato.gov.au", "anything.gov.au", "linktr.ee", "www.linktree.com", "mygov.in", "bonanza.top",
    "tomato.xyz", "nabila.shop", "parceltracking.top", "onlinebanking.example.com", "singing.com",
    "eucalyptus.com", "medicare.gov", "bendigo-plumbing.com.au", "port-macquarie-cafe.com.au",
    "kmart.com", "random-site.top", "example.com", "auspost.com.au", "telstra.com",
    # false positives seen on the live stream
    "zippy-pixie-1959.chatgpt.site", "demo.servicevibes.co", "marketplace.bylinebank.com",
    "commscope.direct.quickconnect.cn", "payment.selectorr-amp.ru", "hjeayxsz.theshoppingdirectory.com",
    "eucalyptusoptusx.com", "mygovernmentjobs.top", "racingaustralia.tips", "login.nab-abzar.ir",
    "nagroup.com.vn", "payid-pokies-games-australia.shop", "mycoles.com.au.mcas.ms", "internetbanking-online.de",
    "login-qc2.dx-idm.vodafone.co.uk", "www.medicarecoveragechecker.com",
    "store.svutsnmlsupdate.update.idrotermica-di-allegri-ing-fabio-c-srl-7.partner-viessmann.it",
])
def test_not_flagged(host):
    assert score(host) is None, (host, WL.score_hostname(host))


def test_defensive_style_exact_name_is_low():
    res = score("optus.xyz")
    assert res is not None and res[1] == "watch"


def test_watchlist_without_bait_words_still_scores():
    """pyahocorasick refuses to iterate an empty automaton; a watchlist with no bait words must still work."""
    import yaml
    from cybercheck.config import ROOT
    from cybercheck.scoring import Watchlist
    data = yaml.safe_load((ROOT / "config/watchlist.yaml").read_text(encoding="utf-8"))
    data["bait_words"] = {}
    wl = Watchlist(data)
    assert wl.score_hostname("commbank-login.top") is not None
    assert wl.score_hostname("example.com") is None


def test_punycode_that_is_not_valid_idna_is_not_decoded():
    """A crafted xn-- label can decode to a lone surrogate or control character, which no browser displays.
    It stays in its xn-- form (scored on that), and a real homoglyph IDN still decodes and scores high."""
    from cybercheck.normalize import decode_idna
    from cybercheck.scoring import default_watchlist
    assert decode_idna("xn--cmmbank-8of35100c.top") == "xn--cmmbank-8of35100c.top"
    real = "xn--" + "cοmmbank-login".encode("punycode").decode() + ".top"     # Greek omicron
    assert decode_idna(real) == "cοmmbank-login.top"
    hit = default_watchlist().score_hostname(real)
    assert hit is not None and hit.tier == "high"


def test_hsbc_group_sites_abroad_are_allowlisted_but_not_argentina():
    from cybercheck.scoring import default_watchlist
    wl = default_watchlist()
    for host in ("www.sit-insh-wechat-wgw.hsbc.com.cn", "tw-aem-tko-lp.hsbc.com.hk",
                 "static.lp.services.online-banking.hsbc.com.mx", "online.hsbc.co.uk"):
        assert wl.score_hostname(host) is None, host
    assert wl.score_hostname("rewards.hsbc.com.ar") is not None           # not verified: still flagged
    assert wl.score_hostname("login.hsbc.com.hkmi.hk") is not None         # lookalike still flagged
    assert wl.score_hostname("n7k4p4.hsbc-online-banking.co.uk") is not None


# ---------------------------------------------------------------------------------------------------
# Tricky forms of the same name. Made-up .example hostnames, except where a brand's real suffix is the
# point of the test (its official domains). Assertions are on brand, match kind and reasons, not on
# exact points, so tuning the weights does not break them.

CYRILLIC_A = "а"       # 'а', looks like Latin 'a'
GREEK_OMICRON = "ο"    # 'ο', looks like Latin 'o'


def puny(host):
    """The punycode (xn--) form of a Unicode hostname, as it appears in a certificate."""
    return host.encode("idna").decode("ascii")


@pytest.mark.parametrize("variant", [
    "COMMBANK-LOGIN.EXAMPLE", "commbank-login.example.", "*.commbank-login.example", " commbank-login.example ",
])
def test_how_a_hostname_is_written_does_not_change_its_score(variant):
    assert score(variant) == score("commbank-login.example") is not None


def test_uppercase_punycode_scores_like_lowercase():
    host = puny(f"commb{CYRILLIC_A}nk-login.example")
    assert score(host.upper()) == score(host) is not None


@pytest.mark.parametrize("host", [
    "WWW.COMMBANK.COM.AU.", "NetBank.Commbank.com.au", "*.commbank.com.au", " commbank.com.au ",
])
def test_official_domains_stay_allowlisted_however_they_are_written(host):
    assert score(host) is None


def test_lookalike_of_an_official_domain_is_not_allowlisted():
    """A Cyrillic 'а' in commbank.com.au is a different domain: it must be flagged, not allowlisted."""
    hit = WL.score_hostname(puny(f"commb{CYRILLIC_A}nk.com.au"))
    assert hit is not None and hit.brand_id == "commbank"
    assert hit.match["kind"] == "homoglyph"


@pytest.mark.parametrize("host,kind", [
    ("c0mmbank-login.example", "lookalike"),                           # zero for o
    ("cornmbank-login.example", "lookalike"),                          # rn for m
    (puny(f"commb{CYRILLIC_A}nk-login.example"), "homoglyph"),          # Cyrillic а
    (puny(f"c{GREEK_OMICRON}mmbank-login.example"), "homoglyph"),       # Greek ο
])
def test_disguised_brand_is_found_and_scores_at_least_as_high_as_plain(host, kind):
    hit = WL.score_hostname(host)
    assert hit is not None and hit.brand_id == "commbank", host
    assert hit.match["kind"] == kind
    assert hit.score >= WL.score_hostname("commbank-login.example").score


def test_mixed_scripts_in_one_label_is_a_reason():
    hit = WL.score_hostname(puny(f"commb{CYRILLIC_A}nk-login.example"))
    assert any(r["why"].startswith("mixed scripts") for r in hit.reasons)
    assert hit.unicode_domain == f"commb{CYRILLIC_A}nk-login.example"


@pytest.mark.parametrize("host", ["comm-bank-login.example", "c-o-m-m-b-a-n-k.example"])
def test_hyphens_inside_the_brand_name_do_not_hide_it(host):
    hit = WL.score_hostname(host)
    assert hit is not None and hit.brand_id == "commbank", host
    assert hit.match["location"] == "reg"


def test_extra_subdomains_keep_the_match_in_the_registered_name():
    hit = WL.score_hostname("secure.login.commbank-verify.example")
    assert hit is not None and hit.brand_id == "commbank"
    assert hit.match["location"] == "reg"
    assert hit.registered_domain == "commbank-verify.example"


def test_brand_only_in_a_subdomain_is_found_there():
    hit = WL.score_hostname("commbank-login.account-check.example")
    assert hit is not None and hit.brand_id == "commbank"
    assert hit.match["location"] == "sub"
    assert hit.registered_domain == "account-check.example"


def test_deep_subdomain_reason_starts_at_four_labels():
    def deep(host):
        return any(r["why"].startswith("deep subdomain") for r in WL.score_hostname(host).reasons)
    assert not deep("a.b.c.commbank-login.example")
    assert deep("a.b.c.d.commbank-login.example")
