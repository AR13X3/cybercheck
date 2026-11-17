"""Invariants of cybercheck.confidence.compute_final_score (pure function, no DB or network)."""
import random

import pytest

from cybercheck import confidence
from cybercheck.confidence import NO_EVIDENCE_CAP, compute_final_score, snapshot_on_domain

VERDICTS = [None, "phishing", "suspicious", "benign", "parked", "error"]
CONFIDENCES = [None, 0.0, 0.3, 0.5, 0.7, 0.9, 1.0]

REG = "commbank-verify.top"
ON = {"url": f"https://{REG}/", "final_url": f"https://{REG}/login"}
CRED_PAGE = {**ON, "has_password_field": True, "has_otp_field": False, "has_card_field": False,
             "brand_mentions": ["commbank"], "external_form_post": True,
             "form_actions": ["https://collector.example/p.php"], "http_status": 200, "error": None}
NO_CRED_PAGE = {**ON, "has_password_field": False, "has_otp_field": False, "has_card_field": False,
                "brand_mentions": ["commbank", "netbank"], "external_form_post": True,
                "form_actions": ["https://collector.example/p.php"], "http_status": 200, "error": None}
EMPTY_PAGE = {**ON, "has_password_field": False, "has_otp_field": False, "has_card_field": False,
              "brand_mentions": [], "external_form_post": False, "form_actions": [], "http_status": 200}
ERROR_PAGE = {**ON, "http_status": 404, "error": None, "has_password_field": True}
IDENTITY_PAGE = {**ON, "has_password_field": False, "has_otp_field": False, "has_card_field": False,
                 "has_identity_field": True, "brand_mentions": ["mygov"], "external_form_post": False,
                 "form_actions": ["/verify.php"], "http_status": 200, "error": None}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("AUTO_REPORT_MIN_FINAL_SCORE", raising=False)
    monkeypatch.delenv("CONFIDENCE_REQUIRE_AI", raising=False)


def D(score, brand="commbank", page_score=None, reg=REG, **kw):
    return {"score": score, "brand_id": brand, "page_score": page_score, "registered_domain": reg, **kw}


def ai(verdict, conf=0.9, brand="commbank"):
    return None if verdict is None else {"verdict": verdict, "confidence": conf, "imitated_brand": brand}


def check_shape(score, reasons):
    assert isinstance(score, int) and 0 <= score <= 100
    assert reasons and all(isinstance(r, dict) and isinstance(r["points"], int) and isinstance(r["why"], str)
                           and r["why"] for r in reasons)
    assert sum(r["points"] for r in reasons) == score


@pytest.mark.parametrize("dscore", [0, 40, 60, 75, 90, 100])
@pytest.mark.parametrize("page", [None, NO_CRED_PAGE, EMPTY_PAGE, ERROR_PAGE, IDENTITY_PAGE])
@pytest.mark.parametrize("verdict", VERDICTS)
def test_without_credential_evidence_capped_below_auto_report(dscore, page, verdict):
    for conf in CONFIDENCES:
        domain = D(dscore, page_score=100)
        score, reasons = compute_final_score(domain, page, ai(verdict, conf))
        check_shape(score, reasons)
        assert score <= 89, (dscore, page, verdict, conf, reasons)


def test_cap_follows_auto_report_setting_below_90(monkeypatch):
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", "80")
    domain = D(100, page_score=100)
    score, _ = compute_final_score(domain, NO_CRED_PAGE, ai("phishing", 1.0))
    assert score == 79
    score, _ = compute_final_score(domain, CRED_PAGE, ai("phishing", 0.95))
    assert score >= 80


@pytest.mark.parametrize("setting", ["90", "95", "100", "101", "1000", "250", "abc", ""])
def test_no_evidence_cap_is_fixed_whatever_the_auto_report_setting(monkeypatch, setting):
    """Regression: AUTO_REPORT_MIN_FINAL_SCORE=101 (documented as 'automatic sends off') or 95 used to
    lift the cap to 100 / 94, so name-only domains reached the >= 90 blocklist level."""
    assert NO_EVIDENCE_CAP == 89
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", setting)
    name_only = D(94, brand="westpac", reg="westpac-login-verify-au.xyz")
    assert compute_final_score(name_only, None, None)[0] == 89
    assert compute_final_score({**name_only, "score": 100}, None, None)[0] == 89
    for verdict in VERDICTS:
        for conf in CONFIDENCES:
            assert compute_final_score(D(100, page_score=100), NO_CRED_PAGE, ai(verdict, conf))[0] <= 89
            # credentials without a confirming AI verdict: still capped
            if not (verdict == "phishing" and conf is not None and conf >= 0.7):
                assert compute_final_score(D(100, page_score=100), CRED_PAGE, ai(verdict, conf))[0] <= 89
    # both signals: the auto-report level is still reachable
    assert compute_final_score(D(85, page_score=90), CRED_PAGE, ai("phishing", 0.95))[0] >= 90


@pytest.mark.parametrize("setting", ["0", "9", "50", "79"])
def test_cap_never_drops_below_the_reporting_floor(monkeypatch, setting):
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", setting)
    assert compute_final_score(D(100), None, None)[0] == 79
    assert compute_final_score(D(30), None, None)[0] == 30


def test_require_ai_off_still_respects_the_fixed_cap(monkeypatch):
    domain = D(95, page_score=100)
    monkeypatch.setenv("CONFIDENCE_REQUIRE_AI", "false")
    assert compute_final_score(domain, CRED_PAGE, None)[0] == 89
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", "85")
    assert compute_final_score(domain, CRED_PAGE, None)[0] == 89          # may reach 85..89, never 90
    assert compute_final_score(domain, NO_CRED_PAGE, None)[0] == 84
    monkeypatch.setenv("CONFIDENCE_REQUIRE_AI", "true")
    assert compute_final_score(domain, CRED_PAGE, None)[0] == 84


def test_credentials_plus_ai_phishing_reaches_auto_report():
    domain = D(80, page_score=80)
    score, reasons = compute_final_score(domain, CRED_PAGE, ai("phishing", 0.95))
    check_shape(score, reasons)
    assert score >= 90
    whys = " ".join(r["why"] for r in reasons)
    assert "password" in whys and "AI page check: phishing" in whys


@pytest.mark.parametrize("dscore", [60, 70, 75, 85, 100])
@pytest.mark.parametrize("verdict", ["benign", "parked"])
@pytest.mark.parametrize("conf", [0.5, 0.8, 0.95, 1.0])
@pytest.mark.parametrize("page_score", [None, 0, 50, 100])
def test_ai_benign_alone_cannot_clear_credential_page(dscore, verdict, conf, page_score):
    domain = D(dscore, page_score=page_score)
    for page in (CRED_PAGE, {**CRED_PAGE, "brand_mentions": [], "external_form_post": False},
                 {**CRED_PAGE, "has_password_field": False, "has_card_field": True}, IDENTITY_PAGE):
        before, _ = compute_final_score(domain, page, None)
        score, reasons = compute_final_score(domain, page, ai(verdict, conf, brand=None))
        check_shape(score, reasons)
        assert score >= min(70, before), (domain, page, verdict, conf, reasons)
        if before >= 70:
            assert score >= 70


def test_identity_page_keeps_its_floor_but_is_not_credential_evidence():
    """Regression: an injected 'benign' verdict took a myGov identity kit from 74 to 46."""
    domain = D(69, brand="mygov", page_score=60, reg="mygov-verify-identity.com")
    page = {**IDENTITY_PAGE, "url": "https://mygov-verify-identity.com/",
            "final_url": "https://mygov-verify-identity.com/verify"}
    before, _ = compute_final_score(domain, page, None)
    after, reasons = compute_final_score(domain, page, ai("benign", 0.95, brand=None))
    assert before >= 70 and after == 70
    assert "identity details" in reasons[-1]["why"]
    # identity fields are not credential evidence: no auto-report level even with AI phishing
    assert compute_final_score({**domain, "score": 100}, page, ai("phishing", 1.0, "mygov"))[0] <= 89


def test_benign_floor_never_raises_a_score():
    domain = D(40, page_score=0)
    page = {**CRED_PAGE, "brand_mentions": [], "external_form_post": False}
    before, _ = compute_final_score(domain, page, None)
    after, _ = compute_final_score(domain, page, ai("benign", 1.0, brand=None))
    assert before < 70 and after <= before


def test_benign_lowers_a_page_without_credentials():
    domain = D(80, page_score=30)
    before, _ = compute_final_score(domain, NO_CRED_PAGE, None)
    after, _ = compute_final_score(domain, NO_CRED_PAGE, ai("benign", 0.9, brand=None))
    assert after < before and after < 70


def test_credentials_without_ai_stay_below_auto_report():
    domain = D(95, page_score=100)
    score, reasons = compute_final_score(domain, CRED_PAGE, None)
    assert score == 89 and "AI 'phishing' verdict" in reasons[-1]["why"]
    for verdict, conf in (("suspicious", 1.0), ("phishing", 0.5)):
        assert compute_final_score(domain, CRED_PAGE, ai(verdict, conf))[0] <= 89


def test_domain_name_only():
    score, reasons = compute_final_score(D(70, brand="anz"), None, None)
    assert score == 70
    assert reasons[0] == {"points": 70, "why": "domain name score"}
    score, reasons = compute_final_score(D(100, brand="anz"), None, None)
    assert score == 89 and "no credential-collecting page evidence" in reasons[-1]["why"]


def test_live_page_without_forms_lowers_score():
    domain = D(70, brand="auspost", page_score=10)
    score, _ = compute_final_score(domain, EMPTY_PAGE, ai("parked", 0.9, None))
    assert score < 40


# ---- page evidence must come from the domain's own page ---------------------------------------

REDIRECTOR = "commbank-netbank.com.au"
OFFICIAL_LOGIN = {"url": f"https://{REDIRECTOR}/", "final_url": "https://www.my.commbank.com.au/netbank/Logon/Logon.aspx",
                  "has_password_field": True, "has_otp_field": False, "has_card_field": False,
                  "brand_mentions": ["commbank", "netbank"], "external_form_post": True,
                  "form_actions": ["https://www.my.commbank.com.au/netbank/Logon/Logon.aspx"], "http_status": 200,
                  "error": None}


def test_redirect_to_the_real_brand_login_is_not_evidence():
    """Regression: a defensive domain redirecting to the real NetBank logon page scored 100."""
    domain = D(60, page_score=90, reg=REDIRECTOR)
    for a in (None, ai("phishing", 0.9), ai("phishing", 1.0)):
        score, reasons = compute_final_score(domain, OFFICIAL_LOGIN, a)
        check_shape(score, reasons)
        assert score <= 89
        whys = " ".join(r["why"] for r in reasons)
        assert "page asks for" not in whys and "page features score" not in whys
        assert "posts to another domain" not in whys and "page mentions" not in whys
        assert "www.my.commbank.com.au" in whys and "official Commonwealth Bank site" in whys
        assert "asks for a password" in whys       # still shown, as context
    before, reasons = compute_final_score(domain, OFFICIAL_LOGIN, None)
    assert before == 60 + confidence.W_REDIRECT_OFFICIAL        # weak benign signal only


def test_redirect_to_another_domains_login_is_not_evidence():
    domain = D(80, page_score=100, reg=REG)
    for final in ("https://login.microsoftonline.com/common/oauth2", f"https://{REG}.evil.example/login",
                  f"https://x{REG}/login", "https://collector.example/" + REG, "about:blank", None, "",
                  "not a url", "https://[bad/"):
        page = {**CRED_PAGE, "final_url": final}
        score, reasons = compute_final_score(domain, page, ai("phishing", 1.0))
        check_shape(score, reasons)
        assert score <= 89, (final, reasons)
        assert not any("page asks for" in r["why"] for r in reasons)
        assert not snapshot_on_domain(page, REG)


def test_subdomain_of_the_domain_counts_as_its_own_page():
    domain = D(80, page_score=80)
    for final in (f"https://{REG}/x", f"https://login.{REG}/x", f"HTTPS://Login.{REG.upper()}./x?a=b",
                  f"https://user@login.{REG}:8443/x"):
        page = {**CRED_PAGE, "final_url": final}
        assert snapshot_on_domain(page, REG), final
        assert compute_final_score(domain, page, ai("phishing", 0.95))[0] >= 90
    assert not snapshot_on_domain(CRED_PAGE, None) and not snapshot_on_domain(CRED_PAGE, "")
    # no registered domain on the domain row: nothing can be proven to be its own page
    assert compute_final_score({"score": 80, "brand_id": "commbank"}, CRED_PAGE, ai("phishing", 0.95))[0] <= 89


def test_accepts_domain_column_names_and_bad_values():
    domain = D(80, page_score=80)
    a = {"ai_verdict": "phishing", "ai_confidence": 0.95, "ai_brand": "commbank"}
    assert compute_final_score(domain, CRED_PAGE, a)[0] >= 90
    for weird in ({}, {"score": None}, {"score": "abc", "page_score": "x"}, {"score": 50, "registered_domain": 7}):
        check_shape(*compute_final_score(weird, {"http_status": "x", "brand_mentions": None}, {"confidence": "?"}))
        check_shape(*compute_final_score(weird, {**CRED_PAGE, "final_url": 12}, None))
    check_shape(*compute_final_score({"score": 50}, {}, {"verdict": "phishing", "confidence": float("nan")}))
    check_shape(*compute_final_score({"score": 50}, None, {"verdict": "made-up", "confidence": 5}))


def test_basis_tag_changes_with_the_rules_and_settings(monkeypatch):
    base = confidence.basis_tag()
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", "85")
    assert confidence.basis_tag() != base
    monkeypatch.setenv("AUTO_REPORT_MIN_FINAL_SCORE", "101")
    assert confidence.basis_tag() == base          # same effective cap as 90
    monkeypatch.setenv("CONFIDENCE_REQUIRE_AI", "false")
    assert confidence.basis_tag() != base


def test_random_inputs_stay_in_range():
    rnd = random.Random(1234)
    for _ in range(3000):
        domain = {"score": rnd.choice([None, -20, 0, 35, 60, 75, 99, 100, 140]),
                  "brand_id": rnd.choice([None, "commbank", "mygov"]),
                  "page_score": rnd.choice([None, -5, 0, 20, 50, 80, 100, 200]),
                  "registered_domain": rnd.choice([REG, REG, None, "other.top"])}
        page = rnd.choice([None, {
            "final_url": rnd.choice([f"https://{REG}/", f"https://www.{REG}/a", "https://www.commbank.com.au/",
                                     "https://elsewhere.example/", None]),
            "has_password_field": rnd.random() < 0.4, "has_otp_field": rnd.random() < 0.2,
            "has_card_field": rnd.random() < 0.2, "has_identity_field": rnd.random() < 0.2,
            "brand_mentions": rnd.choice([[], ["commbank"], ["Telstra"]]),
            "external_form_post": rnd.random() < 0.3, "form_actions": rnd.choice([[], ["/x"]]),
            "http_status": rnd.choice([None, 200, 302, 404, 500]), "error": rnd.choice([None, None, "timeout"])}])
        a = ai(rnd.choice(VERDICTS), rnd.choice(CONFIDENCES), rnd.choice([None, "commbank", "Other"]))
        score, reasons = compute_final_score(domain, page, a)
        check_shape(score, reasons)
        has_creds = bool(page) and not page.get("error") and (page.get("http_status") in (None, 200, 302)) and \
            (page["has_password_field"] or page["has_otp_field"] or page["has_card_field"]) and \
            snapshot_on_domain(page, domain["registered_domain"])
        confirmed = bool(a) and a["verdict"] == "phishing" and (a["confidence"] or 0) >= 0.7
        if not (has_creds and confirmed):
            assert score <= 89


def test_blob_page_counts_as_its_origin():
    """A kit that renders its form in a blob: URL it created is still the domain's own page."""
    domain = D(80, page_score=80)
    page = {**CRED_PAGE, "final_url": f"blob:https://login.{REG}/0f3c-77aa"}
    assert snapshot_on_domain(page, REG)
    assert compute_final_score(domain, page, ai("phishing", 0.95))[0] >= 90
    for final in ("blob:https://evil.example/0f3c", "blob:null/0f3c", f"blob:blob:https://{REG}/x"):
        assert not snapshot_on_domain({**CRED_PAGE, "final_url": final}, REG), final
