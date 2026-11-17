"""Tests for cybercheck.pagefeatures. Pure functions; no network, no database."""
from __future__ import annotations

from types import SimpleNamespace

from cybercheck import pagefeatures as pf


class FakeBrand:
    def __init__(self, bid, name, keywords):
        self.id = bid
        self.name = name
        self.keywords = keywords


class FakeWatchlist:
    def __init__(self, brands, official=()):
        self.brands = {b.id: b for b in brands}
        self.official = {d: "x" for d in official}

    def is_official(self, name):
        return name in self.official


WL = FakeWatchlist(
    [FakeBrand("commbank", "Commonwealth Bank", ["commbank", "netbank"]),
     FakeBrand("auspost", "Australia Post", ["auspost", "australiapost"])],
    official=["commbank.com.au"])


def result(**kw):
    base = dict(ok=True, http_status=200, title="", text_excerpt="", final_url="https://x.top/",
                url="https://x.top/", forms=[])
    base.update(kw)
    return base


# ---- page_loaded -------------------------------------------------------------------------------

def test_page_loaded():
    assert pf.page_loaded(result(title="hi")) is True
    assert pf.page_loaded(result(http_status=200, text_excerpt="hello")) is True
    assert pf.page_loaded({"ok": False, "error": "timeout"}) is False
    assert pf.page_loaded(result(ok=True, http_status=500, title="err")) is False
    assert pf.page_loaded(result(ok=True, http_status=302, title="")) is True
    assert pf.page_loaded(None) is False


# ---- credential detection ----------------------------------------------------------------------

def test_password_and_otp_and_card_fields():
    r = result(
        title="Login",
        forms=[{"action": "/submit", "method": "post", "has_password": True, "has_otp": False,
                "inputs": [{"type": "password", "name": "pwd", "autocomplete": "current-password"},
                           {"type": "text", "name": "otpCode", "autocomplete": "one-time-code"},
                           {"type": "text", "name": "cardNumber", "autocomplete": "cc-number"},
                           {"type": "text", "name": "cvv", "autocomplete": "cc-csc"}]}])
    f = pf.extract(r, {"registered_domain": "x.top", "brand_id": "commbank"}, WL)
    assert f.has_password_field and f.has_otp_field and f.has_card_field
    assert not f.has_identity_field
    assert not f.inconclusive
    assert f.page_score >= 60


def test_identity_fields_medicare_tfn():
    r = result(text_excerpt="Confirm your Medicare number and tax file number to continue.",
               forms=[{"action": "/x", "inputs": [{"type": "text", "name": "medicareNumber", "autocomplete": ""},
                                                  {"type": "text", "name": "tfn", "autocomplete": ""}]}])
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.has_identity_field


def test_otp_not_confused_with_card_cvv():
    # a lone CVV field is a card field, not an OTP field
    r = result(forms=[{"action": "/x", "inputs": [{"type": "text", "name": "cvv2", "autocomplete": "cc-csc"}]}])
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.has_card_field
    assert not f.has_otp_field


# ---- external form post ------------------------------------------------------------------------

def test_external_form_post_detected():
    r = result(final_url="https://commbank-login.top/",
               forms=[{"action": "https://collect.evil-example.ru/p", "inputs": []}])
    f = pf.extract(r, {"registered_domain": "commbank-login.top"}, WL)
    assert f.external_form_post
    assert "evil-example.ru" in f.form_actions


def test_same_site_form_not_external():
    r = result(final_url="https://commbank-login.top/login",
               forms=[{"action": "/do-login", "inputs": []},
                      {"action": "https://commbank-login.top/submit", "inputs": []}])
    f = pf.extract(r, {"registered_domain": "commbank-login.top"}, WL)
    assert not f.external_form_post


# ---- brand mentions ----------------------------------------------------------------------------

def test_brand_mentions_matches_name_and_keyword():
    r = result(title="NetBank sign in", text_excerpt="Welcome to Commonwealth Bank online banking.")
    f = pf.extract(r, {"registered_domain": "x.top", "brand_id": "commbank"}, WL)
    assert "commbank" in f.brand_mentions


def test_no_brand_without_watchlist():
    r = result(title="Commonwealth Bank")
    f = pf.extract(r, {"registered_domain": "x.top"}, None)
    assert f.brand_mentions == []


# ---- parked / decoy / blank are inconclusive ---------------------------------------------------

def test_parked_page_is_inconclusive():
    r = result(title="Buy this domain", text_excerpt="This domain is for sale. Buy this domain today.")
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.parked and f.inconclusive and f.page_score == 0


def test_blank_page_is_inconclusive():
    r = result(title="", text_excerpt="   ", forms=[])
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.blank and f.inconclusive


def test_captcha_gate_is_inconclusive():
    r = result(title="Just a moment...", text_excerpt="Checking your browser before accessing. Cloudflare.")
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.captcha and f.decoy and f.inconclusive


def test_redirect_to_real_brand_is_decoy():
    r = result(final_url="https://commbank.com.au/", text_excerpt="Welcome")
    f = pf.extract(r, {"registered_domain": "commbank-login.top"}, WL)
    assert f.decoy and f.inconclusive


def test_real_brand_login_after_redirect_is_not_credential_evidence():
    """A cloaking kit that redirects automation to the genuine brand login: the brand's real form must not
    make the redirecting domain look like a credential-harvesting page."""
    r = result(final_url="https://www.commbank.com.au/netbank/logon", title="NetBank log on",
               forms=[{"action": "/logon", "method": "post", "has_password": True,
                       "inputs": [{"type": "password", "name": "password", "autocomplete": "current-password"},
                                  {"type": "text", "name": "otp", "autocomplete": "one-time-code"}]}])
    f = pf.extract(r, {"registered_domain": "commbank-login.top", "brand_id": "commbank"}, WL)
    assert not (f.has_password_field or f.has_otp_field or f.has_card_field or f.has_identity_field)
    assert f.offsite_credentials == ["password", "otp"]
    assert f.decoy and f.inconclusive
    assert f.page_score < 30
    assert f.as_dict()["offsite_credentials"] == ["password", "otp"]
    # the same form on the domain itself still counts
    on = pf.extract(dict(r, final_url="https://commbank-login.top/netbank/logon"),
                    {"registered_domain": "commbank-login.top", "brand_id": "commbank"}, WL)
    assert on.has_password_field and on.has_otp_field and not on.offsite_credentials


def test_credential_page_not_inconclusive_even_if_captcha_text_present():
    r = result(text_excerpt="verify you are human and enter your password",
               forms=[{"action": "/x", "inputs": [{"type": "password", "name": "password", "autocomplete": "current-password"}]}])
    f = pf.extract(r, {"registered_domain": "x.top"}, WL)
    assert f.has_password_field
    assert not f.inconclusive


def test_not_loaded_result_is_inconclusive():
    f = pf.extract({"ok": False, "error": "timeout"}, {"registered_domain": "x.top"}, WL)
    assert f.inconclusive and f.page_score == 0
    assert not f.has_password_field


# ---- combine -----------------------------------------------------------------------------------

def test_combine_prefers_the_credential_snapshot():
    cred = pf.extract(result(forms=[{"action": "/x", "inputs": [{"type": "password", "name": "pw", "autocomplete": "current-password"}]}]),
                      {"registered_domain": "x.top"}, WL)
    empty = pf.extract(result(title="", text_excerpt="", forms=[]), {"registered_domain": "x.top"}, WL)
    assert pf.combine([empty, cred]) == cred.page_score
    assert pf.combine([empty]) == empty.page_score


def test_registrable():
    assert pf.registrable("www.commbank.com.au") == "commbank.com.au"
    assert pf.registrable("evil.example.ru") == "example.ru"
    assert pf.registrable("") is None


# ---- review additions: credential flags are load-bearing for auto-reporting, so no false positives ----

def _form(*inputs, **kw):
    f = dict(action="", method="post", has_password=False, has_otp=False, has_card=False,
             inputs=[dict(type=t, name=n, autocomplete=a, label=l) for (t, n, a, l) in inputs])
    f.update(kw)
    return f


def _creds(f):
    return (f.has_password_field, f.has_otp_field, f.has_card_field, f.has_identity_field)


def test_csrf_token_and_company_field_are_not_credentials():
    r = result(title="Contact us", text_excerpt="Tell us about your company and we will call you back.",
               forms=[_form(("hidden", "_token", "", ""), ("hidden", "authenticity_token", "", ""),
                            ("text", "company", "organization", "Company"),
                            ("text", "panel_size", "", "Expand panel"),
                            ("email", "adobe_email", "email", "Email"))])
    f = pf.extract(r, {"registered_domain": "x.top"}, None)
    assert _creds(f) == (False, False, False, False)
    assert f.page_score == 0


def test_hidden_and_button_inputs_never_count():
    r = result(text_excerpt="x" * 60,
               forms=[_form(("hidden", "password", "", ""), ("hidden", "otp", "", ""),
                            ("submit", "card_number", "", "Pay"), ("checkbox", "remember_password", "", ""))])
    assert _creds(pf.extract(r, {"registered_domain": "x.top"}, None)) == (False, False, False, False)


def test_fetcher_form_flags_ignored_when_inputs_are_listed():
    # the classifier, not the coarse per-form flag, decides when the input list is there
    r = result(text_excerpt="x" * 60, forms=[_form(("text", "q", "", "Search"), has_otp=True, has_card=True)])
    assert _creds(pf.extract(r, {"registered_domain": "x.top"}, None)) == (False, False, False, False)
    # ...and is used when it is not
    r = result(text_excerpt="x" * 60, forms=[_form(has_password=True)])
    assert pf.extract(r, {"registered_domain": "x.top"}, None).has_password_field


def test_identity_text_needs_a_text_field():
    article = "Medicare card and tax file number changes announced; check your date of birth details. " * 2
    assert not pf.extract(result(text_excerpt=article), {"registered_domain": "x.top"}, None).has_identity_field
    r = result(text_excerpt=article, forms=[_form(("text", "f1", "", ""))])
    assert pf.extract(r, {"registered_domain": "x.top"}, None).has_identity_field


def test_real_kit_fields_still_detected():
    r = result(title="NetBank", text_excerpt="Log on to NetBank",
               forms=[_form(("text", "clientNumber", "username", "Client number"),
                            ("password", "pw", "", ""),
                            ("tel", "smsCode", "", "Enter the code we sent"),
                            ("text", "cardNumber", "", ""), ("text", "cvv2", "", "CVV"),
                            ("text", "exp", "", "MM/YY"), ("text", "medicareNo", "", ""),
                            ("text", "f9", "cc-csc", ""), ("text", "otp_input", "one-time-code", ""))])
    f = pf.extract(r, {"registered_domain": "x.top"}, None)
    assert _creds(f) == (True, True, True, True)


def test_orphan_inputs_pseudo_form_is_scored():
    # kits that submit with JavaScript have no <form>; the fetcher reports their inputs as method "script"
    r = result(text_excerpt="Verify your account " * 5,
               forms=[_form(("password", "p", "current-password", "Password"), action="", method="script")])
    f = pf.extract(r, {"registered_domain": "x.top"}, None)
    assert f.has_password_field and not f.external_form_post


def test_identity_card_numbers_are_not_payment_cards():
    """'Medicare card number' and 'Licence card number' are identity fields; a real payment card still counts."""
    def classes(**inp):
        return pf._input_class({"type": "text", **inp})
    assert classes(label="Medicare card number") == {"identity"}
    assert classes(name="medicareCardNumber") == {"identity"}
    assert classes(label="Driver licence card number") == {"identity"}
    assert "card" in classes(label="Card number")
    assert "card" in classes(name="cardNumber", autocomplete="cc-number")
    assert classes(label="Medicare card number", autocomplete="cc-number") == {"identity", "card"}
    assert "card" in classes(label="Credit card number")
    assert "card" in classes(name="cvv")
