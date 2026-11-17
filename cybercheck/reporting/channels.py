"""Reporting channels: which exist, which may be automated, and which apply to a domain.

Every channel here comes from the fact-checked research of 2026-11-15:
docs/research/au-reporting.yaml (Australian government, .au registry, brand mailboxes) and
docs/research/intl-reporting.yaml (Netcraft, Google, Microsoft, Cloudflare, registrar / host abuse).
docs/ is not in the app image, so the verified entries are copied here; tests/test_reporting.py checks
them against the YAML files so the two cannot drift apart.

Policy: only channels with automated_ok true in the research and built for automated reports are sent
by the worker without a person. Today that is the Netcraft report API alone. Everything else is an
email draft or a manual web-form checklist item for a reviewer.
"""
from __future__ import annotations

from dataclasses import dataclass

API, EMAIL, MANUAL_KIND = "api", "email", "manual"


@dataclass(frozen=True)
class Channel:
    id: str                    # reports.channel value ("brand:<id>" / "brand_form:<id>" are built per brand)
    name: str
    kind: str                  # api | email | manual
    automated_ok: bool
    url: str = ""              # API endpoint or official web form
    source: str = ""           # official page the research verified it on
    notes: str = ""
    default_on: bool = True
    research_id: str = ""      # id in docs/research/*.yaml


NETCRAFT = Channel(
    "netcraft", "Netcraft report API", API, True,
    url="https://report.netcraft.com/api/v3/report/urls",
    source="https://report.netcraft.com/api/v3/api.json",
    notes="Free, no API key. Needs the reporter's email (the analysis result is sent there). Its feed is "
          "used by many browsers. URLs of one domain go in one submission; country AU.",
    research_id="netcraft")

REGISTRAR = Channel(
    "registrar_abuse", "Registrar abuse contact", EMAIL, False,
    source="https://itp.cdn.icann.org/en/files/accredited-registrars/registrar-accreditation-agreement-global-amendment-05apr24-en.htm",
    notes="Human abuse desk. gTLD registrars must acknowledge and investigate (ICANN RAA 3.18.1, 3.18.2). "
          ".au: report to the registrar of record first (auDA Licensing Rules 3.4.1).",
    research_id="registrar_abuse_contact_gtld")

HOSTING = Channel(
    "hosting_abuse", "Hosting provider abuse contact", EMAIL, False,
    source="https://stat.ripe.net/docs/data-api/api-endpoints/abuse-contact-finder",
    notes="Abuse contact of the network hosting the site (from RIR RDAP). Contacts in RIR data can be wrong.",
    research_id="hosting_abuse_contact")

AU_WHOIS = "https://whois.auda.org.au/"

MANUAL: dict[str, Channel] = {c.id: c for c in (
    Channel("scamwatch", "Scamwatch: Report a scam website (National Anti-Scam Centre)", MANUAL_KIND, False,
            url="https://forms.scamwatch.gov.au/report-a-scamwebsite/",
            source="https://www.scamwatch.gov.au/report-a-scam",
            notes="The only public route into the NASC website takedown service. Two fields: Website URL and "
                  "'What makes the website a scam?'. Do not include personal details (the ACCC may share the "
                  "text with partner organisations). reCAPTCHA; manual only. Labelled as a test form.",
            research_id="scamwatch-report-website"),
    Channel("google_safe_browsing", "Google Safe Browsing: report a phishing page", MANUAL_KIND, False,
            url="https://www.google.com/safebrowsing/report_phish/",
            source="https://developers.google.com/safe-browsing/v4/reporting",
            notes="Manual form; no submission API for non-customers (the Web Risk Submission API is closed to "
                  "new contracts).",
            research_id="google_safe_browsing_report_form"),
    Channel("microsoft_smartscreen", "Microsoft: report an unsafe site (SmartScreen)", MANUAL_KIND, False,
            url="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
            source="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
            notes="Sign in or 'Continue as a guest' (CAPTCHA). Up to 100 URLs. Threat type: Phishing.",
            research_id="microsoft_report_unsafe_site"),
    Channel("cloudflare_abuse_form", "Cloudflare abuse form (site behind Cloudflare)", MANUAL_KIND, False,
            url="https://abuse.cloudflare.com/",
            source="https://developers.cloudflare.com/fundamentals/reference/report-abuse/submit-report/",
            notes="Only for sites on Cloudflare. Choose phishing; give the URLs and how to view the page. Your "
                  "name, email and the URLs may be passed to third parties such as the Lumen Database.",
            research_id="cloudflare_abuse_web_form"),
    Channel("auda_dns_abuse", "auDA: report suspected DNS abuse (general enquiry)", MANUAL_KIND, False,
            url="https://www.auda.org.au/about-auda/contact-us/general-enquiry-form/",
            source="https://www.auda.org.au/au-domain-names/manage-your-au-domain-name/keep-your-au-secure/",
            notes=".au domains only, while the site is live. Describe it as a DNS abuse report: the form says it "
                  "is not for domain or industry complaints. Report to the registrar of record as well.",
            research_id="auda-dns-abuse-enquiry"),
    Channel("reportcyber", "ReportCyber (ASD's ACSC with police)", MANUAL_KIND, False,
            url="https://reportapp.cyber.gov.au/", source="https://www.cyber.gov.au/submit-a-report",
            notes="For victims reporting a cybercrime to police; the research found it is not meant for "
                  "third-party phishing-URL takedown. Off unless listed in REPORT_MANUAL_CHANNELS.",
            default_on=False, research_id="reportcyber"),
    Channel("apwg_report", "APWG public phishing report form", MANUAL_KIND, False,
            url="https://apwg.org/submissions/report-phishing", source="https://apwg.org/reportphishing/",
            notes="Built for people forwarding phishing lures they received. Off unless listed in "
                  "REPORT_MANUAL_CHANNELS.",
            default_on=False, research_id="apwg_public_report"),
)}

BRAND_FORM = "brand_form"   # REPORT_MANUAL_CHANNELS key for brands that only publish a web form


def default_manual_channels() -> frozenset:
    return frozenset([c.id for c in MANUAL.values() if c.default_on] + [BRAND_FORM])


# Channels from the research that CyberCheck does not use, and why (shown on the dashboard).
NOT_USED: tuple[tuple[str, str, str], ...] = (
    ("Spamhaus Submission Portal API (beta)",
     "Not built: whether it has a phishing threat type, and how its no-bots terms (clause 7.3.1) apply to the "
     "API, are unverified. Evaluate with a free account first.", "https://submit.spamhaus.org/api/"),
    ("APWG eCrime eXchange (eCX) API",
     "Members only (from US$1,500 a year, organisational email domain, data sharing agreement).",
     "https://apwg.org/membership/"),
    ("Cloudflare Abuse Reports API",
     "Needs the abuse-reports entitlement on a Cloudflare account (Enterprise by default, others must "
     "request it). The Cloudflare web form is used instead.",
     "https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/"),
    ("Google Web Risk Submission API",
     "Closed to new contracts; deprecated by 2027-12-31.", "https://docs.cloud.google.com/web-risk/docs/submission-api"),
    ("PhishTank", "New user registration is disabled.", "https://phishtank.org/register.php"),
    ("ASD Cyber Threat Intelligence Sharing (CTIS)",
     "Machine-to-machine, but only for approved ASD Network Partners (ABN and IT security capability).",
     "https://www.cyber.gov.au/become-a-partner/become-an-asd-network-partner"),
    ("Microsoft Graph urlThreatSubmission", "Beta, tenant-admin tool for an organisation's own tenant.",
     "https://learn.microsoft.com/en-us/graph/api/security-urlthreatsubmission-post-urlthreats?view=graph-rest-beta"),
    ("URLhaus", "Does not accept phishing (malware only).", "https://urlhaus.abuse.ch/api/"),
    ("ACMA spam forwarding", "Only for spam messages actually received, not domains found in CT logs.",
     "https://www.acma.gov.au/dealing-with-spam"),
    ("auDA complaint", "Only after the registrar of record has had 30 days (Licensing Rules 3.4.4); suits "
     "false eligibility such as a borrowed ABN. Lodge it by hand if needed.",
     "https://www.auda.org.au/au-domain-names/complaints-and-disputes/au-complaints/submit-a-complaint/"),
    ("Automated .au WHOIS / RDAP lookups",
     "Prohibited by auDA WHOIS Policy 5.1 and Licensing Rule 2.18.14: the .au registrar abuse address is "
     "looked up by hand at whois.auda.org.au.", "https://files.auda.org.au/documents/2025-11-WHOIS-Policy.pdf"),
)


# ---- brand mailboxes and forms (docs/research/au-reporting.yaml, scope: brand) ----------------------

@dataclass(frozen=True)
class BrandContact:
    research_id: str
    brand_id: str              # brand_id in the research file
    name: str
    method: str                # email | web_form
    address: str               # mailbox or form URL
    source: str
    notes: str = ""
    screenshots: bool = True   # False: the brand asks for no screenshots


BRAND_CONTACTS: tuple[BrandContact, ...] = (
    BrandContact("commbank-hoax", "commbank", "CommBank hoax mailbox", "email", "hoax@cba.com.au",
                 "https://www.commbank.com.au/support/security/how-to-report-a-scam.html"),
    BrandContact("bankwest-abuse", "bankwest", "Bankwest scam mailbox", "email", "abuse@bankwest.com.au",
                 "https://www.bankwest.com.au/support/security/report-a-scam"),
    BrandContact("westpac-hoax", "westpac", "Westpac hoax mailbox", "email", "hoax@westpac.com.au",
                 "https://www.westpac.com.au/security/types-of-scams/phishing/"),
    BrandContact("stgeorge-hoax", "stgeorge", "St.George hoax mailbox", "email", "hoax@stgeorge.com.au",
                 "https://www.stgeorge.com.au/online-services/security-centre/how-to-report",
                 "Automatic response only."),
    BrandContact("banksa-hoax", "banksa", "BankSA hoax mailbox", "email", "hoax@banksa.com.au",
                 "https://www.banksa.com.au/online-services/security-centre/how-to-report", "Automatic response only."),
    BrandContact("bankofmelbourne-hoax", "bankofmelbourne", "Bank of Melbourne hoax mailbox", "email",
                 "hoax@bankofmelbourne.com.au",
                 "https://www.bankofmelbourne.com.au/online-services/security-centre/how-to-report",
                 "Automatic response only."),
    BrandContact("anz-hoax", "anz", "ANZ hoax mailbox", "email", "hoax@cybersecurity.anz.com",
                 "https://www.anz.com.au/security/report-scams-fraud/"),
    BrandContact("suncorpbank-security", "suncorpbank", "Suncorp Bank security mailbox", "email",
                 "security@suncorpbank.com.au", "https://www.suncorpbank.com.au/security/identify-report-threats.html",
                 "Re-check this address at each quarterly review."),
    BrandContact("nab-phish", "nab", "NAB phishing mailbox", "email", "phish@nab.com.au",
                 "https://www.nab.com.au/about-us/security/latest-fraud-scam-alerts"),
    BrandContact("bendigo-phishing", "bendigo", "Bendigo Bank phishing mailbox", "email",
                 "phishing@bendigoadelaide.com.au", "https://www.bendigobank.com.au/security/report-suspicious-activity/"),
    BrandContact("ing-fraud", "ing", "ING Australia fraud mailbox", "email", "fraud@ing.com.au",
                 "https://www.ing.com.au/security/latest-alerts.html",
                 "ING's alerts page also lists scam addresses: never take other addresses from it."),
    BrandContact("macquarie-scams", "macquarie", "Macquarie scams mailbox", "email", "scams@macquarie.com",
                 "https://www.macquarie.com.au/help/personal/fraud-disputes-and-security/fraud-and-security/reporting-fraud-scams-or-suspicious-activity.html",
                 "Invites reports from people who have not engaged with the scam."),
    BrandContact("boq-fraud", "boq", "BOQ fraud and scam operations mailbox", "email",
                 "fraudandscamoperations@boq.com.au", "https://www.boq.com.au/personal/help-and-support/fraud-and-scams/report"),
    BrandContact("hsbc-au-phishing", "hsbc-au", "HSBC Australia phishing mailbox", "email", "phishing@hsbc.com",
                 "https://www.hsbc.com.au/help/security-centre/cyber-awareness/"),
    BrandContact("paypal-au-phishing", "paypal-au", "PayPal phishing mailbox", "email", "phishing@paypal.com",
                 "https://www.paypal.com/au/cshelp/article/how-do-i-spot-a-fake-fraudulent-or-phishing-paypal-email-or-website---help164"),
    BrandContact("ato-reportscams", "ato", "ATO scam mailbox", "email", "ReportScams@ato.gov.au",
                 "https://www.ato.gov.au/online-services/scams-cyber-safety-and-identity-protection/verify-or-report-an-ato-scam"),
    BrandContact("servicesaustralia-reportascam", "servicesaustralia",
                 "Services Australia scam mailbox (Centrelink, Medicare, Child Support, myGov)", "email",
                 "reportascam@servicesaustralia.gov.au",
                 "https://www.servicesaustralia.gov.au/report-services-australia-or-mygov-scam",
                 "Covers fake websites too. Same mailbox as myGov: send one report, not two."),
    BrandContact("mygov-reportascam", "mygov", "myGov scam reporting (Services Australia mailbox)", "email",
                 "reportascam@servicesaustralia.gov.au",
                 "https://my.gov.au/en/about/privacy-and-security/security/mygov-scams/how-to-spot-a-mygov-scam",
                 "Same mailbox as Services Australia: send one report, not two."),
    BrandContact("auspost-scams", "auspost", "Australia Post scams mailbox", "email", "scams@auspost.com.au",
                 "https://auspost.com.au/about-us/about-our-site/online-security-scams-fraud",
                 "Asks for no screenshots: send the URL and details only.", screenshots=False),
    BrandContact("aramex-scams", "aramex", "Aramex Australia scams mailbox", "email", "scams@aramex.com.au",
                 "https://www.aramex.com.au/tools/online-security/", "Worded for victims."),
    BrandContact("linkt-report-form", "linkt", "Linkt Report a scam form", "web_form",
                 "https://www.linkt.com.au/contact-us/report-scam", "https://www.linkt.com.au/help/security/is-it-really-from-us",
                 "Requires an image file (jpeg or png, max 5 MB): download the screenshot. 'Verify you are human'."),
    BrandContact("telstra-abuse", "telstra", "Telstra scam email mailbox", "email", "abuse@telstra.com",
                 "https://www.telstra.com.au/support/internet-and-home-phone/protect-against-scams"),
    BrandContact("optus-abuse", "optus", "Optus phishing mailbox", "email", "abuse@optusnet.com.au",
                 "https://www.optus.com.au/support/answer/reporting_hoaxes_phishing_or_scams_10073"),
    BrandContact("vodafone-scam-form", "vodafone", "Vodafone Scam Lodgement Form", "web_form",
                 "https://vha.my.salesforce-sites.com/ScamLodgementForm", "https://www.vodafone.com.au/support/notify/scams",
                 "Hosted on Salesforce, linked from Vodafone's official scams page."),
    BrandContact("energyaustralia-staysafe", "energyaustralia", "EnergyAustralia hoax mailbox", "email",
                 "staysafe@energyaustralia.com.au", "https://www.energyaustralia.com.au/home/help-support/faqs/online-security"),
    BrandContact("agl-report-form", "agl", "AGL Report a scam form", "web_form",
                 "https://www.agl.com.au/customer-security/scams-phishing-and-fraud/report-a-scam",
                 "https://www.agl.com.au/customer-security/scams-phishing-and-fraud/report-a-scam",
                 "Accepts 'Not a current or former customer'; account number N/A allowed."),
    BrandContact("origin-hello", "origin", "Origin Energy customer mailbox", "email", "hello@origin.com.au",
                 "https://www.originenergy.com.au/blog/is-it-really-origin-or-a-scam/",
                 "General customer mailbox, not a dedicated phishing inbox."),
    BrandContact("woolworths-hoax", "woolworths", "Woolworths hoax mailbox", "email", "hoax@woolworths.com.au",
                 "https://www.woolworths.com.au/shop/help/scam-alert"),
    BrandContact("swyftx-security", "swyftx", "Swyftx security mailbox", "email", "security@swyftx.com",
                 "https://support.swyftx.com/en/articles/12015298-suspicious-websites-and-links-recognise-and-report",
                 "Fits fake-website reports: include a screenshot with the URL visible."),
    BrandContact("independentreserve-support", "independentreserve", "Independent Reserve support", "email",
                 "support@independentreserve.com",
                 "https://www.independentreserve.com/blog/knowledge-base/official-independent-reserve-channel-verification",
                 "General support mailbox."),
    BrandContact("asic-impersonation", "asic", "ASIC online inquiry (ASIC impersonation only)", "web_form",
                 "https://www.asic.gov.au/about-asic/contact-us#online",
                 "https://www.asic.gov.au/regulatory-resources/scams/scams-impersonating-asic"),
)

# Watchlist brand ids (config/watchlist.yaml) that name the same organisation as a research brand_id.
# centrelink and medicare: the Services Australia mailbox explicitly covers them (research notes).
WATCHLIST_ALIASES = {
    "hsbc_au": "hsbc-au",
    "aramex_au": "aramex",
    "vodafone_au": "vodafone",
    "suncorp": "suncorpbank",
    "centrelink": "servicesaustralia",
    "medicare": "servicesaustralia",
}


def brand_contact(brand_id: str | None) -> BrandContact | None:
    """The verified contact for a watchlist brand: its mailbox if it has one, else its web form."""
    if not brand_id:
        return None
    rid = WATCHLIST_ALIASES.get(brand_id, brand_id)
    found = [c for c in BRAND_CONTACTS if c.brand_id == rid]
    for method in ("email", "web_form"):
        for c in found:
            if c.method == method:
                return c
    return None


# ---- planning --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Planned:
    channel: str
    kind: str
    status: str                # approved (queued) | pending_review
    auto: bool = False


def is_au(domain: dict) -> bool:
    name = (domain.get("registered_domain") or "").lower()
    return name.endswith(".au")


def is_gov_au(domain: dict) -> bool:
    name = (domain.get("registered_domain") or "").lower()
    return name.endswith(".gov.au") or name == "gov.au"


def is_cloudflare(domain: dict) -> bool:
    return domain.get("asn") in (13335, 209242) or "cloudflare" in (domain.get("as_name") or "").lower()


def automated_channels(cfg) -> list[str]:
    """Automated channels that can send now (mode aside)."""
    return [NETCRAFT.id] if cfg.netcraft_ready else []


def plan(domain: dict, cfg, trigger: str) -> list[Planned]:
    """Channels that apply to a domain.

    trigger 'confirmed' (a reviewer confirmed it; job or dashboard): automated channels queued (not in
    mode off), email drafts and manual checklist items for review.
    trigger 'auto' (REPORTING_MODE=auto, high score with page evidence): automated channels only.
    """
    out: list[Planned] = []
    auto = trigger == "auto"
    if cfg.mode != "off":
        out += [Planned(c, API, "approved", auto=auto) for c in automated_channels(cfg)]
    if auto:
        return out
    out.append(Planned(REGISTRAR.id, EMAIL, "pending_review"))
    cloudflare = is_cloudflare(domain)
    if not cloudflare and (domain.get("hosting_abuse_email") or domain.get("ips")):
        out.append(Planned(HOSTING.id, EMAIL, "pending_review"))
    contact = brand_contact(domain.get("brand_id"))
    if contact and contact.method == "email":
        out.append(Planned(f"brand:{domain['brand_id']}", EMAIL, "pending_review"))
    elif contact and BRAND_FORM in cfg.manual_channels:
        out.append(Planned(f"{BRAND_FORM}:{domain['brand_id']}", MANUAL_KIND, "pending_review"))
    for ch in MANUAL.values():
        if ch.id not in cfg.manual_channels:
            continue
        if ch.id == "cloudflare_abuse_form" and not cloudflare:
            continue
        if ch.id == "auda_dns_abuse" and not is_au(domain):
            continue
        out.append(Planned(ch.id, MANUAL_KIND, "pending_review"))
    return out


def channel_label(channel: str) -> str:
    if channel == NETCRAFT.id:
        return NETCRAFT.name
    if channel == REGISTRAR.id:
        return REGISTRAR.name
    if channel == HOSTING.id:
        return HOSTING.name
    if channel in MANUAL:
        return MANUAL[channel].name
    if ":" in channel:
        prefix, bid = channel.split(":", 1)
        c = brand_contact(bid)
        if c:
            return c.name
        return f"Brand {bid}"
    return channel


def disabled(cfg) -> list[tuple[str, str]]:
    """(what, why) for everything the dashboard should explain as off."""
    from .conf import HARD_MIN_AUTO_SCORE
    out: list[tuple[str, str]] = []
    if cfg.mode_warning:
        out.append(("REPORTING_MODE", cfg.mode_warning))
    if cfg.reporter_email_warning:
        out.append(("REPORTER_EMAIL", cfg.reporter_email_warning))
    if cfg.configured_min_final_score != cfg.min_final_score:
        out.append(("AUTO_REPORT_MIN_FINAL_SCORE",
                    f"set to {cfg.configured_min_final_score}; automatic reports use {cfg.min_final_score} "
                    f"(never below {HARD_MIN_AUTO_SCORE})"))
    elif cfg.min_final_score > 100:
        out.append(("AUTO_REPORT_MIN_FINAL_SCORE",
                    f"set to {cfg.min_final_score}: no combined score can reach it, so nothing is sent "
                    "automatically for unreviewed domains"))
    if cfg.mode == "off":
        out.append(("All reporting", "REPORTING_MODE=off: the worker creates and sends nothing. Drafts made on "
                                     "demand can still be sent by hand (mailto) and marked as sent"))
    if cfg.mode != "auto":
        out.append(("Automatic reports for unreviewed domains",
                    f"REPORTING_MODE={cfg.mode}: only domains a reviewer confirmed are reported"))
    reason = cfg.netcraft_reason()
    if reason:
        out.append((NETCRAFT.name, reason))
    if cfg.netcraft_api_key_set:
        out.append(("NETCRAFT_API_KEY", "set but not used: Netcraft's report API v3 takes no key"))
    if not cfg.smtp:
        out.append(("Sending approved emails", (cfg.smtp_reason or "SMTP is off")
                    + ". Approved drafts are sent from your own mail client (mailto link), then marked as sent."))
    if cfg.rate_per_hour <= 0:
        out.append(("All sending", "REPORT_RATE_PER_HOUR=0: queued reports wait"))
    for ch in MANUAL.values():
        if ch.id not in cfg.manual_channels:
            out.append((ch.name, "not in REPORT_MANUAL_CHANNELS" + (f". {ch.notes}" if not ch.default_on else "")))
    if BRAND_FORM not in cfg.manual_channels:
        out.append(("Brand web forms", "brand_form is not in REPORT_MANUAL_CHANNELS"))
    return out
