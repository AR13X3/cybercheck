"""Report wording: email drafts, manual web-form text and the Netcraft reasons.

Rules for every text: factual and neutral. Say what was observed and when, give the evidence, say that
CyberCheck detected it automatically and whether a person reviewed it, and that the report is made in
good faith. No accusations beyond the evidence ("appears to impersonate", "asks visitors for").
Plain text only; the dashboard escapes it and never renders it as HTML.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..blocklist import SHARED_PLATFORMS
from . import channels
from .common import clean_line, clean_text, valid_email

DRAFT_MAX = 12000


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _official(facts: dict) -> str:
    return ", ".join(facts.get("official_sites") or [])


def _brand_phrase(facts: dict) -> str:
    off = _official(facts)
    return f"{facts.get('brand')}" + (f" (official site: {off})" if off else "")


def _hosting(facts: dict) -> str:
    parts = []
    if facts.get("ips"):
        parts.append(", ".join(facts["ips"]))
    if facts.get("asn"):
        parts.append(f"AS{facts['asn']}" + (f" {facts['as_name']}" if facts.get("as_name") else ""))
    if facts.get("ip_country"):
        parts.append(f"({facts['ip_country']})")
    return " ".join(parts)


def _snapshot(facts: dict) -> str:
    if not facts.get("page_seen"):
        return ""
    s = f"snapshot taken {facts['page_seen']}"
    if facts.get("page_profile"):
        s += f" with a {facts['page_profile']} browser"
    if facts.get("egress_country") == "AU":
        s += " from an Australian network"
    return s


def found_line(facts: dict) -> str:
    line = f"first seen {facts.get('first_seen') or 'recently'} in {facts.get('found_via') or 'monitoring'}"
    if facts.get("ct_log") and "Certificate" in (facts.get("found_via") or ""):
        line += f" ({facts['ct_log']})"
    return line


def evidence_lines(facts: dict) -> list[str]:
    lines = [f"- Domain: {facts.get('domain')}"
             + (f" (displayed as {facts['displayed_as']})" if facts.get("displayed_as") else "")]
    for u in (facts.get("urls") or [])[:10]:
        lines.append(f"- URL: {u}")
    lines.append(f"- Appears to impersonate: {_brand_phrase(facts)}")
    asks = _join(facts.get("asks_for") or [])
    snap = _snapshot(facts)
    if asks:
        lines.append(f"- The page asks visitors for {asks}" + (f" ({snap})" if snap else ""))
    elif snap:
        lines.append(f"- Page {snap}")
    if facts.get("form_posts_elsewhere"):
        lines.append("- A form on the page sends what is typed to another domain")
    lines.append(f"- Domain {found_line(facts)}")
    if facts.get("issuer"):
        lines.append(f"- TLS certificate issuer: {facts['issuer']}")
    reg = []
    if facts.get("registered"):
        reg.append(f"registered {facts['registered']}")
    if facts.get("registrar"):
        reg.append(f"registrar {facts['registrar']}"
                   + (f" (IANA ID {facts['registrar_iana_id']})" if facts.get("registrar_iana_id") else ""))
    if reg:
        lines.append("- Registration: " + "; ".join(reg))
    host = _hosting(facts)
    if host:
        lines.append(f"- Hosting: {host}")
    if facts.get("screenshot") and facts.get("page_seen"):
        lines.append(f"- Screenshot: captured {facts['page_seen']}")
    return lines


def disclosure(facts: dict) -> str:
    if facts.get("source") == "bot" or "forwarded" in (facts.get("found_via") or ""):
        how = "A link to this site was forwarded to CyberCheck, which then checked the site automatically."
    else:
        how = ("CyberCheck, an automated monitor for websites that impersonate Australian brands, found this "
               f"domain in {facts.get('found_via') or 'monitoring'}. No message was received.")
    if facts.get("reviewed_by_human"):
        review = ("A CyberCheck reviewer checked the evidence and confirmed it as phishing"
                  + (f" on {facts['reviewed_on']}." if facts.get("reviewed_on") else "."))
    else:
        review = ("It was assessed by automatic checks (page analysis and an AI review of the page) and has "
                  "not yet been reviewed by a person.")
    return (f"How this was found: {how} {review} This report is made in good faith on the basis of the "
            "evidence above. If you find the site is legitimate, please tell us so we can correct our records.")


def signature(cfg) -> str:
    contact = cfg.reporter_email or (cfg.smtp.sender if cfg.smtp else "")
    lines = ["--", f"{cfg.reporter_name} phishing reports"]
    lines.append(contact or "(add your contact details before sending)")
    return "\n".join(lines)


# ---- email drafts ---------------------------------------------------------------------------------

def _tld(facts: dict) -> str:
    return (facts.get("domain") or "").rsplit(".", 1)[-1].lower()


def email_subject(channel: str, facts: dict) -> str:
    d, b = facts.get("domain"), facts.get("brand")
    if channel == channels.REGISTRAR.id:
        s = f"Phishing (DNS abuse) report: {d} impersonating {b}"
    elif channel == channels.HOSTING.id:
        ip = (facts.get("ips") or [""])[0]
        s = f"Phishing site on your network: {d}" + (f" ({ip})" if ip else "")
    else:
        s = f"Possible phishing site impersonating {b}: {d}"
    return clean_line(s, 200)


def email_request(channel: str, facts: dict) -> str:
    if channel == channels.REGISTRAR.id:
        if (facts.get("domain") or "").lower().endswith(".au"):
            return ("Please investigate under the .au Licensing Rules (rules 2.11.16 and 2.11.17 prohibit illegal "
                    "or fraudulent use and DNS abuse, which includes phishing) and, if you confirm the domain is "
                    "used for phishing, suspend or cancel the licence (rule 2.16.3).")
        if len(_tld(facts)) == 2:
            return ("Please investigate under your abuse policy and, if you confirm the domain is used for "
                    "phishing, suspend it.")
        return ("Please investigate under your abuse procedures (ICANN Registrar Accreditation Agreement "
                "section 3.18) and, if you confirm the domain is used for phishing, suspend it.")
    if channel == channels.HOSTING.id:
        return "Please investigate and, if you confirm the content is phishing, remove it."
    return ("We are passing this on so your team can assess it and arrange a takedown if appropriate.")


def email_intro(channel: str, facts: dict) -> str:
    d = facts.get("domain")
    if channel == channels.HOSTING.id:
        return f"A website on {d}, hosted on your network, appears to be a phishing page impersonating {facts.get('brand')}."
    if channel.startswith("brand:") and facts.get("source") != "bot":
        # brand mailboxes are built for forwarded messages: say first that this is a website report
        return (f"This is a report about a website, not a forwarded message: CyberCheck found it in "
                f"{facts.get('found_via') or 'monitoring'} and no message was received. The domain {d} appears to "
                f"be used for a phishing website impersonating {facts.get('brand')}.")
    return f"The domain {d} appears to be used for a phishing website impersonating {facts.get('brand')}."


def email_template(channel: str, facts: dict, cfg) -> str:
    parts = [email_intro(channel, facts), "", "Evidence:", *evidence_lines(facts), "",
             email_request(channel, facts), "", disclosure(facts), "", signature(cfg)]
    return clean_text("\n".join(parts), DRAFT_MAX)


def wrap_ai_body(ai_body: str, facts: dict, cfg) -> str:
    """The AI writes the report itself; the disclosure and signature are always added by CyberCheck."""
    return clean_text("\n".join([clean_text(ai_body, 6000).strip(), "", disclosure(facts), "", signature(cfg)]),
                      DRAFT_MAX)


def contact_warning(address, domain: dict, flagged=()) -> str:
    """Why a report must not be pre-addressed or sent to `address` ('' when it may). RDAP abuse contacts
    can be the site operator's own: an address on the reported domain (abuse@<phishing domain>), or on
    another domain CyberCheck tracks as suspicious (`flagged`: registrable domains), would tip off the
    attacker and hand them the evidence and the reporter's address.
    A shared hosting platform (blocklist.SHARED_PLATFORMS: weebly.com, wix.com, ...) is not the attacker's:
    the phishing site is one tenant's subdomain, so abuse@weebly.com is the right contact. Only addresses
    on the tenant's own hostnames are refused there."""
    if not valid_email(address):
        return ""
    host = address.rsplit("@", 1)[1].lower().rstrip(".")
    registered = (domain.get("registered_domain") or "").lower().rstrip(".")
    names = {h.lower().rstrip(".") for h in (domain.get("hostnames") or []) if isinstance(h, str)}
    if registered not in SHARED_PLATFORMS:
        names.add(registered)
    names -= SHARED_PLATFORMS

    def under(parent: str) -> bool:
        return bool(parent) and (host == parent or host.endswith("." + parent))
    if any(under(n) for n in names):
        return (f"Not filled in: {address} is on the reported domain itself, so it most likely belongs to the "
                "people running the site. Find the provider's real abuse contact; do not send it there.")
    hit = next((f for f in sorted(flagged) if under(str(f).lower()) and str(f).lower() not in SHARED_PLATFORMS),
               None)
    if hit:
        return (f"Not filled in: {address} is on {hit}, a domain CyberCheck tracks as suspicious, so it may "
                "belong to the attacker. Find the provider's real abuse contact; do not send it there.")
    return ""


def _candidate(channel: str, domain: dict) -> tuple[str, str]:
    """The abuse address on file for this channel before the safety check, and the hint."""
    if channel == channels.REGISTRAR.id:
        to = domain.get("registrar_abuse_email") or ""
        if valid_email(to):
            return to, "From the registrar's RDAP abuse contact."
        if channels.is_au(domain):
            return "", ("The .au registrar abuse address is not looked up automatically (auDA WHOIS Policy 5.1 "
                        f"prohibits automated queries). Look up 'Registrar Abuse Contact Email' by hand at "
                        f"{channels.AU_WHOIS} and enter it here.")
        return "", ("No abuse address was found in RDAP. ICANN-accredited registrars publish one on, or linked "
                    "from, their home page (RAA 3.18.1).")
    if channel == channels.HOSTING.id:
        to = domain.get("hosting_abuse_email") or ""
        if valid_email(to):
            return to, "From the RIR (RDAP) abuse contact of the hosting IP. RIR contacts can be wrong."
        ip = (domain.get("ips") or [""])[0]
        return "", f"No abuse address was found for {ip or 'the hosting IP'}; look it up in RIR data."
    if channel.startswith("brand:"):
        c = channels.brand_contact(channel.split(":", 1)[1])
        if c and c.method == "email":
            return c.address, f"Verified on {c.source}" + (f". {c.notes}" if c.notes else "")
    return "", ""


def recipient_warning(channel: str, domain: dict, flagged=()) -> str:
    """The warning for the reviewer when the address on file was withheld ('' when it was not)."""
    return contact_warning(_candidate(channel, domain)[0], domain, flagged)


def recipient(channel: str, domain: dict, flagged=()) -> tuple[str, str]:
    """(address or '', hint for the reviewer). An address that may be the attacker's is left out, and the
    hint says why (see contact_warning)."""
    to, hint = _candidate(channel, domain)
    warning = contact_warning(to, domain, flagged)
    return ("", warning) if warning else (to, hint)


# ---- manual web forms -----------------------------------------------------------------------------

def _summary(facts: dict, *, short: bool = False) -> str:
    asks = _join(facts.get("asks_for") or [])
    s = f"Appears to impersonate {_brand_phrase(facts)}" + (f" and asks for {asks}" if asks else "") + "."
    s += f" The domain {facts.get('domain')} was {found_line(facts)}"
    if facts.get("registered") and not short:
        s += f" and registered on {facts['registered']}"
    s += "."
    if facts.get("source") == "bot":
        s += " Reported to CyberCheck by a member of the public, checked automatically"
    else:
        s += " Found by automated monitoring (CyberCheck; no message was received)"
    s += " and confirmed by a reviewer." if facts.get("reviewed_by_human") else "."
    return s


def manual_item(channel: str, facts: dict, domain: dict) -> dict:
    """{'url': official form, 'fields': [{'label', 'value'}], 'notes': str} for a checklist item."""
    urls = facts.get("urls") or []
    first = urls[0] if urls else f"https://{facts.get('domain')}/"
    others = [u for u in urls[1:]]
    summary = _summary(facts)
    if others:
        summary += " Other URLs on the same domain: " + ", ".join(others[:5]) + "."
    if channel.startswith(channels.BRAND_FORM + ":"):
        c = channels.brand_contact(channel.split(":", 1)[1])
        return {"url": c.address if c else "", "name": c.name if c else channel,
                "notes": (c.notes if c else "") + (" Source: " + c.source if c else ""),
                "fields": [{"label": "Website / link of the scam", "value": first},
                           {"label": "How you were contacted", "value": "Website found by monitoring; no message was received"},
                           {"label": "Description", "value": summary}]}
    ch = channels.MANUAL[channel]
    if channel == "scamwatch":
        fields = [{"label": "Website URL", "value": first},
                  {"label": "What makes the website a scam?", "value": summary}]
    elif channel == "google_safe_browsing":
        fields = [{"label": "URL", "value": first},
                  {"label": "Additional details", "value": _summary(facts, short=True)}]
    elif channel == "microsoft_smartscreen":
        fields = [{"label": "URLs (one per line)", "value": "\n".join(urls[:100]) or first},
                  {"label": "Threat type", "value": "Phishing"},
                  {"label": "Main language of the site (check the screenshot)", "value": "English"}]
    elif channel == "cloudflare_abuse_form":
        how = "The page was viewed" + (" from an Australian network" if facts.get("egress_country") == "AU" else "")
        if facts.get("page_profile"):
            how += f" with a {facts['page_profile']} browser"
        just = summary + " " + how + "; it may show different content to other visitors."
        host = urlsplit(first).hostname
        same_host = [u for u in urls if urlsplit(u).hostname == host] or [first]
        fields = [{"label": "Report type", "value": "Phishing"},
                  {"label": "URLs (same hostname, one per line)", "value": "\n".join(same_host[:250])},
                  {"label": "Justification", "value": just[:5000]}]
        if facts.get("official_sites"):
            fields.append({"label": "Original work (the genuine site)", "value": f"https://{facts['official_sites'][0]}/"})
    elif channel == "auda_dns_abuse":
        fields = [{"label": "Subject", "value": f"Report of suspected DNS abuse (phishing): {facts.get('domain')}"},
                  {"label": "Message", "value": "This is a report of suspected DNS abuse (phishing) in .au, not a "
                                                "complaint about a registrar. " + summary
                                                + " We have also reported it to the registrar of record."}]
    else:   # reportcyber, apwg_report and any other plain form
        fields = [{"label": "URL", "value": first}, {"label": "Details", "value": summary}]
    return {"url": ch.url, "name": ch.name, "notes": ch.notes, "fields": fields}


# ---- Netcraft --------------------------------------------------------------------------------------

def netcraft_reasons(facts: dict) -> tuple[str, str]:
    """(submission reason, per-URL reason)."""
    asks = _join(facts.get("asks_for") or [])
    off = _official(facts)
    top = (f"Lookalike of {facts.get('brand')} (Australian brand" + (f"; official site {off}" if off else "") + "). "
           f"{facts.get('domain')} was {found_line(facts)}.")
    snap = _snapshot(facts)
    if asks:
        top += f" A {snap or 'page snapshot'} asks for {asks}."
    if facts.get("reviewed_by_human"):
        top += " Detected automatically by CyberCheck and confirmed as phishing by a human reviewer."
    else:
        top += (" Detected automatically by CyberCheck and not yet reviewed by a person (automatic checks: "
                f"combined score {facts.get('final_score')}/100; AI page check: {facts.get('ai_verdict')}).")
    top += " Reported in good faith."
    per_url = f"Appears to impersonate {facts.get('brand')}" + (f"; asks for {asks}" if asks else "")
    return clean_line(top, 2000), clean_line(per_url, 500)
