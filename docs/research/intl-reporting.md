# International phishing-report channels and lookup services (fact-checked)

Topic: `intl-reporting`. Context country: Australia (AU). Checked against primary sources on 2026-11-15.
Machine-readable version: `docs/research/intl-reporting.yaml`.

## Summary

- **Netcraft Report API v3 is still the only free, keyless channel built for automated phishing reports.** This was re-confirmed from the live OpenAPI spec and the FAQ text in Netcraft's site bundle:
  - `POST https://report.netcraft.com/api/v3/report/urls` takes `email` and `urls`, up to 1000 URLs per submission.
  - Each URL can carry `country` (use `AU`), a `reason` and a base64 `screenshot`.
  - Status is polled by UUID. Submissions are archived after 30 days.
  - Netcraft also accepts fake shops and scam sites, not only phishing.
  - It may reject URLs when it gets "a particularly high volume of submissions on the same domain".
- **Spamhaus Submission Portal (beta) is a second automated route the original research missed.** It is a REST API with a Bearer key, and the account is free (log in with GitHub, Google or LinkedIn). Submissions are screened by Spamhaus heuristics, not listed automatically. Whether it has a phishing threat-type code, and how its terms treat bots, are not yet confirmed, so it is conditional.
- **APWG eCX and the Cloudflare Abuse Reports API are confirmed, but both are gated:**
  - eCX needs paid membership. The three cheapest tiers can only see their own submitted phishing data.
  - Cloudflare needs an abuse-reports entitlement on the account.
- **Confirmed closed, manual or out of scope:**
  - Google Web Risk Submission API: closed to new contracts, final renewals by 2026-12-31, deprecation by 2027-12-31.
  - Google Safe Browsing reporting: manual form only.
  - PhishTank: "New user registration temporarily disabled".
  - Microsoft: a web form with CAPTCHA for guests. The Graph API is beta and only for an organisation's own tenant.
  - OpenPhish: report by email only, and the community feed's terms forbid automation and redistribution.
  - URLhaus: does not accept phishing.
- **Corrections that change the design:**
  1. **auDA WHOIS Policy clause 5.1(a) "strictly prohibit[s]" using .au WHOIS data "to support an automated electronic query process".** Clause 2.1 says RDAP is part of the WHOIS service. A pipeline that looks up every .au candidate automatically through `rdap.cctld.au` breaks this policy, and the server returned HTTP 429 (Cloudflare 1015) again on this check's first request. Treat .au registrar lookups as manual or very low-volume until auDA confirms otherwise.
  2. **auDA Registrar Agreement clause 14.8(c) applies only to reports received "via the DNS Abuse Contact".** That contact is nominated between auDA and the registrar in Schedule 1. A public reporter citing 14.8(c) to a registrar's ordinary abuse address may therefore have no contractual force.
  3. **RDAP status values are the RFC 8056 strings with spaces, such as `client hold` and `server hold`, not the EPP forms `clientHold` and `serverHold`.** This was seen live on rdap.verisign.com. Takedown timing code must match the RDAP strings.
  4. **Google Web Risk Lookup pricing has a trap.** Calling `threatLists.computeDiff` reprices `uris.search` to $50 per 1,000.
- **Confirmed live:** RDAP, Team Cymru and RIPEstat lookups work with no account. `.io`, `.co`, `.me`, `.ws` and `.nz` are not in the IANA DNS bootstrap, and rdap.org returns 404 for them, so they need port-43 WHOIS.

## Verified facts

### Netcraft Report API v3
- **Servers:** production `https://report.netcraft.com/api/v3`, development `https://report.netcraft.com/api/v3/test`. Source: https://report.netcraft.com/api/v3/api.json
- **No security on the report endpoint.** `POST /report/urls` has no `security` entry and the spec defines no `securitySchemes`. Only the `/tags/file`, `/tags/mail` and `/tags/url` GET endpoints declare `BearerAuth`, which the spec never defines. The spec lists 401 "Authentication Required" and 403 "Forbidden" as possible responses on `/report/urls`, without saying when they occur. Source: https://report.netcraft.com/api/v3/api.json
- **Request body (`ReportURLs`, `additionalProperties: false`):**
  - Required: `email` (format email; "to which the result of our analysis will be sent") and `urls[]`.
  - Each URL item allows `url`, `country` ("country code of a country the site is known to be accessible from"), `reason`, `tags` (only `smishing` is listed) and `screenshot` {`base64`, `ext`: gif | png | jpg | jpeg}.
  - Top-level optional fields: `reason` (max 10,000 characters), `skip_invalid_urls`, `source` (UUID, only if Netcraft provided one) and `no_submission` (restricted, and cannot be combined with a screenshot).
  - "up to 1000 URLs per submission are permitted".
  - Source: https://report.netcraft.com/api/v3/api.json
- **Responses:** 200 returns {`message`, `uuid`, `invalid_urls`}. 429 means "Too many urls reported. We employ rate limiting…". Source: https://report.netcraft.com/api/v3/api.json
- **Status endpoints:**
  - `GET /submission/{uuid}` returns `state` (processing | no threats | suspicious | malicious), `is_archived`, `classification_log`, `state_counts` and `submitter.email`.
  - `GET /submission/{uuid}/urls` takes `count` up to 1000, plus `page`, `sort`, `url_state` and `url_takedown_state` filters. Each URL has `url_state`, `url_takedown_state` (not injected | not started | in progress | resolved), `incident_report_url`, `ip`, `country_code` and `url_classification_reason`. After archiving it returns 404 "this submission has been archived".
  - `POST /report/mistake` reports a false positive, and `POST /submission/{uuid}/report_issue` raises an issue.
  - Source: https://report.netcraft.com/api/v3/api.json
- **FAQ, quoted from the FAQ text in Netcraft's site bundle** (the page at https://report.netcraft.com/faqs renders client-side):
  - "By default, submissions will be archived after 30 days."
  - "If you have a need to report higher volumes, please contact us … at support@netcraft.com."
  - The page for a submission "can be visited by anyone with the link". The link contains the submission's UUID, which only the submitter is given.
  - Email reports to scam@netcraft.com "are treated in the same way as a report on the web interface or to the API".
  - "Netcraft's feed is used by many browsers, [but] we do not have direct control over what they block."
  - URLs can be rejected because of "a particularly high volume of submissions on the same domain".
  - Netcraft credits "phishing, phishing kit, fake shop, web shell, and scam site URLs". "Anonymous reports are not eligible for credit." Reporters using free email providers "may not receive result emails until you have made more than one submission".
  - Source: https://report.netcraft.com/faqs
- **Rate-limit page text:** "Adding a small delay between requests should be sufficient." Source: https://report.netcraft.com/faqs (site bundle)

### Google
- **Web Risk Submission API is closing.** The page says: "in a formal feature freeze and closed to new orders ahead of full deprecation no later than December 31, 2027". "The final date to renew existing contracts is December 31, 2026." "We no longer accept new contracts or expansions." The page was last updated 2026-11-10. The endpoint is `POST https://webrisk.googleapis.com/v1/projects/{project}/uris:submit`, which returns a long-running operation. Accepted evidence includes social-engineering content that "mimics a legitimate online brand (brand name, logo, look and feel) … or requests users to enter sensitive credentials". Source: https://docs.cloud.google.com/web-risk/docs/submission-api
- **Safe Browsing reporting is manual.** Google's docs point phishing reports to https://www.google.com/safebrowsing/report_phish/ and false positives to https://www.google.com/safebrowsing/report_error/. Both URLs returned 200. Source: https://developers.google.com/safe-browsing/v4/reporting
- **v4 is deprecated.** The v4 overview says "The Safe Browsing APIs (v4) are deprecated." No shutdown date is given. "The Safe Browsing API is for non-commercial use only." Source: https://developers.google.com/safe-browsing/v4
- **v5 endpoints:** `GET https://safebrowsing.googleapis.com/v5/hashes:search`, `GET /v5/hashLists:batchGet` and `GET /v5alpha1/urls:search`. For urls:search, "Clients MUST NOT send more than 50 URLs." The API key is passed as a query parameter. Sources: https://developers.google.com/safe-browsing/reference and https://developers.google.com/safe-browsing/reference/rest/v5alpha1/urls/search
- **Appropriate Usage page (last updated 2025-03-05):**
  - Non-commercial means "not for sale or revenue generating purposes".
  - "All Google Safe Browsing APIs are free of charge."
  - A default quota is allocated when the API is enabled.
  - Warnings must carry "Advisory provided by Google".
  - Source: https://developers.google.com/safe-browsing/reference/Appropriate.Usage
- **Terms (last modified 2025-11-20):** "Unless you have a separate agreement with Google, you may not use the Safe Browsing API for commercial purposes." "You may not treat a URL from Google's list as an unsafe web resource, such as by showing users a warning about the site or blocking access to it, unless your application has received from Google updated information … within the past thirty minutes." Source: https://developers.google.com/safe-browsing/terms
- **Web Risk pricing:** `uris.search` is free for 0 to 100,000 calls a month, then $0.50 per 1,000. `threatLists.computeDiff` is free. However, "Calling threatLists.computeDiff changes the pricing of uris.search calls to the pricing of hashes.search calls", and "uris.search to confirm threats" in Lookup + Update mode costs $50.00 per 1,000. Source: https://cloud.google.com/web-risk/pricing

### PhishTank
- **Registration closed:** the register page shows "New user registration temporarily disabled." Source: https://phishtank.org/register.php
- **Lookup:** requests go to https://checkurl.phishtank.com/checkurl/ with `url`, `format` (xml | php | json) and an optional `app_key` ("without it the rate at which you can make requests will be much more limited"). A descriptive User-Agent is required, e.g. `phishtank/[username]`. Going over the limit returns HTTP 509. Source: https://phishtank.org/api_info.php
- **Database downloads** are at `https://data.phishtank.com/data/online-valid.{xml,csv,json}[.gz|.bz2]`. "Without this key, you will be limited to a few downloads per day." Source: https://phishtank.org/developer_info.php
- **FAQ:** commercial and non-commercial use is "OK". Requests per hour are limited. A "complete rewrite" is planned with "No timeline". Source: https://phishtank.org/faq.php

### APWG eCX
- **Membership dues (USD):** Premium $15,000, Sponsoring $7,500, Corporate $5,000, Individual Corporate $2,500, Accredited Reporter $1,500.
  - Apply by emailing membership@apwg.org from the organisation's own email domain. Webmail (Gmail, Yahoo, Protonmail, GMX, Tuta and others) "cannot be considered".
  - After approval come a data sharing agreement, an invoice, and an eCX invitation.
  - Discounts are "sometimes" offered to non-profits, academics, government, law enforcement and NGOs.
  - **Accredited Reporter, Individual Corporate and Corporate members can "View only your eCX submitted phishing URL data".** Only Premium and Sponsoring members get the Phish Data Module.
  - Source: https://apwg.org/membership/
- **API:** OpenAPI 3.1.0 spec, `info.version` 1.1.2 (identical on the `main` default branch and on `master`). Production `https://ecrimex.net/api/v1`, sandbox `https://sandbox.ecx2.ecrimex.net/api/v1`. Auth is `Authorization: Bearer <api_key>`. `POST /phish` requires `url` and `confidence`, and also takes `brand`, `discoveredAt`, `status`, `ip[]` and `asn[]`. `GET /phish` returns up to 10,000 of the latest records. There are also `/malicious-domain`, `/malicious-sms` and `/report-phishing` modules. Support contact: support@ecrimex.net. Source: https://raw.githubusercontent.com/APWG/ecx2-openapi-doc/main/ecx2-openapi.yaml
- **Public route:** forward suspected phishing email to reportphishing@apwg.org. Source: https://apwg.org/reportphishing/

### Cloudflare
- **Submit endpoint:** `POST /accounts/{account_id}/abuse-reports/{report_param}`. `report_param` is described only as "The report type for submitted reports."
  - Needs the "Trust and Safety Write" permission and the abuse-reports entitlement: "Enterprise accounts have it by default; other accounts must request access". Without it the API returns 401.
  - Phishing (`act: abuse_phishing`) required fields: `email`, `email2` (must match), `host_notification` and `owner_notification` (`send` or `send-anon`; phishing does not accept `none`), `justification` (20 to 5000 characters), `name` and `urls` (at most 250, newline-separated, unique, same hostname).
  - Optional fields: `comments`, `company`, `original_work`, `reported_country` (2 characters), `reported_user_agent`, `tele` and `title`.
  - Response: {`abuse_rand`, `request.act`, `result`}.
  - `name`, `urls`, `email`, `company` and `tele` "may be released by Cloudflare to third parties such as the Lumen Database".
  - Source: https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/
- **Other endpoints:** `GET /abuse-reports/submitted`, `GET /abuse-reports/submitted/{report_id}` and `GET /abuse-reports/submitted/{report_id}/emails`. `denial_reason` has 13 values: unable_to_confirm, incomplete_report, not_on_cloudflare, duplicate_report, content_removed, report_details_mismatch, no_abuse_found, missing_original_work, direct_url_required, wrong_report_category, content_unavailable, law_enforcement_referral_required, domain_dispute_process_required. Source: https://developers.cloudflare.com/api/resources/abuse_reports/
- **Web form:** https://abuse.cloudflare.com/ still returned 403 to a scripted fetch. Source: https://developers.cloudflare.com/fundamentals/reference/report-abuse/submit-report/

### Microsoft
- **Report unsafe site form:** sign in or "Continue as a guest". The guest form has a CAPTCHA (image and audio), takes up to 100 URLs or a .txt file under 1 MB, and asks for the threat type (Phishing, or Malware or other threats) and the site's main language. Sources: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site and https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest
- **Graph API (beta):** `POST https://graph.microsoft.com/beta/security/threatSubmission/urlThreats` with {`category`, `webUrl`}.
  - Permissions: delegated (work or school) `ThreatSubmission.ReadWrite`, or application `ThreatSubmission.ReadWrite.All`. Personal Microsoft accounts are "Not supported".
  - "Use of these APIs in production applications is not supported."
  - The example response shows `"source": "administrator"` and a `tenantId`, so it is a tenant-admin tool.
  - Source: https://learn.microsoft.com/en-us/graph/api/security-urlthreatsubmission-post-urlthreats?view=graph-rest-beta

### OpenPhish
- **Reporting:** the home page links to "Report Phishing" as `mailto:report@openphish.com`. False positives go to support@openphish.com. The knowledge base says: "We don't offer an API to determine if a URL is phishing". Sources: https://openphish.com/ and https://openphish.com/kb.html
- **Feeds:** the Community feed updates every 12 hours and is free under the Terms of Use. Premium and Platinum update every 5 minutes. Law enforcement may get the Premium Gov feed at no cost. `feed.txt` returns a 302 to `raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`. Source: https://openphish.com/phishing_feeds.html
- **Terms:**
  - Use is "solely for your personal use", or for research "provided that such research does not support your organization's business operations".
  - The terms forbid commercial use "including … security operations, threat intelligence, detection, enrichment, product development, automation, customer protection".
  - The terms forbid making any portion of the information "available to any third party".
  - Source: https://openphish.com/terms.html

### URLhaus
- Phishing sites and phishing kits "should not be submitted to URLhaus (Phishing is not Malware)". The policy points to APWG, PhishTank or Netcraft instead.
- An Auth-Key is "Required" for API use, and is free from the abuse.ch Authentication Portal.
- Source: https://urlhaus.abuse.ch/api/

### urlscan.io
- **Free plan daily quotas:** 50 private scans, 1,000 unlisted, 5,000 public, 1,000 searches and 10,000 result requests. Country selection works for "Public Scans" only on Free; paid plans allow it for "All Scans". Source: https://urlscan.io/pricing/
- **Rate limits** are set per minute, per hour and per day for each action. Headers: `X-Rate-Limit-Scope`, `-Action`, `-Window`, `-Limit`, `-Remaining`, `-Reset` and `-Reset-After`. Check current quotas at `/api/v1/quotas`. Source: https://docs.urlscan.io/pages/api-rate-limits
- **Best practices:** "Consider first searching for a domain or URL before submitting it to be scanned again", use exponential backoff, and submit URLs containing personal data as Unlisted. Source: https://docs.urlscan.io/pages/api-best-practices
- **Terms of Service (last updated 2020-07-22):** grant a licence "solely for your personal, non-commercial use". "Commercial use of any part of our service requires express written permission." Automated access is banned "With the exception of acceptable API usage". Source: https://urlscan.io/terms/
- **API keys:** "Unauthenticated users only receive minor quotas for API calls." Source: https://docs.urlscan.io/pages/api-intro

### Spamhaus Submission Portal (added; beta)
- **API:**
  - Base URL: `https://submit.spamhaus.org/portal/api/v1/`, with an `Authorization: Bearer <token>` header.
  - The key is created in the portal under "API Key Creation" and is shown once.
  - Submit with `POST submissions/add/url`, `add/domain`, `add/ip` or the raw-email endpoint, using the body {`threat_type`, `reason` (at most 3,999 characters), `source.object`}.
  - Valid threat codes come from `GET lookup/threats-types`.
  - `GET submissions/list` and `GET submissions/count` (with a "matched" count) cover the last 30 days.
  - The portal is labelled "BETA".
  - Source: https://submit.spamhaus.org/api/
- **Accounts:** an account is created by signing in with LinkedIn, Google or GitHub. "Any domain, URL, IP etc submitted is not automatically listed in Spamhaus data sets." Source: https://submit.spamhaus.org/faq/
- **Terms:** the site is "made available free of charge". Clause 7.3.1 bans bots and other automated tools from accessing the site. Clause 6.3 grants Spamhaus a licence to "distribute in any way we wish" what is uploaded. Source: https://submit.spamhaus.org/terms-conditions/

### RDAP and registration data
- **dns.json:** published 2026-10-28T22:00:04Z with 592 services. Examples: com → https://rdap.verisign.com/com/v1/ ; au → https://rdap.cctld.au/rdap/ ; top → https://rdap.zdnsgtld.com/top/ ; xyz → https://rdap.centralnic.com/xyz/ ; shop → https://rdap.gmoregistry.net/rdap/ ; cc → https://tld-rdap.verisign.com/cc/v1/ ; uk → https://rdap.nominet.uk/uk/. Not present: io, co, me, ws, nz. Source: https://data.iana.org/rdap/dns.json
- **WHOIS servers for TLDs missing from the bootstrap:** whois.nic.io, whois.registry.co and whois.nic.me, taken from IANA's port-43 root WHOIS (whois.iana.org) on 2026-11-15. Source: https://www.iana.org/domains/root/db
- **rdap.org:**
  - "Cloudflare limits clients to a maximum of 10 requests in 10 seconds", with 429 when exceeded and 403 for abuse.
  - "RDAP.org only knows about RDAP servers that are registered with IANA", and it returned 404 for .io, .co and .me test names.
  - It is run by Gavin Brown "in my own time and at my own cost".
  - Source: https://about.rdap.org/
- **Live .com lookup (`rdap.verisign.com/com/v1/domain/google.com`):** entity roles [registrar], handle `292`, publicIds [{type "IANA Registrar ID", identifier "292"}], and a nested entity with roles [abuse] and email abusecomplaints@markmonitor.com. Status values look like `client delete prohibited` and `server update prohibited`, with spaces. Source: https://rdap.verisign.com/com/v1/
- **Registrar IDs:** the IANA registrar-ids CSV has the columns ID, Registrar Name, Status and RDAP Base URL. Example row: `292,MarkMonitor Inc.,Accredited,https://rdap.markmonitor.com/rdap/`. Source: https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv
- **ipv4.json** lists both `http://` and `https://` bases for some RIRs. Use https only. The https bases are https://rdap.afrinic.net/rdap/, https://rdap.apnic.net/, https://rdap.arin.net/registry/, https://rdap.db.ripe.net/ and https://rdap.lacnic.net/rdap/. Source: https://data.iana.org/rdap/ipv4.json
- **object-tags.json** was published 2026-10-10. Source: https://data.iana.org/rdap/object-tags.json
- **Live IP lookups:**
  - APNIC 1.1.1.1 returned a top-level entity with roles [abuse], handle IRT-APNICRANDNET-AU, email helpdesk@apnic.net. This prefix is APNIC's research network (APNIC-LABS).
  - ARIN 8.8.8.8 returned the registrant GOGL with a nested [abuse] entity ABUSE5250-ARIN, email network-abuse@google.com.
  - Sources: https://rdap.apnic.net/ and https://rdap.arin.net/registry/
- **RDAP is definitive:** RDAP became the definitive source for gTLD registration data "As of 28 January 2025". Source: https://www.icann.org/en/announcements/details/icann-update-launching-rdap-sunsetting-whois-27-01-2025-en

### ICANN obligations
- **RAA 3.18, from the 2024 Amendment effective 5 April 2024:**
  - 3.18.1: keep an abuse contact, publish an email address or webform on or readily accessible from the home page, "provide the reporter with confirmation", and "take reasonable and prompt steps to investigate".
  - 3.18.2: "When Registrar has actionable evidence … must promptly take the appropriate mitigation action(s)".
  - 3.18.3: a 24/7 contact for reports of Illegal Activity.
  - 3.18.4: publish the abuse procedures and keep records for the shorter of 2 years or the legal maximum.
  - Source: https://itp.cdn.icann.org/en/files/accredited-registrars/registrar-accreditation-agreement-global-amendment-05apr24-en.htm
- **Registries are covered too.** The amendments place mitigation duties on registry operators (Base Registry Agreement Specification 6, Section 4) as well as registrars.
  - To escalate, first report to the registrar of record and wait "a reasonable time". Then file through ICANN's "abuse involving a domain name" complaint form.
  - ICANN publishes monthly DNS Abuse enforcement reports.
  - Sources: https://www.icann.org/dnsabuse and https://www.icann.org/compliance/complaint

### auDA (.au)
- **WHOIS Policy 2025-11** (version 1.1 approved 5 February 2026; version 1.2 dated 23 June 2026):
  - Clause 2.1 says the WHOIS service is provided "via a web-based tool, Port 43 and RDAP".
  - Schedule A lists Registrar Abuse Contact Email as disclosed on RDAP.
  - Clause 4.4 says "auDA has removed all email addresses from Port 43 WHOIS and RDAP responses". This contradicts Schedule A.
  - **Clause 5.1 "strictly prohibit[s]": "a) use of WHOIS data to support an automated electronic query process; and b) bulk access to WHOIS data".**
  - Clause 5.2 says auDA "will impose restrictions on the number of queries" on web WHOIS, port 43 and RDAP.
  - Sources: https://www.auda.org.au/au-domain-names/au-rules-and-policies/whois-policy-2025-11/ and https://files.auda.org.au/documents/WHOIS-Policy-June-2026.pdf
- **Live check:** `https://rdap.cctld.au/rdap/domain/auda.org.au` returned HTTP 429 with "error code: 1015" on the first request from the test host on 2026-11-15. It was the first request of this check too.
- **2025 Registrar Agreement (dated 06 December 2024), clause 14.8:**
  - (a) auDA and the registrar nominate, in Schedule 1, a "DNS Abuse Contact" as the "primary point of contact between auDA and the Registrar" for "malicious conduct in the .au ccTLD".
  - (c) "If the Registrar receives a report of DNS Abuse via the DNS Abuse Contact", it must confirm receipt to "the person that made the report" and investigate. With actionable evidence it "must promptly take appropriate mitigation action".
  - The DNS Abuse definition is the same as ICANN's.
  - Source: https://files.auda.org.au/documents/2025-Registrar-Agreement.pdf

### IP to ASN
- **Team Cymru DNS lookups, tested live on 2026-11-15:**
  - `8.8.8.8.origin.asn.cymru.com` returned "15169 | 8.8.8.0/24 | US | arin | 2023-12-28".
  - `1.1.1.1.origin.asn.cymru.com` returned "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11".
  - `AS15169.asn.cymru.com` returned "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US".
  - The origin6 query for 2001:4860:: returned "15169 | 2001:4860::/32 | US | arin | 2005-03-14".
  - The peer zone is queried by reversed IP: `1.1.1.1.peer.asn.cymru.com` returned "2914 6461 23352 | 1.1.1.0/24 | AU | apnic | 2011-08-11".
  - The page says: "Free, forever"; "50+" BGP peers; refresh every "4 hours"; "10k IPs / min" bulk speed; "$0"; bulk through whois.cymru.com (also v4.whois.cymru.com).
  - Source: https://www.team-cymru.com/ip-asn-mapping
- **RIPEstat:**
  - `network-info` for 1.1.1.1 returned asns ["13335"] and prefix 1.1.1.0/24.
  - `abuse-contact-finder` returned ['helpdesk@apnic.net'] with authoritative_rir apnic.
  - Rules: "No limit on the amount of requests", but register (email stat@ripe.net) "if you plan to regularly do more than 1000 requests/day". "8 concurrent … requests coming from one IP address."
  - Sources: https://stat.ripe.net/docs/data-api/ripestat-data-api/ and https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions

## Corrections made

1. **auDA automated lookups.** The researcher called .au RDAP only "tightly rate-limited" and recommended querying it "sparingly". **Correction:** auDA WHOIS Policy clause 5.1(a) prohibits using WHOIS data (which includes RDAP, per clause 2.1) "to support an automated electronic query process". CyberCheck should not look up .au names automatically through rdap.cctld.au or whois.auda.org.au without auDA's permission. The recommendation was changed accordingly.
2. **Citing auDA clause 14.8(c).** The researcher recommended citing it in .au registrar reports. **Correction:** 14.8(c) is triggered only by reports "via the DNS Abuse Contact", which Schedule 1 nominates between auDA and the registrar. Citing it to a registrar's public abuse address may carry no contractual weight. It was moved to uncertain, with a suggested question to auDA.
3. **RDAP status strings.** The researcher used `clientHold` and `serverHold`. **Correction:** RDAP JSON uses the RFC 8056 strings with spaces (`client hold`, `server hold`, `client delete prohibited`, and so on), as seen live on Verisign.
4. **Google attribution source.** "Advisory provided by Google" is in the Safe Browsing Appropriate Usage page, not the Terms. The Terms require "attribution and conspicuous notice" and the 30-minute freshness rule. The source was corrected.
5. **Web Risk Submission access.** The researcher's "Access needs Sales approval / contact Sales" is outdated. The current page says "We no longer accept new contracts or expansions". The Sales text was removed.
6. **Web Risk Lookup pricing.** Added that calling `threatLists.computeDiff` reprices `uris.search` to $50.00 per 1,000.
7. **APWG eCX value.** Added that Accredited Reporter ($1,500), Individual Corporate and Corporate members can only "View only your eCX submitted phishing URL data". The spec source was changed to the `main` default branch, whose content is identical, version 1.1.2. Note that the spec's `PhishPostBody` component names the discovery field `disc`, while the inline request schema says `discoveredAt`. Use `discoveredAt` and test in the sandbox.
8. **Netcraft details.**
   - The `/tags/*` endpoints declare an undefined `BearerAuth`. The report and submission endpoints declare no auth.
   - Added the FAQ's same-domain volume rejections, accepted types (fake shop, scam site), no credit for anonymous reports, and delayed result emails for free-mail reporters.
   - Netcraft's "30 days" archive and "support@netcraft.com for higher volumes" are now quoted from Netcraft's own FAQ text, not inferred.
9. **Cloudflare details.** `denial_reason` has 13 values, not the partial list given. `owner_notification` for phishing does not accept `none`. Mitigation and appeal endpoints exist.
10. **Bootstrap gaps.** Added that .ws and .nz are also absent, that rdap.org returns 404 for these TLDs (it only knows IANA-registered servers), and the port-43 servers for .io, .co and .me.
11. **Team Cymru peer zone.** The peer zone is queried by reversed IP (`<rev-ip>.peer.asn.cymru.com`), not as `AS<n>.peer...`.
12. **ipv4.json URLs.** The file includes plain `http://` RDAP bases. Use the https ones.
13. **ICANN scope.** Added that registry operators (Base Registry Agreement Specification 6, Section 4) are also bound, and the escalation sequence: registrar first, then the ICANN complaint form.
14. **Missed channel.** Added the Spamhaus Submission Portal API as a conditional automated channel.

## Uncertain / unverified

- **Spamhaus phishing threat code:** whether `lookup/threats-types` includes a phishing code for URL or domain submissions. The FAQ mentions phishing as a category, but the code list needs an API key to read.
- **Spamhaus terms:** whether clause 7.3.1 (no bots) conflicts with using its published API. It probably does not, but this was not confirmed.
- **Cloudflare `report_param`:** its accepted values are undocumented. Presumably it equals `act` (e.g. `abuse_phishing`), but that is unverified. Also unknown is whether Cloudflare grants the entitlement to a non-Enterprise, non-commercial project.
- **Netcraft limits:** there is no numeric rate limit, and no documented trigger for the 401/403 responses on `/report/urls`. What `BearerAuth` on `/tags/*` means is also unknown.
- **urlscan.io unlisted visibility:** the claim that unlisted scans are visible to "urlscan Pro" users comes from a search-result extract of the pricing and FAQ pages, not a direct read in this check. Treat it as likely, not confirmed.
- **Safe Browsing:** no v4 shutdown date, and no published default quota numbers for v4 or v5.
- **Safe Browsing report form:** whether it uses a CAPTCHA. It renders client-side and was not inspected.
- **ICANN RDAP Response Profile:** the claim that it makes an abuse entity with `tel` and `email` mandatory was not re-read. The PDF could not be text-extracted here. Live .com data is consistent with it.
- **WHOIS sunset exceptions:** the claim of exceptions for .com, .name and .post. The ICANN announcement page does not mention them.
- **auDA Policy:** whether .au RDAP actually returns a registrar abuse email (the Schedule A versus clause 4.4 conflict), and the RDAP query limit. Also unconfirmed is whether WHOIS Policy 2025-11 is already in force, or whether the 2014 policy, with similar automated-query wording, still applies until a commencement date.
- **Microsoft Graph:** whether `urlThreatSubmission` needs a Defender for Office 365 licence, and whether its submissions feed global SmartScreen blocking.
- **OpenPhish academic use:** whether OpenPhish's "Academic Use" offering (https://openphish.com/academic_use.html exists) would cover CyberCheck. Not read.
- **auDA complaints route:** the researcher's claim that the auDA Licensing Rules provide a complaints path (registrar first, then auDA) was not re-read in this check. Source to read: https://www.auda.org.au/au-domain-names/au-rules-and-policies/au-domain-administration-rules-licensing-2/
- **Registry RDAP for gap TLDs:** whether the registries for .io, .co and .me run RDAP servers outside the IANA bootstrap. Not researched.

## Recommendation

1. **Auto-send through Netcraft only for now.**
   - Use `POST https://report.netcraft.com/api/v3/report/urls` with a dedicated role mailbox on a domain CyberCheck owns. Free-mail reporters get delayed result emails, and anonymous reports earn no credit.
   - Set `country: "AU"`, a short per-URL `reason` naming the Australian brand, and a base64 screenshot from the sandbox.
   - Batch URLs from the same domain into one submission, because many separate submissions on one domain can lead to rejections.
   - Add a delay between requests, back off on 429, and test against `/api/v3/test` first.
   - Poll `/submission/{uuid}/urls?count=1000` and save every `url_state` and `url_takedown_state` change before the 30-day archive.
   - Email support@netcraft.com before going to high volume.
2. **Evaluate Spamhaus Submission Portal as a second automated channel.** Create a free account, read `lookup/threats-types`, and confirm there is a phishing code and that the API is meant for scripted use. Only then enable it, and still only above the high-confidence threshold.
3. **Enable these only once eligible:**
   - APWG eCX (from US$1,500 a year, organisational email domain, data sharing agreement). Cheap tiers do not get the shared phish feed.
   - Cloudflare Abuse Reports API, once the entitlement is granted. Use `owner_notification: "send-anon"`, `reported_country: "AU"` and a mobile `reported_user_agent`.
4. **Send everything else to the human-review queue:** the Google Safe Browsing form, the Microsoft unsafe-site form, the Cloudflare web form, APWG email and form, and registrar and host abuse contacts. Don't plan around Web Risk Submission or PhishTank submissions, and don't send phishing to URLhaus.
5. **Use lookups for measurement, not for the published blocklist:**
   - Use Safe Browsing v5 (`hashes:search`, or alpha `urls:search` with at most 50 URLs) and PhishTank checkurl only as "listed at time T" signals, and only if CyberCheck counts as non-commercial.
   - Never copy Safe Browsing or OpenPhish community data into the DNS blocklist.
   - If Web Risk Lookup is used, do not call `computeDiff` from the same account unless the $50 per 1,000 repricing is acceptable.
6. **Find abuse contacts this way:**
   - Cache the IANA bootstrap files daily and use their https bases.
   - gTLDs: take the registrar entity, then its nested `abuse` entity, then the vCard email.
   - IPs: walk entities recursively for the `abuse` role, using Team Cymru for the ASN and RIPEstat as a cross-check (send `sourceapp`, at most 8 concurrent requests).
   - .io, .co, .me: use port-43 WHOIS (whois.nic.io, whois.registry.co, whois.nic.me).
   - **.au: do not look names up automatically.** Get the registrar for flagged .au names through a human step (the auDA web WHOIS) at review time, or ask auDA for permission or an agreed access route first.
   - Time takedowns from RDAP `status` values such as `client hold` and `server hold`, plus DNS and HTTP checks.
   - Cite RAA 3.18.1 and 3.18.2 for gTLD registrars, and escalate unresolved cases to ICANN Compliance. For .au, report to the registrar, then escalate through auDA's complaints process, rather than relying on clause 14.8(c).

## Open questions

1. Is CyberCheck "commercial"? This decides whether it can use the Google Safe Browsing API ("not for sale or revenue generating purposes"), urlscan.io's free plan (personal, non-commercial) and the OpenPhish community feed (no organisational operations). Confirm with the user.
2. Ask auDA whether a low-volume, cached, automated RDAP lookup for suspected phishing domains is acceptable under WHOIS Policy clause 5.1. Also ask which version of the policy is in force, and whether public reporters can reach registrars' "DNS Abuse Contact" under Registrar Agreement clause 14.8.
3. Ask Netcraft (support@netcraft.com) about numeric rate limits, the 401/403 triggers, and whether a `source` UUID is available for a project like CyberCheck.
4. Does Spamhaus's threat-type list include phishing for URL or domain submissions, and is scripted use of the portal API allowed under its terms?
5. Will Cloudflare grant the abuse-reports entitlement to a non-Enterprise account, and what value does `{report_param}` take?
6. Do the .io, .co and .me registries run RDAP servers outside the IANA bootstrap?
7. National Australian channels (ASD's ACSC ReportCyber, Scamwatch and the National Anti-Scam Centre, auDA complaints, brand-owner abuse addresses) are out of scope here and still need researching.
8. VirusTotal URL submission (public API, free key, non-commercial terms) was not covered. It may be worth checking as another optional evidence and distribution route.
