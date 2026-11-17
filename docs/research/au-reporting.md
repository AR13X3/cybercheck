# Reporting phishing that targets Australian brands: verified channels

Fact-check of the "au-reporting" research, done 2026-11-15. Every address and URL in `au-reporting.yaml` was checked against the official page named as its source, on this date. Pages were downloaded with curl and their text and `mailto:` links extracted, including addresses hidden by Cloudflare email protection. The auDA PDFs were parsed locally.

## Summary

- **No automated channel is open to CyberCheck in Australia.** No public Australian phishing-reporting channel accepts automated or API submissions from third parties. The one machine-to-machine channel is ASD's CTIS. Only ASD Cyber Security Network Partners can join it, and they must be eligible Australian organisations with an ABN and IT security capability. Until CyberCheck is accepted, every Australian channel should go to the human review queue.
- **Scamwatch's "Report a scam website" form is the main public intake for takedowns.** It feeds the National Anti-Scam Centre (NASC), which runs a website takedown service using a third-party provider. The form is manual, protected by reCAPTCHA, and labelled as a test.
- **Brand mailboxes are verified, but they are designed for people forwarding messages they received.** All 32 brand entries in the YAML were seen on the brand's own page today. Only Macquarie and Swyftx explicitly invite reports from someone who has not interacted with the scam, or reports of fake websites.
- **.au domains: report to the registrar of record first.** Escalate to auDA only after that. A .au complaint suits false eligibility (for example a borrowed ABN). auDA tells scam reports to go to Scamwatch, and DNS-abuse reports to go to its general enquiry form.
- **Automated .au lookups are prohibited, and RDAP would not help much anyway.** The rules prohibit automated WHOIS/RDAP querying and compiling WHOIS data. RDAP and Port 43 responses carry no email addresses, so the registrar abuse email appears only in the CAPTCHA-protected web lookup.
- **No .au zone-file access for researchers was found.**
- **Corrections made:** some URLs had moved (cyber.gov.au, auDA complaint page, EnergyAustralia, Linkt) and some notes were wrong (AGL, Swyftx, Westpac, Suncorp). Two brands were added (PayPal, Origin). DHL was removed because it could not be verified.

## Verified facts

### Government channels

1. **Scamwatch has a separate website-report form.**
   - The report page asks "Are you reporting a website?" and says: "We're testing ways to make it quicker and easier to report a scam. Help us take down scam websites from social media and search results."
   - Answering "No" to money stolen and "No" to investment scam leads to "Report a website": https://forms.scamwatch.gov.au/report-a-scamwebsite/
   - That form has two required fields, "Website URL" and "What makes the website a scam?". It warns that "The ACCC may share anything I write here with its partner agencies and organisations" and that you must not give identifying personal details. It uses Google reCAPTCHA and a "Leave this field blank" honeypot.
   - The report page also says: "With your consent, we can use your report to work with organisations and remove scam websites, scam ads and contact details."
   - Sources: https://www.scamwatch.gov.au/report-a-scam and https://forms.scamwatch.gov.au/report-a-scamwebsite/
2. **The full Scamwatch form runs in five steps** (Introduction, About the scam, About you, Preview & submit, Complete). It says "We can't respond to reports made through this form" and that it is not a police report. https://portal.scamwatch.gov.au/report-a-scam/
3. **The NASC runs a takedown service.**
   - It says: "We have commenced a scam website takedown service targeting, among other things, phishing scams and online shopping scams." https://www.nasc.gov.au/what-we-do/disruption
   - In 2025 it "sent over 8,400 websites for assessment, resulting in the removal of over 7,500 scam URLs". It also "referred intelligence to our third-party takedown service". The vendor is not named. Source: media release of 30 Mar 2026, https://www.nasc.gov.au/news/continued-action-critical-to-combat-fraud-as-annual-scam-losses-exceed-2-billion
   - In Q1 2026 it took down 5,834 scam websites, including 1,960 fake gambling sites. Source: release of 5 Jun 2026, https://www.nasc.gov.au/news/thousands-of-scam-websites-taken-down-as-online-scams-continue-to-cost-australians
4. **How data reaches the NASC.**
   - It receives "near real-time automated data from ReportCyber, and regular scam data from the Australian Financial Crimes Exchange (AFCX)".
   - It is building a system that will "receive a report of a scam from any institution or individual (private or government)". No launch date, eligibility rules or API are published.
   - Source: https://www.nasc.gov.au/what-we-do/collaboration
5. **The NASC/Scamwatch contact form is not a reporting channel.** It says "Do not report a scam through this form" and "we can't respond to everyone". One reason option is "Make a business, government or other enquiry". https://forms.scamwatch.gov.au/contact-us/ (linked from https://www.nasc.gov.au/what-we-do/contact-us)
6. **ASIC's takedown capability has no public intake.**
   - Since July 2023 ASIC has "coordinated the removal of tens of thousands of investment scam and phishing websites and online advertisements". The page offers no way to submit sites. https://www.asic.gov.au/regulatory-resources/scams/asic-s-website-takedown-capability
   - Moneysmart (last updated 11 Sep 2026) says: "Report all scams, including investment scams, to Scamwatch". It also gives 19,400 removals in FY2025/26. https://moneysmart.gov.au/check-and-report-scams/report-an-investment-scam
   - ASIC impersonation scams go to an ASIC online inquiry. https://www.asic.gov.au/regulatory-resources/scams/scams-impersonating-asic
7. **ReportCyber is for victims to report cybercrime to police.**
   - cyber.gov.au calls it "our joint tool, ReportCyber". https://www.cyber.gov.au/guidance/help-during-a-cybercrime
   - The hotline is 1300 CYBER1 (1300 292 371).
   - `/report-and-recover/report` now redirects to https://www.cyber.gov.au/submit-a-report, which links to https://reportapp.cyber.gov.au/. That app shows an error in browsers it does not support.
8. **ASD's incident reporting (published 17 Jun 2026) is "for large organisations, government or critical infrastructure"**, including those with SOCI and telecommunications reporting duties. https://www.cyber.gov.au/report-a-cyber-security-incident
9. **CTIS is open only to Network Partners.**
   - CTIS is "a two-way sharing platform that enables government and industry partners to receive and share information about malicious cyber activity at machine speed". It has Sentinel and Splunk ES plugins. "To join CTIS, you need to be an ASD Cyber Security Network Partner." The blog was last reviewed 24 Mar 2024. https://www.cyber.gov.au/blog/join-the-cyber-threat-intelligence-sharing-service-through-sentinel-or-splunk-enterprise-security
   - Network Partner eligibility (published 22 Jun 2026): "registered businesses with IT security capabilities, government and security agencies, and academic or not-for-profit institutions". The form asks for an ABN, organisation size and where the IR/SOC team is located. https://www.cyber.gov.au/become-a-partner/become-an-asd-network-partner (the old `/business-government/partnership-program/...` URL redirects here)
   - In FY2025-26, CTIS "grew by 22% to over 550 partners, and shared over 1 million indicators of compromise". https://www.cyber.gov.au/publication/annual-cyber-threat-report-2025-26/year-in-review
10. **ACMA spam forwarding.**
    - Forward SMS spam to 0429 999 888 and email spam to report@submit.spam.acma.gov.au. "Please do not edit the message or change the subject line." This "is not a complaint". https://www.acma.gov.au/dealing-with-spam
    - ACMA's scams page says: "Report a scam to Scamwatch." https://www.acma.gov.au/phone-and-sms-scams
11. **SMS Sender ID Register.**
    - "The SMS Sender ID Register, which commences on 1 July" (Treasury, 28 May 2026). https://ministers.treasury.gov.au/ministers/daniel-mulino-2025/media-releases/albanese-government-steps-industry-protections-stop
    - Telstra: "From 1 July 2026, all organisations must officially register their sender IDs." https://www.telstra.com.au/cyber-security-and-safety/scams
12. **Scams Prevention Framework (SPF).**
    - On 28 May 2026 the government "designated banking, telecommunications, and key digital platforms as the first sectors". They must have systems "ready for 31 March next year", which is 31 March 2027, and must "provide clear pathways for consumers to report incidents". Treasury release, as above.
    - The designation instrument has parts for banking, telecommunications, instant messaging, internet search and social media. https://www.legislation.gov.au/F2026L00627/asmade/text
    - The SPF Rules 2026 (F2026L01140) are dated 31 August 2026 and in force. https://www.legislation.gov.au/F2026L01140/asmade
    - The Act is the Scams Prevention Framework Act 2025, No. 15, 2025. https://www.legislation.gov.au/C2025A00015/asmade
13. **AFCX** "is open to organisations involved in financial transactions – such as banking, financing, insurance, superannuation, public utilities and telcommunication providers". https://www.afcx.com.au/
    - The NASC joined the AFCX intel loop on 13 Jun 2024. It shares "scam phone numbers, URLs, and bank accounts". https://ministers.treasury.gov.au/ministers/stephen-jones-2022/media-releases/government-joins-cutting-edge-intel-tool-fight-scammers

### .au registry

14. **Licensing Rules** (auDA Board amendment date 23 June 2026): https://files.auda.org.au/documents/au-Licensing-Rules-July-2026.pdf
    - **3.4.1:** the complainant must "make the Complaint to the Registrar of Record", about the obligations of a Registrant or Registrar under the auDA Rules, "in the manner or form as required by the relevant Registrar".
    - **3.4.4–3.4.6:** the registrar has 30 calendar days unless it gives a new timeframe. It must then give a written decision with reasons and the right of appeal.
    - **3.5.1:** after that, auDA can review the registrar's decision.
    - **2.11.16:** prohibits illegal or fraudulent use.
    - **2.11.17:** prohibits use for DNS Abuse, which is defined to include phishing by reference to SSAC SAC115.
    - **2.16.3:** auDA or a registrar may suspend or cancel a licence for untrue warranties, non-compliance or the public interest.
    - **2.11.19:** auDA may act on a request from an Enforcement Body or Intelligence Agency.
    - **2.18.9:** registry information is provided "only in circumstances where access to that information is authorised or requested under Australian Law". **2.18.11–2.18.12** add an approved form and a fee.
    - **2.18.14:** prohibits "(1) the use of WHOIS Data to support an automated electronic query process; and (2) bulk access to WHOIS Data". **2.18.15:** auDA limits query numbers.
15. **WHOIS Policy 2025-11** (approved 5 Feb 2026): https://files.auda.org.au/documents/2025-11-WHOIS-Policy.pdf
    - **5.1** "strictly" prohibits automated query processes and bulk access. **5.2:** query limits on web, Port 43 and RDAP.
    - **4.4:** CAPTCHA and rate limits on web WHOIS, and **"auDA has removed all email addresses from Port 43 WHOIS and RDAP responses"**.
    - **4.5:** creation, renewal and expiry dates are not disclosed.
    - **Schedule A** lists "Registrar Abuse Contact Email" and "Registrar Abuse Contact Phone".
16. **The web WHOIS terms are stricter than the rules alone.** The service may be used "solely" to check availability, identify the holder, or contact the holder about the domain and its use. They forbid "aggregating, collecting or compiling information from the WHOIS database" and "high volume, automated, electronic processes". https://whois.auda.org.au/
17. **RDAP.** The endpoint is `https://rdap.cctld.au/rdap/` (announced 2 Mar 2026). auDA describes RDAP as "a new way for machine-to-machine access", with authenticated tiers for "authorised users such as registrars, enforcement bodies". https://www.auda.org.au/news-insights/statements/auda-implements-rdap-protocol-to-access-public-au-registry-data/
18. **What the auDA complaint covers.**
    - It covers eligibility or allocation breaches and registrar conduct. "All complaints must first be lodged with the registrar of record."
    - It sends scams to Scamwatch, website content to ACMA, hosting to the host and IP disputes to auDRP. An upheld complaint never transfers the domain.
    - https://www.auda.org.au/au-domain-names/complaints-and-disputes/au-complaints/submit-a-complaint/
19. **Reporting DNS abuse to auDA.**
    - "To get in touch with us, including to report a suspected instance of DNS abuse, submit a general enquiry." auDA also does "daily checks against DNS abuse threat intelligence feeds". https://www.auda.org.au/au-domain-names/manage-your-au-domain-name/keep-your-au-secure/
    - The CEO blog (10 Aug 2026) says auDA monitors "25 daily threat feeds" and is a member of the NetBeacon Advisory Council. https://www.auda.org.au/news-insights/blog/from-the-ceo-uplifting-australian-and-global-scam-prevention/

### Brands

20. **All 32 brand entries in the YAML were seen on the brand's own page on 2026-11-15**, with the quoted wording in each `notes` field.
    - Banks: CommBank, Bankwest, Westpac, St.George, BankSA, Bank of Melbourne, ANZ, Suncorp Bank, NAB, Bendigo, ING (two addresses), Macquarie, BOQ, HSBC.
    - Payments: PayPal.
    - Government services: ATO (email and form), Services Australia and myGov.
    - Post and couriers: Australia Post, Aramex.
    - Tolls: Linkt.
    - Telcos: Telstra (email and form), Optus, Vodafone.
    - Energy: EnergyAustralia, AGL, Origin.
    - Retail: Woolworths.
    - Crypto: Swyftx, Independent Reserve.
21. **Brands that spot checks found have no phishing mailbox.**
    - Aware Super's only address (financialcrimes@aware.com.au) is for disclosing security vulnerabilities. https://aware.com.au/member/about-us/security
    - EastLink says scam toll texts need not be reported: "there is no need to report it to EastLink". https://www.eastlink.com.au/enquiries/alerts/how-to-check-whether-a-text-message-about-unpaid-eastlink-tolls-is-a-scam
    - CoinSpot's security page offers only HackerOne for vulnerabilities. https://www.coinspot.com.au/security
    - QLD TMR's page was last updated 5 Feb 2024 and still refers to ACORN. https://www.qld.gov.au/transport/online-services/scam-emails
    - ART, UniSuper, Hostplus, AusPayPlus, Coles, Revenue NSW and ID Support NSW: no reporting mailbox on the cited pages.

### Other enforcement capability

22. **ASD's ACSC has its own takedown service and a protective DNS service.** The FY2025-26 report describes "issuing domain take downs to remove the malicious domains via ASD's ACSC's takedown service", blocking via the Australian Protective DNS (AUPDNS), and sharing domains "via CTIS block feeds". https://www.cyber.gov.au/publication/annual-cyber-threat-report-2025-26/programs

## Corrections made

| Item | Researcher said | Corrected to |
|---|---|---|
| ReportCyber URL | `https://www.cyber.gov.au/report-and-recover/report` | Redirects to `https://www.cyber.gov.au/submit-a-report`. The form is `https://reportapp.cyber.gov.au/`. |
| Network Partner page | `/business-government/partnership-program/become-an-asd-network-partner` | Redirects to `https://www.cyber.gov.au/become-a-partner/become-an-asd-network-partner` (published 22 Jun 2026) |
| CTIS 550 partners / 1M IOCs source | `.../annual-cyber-threat-report-2025-26/programs` | The figures are on the `/year-in-review` chapter. The CTIS blog itself was last reviewed in March 2024. |
| auDA complaint URL | `/au-domain-names/complaints-and-disputes/submit-complaint` | `https://www.auda.org.au/au-domain-names/complaints-and-disputes/au-complaints/submit-a-complaint/` |
| Registrar abuse email | Implied available from WHOIS/RDAP lookups | Available only from the **web** WHOIS (CAPTCHA). Port 43 and RDAP responses have **no email addresses** (WHOIS Policy 4.4). |
| auDA complaint scope | Strong ground for phishing | Suits eligibility breaches such as a false or borrowed ABN, and registrar inaction. auDA's page sends scams to Scamwatch, content to ACMA and hosting to the host. |
| auDA general enquiry | Stated route for DNS abuse | Correct per the keep-secure page. But the form says it "should not be used to lodge domain or industry complaints", so frame the case as a DNS abuse report. |
| "auDA checks 25 threat feeds" | Attributed to keep-secure page | The figure comes from the CEO blog (10 Aug 2026). The keep-secure page only says "daily checks". |
| NASC "40+ arrangements, partner portal onboarding" | Kept as a finding | Could not confirm on a primary source (the PDF could not be parsed), so moved to Uncertain. Confirmed instead: 8,400 sent / 7,500 removed in 2025, and use of a "third-party takedown service" (30 Mar 2026 release). |
| NASC enquiry form | "Use the general enquiry form to ask" | The form says it is not for reports and replies are not guaranteed. Channel renamed `nasc-enquiry`. |
| EnergyAustralia URL | `/home/help-and-support/faqs/online-security` | Redirects to `/home/help-support/faqs/online-security` |
| Linkt form URL | `/contact-us/report-scam.html` | Redirects to `/contact-us/report-scam` |
| AGL notes | "Fields render with JavaScript and were not visible"; "Fraud Management team"; spam@agl.com.au | The fields are visible in the page source, and the form accepts non-customers. "Fraud Management team" was not on the page. spam@agl.com.au was unverified and has been removed. |
| Westpac notes | vulnerability@westpac.com.au | Not on the cited page. Removed. |
| Suncorp notes | "moving customers to ANZ" | Not stated on the page. Removed. |
| Swyftx notes | "Emails: send as an attachment" | Not on the cited page (it may be in a separate "Suspicious emails" article). Removed. |
| Vodafone name | "Vodafone/TPG" | The page is Vodafone's only. Renamed. |
| DHL Australia (phishing@dhl.com) | Listed (low confidence) | dhl.com would not load, and the address came only from a search-engine summary. **Removed from the YAML** and kept as a comment. |
| PayPal | Open question only | **Added** phishing@paypal.com, verified on the PayPal AU help page. phishing@paypal.com.au is still unverified (page returned 403). |
| Origin | Open question (hello@origin.com.au unverified) | **Added**. Verified on Origin's blog page: "Forward the suspicious email to hello@origin.com.au and report it to Scamwatch." It is a general mailbox. |
| ING | Two addresses | Both confirmed. The newer alerts page (2026) uses fraud@ing.com.au, and the security page uses fraud.au@ing.com. The alerts page also lists dozens of *scam* addresses; never take addresses from it automatically. |
| ACSC email | "No public email" | Confirmed. The assist@asd.gov.au and asd.assist@defence.gov.au strings are in a hidden page-feedback field, not a reporting channel. |
| Recommendation on RDAP | "Do not build automated enrichment" | Kept. In addition, auDA advertises RDAP as machine-to-machine, which conflicts with the rules (see Uncertain). The web WHOIS terms also forbid compiling WHOIS data, which limits storing lookup results. |

## Uncertain / unverified

- **NASC data partners and portal.** It could not be confirmed that the NASC has "over 40 data-sharing arrangements" or onboards partners to a "partner portal". The Targeting Scams 2025 PDF could not be parsed here. The 2023 report mentioned a planned Partner Portal, per a search summary only. No eligibility rules, API or onboarding process are published anywhere found.
- **How the NASC takedown works.** The takedown vendor, the typical time to takedown, and whether Scamwatch website-form reports go automatically to the takedown provider or to ASIC are all unknown. The statement that investment-scam URLs go automatically to ASIC comes only from third-party summaries.
- **Scamwatch website form.** It is labelled as testing. Its permanence, any submission limits, and whether it accepts reports from non-victims at volume are not stated.
- **SPF Rules 2026.** The operative text (format and timing of "actionable scam intelligence" reports to the ACCC, and whether entities must accept intelligence from third parties) could not be read, because legislation.gov.au renders the text with JavaScript. The Act's assent date (20 Feb 2025) is from memory and was not shown on the page fetched.
- **RDAP and automation.** It is unclear whether occasional software-triggered RDAP lookups (for example one per suspect domain, to get the registrar name) count as a prohibited "automated electronic query process". auDA's RDAP announcement promotes machine-to-machine use, but Rule 2.18.14, WHOIS Policy 5.1–5.2 and the WHOIS terms prohibit automated queries and compiling data. The current numeric rate limit is unpublished; the earlier "20 per hour per IP" figure is unverified.
- **.au zone data.** No auDA zone-file or new-registration feed for researchers was found. Absence is not proof; ask auDA.
- **NetBeacon and .au.** auDA is on the NetBeacon Advisory Council, but it was not confirmed whether NetBeacon's reporter accepts .au domains.
- **Unconfirmed brand addresses (not in the YAML):**
  - DHL Australia: phishing@dhl.com, or the global phishing-dpdhl@dhl.com.
  - PayPal: phishing@paypal.com.au.
  - ubank: phish@nab.com.au or phish@ubank.com.au (pages returned 403).
  - AGL: spam@agl.com.au.
  - Super funds, Coles, Service NSW, VicRoads (403) and Australian Payments Plus: no mailbox found. The VicRoads and AustralianSuper pages returned 403 today, so their "no mailbox" status was not re-checked.
- **Whether brand mailboxes act on CT-log findings.** None of the brand pages says whether reports from third-party researchers with no received message are acted on. Macquarie ("If you haven't engaged with... but wish to report it") and Swyftx (fake websites) come closest.
- **ASD's ACSC takedown service.** It exists, but no public intake or eligibility rules were found.

## Recommendation

1. **Australian channels: no auto-send.** Route every Australian channel to the human review queue (`automated_ok: false`). The exception is `asd-ctis`, and only after ASD approves Network Partner membership. Global automated channels (registrar or host abuse APIs, browser blocklists and similar) are a separate topic and still apply to .au targets.
2. **Per confirmed finding, a reviewer:**
   1. Files the URL in the Scamwatch "Report a scam website" form. Add a short factual reason, such as "impersonates <brand> login; first seen in CT log <timestamp>", with no personal data. This is the only public route into the NASC takedown pipeline.
   2. Emails the brand's mailbox from the YAML, in plain text: URL, first-seen time, certificate SHA-256 and SAN list, hosting IP or ASN, and one screenshot. Note at the top that no message was received and the site was found through Certificate Transparency.
      - Prefer brands whose pages fit this kind of report (Macquarie, Swyftx, Services Australia "found a scam", Woolworths, NAB, Westpac group).
      - Australia Post asks for no screenshots, so send the URL and details only.
      - Linkt requires an image file in its web form.
      - Send one report per brand per domain. Several mailboxes send only an automatic reply.
   3. For .au domains, gets the registrar from a manual web WHOIS lookup and reports to the registrar's abuse contact, citing Licensing Rules 2.11.16–2.11.17. If the registrant's ABN or eligibility looks false, or the registrar does not respond within 30 days (3.4.4), escalate through the auDA complaint form. For live DNS abuse, also send auDA a general enquiry.
   4. For non-.au domains impersonating Australian brands, use the registrar and host abuse channels from the global research topic.
3. **.au lookups: automate nothing.** Do not build automated .au WHOIS/RDAP enrichment, and do not store WHOIS records in bulk (Rule 2.18.14, WHOIS Policy 5.1, WHOIS terms). Instead:
   - Keep a hand-maintained table of the main .au registrars and their published abuse addresses, built from auDA's accredited registrar list (https://www.auda.org.au/registrar-resources/list-of-au-accredited-registrars/).
   - Write to auDA (general@auda.org.au) asking whether low-volume RDAP lookups for abuse reporting are allowed, and whether a researcher or trusted-notifier arrangement exists.
4. **.au discovery: stay on Certificate Transparency.** No zone-file access was found.
5. **Longer-term options for an automated route:**
   - Apply for ASD Network Partner status. This needs an ABN and IT security capability, and gives CTIS access.
   - Send the NASC a business enquiry about data sharing. Mention its planned system to "receive a report of a scam from any institution or individual".
6. **Upkeep and metrics.**
   - Re-check each brand page every quarter. ING, NAB, ATO and Origin addresses or pages have changed recently, and ING's alerts page mixes the real address with scam addresses.
   - For takedown-time metrics, record which channel was used and when. The NASC uses an unnamed third-party takedown provider, so takedowns cannot be attributed to the NASC versus the brand's own vendor.

## Open questions

1. Do the brand mailboxes act on CT-log findings where no message was received, and do any brands offer a direct line for security researchers?
2. Will auDA confirm whether low-volume, abuse-driven RDAP queries are allowed? Does it offer researcher access to new-registration or zone data, or take part in NetBeacon for .au?
3. Does CTIS accept phishing-domain indicators from small Network Partners? What format (STIX/TAXII?), volume and vetting apply?
4. What are the NASC's partner onboarding criteria, and will its new data-sharing system accept third-party researcher submissions?
5. Will the Scamwatch website form become permanent, and are there limits per submitter?
6. What do the SPF Rules 2026 require for actionable scam intelligence, and must regulated banks and telcos accept intelligence from third parties after 31 March 2027?
7. Which vendor runs the NASC takedown service, and how long do takedowns typically take?
8. What are the current official addresses for DHL Australia, PayPal Australia (.com.au), ubank and AGL? Their pages could not be fetched or confirmed.
9. Can ASD's ACSC takedown service be asked to act on reports from Network Partners?
