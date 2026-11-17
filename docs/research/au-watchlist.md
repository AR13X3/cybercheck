# Australian brand watchlist (verified, 2026-11-15)

This is a fact-check of the earlier "au-watchlist" research for CyberCheck, which looks for phishing domains that impersonate Australian brands. On 2026-11-15 I re-checked every medium- or low-confidence claim, every domain in the allowlist, and every claim the recommendation depends on.

The machine-readable list is `au-watchlist.yaml`, next to this file. It has 80 brands, 162 official domains, 39 uncertain domains, 108 bait words, 23 Australian-context tokens and 30 suspicious TLDs, and it passes PyYAML.

## Summary

**The ranking stands, with caveats.** Government impersonation is the largest category. The most-named services are myGov, the ATO, Centrelink, Medicare, Service NSW and Revenue NSW. Next come:
- toll roads (Linkt, E-Toll);
- loyalty points (Qantas Frequent Flyer);
- Amazon, which the researcher missed. It was the third-largest category in Trend Micro's AU/NZ 2026 data;
- Australia Post and StarTrack;
- the banks.

Banks are a small share of detections (Trend Micro's 5,896), but they are core targets of the Lighthouse/Smishing Triad kit. No primary source ranks individual banks, super funds, energy retailers or retailers.

**Allowlist checks.**
- The auDA registry (RDAP and port-43 WHOIS) still blocks this host. A test RDAP query returned 429 with `Retry-After: 83294` (about 23 hours), and WHOIS refused the connection. So I used two other sources of evidence, both from 2026-11-15:
  - the organisation name in each site's live TLS certificate. An OV/EV certificate's subject organisation is checked by the certificate authority;
  - registrar RDAP.
- I also re-read the earlier researcher's saved auDA results, rather than taking the summary on trust.
- With that evidence, I promoted 11 uncertain domains to official, added 6 newly confirmed domains and added 5 brands.
- I removed or downgraded entries that could not be confirmed: `qld.gov.au` is a public suffix, and `cbus.com.au` has no DNS.

**Evidence corrections.**
- The ATO "75% of email scams lead to a fake myGov sign-in" figure dates from March 2024, not 2025-2026.
- The Proofpoint article does not mention 2FA codes or session cookies.
- auDA's blog does not say that most .au abuse comes from compromised sites.
- The Australia Post scam page does not publish a list of genuine domains.
- The NAB PayID article is from 2023.

**Things the researcher missed.**
- Amazon impersonation.
- Direct `.au` defensive registrations held by the big brands, such as `commbank.au` and `nab.au`.
- The NASC finding that 77% of confirmed .au scam sites in 2025 came through just three registrars.
- The heavy use of URL shorteners and free-hosting subdomains (for example `telstra-au.1wp.site`), which CT-only monitoring will miss.
- Keyword collisions: `amazon` (for example amazonaws.com), `linkt` (linktree and others) and `toll` (Toll Group).

## Verified facts

### Which brands are impersonated (2025-2026)

- **Trend Micro TrendLife, AU and NZ combined, January to early August 2026:** 236,839 detections.
  - Government and essential services: 90,095 (38%).
  - Rewards programs: 56,241 (23.7%). Qantas Frequent Flyer and Air NZ Airpoints are about 98% of these.
  - Amazon: 30,608 (12.9%).
  - Toll providers (Linkt, E-Toll): 24,412.
  - Police and fines: 17,094.
  - Apple: 6,740.
  - Banks and financial institutions: 5,896.
  - Betting: 3,512.
  - Subscriptions: 2,045.
  - Delivery companies: 196.

  Detections peaked in March 2026 (58,641). No domains or TLDs are named. https://trendlife.com/en-au/blog/2026/09/08/from-mygov-to-frequent-flyer-points-the-scam-impersonations-dominating-2026
- **ID Support NSW, May to August 2025, share of reports by impersonated organisation:** myGov 39%, Service NSW 18%, ATO 14%, Revenue NSW 8%, Centrelink 6%. https://www.nsw.gov.au/departments-and-agencies/id-support-nsw/learn/data-breaches/data-breach-announcements/scams-update-aug-25
- **Mimecast, 17 Oct 2025.** Campaign MCTO3001 has impersonated Services Australia, Centrelink and myGov since 2023.
  - Fake myGov logins are hosted on replit.app subdomains (`myatoclaimc[.]replit[.]app`, `auclaimnow[.]replit[.]app`, `aunewclmmmm[.]replit[.]app`) and on portmap.io tunnels.
  - Lures include "detected sign-in", "Your eft refund is ready", "myGov: Pending Payment Alert", Superannuation, Medicare, JobSeeker and Family Tax Benefit.
  - https://www.mimecast.com/threat-intelligence-hub/australian-government-impersonation-campaign/
- **Scamwatch, 26 Jun 2026:** an ATO and myGov impersonation alert ahead of tax time 2026. https://www.scamwatch.gov.au/about-us/news-and-alerts/australian-taxation-office-ato-and-mygov-impersonation-scams
- **Proofpoint via IT Brief, 17 Aug 2026:** myGov-branded phishing leading to a fake login page that captures credentials. https://itbrief.com.au/story/proofpoint-warns-of-mygov-invoice-scams-in-australia
- **Linkt's "latest scams" page** lists, among others:
  - account on hold (Aug 2026);
  - SMS urgent payment (May 2026);
  - outstanding toll balance, with 12 hours to pay (Aug 2025);
  - suspended account (May 2025);
  - unpaid toll invoice (Jan 2025);
  - a toll relief rebate (2023);
  - a Collection House debt variant.

  https://www.linkt.com.au/help/security/latest-scams
- **MailGuard, 19 Feb 2026:** a Linkt email, "Your vehicle has an overdue Final Toll Invoice", sent from unrelated domains. https://www.mailguard.com.au/blog/linkt-overdue-final-toll-invoice-phishing-scam
- **Bitdefender via IT Brief, 30 Apr 2026:** a Linkt-spoofed SMS campaign with more than 2,200 **shortened URLs**, active from December 2025 to April 2026, with sender-ID spoofing. https://itbrief.com.au/story/sms-phishing-campaign-targets-australia-new-zealand
- **Unit 42, 23 Oct 2025:**
  - 194,345 FQDNs on 136,933 root domains. Tolls are the most impersonated category, with about 90,000 FQDNs.
  - Most root domains are hyphenated `[string1]-[string2].TLD`. The `com-` prefix was the most common until May 2025, and `gov-` grew after that.
  - Registrars: Dominet (HK) 68.06%, NameSilo 11.85%, Gname 7.94%.
  - Lifetimes: 29.19% were active for 2 days or less, about 71.3% for less than a week, and 82.6% for 2 weeks or less.
  - Australia is named among the countries whose toll and postal services are impersonated.
  - https://unit42.paloaltonetworks.com/global-smishing-campaign/
- **Australia Post's scam-alerts page** includes:
  - iMessage/RCS high-volume scam (first published 12 May 2025, updated 11 Sep 2026);
  - verify your postcode (18 Mar 2026);
  - "confirm delivery address", leading to a fake StarTrack site (27 Mar 2026);
  - confirm your details (22 May 2026);
  - attempted delivery (1 Jul 2026);
  - redelivery fee (10 Jul 2026);
  - fake Facebook group (23 Jul 2026);
  - fraudulent postage-label websites (11 Nov 2026).

  Reports go to scams@auspost.com.au. https://auspost.com.au/about-us/about-our-site/online-security-scams-fraud/scam-alerts
- **IDCARE:** "June 2025 is now the biggest month on IDCARE record for AusPost-related scams". The text asked for a 35-cent "processing fee". https://www.idcare.org/news/scam-alert-spike-in-australia-post-invalid-postcode-scams
- **MailGuard, 19 Jun 2026:** an Australia Post redelivery scam with a $10.60 fee, sent through a Google sharing-link redirect. https://www.mailguard.com.au/blog/australia-post-redelivery-scam-uses-fake-scheduling-and-payment-pages
- **MailGuard, 5 Aug 2026:** a fake Telstra "duplicate payment" refund, hosted at `telstra-au.1wp(dot)site`, a free-hosting subdomain in the brand-hyphen-au form. https://www.mailguard.com.au/blog/fake-telstra-duplicate-payment-refund-scam-targets-australians
- **CommBank's alerts page:**
  - rewards-points-expiry texts (Oct 2026);
  - fake NetBank logon pages (Sep 2026);
  - AUSTRAC impersonation (Sep 2026);
  - staff impersonation over Google Meet and Gmail (Oct 2026).

  The page names commbank.com.au and netbank.com.au, and hoax@cba.com.au for reports. https://www.commbank.com.au/support/security/latest-scams-and-security-alerts.html
- **Silent Push, 10 Apr 2025.** Australian institutions targeted by the Lighthouse kit:
  - Bendigo and Adelaide Bank, Bank of Sydney, Bank Australia, Bank of Queensland, ANZ, CBA, Cuscal, HSBC Australia, ING Australia, NAB, Newcastle Permanent, Police Bank, St.George ("George Bank"), Westpac and Macquarie;
  - the kits were "initially focused on Australian financial institutions";
  - the most popular TLDs were .top, .xin, .vip, .world, .cc, .com, .xyz, .icu, .cfd and .ink;
  - an Australia Post example is `auspoust[.]cc`.

  https://www.silentpush.com/?p=9978
- **NASC annual results (30 Mar 2026):**
  - $2.18bn lost in 2025, up 7.8%, from 481,523 reports.
  - Phishing was the most-reported type, with 65,361 reports and $97.6m lost.
  - Text-message scam reports fell from 77,365 (2024) to 29,058 (2025).
  - Online-based scams with a loss rose 31.8%.
  - More than 7,500 scam URLs were removed.

  https://www.nasc.gov.au/news/continued-action-critical-to-combat-fraud-as-annual-scam-losses-exceed-2-billion
- **NASC, 29 Apr 2025:** 16,700 phishing reports from 1 Jan to 23 Mar 2025, with $11.1m lost (up more than 200%). Over 75% of the losses were cryptocurrency phishing, using "account compromised" and "suspicious transactions" lures. CoinSpot and Swyftx are named as data-sharing partners, not as impersonated brands. https://www.nasc.gov.au/news/criminals-use-%E2%80%98account-compromise-scams-to-scare-australians-and-steal-their-money-or-cryptocurrency
- **NASC submission to auDA's licensing rules review (March 2026):**
  - In 2025 the NASC sent 86 takedown requests for confirmed .au scam sites.
  - 47% were at one registrar, and 77% at three registrars.
  - Named weaknesses: misused ABNs, re-registration of recently expired .au domains, trademark checks, and forged documents.

  https://files.auda.org.au/documents/NASC-submission.pdf
- **auDA blog (29 Jul 2025):** auDA analyses "over 25 daily threat feeds". .au abuse was about 0.0002% of names in Dec 2024. https://www.auda.org.au/news-insights/blog/tackling-scams-and-ransomware-audas-role-in-mitigating-dns-abuse/
- **ACMA SMS Sender ID Register:** from 1 Jul 2026, messages from unregistered sender IDs show "Unverified". The register opened on 30 Nov 2025; that date is from industry sources, as the ACMA page timed out for me. https://www.acma.gov.au/about-register and https://www.acma.gov.au/sites/default/files/2026-01/SMS%20Sender%20ID%20Register%20user%20guide%20for%20businesses%20and%20organisations_Dec%202025.pdf
- **nbn Co:** nbn impersonation is mainly phone-based. People aged 65+ accounted for 86% of nbn-impersonation losses in Jan-Jul 2024. https://www.nbnco.com.au/corporate-information/media-centre/media-statements/protect-yourself-from-scams

### Interisle / Cybercrime Information Center TLD data (global, 1 May 2025 to 30 Apr 2026)

https://www.cybercrimeinfocenter.org/phishing-activity-year-over-year-tlds-may-april-2026

- **By number of phishing domains:** com 869,180, top 375,514, cn 167,651, pro 130,945, info 99,602, xyz 93,987, vip 83,816, shop 79,625, cc 77,660, icu 74,786, cfd 70,944, sbs 63,518, net, online, jp, bond, live, click, org, xin 35,077.
- **By phishing score (phishing domains per 10,000 delegated):** xin 5,910, win 1,640.7, icu, garden, cfd, pro, help, mom, rest, mobi, qpon, live, ink, best, lat, cyou, top, wang, life, homes.

### Allowlist evidence

**auDA registry records (registrant and ABN).** These come from the earlier researcher's saved lookups, which I re-read; they are not new queries.
- commbank, commonwealthbank, commsec, bankwest, commbiz (CBA).
- westpac, westpacgroup, stgeorge, banksa, bankofmelbourne (Westpac ABN 33007457141).
- nab, ubank (NAB ABN 12004044937); 86400.com.au (86400 Holdings).
- ing, ingdirect; bendigobank, adelaidebank, up.com.au; boq; mebank; virginmoney (Virgin Enterprises).
- amp (AMP Services); hsbc.com.au.
- greatsouthernbank and cua; newcastlepermanent; beyondbank.
- heritage, peopleschoice, peoplefirstbank; tmbank.
- bankaust (registrant MECU Limited, ABN 21087651607, which is Bank Australia's ABN).
- servicesaustralia, humanservices, centrelink, medicare, mygov (.gov.au).
- service.nsw, revenue.nsw, transport.nsw, nsw; vicroads.vic, service.vic, fines.vic; tmr.qld, qld; asic, moneysmart (.gov.au).
- auspost and australiapost; startrack; aramex and fastway (same ACN 057389769); couriersplease.
- linkt and transurban; myetoll.com.au (Transport for NSW); eastlink (ConnectEast); telstra.com.au.
- Also, these do **not** belong to the brands: me.com.au (B M B Properties) and hpc.com.au (Publishing Australia).

The cache has **no** auDA record for anz.com.au, anzplus.com.au, suncorpbank.com.au, suncorp.com.au, macquarie.com.au, cba.com.au, netbank.com.au, my.gov.au or ato.gov.au: those queries got HTTP 429. I confirmed them with the TLS certificates below instead.

**TLS certificate subject organisation (OV/EV), fetched 2026-11-15.** The certificate authority validated each organisation.

| Domain(s) | Organisation in the certificate |
|---|---|
| anz.com.au (SAN includes anz.com) | Australia and New Zealand Banking Group Limited |
| anzplus.com.au (SAN includes anzplus.com) | Australia and New Zealand Banking Group Ltd |
| suncorpbank.com.au | NORFINA LIMITED |
| suncorp.com.au, aami.com.au | Suncorp Corporate Services |
| macquarie.com.au, macquarie.com, macquariebank.com.au | Macquarie Group Ltd |
| cba.com.au, netbank.com.au, commbiz.com.au, commbank.com.au | Commonwealth Bank of Australia |
| commsec.com.au | Commonwealth Securities Limited |
| nab.com, nab.com.au, nabgroup.com, nabtrade.com.au | National Australia Bank Limited |
| ubank.com.au (SAN includes 86400.com.au) | ubank (National Australia Bank Limited) |
| ing.com.au (SAN includes ingdirect.com.au) | ING Australia Holdings |
| ing.com | ING Groep N.V. |
| hsbc.com.au, hsbc.com | HSBC Group Management Services |
| westpac.com.au, stgeorge.com.au, banksa.com.au, bankofmelbourne.com.au | Westpac |
| bankwest.com.au | Bankwest |
| mebank.com.au | Members Equity |
| virginmoney.com.au | Virgin Money (Australia) |
| amp.com.au | AMP Limited |
| newcastlepermanent.com.au, greater.com.au | Newcastle Greater Mutual Group |
| heritage.com.au, peoplefirstbank.com.au | Heritage and People's Choice |
| bankaust.com.au | Bank Australia Limited |
| ato.gov.au | Australian Taxation Office |
| myid.gov.au (SAN includes mygovid.gov.au) | Australian Taxation Office |
| optus.com.au (www) | Singtel Optus |
| vodafone.com.au | TPG Telecom |
| telstra.com.au (SAN includes telstra.com) | Telstra Limited |
| www.bigpond.com | Telstra Limited |
| australiansuper.com, australiansuper.com.au | AustralianSuper Pty Ltd |
| australianretirementtrust.com.au, qsuper.com.au | Australian Retirement Trust |
| hostplus.com.au | Host-Plus |
| unisuper.com.au | UniSuper Management |
| aware.com.au | Aware Super |
| agl.com.au | AGL Energy |
| energyaustralia.com.au | EnergyAustralia |
| nppa.com.au (SANs include payid.com.au and payto.com.au) | Bpay Group Pty Ltd |
| woolworths.com.au, everyday.com.au, woolworthsrewards.com.au, woolworthsgroup.com.au | Woolworths Group |
| coles.com.au | Coles Supermarkets |
| bunnings.com.au | Bunnings Group |
| kmart.com.au | Kmart Australia |
| qantas.com, qantas.com.au | Qantas Airways |
| jetstar.com, jetstar.com.au | Jetstar Airways |
| virginaustralia.com, velocityfrequentflyer.com | Virgin Australia Airlines Holdings |
| nrma.com.au | Insurance Australia Group |
| racv.com.au | RACV |
| racq.com.au (SAN includes racq.com) | RACQ |
| medibank.com.au | Medibank Private |
| bupa.com.au | Bupa Health Services |
| bupa.com | British United Provident Association |
| linkt.com.au, transurban.com | Transurban Limited |
| eastlink.com.au | ConnectEast |
| aramex.com.au | Fastway Global Ltd (fastway.com.au is in the SAN of aramex's certificate) |
| auspost.com.au | Australia Post |
| nbn.com.au, nbnco.com.au | NBN Co Limited |

**Registrar RDAP registrant organisation.**
- New for this check: commbank.com and cba.com are both registered to Commonwealth Bank of Australia (CSC RDAP), and woolworthsrewards.com to Woolworths Group Limited.
- From the earlier saved results: banksa.com, bankofmelbourne.com, westpacgroup.com (Westpac); nabgroup.com; boq.com; bendigobank.com; macquariebank.com; ingaustralia.com; virginaustralia.com, velocityfrequentflyer.com; transurban.com; telstra.com, bigpond.com; optus.com, optusnet.com; tpgtelecom.com, iinet.net; independentreserve.com; auspost.com, australiapost.com; energyaustralia.com; bupa.com; nrma.com (NRMA Insurance Ltd); racv.com; zipmoney.com (Zipmoney Payments).
- Same source: amp.com belongs to TE Connectivity, upbank.com to Regions Financial, kmart.com to Transform SR Brands and art.com to Art.com, Inc. None of these is the Australian brand.
- Lookups: https://rdap.verisign.com/com/v1/domain/cba.com and https://rdap.cscglobal.com/dbs/rdap-api/v1/domain/CBA.COM.

**Brands' own pages.**
- **Linkt** lists transurban.com, transurban.com.au, linkt.com.au and these subdomains: tollnotice, manage, digital, pay, info and billing.linkt.com.au. https://linkt.com.au/help/security/is-it-really-from-us
- **NAB** lists nab.com.au, ib.nab.com.au, nabtrade.com.au and other nab.com.au hosts. It also uses "nab.com instead of nab.com.au" as a lookalike example, even though NAB holds nab.com (OV certificate). https://www.nab.com.au/about-us/security/online-safety-tips/identify-spam-phishing-messages
- **myID** says its genuine URLs are myID.gov.au and www.myID.gov.au, and that "We do not currently send any SMS messages from myID". https://www.myid.gov.au/security-and-privacy/how-to-verify-or-report-a-scam
- **CBA** acquired cba.com in April 2017. https://www.commbank.com.au/content/shared/newsroom/2018/06/email-domain-issue.html
- **StarTrack:** startrack.com.au links to startrackcourier.com.au, and that site redirects to auspost.com.au (fetched 2026-11-15).
- **Australian Payments Plus:** payid.com.au, osko.com.au, bpay.com.au and eftpos.com.au each redirect to auspayplus.com.au/solutions/... (fetched 2026-11-15).

**Brand TLDs.** The IANA root database lists these managers:
- .anz: ANZ;
- .auspost: Australian Postal Corporation;
- .cba, .commbank and .netbank: Commonwealth Bank of Australia;
- .nab and .ubank: National Australia Bank Limited.

https://www.iana.org/domains/root/db/ubank.html (and the same path for each TLD); TLD list version 2026111500 at https://data.iana.org/TLD/tlds-alpha-by-domain.txt.

**Public Suffix List.**
- qld.gov.au, sa.gov.au, tas.gov.au, vic.gov.au and wa.gov.au are public suffixes. nsw.gov.au, act.gov.au and nt.gov.au were removed at the request of those governments.
- The PSL also lists the state second-level domains nsw.au, vic.au and so on.
- https://publicsuffix.org/list/public_suffix_list.dat

**Suncorp Bank.** ANZ acquired Norfina Ltd (Suncorp Bank) on 31 Jul 2024. Customers move to ANZ products and platforms by June 2027, as announced on 7 Sep 2026. https://www.suncorpbank.com.au/about-us/newsroom/suncorp-bank-announces-customer-move-to-anz.html

**E-Toll.** NSW Motorways still treats E-Toll as a current provider, at myetoll.transport.nsw.gov.au. https://www.nsw.gov.au/departments-and-agencies/nsw-motorways/improving-and-reforming-tolling-system

## Corrections made

**Overstated or wrongly attributed evidence**
1. **ATO 75% figure.** The ATO's figure ("approximately 75% of all email scams reported ... over the past 6 months have linked to a fake myGov sign in page") is from an ATO media release of **March 2024**, as quoted in search results. The ATO site returns 403 to this host. It is no longer cited as 2025-2026 evidence.
2. **Proofpoint (IT Brief, 17 Aug 2026)** describes credential capture only. The claim about stealing "2FA codes and session cookies" was removed.
3. **auDA blog.** It does not say "almost all .au abuse is compromised small-business sites". That claim is now uncertain. What the NASC submission does support: misused ABNs, re-registered expired domains, and concentration at a few registrars.
4. **Australia Post page.** It does not publish a list of genuine domains (merchant-portal, msto.startrack, and so on). That claim was removed. startrackcourier.com.au stays official on other evidence: StarTrack's own site links to it, and it redirects to auspost.com.au.
5. **Australia Post alert of 27 Mar 2026.** It is titled "Australia Post 'confirm delivery address'" and leads to a fake StarTrack site. The researcher had called it a "StarTrack" alert.
6. **NAB "PayID will never send you an email".** The article is dated 27 Feb 2023 (updated 26 Jul 2023), so it is older background, not 2025-2026 evidence.
7. **myID "reconfirm details" lure.** That wording is not on the myID page. The page warns about "suspicious activity on your myID" emails and texts, and says myID sends no SMS.
8. **TrendLife figures cover AU and NZ combined**, not Australia only. The 98% rewards share is Qantas plus Air NZ.
9. **NASC 31.8%.** The figure is for "online-based scams with a loss", not "website- and social-media-based".

**Missing context**
10. **The bank ranking leaves out Amazon.** Amazon is TrendLife's third-largest category (30,608), so I added it as a brand. Delivery companies were only 196 detections in TrendLife's data. Australia Post's high priority rests on its own alert volume and the IDCARE record month, not on TrendLife.

**Allowlist changes**
11. **Removed from official.** `qld.gov.au` is a public suffix, so it can never be a registrable-domain match. The `.gov.au` suffix rule covers it.
12. **Removed from uncertain.** `cbus.com.au` has no NS or SOA record. It may not be registered, so giving it any score reduction is risky.
13. **Promoted from uncertain to official, with the evidence above.** mygovid.gov.au, nabtrade.com.au, macquariebank.com.au, australiansuper.com.au, qsuper.com.au, qantas.com.au, jetstar.com.au, woolworthsrewards.com.au, greater.com.au, payid.com.au and nppa.com.au.
14. **Newly confirmed and added.** anzplus.com, payto.com.au, woolworthsgroup.com.au, racq.com, amazon.com.au and amazon.com. The Amazon domains rest on primary-site evidence only.
15. **Added brands.** Amazon Australia, nbn (NBN Co), RACQ, CouriersPlease and AUSTRAC. Newcastle Permanent now also covers Greater Bank (keyword `greaterbank`). PayID now includes PayTo.
16. **Added to uncertain.** Direct .au names that resolve to brand-style nameservers: commbank.au (AWS), westpac.au, anz.au and qantas.au (Brandshelter), nab.au (ns*.national.com.au), telstra.au (bigpond NS), auspost.au and linkt.au (CSC DNS). Also myetoll.com, which is in the SAN of the E-Toll certificate but has only a DV certificate. None of these had registry confirmation.

**Matching rules**
17. **`amazon` is a short_token, not a keyword.** As a substring it would match amazonaws.com and every Amazon global domain.
18. **Added `duplicate` and `frequentflyer` to the bait words** (from the Telstra and loyalty lures).

## Uncertain / unverified

**Registry checks not possible**
- auDA registrant records for anz.com.au, anzplus.com.au, suncorp(bank).com.au, macquarie.com.au, cba.com.au, netbank.com.au, my.gov.au and ato.gov.au. They are covered by OV certificates or .gov.au, but have not been confirmed in the registry.
- About 60 more .au domains; auDA blocks this host for about 23 hours.

**Official, but weaker evidence.** These rest only on primary-site evidence: a DV certificate plus being the brand's live main site.
- tpg.com.au, tpgtelecom.com.au, iinet.net.au and aussiebroadband.com.au;
- rest.com.au, cbussuper.com.au and hesta.com.au;
- originenergy.com.au. Its certificate SAN also lists Origin properties such as vitalgas.com.au and origin-lpg.com.
- auspayplus.com.au, beem.com.au, afterpay.com and zip.co;
- flybuys.com.au, jbhifi.com.au and myer.com.au;
- coinspot.com.au and swyftx.com;
- mynrma.com.au and ahm.com.au;
- startrack.com.au (registry) and startrackcourier.com.au;
- amazon.com.au and amazon.com.

**Uncertain domains.** These redirect to the brand or share its nameservers or certificates, but ownership is unconfirmed.
- bpay.com.au, bpay.com, osko.com.au and osko.com. osko.com.au's DV certificate also covers osko.com and bpay.com.au hosts.
- eftpos.com.au and beemit.com.au;
- afterpay.com.au, zipmoney.com.au and zippay.com.au (same Cloudflare nameserver pair as the brand);
- swyftx.com.au, independentreserve.com.au, coinspot.com and myer.com;
- bunnings.com, colesgroup.com.au, woolworths.com and woolworthsgroup.com;
- art.com.au, which redirects to ART but sits on a different DNS provider;
- westpac.com, stgeorge.com, stgeorgebank.com and bankwest.com (privacy-proxied);
- qantasloyalty.com and qantasmoney.com;
- virginaustralia.com.au and velocityfrequentflyer.com.au;
- optusnet.com.au and bigpond.com.au;
- aussiebroadband.com and aramex.com (global Aramex, not Aramex Australia);
- the direct .au names in correction 16.

**Claims not re-verified** (pages timed out or returned 403)
- ACMA's 2024 list of the "5 most common SMS impersonation scams".
- AGL's recent-scams page.
- The 2026 ASIC alert about a cloned Rest Super site, seen only in search results.
- The MailGuard EnergyAustralia and Origin refund posts.
- The exact months of MailGuard's myGov and Medicare posts.
- The ASIC letter to super trustees (Jan 2025).

**Other**
- The literal tokens `gov-au` and `com-au` are still inferred from Unit 42's `gov-` and `com-` prefixes. The one verified Australian example of a brand-plus-au token is `telstra-au.1wp.site`.
- `suspicious_tlds` is mostly global data. Only the Silent Push list is tied to the Australia-focused kit.
- Aramex Australia's current parent company was not checked. The domains themselves are confirmed.

## Recommendation

**1. Allowlist matching**
- Match by registrable domain with a current Public Suffix List.
- Also allowlist by suffix any host under `.gov.au` and under the brand TLDs `.anz .auspost .cba .commbank .netbank .nab .ubank`.
- Keep subdomain entries such as `service.nsw.gov.au`. Under the PSL they collapse to `nsw.gov.au`.

**2. Uncertain domains**
- Use `uncertain_domains` only to lower a score or force human review.
- Before promoting one, check it with auDA RDAP (`https://rdap.cctld.au/rdap/domain/<name>`) at 10 queries an hour or fewer, cache the results, and back off on 429s. A `Retry-After` of about 23 hours was seen.
- As a no-registry fallback, accept an OV/EV certificate whose subject organisation matches the brand.

**3. Matching rules**
- Match `keywords` as substrings after normalising: lowercase, remove hyphens and digits, map homoglyphs, decode punycode.
- Match `short_tokens` only as whole tokens, and only when a bait word, an `au_context_tokens` entry or a suspicious TLD is also present.
- Keep an exclusion list:
  - `linktree`, `linktr`, `linkto` (the `linkt` keyword is noisy);
  - `amazonaws`, `eastlink.ca`, `medicare.gov`, `mygov.in`, `etoll.gov.pl`, `woolworths.co.nz`;
  - `kmart.com`, `upbank.com`, `amp.com`, `art.com`, `me.com.au`, `hpc.com.au`;
  - `toll.com.au` and `tollgroup.com.au`. Toll Group is a real courier, and "toll" is also a bait word.

**4. Crawl and vision priority**
1. myGov, ATO, Centrelink, Medicare and myID.
2. Linkt and E-Toll.
3. Qantas Frequent Flyer.
4. Australia Post and StarTrack.
5. Amazon AU.
6. Service NSW, Revenue NSW and other fines bodies.
7. The big four banks and their sub-brands, which matter for the Lighthouse kit.

**5. High-risk domain pattern**
- New hyphenated `com-` and `gov-` prefixed domains on .top, .xin, .vip, .cc, .icu or .cfd, registered through Dominet, NameSilo or Gname, are high-risk.
- 71% are gone within a week, so speed of detection matters more than takedown time for these.

**6. Blind spots**
- CT and zone files will miss:
  - shortened URLs (the Linkt campaign used more than 2,200);
  - free-hosting and wildcard-certificate platforms such as replit.app, portmap.io and 1wp.site;
  - compromised .au sites;
  - re-registered expired .au domains (NASC).
- Add URL feeds to cover these. For takedown statistics, note that 77% of the NASC's 2025 .au takedown requests went to three registrars.

**7. Refresh**
- Refresh the list quarterly. Upcoming changes: Suncorp Bank moves into ANZ by June 2027, and Heritage and People's Choice now trade as People First Bank.

## Open questions

- **Re-run auDA RDAP slowly** for the domains above, once the block lifts. This would confirm the registrants for the primary-site-only entries and the uncertain .au entries.
- **Direct .au names.**
  - Who holds commbank.au, westpac.au, nab.au, anz.au, auspost.au, telstra.au, linkt.au and qantas.au? They have DNS but no registry check.
  - Why do mygov.au, ato.au, centrelink.au, medicare.au, optus.au, woolworths.au, coles.au and servicensw.au not resolve? They may be reserved, unregistered or parked without DNS. If any is unregistered, it is a takeover risk worth watching.
- **NASC Targeting Scams Report 2025** (https://www.nasc.gov.au/system/files/targeting-scams-report-2025.pdf). The PDF downloaded, but its text could not be extracted here because the fonts are encoded. It may break impersonation down by organisation.
- **The ATO's current numbers.** The ATO site returns 403 to this host, so its 2026 scam statistics could not be read.
- **Per-brand volumes.** No primary source gives volumes for individual banks, super funds, energy retailers or retailers, so priorities 2 and 3 in those categories are judgement calls.
- **Australia-specific TLD data.** None was found beyond Silent Push's kit list and single examples (`auspoust[.]cc`).
- **Netcraft and Okta.** I found no recent Australia-specific per-brand reporting from them. This was not searched exhaustively.
