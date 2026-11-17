# ICANN CZDS for new-domain detection (verified, 2026-11-15)

Fact-check of the earlier "czds" research for CyberCheck, which looks for phishing domains that impersonate Australian brands. I re-checked every endpoint, number and policy claim against primary sources on 2026-11-15. Anything I could not confirm is listed under "Uncertain / unverified" and is not stated as fact.

## Summary

- CZDS is still the free, official way to get daily gTLD zone files. It covers gTLDs only: **.au, .cc and every other ccTLD are not in it**. ICANN's public CZDS user report for Oct 2026 lists 1,122 TLDs. It includes every TLD CyberCheck wants (.com, .net, .org, .info, .top, .xyz, .shop, .online, .site, .icu, .cfd, .sbs, .bond, .click, .xin, .vip, .cyou, .live, .life, .win, .help, .lat, .pro, .mobi, .sydney, .melbourne), and it has no .au or .cc. The researcher's open question about .info is therefore settled: .info is available.
- The API is unchanged from spec v1.0.9 (2022-05-24):
  - Log in with `POST https://account-api.icann.org/api/authenticate`. This returns a JWT `accessToken` that is valid for 24 hours. The login limit is 8 attempts per 5 minutes per IP address.
  - List your zones with `GET https://czds-api.icann.org/czds/downloads/links`.
  - Download each zone with `GET` or `HEAD` on the returned `https://czds-download-api.icann.org/czds/downloads/<tld>.zone`, using a Bearer token and a real User-Agent.
  - Without credentials, all three hosts answered on 2026-11-15 (401/401/500).
- **Both the current CZDS Terms & Conditions and the CZDS Terms of Use can be read without a login**, through the CZDS API itself. The researcher had said both needed a login. The live T&C is version "1.00" (created 2018-10-22). It matches the 2013 template, except that s1.8 now reads "SFTP or HTTP no more than once per 24-hour period".
- Things the researcher missed:
  - Some TLDs in CZDS are flagged **SFTP-only**: you register your IP addresses and download from the registry's SFTP host, not the HTTP API.
  - Some registries add their own credential checks by email on top of CZDS.
  - The API hostnames now publish IPv6 (AAAA) records, even though the spec still says "IPv4 only".
  - .live, .life and .mobi, like .top, use NSEC3 **without** opt-out, so their files are larger per domain than the researcher's estimate assumed.
- Corrections:
  - The January 2026 .top revocation was not "restored on 2026-01-09". On 9 Jan ICANN said it would restore requests "over the next few days", and one user reported access back at 01:47 on 8 Jan.
  - The spec documents a GET content type of `text/dns`, not `application/x-gzip`.
  - Small count corrections for .vip and .xin.
- The verdict on the blocklist stands, but it is an interpretation and not legal advice. A curated list of domains CyberCheck itself confirmed as malicious fits the s1.6 "value-added product" exception, if no raw zone data is published and the blocklist's licence forbids the s1.1 uses.

## Verified facts

### API (spec v1.0.9, 2022-05-24, still the latest published)

Source for everything in this section unless noted: ICANN CZDS REST API spec PDF, https://github.com/icann/czds-api-client-java/blob/master/docs/ICANN_CZDS_api.pdf. The CZDS help page links to https://github.com/icann/czds-api-client-* for the spec (https://czds.icann.org/help).

**Revision history.** The last change was v1.0.9 on 2022/05/24: "Replaced the <base-url> references with <download-url> from links and zone download methods". Earlier changes: v1.0.4 (2018/12/04) set the "access_token lifetime to 24 hours"; v1.0.6 (2019/01/30) added the rate limit on `/api/authenticate`; v1.0.8 (2019/03/04) documented `Last-Modified` on HEAD.

**Authentication**
- Request: `POST https://account-api.icann.org/api/authenticate` with body `{"username": "...", "password": "..."}`.
- Headers: `Content-Type: application/json`, `Accept: application/json`, and `User-Agent: <product>/<product-version> <comment>`. The spec warns: "You must provide a valid User-Agent string. Otherwise, you might be redirected to an ICANN maintenance page."
- Success: HTTP 200 with a JSON body `{"accessToken": "<JWT>"}`. "Every successful authentication API call will generate a brand new token."
- Errors: 400 malformed request; 401 invalid credentials ("There is no text response in the body"); 415 unsupported content type (JSON error body); 500 server error.
- Rate limit: 429 "too many authentication attempts from the same IP address... It allows 8 authentication attempts in 5 minutes... denied for the remainder of the 5-minute cycle."
- Token life: the token "is invalid after its expiration time, which is 24 hours after the token is created". The exact expiry is in the JWT `exp` claim.
- The API cannot manage credentials. Password resets go through the portal.
- Spec: "The CZDS REST API supports IPv4 transport only" and only HTTPS.
- ICANN's own Python client posts to `<authentication.base.url>/api/authenticate` with the same JSON body and reads `accessToken` (https://raw.githubusercontent.com/icann/czds-api-client-python/master/do_authentication.py). Its last commit was on 2025-03-23 (GitHub API, https://api.github.com/repos/icann/czds-api-client-python/commits).

**Authorization.** Send `Authorization: Bearer <accessToken>`. A missing or invalid token gets HTTP 401 with an empty body.

**Listing your zones.** `GET https://czds-api.icann.org/czds/downloads/links` with Bearer and User-Agent headers. HTTP 200 returns a JSON array of download URLs, for example `"https://czds-download-api.icann.org/czds/downloads/example1.zone"`. Since v1.0.9, use the URLs exactly as returned rather than building them yourself.

**Downloading a zone**
- Request: `GET <download_url>/<tld>.zone` with Bearer and User-Agent headers. "The downloaded file is in gzip format."
- The spec says a 200 response "sets the HTTP header Content-type to 'text/dns'".
- Errors: 400 malformed; 403 "the requested zone does not exist or the username... has no permissions"; 409 the user "has not accepted the new Terms & Condition" and must log in to the portal to accept them.
- The spec says nothing about 404. ICANN's Python client treats it separately (https://raw.githubusercontent.com/icann/czds-api-client-python/master/download.py).

**Checking a zone without downloading.** `HEAD` on the same URL returns `Content-Length` (in bytes), `Content-Disposition` (the filename) and `Last-Modified`. The example response shows `Content-Type: application/x-gzip` and `Content-Disposition: attachment;filename=example1.txt.gz`.

**Live check (2026-11-15, my own unauthenticated requests)**
- `GET .../czds/downloads/links` returned HTTP 401 from Apache.
- `GET .../czds/downloads/com.zone` returned HTTP 401.
- `POST .../api/authenticate` with an empty JSON body returned HTTP 500.
- `czds-api.icann.org` resolves to 192.0.32.45 over IPv4.
- All three hosts also publish AAAA records (for example, czds-download-api resolves to 2620:0:2d0:200::b:20). The test host has no IPv6 route, so I could not test whether IPv6 actually works.

### Download schedule and frequency
- The CZDS help page says: "ICANN begins the daily collection of zone files from the registry operators at 00:00 UTC, and the process takes no more than 6 hours. This means that all updated zone files are available for download from CZDS after 06:00 UTC." Also: "an end user of CZDS should only download each TLD zone file a maximum of once per 24-hour period", and "You are permitted to download each zone file just once every 24 hours, as stated in the registry Terms and Conditions." (https://czds.icann.org/help; the text is in the help bundle https://czds.icann.org/227.4de04b8fcac80a46.js.)
- Current CZDS T&C s1.8: "access the Data through CZDS using SFTP or HTTP no more than once per 24-hour period" (https://czds-api.icann.org/czds/terms/condition).
- Base Registry Agreement 2024, Spec 4:
  - s2.1.3: copy zone files "no more than once per 24 hour period".
  - s2.3: zone files given to ICANN "will include SRS data committed as close as possible to 00:00:00 UTC".
  - Source: https://itp.cdn.icann.org/en/files/registry-agreements/base-registry-agreement-21-01-2024-en.html

### File format
- Base RA 2024 Spec 4 s2.1.4 (URL above): a subformat of the RFC 1035 master-file format "including all the records present in the actual zone used in the public DNS". Each record sits on one line as `<domain-name> <TTL> <class> <type> <RDATA>`. Class and type are lowercase mnemonics, the TTL is always present, and domain names are lowercase and fully qualified. Fields are separated by exactly one tab. There are no $ORIGIN, $INCLUDE or $TTL directives, no "@", no comments and no blank lines. "The SOA record should be present at the top and (duplicated at) the end." "With the exception of the SOA record, all the records in a file must be in alphabetical order."
- Signed zones therefore also contain DS, RRSIG and NSEC/NSEC3 records. In 2022 a user proposed CZDS files without the RRSIG/NSEC/NSEC3 records. ICANN only replied that it "will take note of these suggestions... in the future" (https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/C4AJLTHNKHACK4LZAEIX4662MZBOPC2S/). I found no sign this was ever built.
- Verisign: its zone files "do not contain domain names in the following states: serverHold, clientHold, pendingDelete, and redemptionPeriod". They also leave out names with no name servers. Requests for .com, .net, .name and other Verisign gTLDs go through CZDS. Source: https://www.verisign.com/resources/zone-file/ (redirect target of https://verisign.com/zone).

### Access process
- You need an ICANN Account and a CZDS profile with "organization name, contact name, address, telephone number, facsimile number, email address and IP address". The help page adds: "All information must be verifiable by the registry operator, and failure to provide all required details may result in your zone file request being denied." You also accept the CZDS Terms of Use. (https://czds.icann.org/help) Spec 4 s2.1.2 lists the same credentials, IP address included.
- For each TLD you give a reason and accept that registry's T&C. The help page says: "If the TLD requires you to download the zone files via SFTP, you will be prompted to enter your IP address on the next screen." (https://czds.icann.org/227.4de04b8fcac80a46.js)
- After you submit, the portal says: "Please allow one week for Registries to respond to your request". It also says: "Registry Operators are not required to process your request for zone file access within a certain time period, even if you previously had zone file access." (https://czds.icann.org/950.f2eb12fde2b3d26d.js)
- ICANN Compliance says the contract "does not define a time period by which registry operators must process zone file access requests". Complaints go through https://forms.icann.org/en/resources/compliance/registries/zfa/form (https://www.icann.org/en/resources/compliance/registries/zfa).
- Requests can sit for a long time. On the gtld-tech list, 9 to 11 Aug 2026, users reported pending requests for .web (since 2026-07-24), xn--czr694b (since 2026-01-11), xn--g2xx48c (since 2026-03-28), and ".VOTING pending for over a year". The advice given was to file Zone File Access complaints (https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/DIUJL6YQ2J5ZUMZV7C4IHOZCUJEV2E4D/).
- Some registries add their own vetting. In January 2026 the operator of xn--6qq986b3xl asked an existing user to email "Credentialing Requirements" within 7 days and said it would decide "via the CZDS in 45 days" (https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/EBXTBEQR7GPSILQGMCJD3FAGEXRKPHWC/).
- "Download All Requests" in the portal exports a CSV of all TLDs with your request status (https://czds.icann.org/950.f2eb12fde2b3d26d.js).
- **A public monthly report lists every CZDS TLD and its number of active users**, no login needed. The index is https://dc2og7iuc7hkj.cloudfront.net/structure.json; the latest is https://dc2og7iuc7hkj.cloudfront.net/2026/czds-users-2026-10.csv, with 1,122 TLDs. Active users in October 2026, by TLD:

  | TLD | Users | TLD | Users | TLD | Users |
  |---|---|---|---|---|---|
  | com | 11,140 | net | 9,278 | org | 9,481 |
  | info | 7,950 | top | 5,934 | xyz | 8,397 |
  | shop | 8,284 | online | 8,851 | site | 8,710 |
  | icu | 6,254 | cfd | 8,249 | sbs | 6,961 |
  | bond | 6,824 | click | 7,558 | xin | 7,519 |
  | vip | 5,645 | cyou | 8,188 | live | 8,449 |
  | life | 8,331 | win | 6,331 | help | 7,465 |
  | lat | 5,817 | pro | 8,400 | mobi | 8,159 |
  | sydney | 5,319 | melbourne | 5,098 | | |

  The help page describes this as a report of "the number of active CZDS users per TLD", published at the end of each month. The thousands of users per TLD suggest these registries do approve requests routinely.

### Term, renewal and revocation
- Spec 4 s2.1.6: access lasts "not less than three (3) months", and users must be allowed to renew. Spec 4 s2.1.7: access is free (base RA URL above).
- ICANN notice: "Starting 15 November 2022, approved zone file access requests will be automatically renewed by the system at the time of expiration... without any action required by the registry operator or the requestor." Registries can turn auto-renew off for a whole TLD or for single requests, which "will force approved requesters to resubmit their access requests manually at the end of each approved term" (https://itp.cdn.icann.org/en/files/contracted-parties-communications/czds-system-updates-automatic-renewal-zone-access-15nov22-en.pdf).
- Extensions: an "Approved" request within 30 days of expiry can ask for an extension. "If the registry operator does not approve the access extension request before the original expiration date, the access will expire normally." (https://czds.icann.org/help; extension feature announced 28 Jun 2022, https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/DTLIINOVB6N3ZTPIM5FE3TSOTJSPIDSK/)
- Revocation incident:
  - On 2026-01-07 users received "Request revoked as TLD has been made inactive" for .TOP.
  - ICANN (08 Jan): "an issue that temporarily marked the .TOP gTLD as inactive in the Centralized Zone Data Service (CZDS) system and caused approved CZDS access requests for the .TOP zone file to be revoked."
  - One user reported "The ZFA to .TOP was re-enabled at 01:47".
  - ICANN (09 Jan): "We are actively working to restore the impacted CZDS access requests for the .TOP zone file over the next few days", and users "may also submit a new request".
  - Source: https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/EBXTBEQR7GPSILQGMCJD3FAGEXRKPHWC/

### Terms (current live text)
- **CZDS T&C, version 1.00** (registry to user), at https://czds-api.icann.org/czds/terms/condition. It is also served for `?tld=top`, but I could not confirm whether registries can swap in their own text.
  - s1: "any legal purpose not otherwise prohibited by the Terms".
  - s1.1: lawful purposes only. Never use the Data to "(1) allow, enable, or otherwise support any marketing activities" or "(2) enable high volume, automated, electronic processes that send queries or data to the systems of registry operator or any ICANN-accredited registrar, except as reasonably necessary to register domain names or modify existing registrations".
  - s1.2: do not harass registrants or disrupt their business.
  - s1.3: no marketing purposes of any kind.
  - s1.4: copy the Data only as needed for permitted use.
  - s1.6: "not distribute the Data... to any other party without the express prior written consent of Registry Operator, except that you may redistribute the Data insofar as it has been incorporated by you into a value-added product or service that does not permit the extraction of a substantial portion of the Data from the value-added product or service, provided you prohibit the recipient of the Data from using the Data in a manner contrary to Section 1.1."
  - s1.7: take reasonable security steps.
  - s1.8: at most one access per 24 hours, by SFTP or HTTP.
  - s3: copies must keep the notices found in the Data.
  - s4: the registry may suspend access in emergencies.
  - s6: California law, Los Angeles County venue.
  - s7: "Registry Operator may terminate these Terms at any time and without notice... for any reason".
- **CZDS Terms of Use, version 1.00** (ICANN to user), at https://czds-api.icann.org/czds/terms/use.
  - s2.2: keep your credentials confidential, and "promptly notify ICANN of any CZDS security breach in writing".
  - s2.3(b): you must not "re-distribute or sublicense access to CZDS... to any third party".
  - s5: ICANN may terminate after a breach that is not fixed within 14 days, or immediately for a breach of s2.3.
  - s7.1: ICANN may change these terms, and continuing to use CZDS counts as accepting the change.
- Spec 4 s2.1.5 (base RA 2024) has the same core limits. Registries may refuse or revoke access for suspected s2.1.5 violations (s2.1.1).
- The 2013 template is still linked from ICANN's CZDS registry page (http://newgtlds.icann.org/en/program-status/czds/terms-conditions-30sep13-en.pdf, linked from https://www.icann.org/en/contracted-parties/registry-operators/services/centralized-zone-data-service).
- The CZDS help page names combating phishing as a purpose: organisations "apply the bulk zone data to combat phishing, spam, brand and trademark infringements" (https://czds.icann.org/help).

### Measured sizes and DNSSEC
- .com: 4,201,149,204 bytes, from the expected-length figure in a truncated-download error in Aug 2024. .org: 425,177,338 bytes, same thread. Source: https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/2YG52UHHNAQCULTWK4UPV5MFWB4KHACY/
- .top: 895,301,507 bytes on 2025-07-07 (https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/message/B6BUCMQIYPNQYRZVNG2TFIWLS5JODL7S/).
- .gov: 482,798 bytes (47,411 lines) on 2026-07-16 (https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/ZVWLQFTYSGDKK3MUZFYSIQ6X7R5PSIL5/).
- Registered-domain totals from ICANN monthly registry reports (`Totals` row, `total-domains` column):
  - com: 160,910,678 (2024-08) and 171,294,594 (2026-07)
  - org: 11,480,875 (2024-08) and 12,672,940 (2026-07)
  - top: 5,187,040 (2025-07) and 7,320,275 (2026-07)
  - net: 12,791,752; xyz: 9,635,766; info: 5,604,654; shop: 4,880,796; online: 4,025,772; site: 2,148,440
  - vip: 2,018,155; sbs: 1,342,545; bond: 1,201,416; click: 911,809; icu: 690,610; live: 681,877; cfd: 661,154
  - life: 477,186; mobi: 398,748; xin: 77,167; sydney: 6,038; melbourne: 5,158
  - The 2026 figures are all for 2026-07.
  - URL pattern: https://www.icann.org/sites/default/files/mrr/<tld>/<tld>-transactions-YYYYMM-en.csv
- Ratios from these figures: .com 26.1 bytes per domain, .org 37.0, .top 172.6.
- DNSSEC check on 2026-11-15, reading the NSEC3 flags field in NXDOMAIN proofs from 1.1.1.1:
  - **No opt-out (flags 0): .top, .live, .life, .mobi.**
  - Opt-out (flags 1): com, net, org, info, xyz, shop, online, site, icu, cfd, sbs, bond, click, xin, vip, cyou, win, help, lat, pro, sydney, melbourne.
  - With no opt-out, every delegation carries its own NSEC3 and RRSIG records. That explains why .top's file is so large.

### Operational faults seen in practice (gtld-tech list)
- **Aug 2024 (.com/.org):**
  - Truncated transfers: `ResponseBodyTooShort 4201149204 124156800`.
  - The same .com file was served on consecutive days, with SOA serial 1723766420 (Aug 16).
  - HEAD requests failed often.
  - ICANN blamed "extremely high traffic to CZDS API on August 17th and August 18th".
  - Source: thread 2YG52 (URL above).
- **Jul 2025 (.top):** the file was empty (20 bytes). One long-time user's code "skips" a zone if the file does not start and end with identical SOA records. Sources: https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/ZTJ7TC4TYOMYJVKCYWQGBECE52TAV6DU/ and the B6BUC message above.
- **Jul 2026 (.gov):**
  - A 39-byte gov.txt.gz contained only `; Transfer failed.`.
  - After ICANN fixed it, the user still received the 39-byte file once from the browser, then the correct file on an immediate retry.
  - ICANN said the file "is available across all CZDS mirrors".
  - Source: thread ZVWLQ (URL above).
- **Mar-Apr 2026 (.online/.site):** "a gap from around March 17 to April 12 during which no domains were added", then "three days with levels of additions 2-5x" normal. A registrar replied: "They moved registry backend providers Centralnic -> Tucows". Source: https://lists.icann.org/hyperkitty/list/gtld-tech@icann.org/thread/NSNDWSAKTJFJXXY65A62GXPE3MRHXZTV/

### ccTLDs and .au
- ICANN: "This contractual obligation does not apply to any ccTLD (such as .us, .de, or .uk)" (https://www.icann.org/en/resources/compliance/registries/zfa). Neither .au nor .cc is in the Oct 2026 CZDS user report.
- auDA's registry search request returns ".au domain names connected to the organisation's details, such as company name, Australian trade mark, ACN, or ABN". Only the organisation itself or its authorised representative may ask. The page does not mention bulk zone files or newly-registered-domain lists (https://www.auda.org.au/au-domain-names/au-tools/registry-search-request).

### Phishing data (for choosing TLDs)
- Interisle / Cybercrime Information Center, May 2025 to Apr 2026: malicious phishing domains per TLD, with the score (per 10,000 domains) in brackets.
  - com 577,821 (35.68); top 297,486 (472.24); pro 110,609 (1,013.72); vip 79,694 (476.34); xyz 79,436 (99.93); cc 72,266 (297.23); info 71,488 (136.15); icu 71,070 (1,527.14); cfd 67,461 (1,319.29); sbs 59,737 (435.88)
  - shop 48,459 (122.91); bond 41,184 (359.24); net 39,123 (32.05); online 38,185 (115.06); live 37,525 (668.56); xin 33,541 (5,651.20); click 32,150 (444.32); cyou 28,685 (634.24); org 23,074 (19.52); site 23,026 (132.89)
  - win 18,414 (1,621.99); help 17,382 (983.14); life 19,837 (477.74); lat 8,628 (627.50); mobi 30,234 (764.47); au 197 (0.46)
  - Sources: https://www.cybercrimeinfocenter.org/s/Phishing-TLDstats-May2025-Apr2026.csv; report page https://www.cybercrimeinfocenter.org/phishing-landscape-2026
- Unit 42, 23 Oct 2025, on the Smishing Triad:
  - "39,964 (29.19%) domains were active for two days or less".
  - Registrars of 136,933 root domains: Dominet (HK) 68.06%, NameSilo 11.85%, Gname 7.94%.
  - Australia appears among the countries whose electronic toll and postal or delivery services are impersonated. Australian banks and government agencies are not mentioned.
  - Source: https://unit42.paloaltonetworks.com/global-smishing-campaign/

### Alternatives
- **WhoisDS free list.**
  - Each of the files for 2026-11-12 to 2026-11-15 shows exactly 70,000 domains, "[Only Domains, No Whois Data]".
  - The page says the lists "may be reused, including for commercial purposes, without a license and without any payment" "except where otherwise stated".
  - Link format: `https://www.whoisds.com/whois-database/newly-registered-domains/<base64("YYYY-MM-DD.zip")>/nrd`. Example: `MjAyNi0xMS0xNS56aXA=` is `2026-11-15.zip`.
  - Paid domains-only list: $60/month or $650/year.
  - Source: https://www.whoisds.com/newly-registered-domains
  - The Terms of Use say "NO REDISTRIBUTION: You may NOT redistribute our data to other parties" (https://www.whoisds.com/terms-of-use).
- **Domains-Monitor.**
  - Terms (last updated 10 Aug 2026): use "for any lawful purpose, including commercial use", "including creating derivative works or value-added products". Not allowed: "make the data publicly available", distribution "as a standalone dataset", competing products, "resell, sublicense, or otherwise redistribute the data in its original form", and scraping outside the API (https://domains-monitor.com/terms/).
  - Plans: Standard $9, Pro $29, Ultimate $79 per month (https://domains-monitor.com/price/).
  - It claims 1,570 zones. Its .au list had 2,483,927 domains on 15.11.2026 (https://domains-monitor.com/domainzones/). Interisle counts about 4.24M .au domains under management, so that list looks partial. Domains-Monitor does not say where its .au data comes from.
  - Free lists: 100 random domains per zone (https://domains-monitor.com/freelists/).

## Corrections made

1. **The Terms can be read without a login.** The current CZDS T&C (v1.00) and Terms of Use (v1.00) are public at https://czds-api.icann.org/czds/terms/condition and https://czds-api.icann.org/czds/terms/use. s1.8 now says "SFTP or HTTP". The Terms of Use add s2.3(b), which bans re-distributing or sublicensing *access* to CZDS. So no shared accounts.
2. **.info and the other target TLDs are confirmed in CZDS** by the public Oct 2026 user report. The researcher had only "medium confidence via a 2017 RSEP".
3. **The .top revocation (Jan 2026) was not "restored by ICANN on 2026-01-09".** On 2026-01-09 ICANN said it was working to restore requests "over the next few days" and invited new requests. One user saw access back at 01:47 on 8 Jan. The researcher also attached the 2022 access-extension thread (DTLIINOV...) as a source for this incident. That thread is about extension requests only.
4. **Content type.** The spec documents `Content-type: text/dns` for a 200 GET. `application/x-gzip` appears only in the HEAD example. Do not validate on Content-Type; check the gzip magic bytes and Content-Length instead.
5. **IPv4-only.** The spec still says so, but all three API hostnames now publish AAAA records. Force IPv4 (for example `curl -4`) to stay within the documented behaviour.
6. **No opt-out is not limited to .top.** .live, .life and .mobi also use NSEC3 without opt-out, so the "26-37 bytes per domain" estimate does not apply to them. My rough estimate at .top's ratio: 70-120 MB each.
7. **Counts.** .vip has about 2.02M domains (ICANN, Jul 2026), not "about 1.7M". 1.67M is Interisle's figure for the measurement year. .xin has 77,167 (Jul 2026), not "about 59k". 59,352 is Interisle's figure.
8. **The .online/.site "CentralNic to Tucows" explanation** comes from a registrar's reply on the list (Blacknight), not from the registry. It is still unofficial.
9. **WhoisDS URL** has a single slash: `https://www.whoisds.com/whois-database/...`, not `//whois-database`.
10. **The "CZDS mirrors" wording (.gov, Jul 2026)** came from ICANN ("available across all CZDS mirrors"). The user only guessed at caching ("Might have been a caching issue?"). Treat the cause as unconfirmed. The practical lesson stands: retry when the file is tiny.

## Uncertain / unverified

- **SFTP-only TLDs.** The portal has a per-TLD `sftp` flag: you enter your IP addresses, and the portal shows a host, username and password instead of an HTTP download button. I could not find which TLDs use it, or whether those zones appear in `/czds/downloads/links`. Use the portal's CSV export or the request details to check.
- **Does HEAD count toward the once-per-24h limit?** Not documented. Long-time users run HEAD before every GET (thread 2YG52). Use at most one HEAD and one GET per zone per day.
- **Per-registry T&C.** The API serves the same v1.00 text for `?tld=top`. Some registries publish their own CZDS policies (for example dotApple, https://www.apple.com/legal/internet-services/docs/dotApple_CZDS_Policy.pdf, which I did not read) or add email credentialing. Read the T&C shown for each request.
- **The blocklist verdict** is an interpretation of s1.6, not legal advice or a ruling.
- **Estimated sizes** for TLDs other than .com, .org, .top and .gov are calculated from domain counts, not measured. Registered counts include names that are not in the zone, so real files may be smaller.
- **IPv6.** The AAAA records exist, but I did not test whether IPv6 transport works or is supported.
- **Domains-Monitor** said 310,911 domains were registered "that day". Not re-checked, and not important.
- **WhoisDS's own monthly counts** (0.66-1.04M per day in Oct 2026) were not re-checked. The 70,000-per-day cap is inferred from four identical daily counts.
- **2026 next-round Registry Agreement drafts.** I did not check whether they change Spec 4 for existing TLDs.
- A third-party blog (dn.org) describes a "CZDS 2.0". I found no ICANN source for it, so I ignored it.

## Recommendation

1. **Register now.**
   - Create the ICANN Account and CZDS profile with accurate, checkable details: organisation, address, phone, email, and the IP address you will download from.
   - Download from the CyberCheck host's normal public IPv4 address, not the sandbox VPN, so your traffic matches the profile.
   - Use one reason for every request, for example: "Anti-phishing research: detecting newly delegated domains that impersonate Australian banks, government services, postal, toll and telco brands; data used only for internal security analysis and low-volume abuse reporting; no marketing; at most one download per 24h; raw zone data never redistributed."
   - Save the T&C text from each approval.
   - If a request is still pending after about 30 days, file a Zone File Access complaint at https://forms.icann.org/en/resources/compliance/registries/zfa/form.
   - Do not share the account with anyone (Terms of Use s2.3(b)).
2. **Which TLDs to request** (same as the researcher's list; all confirmed in CZDS):
   - Phase 1, small and heavily abused: icu, cfd, sbs, bond, click, xin, vip, cyou, live, life, win, help, lat, pro, mobi, and top. Top costs about 1.2-1.3 GB a day but is the main TLD for toll and parcel smishing.
   - Phase 2: xyz, info, shop, online, site, sydney, melbourne.
   - Phase 3, once the pipeline is stable: com, net, org. That adds about 5.3 GB a day.
   - .au and .cc are not possible through CZDS. Use CertStream for them.
3. **Daily job at about 06:30 UTC** (16:30 AEST / 17:30 AEDT):
   - Log in once with a real User-Agent and IPv4, and cache the token for under 24 hours. Stay well under 8 logins per 5 minutes.
   - GET `links` and compare it with yesterday's list. Alert on any TLD that disappears; it could be a revocation like .top in Jan 2026.
   - For each zone, make one HEAD. Skip the zone if `Last-Modified` and `Content-Length` are unchanged. Otherwise make one GET, streamed to disk.
   - Check the file before using it:
     - byte count equals Content-Length
     - `gzip -t` passes
     - the first and last records are identical SOA records
     - the SOA serial is newer than yesterday's
     - the domain count is within about 20% of yesterday's
     - the file is larger than a tiny minimum size (20-byte and 39-byte failures have happened)
   - If any check fails, keep yesterday's list and retry later, without going over one download per 24 hours.
4. **Low-RAM diff.** The recipe is in czds.yaml and is unchanged from the researcher's version except for one stronger validation:
   - `zcat | awk -F'\t' 'tolower($4)=="ns"{print tolower($1)}' | LC_ALL=C sort -u -S 256M -T <tmp> --compress-program=zstd`
   - then `comm -13` gives added names and `comm -23` gives removed names.
   - zstd, zcat, comm and sort are standard on Ubuntu/Debian hosts.
   - Always re-sort with `LC_ALL=C`. Spec 4 says "alphabetical order" but does not define the collation, so don't rely on the file's own order for `comm`.
   - Keep only 2-3 days of sorted lists (T&C s1.4: copy only as necessary).
   - Store deltas and scores in CyberCheck's own Postgres database, which is backed up. Do not keep them only in a cache such as Redis.
5. **Use of the data.**
   - Feed only the added names into the scorer, deduplicating against CertStream.
   - Use removed names as a daily takedown signal.
   - Run RDAP only on shortlisted candidates, rate-limited (T&C s1.1(2)).
   - Abuse reports stay low-volume and high-confidence, sent only through each registrar's published abuse channel.
6. **Blocklist.**
   - Publish only domains CyberCheck itself confirmed as malicious. Never publish raw zone data, diffs, keyword hits or NS records.
   - The blocklist licence must forbid marketing use and high-volume automated queries to registry or registrar systems. That mirrors s1.1, which s1.6 requires.
   - Keep evidence for each entry.
   - If you want certainty, ask globalsupport@icann.org or the main registries in writing. The address appears in the CZDS portal (https://czds.icann.org/950.f2eb12fde2b3d26d.js).
7. **CertStream stays the primary real-time feed.** CZDS is 6-30 hours behind, and 29% of Smishing Triad domains live 2 days or less. Treat WhoisDS (no redistribution) and Domains-Monitor (no standalone publication) as optional internal supplements only.
8. If the downloader runs as a long-lived service rather than a systemd timer, add an uptime monitor (Uptime Kuma or similar). Either way, alert when a day's run fails.

## Open questions

- Which CZDS TLDs are SFTP-only? Do any of the target TLDs fall in that group, and how does an SFTP zone show up in `/downloads/links`? Answer it from the portal after you register.
- Does a HEAD request count toward the once-per-24h rule? You could ask ICANN globalsupport.
- Will registries approve an individual or home-based applicant? Approval rules are not published, and some registries add email vetting (xn--6qq986b3xl asked for it within 7 days, with a decision in up to 45 days).
- Do any registries for the phase-1 TLDs (.top, .xin, .vip, .icu and others) use a T&C that differs from v1.00? Check each one when you request it.
- Does Verisign offer .cc zone access outside CZDS? Verisign's zone-file page does not mention .cc.
- Do the 2026 next-round Registry Agreement drafts change Spec 4?
- What are the real file sizes? Record HEAD Content-Length for each TLD after approval and replace the estimates.
