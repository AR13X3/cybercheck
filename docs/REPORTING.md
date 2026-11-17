# Reporting

CyberCheck reports phishing domains so they get blocked and taken down. False positives are the main risk, so the rule is simple: **reports go out without a person only through channels built for automated reports, and only for very strong evidence. Everything else is a draft that a reviewer checks and sends.** All outgoing reports are rate-limited.

Code: `cybercheck/reporting/` (worker job `report`, every 60 s, in `cybercheck/jobs/report.py`), dashboard page `/reports` (`cybercheck/web/pages_reports.py`), schema `migrations/040_reporting.sql`. Channels come from the fact-checked research of 2026-11-15: `docs/research/au-reporting.*` and `docs/research/intl-reporting.*`. `tests/test_reporting.py` checks the catalogue in `cybercheck/reporting/channels.py` against those YAML files, so they cannot drift apart.

## Modes (`REPORTING_MODE`)

| Mode | What happens |
|---|---|
| `off` | The worker creates and sends nothing. A reviewer can still create drafts on demand and send them by hand. |
| `review` (default) | Domains a reviewer **confirmed** get reports: automated channels (Netcraft) are queued and sent; email drafts and web-form checklist items wait on `/reports`. |
| `auto` | As `review`, plus unreviewed domains that meet every automatic-report rule below are sent to **automated channels only**. Their email and web-form drafts are made only after a reviewer confirms the domain. |

### Automatic-report rules (mode `auto`, unreviewed domains)

All of these must hold, checked when the report is planned and again just before it is sent:

- `status = 'open'` (never `false_positive` or `benign`; confirmed domains follow the reviewed path), not taken down;
- `final_score >= AUTO_REPORT_MIN_FINAL_SCORE` (default 90; never below 90 whatever the setting says, so a typo cannot start mass reporting and no name-only score can qualify; a value above 100 turns automatic sends off);
- `ai_verdict = 'phishing'` with confidence at least 0.7;
- the **newest** page snapshot (the latest fetch run) loaded and asks for a password, one-time code or card details;
- `data/sandbox_verified.json` exists and is at most 30 days old. `scripts/verify-sandbox.sh` (fetch module) writes it only when every isolation test of the fetcher passes and deletes it when one fails: `{"verified_at": ISO8601 UTC, "egress_ip": str, "egress_country": str, "tests_passed": int}`;
- not a `.gov.au` domain and not an official domain of any watchlist brand.

`cybercheck/confidence.py` caps `final_score` at `NO_EVIDENCE_CAP` (89) without credential-collecting page evidence on the domain's own page and an AI phishing verdict, so two independent signals must agree. The floor of 90 is hard-coded in `cybercheck/reporting/conf.py` (`HARD_MIN_AUTO_SCORE`) against that contract.

## Channels

| Channel (`reports.channel`) | Kind | Sent by | Why | How to enable |
|---|---|---|---|---|
| `netcraft` | API | worker, automatically | The only free channel built for automated phishing reports (Netcraft Report API v3, `automated_ok: true` in the research). Its feed is used by many browsers. | Set `REPORTER_EMAIL` (required by the API: the analysis result is emailed there). Use a role mailbox on a domain you own: free-mail reporters get delayed results and anonymous reports get no credit. Try `NETCRAFT_TEST=true` first (development endpoint `/api/v3/test`; see below). `NETCRAFT_ENABLED=false` turns it off. |
| `registrar_abuse` | email draft | reviewer (SMTP or own mail client) | Registrars must act on abuse reports (ICANN RAA 3.18.1/3.18.2; .au Licensing Rules 2.11.16, 2.11.17, 2.16.3). | Always drafted. Address from RDAP (enrich). **.au: no address**. auDA WHOIS Policy 5.1 forbids automated lookups, so look up "Registrar Abuse Contact Email" by hand at https://whois.auda.org.au/ and type it in. |
| `hosting_abuse` | email draft | reviewer | The network hosting the page can remove it. RIR contacts can be wrong, and can be the site operator's own (a customer reassignment). | Drafted when the domain has IPs and is not on Cloudflare (then the Cloudflare form is used). Address from RIR RDAP (enrich). |
| `brand:<brand_id>` | email draft | reviewer | The impersonated brand's own scam/hoax mailbox, **only if verified** on the brand's official page in `au-reporting.yaml`. The email says up front that this is a website report and no message was received. | Automatic for the 30 verified mailboxes. Watchlist ids that name the same organisation are mapped (`hsbc_au`, `aramex_au`, `suncorp`; `centrelink` and `medicare` use the Services Australia mailbox, which explicitly covers them). Australia Post asks for no screenshots, so none is attached. |
| `brand_form:<brand_id>` | web form | reviewer | Brands with only a web form: Linkt (needs an image: download the JPEG), Vodafone, AGL, ASIC (impersonation only). | On by default; remove `brand_form` from `REPORT_MANUAL_CHANNELS` to stop. |
| `scamwatch` | web form | reviewer | Scamwatch "Report a scam website" is the only public route into the National Anti-Scam Centre's takedown service. reCAPTCHA, manual only. Never include personal details. | On by default. |
| `google_safe_browsing` | web form | reviewer | Safe Browsing has no submission API for us (Web Risk Submission is closed to new contracts). | On by default. |
| `microsoft_smartscreen` | web form | reviewer | SmartScreen; guest form with CAPTCHA. | On by default. |
| `cloudflare_abuse_form` | web form | reviewer | For sites behind Cloudflare (AS13335/AS209242). Name, email and URLs may be passed to third parties (Lumen). | On by default, only for Cloudflare-hosted sites. |
| `auda_dns_abuse` | web form | reviewer | auDA's general enquiry form is its stated route for DNS-abuse reports. | On by default, only for `.au` domains. |
| `reportcyber` | web form | reviewer | ReportCyber is for victims reporting a cybercrime to police, not third-party takedowns (research). | Off. Add `reportcyber` to `REPORT_MANUAL_CHANNELS` if you want the checklist item. |
| `apwg_report` | web form | reviewer | APWG's public form is built for people forwarding lures. | Off. Add `apwg_report` to `REPORT_MANUAL_CHANNELS`. |

**Abuse addresses that may be the attacker's are never used.** An RDAP abuse contact on the reported domain itself (`abuse@<the phishing domain>` or a subdomain), or on another domain CyberCheck tracks as suspicious (status `open` or `confirmed`), is not filled in: the draft stays unaddressed with a red warning for the reviewer, it gets no mail-client link, Approve refuses such an address, and the worker skips an email queued to one. Sending there would tip off the attacker and hand them the evidence and the reporter's address. A shared hosting platform (`weebly.com`, `wix.com` and the others in `cybercheck/blocklist.py` SHARED_PLATFORMS) is the exception: the phishing site is one tenant's subdomain there, so the platform's own abuse address is the right one.

Not used, and why (also listed on the dashboard):
- Spamhaus Submission Portal API: whether it has a phishing threat type, and how its no-bots terms apply, are unverified.
- APWG eCX: paid membership only.
- Cloudflare Abuse Reports API: needs an account entitlement.
- Google Web Risk Submission API: closed to new contracts.
- PhishTank: new registration is disabled.
- ASD CTIS: approved Network Partners only.
- Microsoft Graph urlThreatSubmission: a beta tool for an organisation's own tenant.
- URLhaus: does not accept phishing.
- ACMA spam forwarding: only for messages actually received.
- auDA complaint: only after the registrar of record has had 30 days; lodge it by hand.
- Automated `.au` WHOIS/RDAP lookups: forbidden by auDA.

`NETCRAFT_API_KEY` is not used: the v3 report endpoint takes no key.

No Australian channel accepts automated third-party reports today, so every Australian channel is a draft.

## What happens to a domain

1. **A reviewer confirms it** (domain page). Within a minute the worker creates one `reports` row per channel that applies (`UNIQUE (domain_id, channel)` prevents duplicates): Netcraft queued, email drafts and web-form items waiting on `/reports`. "Create reports" on `/reports` does the same at once (POST `/reports/create/{domain_id}`, confirmed domains only). Confirmed domains are planned automatically for `REPORT_LOOKBACK_DAYS` (30) after confirmation.
2. **Email drafts**: the template text is replaced by an AI draft (`cybercheck.ai.api.draft_report`) when AI is available; CyberCheck always appends its own disclosure and signature. Edit anything, then either
   - **Approve and send** (only when SMTP is configured and the domain is still confirmed): the worker sends it inside the rate limit, with the screenshot attached as a JPEG unless the recipient asks for none; or
   - **Open in my mail client** (a `mailto:` link) or copy the text, send it yourself, then **Mark as sent**.
   A reviewer's edits are never overwritten by a later AI draft.
3. **Web forms**: open the official link, copy the prefilled fields, submit, **Mark as done**.
4. **Reject** / **Not applicable** closes an item for good; it is never recreated.
5. When a domain is marked `false_positive` or `benign`, everything still pending or queued for it is skipped.

`domains.reported_at` is set on the first successful send (or when a reviewer marks an email or form as sent), and every one adds a `reported` event naming the channel. A submission to Netcraft's test endpoint (`NETCRAFT_TEST=true`) is **not** a report: the row becomes `skipped` with `response.test = true` and the note "test submission (NETCRAFT_TEST)", `reported_at` stays empty, and it is never sent to the test endpoint twice. Once `NETCRAFT_TEST` is removed, the worker queues it for the production endpoint: confirmed domains (within `REPORT_LOOKBACK_DAYS`; older ones with Retry on `/reports`), and unreviewed domains that still meet every automatic-report rule. Test submissions recorded as `sent` by older versions are converted the same way. API responses go to `reports.response`, submission ids (Netcraft uuid, SMTP Message-ID) to `reports.external_id`. Netcraft submissions are polled every 6 hours until resolved or archived (30 days); their state shows in the sent log, and every state change is kept in `reports.response.status_history`.

## Report content

Every report is factual and neutral. It contains:
- what was observed and when;
- the URLs. Only URLs from the snapshots that are the evidence are used: the fetch run of the chosen snapshot and, when it asks for credentials, only the snapshots that do too. And only URLs on (or under) a hostname seen in a certificate for this domain, so a kit that redirects to the real brand site can never get the brand reported, and a kit on a hacked small-business site (`netbank-login.someplumber.com.au`) that cloaks visitors to the business's own home page can never get `someplumber.com.au` reported;
- when the domain was first seen in Certificate Transparency, and the log name;
- the credential fields the page asks for, the snapshot time and the browser profile. A snapshot is described as "from an Australian network" only when its recorded egress IP is the one `scripts/verify-sandbox.sh` verified;
- the TLS issuer, the registration date and the registrar;
- the IPs and ASN;
- the screenshot, unless the recipient asks for none (Australia Post): then the email does not mention one either;
- the brand impersonated, with its official site.

Every report also says that it was detected automatically and whether a person reviewed it, that it is made in good faith, and asks to be told if the site is legitimate. The wording is "appears to impersonate"; nothing goes beyond the evidence. The reviewer's identity is never included.

## Rate limits and retries

- `REPORT_RATE_PER_HOUR` (default 10): outgoing requests per hour across all channels (API calls and SMTP deliveries, failed ones included), counted from `report_attempts`.
- `REPORT_CHANNEL_MIN_INTERVAL_S` (default 60): minimum gap between two sends on the same channel.
- Over the limit, items **wait** in the queue; nothing is dropped. HTTP 429 pauses that channel (Retry-After, default 15 minutes) and the item waits; it never turns into `failed`.
- Other failures retry after 5 min, 15 min, 1 h, 3 h, 12 h, up to `REPORT_MAX_ATTEMPTS` (5), then `failed`. Permanent errors (HTTP 400/401/403/..., SMTP 5xx, login failure, no STARTTLS) fail at once. Failed items can be retried from the dashboard.
- Items for a channel that is not configured yet (no `REPORTER_EMAIL`, no SMTP) are held and re-checked every 15 minutes.
- A send that was interrupted (the worker was killed or lost the database after handing the report to Netcraft or the SMTP server) has an unknown outcome: after 15 minutes it becomes `failed` with "the outcome is unknown", never re-sent automatically. Check the Netcraft submissions or the mailbox, then use Retry if it did not go out.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `REPORTING_MODE` | `review` | `off`, `review` or `auto` (anything else is treated as `review`, with a dashboard warning) |
| `AUTO_REPORT_MIN_FINAL_SCORE` | 90 | combined score needed for automatic reports (never below 90; above 100 turns automatic sends off) |
| `REPORT_RATE_PER_HOUR` | 10 | global send limit (0 holds everything) |
| `REPORTER_EMAIL` | empty | reporter identity; Netcraft stays off without it and drafts ask you to add contact details |
| `REPORTER_NAME` | `CyberCheck` | name in signatures |
| `REPORT_CHANNEL_MIN_INTERVAL_S` | 60 | per-channel gap between sends |
| `REPORT_MAX_ATTEMPTS` | 5 | attempts before `failed` |
| `REPORT_LOOKBACK_DAYS` | 30 | confirmed domains are planned automatically this long after confirmation |
| `REPORT_AI_DRAFTS` / `REPORT_AI_DRAFTS_PER_RUN` | true / 3 | AI email drafts (subject to the AI budget caps) |
| `REPORT_MANUAL_CHANNELS` | all except `reportcyber`, `apwg_report` | comma list of web-form channels, plus `brand_form` |
| `NETCRAFT_ENABLED` / `NETCRAFT_TEST` | true / false | Netcraft on/off; send to the development endpoint |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | empty | SMTP for approved drafts; off unless **all five** are set |

SMTP: port 465 uses implicit TLS; any other port must offer STARTTLS or nothing is sent. Certificates are verified. `From` is `SMTP_FROM`, `Reply-To` is `REPORTER_EMAIL`. smtplib runs in a thread. Keep the password in `.env` (mode 600). Many submission servers (Gmail SMTP AUTH, for example) add the client's public IP to a `Received` header, so a recipient learns your server's home IP address. Use a provider that strips it, or send from your own mail client.

## Enabling, step by step

1. Create a role mailbox on a domain you own (for example `reports@<your domain>`) and set `REPORTER_EMAIL`. Optionally email support@netcraft.com before reporting at volume.
2. Set `NETCRAFT_TEST=true`, confirm a test domain, check that the dashboard shows a Netcraft submission uuid (the row is `skipped`, marked "test endpoint"), then remove `NETCRAFT_TEST`. While it is set, every confirmed domain in the lookback window (and in mode `auto` every eligible one) goes to the test endpoint once; none of them counts as reported, and they all go to production when the setting is removed.
3. Optional: set the five `SMTP_*` settings to send approved email drafts from the worker.
4. Switch to `auto` only after both of these:
   - the fetcher's isolation tests pass. `scripts/verify-sandbox.sh` then writes `data/sandbox_verified.json`; re-run it at least every 30 days;
   - you have watched `review` mode for a while.

## Data (migration 040)

`reports` gains `kind` (api | email | manual), `attempts`, `next_attempt_at`, `last_attempt_at`, `updated_at`, `reviewed_by`, `reviewed_at`, `sent_via` (api | smtp | manual), `sent_by` and `checked_at`. Statuses: `pending_review` (waiting for a reviewer), `approved` (queued), `sending`, `sent`, `failed`, `rejected`, `skipped` (no longer qualified). `report_attempts` logs every outgoing request (rows older than 180 days are deleted by the job). `kv['report:pause']` holds 429 pauses.

## Upkeep

- Re-check the brand pages in `au-reporting.yaml` every quarter (ING, NAB, ATO and Origin changed recently), update the YAML, then `cybercheck/reporting/channels.py`; the tests fail until both agree.
- Open questions from the research worth asking: auDA (low-volume RDAP for abuse reports), Netcraft (rate limits, a `source` UUID), the NASC (data-sharing for researchers), ASD (Network Partner status for CTIS).