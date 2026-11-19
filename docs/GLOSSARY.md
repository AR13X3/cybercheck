# Glossary

What the statuses, tiers, scores, verdicts and other labels on the dashboard mean. Everything here is taken
from the code; the file named under each heading is where to look when you need the exact rule. Where the
dashboard shows a different word from the value stored in the database, both are given as
`stored value` → "dashboard text".

Hostnames used as examples are made up.

## Domain review status

A person's decision about a domain (`domains.status`). Only the dashboard changes it; nothing automatic
does. Code: `cybercheck/web/app.py`, `cybercheck/enrich.py`, `cybercheck/blocklist.py`.

| Status | Dashboard | Meaning and effect |
|---|---|---|
| `open` → "open" | button "Reopen" | Not decided yet. Open domains in tier review or high make up the review queue. An open domain can still be blocklisted or, in `REPORTING_MODE=auto`, reported automatically, but only with a combined score of 90 or more (see [Combined score](#combined-score)). |
| `confirmed` → "confirmed phishing" | button "Confirm phishing" | A reviewer confirmed phishing. The domain is blocklisted whatever its score, report drafts are made, its snapshots are kept as evidence, and it is checked hourly for a takedown. Refused for a brand's official domain. |
| `false_positive` → "false positive" | button "Mark false positive" | The name matched a brand, but the site has nothing to do with it. Never blocklisted or reported. DNS checks, page fetches and AI checks stop, and unsent report drafts are cancelled. |
| `benign` → "benign" | button "Mark benign / parked" | Parked, empty, for sale or otherwise not phishing. Handled exactly like a false positive: never blocklisted or reported, and checks stop. A new certificate for the domain updates its hostnames and score but does not change the status. Only "Reopen" brings it back to the queue. |

## Tier

How suspicious the domain **name** alone is (`domains.tier`), from the [domain-name score](#domain-name-score).
Code: `cybercheck/scoring.py`, `cybercheck/config.py`.

| Tier | Score (defaults) | What happens |
|---|---|---|
| `high` | 75 or more | In the review queue, sorted first. The page is fetched and judged by the AI. |
| `review` | 60 to 74 | In the review queue. The page is fetched and judged by the AI. |
| `watch` | 40 to 59 | Stored and its DNS is watched, but it is not in the review queue, not fetched with the default `FETCH_MIN_SCORE` (60), and not judged. Open watch domains with no pages or reports are deleted after 120 days without a new sighting. |

Names scoring under 40 are not stored at all. The thresholds are `STORE_THRESHOLD`, `REVIEW_THRESHOLD`
and `HIGH_THRESHOLD`. A tier the dashboard cannot read shows as "none".

## Scores

There are three scores, each from 0 to 100.

### Domain-name score

`score`: how much the hostname looks like an impersonation of a watched brand, before anyone looks at the
page. The dashboard shows it as "Score" and explains it under "Why it was flagged", one line per reason
with its points. Code: `cybercheck/scoring.py` (the `W_*` constants hold the points).

It starts from the best brand match, then adds:

- **bait words** such as `login`, `verify`, `refund` (capped);
- **Australian context**: `au`, `gov-au`, `com-au` and similar written into the name;
- **official domain written into the hostname**, for example `commbank.com.au.login-check.example`;
- **high-abuse suffix**: a domain ending on the watchlist's `suspicious_tlds` list;
- **deep subdomain**: four or more labels before the registered domain;
- **3+ hyphens in one label**;
- **mixed scripts**: Latin letters mixed with Cyrillic or Greek ones in one label.

A line "exact brand name on another suffix (may be a defensive registration)" is information only (0 points).
Each brand match is described in one of these ways:

| Match kind (in code) | Reason text on the dashboard |
|---|---|
| exact | "brand keyword '…' in domain name" (or "in subdomain") |
| homoglyph | the same, followed by "(look-alike Unicode letters)", e.g. a Cyrillic `а` in place of `a` |
| lookalike | the same, followed by "(look-alike characters)", e.g. `c0mmbank`, `cornmbank` |
| typo | "typo of brand keyword '…' in …", one edit away, e.g. `westpak` |
| short token | "short brand token '…' (whole token)" or "(joined to a bait word)", for short names such as `nab` that only count with Australian context or a bait word in the same label |

Brands marked `needs_context` in the watchlist (common words, brands from other countries) get a much
lower score when the name has no bait word and no Australian context.

### Page score

`page_score`: how much the fetched page looks like credential phishing. Shown as "page N" next to the
domain score. Code: `cybercheck/pagefeatures.py`.

It counts fields asking for a password, a one-time code, card details or identity details; the page
mentioning the matched brand (or other watched brands); a form that sends its data to another domain; and
a login or payment form. A page that did not load, or is parked, blank, a decoy or a CAPTCHA, is
**inconclusive**: it adds nothing and is never treated as proof that the site is harmless. The domain's
page score is the highest of the snapshots from one fetch round, preferring conclusive ones.

### Combined score

`final_score`, shown as "Combined score (domain + page + AI)", the column "Combined", and the score
ring. It is "-" ("Not computed yet") until it has been calculated. Code: `cybercheck/confidence.py`.

It starts from the domain-name score and adds or subtracts points for:

- **page evidence**, which only counts from a snapshot whose final address is on the domain itself (a
  redirect to another site is not evidence against the domain; a redirect to the brand's official site
  takes a few points off);
- **the page score**;
- **the AI verdict**, weighted by its confidence. Phishing and suspicious add; benign and parked subtract;
  an error adds nothing.

Rules that always hold:

- **Without credential fields on the domain's own page and an AI "phishing" verdict with at least 70%
  confidence, the combined score is at most 89.** No setting can raise that cap. The blocklist and
  automatic reports both need 90 or more, so a name or an AI verdict alone can never get a site blocklisted
  or reported automatically. The cap can be lower (79 to 89) when `AUTO_REPORT_MIN_FINAL_SCORE` is below 90.
- If the page asks for credentials or identity details on a domain matching a brand, an AI "benign" or
  "parked" verdict alone cannot take the score below 70 (or below its score before the AI, if lower).
- On a domain's page, an open domain at 90 or more shows "Strong evidence of phishing. Waiting for your decision."

In lists the combined score is red from 80 and amber from 50.

## AI

Code: `cybercheck/ai/prompts.py` (the definitions the model is given), `cybercheck/jobs/judge.py`,
`cybercheck/web/pages_ai.py`.

### Page verdicts

The AI looks at a screenshot and the page facts and gives one verdict (`ai_verdict`). The dashboard shows
it as "AI phishing 85%" (verdict and confidence).

| Verdict | Dashboard | Meaning given to the model |
|---|---|---|
| `phishing` | "Phishing" | Imitates a brand and asks for passwords, codes, card, bank or identity details or personal information, or is one step of such a flow (a fake toll payment, parcel fee or refund). |
| `suspicious` | "Suspicious" | Signs of impersonation or fraud without clear data collection, data collection without a clear brand, or a phishing kit that is not fully set up. |
| `benign` | "Benign" | A legitimate site, including ones that mention a brand without pretending to be it (news, reviews, resellers). |
| `parked` | "Parked" | A placeholder, domain-for-sale, default web-server or empty page. |
| `error` | "Check failed" (on /live: "could not judge") | The page could not be judged: an error page, blank screenshot, CAPTCHA or access-denied wall. Also used when the model's answer is not in the expected form. |
| none | "no AI verdict", "Not judged yet" | The page has not been judged (no key, no budget left, or not due yet). |

**Confidence** (`ai_confidence`) is the model's own probability, from 0 to 1, that its verdict is right.
A phishing verdict counts towards the blocklist, automatic reports and the 90+ combined score only at
**0.7 (70%) or more**.

### Name triage

For open review or high domains that still have no page some hours after they were first seen
(`AI_TRIAGE_AFTER_H`), the AI makes a cheap guess from the name and registration facts alone:
`likely_phishing`, `unclear` or `likely_benign`. The domain page shows it as "AI name triage …". It is
for the reviewer's information only and does not change any score.

### AI call statuses

On the AI page (`/ai`), each call to the model has a status:

| Status | Meaning |
|---|---|
| `ok` | A valid answer. |
| `pending` | Reserved against the budget and in progress. |
| `refusal` | The model declined to answer. |
| `api_error` | An HTTP or connection error, or a timeout. |
| `error` | An unexpected error in CyberCheck. |
| `invalid` | The answer was cut off, empty, or not in the expected form. |
| `abandoned` | Still pending after 30 minutes. |

The last five are counted as "refused or failed". The purpose of a call is `page_judge` ("Page judge"),
`domain_triage` ("Domain triage"), `report_draft` ("Report drafts"), `bot` ("Bot replies") or
`watchlist` ("Watchlist").

## DNS, live state and takedowns

Code: `cybercheck/enrich.py` (DNS, RDAP, takedowns), `cybercheck/jobs/fetch.py` (live state).

### DNS state

`dns_state`, shown as "DNS" on the domain page.

| Value | Meaning |
|---|---|
| `unknown` | Not checked yet. |
| `resolves` | The domain (or its first hostname) has an IPv4 or IPv6 address. Only these domains are fetched. |
| `nxdomain` | The domain does not exist in DNS. |
| `no_answer` | The name exists but has no address. |
| `error` | The lookup timed out or failed. An error does not overwrite an earlier real answer. |

### Live state

`live_state`, shown as a pill.

| Value | Dashboard | Meaning |
|---|---|---|
| `live` | "live" | A page loaded with real content. |
| `down` | "down" | A page that had been live failed to load twice, at least 15 minutes apart. Problems with the fetcher itself never count. |
| `unknown` | "not checked" | Never fetched. |

The dashboard also has pills for `no_dns` ("no DNS") and `blocked` ("blocked"), but the code currently
never stores those values.

### Takedown

A domain counts as **taken down** (`takedown_at`) when, after it had resolved or been live, one of these
signals (`takedown_signal`) is seen. If several are seen, the earliest wins.

| Signal | Dashboard | Rule |
|---|---|---|
| `nxdomain` | "NXDOMAIN" | The domain no longer exists, on two checks in a row. |
| `rdap_hold` | "registry hold" | The registry put the domain on `clientHold` or `serverHold` (counts at once). |
| `http_gone` | "page gone" | The page went from live to down, on two checks in a row. |

"content removed" (`content_removed`) also has a label, but nothing sets it. Before the second check
confirms a takedown, the domain page shows "possible takedown, confirming on next check". If a new
certificate appears for a taken-down domain, the takedown is cleared and a `reappeared` event is added.

### How long a domain is checked

- **Watch window** (`watch_until`): every domain is re-checked until `WATCH_DAYS` (14) days after its most
  recent certificate. Checks start often and slow down: after 10 minutes, 30 minutes, 1, 3, 6 and 12 hours,
  then daily. The domain page shows "Next check …, watched until …".
- **Tracked**: a domain that is confirmed, reported, or judged phishing by the AI, and not marked false
  positive or benign, is checked **hourly** for a takedown until `ENRICH_TRACK_DAYS` (30) days after it was
  first seen, reported or confirmed (whichever is latest). Its page is re-fetched every 2 hours over the
  same period.
- False positive and benign domains are not checked at all.

## Timeline events

The domain page's timeline lists events by their stored name (with their details), coloured by kind.

| Event | When |
|---|---|
| `first_seen` | The domain was stored for the first time. |
| `reappeared` | A new certificate arrived for a domain that had been taken down. |
| `czds_new_delegation` | An already-known domain appeared in a CZDS zone file. |
| `bot_forward` | Someone forwarded a link to it through the Telegram bot. |
| `status` | A reviewer changed its status. |
| `dns_resolves` | It started resolving in DNS. |
| `nxdomain` | It stopped existing in DNS after having resolved. |
| `went_live` / `page_down` | Its page became live / went down. |
| `ai_verdict` | The AI judged a page (or a previous verdict for the same page was reused). |
| `final_score` | Its combined score changed by 10 points or more. |
| `ai_triage` | The AI made a name-only guess. |
| `reported` | A report was sent, or marked sent by a reviewer. |
| `taken_down` | A takedown was recorded. |
| `blocklisted` / `unblocklisted` | It was added to / removed from the blocklist. |
| `blocklist_excluded` / `blocklist_included` | A reviewer kept it off the blocklist / lifted that exclusion. |

## Status line

The row of chips at the top of every page. "unknown" on any chip means the information could not be
read. Code: `cybercheck/web/common.py`.

| Chip | What it can show |
|---|---|
| ct | "N/min": certificates per minute, stream healthy. "stalled 5m": no heartbeat for 3 minutes or more. "no heartbeat": the ingest service has never reported. |
| queue | "empty", or "N open" (with ", M high"): open review and high domains waiting for a decision. |
| worker | "ok": a background job reported in the last 10 minutes. "stalled 15m": none has since. "not running": no job has ever reported. |
| fetcher | "ok", "off" (no `FETCHER_TOKEN` set), "down" (unreachable or refused), "error" (the fetch job failed), "stale" (no report for 10 minutes). |
| vpn | The VPN exit country (for example "AU") when the fetcher is working; "off" when the fetcher is off. |
| ai | "$x.xx of $cap": AI spend since 00:00 UTC against the daily cap, amber from 70% and red when the cap is reached. "off" when there is no key or `AI_ENABLED=false`. |

## Overview page

- **Windows**: "6 h", "24 h" (default) and "7 d".
- **Pipeline by stage**: "Seen in CT" (certificates), "Scored" (domains stored), "Page live",
  "AI judged", "Confirmed", "Reported" and "Taken down": how many domains reached each stage in the window.
- **Live phishing pages**: domains whose AI verdict is phishing and whose page is live (not marked false
  positive or benign), "of the pages the AI judged".
- **Review queue**: open review and high domains, with how many were decided in the last 7 days.
- **AI spend today**: spend against the daily cap. "Cap reached, checks pause until 00:00 UTC" when it is used up.

## Reports

Code: `cybercheck/reporting/`, `cybercheck/web/pages_reports.py`, [REPORTING.md](REPORTING.md).

### Reporting mode

`REPORTING_MODE` is shown at the top of the reports page.

- `off`: nothing is created or sent.
- `review` (default): reports are made only for domains a reviewer confirmed. Netcraft reports are sent;
  emails and web forms wait for a person.
- `auto`: as review, and unreviewed domains with a combined score of 90 or more, an AI phishing verdict,
  credential fields on their own page and a recent sandbox test are also sent, **to automated channels
  (Netcraft) only**.

### Report status

| Status | Dashboard | Meaning |
|---|---|---|
| `pending_review` | "waiting for you" | An email draft or a web form waiting for a reviewer. |
| `approved` | "queued" | Waiting for the worker to send it. |
| `sending` | "sending" | Being sent now. If it is still sending after 15 minutes it becomes failed, because the outcome is unknown. |
| `sent` | "sent" | Sent through the API or by email, or marked sent / done by a reviewer. |
| `failed` | "failed" | Sending failed and will not be retried automatically. |
| `rejected` | "rejected" | A reviewer rejected or cancelled it. It is not made again. |
| `skipped` | "skipped" | The domain no longer qualified (for example, marked false positive). Also used for Netcraft test submissions. |

### Report kinds and how they were sent

- **Kind**: `api` → "API" (Netcraft), `email` → "email" (registrar abuse, hosting abuse, the brand's
  security team), `manual` → "web form" (Scamwatch, Google Safe Browsing and other forms a person files).
- **Sent via**: "API", "SMTP" or "by hand". A report sent without a reviewer has the pill "automatic".
- **"address withheld"**: the abuse address found for the domain may belong to the attacker (it is on the
  reported domain, or on another domain CyberCheck is tracking), so it was not filled in. Approving a report
  to such an address is refused. "no address yet" means no address was found.
- **AI-drafted text**: "AI draft pending; this is the template text", "written by the AI from the facts
  below, then checked by you", "template text (AI unavailable)", "edited by a reviewer" (the AI will not
  overwrite it), or "template text" (AI drafts are off).

## Blocklist

Code: `cybercheck/blocklist.py`, `cybercheck/web/pages_blocklist.py`.

**Blocklisted** means the domain is in the published blocklist files. A domain is listed when it is:

- **confirmed** by a reviewer ("by a reviewer"), or
- **open** with a combined score of at least 90 (`BLOCKLIST_MIN_FINAL_SCORE`, never below 90) and an AI
  phishing verdict at 70% confidence or more ("automated, not reviewed yet").

Never listed: false positives, benign domains, domains a reviewer excluded, government and public-suffix
names, and the watchlist's official domains. Domains found only through CZDS are "held back (CZDS terms)"
unless `BLOCKLIST_CZDS_TERMS_OK=yes`.

- **Whole domain or "hostnames only"**: the whole domain is listed only when the brand is in the registered
  name itself. Only the hostnames seen are listed when the brand is only in a subdomain, the domain is a
  shared hosting platform, or (for unreviewed domains) it was registered more than a year before it was
  first seen, which suggests a hacked older site.
- **Expires**: an entry stays for `BLOCKLIST_DAYS` (90) after it was listed or last seen live, whichever
  is later. "soon, unless still live" marks entries expiring within 7 days.
- **Recent changes**: "listed", "removed", "excluded" (by a reviewer) and "exclusion lifted".

## Telegram bot

Code: `cybercheck/bot.py`, `cybercheck/web/pages_bot.py`.

- **Chat status**: `pending` (new chat; the bot replies once that it is not enabled and then ignores it),
  `allowed` (the bot checks links sent there, also shown for chats in `TELEGRAM_ALLOWED_CHATS`),
  `blocked` (ignored silently).
- **What the bot said** about a forwarded link: `confirmed` (confirmed phishing), `suspicious` (a
  watchlist match not cleared by a reviewer; worded "very suspicious", "suspicious" or "some warning signs"
  by tier), `official` (one of the brand's genuine addresses), `shortener` (a link shortener, so the real
  destination is unknown) or `not_flagged` → "not flagged".

## CZDS

Code: `cybercheck/czds.py`, `cybercheck/web/pages_czds.py`, [CZDS.md](CZDS.md).

Status of each top-level domain, as shown on the CZDS page:

| Status | Dashboard | Group |
|---|---|---|
| `pending` | "waiting for the first CZDS check" | waiting |
| `not_approved` | "not approved for this account (yet)" | waiting |
| `approved` | "approved; first download in the next window" | waiting |
| `not_configured` | "approved, but not in CZDS_TLDS" | waiting |
| `downloading`, `downloaded`, `processing` | "downloading", "downloaded, waiting to be processed", "processing" | in progress |
| `ok` | "processed" | up to date |
| `baseline` | "baseline stored (first list; nothing counted as new)" | up to date |
| `unchanged` | "same file as before; skipped" | up to date |
| `rebaseline` | "too many new names; stored as a new baseline" (more than `CZDS_MAX_NEW_NAMES`; nothing was scored) | needs a look |
| `retrying` | "download failed; retrying" | needs a look |
| `revoked` | "no longer approved" | failing |
| `invalid` | "file rejected by a check" | failing |
| `terms` | "new Terms & Conditions to accept in the CZDS portal" | failing |
| `no_access` | "CZDS refused access (HTTP 403)" | failing |
| `low_disk` | "not enough free disk" | failing |
| `error` | "error" | failing |

## Takedown timing

The "Takedowns" page (`/takedown`, code: `cybercheck/web/pages_takedown.py`) measures how fast flagged
domains disappear, for "Confirmed by a reviewer" domains or for all tracked ones ("Confirmed, reported or
judged phishing by the AI").

- **Taken down** uses the [takedown](#takedown) rules above; "Still up" is everything else.
- **Median / p90 from first seen**: time from when CyberCheck first saw the domain to the takedown.
- **Median / p90 from report**: time from the first report to the takedown, counted only when the takedown
  came after the report.
- Results are grouped by registrar and by hosting network. Times are accurate to about an hour.
