# CZDS: newly registered domains from ICANN zone files

CyberCheck's main feed is the Certificate Transparency stream: it sees a phishing domain minutes after
its TLS certificate is issued. ICANN's Centralized Zone Data Service (CZDS) adds a second, slower feed:
the daily zone file of each gTLD, which lists every delegated domain, including domains that never get
a certificate. CyberCheck compares each day's file with the previous day's, scores the names that are
new, and stores the hits like CT hits (`source = 'czds'`). From there they are enriched, fetched, judged
and reported in the normal way.

Facts and sources: [docs/research/czds.md](research/czds.md) and [czds.yaml](research/czds.yaml)
(verified 2026-11-15). Code: `cybercheck/czds.py`, job `cybercheck/jobs/czds.py`, dashboard `/czds`.

## What CZDS can and cannot give you

- **gTLDs only.** `.au`, `.cc` and every other country-code TLD are not in CZDS. The CT stream covers them.
  Any two-letter entry in `CZDS_TLDS` is flagged on the dashboard and never downloaded.
- **Slow.** ICANN collects the files from 00:00 UTC and has them all ready after 06:00 UTC, so a name
  registered just after midnight UTC shows up about 30 hours later. 29% of Smishing Triad domains lived two
  days or less (Unit 42, Oct 2025), so CZDS complements CT and does not replace it.
- **Delegated names only.** Names on hold (`clientHold`, `serverHold`) are not in the DNS, so they are not in
  the files either. Verisign also leaves out names in `pendingDelete` or `redemptionPeriod` and names
  without name servers.

## Applying for access

1. Create an ICANN Account at <https://czds.icann.org> and fill in the CZDS profile: organisation,
   contact name, address, phone, fax, email, and the **IP address you will download from**. "All information
   must be verifiable by the registry operator." Use the CyberCheck host's normal public IPv4 address, not the
   sandbox VPN's.
   CyberCheck downloads over IPv4 only, as the API spec says.
2. Accept the CZDS Terms of Use. **Do not share the login with anyone** (Terms of Use s2.3(b) forbids
   sharing access).
3. Request each TLD separately. Give the same reason for every request, for example:

   > Anti-phishing research: detecting newly delegated domains that impersonate Australian banks,
   > government services, postal, toll and telco brands; data used only for internal security analysis and
   > low-volume abuse reporting; no marketing; at most one download per 24h; raw zone data never redistributed.

   Read the Terms & Conditions shown for each TLD and keep a copy. Some registries add their own checks by
   email (one asked for "credentialing requirements" within 7 days and took up to 45 days to decide).
4. Wait. The portal says "Please allow one week". There is no deadline, though, and some requests have stayed
   pending for months. If a request is still pending after about 30 days, file a Zone File Access complaint:
   <https://forms.icann.org/en/resources/compliance/registries/zfa/form>.
5. Access lasts at least 3 months and, since November 2022, renews automatically unless the registry
   turns renewal off. In that case, request an extension in the portal within 30 days of expiry. It must be
   approved **before** the expiry date.
6. **SFTP-only TLDs.** Some TLDs can be downloaded only by SFTP from the registry. You enter IP addresses
   in the portal, and you get a host, user name and password instead of an HTTP download. CyberCheck only
   downloads over HTTPS. The research could not confirm how such a zone shows up in the API. If it is missing
   from the download list, it stays at "not approved" on the dashboard; if it is listed, its download fails
   with an HTTP error shown on the dashboard. Check each approval's details in the portal.

ICANN's public monthly report of active users per TLD needs no login and shows which TLDs are in CZDS:
<https://dc2og7iuc7hkj.cloudfront.net/structure.json>.

## Which TLDs to request first

Abuse figures are from Interisle (malicious phishing domains May 2025 to Apr 2026, and per 10,000 domains).
Sizes are per daily download (gzip). Only .com, .org and .top were measured; the others are estimated from
domain counts. The dashboard shows the real sizes after the first download.

| Phase | TLDs | Why | Download per day |
|---|---|---|---|
| 1 | icu, cfd, sbs, bond, click, xin, vip, cyou, win, help, lat, pro | small zones with very high phishing rates (icu 1,527/10k, cfd 1,319, win 1,622, xin 5,651) | a few MB to ~75 MB each |
| 1 | live, life, mobi | high rates (669, 478, 764 per 10k); NSEC3 without opt-out, so bigger files | ~70-120 MB each (estimate) |
| 1 | top | 2nd-largest source (297,486 domains); the main TLD for toll and parcel smishing | ~1.2-1.3 GB |
| 2 | xyz, info, shop, online, site | large volumes, lower rates; shop for retail and parcel lures | ~55-360 MB each |
| 2 | sydney, melbourne | Australian city gTLDs; tiny; cheap cover for AU-themed lures | < 0.3 MB each |
| 3 | com, net, org | the largest source in absolute terms, but CT already covers much of it | com ~4.5 GB, net/org ~0.4 GB each |

Phases 1 and 2 together come to about **2.6 GB of downloads a day**; com, net and org add about 5.3 GB.
Start with phase 1. Add phase 2 once a week of phase 1 runs looks healthy, and add phase 3 only if disk and
run time allow.

## Configuration

In `.env` (then restart the worker: `docker compose up -d worker`):

```
CZDS_USERNAME=<CZDS login email>
CZDS_PASSWORD=<CZDS password>
CZDS_TLDS=icu,cfd,sbs,bond,click,xin,vip,cyou,win,help,lat,pro,live,life,mobi,top
```

Without a username and password the job downloads nothing (`{"skipped": "no CZDS credentials"}`) and makes
no network or database calls; it only cleans up `data/czds` (see [Stopping CZDS](#stopping-czds)). If
`CZDS_TLDS` is empty, nothing is downloaded; the job only lists which zones the account is approved for, so
the dashboard can show them.

Optional settings (defaults shown):

| Setting | Default | Meaning |
|---|---|---|
| `CZDS_WINDOW_START` | `06:30` | UTC time the daily download window opens (ICANN's files are ready after 06:00 UTC) |
| `CZDS_WINDOW_HOURS` | `8` | how long the window stays open |
| `CZDS_SORT_BUFFER` | `128M` | memory for `sort -S` (the worker container has `mem_limit: 512m`) |
| `CZDS_MAX_ZONE_GB` | `8` | refuse files larger than this |
| `CZDS_MIN_FREE_GB` | `3` | disk that must stay free after a download |
| `CZDS_MAX_COUNT_CHANGE` | `0.2` | reject a file whose name count moved more than 20% from the last one |
| `CZDS_MAX_NEW_NAMES` | `1000000` | more new names than this in one day: store a new baseline, score nothing |
| `CZDS_MAX_HITS_PER_ZONE` | `2000` | store at most this many hits per zone and day, best scores first |
| `CZDS_STRICT_SOA` | `true` | require the file to start and end with the same SOA record |
| `CZDS_KEEP_UNCONFIGURED_DAYS` | `7` | delete the lists of a TLD this long after it leaves `CZDS_TLDS`, and every TLD's lists this long after the credentials are removed |
| `JOB_CZDS_ENABLED` | `true` | turn the job off entirely. The housekeeping job (every 6 h) then does the local clean-up: see [Stopping CZDS](#stopping-czds) |

## What the job does

The job runs hourly in the worker. No new container is needed. A run waits up to an hour for a zone that is
nearly due, so each zone is downloaded at roughly the same time every day.

1. **Log in** with `POST https://account-api.icann.org/api/authenticate` and keep the token in memory until
   shortly before it expires (24 hours, or the JWT `exp` claim). Never more than 3 logins in 5 minutes
   (ICANN allows 8). A wrong password stops login attempts for 6 hours; a 429 stops them for 6 minutes.
   The token is never written to disk or the database.
2. **List approved zones** (`GET /czds/downloads/links`) at most every 12 hours, and shortly before a
   download. A configured zone that disappears from the list is marked **revoked** on the dashboard and in
   the job result. In January 2026 a CZDS fault revoked every user's .top access, so watch for this.
3. **For each configured, approved zone, at most once per 24 hours** (CZDS T&C s1.8; CyberCheck keeps a
   24 h 5 min gap) and only inside the window, one zone at a time:
   - one `HEAD`. If `Last-Modified` and `Content-Length` match the file already processed, the zone is
     skipped until the next day;
   - one `GET`, streamed straight to `data/czds/<tld>/zone.gz.part`, with a size cap and free-disk checks.
     Once the download has started, the day's access counts as used, so an interrupted download is retried
     the next day, never the same day.
4. **Check the file** before using it:
   - the byte count equals `Content-Length`;
   - it is gzip and its CRC is intact;
   - it is larger than a tiny minimum size (20- and 39-byte failure files have been served);
   - the first record is the zone's SOA, and the last record is the same SOA;
   - the SOA serial is newer than the last one processed (the same serial means the same file: "unchanged");
   - the name count is within 20% of the last one (for zones with 1,000 or more names);
   - no line is longer than 1 MB, and the disk keeps 1 GB free while the names are sorted (sort spills to disk).

   A failed file is deleted and the previous list stays. A count change that persists the next day is
   accepted. A registry whose files never close with the SOA, or that resets its serial, is accepted after
   two days in a row.
5. **Extract names.** Only the owner names of NS records directly under the TLD (`example.top.`) are kept.
   The apex, glue (A/AAAA), DS, RRSIG, NSEC/NSEC3 and deeper delegations are ignored.
6. **Sort and diff with bounded memory.** The names go through `LC_ALL=C sort -u -S 128M` (or a Python
   external sort with sorted chunk files and a heap merge, if `sort` is missing or orders bytes differently),
   then a single streaming merge against the previous list finds the new names.
7. **Score** each new name with the brand watchlist. Hits go to `store_hit(..., source='czds')`. A hit that
   CT already found gets a `czds_new_delegation` event on its timeline instead.
8. **Keep only the current and the previous sorted list** (`names.gz`, `names.prev.gz`) per TLD. The raw
   download is deleted as soon as it has been processed.

**First run per TLD:** the first good file is stored as the **baseline**. Nothing is counted as new, because
every name in it already existed. New names are counted from the second day on. The same happens if the
lists are deleted or a TLD is added again later.

## Disk and time cost

Measured on a small home server (synthetic 2-million-name zone with 8 million records, Python 3.13): about
**9 seconds** to parse, check, sort and diff, which is roughly 1 million zone records a second. The worker process stayed
under 105 MB at its peak (50 MB with the system `sort`, which itself stays under `CZDS_SORT_BUFFER`).

Rough estimates from that rate (the worker container may be slower; the dashboard shows real times):

| Zone | Download | Processing | Peak disk while processing | Kept between runs |
|---|---|---|---|---|
| small phase-1 zone (icu, cfd, ...) | seconds | seconds | < 0.2 GB | a few MB |
| .top (7.3M names, NSEC3 without opt-out) | 1.2-1.3 GB | about 1 minute | ~1.5 GB | ~100 MB |
| all of phases 1+2 | ~2.6 GB | a few minutes | ~2 GB (zones go one at a time) | ~0.5 GB |
| .com (171M names) | ~4.5 GB | 10-20 minutes | ~10 GB | ~2 GB |

Before each download the job checks that the disk has room for 1.6 times the expected file size plus
`CZDS_MIN_FREE_GB`. Otherwise the zone shows `low_disk` and waits. Download time depends on the line:
4.5 GB takes about 6 minutes at 100 Mbit/s.

## Terms of use: what CyberCheck does and what you must not do

The zone data is licensed by each registry (CZDS Terms & Conditions v1.00):

- **No redistribution** (s1.6). Zone files, name lists, diffs, keyword matches and NS records are never
  published, served by the dashboard or exported. The dashboard shows only counts and CyberCheck's own
  scored hits. The blocklist module never reads zone data, and domains first found through CZDS
  (`source = 'czds'`) are held out of the public blocklist until `BLOCKLIST_CZDS_TERMS_OK=yes`. Set that only
  once the blocklist licence (`BLOCKLIST_LICENSE`) forbids recipients the s1.1 uses (marketing, high-volume
  queries to registries and registrars). A CZDS domain that later appears in Certificate Transparency
  becomes `source = 'ct'` (public data) and is no longer held.
- **Copy only what is needed** (s1.4). Only two sorted lists per TLD are kept and raw files are deleted after
  processing. A raw file of a zone whose access ended is deleted at once. Lists of TLDs removed from
  `CZDS_TLDS` (or of every TLD, when `CZDS_TLDS` is emptied or the credentials are removed) are deleted after
  7 days; [Stopping CZDS](#stopping-czds) has the details, including the case the job cannot handle.
  **Do not add `data/czds` to any backup.** If it is lost, the next run simply stores a new baseline.
- **Security** (s1.7). `data/czds` has mode 700, and the credentials stay in `.env`. If the account or the
  data is ever exposed, the Terms of Use (s2.2) require you to notify ICANN in writing.
- **No marketing, no harassing registrants, and no high-volume automated queries to registries or
  registrars** (s1.1-s1.3). RDAP runs only on scored hits (enrich module, rate-limited), and reports stay
  low-volume through each registrar's published abuse channel.
- At most **one download per zone per 24 hours** (s1.8). The job enforces this; do not download the
  files by hand as well.

The blocklist assessment (a curated list of individually confirmed malicious domains is a permitted
"value-added product") is an interpretation, not legal advice. For certainty, ask globalsupport@icann.org
or the registries in writing.

## Stopping CZDS

What happens to the zone data in `data/czds` (T&C s1.4: copy only what is needed):

| You... | What happens |
|---|---|
| remove a TLD from `CZDS_TLDS`, or empty it | the hourly job deletes that TLD's raw or partial download at once, and its lists `CZDS_KEEP_UNCONFIGURED_DAYS` (7) days after its folder last changed |
| remove `CZDS_USERNAME` / `CZDS_PASSWORD` | the hourly job does the same for **every** TLD, including those still in `CZDS_TLDS`, with no network or database calls (`deleted_lists` in the job result names the TLDs). This is the recommended way to stop |
| set `JOB_CZDS_ENABLED=false` | the czds job does not run; the housekeeping job (every 6 h, local disk only, no network) deletes raw downloads at once and every TLD's lists 7 days after their folders last changed (`czds_deleted_lists` in its result) |

So to stop using CZDS, remove the credentials or turn the job off, and restart the worker
(`docker compose up -d --force-recreate worker`); the lists are gone about 7 days later. To delete them at
once, restart the worker first (so no download is in progress), then, in the CyberCheck folder:

```
rm -rf data/czds
```

`czds_zones` and `czds_runs` in Postgres keep only per-zone counters, no zone data. If CZDS is used again
later, the folder is recreated (mode 700) and each zone's first file is stored as a new baseline.

## Dashboard statuses

| Status | Meaning / what to do |
|---|---|
| `pending`, `not_approved` | not approved for this account (yet). Check the request in the portal |
| `approved` | approved; the first download happens in the next window |
| `not_configured` | approved, but not in `CZDS_TLDS` |
| `revoked` | the approval disappeared from CZDS. Check the portal; request it again if needed |
| `baseline` | first list stored; new names are counted from the next file |
| `ok` | processed; the counts are on the row |
| `unchanged` | ICANN served the same file again; try again the next day |
| `invalid` | the file failed a check (the reason is shown); the previous list is kept |
| `rebaseline` | more than `CZDS_MAX_NEW_NAMES` new names (a registry migration, for example); stored as a new baseline |
| `retrying` | the download failed before it started (network, 5xx); retried after 1, 2, then 4 hours, inside the window |
| `terms` | HTTP 409: accept the new Terms & Conditions in the CZDS portal |
| `no_access` | HTTP 403: the request expired or was revoked |
| `low_disk` | not enough free disk for the download, or the disk filled up while the file was processed (the previous list is kept) |
| `error` | anything else; see the message |

A failed login (wrong password, rate limit) shows as an error on the job itself, at the top of `/czds`.
The job runs inside the worker, so the worker's own monitoring covers it. Look at `/czds` after the first
few days, and again whenever a zone's request might have expired.
