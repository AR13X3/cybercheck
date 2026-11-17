# CyberCheck architecture and module contracts

CyberCheck finds phishing domains that impersonate Australian brands soon after they appear, checks
them safely, and helps get them blocked and taken down.

```
CT logs ──► certstream (Go, 127.0.0.1:8431) ──► ingest ──► scoring ──► Postgres `domains`
CZDS zone diffs ──────────────────────────────────────────┘                 │
Telegram bot (user forwards) ─────────────────────────────────────────────┘ │
                                                                             ▼
worker jobs:  enrich (DNS/RDAP/ASN, re-check schedule, takedown detection)
              fetch  ──HTTP──► fetcher (Playwright) inside gluetun VPN netns ──► internet via VPN only
              judge  (AI page check + final_score)
              report (drafts / automated channels, rate-limited)
              blocklist (hosts / AdGuard / dnsmasq / RPZ files)
              czds   (daily zone diffs)
              retention (screenshot clean-up)
web dashboard (FastAPI, 127.0.0.1:8430; other devices via a private proxy such as `tailscale serve`)
```

## Ground rules (all modules)

- **Only the fetcher contacts suspicious hosts**, and only through the VPN. No other code may open an
  HTTP/TCP connection to a flagged domain or its IPs. DNS lookups go to public resolvers
  (`DNS_RESOLVERS`, default 1.1.1.1 and 9.9.9.10, both unfiltered), RDAP goes to registries/RIRs, IP→ASN to Team Cymru DNS.
- **Page content is hostile input.** Never render fetched HTML in the dashboard; serve screenshots only
  as images with a restrictive CSP. Text from pages passed to the AI is wrapped as untrusted data.
- **No inbound ports**, nothing on 0.0.0.0. Container ports publish on 127.0.0.1 only.
- **False positives are the main risk.** Reports go out automatically only through channels built for
  automated reports and only above `AUTO_REPORT_MIN_FINAL_SCORE` with corroborating page evidence;
  everything else is a draft for human review. All outgoing reports are rate-limited.
- **Cost cap.** All AI calls go through `cybercheck.ai` which enforces `AI_DAILY_BUDGET_USD` and
  `AI_MONTHLY_BUDGET_USD` using the `ai_calls` table.
- Keep memory low: it is meant to fit on a small home server or VPS next to other services (the
  `mem_limit`s of the whole stack, fetcher included, add up to under 4 GB). Every container has `mem_limit`.

## Code layout

| Path | Owner | What |
|---|---|---|
| `cybercheck/config.py` | core | `settings()` from env. Modules needing a new setting read `os.environ` in their own module and document it. |
| `cybercheck/db.py` | core | `await db.pool()` (psycopg 3 async pool, dict rows, autocommit), `connect_sync()`, `jsonb()`, `add_event(conn, domain_id, kind, detail)`, `kv_get/kv_set`, `migrate()` |
| `cybercheck/scoring.py` | core | `default_watchlist().score_hostname(host) -> Hit|None`; `Watchlist.brands[brand_id].name/official_domains` |
| `cybercheck/store.py` | core | `await store_hit(conn, hit, source, issuer, ct_log) -> (domain_id, inserted)` |
| `cybercheck/worker.py` | core | `Job(name, interval, run, initial_delay=5, enabled_by_default=True)`; modules put `JOB = Job(...)` in `cybercheck/jobs/<name>.py`; `run(ctx)` gets `JobContext(settings, log, state)` and returns a small dict shown on the dashboard |
| `cybercheck/web/common.py` | core | `templates`, `fetchall`, `fetchone`, `same_origin(request)` (call on every POST: refuses a Host outside `WEB_ALLOWED_HOSTS` (default: loopback plus `WEB_PUBLIC_HOSTNAME`) and any POST without same-origin evidence), `allowed_hosts()`, `host_allowed()`, `origin_allowed()`, `reviewer(request)`, nav list `templates.env.globals["nav"]`. A middleware refuses every request whose Host is not allowlisted (DNS rebinding). |
| `cybercheck/web/pages_<mod>.py` | module | `def register(app, templates, nav)`: add routes and `nav.append((path, label))`. Templates go in `cybercheck/web/templates/<mod>_*.html` and extend `base.html` (see `domain.html` for style classes). |
| `cybercheck/ai/api.py` | ai | public AI functions (see docstrings). Others import only this. |
| `cybercheck/confidence.py` | ai | `compute_final_score(domain, page, ai) -> (int, reasons)`; `NO_EVIDENCE_CAP = 89`: without a loaded snapshot ON THE DOMAIN ITSELF that asks for credentials plus an AI phishing verdict, `final_score` never exceeds it, whatever the settings. Blocklist and auto-report floors are >= 90 and rely on this. `snapshot_on_domain(page, registered_domain)`. |
| `cybercheck/fetch_client.py` | fetch | worker-side client for the fetcher API |
| `fetcher/` | fetch | fetcher image, `fetcher/compose.yaml` (vpn + fetcher), `vpn.env.example`, isolation test script |
| `migrations/NNN_<mod>.sql` | module | ranges: 010 enrich, 020 fetch, 030 ai, 040 reporting, 050 blocklist, 060 czds, 070 bot, 080+ core. Additive only (new tables, `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`). |
| `tests/test_<mod>.py` | module | pytest, must run without network or database (mock them) |

Do not edit files owned by another module or core files; if you need a change there, say so in your report.
Dependencies available (requirements.txt): websockets, orjson, psycopg 3 + pool, pyyaml, publicsuffixlist,
pyahocorasick, fastapi, uvicorn, jinja2, python-multipart, httpx, dnspython, anthropic, pillow, pytest.
Do not edit requirements.txt; name any extra dependency in your report.

## Database (migrations/001_init.sql)

`domains` is one row per registrable domain (eTLD+1 per the PSL, private section included).
Who writes which columns:

| Columns | Written by |
|---|---|
| identity, `score`, `tier`, `reasons`, `hostnames`, `sightings`, `first_seen`, `last_seen`, `issuer`, `ct_log`, `source` | ingest / czds / bot via `store_hit` |
| `status`, `status_changed_at`, `status_by`, `notes` | dashboard (human) only. `open`, `confirmed`, `false_positive`, `benign` |
| `dns_state`, `ips`, `asn`, `as_name`, `ip_country`, `registrar*`, `hosting_abuse_email`, `rdap_status`, `registered_at`, `enriched_at`, `next_check_at`, `check_count`, `takedown_at`, `takedown_signal` | enrich |
| `live_state`, `first_live_at`, `last_live_at`, `page_score` | fetch |
| `ai_verdict`, `ai_confidence`, `ai_brand`, `final_score` | ai (judge job) |
| `reported_at` | reporting |
| `blocklisted`, `blocklist_expires_at` | blocklist |

Tiers from the domain-name score: `watch` 40-59, `review` 60-74, `high` 75+. Re-check window:
`watch_until` = last certificate + 14 days. `domain_events.kind` values in use: `first_seen`, `status`,
plus module events (`dns_resolves`, `nxdomain`, `went_live`, `page_down`, `ai_verdict`, `reported`,
`taken_down`, `blocklisted`, `reappeared`, `czds_new_delegation`, ...). Other tables: `checks`, `pages`, `ai_calls`, `reports` (unique per
domain+channel), `ingest_stats`, `kv`.

## Pipeline order for one domain

1. stored by ingest (score >= 40) → `next_check_at = now()`
2. enrich: DNS + RDAP + ASN; schedules the next check (back-off over the watch window)
3. fetch (tier review/high, DNS resolves, due): desktop + mobile snapshots via the fetcher → `pages`, `live_state`, `page_score`
4. judge: AI page check (if key and budget) → `ai_*`; always recomputes `final_score` via `confidence.py`
5. report: when `status = confirmed` (human) or, in `REPORTING_MODE=auto`, when `final_score >= max(90, AUTO_REPORT_MIN_FINAL_SCORE)` with an AI phishing verdict (>= 0.7) and a credential-collecting snapshot on the domain itself, and `scripts/verify-sandbox.sh` passed within 30 days → automated channels (Netcraft) send, others become drafts (docs/REPORTING.md)
6. blocklist: confirmed, or open with final_score >= max(90, `BLOCKLIST_MIN_FINAL_SCORE`) and an AI phishing verdict (>= 0.7); never `false_positive`/`benign`; CZDS-sourced domains are held unless `BLOCKLIST_CZDS_TERMS_OK=yes`. Only the hostnames seen are listed (no wildcard) when the brand is only in a subdomain, the registered domain is a shared platform, or (unreviewed) it was registered more than 365 days before it was first seen; the domain page shows which before a reviewer confirms. Entries expire after `BLOCKLIST_DAYS` unless still live
7. enrich keeps checking reported/confirmed domains and records `takedown_at` (NXDOMAIN, RDAP hold, or the fetcher seeing the page gone)
