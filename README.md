# CyberCheck

CyberCheck finds phishing websites that impersonate **Australian** organisations (banks, myGov, the ATO,
Centrelink and Medicare, Australia Post, Linkt and other toll roads, telcos, super funds, payment services,
retailers) within minutes of their TLS certificate appearing in public Certificate Transparency (CT) logs.
It checks suspicious sites from an isolated browser behind a VPN, asks an AI model to judge the screenshot,
and prepares takedown reports that a person reviews before they are sent.

Status: **alpha**. It works end to end, but expect breaking changes, rough edges and missing documentation.

Repository: https://github.com/AR13X3/cybercheck

## Why

Most phishing aimed at Australians uses a handful of brands and a familiar set of lures: a toll you have
not paid, a parcel that could not be delivered, a tax refund, a frozen bank account. Nearly every one of
these sites uses HTTPS, and every publicly trusted certificate is published in CT logs before or soon
after the site goes live. Watching CT is the earliest free signal there is, often before the first SMS
lure is sent.

General-purpose phishing feeds are built for global brands and English-speaking markets in general.
CyberCheck is tuned for Australia: its brand watchlist (`config/watchlist.yaml`) lists Australian
organisations with their verified official domains, Australian bait words (`rego`, `payid`, `mygov`,
`linkt`), look-alikes such as `gov-au` and `com-au`, and the reporting channels that exist in Australia.

## Features

- Follows every CT log in Chrome's log list (about 1,000 hostnames a second) and scores each hostname
  against the watchlist: brand keywords, typos, look-alike Unicode (punycode), short brand tokens with
  context, bait words, Australian context and high-abuse domain endings.
- Enriches hits with DNS, RDAP (registrar, abuse contact, registration date) and IP-to-network lookups,
  and re-checks them for 14 days, because many phishing domains are registered first and used later.
- Takes desktop and mobile screenshots of live suspicious sites in a sandboxed Chromium that can only
  reach the internet through a VPN (optional).
- Has an AI model (Anthropic Claude) judge each screenshot and the page facts, with hard daily and monthly
  spending caps (optional).
- A review queue in a web dashboard: confirm phishing, mark a false positive, or mark benign / parked.
- Report drafts for registrars, hosting providers, the impersonated brand, Scamwatch, Google Safe Browsing
  and others; only Netcraft, which is built for automated reports, can be sent without a person.
- A DNS blocklist in hosts, AdGuard / Pi-hole, dnsmasq, Unbound and RPZ formats (built locally; publishing
  it is a separate, deliberate step).
- Takedown timing per registrar and hosting network.
- Optional: newly registered domains from ICANN CZDS zone files, and a Telegram bot that answers when
  someone forwards a suspicious link.

## Screenshots

All screenshots show seeded test data.

| Overview | Review queue |
|---|---|
| ![Overview: CT rate, hits over time, pipeline by stage, live hits and hits by brand](docs/ui-screenshots/overview-desktop.webp) | ![Review queue: domain list on the left, screenshots, AI verdict and combined score on the right](docs/ui-screenshots/review-desktop.webp) |

| Domain page | Reports |
|---|---|
| ![Domain page: score breakdown, snapshots, details and timeline](docs/ui-screenshots/domain-desktop.webp) | ![Reports: email drafts to approve and web forms to file](docs/ui-screenshots/reports-desktop.webp) |

More, including phone layouts, are in [docs/ui-screenshots/](docs/ui-screenshots/).

## How it works

```mermaid
flowchart LR
    CT[CT logs] --> CS[certstream<br/>local websocket]
    CS --> ING[ingest + scoring]
    CZDS[CZDS zone diffs<br/>optional] --> ING
    BOT[Telegram forwards<br/>optional] --> ING
    ING --> DB[(Postgres)]
    DB --> EN[enrich<br/>DNS, RDAP, ASN]
    EN --> FE[fetch]
    FE -->|HTTP + token| FT[fetcher<br/>Chromium sandbox]
    FT -->|VPN tunnel only| NET((internet))
    FE --> JU[AI judge<br/>budget-capped]
    JU --> RV{human review<br/>dashboard}
    RV -->|confirmed| REP[report drafts<br/>and Netcraft]
    RV -->|confirmed| BL[blocklist files]
    EN --> TD[takedown timing]
```

1. **CT stream.** `certstream-server-go` follows the CT logs and serves a websocket on `127.0.0.1:8431`.
2. **Scoring.** Each hostname is scored from 0 to 100 against the watchlist. A score of 40 or more is
   stored. Tiers: watch 40-59, review 60-74, high 75+.
3. **Enrichment.** DNS through public resolvers, RDAP from the registries, IP to network through Team
   Cymru's DNS service. Domains are re-checked on a back-off schedule over 14 days.
4. **Page check.** For review- and high-tier domains that resolve, the fetcher takes desktop and mobile
   snapshots. It is the only component that ever connects to a suspicious site.
5. **AI judge.** Claude gets the screenshot and the page facts and returns a structured verdict. The
   result is combined with the name score and the page evidence into a final score
   (`cybercheck/confidence.py`).
6. **Review.** A person confirms or rejects each domain on the dashboard.
7. **Reporting and blocklist.** Confirmed domains get report drafts and go on the blocklist. Enrichment
   keeps checking them and records when they are taken down.

The full design, module contracts and database layout are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
What each status, tier, score and verdict on the dashboard means: [docs/GLOSSARY.md](docs/GLOSSARY.md).

## Safety design

CyberCheck handles hostile content and sends reports that can get a website taken down. The design
assumes both can go wrong.

- **Only the fetcher visits suspicious sites, and only through the VPN.** It runs in the VPN container's
  network namespace (gluetun), so if the tunnel drops it reaches nothing. Its container drops all
  capabilities, has a read-only root filesystem, a custom seccomp profile and no access to the app's
  secrets, and Chromium's own sandbox stays on. Host firewall rules and in-container rules block the
  local network, the host and private address ranges. `scripts/verify-sandbox.sh` tests all of this from
  inside the containers, including a kill-switch test. Details: [docs/FETCHER.md](docs/FETCHER.md).
- **No inbound ports.** Every container port is published on `127.0.0.1` only. The dashboard has no
  login of its own: keep it on loopback and reach it through an SSH tunnel or a private network such as
  Tailscale. It refuses requests whose `Host` is not on its allowlist (DNS-rebinding protection) and
  requires same-origin evidence on every POST.
- **Page content is treated as hostile.** The dashboard never renders fetched HTML; screenshots are served
  as images. Every response carries a strict Content Security Policy (`script-src 'self'`, no inline
  scripts or styles), templates are auto-escaped, and phishing URLs are never turned into links.
- **Text from pages given to the AI is marked as untrusted data**, the model gets no tools, and its
  verdict alone can never trigger a report.
- **A person decides before anything is reported.** By default (`REPORTING_MODE=review`) reports are made
  only for domains a reviewer confirmed. The optional `auto` mode sends only to channels built for
  automated reports (Netcraft), and only when the final score is 90 or more, the AI verdict is phishing,
  the domain's own page asks for credentials, and the sandbox test passed within the last 30 days.
  Without page evidence plus an AI phishing verdict, the final score is capped at 89. All sending is
  rate-limited. Details: [docs/REPORTING.md](docs/REPORTING.md).
- **No automated `.au` WHOIS or RDAP.** auDA's WHOIS policy forbids automated lookups, so `.au` registrar
  contacts are always looked up by hand.
- **CZDS terms are followed.** Zone data is never published, exported or backed up, only what is needed
  is kept, and domains found only through CZDS stay out of the public blocklist unless you decide
  otherwise. Details: [docs/CZDS.md](docs/CZDS.md).
- **Screenshots are deleted after 60 days** unless they are evidence for a confirmed domain.

## Quick start

You need a Linux host with Docker and Docker Compose 2.24 or newer. The core services use host
networking, so Docker Desktop on macOS or Windows is not a good fit. The core services need about 2 GB of
RAM; the optional fetcher needs another 1.8 GB.

```bash
git clone https://github.com/AR13X3/cybercheck.git
cd cybercheck
```

**1. Settings.** Copy the example. `.env` holds secrets, so keep it private:

```bash
cp .env.example .env
chmod 600 .env
```

`.env`, `vpn.env` and `data/` are in `.gitignore`. Never commit them.

**2. Postgres.** CyberCheck needs PostgreSQL 17. The core services connect through `127.0.0.1`. If you
already run Postgres, create a database and a login for CyberCheck and put its URL in `DATABASE_URL` in
`.env`. Otherwise start one bound to loopback; this writes a random password straight into `.env`:

```bash
PGPASS="$(openssl rand -hex 24)"
sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://cybercheck:${PGPASS}@127.0.0.1:5432/cybercheck|" .env
docker run -d --name cybercheck-db --restart unless-stopped \
  -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=cybercheck -e POSTGRES_DB=cybercheck -e POSTGRES_PASSWORD="$PGPASS" \
  -v cybercheck-db:/var/lib/postgresql/data \
  postgres:17
unset PGPASS
```

Other ways to provide Postgres, and backups, are in [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

**3. Core services** (CT stream, ingest, worker, dashboard):

```bash
mkdir -p data/certstream   # data/ must be writable by the user the containers run as (`user:` in docker-compose.yml)
docker compose up -d --build
docker compose logs -f ingest      # hits start arriving within a few minutes
```

The database schema is created on first start. Open the dashboard at `http://127.0.0.1:8430` on the
host (or through an SSH tunnel: `ssh -L 8430:127.0.0.1:8430 your-server`).

**4. Optional: the page fetcher behind a VPN.** Without it, CyberCheck still scores, enriches and lets you
review domains by name, but takes no screenshots. Choose a VPN with an Australian exit (a commercial
WireGuard provider, or your own small VPS with `scripts/vps-wireguard-setup.sh`), then:

```bash
$EDITOR .env                          # FETCHER_TOKEN=<output of: openssl rand -hex 24>
cp vpn.env.example vpn.env && chmod 600 vpn.env
$EDITOR vpn.env                       # GLUETUN_API_KEY and ONE provider block
./scripts/host-firewall.sh            # shows the host rules (dry run)
./scripts/host-firewall.sh --apply    # applies them (sudo)
docker compose --env-file .env --env-file vpn.env --profile fetch up -d --build
docker compose up -d --force-recreate worker web   # so they read FETCHER_TOKEN
./scripts/verify-sandbox.sh           # every line must say [PASS]
```

If any check fails, stop the fetcher (`docker compose --profile fetch stop vpn fetcher`) and read
[docs/FETCHER.md](docs/FETCHER.md).

**5. Optional: the AI judge.** Put an Anthropic API key in `.env` without it showing on screen, then restart
the worker and dashboard:

```bash
./scripts/set-ai-key.sh
docker compose up -d --force-recreate worker web
```

Step-by-step first-run notes: [docs/FIRST-RUN.md](docs/FIRST-RUN.md). Running it long term on your own
server (systemd timers, Tailscale, VPN choices): [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

Useful commands:

```bash
docker compose run --rm --no-deps ingest score commbank-login.top   # score one hostname
docker compose run --rm --no-deps ingest rescore                    # re-score stored domains after a watchlist change
```

## Costs

CyberCheck itself needs no paid service. What can cost money:

- **AI (optional).** Every AI call is reserved against two caps before it is made, under a database
  lock, so concurrent processes cannot overspend together: `AI_DAILY_BUDGET_USD` (default 1.60) and
  `AI_MONTHLY_BUDGET_USD` (default 48). When either is reached, AI calls stop until the next UTC day or
  month; everything else keeps working. Cheap name-only triage uses at most a quarter of the daily cap.
  The dashboard's `/ai` page shows the cost of every call and the spend so far.
- **VPN (optional).** A commercial VPN subscription, or a small VPS if you run your own exit.
- **Disk.** Screenshots and HTML snapshots; the fetcher stops writing files below `FETCH_MIN_FREE_GB`
  (default 10) of free space. CZDS zone files, if you use them, need several GB while being processed.

## Known gaps

- Phishing on hacked websites, or on shared hosting with wildcard certificates (for example
  `*.pages.dev`), never shows up as a new certificate name, so CT monitoring cannot see it.
- `.au` zone files are not available through CZDS, so `.au` look-alikes are only seen through CT.
- Phishing kits often hide from datacenter IP addresses, foreign visitors and automated browsers. Those
  snapshots are recorded as inconclusive, never as benign.
- "Not flagged" never means "safe".

## Responsible use

CyberCheck is for defending people and brands: finding phishing sites so they can be blocked and taken
down. Do not use it, or the data it collects, to find targets, to build or test phishing kits, to harass
domain registrants, or to send reports you have not checked. A false report can take down a legitimate
small business's website; review before you report. Respect the terms of the data sources you connect
(the CZDS terms, auDA's WHOIS policy, each reporting channel's rules) and the law where you run it.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and the
[code of conduct](CODE_OF_CONDUCT.md). Report security problems privately, as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## Licence

Copyright (C) 2026 the CyberCheck contributors.

CyberCheck is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation, version 3 of the License. It is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.

The AGPL means that if you run a modified version as a service that other people use over a network,
you must offer them the source code of your version.

Third-party components keep their own licences, for example the bundled Outfit font
(`cybercheck/web/static/fonts/Outfit-OFL.txt`, SIL Open Font License).
