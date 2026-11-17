# First run: core stack, AI key, VPN and the page checker

This walks a fresh install from nothing to a checked, isolated page checker. Installing the host
itself (Docker, Postgres, where to run it) is in `docs/SELF-HOSTING.md`.

At the end of step 1 you have the CT stream, ingest, the worker and the dashboard on
`http://127.0.0.1:8430`. The page checker (fetcher) and the Telegram bot are not started, and
reporting is in `review` mode: nothing is sent without you.

Do the steps in order. Each one is safe to stop after.

## 1. Start the core stack (about 10 minutes)

You need Docker with Compose v2 and a Postgres 17 database with its own login for CyberCheck (the
app runs its migrations on start).

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env                  # DATABASE_URL, and FETCHER_TOKEN=$(openssl rand -hex 24)
docker compose up -d --build
docker compose ps
```

The core services use host networking, so `DATABASE_URL` points at `127.0.0.1:5432` (or wherever
your Postgres listens). The dashboard binds to `127.0.0.1:8430` only. To open it from your other
devices, put a private proxy in front of it, for example Tailscale:

```bash
tailscale serve --bg --https=8430 http://127.0.0.1:8430
```

and set `WEB_PUBLIC_HOSTNAME` in `.env` to the name the browser uses (for example
`dashboard.example.ts.net`), then `docker compose up -d --force-recreate web`. The dashboard
answers only on the hosts it knows (a DNS-rebinding guard), and it has no login of its own: never
publish it on the internet.

## 2. Add the AI key (about 2 minutes)

1. Put the key in `.env` (mode 600) with `./scripts/set-ai-key.sh`, or by hand:
   `ANTHROPIC_API_KEY=...`. The example caps are `AI_DAILY_BUDGET_USD=1.60` and
   `AI_MONTHLY_BUDGET_USD=48`; change them to suit you.
2. Restart the worker and the dashboard so they read it:
   ```bash
   docker compose up -d --no-build --force-recreate worker web
   ```
3. Open `/ai` on the dashboard. Within about 2 hours of a domain first being seen, review- and
   high-tier domains with no page snapshot get a cheap name-only triage (at most a quarter of the daily
   budget). Each call shows its cost, and today's/this month's spend is at the top.
   Screenshot judging starts only once the page checker runs (step 4).

Spending stops at either cap. `AI_FALLBACKS=default` lets a refused call be re-run on an older Opus
model; set `AI_FALLBACKS=off` in `.env` to turn that off.

## 3. Choose and set up the VPN (about 10 minutes)

The page checker only ever goes out through the VPN, from an Australian exit. Pick one:

- **Mullvad** (simplest): WireGuard config for a Sydney or Melbourne relay.
- **Your own Australian VPS**: you control the exit. `scripts/vps-wireguard-setup.sh` sets up
  WireGuard and a hardened firewall on a fresh Ubuntu VPS.
- **ProtonVPN** (paid plan): Sydney.

```bash
cp vpn.env.example vpn.env
chmod 600 vpn.env
openssl rand -hex 24          # paste as GLUETUN_API_KEY in vpn.env
$EDITOR vpn.env               # fill ONE provider block
```

`FETCHER_TOKEN` lives in `.env` (step 1).

## 4. Start the page checker and prove it is isolated (about 10 minutes)

```bash
./scripts/host-firewall.sh            # shows the two host rules (dry run)
./scripts/host-firewall.sh --apply    # needs sudo; NOT persistent: re-run after a reboot
docker compose --env-file .env --env-file vpn.env --profile fetch up -d --build
./scripts/verify-sandbox.sh
```

To keep the host rules across reboots, install them as a systemd timer:
`sudo ./deploy/install-host-firewall.sh`. To re-run the isolation test every week, install the user
timer: `./deploy/install-verify-sandbox.sh`.

Every line of `verify-sandbox.sh` must say `[PASS]`. It checks, from inside the containers, that the
home LAN, the tailnet, this host, Postgres and the VPN control server are unreachable, that traffic
leaves from the VPN in Australia, that Chromium's own sandbox is on, and that nothing leaves when the
VPN drops (it stops the VPN for a minute or two to prove that). The tailnet-IP checks use `TAILNET_IP`
or `tailscale ip -4`, and are skipped on a host without Tailscale. If anything fails, stop the stack
(`docker compose --profile fetch stop vpn fetcher`) and look at `docs/FETCHER.md`, section 3.

After it passes, domains scoring 60 or more get page snapshots within a few minutes: open one on
`/domains`. With the AI key set, the judge then looks at each screenshot and the combined score
appears on the domain page.

## 5. Look before reporting anything

- Watch `/review` for a few days. Mark each domain **Confirm phishing**, **False positive** or
  **Benign / parked** (an optional note goes with the decision). Only confirmed domains get report
  drafts on `/reports`. Before you confirm, the domain page says what the blocklist would list: the
  whole domain, or only the hostnames seen (shared platforms, possibly hacked sites). Official brand
  domains cannot be confirmed.
- Netcraft is the only channel that sends by itself, and it needs `REPORTER_EMAIL`: a role mailbox on a
  domain you own (not a personal address). Try `NETCRAFT_TEST=true` first. See `docs/REPORTING.md`.
- `.au` registrar contacts are always a manual lookup at whois.auda.org.au: auDA forbids automated
  lookups.
- Keep `REPORTING_MODE=review` until you trust the results. `auto` also needs a passing
  `verify-sandbox.sh` from the last 30 days.
- The public blocklist is built in `data/blocklist/` but never published.
  `scripts/publish-blocklist.sh` refuses to run without `BLOCKLIST_PUBLISH_CONFIRMED=yes`. Publishing
  makes it public, so decide on the hosting and the licence first.

## 6. Monitoring

Add monitors in your uptime monitor (Uptime Kuma or similar):

| Monitor | Type | Target |
|---|---|---|
| Dashboard + CT ingest | HTTP | `http://127.0.0.1:8430/healthz` (503 when ingest has been silent for 3 minutes) |
| Worker | HTTP | `http://127.0.0.1:8430/healthz/worker` |
| Sandbox test | HTTP | `http://127.0.0.1:8430/healthz/sandbox` (503 when the last passing `verify-sandbox.sh` is too old) |
| CT stream | Docker container | `cybercheck-certstream-1` |
| Fetcher | HTTP | `http://127.0.0.1:8432/health`, header `Authorization: Bearer <FETCHER_TOKEN>` |
| VPN container | Docker container | `cybercheck-vpn-1` |
| Telegram bot (if started) | Docker container | `cybercheck-bot-1` |

Container names assume the Compose project is called `cybercheck` (the default for a checkout in a
folder of that name).

## Optional later

- **CZDS** (generic TLDs such as `.top`, `.xyz`, `.info`): apply at czds.icann.org, then set
  `CZDS_USERNAME`, `CZDS_PASSWORD`, `CZDS_TLDS`. See `docs/CZDS.md`.
- **Telegram bot** (people forward a suspicious link and get an answer):
  `TELEGRAM_BOT_TOKEN` plus `docker compose --profile bot up -d`. New chats wait for your approval on
  `/bot`.
