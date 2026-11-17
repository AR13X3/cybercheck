# Self-hosting CyberCheck

This guide is for running CyberCheck long term on a Linux machine of your own: a home server, a small
office box or a VPS. The [README quick start](../README.md#quick-start) gets it running; this page covers
the choices around it.

## Requirements

- Linux with Docker Engine and the Docker Compose plugin 2.24 or newer (the compose files use `include:`
  and optional `env_file` entries). The core services use host networking, which Docker Desktop on macOS
  and Windows does not fully support.
- RAM: about 2 GB for the core services (CT stream 512 MB, ingest 384 MB, worker 512 MB, dashboard 256 MB),
  plus about 1.8 GB for the optional fetcher and VPN. Every container has a `mem_limit`.
- Disk: a few GB for the database and screenshots. The fetcher stops writing files when free space drops
  below `FETCH_MIN_FREE_GB` (default 10). CZDS, if you use it, needs several GB while a zone is processed.
- Outbound internet. CyberCheck needs **no inbound ports**: every container port is published on
  `127.0.0.1` only. Do not change that to `0.0.0.0`.
- For the fetcher: a VPN with an Australian exit, and `sudo` once to install host firewall rules.

## Files and users

| Path | What | Notes |
|---|---|---|
| `.env` | app settings and secrets | mode 600, gitignored. Start from `.env.example` |
| `vpn.env` | VPN credentials and the gluetun control-server key | mode 600, gitignored. Start from `vpn.env.example` |
| `config/watchlist.yaml` | brands, keywords, official domains | mounted read-only into the containers |
| `data/` | screenshots, HTML snapshots, blocklist files, CT stream state, CZDS lists | gitignored. Must be writable by the user the app containers run as (`user:` in `docker-compose.yml`) |

## Postgres

CyberCheck needs PostgreSQL 17 and its own database and login. It uses no extensions. The schema is created
and upgraded by the ingest service when it starts (`python -m cybercheck migrate` does the same by hand);
migrations are additive only.

**Option A: a container on the same host** (what the README does). Bind it to `127.0.0.1` and keep its
data in a named volume:

```bash
docker run -d --name cybercheck-db --restart unless-stopped \
  -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=cybercheck -e POSTGRES_DB=cybercheck -e POSTGRES_PASSWORD="<random password>" \
  -v cybercheck-db:/var/lib/postgresql/data \
  --memory 512m --log-opt max-size=10m --log-opt max-file=3 \
  postgres:17
```

Pin an exact minor version (`postgres:17.x`) if you want upgrades to be deliberate.

**Option B: an existing Postgres server.** Create a separate login and database, and do not give
CyberCheck an admin login:

```sql
CREATE ROLE cybercheck LOGIN PASSWORD '<random password>';
CREATE DATABASE cybercheck OWNER cybercheck;
REVOKE ALL ON DATABASE cybercheck FROM PUBLIC;
```

Then set `DATABASE_URL=postgresql://cybercheck:<password>@<host>:5432/cybercheck` in `.env`. Because the
core services use host networking, `<host>` is resolved from the host itself: `127.0.0.1` for a server on
the same machine.

**Option C: managed Postgres.** Works the same way; add `?sslmode=require` (or `verify-full` with your provider's CA
certificate) to `DATABASE_URL`. Keep the latency low: the ingest service writes every hit as it arrives.

### Backups

- Back up the database (`pg_dump -Fc`) regularly. It holds every decision a reviewer made, the reports
  sent, and the takedown history.
- Back up `data/screenshots/` if you need screenshots as evidence beyond their 60-day retention.
- **Never back up `data/czds/`.** The CZDS terms allow keeping only what is needed (see
  [CZDS.md](CZDS.md)); if it is lost, the next run stores a new baseline.

## Updating

```bash
git pull
docker compose up -d --build
docker compose --env-file .env --env-file vpn.env --profile fetch up -d --build   # if you run the fetcher
./scripts/verify-sandbox.sh                                                       # after any fetcher, VPN or firewall change
```

To build the image from committed files only (so files you are still editing never reach it):

```bash
git archive HEAD | docker build -q -t cybercheck-app:local - && \
  docker compose up -d --no-build --force-recreate ingest worker web
```

## The VPN for the page fetcher

The fetcher is the only component that visits suspicious sites, and it can only reach the internet
through the VPN container (gluetun). Choose an **Australian** exit: phishing kits aimed at Australians
often show nothing to visitors from other countries. Datacenter exits (all commercial VPN relays, and any
VPS) are also filtered by some kits; those snapshots are recorded as inconclusive.

### Option A: a commercial VPN

`vpn.env.example` has ready blocks for Mullvad and ProtonVPN (a paid plan; the free tier has no Australian
server). gluetun supports many other providers; see its documentation for the variable names.

```bash
cp vpn.env.example vpn.env && chmod 600 vpn.env
openssl rand -hex 24          # paste as GLUETUN_API_KEY
$EDITOR vpn.env               # fill ONE provider block, delete the others
```

### Option B: your own VPS as the exit

`scripts/vps-wireguard-setup.sh` turns a fresh Ubuntu 24.04 VPS (in Australia) into a WireGuard exit that
forwards the tunnel to the internet only: traffic from the tunnel to private, CGNAT, link-local (cloud
metadata) and loopback addresses, and new connections to the VPS itself, are dropped. SSH (key only) and
UDP 51820 are the only inbound ports. Allow UDP 51820 in your cloud provider's firewall as well.

Run it from the CyberCheck host, never by pasting it into the VPS. It prints the `WIREGUARD_*` lines for
`vpn.env`, including a private key, so send its output straight into the file instead of to the screen:

```bash
cp vpn.env.example vpn.env && chmod 600 vpn.env
$EDITOR vpn.env      # set GLUETUN_API_KEY, delete the Mullvad block, add:
                     #   VPN_SERVICE_PROVIDER=custom
                     #   VPN_TYPE=wireguard
                     #   WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL=25s
ssh -i ~/.ssh/<your key> <user>@<vps address> 'sudo bash -s' < scripts/vps-wireguard-setup.sh >> vpn.env
```

The script is idempotent: re-running it keeps the existing keys. Keep the VPS patched, do not run other
services on it, and do not make it a subnet router for any private network.

### Start and verify

```bash
./scripts/host-firewall.sh --apply                                   # host rules for the fetcher's bridge
docker compose --env-file .env --env-file vpn.env --profile fetch up -d --build
./scripts/verify-sandbox.sh
```

`verify-sandbox.sh` checks, from inside the containers, that the fetcher cannot reach the local network,
the host, Postgres or the VPN control server; that its traffic leaves through the VPN from the expected
country; that Chromium's sandbox is on; and that nothing leaves when the VPN drops. On success it writes
`data/sandbox_verified.json`, which automatic reporting requires to be at most 30 days old. Read
[FETCHER.md](FETCHER.md) for what is isolated and how, and what to do when a check fails.

## Reaching the dashboard

The dashboard listens on `127.0.0.1:8430` and has **no login of its own**. Anyone who can reach it can
confirm domains and send reports, so never expose it to the internet. Ways to reach it:

- **On the host itself:** `http://127.0.0.1:8430`.
- **SSH tunnel:** `ssh -L 8430:127.0.0.1:8430 <user>@<host>`, then open `http://127.0.0.1:8430` locally.
- **Tailscale (optional):** keep the dashboard on loopback and let `tailscale serve` proxy it with HTTPS
  inside your tailnet only:

  ```bash
  tailscale serve --bg --https=8430 http://127.0.0.1:8430
  ```

  Then set `WEB_PUBLIC_HOSTNAME=<machine name>.<your tailnet>.ts.net` in `.env` and recreate the `web`
  service, so the dashboard accepts that `Host` header (it refuses unknown hosts to block DNS
  rebinding). `tailscale serve` adds a `Tailscale-User-Login` header, which the dashboard records as the
  reviewer. Do **not** use Tailscale Funnel: that makes the dashboard public.

Use `WEB_ALLOWED_HOSTS` instead of `WEB_PUBLIC_HOSTNAME` only if you need full control of the allowed
`Host` values (each entry with an explicit port).

## systemd units (deploy/)

Two units keep the fetcher's safety checks in place. Both are only needed if you run the fetcher.

**Host firewall** (root). `scripts/host-firewall.sh --apply` is not persistent; this installs a root-owned
copy and a timer that re-applies the rules at boot and every 15 minutes:

```bash
sudo ./deploy/install-host-firewall.sh
```

**Weekly isolation test** (user unit). Runs `scripts/verify-sandbox.sh` once a week. If a test fails,
the script deletes `data/sandbox_verified.json`, which turns `/healthz/sandbox` red and switches automatic
reporting off until a test passes again. The install script fills in your checkout's path; run it as your
normal user, not with `sudo`:

```bash
./deploy/install-verify-sandbox.sh
sudo loginctl enable-linger "$USER"     # run the timer while you are logged out
```

The user needs to be in the `docker` group. The test pauses fetching for a minute or two, so the timer
runs at night in eastern Australia; change `OnCalendar=` in `deploy/systemd/cybercheck-verify-sandbox.timer`
to a quiet hour for you before installing.

## Monitoring

The dashboard has health endpoints for any uptime monitor. Each answers 200 when healthy and 503
otherwise, and none needs a token or returns secrets:

| Endpoint | Healthy when |
|---|---|
| `/healthz` | the ingest service wrote a heartbeat in the last 3 minutes |
| `/healthz/worker` | a worker job reported in the last 10 minutes |
| `/healthz/fetcher` | the fetcher answers, the VPN is up and the exit country matches |
| `/healthz/sandbox` | `verify-sandbox.sh` passed in the last 9 days |

Also watch the containers themselves (`docker compose ps`) and free disk space.

## Optional features

- **AI judge:** `./scripts/set-ai-key.sh` puts an Anthropic API key into `.env` without showing it.
  Spending stops at `AI_DAILY_BUDGET_USD` and `AI_MONTHLY_BUDGET_USD`.
- **Reporting:** stays in `review` mode by default. Read [REPORTING.md](REPORTING.md) before setting
  `REPORTER_EMAIL` (a role mailbox on a domain you own, not a personal address) or SMTP settings. Some
  SMTP servers add your public IP address to the message headers; use one that does not, or send from
  your own mail client.
- **CZDS** (zone files for generic TLDs such as `.top` and `.xyz`): apply for access at ICANN, then see
  [CZDS.md](CZDS.md). Read the terms section before turning it on.
- **Telegram bot:** set `TELEGRAM_BOT_TOKEN` and run `docker compose --profile bot up -d`. New chats wait
  for approval on the dashboard's `/bot` page.
- **Publishing the blocklist:** the files are built in `data/blocklist/` but never published
  automatically. `scripts/publish-blocklist.sh` pushes them to a git repository you choose, and refuses to
  run until you opt in and set a blocklist licence. Publishing makes the list public; decide on hosting
  and terms first.
