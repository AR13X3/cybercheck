# CyberCheck sandboxed page fetcher

The fetcher is the **only** component that visits a suspicious site, and it does so from inside a VPN
network namespace. Everything else in CyberCheck (ingest, enrich, judge, report, blocklist, the
dashboard) only ever talks to public resolvers, registries and the fetcher's local API — never to a
flagged domain. This document covers setup, what is isolated and how, and the known limits.

```
worker ──HTTP(token)──► fetcher API (127.0.0.1:8432)
                         └ fetcher (Playwright/Chromium)  ── network_mode: service:vpn ──┐
                         gluetun (VPN) ── wg0 ──► VPN provider ──► internet               │
                              ▲ control server 127.0.0.1:8000 (API key)                   │
   host ── published 127.0.0.1:8432 only ────────────────────────────────────────────────┘
```

The fetcher shares gluetun's network namespace, so its only route to the internet is the VPN tunnel.
If the tunnel is down, gluetun's kill switch (OUTPUT policy DROP) means the fetcher reaches nothing.

## 1. Set up

Everything lives under `fetcher/` plus `vpn.env` at the repo root. The images are pinned by digest
(gluetun `v3.41.3`, Playwright `python:v1.65.2-noble`).

1. **Choose a VPN and fill `vpn.env`.** Copy the example and pick an Australian exit:
   ```bash
   cp vpn.env.example vpn.env
   chmod 600 vpn.env
   $EDITOR vpn.env          # set GLUETUN_API_KEY and one provider block (Mullvad / own VPS / Proton)
   ```
   - `GLUETUN_API_KEY`: a 32+ char random string of letters and digits only (`openssl rand -hex 24`;
     it is embedded in a JSON value, so no quotes or backslashes). It protects the gluetun control
     server so page JavaScript inside the namespace cannot drive the VPN. The fetcher refuses to fetch
     if the key is shorter than 16 characters, and also if the control server answers a request that
     does NOT carry the key (i.e. auth is not actually enforced).
   - An **Australian** exit (Mullvad or Proton Sydney, or your own AU VPS) matters: kits that target
     Australian brands commonly cloak non-AU and datacenter IPs. `vpn.env` is gitignored and must be
     mode 600.
   - Set `FETCHER_TOKEN` in the app `.env` (the worker and web read it too): at least 16 random
     characters (`openssl rand -hex 24`). The fetcher rejects every request when it is shorter.

2. **Start the fetch stack** (behind the `fetch` profile; plain `docker compose up` never starts it).
   Run it from the repo root (the seccomp profile path is relative to it). Both secret files are needed
   for interpolation; the fetcher container receives only its own vars:
   ```bash
   docker compose --env-file .env --env-file vpn.env --profile fetch up -d
   ```
   `fetcher/compose.yaml` interpolates with `${VAR:-}`, never `${VAR:?}`: Compose interpolates every
   service before applying profiles, so a required-variable error would break plain
   `docker compose up -d` of the core services on a host without `vpn.env`. A missing secret instead
   fails **closed** at runtime (no token: every request is refused; no key: no fetch).

3. **Close the host side of the bridge** first (second layer behind the in-container post-rules):
   ```bash
   ./scripts/host-firewall.sh            # prints the rules (dry run)
   ./scripts/host-firewall.sh --apply    # installs them (sudo)
   ```
   Both rules go at the top of `INPUT` (ACCEPT established/related from `ccvpn0`, then DROP the rest
   from `ccvpn0`), so a broad ACCEPT elsewhere in `INPUT` cannot shadow them. Re-running is idempotent.

4. **Verify the isolation** (required before any automatic report goes out):
   ```bash
   ./scripts/verify-sandbox.sh
   ```
   It runs every check inside the containers and passes only if all of them pass: no app secrets in
   the fetcher's environment; the fetcher's real traffic leaves from the VPN exit, which differs from
   the home IP (looked up on the host; set `HOME_IP=` if the host cannot look it up) and is in
   `FETCH_EXPECTED_COUNTRY`; DNS is gluetun's only; IPv6 is off; the home LAN gateway and this host's
   LAN IP, 192.168.0.1/1.1, 10.0.0.1, 172.17.0.1, the vpn bridge gateway (incl. Postgres :5432 and
   SSH), 127.0.0.1:5432, this host's tailnet IP (incl. :5432 and :22; from `TAILNET_IP` or
   `tailscale ip -4`, skipped without Tailscale), 100.100.100.100, 169.254.169.254 and
   fd7a:115c:a1e0::1 are all unreachable (curl must fail to *connect*: exit 7 or 28); the control
   server answers 401 without the key; the firewall policy is DROP with every post-rule loaded;
   Chromium fetches through the fetcher API and no Chromium process has `--no-sandbox`; and a
   **kill-switch test**: it stops the VPN through the control server, checks that nothing leaves and
   the API fails closed (503), then starts the VPN again (a trap restarts it if interrupted). Expect
   a ~1-2 minute fetch outage while it runs.

   On success it writes `data/sandbox_verified.json`; on any failure it deletes it. The report module
   refuses automatic reporting unless that file exists and is at most 30 days old, so re-run it
   monthly (and after any VPN, image or firewall change).

   To re-run it weekly, install the systemd user timer: `./deploy/install-verify-sandbox.sh` (it fills
   in the checkout's path; `sudo loginctl enable-linger $USER` lets it run while you are logged out).

5. **Monitoring.** Add uptime monitors (Uptime Kuma or similar) for the gluetun container health and
   for the fetcher API (`GET http://127.0.0.1:8432/health` with the bearer token returns 200 only when
   the VPN is up, the egress country matches and Chromium can start). `/healthz/sandbox` on the
   dashboard turns 503 when the last passing isolation test is too old. Watch the two containers'
   CPU and memory with `docker stats` or your usual host monitor.

## 2. What is isolated, and how

**Network (the real boundary).**
- The fetcher has `network_mode: service:vpn` and no network of its own. Its default route is the
  WireGuard tunnel (`wg0`); gluetun's kill switch sets the OUTPUT policy to `DROP`, so if the tunnel
  drops, nothing leaves.
- gluetun leaves two gaps, which `fetcher/post-rules.txt` (read-only mounted) closes: it rejects NEW
  connections, on **any** interface, to the container's own Docker subnet (whose gateway is the host),
  RFC1918, CGNAT (`100.64.0.0/10`, the tailnet), link-local (`169.254.0.0/16`, cloud metadata),
  `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15` and multicast/reserved (`224.0.0.0/3`), which would
  otherwise reach the host via the bridge or be routed into the tunnel to the VPN provider's network.
  Only NEW connections are rejected, so replies on the published API port still flow.
  `scripts/host-firewall.sh` adds the matching host INPUT drop on the `ccvpn0` bridge.
- If a post-rule fails to load, gluetun opens its firewall and **exits**; the fetcher only starts
  once gluetun is healthy (`depends_on: service_healthy`), and the fetcher's own egress gate needs
  the VPN status "running" plus an Australian public IP before every fetch.
- If gluetun restarts on its own, the fetcher is left in the old network namespace, which has only
  loopback (nothing reachable, nothing leaks). A watchdog in the fetcher exits after
  `FETCH_WATCHDOG_S` (default 300 s) without the control server, and Docker's restart policy then
  re-joins the new namespace.
- DNS goes through gluetun's DoT forwarder. The malicious/ads blocklists are **off** (they would hide
  phishing domains), and so are filtering upstreams: `DNS_UPSTREAM_RESOLVERS` is `cloudflare,google`
  (1.1.1.1 and 8.8.8.8, both unfiltered). gluetun's `quad9` is Quad9's threat-blocking 9.9.9.9, which
  answers NXDOMAIN for domains on its feeds, i.e. the reported ones; the fetcher would then see the page
  fail, `live_state` would go `down` and enrich would record a false takedown. `quad9 unsecured`
  (9.9.9.10) would be acceptable; `cloudflare security`/`family`, `quad9 secured`, `cleanbrowsing *` and
  `cira *` are not. `verify-sandbox.sh` fails if the list holds anything else or `BLOCK_MALICIOUS` is
  not `off`. `DNS_BLOCK_IP_PREFIXES` adds `100.64.0.0/10` and `0.0.0.0/8`, which gluetun's
  rebinding protection does not cover. A domain that resolves only to a private/CGNAT IP therefore
  returns nothing to the fetcher (resolve it in the scorer instead if you want that as a signal).
- IPv6 is disabled in the namespace (`net.ipv6.conf.all` and `.default.disable_ipv6=1`, IPv4-only
  bridge), so there is no IPv6 path at all.
- **WebRTC** is limited to proxied UDP (`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`);
  with no proxy that means no WebRTC UDP, and anything it tried would still only see the tunnel.

**Control server.** gluetun's control server (`127.0.0.1:8000`) ships with a no-auth public role that
includes state-changing routes a page could hit with an `<img>` tag. It is pinned to an API-key default
role (`HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE`), so every route needs `X-API-Key`. The fetcher uses the
key to read the public IP/country (cached 60 s) and **fails closed (503)** if the key is missing,
the control server does not enforce it, the VPN is not running, the egress is unknown, or the country
is not `FETCH_EXPECTED_COUNTRY` (unset means `AU`; only an explicitly empty value disables that one
check).

**Container.** `user: pwuser`, `cap_drop: ALL`, `no-new-privileges`, the seccomp profile
`fetcher/seccomp.json` (below), `read_only` root with tmpfs for
`/tmp` and `/home/pwuser`, `shm_size 1g`, `mem_limit ~1.5g` with `memswap_limit` equal to it (no
swap: Docker otherwise lets a container use as much of the host's swap as its RAM limit; the
vpn container likewise), `pids_limit 512`, `init: true`, pinned
image by digest, json-file logging (10m ×3). The fetcher receives only `FETCHER_TOKEN`, the control-
server key and its own `FETCH_*` settings — never `DATABASE_URL`, `ANTHROPIC_API_KEY` or any other
secret from the app `.env`.

**Browser.** Chromium launches with the sandbox **on** (`chromium_sandbox=True`, `channel="chromium"`
for new-headless, which is less fingerprintable). Each fetch gets a fresh context (no persistence),
service workers blocked, downloads off, permissions denied, dialogs dismissed, only http/https
navigations, and route handlers (HTTP and WebSocket) that abort any request to `localhost` /
`*.localhost` or to any IP literal that is not public unicast, including legacy spellings such as
`127.1` or `0x7f000001` and IPv4-mapped IPv6 (defence in depth behind the network controls).
Forms are read with `getAttribute` (a kit can clobber `form.action`), from every frame (up to 10), and
inputs outside any `<form>` are reported as a pseudo-form with method `script`, because many kits
submit with JavaScript. Per-page timeout
~25 s with a ~45 s hard cap, max 2 concurrent pages, and the browser is recycled after N pages or a
crash. The mobile profile is an Android Pixel with `en-AU` / `Australia/Sydney` and a reduced UA; the
desktop profile is Chrome on Windows 1366×768. The fetcher stores nothing; it returns JSON only.

**API.** Bearer `FETCHER_TOKEN` (constant-time compared), requests carrying an `Origin` header are
rejected, and the API is published to the host on `127.0.0.1` only. Inside the isolated namespace the
API binds all interfaces (so Docker's published-port DNAT can reach it); the token and origin check are
what protect it from page JavaScript that reaches the shared namespace.

### The fetcher API

- `GET /health` → `{ok, vpn_running, egress_ip, egress_country, browser_ok}` (200 only when `ok`, else
  503). After a Chromium launch failure it tries to start Chromium again.
- `POST /fetch {url, profile:"mobile"|"desktop"}` → `{ok, final_url, http_status, redirect_chain,
  title, html, text_excerpt, screenshot_webp_b64, forms, egress_ip, egress_country, timings, error,
  fetcher_error}`.

`/fetch` answers 503 (fetch nothing, record nothing) when the egress gate is closed, when Chromium
cannot be started, and when a navigation failed and a forced egress re-check shows the VPN dropped or
changed exit during the fetch (the gate itself is cached for 60 s). A launch that has not finished
within 40 s (less than a fetch's own 50 s budget, so a hung Playwright driver is counted too) is a
failure. After 3 launch failures in a row the fetcher exits so Docker restarts it with a fresh Playwright driver; a cause that persists (for example
"No usable sandbox") then shows as a restart loop and an unreachable API, never as fetch results.
Every string in a result comes from the page, which can replace JavaScript builtins, so the fetcher
rebuilds it in Python (strings only, lone surrogates replaced, control characters dropped, forms
capped at 50 forms and 500 inputs, HTML capped at 2 MB of UTF-8) and keeps the body under 8 MB
(dropping the HTML first); a result that still cannot be encoded becomes a `fetcher_error` result,
never a 500.

The worker side (`cybercheck/fetch_client.py`) returns `None` whenever the fetcher is unreachable,
failing closed (503) or rejects the token (401/403); the fetch job then returns
`{"skipped": "fetcher unavailable"}` and changes nothing. If that happens in the middle of a run, the
domain being fetched is left exactly as it was (no page row, no failure counted) and the run stops.
A failure of one request (another 5xx, a read timeout, a dropped connection) makes it ask `/health`
again: if the fetcher is down, that is `None` as above; if it is healthy, the request becomes a
`fetcher_error` result for that domain, so one page cannot stall the queue. Bodies over 10 MB, non-JSON
and 400 answers are `fetcher_error` results too. A result with `fetcher_error: true` (browser crash,
hard timeout) is stored as a snapshot but does not count towards `live_state = 'down'`, which enrich
reads as a takedown signal.

### Worker jobs

- **fetch** (every ~30 s): picks resolving review/high (or `score >= FETCH_MIN_SCORE`) open/confirmed
  domains that are not taken down and due per schedule (first fetch ASAP, then +1 h, +6 h, +24 h, then
  daily within the watch window; confirmed / reported / AI-phishing domains every ~2 h). It fetches
  `https://<first hostname>/` (falling back to `http://`), mobile first and desktop too on the first
  round, stores a `pages` row per profile (screenshot and gzipped HTML under `data/`, de-duplicated when
  the content hash is unchanged), writes the page features and `page_score`, and maintains `live_state`
  (`live` on a load; `down` only after two failed fetches ≥ 15 min apart, so a single blip and a
  never-live domain are never reported as down; after a live page's first failure it re-checks
  within ~20 min). Past the watch window an untracked domain is parked at `watch_until` and fetched
  again only if a new certificate extends the window or it becomes tracked. Human-confirmed domains
  are fetched whatever their tier. The ~2-hourly tracking lasts `ENRICH_TRACK_DAYS` (30) from the
  latest of first seen, reported and confirmed, the same window as enrich's hourly checks: only enrich
  records a takedown, so fetching stops tracking when enrich does (after that the domain follows the
  normal watch-window schedule). A round in which every snapshot was a fetcher fault does not use up a
  schedule step (a first round keeps its desktop profile) and is retried after 30 min, doubling per
  fault in a row up to 6 h. Below `FETCH_MIN_FREE_GB` free on the data disk (which may also hold
  Postgres) no screenshot/HTML file is written; the `pages` row is still stored and the run reports
  `low_disk`.
- **retention** (every ~6 h): deletes screenshot/HTML files past `retain_until` unless the snapshot is
  evidence or the domain is confirmed (then it is kept and marked evidence); only files under `data/`
  are ever touched. The evidence mark lasts only while the domain is confirmed: 7 days after a reviewer
  moves it to another status, its snapshots fall back to the normal rule. A file that cannot be deleted
  keeps its path and is retried next run. Once a day, files under `data/screenshots/<id>/` and
  `data/html/<id>/` older than a day that no `pages` row references (left by a worker killed mid-save)
  are deleted.

### Settings (defaults in `cybercheck/config.py` / read from the environment)

| Setting | Default | Where |
|---|---|---|
| `FETCHER_URL` | `http://127.0.0.1:8432` | app `.env` |
| `FETCHER_TOKEN` | — (required) | app `.env` |
| `FETCH_MIN_SCORE` | 60 | app `.env` |
| `FETCH_CONCURRENCY` | 2 | app `.env` / fetcher |
| `SCREENSHOT_RETENTION_DAYS` | 60 | app `.env` |
| `FETCH_BATCH` | 20 | worker env |
| `FETCH_EXPECTED_COUNTRY` | `AU` (empty disables) | worker env / fetcher |
| `FETCH_TRACK_INTERVAL_H` | 2 | worker env |
| `FETCH_MIN_FREE_GB` | 10 (0 disables) | worker env |
| `RETENTION_BATCH` | 500 | worker env |
| `GLUETUN_API_KEY` | — (required) | `vpn.env` |
| `FETCH_MAX_PAGES` | 200 | fetcher |
| `FETCH_WATCHDOG_S` | 300 (0 disables) | fetcher |

## 3. Known limits

- **Cloaking.** Kits that target Australian brands filter by IP reputation, geography and device type,
  and gate content behind CAPTCHAs or redirect scanners to the real brand site. A snapshot that is
  parked, blank, a CAPTCHA gate or a redirect to the real brand is recorded as **inconclusive** and
  sent to human review — never scored as "benign". Expect a non-trivial inconclusive rate.
- **Datacenter exits.** Mullvad and Proton Australian relays are all rented datacenter IPs, so some kits
  will show nothing or a decoy. A residential AU exit (your own custom WireGuard endpoint) sees more,
  at the cost of running that endpoint and reviewing its terms of service.
- **Chromium sandbox and seccomp.** Docker's default seccomp profile allows `unshare`, `setns` and
  namespace-creating `clone` only with `CAP_SYS_ADMIN`, which `cap_drop: ALL` removes, so Chromium's
  user-namespace sandbox could not start under it. `fetcher/seccomp.json` therefore allows those and
  instead denies (EPERM) the syscalls that matter for container escape and kernel attack surface:
  module loading, `mount`/new mount API, `pivot_root`, keyrings, `bpf`, `perf_event_open`, `ptrace`
  and `process_vm_*`, `io_uring`, `userfaultfd`, clock/time setting, swap, `reboot`, `kexec` and
  similar. It is a deny-list (default allow), which is looser than Docker's allow-list for obscure
  syscalls: that is the price of Chromium's sandbox, which Playwright's own profile also pays.
  Because the user and network namespaces it allows give a process a namespaced `CAP_NET_ADMIN`
  and `CAP_NET_RAW`, `socket()`/`socketpair()` are also narrowed to what Chromium, Node and Python
  use: every address family from 17 up (`AF_PACKET`, `AF_ALG`, `AF_VSOCK`, `AF_RDS`, `AF_TIPC`,
  `AF_XDP`, ...) and the obsolete ones below 16 (`AF_KEY`, `AF_APPLETALK`, ...) fail with
  `EAFNOSUPPORT`, and `AF_NETLINK` with `NETLINK_NETFILTER` (nf_tables) or `NETLINK_XFRM` fails with
  `EPROTONOSUPPORT`. `NETLINK_ROUTE`, which Chromium needs, and with it the net/sched surface, stays
  open. Only the x86_64 ABI is listed, so 32-bit `int 0x80` system calls (and x32) are refused
  (SIGSYS) and cannot get around the argument checks. Re-tested on 2026-11-16 (Ubuntu 26.04) with these
  filters: "You are adequately sandboxed", no `--no-sandbox` process, the listed families refused
  (also with junk in the upper 32 bits of the argument), `int 0x80` killed. `personality()` is not
  restricted (Docker restricts it with an allow-list of values, which a default-allow profile cannot
  express without risking Chromium).
  Tested on Ubuntu 26.04 (2026-11-16, `kernel.apparmor_restrict_unprivileged_userns=1`, `--network none`,
  the compose security options): with `fetcher/seccomp.json` Chromium's `chrome://sandbox` page
  reports the namespace sandbox (PID and network namespaces) and the seccomp-BPF sandbox on, "You
  are adequately sandboxed", and no process has `--no-sandbox`. With Docker's default profile
  Chromium aborts (SIGABRT) instead of running unsandboxed. If a future kernel, Docker or AppArmor
  change makes Chromium log "No usable sandbox", every fetch fails and verify-sandbox fails: the
  fetcher never falls back to `--no-sandbox`. Fix the AppArmor or seccomp side rather than disabling
  the sandbox. `scripts/verify-sandbox.sh` checks no Chromium process has `--no-sandbox`.
- **Local names.** gluetun forwards "local-looking" names (single label, `.local`, `.lan`, …) to Docker's
  embedded resolver. Attackers cannot register such names, but confirm with `tcpdump` on the host uplink
  that no query leaks outside the tunnel if you are cautious.
- **Hard timeouts and slow sites.** A site that never reaches DOMContentLoaded within ~25 s counts as
  a failed fetch, so a very slow live kit can be recorded as `down` after two such failures; enrich
  still needs two consecutive checks before it records a takedown.
- **Memory.** Chromium is ~100–300 MB plus ~50–150 MB per page; the container cap is ~1.5 GB and it
  recycles the browser after `FETCH_MAX_PAGES`. Watch it with `docker stats` if the host is short of RAM.
