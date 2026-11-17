# Sandboxed page fetcher: verified research

Topic: the isolated headless-Chromium fetcher for CyberCheck on a home server (Docker 29.5, Compose v5, Ubuntu 26.04, Tailscale installed). Fact-checked on 2026-11-15 against primary sources: GitHub API, Docker Hub and MCR registries, gluetun source at tag v3.41.3, Playwright source and docs at v1.65.1/v1.65.2, the Docker and Chrome docs, and the Mullvad relay API. Nothing was installed or run against the host's Docker. The source repos were only cloned into a scratch directory to read them.

## Summary

- **gluetun**: pin `qmcgaw/gluetun:v3.41.3` by digest. That is the newest stable release (2026-07-30). The repo moved to `passteque/gluetun`, but the image name didn't change. The wiki describes `master`, not v3.41.3, so check each variable against the source at the tag.
- **Kill switch**: in v3.41.3 the IPv4 and IPv6 policies are DROP. The only exits allowed are loopback, the VPN endpoint on eth0, everything on wg0, and the container's own Docker subnet, which includes the host gateway. Every other private, CGNAT or link-local destination follows the default route into wg0, so it reaches the VPN provider's network, not the LAN or tailnet. Use `/iptables/post-rules.txt` and host INPUT rules to close both gaps.
- **Correction, firewall**: the firewall can be turned off. The variable `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=off` disables it. Also, if enabling fails at startup (a bad post-rules line, for example), gluetun sets every policy to ACCEPT and then exits. The fetcher must start only after gluetun is healthy.
- **Control server**: with no auth configured, v3.41.3 leaves a public, no-password role on routes that change state. That includes `PUT /v1/vpn/status` and legacy GET routes such as `GET /openvpn/actions/restart`. A page's JavaScript can call a GET route with nothing more than an `<img>` tag. Set `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE` to an API-key role.
- **DNS**: gluetun's built-in DoT forwarder is on by default. `BLOCK_MALICIOUS` is on by default and must be turned off, or phishing domains will look dead.
  - Correction: `BLOCK_SURVEILLANCE` is effectively off in the image, because the Dockerfile sets it to `off`.
  - Addition: gluetun's rebinding filter doesn't cover `100.64.0.0/10`, the tailnet range. Add it with `DNS_BLOCK_IP_PREFIXES`.
- **Playwright**: pin `mcr.microsoft.com/playwright/python:v1.65.2-noble` by digest and `pip install playwright==1.65.2`.
  - Correction: Python 1.65.2 ships Chromium **159.0.8154.6**. The 158 figure is from the 1.65.0 notes.
  - Playwright adds `--no-sandbox` unless `chromium_sandbox=True`.
  - WebP screenshots are native, so Pillow isn't needed.
  - The official image is documented as "not recommended to visit untrusted websites", so the isolation has to come from this setup.
- **Cloaking**: verified sources (Silent Push, Netcraft, PhishFarm, urlscan) back the plan of an Australian exit plus a mobile (Android) device profile. Mullvad's Australian relays are all on rented datacenter hosting (M247, xtom, HostRoyale, hostuniversal), so expect some kits to filter them by IP reputation. Treat empty or decoy results as inconclusive.

## Verified facts

### gluetun release and image
1. Latest stable is **v3.41.3, published 2026-07-30T14:48:13Z**. Earlier releases: v3.41.2 (2026-07-29), v3.41.1 (2026-02-11) and v3.41.0 (2025-12-25). None is a pre-release, and no v3.42 exists. Source: https://api.github.com/repos/passteque/gluetun/releases and https://github.com/passteque/gluetun/releases/tag/v3.41.3
2. Docker Hub `qmcgaw/gluetun:v3.41.3`, `:v3.41` and `:v3` all resolve to the index digest `sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027`. I checked this against the registry API. Source: https://hub.docker.com/r/qmcgaw/gluetun/tags
3. The README says the repo moves to `github.com/passteque/gluetun` on 2026-05-21 and that "The Docker image names will remain the same." `api.github.com/repos/qdm12/gluetun` now returns a 301 redirect. Source: https://github.com/passteque/gluetun/blob/master/README.md
4. The wiki documents master, not the release. `DNS_UPSTREAM_PLAIN_ADDRESSES` is in the wiki but absent from the v3.41.3 source, which has `DNS_ADDRESS` instead. Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/options/dns.md and https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/dns.go

### gluetun firewall and routing (v3.41.3 source)
5. `enable()` sets the IPv4 and IPv6 policies to DROP. It then accepts:
   - loopback;
   - ESTABLISHED/RELATED traffic;
   - output to the VPN server IP, port and protocol on the default-route interface;
   - output from the container IP to each local subnet (`acceptOutputFromIPToSubnet`, which covers the Docker bridge subnet and its gateway, i.e. the host);
   - `FIREWALL_OUTBOUND_SUBNETS`;
   - **all input on eth0 addressed to the local subnet** (`acceptInputToSubnet`);
   - `FIREWALL_INPUT_PORTS`;
   - finally, `/iptables/post-rules.txt`.

   Source: https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/enable.go
6. After the tunnel is up, `SetVPNConnection` appends `-A OUTPUT -o wg0 -j ACCEPT`. Because it appends, post-rules inserted with `-I` stay above it. Source: https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/vpn.go
7. Routing:
   - WireGuard installs a fwmark rule that sends unmarked traffic to its own table, which routes `0.0.0.0/0` (and `::/0` if IPv6 is supported) through wg0.
   - `AddLocalRules` adds priority-98 rules so that only the local Docker subnet uses the main table, via eth0.
   - Every other private destination therefore goes into wg0.

   Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/wireguard/rule.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/routing/local.go and https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/wireguard.go
8. `FIREWALL_OUTBOUND_SUBNETS` adds ACCEPT rules on the default (eth0) interface and policy routes (table 199, priority 99) through the Docker gateway. Those subnets therefore skip the tunnel. Leave it unset. Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/routing/outbound.go and https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/enable.go
9. Post-rules:
   - The path is fixed at `/iptables/post-rules.txt`.
   - Only lines that start with `iptables`, `iptables-nft`, `iptables-legacy`, `ip6tables`, `ip6tables-nft` or `ip6tables-legacy` are run. Other lines are ignored.
   - If one rule fails, the earlier ones are rolled back and `enable()` returns an error.

   Source: https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/iptables.go
10. **The firewall can be off.**
    - `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT` (default `on`) controls it.
    - If `enable()` fails after the first policy change, a deferred `fallbackToDisabled` clears all rules and sets the policies to ACCEPT. `main.go` then returns the error and gluetun exits.

    This contradicts the wiki FAQ line "The firewall is never de-activated". Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/enable.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/firewall.go, https://github.com/passteque/gluetun/blob/v3.41.3/cmd/gluetun/main.go and https://github.com/qdm12/gluetun-wiki/blob/main/faq/firewall.md
11. If no working ip6tables is found, `runIP6tablesInstruction` returns nil and the IPv6 rules are skipped without an error. Source: https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/ip6tables.go
12. The gluetun wiki turns IPv6 *on* with `sysctls: net.ipv6.conf.all.disable_ipv6=0` and an IPv6-enabled network. So IPv4-only is the default, and `disable_ipv6=1` can be set explicitly with Compose `sysctls`, which are allowed for namespaced `net.*` keys. Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/ipv6.md and https://docs.docker.com/reference/compose-file/services/
13. Docker 28.0.0 fixed "a security issue that was allowing neighbor hosts to connect to ports mapped on a loopback address" and blocks direct routed access to unpublished ports. It also says: "Unpublished container ports continue to be directly accessible from the Docker host via the container's IP address." Sources: https://docs.docker.com/engine/release-notes/28/ and https://www.docker.com/blog/docker-engine-28-hardening-container-networking-by-default/

### Connecting the fetcher and exposing a port
14. Publish ports on the gluetun service and give the joined container `network_mode: "service:gluetun"`. The wiki's example publishes on all interfaces (`9000:9000/tcp`), so add `127.0.0.1:` yourself. Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/port-mapping.md and https://github.com/qdm12/gluetun-wiki/blob/main/setup/connect-a-container-to-gluetun.md
15. Because of fact 5, published ports work without `FIREWALL_INPUT_PORTS`. The wiki says that variable "seems needed for Kubernetes sidecars". Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/options/firewall.md and https://github.com/passteque/gluetun/blob/v3.41.3/internal/firewall/enable.go
16. In container network mode, Docker gives the joining container the *same* resolv.conf, hosts and hostname files as the container it joins (`initializeNetworkingPaths`). The fetcher therefore sees the nameserver gluetun writes. Source: https://github.com/moby/moby/blob/master/daemon/container_operations_unix.go
17. Compose `depends_on.restart: true` "restarts this service after it updates the dependency service". That applies only to Compose-driven updates, not to restarts by the daemon's restart policy. Source: https://docs.docker.com/reference/compose-file/services/

### gluetun control and health servers
18. The control server defaults to `:8000` (`HTTP_CONTROL_SERVER_ADDRESS`). The auth file is `/gluetun/auth/config.toml`. `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE` defaults to `{}`, which means no default role. Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/server.go and https://github.com/passteque/gluetun/blob/v3.41.3/Dockerfile
19. With no auth file and no default role, `SetDefaults` adds role `public` with `auth: none` on these routes:
    - GET `/openvpn/actions/restart`, `/unbound/actions/restart`, `/openvpn/portforwarded`, `/updater/restart`, `/v1/version`, `/v1/openvpn/portforwarded`, `/v1/publicip/ip` and `/v1/portforward`;
    - GET and PUT `/v1/vpn/status`, `/v1/openvpn/status`, `/v1/dns/status` and `/v1/updater/status`.

    `/v1/vpn/settings` is not public. Setting a default role assigns it every route not already in a role. Unauthorised requests get 401. The API-key header is `X-API-Key`. Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/server/middlewares/auth/settings.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/server/middlewares/auth/apikey.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/server/middlewares/auth/middleware.go and https://github.com/passteque/gluetun/blob/v3.41.3/internal/server/server.go
20. The v3.41.0 release notes introduced `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE` (JSON), with the example `{"auth":"apiKey","apikey":"xyz"}`. The source constant is `apikey`. Source: https://github.com/passteque/gluetun/releases/tag/v3.41.0
21. `gluetun genkey` exists as a CLI subcommand. Source: https://github.com/passteque/gluetun/blob/v3.41.3/cmd/gluetun/main.go
22. `GET /v1/publicip/ip` returns JSON with the fields `public_ip`, `region`, `country`, `city`, `hostname`, `location`, `organization`, `postal_code` and `timezone`. The default lookup APIs are `ipinfo,ifconfigco,ip2location,cloudflare`. Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/models/publicip.go and https://github.com/passteque/gluetun/blob/v3.41.3/Dockerfile
23. Health server and checks:
    - The health server listens on `127.0.0.1:9999`.
    - Defaults: `HEALTH_TARGET_ADDRESSES=cloudflare.com:443,github.com:443`, `HEALTH_ICMP_TARGET_IPS=1.1.1.1,8.8.8.8`, `HEALTH_SMALL_CHECK_TYPE=icmp` and `HEALTH_RESTART_VPN=on`.
    - The image has `HEALTHCHECK ... CMD /gluetun-entrypoint healthcheck`.

    Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/health.go, https://github.com/passteque/gluetun/blob/v3.41.3/Dockerfile and https://github.com/qdm12/gluetun-wiki/blob/main/faq/healthcheck.md
24. `HTTPPROXY` (8888) and `SHADOWSOCKS` (8388) are off by default. Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/httpproxy.go and https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/shadowsocks.go

### gluetun DNS
25. Effective defaults in the v3.41.3 image:
    - `DNS_SERVER=on`, `DNS_UPSTREAM_RESOLVER_TYPE=DoT` (one of `dot`, `doh` or `plain`), `DNS_UPSTREAM_RESOLVERS=cloudflare`;
    - `DNS_CACHING=on`, `DNS_UPSTREAM_IPV6=off`, `DNS_ADDRESS=127.0.0.1`, `DNS_KEEP_NAMESERVER=off`;
    - `BLOCK_MALICIOUS=on`, **`BLOCK_SURVEILLANCE=off`** (set in the Dockerfile; the Go fallback is `true`), `BLOCK_ADS=off`.

    Sources: https://github.com/passteque/gluetun/blob/v3.41.3/Dockerfile, https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/dns.go and https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/dnsblacklist.go
26. Upstream resolver names are matched case-insensitively. `quad9` is valid (provider name `Quad9`). Sources: https://github.com/qdm12/dns/blob/9de8e7fdbe3a/pkg/provider/providers.go and https://github.com/qdm12/dns/blob/9de8e7fdbe3a/pkg/provider/quad9.go
27. "DNS rebinding protection is always enabled" since v3.41.0, and `DNS_REBINDING_PROTECTION_EXEMPT_HOSTNAMES` can exempt names. The blocked answer ranges are 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7, fe80::/10 and their IPv4-mapped forms. **`100.64.0.0/10` and `0.0.0.0/8` are not included.** `DNS_BLOCK_IP_PREFIXES` adds more ranges. Sources: https://github.com/passteque/gluetun/releases/tag/v3.41.0, https://github.com/qdm12/dns/blob/9de8e7fdbe3a/pkg/middlewares/filter/mapfilter/privateip.go and https://github.com/qdm12/gluetun-wiki/blob/main/setup/options/dns.md
28. Names judged "local" are sent to the resolvers found in resolv.conf at startup (Docker's 127.0.0.11) rather than upstream. These are single-label names, names ending in `.local`, `.lan`, `.private`, `.internal`, `.corp`, `.home` or `.intranet`, and names whose suffix isn't in the public-suffix list. Sources: https://github.com/qdm12/dns/blob/9de8e7fdbe3a/internal/local/islocal.go and https://github.com/passteque/gluetun/releases/tag/v3.41.0

### gluetun WireGuard providers
29. **Custom provider** requirements:
    - Required: `WIREGUARD_ENDPOINT_IP` (an IP; "domain names are not supported"), `WIREGUARD_ENDPOINT_PORT`, `WIREGUARD_PUBLIC_KEY`, `WIREGUARD_PRIVATE_KEY` and `WIREGUARD_ADDRESSES`. `WIREGUARD_PRESHARED_KEY` is optional.
    - Defaults: `WIREGUARD_MTU=1320`, `WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL=0` and `WIREGUARD_IMPLEMENTATION=auto`. Allowed IPs default to `0.0.0.0/0`, plus `::/0` when IPv6 is supported.
    - An IPv6 interface address fails validation when IPv6 is unsupported.

    Sources: https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/wireguardselection.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/wireguard.go, https://github.com/passteque/gluetun/blob/v3.41.3/Dockerfile and https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md
30. **Mullvad**:
    - Set `WIREGUARD_PRIVATE_KEY` and `WIREGUARD_ADDRESSES`, using the IPv4 address from a downloaded config file. Note that the "Wireguard Key" on the Devices page is not the private key.
    - Filter with `SERVER_COUNTRIES` or `SERVER_CITIES`.
    - The endpoint IP and public key are built in, and the port is optional.

    Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/mullvad.md and https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/wireguardselection.go
31. **ProtonVPN**:
    - `WIREGUARD_PRIVATE_KEY` comes from Proton's WireGuard config page. The address defaults to `10.2.0.2/32`. `WIREGUARD_ENDPOINT_PORT` must not be set.
    - Filters: `SERVER_COUNTRIES`, `SERVER_REGIONS`, `SERVER_CITIES`, `FREE_ONLY`, `SECURE_CORE_ONLY` and `PORT_FORWARD_ONLY`. Port forwarding is controlled by `VPN_PORT_FORWARDING`, which defaults to off.
    - Since v3.41.0, the Proton server-data updater has to log in (`UPDATER_PROTONVPN_EMAIL` and `UPDATER_PROTONVPN_PASSWORD`).

    Sources: https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/protonvpn.md, https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/wireguard.go, https://github.com/passteque/gluetun/blob/v3.41.3/internal/configuration/settings/updater.go and https://github.com/passteque/gluetun/releases/tag/v3.41.3
32. Australian servers in the server list bundled with v3.41.3:
    - Mullvad: 18 WireGuard servers in Sydney, Melbourne, Brisbane, Adelaide and Perth. The list is dated 2025-10-03.
    - Proton: 39 WireGuard servers in the same cities, with secure-core in Sydney. The list is dated 2025-11-18. **None of the Australian Proton servers is free tier.**

    Source: https://github.com/passteque/gluetun/blob/v3.41.3/internal/storage/servers.json
33. Mullvad's live relay API currently lists 25 Australian WireGuard relays, some of them inactive, across Adelaide, Brisbane, Melbourne, Perth and Sydney. All are `owned: false`, hosted by M247, xtom, HostRoyale and hostuniversal. Source: https://api.mullvad.net/www/relays/wireguard/
34. Proton's Australia page lists servers in Adelaide, Brisbane, Melbourne, Perth and Sydney, and Plus servers are paid. Source: https://protonvpn.com/vpn-servers/australia

### Playwright
35. The latest Playwright for Python is **1.65.2**: on PyPI uploaded 2026-11-14, and the GitHub release was published 2026-11-14T00:23Z. The core `microsoft/playwright` repo's latest tag is v1.65.1 (2026-11-13). Sources: https://pypi.org/project/playwright/, https://github.com/microsoft/playwright-python/releases/tag/v1.65.2 and https://github.com/microsoft/playwright/releases/tag/v1.65.1
36. MCR digests:

    | Tag | Digest |
    |---|---|
    | `v1.65.2-noble` | `sha256:38dd67fc654b56b3cba611e4c8eb71cd33750e1cd29eea2a5dc00b484817a75f` |
    | `v1.65.1-noble` | `sha256:0ab41a37431309d72b7a26f40ef1fdb464a62740196b2143965a2f59dc090409` |
    | `v1.65.2-resolute` | `sha256:8c0e5d0ff77103dd1c3552d514fa98a86ceaa30aa50e4263573df81c716e11e0` |

    `jammy`, `noble` and `resolute` variants exist for each version. Source: https://mcr.microsoft.com/v2/playwright/python/tags/list
37. Python v1.65.2 rolls Chromium to r1255, **v159.0.8154.6**. The core repo's `browsers.json` at v1.65.1 shows the same. The 1.65 release notes list Chromium 158.0.8127.18, which is the 1.65.0 build (r1254). Sources: https://github.com/microsoft/playwright-python/releases/tag/v1.65.2, https://github.com/microsoft/playwright/blob/v1.65.1/packages/playwright-core/browsers.json and https://github.com/microsoft/playwright/blob/v1.65.1/docs/src/release-notes-python.md
38. Docker docs, quoted:
    - "The Playwright package/dependency is not included in the image and should be installed separately."
    - "It is not recommended to use this Docker image to visit untrusted websites."
    - The root user disables the Chromium sandbox. For crawling, use a separate user with `--security-opt seccomp=seccomp_profile.json`.
    - `--init` is recommended. `--ipc=host` is recommended "when using Chromium. Without it, Chromium can run out of memory and crash."

    Sources: https://playwright.dev/python/docs/docker and https://github.com/microsoft/playwright/blob/main/docs/src/docker.md
39. The Python image's Dockerfile installs `python3` and `curl`, creates `pwuser`, and puts the browsers in `/ms-playwright`. The default TZ build argument is America/Los_Angeles. Source: https://github.com/microsoft/playwright-python/blob/v1.65.2/utils/docker/Dockerfile.noble
40. `chromium.ts` adds `--no-sandbox` whenever `chromiumSandbox !== true`. `chromiumSwitches.ts` includes `--disable-dev-shm-usage`, `--disable-popup-blocking`, and one `--disable-features=` list that includes `HttpsUpgrades`. User `args` are appended after Playwright's own. Sources: https://github.com/microsoft/playwright/blob/v1.65.1/packages/playwright-core/src/server/chromium/chromium.ts and https://github.com/microsoft/playwright/blob/v1.65.1/packages/playwright-core/src/server/chromium/chromiumSwitches.ts
41. `seccomp_profile.json` has defaultAction `SCMP_ACT_ERRNO` and allows `clone`, `setns` and `unshare` unconditionally. Its last commit was 2021-01-03. It is based on an older Docker default profile and doesn't name `clone3`. Sources: https://github.com/microsoft/playwright/blob/v1.65.1/utils/docker/seccomp_profile.json and https://github.com/microsoft/playwright/commits/main/utils/docker/seccomp_profile.json
42. In headless mode Playwright uses the *headless shell* by default. `channel="chromium"` opts into "new headless", which is "the real Chrome browser, and is thus more authentic". Source: https://github.com/microsoft/playwright/blob/v1.65.1/docs/src/browsers.md
43. WebP screenshots arrived in 1.62. Type is `"png"|"jpeg"|"webp"`, and for WebP "a quality of 100 (the default) produces a lossless image". Python 1.65.2 has `Literal["jpeg", "png", "webp"]`. Sources: https://github.com/microsoft/playwright/blob/v1.65.1/docs/src/release-notes-python.md, https://github.com/microsoft/playwright/blob/v1.65.1/docs/src/api/params.md and https://github.com/microsoft/playwright-python/blob/v1.65.2/playwright/async_api/_generated.py
44. Context options, from the Python 1.65.2 types:
    - `service_workers: Literal["allow","block"]`
    - `accept_downloads`, which defaults to true, so set it to False
    - `record_har_content` (`omit`, `embed` or `attach`; default `embed`)
    - `record_har_mode` (`full` or `minimal`)
    - `route_web_socket`

    Sources: https://github.com/microsoft/playwright/blob/v1.65.1/docs/src/api/params.md, https://github.com/microsoft/playwright-python/blob/v1.65.2/playwright/async_api/_generated.py and https://playwright.dev/python/docs/api/class-browser#browser-new-context
45. The device descriptors include `Pixel 7` through `Pixel 10 Pro XL`, `Galaxy S24` and `iPhone 15`. The `Pixel 7` UA is `... Chrome/159.0.8154.6 Mobile Safari/537.36`, with viewport 412x839, `isMobile` and `hasTouch`. Source: https://github.com/microsoft/playwright/blob/v1.65.1/packages/isomorphic/deviceDescriptorsSource.json

### Chromium
46. The switch `--force-webrtc-ip-handling-policy` exists in Chromium `content_switches.cc` (main). Valid values include `default_public_interface_only` and `disable_non_proxied_udp`. Sources: https://chromium.googlesource.com/chromium/src/+/main/content/public/common/content_switches.cc and https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/common/peerconnection/webrtc_ip_handling_policy.cc
47. Chrome 142 launches the Local Network Access permission prompt. Its "local" ranges are private IPv4, 169.254/16, fc00::/7, fe80::/10 and mapped forms, and loopback is 127/8 and ::1. **CGNAT 100.64/10 is not listed**, and automation isn't mentioned. Source: https://developer.chrome.com/blog/local-network-access
48. Ubuntu's `kernel.apparmor_restrict_unprivileged_userns` can break Chromium's namespace sandbox. The Chromium doc lists workarounds but doesn't cover Docker. Source: https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md

### Cloaking
49. Silent Push, "Smishing Triad", 2025-04-10:
    - The admin panel has "A country whitelist so that the page can likely only load for people on specific IP addresses" and "A toggle to allow desktop access (most pages only render to mobile user agents)".
    - "The kits were initially focused on Australian financial institutions". CommBank, Bendigo and Adelaide Bank, Bank of Sydney and Australia Post are named.

    Source: https://www.silentpush.com/blog/smishing-triad
50. Netcraft on darcula v3, 2025-02-20:
    - "Risky IP filtering", "Crawl filtering", and "Unallowed device types is often used to block non-mobile devices".
    - Detection "Requires a global proxy network to fetch fraudulent content in certain geographies and from unknown IPs" on varying device types.

    Source: https://netcraft.com/blog/darcula-v3-phishing-kits-targeting-any-brand
51. PhishFarm (Oest et al., IEEE S&P 2019) tested cloaking filters (geo, mobile-only, security-entity) against anti-phishing blacklists. Source: https://adamdoupe.com/publications/phishfarm-oakland2019.pdf
52. urlscan.io's scan API takes `country` (ISO 3166-1 alpha-2), `customagent` and `referer`. Source: https://docs.urlscan.io/apis/urlscan-openapi/scanning/submitscan.md
53. Unit 42 reports CAPTCHA-gated phishing pages, which hide content from automated scanners. Source: https://unit42.paloaltonetworks.com/captcha-protected-phishing/

## Corrections made

1. **`BLOCK_SURVEILLANCE` default.** The researcher said it defaults to on in v3.41.3. The Go fallback is on, but the image's Dockerfile sets `BLOCK_SURVEILLANCE=off`, so the effective default is **off**. Setting it to off explicitly is still fine.
2. **"The firewall is never switched off."** Not true unconditionally. `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=off` disables it. Any error during `enable()`, including a failing post-rules line, triggers `fallbackToDisabled` (policies ACCEPT, rules cleared) before gluetun exits. The design must start the fetcher only once gluetun is healthy, and must test post-rules.
3. **Chromium version.** The researcher said the 1.65 browsers are Chromium 158.0.8127.18. Python 1.65.2 (and core 1.65.1) ships **Chromium 159.0.8154.6**. 158.0.8127.18 is the 1.65.0 build.
4. **`--ipc=host`.** The Playwright docs *recommend* `--ipc=host` for Chromium. The researcher's private IPC namespace with a larger `shm_size` relies on Playwright's default `--disable-dev-shm-usage`. That is a defensible hardening choice, but it's our own reasoning, not documented guidance, so it is labelled that way below.
5. **Docker 28 loopback-port claim.** The researcher's source (the Docker blog) doesn't say this. I confirmed it from the Docker 28.0.0 release notes instead.
6. **Control-server exposure, more serious than stated.** The public role includes legacy **GET** routes that change state (`/openvpn/actions/restart`, `/unbound/actions/restart`, `/updater/restart`). Page JavaScript can call these from inside the shared namespace with a simple request (an `<img>` tag needs no CORS preflight). Also, binding the control server to `127.0.0.1:8000` means it *cannot* be published to the host at all, because published ports are DNATed to eth0. The host orchestrator must go through the fetcher API.
7. **DNS rebinding coverage.** The researcher implied private answers are blocked. They are, but not `100.64.0.0/10` (the tailnet/CGNAT range) or `0.0.0.0/8`. Added `DNS_BLOCK_IP_PREFIXES=100.64.0.0/10,0.0.0.0/8`.
8. **ProtonVPN.** Australian Proton servers are paid-tier only (none is free in the bundled list). Since v3.41.0 the Proton updater needs Proton credentials, so leave `UPDATER_PERIOD` unset for Proton and rely on the bundled list plus image upgrades.
9. **Mullvad list freshness.** The bundled list (2025-10) has 18 Australian relays. The live API has 25. Without `UPDATER_PERIOD`, newer relays can't be used and removed ones may fail.
10. **Isolation tests fixed:**
    - `-H 'X-API-Key: $KEY'` in single quotes never expands. Now uses double quotes with an env var inside the container.
    - The kill-switch test "stop gluetun" only removes the namespace. It doesn't test the kill switch. Now uses `PUT /v1/vpn/status` `{"status":"stopped"}` with the firewall still up.
    - The malformed `gluetun-vpn-only` entry is removed.
    - `ip route get` now runs in the gluetun container (busybox `ip`). The Playwright image isn't confirmed to include iproute2.
    - Added a test for a 100.64/10 DNS answer.
11. **Netcraft wording.** Netcraft says "a global proxy network ... from unknown IPs" on "varying device types", not "region-appropriate egress". The meaning is close, but "unknown IPs" also implies that known VPN or datacenter IPs are a weakness.
12. **Unit 42 URL** changed to its canonical form, `https://unit42.paloaltonetworks.com/captcha-protected-phishing/`.
13. **Added, missing from the original:**
    - gluetun needs `cap_add: [NET_ADMIN]` and `devices: [/dev/net/tun]`.
    - Set `sysctls: net.ipv6.conf.all.disable_ipv6=1` explicitly on gluetun.
    - Use `channel="chromium"` (new headless) to reduce the headless fingerprint.
    - The device-descriptor UA carries a full Chromium build number.
    - Mullvad's Australian relays are rented datacenter IPs.
    - The bundled seccomp profile dates from 2021.

## Uncertain / unverified

- **Docker's IPv6 default in containers on an IPv4-only network.** The Docker IPv6 docs don't say whether `disable_ipv6=1` is set. The gluetun wiki implies it is, since it uses a sysctl to enable IPv6. Set it explicitly and check inside the container.
- **Where Docker's embedded DNS (127.0.0.11) forwards from.** It matters for "local-looking" names that gluetun forwards there. The Docker docs say `--dns` servers are queried "from the container's network namespace", but they don't cover the systemd-resolved (127.0.0.53) case that Ubuntu uses. Risk: query names leak outside the VPN, for non-ICANN or local suffixes only, which an attacker can't register. Check with tcpdump on the host.
- **The 2021 Playwright seccomp profile on a 2026 kernel.** It doesn't name `clone3`. runc usually returns ENOSYS for syscalls newer than any listed in the profile, which lets glibc fall back to `clone`, but I didn't confirm this from a primary source for runc in Docker 29.5. If Chromium misbehaves, build a profile from Docker's current default plus the Playwright `clone`/`setns`/`unshare` rule.
- **Ubuntu 26.04's AppArmor userns restriction** (`kernel.apparmor_restrict_unprivileged_userns`) inside a `docker-default`-confined container. I didn't confirm whether it blocks Chromium's namespace sandbox. This needs a test on the target host.
- **Chromium's handling of duplicate `--disable-features` switches.** I didn't verify whether Chromium merges them or keeps the last one. To be safe, don't pass `--disable-features` yourself.
- **Chrome Local Network Access under Playwright automation.** Behaviour is undocumented.
- **Memory per page.** No primary source. Third-party figures (Browserless) suggest roughly 100–300 MB for the browser plus 50–150 MB per page. Measure with `docker stats`. Sources: https://docs.browserless.io/enterprise/long-queues and https://www.browserless.io/blog/observations-running-headless-browser
- **How often Australian kits filter Mullvad or Proton Sydney exits.** No source. Measure the inconclusive rate.
- **Whether `chrome://sandbox` renders in headless.** Not confirmed. The test plan therefore also checks `/proc/<pid>/status` (Seccomp: 2) of renderer processes.
- **Whether `ip`/iproute2 is in the Playwright image.** Not confirmed. The Dockerfile only shows that `curl` is installed.

## Recommendation

1. **gluetun**: `qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027`.
   - Set `cap_add: [NET_ADMIN]`, `devices: [/dev/net/tun]`, `sysctls: [net.ipv6.conf.all.disable_ipv6=1]`, `restart: unless-stopped`, a `mem_limit` and log rotation, following the project's compose conventions.
   - Put it on its own IPv4-only bridge with a fixed subnet and no other members.
   - Exit: an Australian WireGuard exit (Mullvad Sydney, or Proton Sydney on a paid plan).
   - DNS: `BLOCK_MALICIOUS=off` and `BLOCK_SURVEILLANCE=off`.
   - Firewall: leave `FIREWALL_OUTBOUND_SUBNETS` unset. Never set `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT`.
   - Control server: an API-key `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE`, with `HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:8000`.
2. **Post-rules**: mount a read-only `/iptables/post-rules.txt` that rejects:
   - new connections to the Docker subnet;
   - RFC1918, CGNAT and link-local destinations on wg0;
   - fc00::/7 and fe80::/10.

   Test it, because a failing line makes gluetun open the firewall and exit. Add host INPUT rules on the bridge (accept ESTABLISHED/RELATED, drop new connections). Add the `DNS_BLOCK_IP_PREFIXES` values from Correction 7.
3. **Fetcher**: `mcr.microsoft.com/playwright/python:v1.65.2-noble@sha256:38dd67fc...` with `pip install playwright==1.65.2`.
   - Container settings: `network_mode: service:gluetun`, `user: pwuser`, `init: true`, a seccomp profile allowing userns, `no-new-privileges`, `cap_drop: ALL`, read-only root with tmpfs, `shm_size: 1gb` (or `ipc: host` if Chromium crashes; host IPC is weaker isolation), `mem_limit` and `pids_limit`.
   - Start order: `depends_on: gluetun: {condition: service_healthy, restart: true}`. After any gluetun restart the daemon does on its own, restart the fetcher too, because its namespace goes stale.
4. **Browser**:
   - Launch with `chromium_sandbox=True` and `channel="chromium"`.
   - Context: an Android device profile (Pixel 7 or 8) with the UA rewritten to a reduced `Chrome/<major>.0.0.0` form, `locale="en-AU"`, `timezone_id="Australia/Sydney"`, `service_workers="block"`, `accept_downloads=False`, and a HAR file.
   - Add a route handler that aborts private, loopback, CGNAT and link-local IP literals.
   - Capture a WebP screenshot, `page.url`, the redirect chain and `page.content()`.
   - Treat the network controls as the real boundary and the route handler as defence in depth.
5. **Gating**: pass every isolation test before CyberCheck sends any automatic report. Check `/v1/publicip/ip` (country Australia) at the start of each batch, and fail closed if it doesn't match.
6. **Own VPS**: if you use your own VPS as the VPN server, firewall its FORWARD chain against private, CGNAT, metadata and ULA destinations from wg0 first. This is my analysis, which follows from fact 7.
7. **Monitoring**: add uptime monitors (Uptime Kuma or similar) for gluetun and the fetcher API.

## Open questions

1. Does Ubuntu 26.04's AppArmor userns restriction stop Chromium's namespace sandbox in a `docker-default` container on the target host? Test with `chromium_sandbox=True`, and check `Seccomp: 2` plus a separate user namespace on the renderer processes.
2. Does Chromium 159 run reliably under the 2021 Playwright seccomp profile, or does it need a profile built from the current Docker default?
3. Do queries for local-looking names that gluetun forwards to 127.0.0.11 leave the host outside the VPN? Check with tcpdump on the host's uplink.
4. What fraction of Australian smishing pages return decoys or nothing from Mullvad or Proton datacenter exits? Is a residential Australian exit (a second custom WireGuard endpoint) worth the cost and the ethics or terms-of-service review?
5. How does Chrome's Local Network Access behave under Playwright when nothing grants the permission?
6. Re-check the control-server auth defaults and the DNS variable names when v3.42 is released. Master has already removed the public role and renamed DNS options.
7. Should CyberCheck do its own DNS resolution for scoring (outside the fetcher), so that a phishing domain resolving to a private or CGNAT IP is recorded as a signal rather than hidden by gluetun's filter?
