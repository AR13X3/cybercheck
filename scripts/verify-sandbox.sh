#!/usr/bin/env bash
# CyberCheck: prove the sandboxed fetcher is actually isolated, then (only if every test passes) write
# data/sandbox_verified.json. Automatic reporting requires that file to exist and be <= 30 days old.
#
# Run on the HOST that runs the stack, from anywhere, after the fetch stack is up:
#     docker compose --env-file .env --env-file vpn.env --profile fetch up -d
#     ./scripts/verify-sandbox.sh
#
# It runs the checks INSIDE the running containers (docker compose exec). It never changes the firewall;
# scripts/host-firewall.sh does that. The kill-switch test briefly STOPS the VPN through the gluetun
# control server and starts it again (a trap restarts it if the script is interrupted).
#
# Contract (shared with the reporting module): on success it writes
#     {"verified_at": ISO8601 UTC, "egress_ip": str, "egress_country": str, "tests_passed": int}
# and on ANY failure it deletes the file.
#
# Env: FETCH_EXPECTED_COUNTRY (default AU; empty skips the country check), DOCKER_COMPOSE (override the
# compose command), HOME_IP (skip the host-side what-is-my-ip lookup), TAILNET_IP (this host's Tailscale
# IPv4; default: `tailscale ip -4` when Tailscale is installed, otherwise the tailnet-IP checks are skipped).
set -u

cd "$(dirname "$0")/.." || exit 2
OUT="data/sandbox_verified.json"
EXPECTED_COUNTRY="$(printf '%s' "${FETCH_EXPECTED_COUNTRY-AU}" | tr '[:lower:]' '[:upper:]')"
ENVFILES=""
[ -f .env ] && ENVFILES="$ENVFILES --env-file .env"
[ -f vpn.env ] && ENVFILES="$ENVFILES --env-file vpn.env"
# shellcheck disable=SC2086
DC="${DOCKER_COMPOSE:-docker compose $ENVFILES --profile fetch}"
FETCH="$DC exec -T fetcher"
VPN="$DC exec -T vpn"
CCVPN_GATEWAY="172.29.254.1"      # must match fetcher/compose.yaml networks.ccvpn.ipam.gateway
CCVPN_SUBNET="172.29.254.0/28"
IP_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

passed=0
failed=0
vpn_stopped=0

note()  { printf '  %s\n' "$*"; }
ok()    { passed=$((passed+1)); printf '  [PASS] %s\n' "$*"; }
bad()   { failed=$((failed+1)); printf '  [FAIL] %s\n' "$*"; }

restore_vpn() {
    if [ "$vpn_stopped" -eq 1 ]; then
        $FETCH sh -c 'curl -s -m 10 -o /dev/null -X PUT -H "X-API-Key: $GLUETUN_API_KEY" -H "Content-Type: application/json" -d "{\"status\":\"running\"}" http://127.0.0.1:8000/v1/vpn/status' >/dev/null 2>&1
        vpn_stopped=0
    fi
}
trap 'restore_vpn; rm -f "$OUT" 2>/dev/null; printf "\nInterrupted: deleted %s\n" "$OUT"; exit 130' INT TERM

fail_out() {
    restore_vpn
    printf '\nFAILED: %s\n' "$1"
    rm -f "$OUT" 2>/dev/null
    printf 'Deleted %s (automatic reporting stays disabled).\n' "$OUT"
    exit 1
}

# Passes only if curl, run INSIDE the fetcher, could not connect: exit 7 (refused / unreachable, which
# is what a REJECT gives) or 28 (timed out, which is what a DROP gives). Anything else, including 0
# (it answered), 52/56 (a connection was made), or a docker/exec error, is a failure.
unreachable() {
    local target="$1" label="$2" rc
    $FETCH sh -c "curl -s -m 5 -o /dev/null \"\$1\"" sh "$target" >/dev/null 2>&1
    rc=$?
    case "$rc" in
        7|28) ok "blocked: $label ($target)" ;;
        0)    bad "REACHABLE: $label ($target)" ;;
        *)    bad "unexpected result for $label ($target): exit $rc (connection made, or exec failed)" ;;
    esac
}

json_field() {   # json_field <name>  (reads JSON on stdin; flat string fields only)
    grep -o "\"$1\":\"[^\"]*\"" | head -n1 | cut -d'"' -f4
}

echo "== preconditions =="
if ! $FETCH sh -c 'command -v curl >/dev/null' >/dev/null 2>&1; then
    fail_out "cannot exec into the fetcher container (is the fetch stack up? run from the repo with vpn.env present)"
fi
if ! $VPN sh -c 'command -v iptables >/dev/null' >/dev/null 2>&1; then
    fail_out "cannot exec into the vpn (gluetun) container"
fi
note "fetcher and vpn containers reachable"

echo
echo "== the fetcher container holds no app secrets =="
leaks="$($FETCH sh -c 'env | cut -d= -f1 | grep -E "^(DATABASE_URL|ANTHROPIC_API_KEY|NETCRAFT_API_KEY|TELEGRAM_BOT_TOKEN|CZDS_PASSWORD|CZDS_USERNAME|SMTP_PASSWORD|WIREGUARD_PRIVATE_KEY|WIREGUARD_PRESHARED_KEY|OPENVPN_PASSWORD)$"' 2>/dev/null)"
if [ -z "$leaks" ]; then ok "no DATABASE_URL / API keys / VPN keys in the fetcher environment"
else bad "secrets present in the fetcher environment: $(printf '%s' "$leaks" | tr '\n' ' ')"; fi
if $FETCH sh -c '[ "$(id -u)" != "0" ]' >/dev/null 2>&1; then ok "fetcher runs as a non-root user"
else bad "fetcher runs as root"; fi

echo
echo "== positive control: egress works and goes through the VPN =="
IPJSON="$($FETCH sh -c 'curl -s -m 10 -H "X-API-Key: $GLUETUN_API_KEY" http://127.0.0.1:8000/v1/publicip/ip' 2>/dev/null)"
EGRESS_IP="$(printf '%s' "$IPJSON" | json_field public_ip)"
EGRESS_COUNTRY="$(printf '%s' "$IPJSON" | json_field country)"
if ! printf '%s' "$EGRESS_IP" | grep -Eq "$IP_RE"; then
    fail_out "could not read the VPN egress IP from the gluetun control server"
fi
EGRESS_COUNTRY="$(printf '%s' "$EGRESS_COUNTRY" | tr -cd 'A-Za-z .-' | cut -c1-40)"
ok "VPN egress IP (gluetun): $EGRESS_IP (${EGRESS_COUNTRY:-unknown})"

# What the fetcher's own traffic actually looks like from outside.
SEEN_IP="$($FETCH sh -c 'curl -s -m 15 https://ipinfo.io/ip || curl -s -m 15 https://ifconfig.me' 2>/dev/null | tr -d '[:space:]')"
if printf '%s' "$SEEN_IP" | grep -Eq "$IP_RE"; then
    if [ "$SEEN_IP" = "$EGRESS_IP" ]; then ok "fetcher traffic leaves from the VPN exit ($SEEN_IP)"
    else bad "fetcher traffic leaves from $SEEN_IP, not the VPN exit $EGRESS_IP"; fi
else
    bad "could not load a what-is-my-ip page through the tunnel"
fi

HOME_IP="${HOME_IP:-}"
if [ -z "$HOME_IP" ]; then
    HOME_IP="$(curl -s -m 10 https://ipinfo.io/ip 2>/dev/null || curl -s -m 10 https://ifconfig.me 2>/dev/null || true)"
fi
HOME_IP="$(printf '%s' "$HOME_IP" | tr -d '[:space:]')"
if printf '%s' "$HOME_IP" | grep -Eq "$IP_RE"; then
    if [ "$HOME_IP" = "$EGRESS_IP" ] || [ "$HOME_IP" = "$SEEN_IP" ]; then
        bad "the fetcher's egress IP equals the home IP ($HOME_IP): traffic is NOT going through the VPN"
    else ok "egress IP differs from the home IP"; fi
else
    bad "could not determine the home IP from the host (set HOME_IP=... to supply it); cannot prove the egress differs"
fi

if [ -n "$EXPECTED_COUNTRY" ]; then
    uc="$(printf '%s' "$EGRESS_COUNTRY" | tr '[:lower:]' '[:upper:]')"
    if [ "$uc" = "$EXPECTED_COUNTRY" ] || { [ "$EXPECTED_COUNTRY" = "AU" ] && [ "$uc" = "AUSTRALIA" ]; }; then
        ok "egress country matches $EXPECTED_COUNTRY"
    else
        bad "egress country is '$EGRESS_COUNTRY', expected $EXPECTED_COUNTRY"
    fi
else
    note "FETCH_EXPECTED_COUNTRY is empty: country check skipped"
fi

echo
echo "== DNS is the VPN's and IPv6 is off =="
if $FETCH sh -c 'grep -Eq "^nameserver 127\.0\.0\.1$" /etc/resolv.conf && [ "$(grep -c "^nameserver" /etc/resolv.conf)" = "1" ]'; then
    ok "resolv.conf has only gluetun's 127.0.0.1 resolver"
else bad "resolv.conf is not gluetun's alone (DNS may bypass the VPN)"; fi
if $FETCH sh -c 'curl -s -m 10 -o /dev/null https://example.com/'; then ok "public names resolve and load through the tunnel"
else bad "could not resolve/load a known-good public site through the tunnel"; fi
# Filtering upstreams (gluetun's "quad9" = 9.9.9.9, "cloudflare security", ...) answer NXDOMAIN for
# domains on threat feeds, i.e. the phishing domains we track, which would be recorded as taken down.
DNS_UP="$($VPN sh -c 'printf "%s" "${DNS_UPSTREAM_RESOLVERS-}"' 2>/dev/null)"
bad_up=""
[ -n "$DNS_UP" ] || bad_up=" (DNS_UPSTREAM_RESOLVERS is not set)"
set -f
OLDIFS=$IFS
IFS=','
for r in $DNS_UP; do
    r="$(printf '%s' "$r" | tr '[:upper:]' '[:lower:]' | sed 's/^ *//; s/ *$//')"
    case "$r" in
        cloudflare|google|"quad9 unsecured") ;;
        *) bad_up="$bad_up '$r'" ;;
    esac
done
IFS=$OLDIFS
set +f
if [ -z "$bad_up" ]; then ok "gluetun DNS upstreams are unfiltered resolvers only ($DNS_UP)"
else bad "gluetun DNS upstreams are not all unfiltered resolvers:$bad_up (filtering ones hide phishing domains)"; fi
BLOCK_MAL="$($VPN sh -c 'printf "%s" "${BLOCK_MALICIOUS-}"' 2>/dev/null | tr '[:upper:]' '[:lower:]')"
if [ "$BLOCK_MAL" = "off" ]; then ok "gluetun's malicious-domain blocklist is off"
else bad "gluetun BLOCK_MALICIOUS is '$BLOCK_MAL' (must be off: the blocklist hides phishing domains)"; fi
if $FETCH sh -c '[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]'; then ok "IPv6 is disabled in the namespace"
else bad "IPv6 is not disabled in the namespace"; fi
if $FETCH sh -c '[ -z "$(awk "\$6 != \"lo\"" /proc/net/if_inet6 2>/dev/null)" ]'; then ok "no IPv6 address on any non-loopback interface"
else bad "an interface has an IPv6 address"; fi

echo
echo "== the fetcher cannot reach the LAN, host, tailnet, Postgres or metadata =="
HOST_GW="$(ip -4 route show default 2>/dev/null | awk '/^default/ {print $3; exit}')"
HOST_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
if [ -n "${HOST_GW:-}" ]; then unreachable "http://$HOST_GW/" "home LAN gateway"
else bad "could not detect the home LAN gateway on the host (ip route)"; fi
if [ -n "${HOST_IP:-}" ]; then
    unreachable "http://$HOST_IP/" "this host's LAN IP"
    unreachable "http://$HOST_IP:5432/" "Postgres via this host's LAN IP"
else bad "could not detect this host's LAN IP (ip route get)"; fi
unreachable "http://192.168.0.1/"            "192.168.0.1"
unreachable "http://192.168.1.1/"            "192.168.1.1"
unreachable "http://10.0.0.1/"               "10.0.0.1"
unreachable "http://172.17.0.1/"             "172.17.0.1 (default docker bridge = host)"
unreachable "http://172.17.0.1:5432/"        "Postgres via the default docker bridge"
unreachable "http://$CCVPN_GATEWAY/"         "the vpn bridge gateway (= host)"
unreachable "http://$CCVPN_GATEWAY:5432/"    "Postgres via the vpn bridge gateway"
unreachable "http://$CCVPN_GATEWAY:22/"      "SSH via the vpn bridge gateway"
unreachable "http://127.0.0.1:5432/"         "127.0.0.1:5432 inside the namespace (must not be the host's Postgres)"
TAILNET_IP="${TAILNET_IP:-}"
if [ -z "$TAILNET_IP" ] && command -v tailscale >/dev/null 2>&1; then
    TAILNET_IP="$(tailscale ip -4 2>/dev/null | head -n1)"
fi
TAILNET_IP="$(printf '%s' "$TAILNET_IP" | tr -d '[:space:]')"
if printf '%s' "$TAILNET_IP" | grep -Eq "$IP_RE"; then
    unreachable "http://$TAILNET_IP/"         "this host's tailnet IP"
    unreachable "http://$TAILNET_IP:5432/"    "Postgres via this host's tailnet IP"
    unreachable "http://$TAILNET_IP:22/"      "SSH via this host's tailnet IP"
else
    note "no tailnet IP (set TAILNET_IP=... or install Tailscale): tailnet-IP checks skipped"
fi
unreachable "http://100.100.100.100/"        "tailnet MagicDNS"
unreachable "http://169.254.169.254/"        "cloud metadata"
# IPv6 targets: IPv6 is off, so any non-zero curl exit other than an exec failure counts as blocked.
$FETCH sh -c 'curl -6 -s -m 5 -o /dev/null "http://[fd7a:115c:a1e0::1]/"' >/dev/null 2>&1
rc=$?
case "$rc" in
    0)           bad "REACHABLE: tailnet IPv6 fd7a:115c:a1e0::1" ;;
    125|126|127) bad "could not run the IPv6 test (exit $rc)" ;;
    *)           ok "blocked: tailnet IPv6 fd7a:115c:a1e0::1 (exit $rc)" ;;
esac

echo
echo "== gluetun control server rejects unauthenticated requests =="
code="$($FETCH sh -c 'curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/v1/vpn/status' 2>/dev/null)"
if [ "$code" = "401" ]; then ok "control server requires the API key (401 without it)"
else bad "control server returned '$code' without a key (expected 401)"; fi
code="$($FETCH sh -c 'curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/openvpn/actions/restart' 2>/dev/null)"
if [ "$code" = "401" ]; then ok "legacy GET control route also protected (401)"
else bad "legacy control route returned '$code' (expected 401)"; fi

echo
echo "== firewall: policy DROP with the post-rules in place =="
RULES="$($VPN sh -c 'iptables -S OUTPUT' 2>/dev/null)"
if printf '%s\n' "$RULES" | grep -q -- "^-P OUTPUT DROP"; then ok "OUTPUT policy is DROP"
else bad "OUTPUT policy is not DROP (kill switch not armed)"; fi
for net in "$CCVPN_SUBNET" 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do
    if printf '%s\n' "$RULES" | grep -q -- "-d $net .*-j REJECT"; then ok "post-rule REJECT for $net is loaded"
    else bad "post-rule REJECT for $net is missing"; fi
done
if $VPN sh -c 'iptables -S INPUT' 2>/dev/null | grep -q -- "^-P INPUT DROP"; then ok "INPUT policy is DROP"
else bad "INPUT policy is not DROP"; fi

echo
echo "== Chromium starts WITH its sandbox, through the fetcher API =="
FJSON="$($FETCH sh -c 'curl -s -m 90 -H "Authorization: Bearer $FETCHER_TOKEN" -H "Content-Type: application/json" -d "{\"url\":\"https://example.com/\",\"profile\":\"mobile\"}" http://127.0.0.1:8432/fetch' 2>/dev/null)"
if printf '%s' "$FJSON" | grep -q '"ok":true' && printf '%s' "$FJSON" | grep -q '"http_status":200'; then
    ok "fetcher API fetched https://example.com/ through the VPN"
else
    bad "fetcher API could not fetch https://example.com/ ($(printf '%s' "$FJSON" | json_field error | cut -c1-160))"
fi
# The browser stays up between fetches. Scan /proc (procps may not be in the image).
CMDS="$($FETCH sh -c 'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline" 2>/dev/null; echo; done' 2>/dev/null)"
if printf '%s\n' "$CMDS" | grep -qiE 'chrom(e|ium)'; then
    if printf '%s\n' "$CMDS" | grep -Eq -- '--no-sandbox( |$)'; then bad "a Chromium process runs with --no-sandbox"
    else ok "Chromium is running and no process has --no-sandbox"; fi
else
    bad "no Chromium process found after a fetch (cannot confirm the sandbox)"
fi

echo
echo "== kill switch: with the VPN stopped, nothing leaves =="
code="$($FETCH sh -c 'curl -s -m 10 -o /dev/null -w "%{http_code}" -X PUT -H "X-API-Key: $GLUETUN_API_KEY" -H "Content-Type: application/json" -d "{\"status\":\"stopped\"}" http://127.0.0.1:8000/v1/vpn/status' 2>/dev/null)"
if [ "$code" = "200" ]; then
    vpn_stopped=1
    sleep 4
    LEAK="$($FETCH sh -c 'curl -s -m 8 https://ipinfo.io/ip' 2>/dev/null | tr -d '[:space:]')"
    if [ -z "$LEAK" ]; then ok "with the VPN stopped the fetcher reaches nothing"
    elif [ "$LEAK" = "$HOME_IP" ]; then bad "LEAK: with the VPN stopped the fetcher reached the internet from the HOME IP ($LEAK)"
    else bad "with the VPN stopped the fetcher still reached the internet as $LEAK (VPN auto-restarted?); kill switch not proven, re-run"; fi
    HCODE="$($FETCH sh -c 'curl -s -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FETCHER_TOKEN" http://127.0.0.1:8432/health' 2>/dev/null)"
    # The fetcher caches the egress check for 60 s; it must fail closed within ~70 s.
    tries=0
    while [ "$HCODE" != "503" ] && [ "$tries" -lt 8 ]; do
        sleep 10; tries=$((tries+1))
        HCODE="$($FETCH sh -c 'curl -s -m 10 -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FETCHER_TOKEN" http://127.0.0.1:8432/health' 2>/dev/null)"
    done
    if [ "$HCODE" = "503" ]; then ok "fetcher API fails closed (503) while the VPN is down"
    else bad "fetcher API did not fail closed with the VPN down (health returned '$HCODE')"; fi
    restore_vpn
    back=0
    for _ in $(seq 1 18); do
        sleep 5
        st="$($FETCH sh -c 'curl -s -m 5 -H "X-API-Key: $GLUETUN_API_KEY" http://127.0.0.1:8000/v1/vpn/status' 2>/dev/null)"
        if printf '%s' "$st" | grep -q '"running"'; then back=1; break; fi
    done
    if [ "$back" -eq 1 ]; then ok "VPN restarted after the kill-switch test"
    else bad "VPN did not come back after the kill-switch test (check: docker compose logs vpn)"; fi
else
    bad "could not stop the VPN through the control server for the kill-switch test (HTTP '$code')"
fi

echo
echo "-------------------------------------------------------------"
printf 'passed=%d  failed=%d\n' "$passed" "$failed"
if [ "$failed" -ne 0 ] || [ "$passed" -lt 20 ]; then
    fail_out "$failed isolation test(s) failed"
fi

VERIFIED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p data
tmp="$OUT.tmp.$$"
printf '{"verified_at":"%s","egress_ip":"%s","egress_country":"%s","tests_passed":%d}\n' \
    "$VERIFIED_AT" "$EGRESS_IP" "${EGRESS_COUNTRY:-unknown}" "$passed" > "$tmp" && chmod 644 "$tmp" && mv "$tmp" "$OUT" \
    || fail_out "could not write $OUT"
printf 'All checks passed. Wrote %s (%d tests). Automatic reporting is permitted for 30 days.\n' "$OUT" "$passed"
