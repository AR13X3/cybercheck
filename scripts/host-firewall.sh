#!/usr/bin/env bash
# CyberCheck: host-side firewall rules for the fetcher's VPN bridge (ccvpn0).
#
# gluetun ACCEPTs its own Docker subnet, whose gateway IS the host, so the in-container post-rules
# (fetcher/post-rules.txt) reject the fetcher -> host direction. These host INPUT rules are the second
# half: they stop anything on the ccvpn0 bridge from opening a NEW connection to the host, while letting
# replies to the host's own connections (and the published fetcher API) through.
#
# By default this script only PRINTS the rules. Pass --apply to apply them with sudo iptables. It never
# changes anything without --apply.
#
#   ./scripts/host-firewall.sh            # print the rules (dry run)
#   ./scripts/host-firewall.sh --apply    # apply them (needs sudo)
set -u

BRIDGE="${CCVPN_BRIDGE:-ccvpn0}"        # must match fetcher/compose.yaml driver_opts bridge name
APPLY=0
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

# Rule set: accept established/related replies from the bridge, drop every new connection from it to the
# host. BOTH go at the TOP of INPUT (an appended DROP could be shadowed by an earlier broad ACCEPT, e.g.
# from ufw or a local "-j ACCEPT"), the ACCEPT above the DROP. Existing copies are removed first, so
# re-running is idempotent and always restores the right order.
RULES_ACCEPT=(INPUT -i "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT)
RULES_DROP=(INPUT -i "$BRIDGE" -j DROP)

print_rules() {
    echo "# Host INPUT rules for the fetcher bridge ($BRIDGE):"
    echo "while iptables -D ${RULES_ACCEPT[*]} 2>/dev/null; do :; done"
    echo "while iptables -D ${RULES_DROP[*]} 2>/dev/null; do :; done"
    echo "iptables -I ${RULES_DROP[0]} 1 ${RULES_DROP[*]:1}"
    echo "iptables -I ${RULES_ACCEPT[0]} 1 ${RULES_ACCEPT[*]:1}"
}

if [ "$APPLY" -ne 1 ]; then
    print_rules
    echo
    echo "# Dry run. Re-run with --apply to install these rules (uses sudo)."
    exit 0
fi

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    printf 'warning: bridge %s does not exist yet. Start the fetch stack first:\n' "$BRIDGE" >&2
    printf '  docker compose --env-file .env --env-file vpn.env --profile fetch up -d\n' >&2
fi

echo "Applying host INPUT rules for $BRIDGE (sudo)..."
n=0
while sudo iptables -D "${RULES_ACCEPT[@]}" 2>/dev/null; do n=$((n+1)); [ "$n" -gt 50 ] && break; done
n=0
while sudo iptables -D "${RULES_DROP[@]}" 2>/dev/null; do n=$((n+1)); [ "$n" -gt 50 ] && break; done
sudo iptables -I "${RULES_DROP[0]}" 1 "${RULES_DROP[@]:1}" || { echo "failed to insert the DROP rule" >&2; exit 1; }
sudo iptables -I "${RULES_ACCEPT[0]}" 1 "${RULES_ACCEPT[@]:1}" || { echo "failed to insert the ACCEPT rule" >&2; exit 1; }
echo "Done. Current INPUT rules for $BRIDGE (ACCEPT must come before DROP):"
sudo iptables -S INPUT | grep -- "-i $BRIDGE" || true
echo
echo "Note: these rules are not persistent across a reboot unless your host saves iptables (e.g."
echo "netfilter-persistent). Docker recreating the bridge keeps the same name, so re-running is safe."
