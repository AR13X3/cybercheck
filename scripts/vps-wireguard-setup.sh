#!/usr/bin/env bash
# CyberCheck: turn a fresh Ubuntu 24.04 VPS (any provider with an Australian region, e.g. an Oracle Cloud
# Always Free instance in Sydney or Melbourne) into the fetcher's VPN exit.
#
# Run FROM the CyberCheck host (never paste it into the VPS by hand):
#     ssh -i ~/.ssh/<your-vps-key> <user>@<VPS_IP> 'sudo bash -s' < scripts/vps-wireguard-setup.sh
#
# What it does on the VPS:
#   - installs WireGuard and nftables; wg0 = 10.13.13.1/24 on UDP 51820, one peer (the CyberCheck fetcher, 10.13.13.2)
#   - forwards ONLY wg0 -> internet, NAT'd. Traffic from the tunnel to private / CGNAT (tailnet) / link-local
#     (cloud metadata 169.254.169.254) / loopback / multicast addresses is dropped, and so is any NEW
#     connection from the tunnel to the VPS itself. A phishing page can reach the internet, nothing else.
#   - no IPv6 forwarding; SSH (key only) and UDP 51820 are the only inbound ports
#   - replaces any image iptables rules (Oracle's Ubuntu images REJECT all forwarding) with this nftables ruleset
# Idempotent: re-running keeps the existing keys.
#
# It prints KEY=VALUE lines for vpn.env at the end (they include the peer's private key: the caller writes
# them into vpn.env, mode 600, and never shows them).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo bash -s)" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard nftables >/dev/null

UPLINK=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}' | head -1)
[ -n "$UPLINK" ] || { echo "cannot find the uplink interface" >&2; exit 1; }

umask 077
mkdir -p /etc/wireguard
cd /etc/wireguard
[ -f server.key ] || wg genkey > server.key
[ -f peer.key ] || wg genkey > peer.key
wg pubkey < server.key > server.pub
wg pubkey < peer.key > peer.pub
[ -f peer.psk ] || wg genpsk > peer.psk

cat > wg0.conf <<EOF
[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = $(cat server.key)

[Peer]
# CyberCheck fetcher (gluetun)
PublicKey = $(cat peer.pub)
PresharedKey = $(cat peer.psk)
AllowedIPs = 10.13.13.2/32
EOF

# forwarding: IPv4 only
cat > /etc/sysctl.d/90-cybercheck-wg.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0
EOF
sysctl -q --system

# Some cloud images (Oracle's Ubuntu, for one) ship iptables rules (netfilter-persistent) that REJECT forwarded
# traffic. Replace them.
if systemctl list-unit-files netfilter-persistent.service >/dev/null 2>&1; then
    systemctl disable --now netfilter-persistent >/dev/null 2>&1 || true
fi
for t in iptables ip6tables; do
    command -v $t >/dev/null || continue
    $t -P INPUT ACCEPT; $t -P FORWARD ACCEPT; $t -P OUTPUT ACCEPT
    $t -F; $t -X; $t -t nat -F 2>/dev/null || true
done
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# CyberCheck VPN exit (scripts/vps-wireguard-setup.sh)
flush ruleset

define BLOCKED4 = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                    192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 }

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        iifname "wg0" drop                       # the tunnel may not open connections to this server
        icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, destination-unreachable,
                      packet-too-big, time-exceeded } accept
        tcp dport 22 accept
        udp dport 51820 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state invalid drop
        iifname "wg0" ip daddr \$BLOCKED4 drop
        iifname "wg0" oifname "$UPLINK" accept
        iifname "$UPLINK" oifname "wg0" ct state established,related accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "$UPLINK" ip saddr 10.13.13.0/24 masquerade
    }
}
EOF
nft -c -f /etc/nftables.conf
systemctl enable --now nftables >/dev/null
nft -f /etc/nftables.conf

systemctl enable wg-quick@wg0 >/dev/null 2>&1
systemctl restart wg-quick@wg0

PUBLIC_IP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
echo "WIREGUARD_ENDPOINT_IP=${PUBLIC_IP}"
echo "WIREGUARD_ENDPOINT_PORT=51820"
echo "WIREGUARD_PUBLIC_KEY=$(cat server.pub)"
echo "WIREGUARD_PRIVATE_KEY=$(cat peer.key)"
echo "WIREGUARD_PRESHARED_KEY=$(cat peer.psk)"
echo "WIREGUARD_ADDRESSES=10.13.13.2/32"
echo "# uplink=$UPLINK wg=$(wg show wg0 listen-port 2>/dev/null) nft=$(nft list ruleset | grep -c drop) drop-rules"
