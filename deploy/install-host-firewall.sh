#!/usr/bin/env bash
# Install the CyberCheck host firewall as a root-owned copy plus a systemd timer (boot + every 15 min).
#   sudo ./deploy/install-host-firewall.sh
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
cd "$(dirname "$0")/.."
install -o root -g root -m 0755 scripts/host-firewall.sh /usr/local/sbin/cybercheck-host-firewall
install -o root -g root -m 0644 deploy/systemd/cybercheck-host-firewall.service deploy/systemd/cybercheck-host-firewall.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cybercheck-host-firewall.timer
systemctl start cybercheck-host-firewall.service
systemctl --no-pager --lines=0 status cybercheck-host-firewall.timer | head -3
iptables -S INPUT | grep ccvpn0
echo "Installed. The rules are re-applied at boot and every 15 minutes."
