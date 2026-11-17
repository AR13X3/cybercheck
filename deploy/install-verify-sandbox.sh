#!/usr/bin/env bash
# Install the weekly fetcher isolation test as a systemd USER timer for the current user (who must be able
# to run docker). Fills in this checkout's path, so the repo can live anywhere.
#   ./deploy/install-verify-sandbox.sh            # as your normal user, NOT with sudo
# For the timer to run while you are logged out:  sudo loginctl enable-linger "$USER"
set -eu
[ "$(id -u)" != 0 ] || { echo "run as your normal user (a user unit), not root" >&2; exit 1; }
cd "$(dirname "$0")/.."
DIR="$(pwd -P)"
case "$DIR" in
    *[[:space:]]*) echo "the checkout path contains whitespace; systemd needs it quoted, move the repo" >&2; exit 1 ;;
esac
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$UNIT_DIR"
sed "s|@CYBERCHECK_DIR@|$DIR|g" deploy/systemd/cybercheck-verify-sandbox.service > "$UNIT_DIR/cybercheck-verify-sandbox.service"
install -m 0644 deploy/systemd/cybercheck-verify-sandbox.timer "$UNIT_DIR/"
systemctl --user daemon-reload
systemctl --user enable --now cybercheck-verify-sandbox.timer
systemctl --user --no-pager list-timers cybercheck-verify-sandbox.timer | head -3
echo "Installed for $DIR. Run it now with: systemctl --user start cybercheck-verify-sandbox.service"
