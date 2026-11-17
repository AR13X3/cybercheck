#!/usr/bin/env bash
# Put the Anthropic API key into .env without it appearing on screen or in shell history.
#   ./scripts/set-ai-key.sh
set -eu
cd "$(dirname "$0")/.."
printf 'Paste the Anthropic API key (it will not be shown), then press Enter: '
IFS= read -rs KEY
echo
KEY="$(printf '%s' "$KEY" | tr -d '[:space:]')"
case "$KEY" in
  sk-ant-*) ;;
  "") echo "Nothing pasted; .env unchanged."; exit 1 ;;
  *) echo "That does not look like an Anthropic key (they start with sk-ant-); .env unchanged."; exit 1 ;;
esac
KEY="$KEY" python3 - <<'EOF'
import os, re
p = ".env"
t = open(p).read()
line = "ANTHROPIC_API_KEY=" + os.environ["KEY"]
t = re.sub(r"(?m)^ANTHROPIC_API_KEY=.*$", lambda m: line, t) if re.search(r"(?m)^ANTHROPIC_API_KEY=", t) else t.rstrip("\n") + "\n" + line + "\n"
open(p, "w").write(t)
EOF
chmod 600 .env
unset KEY
echo "Saved to .env (key ending ...$(grep '^ANTHROPIC_API_KEY=' .env | tail -c 5)). Restart the stack to use it: docker compose up -d"
