#!/usr/bin/env bash
# Publish the CyberCheck blocklist files to a public git repository.
#
#   BLOCKLIST_PUBLISH_CONFIRMED=yes BLOCKLIST_GIT_DIR=/path/to/blocklist-repo scripts/publish-blocklist.sh
#
# Publishing makes the list public, so this refuses to run unless the owner has opted in with
# BLOCKLIST_PUBLISH_CONFIRMED=yes. It copies only the blocklist files into the checkout, commits only
# those files, and pushes only that one commit (current branch to its upstream, no tags, no force).
# It refuses if the checkout has staged changes or local commits that are not on the remote yet.
#
# It also refuses while the files say "License: not yet decided": a public list needs terms. Set
# BLOCKLIST_LICENSE (read by the worker) first. Domains found in ICANN CZDS zone files are only in the
# files when the worker runs with BLOCKLIST_CZDS_TERMS_OK=yes, and that may be set only when the licence
# forbids recipients the CZDS terms s1.1 uses (marketing, high-volume queries to registries and
# registrars): the s1.6 value-added exception for redistributing zone-derived names depends on it.
#
# Settings (environment only; this script never reads .env):
#   BLOCKLIST_PUBLISH_CONFIRMED  must be exactly "yes"
#   BLOCKLIST_GIT_DIR            top folder of a local clone of the public blocklist repository
#   BLOCKLIST_SRC_DIR            where the worker writes the files (default: <CyberCheck>/data/blocklist)
set -euo pipefail
umask 022

FILES=(hosts.txt adguard.txt domains.txt dnsmasq.conf unbound.conf rpz.zone blocklist.json)
TITLE="CyberCheck Australian phishing blocklist"

die() { echo "publish-blocklist: $*" >&2; exit 1; }

[[ "${BLOCKLIST_PUBLISH_CONFIRMED:-}" == "yes" ]] \
  || die "refusing to publish: this makes the blocklist public. Set BLOCKLIST_PUBLISH_CONFIRMED=yes to opt in."

command -v git >/dev/null || die "git is not installed"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SRC="${BLOCKLIST_SRC_DIR:-$ROOT/data/blocklist}"
DEST="${BLOCKLIST_GIT_DIR:-}"
[[ -n "$DEST" ]] || die "BLOCKLIST_GIT_DIR is not set"
[[ -d "$DEST" ]] || die "BLOCKLIST_GIT_DIR ($DEST) is not a folder"
[[ -d "$SRC" ]] || die "blocklist folder $SRC not found (has the blocklist job run?)"
DEST="$(cd "$DEST" && pwd -P)"
SRC="$(cd "$SRC" && pwd -P)"

# The target must be its own repository, never CyberCheck itself or anything inside it.
case "$DEST/" in "$ROOT"/*) die "BLOCKLIST_GIT_DIR must be a separate repository outside $ROOT" ;; esac
case "$ROOT/" in "$DEST"/*) die "BLOCKLIST_GIT_DIR must not contain $ROOT" ;; esac
top="$(git -C "$DEST" rev-parse --show-toplevel 2>/dev/null)" || die "$DEST is not a git checkout"
[[ "$(cd "$top" && pwd -P)" == "$DEST" ]] || die "BLOCKLIST_GIT_DIR must be the top folder of the checkout ($top)"

# Source files must all exist and look like ours; targets must be plain files (no symlink tricks).
for f in "${FILES[@]}"; do
  s="$SRC/$f"; d="$DEST/$f"
  [[ -f "$s" && ! -L "$s" && -s "$s" ]] || die "missing or empty $s"
  grep -qF "$TITLE" "$s" || die "$s does not look like a CyberCheck blocklist file"
  [[ ! -L "$d" ]] || die "$d is a symlink, refusing"
  [[ ! -e "$d" || -f "$d" ]] || die "$d exists and is not a regular file"
  ! grep -qiF "not yet decided" "$s" \
    || die "$s has no licence yet (License: not yet decided). Set BLOCKLIST_LICENSE for the worker and rebuild first."
done

cd "$DEST"
gitdir="$(git rev-parse --absolute-git-dir)"
if command -v flock >/dev/null; then
  exec 9>"$gitdir/cybercheck-publish.lock"
  flock -n 9 || die "another publish is running"
fi

branch="$(git symbolic-ref --quiet --short HEAD)" || die "the checkout is on a detached HEAD"
remote="$(git config --get "branch.$branch.remote" || true)"
merge_ref="$(git config --get "branch.$branch.merge" || true)"
[[ -n "$remote" && -n "$merge_ref" && "$remote" != "." ]] \
  || die "branch $branch has no remote upstream (git branch --set-upstream-to=origin/$branch)"
[[ "$(git config --get "remote.$remote.mirror" || true)" != "true" ]] || die "remote $remote is a mirror, refusing"

is_ours() { local p="$1" f; for f in "${FILES[@]}"; do [[ "$p" == "$f" ]] && return 0; done; return 1; }
while IFS= read -r p; do
  [[ -z "$p" ]] || is_ours "$p" || die "the checkout has other staged changes ($p); refusing to commit anything but the blocklist files"
done < <(git diff --cached --name-only)
git fetch --quiet "$remote"
git merge --ff-only --quiet '@{upstream}' || die "could not fast-forward $branch to its upstream"
ahead="$(git rev-list --count '@{upstream}..HEAD')"
[[ "$ahead" == 0 ]] || die "$branch has $ahead local commit(s) not on the remote; refusing to push anything but the blocklist update"

tmp=""
cleanup() { if [[ -n "$tmp" ]]; then rm -f -- "$tmp"; fi; }
trap cleanup EXIT
for f in "${FILES[@]}"; do
  tmp="$(mktemp "$DEST/.$f.XXXXXX")"
  cp -- "$SRC/$f" "$tmp"
  chmod 644 "$tmp"
  mv -f -- "$tmp" "$DEST/$f"
  tmp=""
done

git add -- "${FILES[@]}"
if git diff --cached --quiet; then
  echo "publish-blocklist: no changes"
  exit 0
fi

while IFS= read -r p; do
  [[ -z "$p" ]] || is_ours "$p" || die "unexpected staged file $p, refusing"
done < <(git diff --cached --name-only)

count="$(grep -Ecv '^(#|$)' domains.txt || true)"
git commit --quiet -m "Update blocklist: $count domains ($(date -u '+%Y-%m-%d %H:%M UTC'))" -- "${FILES[@]}"

# Check exactly one new commit that only touches the blocklist files, then push just that.
[[ "$(git rev-list --count '@{upstream}..HEAD')" == 1 ]] || die "unexpected commits to push, refusing"
while IFS= read -r p; do
  [[ -z "$p" ]] || is_ours "$p" || { git reset --quiet --soft HEAD~1; die "commit touched $p, undone"; }
done < <(git diff-tree --no-commit-id --name-only -r HEAD)

git push --quiet --no-follow-tags "$remote" "HEAD:$merge_ref"
echo "publish-blocklist: pushed $count domains to $remote ($merge_ref)"
