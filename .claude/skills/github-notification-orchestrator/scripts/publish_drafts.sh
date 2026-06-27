#!/usr/bin/env bash
# Publish local gh-notif triage binders to a PRIVATE drafts repo so the daily
# digest can link to rendered drafts (reachable from chat / mobile).
#
# DRAFT-ONLY: this mirrors LOCAL draft files to YOUR OWN PRIVATE repo. It NEVER
# posts to any upstream issue/PR. The target repo is read from the first line of
# <workspace>/.drafts-remote  (format: "owner/repo" or a repo URL, optional
# "#branch"); if that file is absent, publishing is disabled (no-op).
#
#   usage: publish_drafts.sh <gh-notif-workspace-dir>
#   e.g.   publish_drafts.sh "$HOME/.zeroclaw/workspace/gh-notif"
set -euo pipefail

WS="${1:?usage: publish_drafts.sh <gh-notif-workspace-dir>}"
TRIAGE="$WS/triage"
CLONE="$WS/drafts-repo"
CONF="$WS/.drafts-remote"

[ -f "$CONF" ] || { echo "publish: no $CONF (publishing disabled); skipping"; exit 0; }
[ -d "$TRIAGE" ] || { echo "publish: no triage dir; nothing to do"; exit 0; }

SLUG="$(head -n1 "$CONF" | tr -d '[:space:]')"
[ -n "$SLUG" ] || { echo "publish: empty $CONF; skipping"; exit 0; }
BRANCH=main
case "$SLUG" in *"#"*) BRANCH="${SLUG#*#}"; SLUG="${SLUG%%#*}";; esac
SLUG="${SLUG#https://github.com/}"; SLUG="${SLUG%.git}"; SLUG="${SLUG#/}"; SLUG="${SLUG%/}"
REMOTE="https://github.com/$SLUG.git"

if [ ! -d "$CLONE/.git" ]; then
  git clone --branch "$BRANCH" "$REMOTE" "$CLONE" 2>/dev/null || git clone "$REMOTE" "$CLONE"
fi
git -C "$CLONE" pull --ff-only --quiet 2>/dev/null || true

# Mirror the triage tree (drafts + INDEX) into the repo; skip raw snapshot files.
mkdir -p "$CLONE/triage"
rsync -a --delete \
  --exclude='new.tsv' --exclude='notifications.json' --exclude='notifications.tsv' \
  "$TRIAGE/" "$CLONE/triage/"

git -C "$CLONE" add -A
if git -C "$CLONE" diff --cached --quiet; then
  echo "publish: no changes to push"
else
  N=$(find "$TRIAGE" -type f -path '*/items/*' -name '*.md' | wc -l | tr -d ' ')
  git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' \
    commit -q -m "drafts: sync $(date +%F) ($N item drafts)"
  git -C "$CLONE" push -q origin "$BRANCH"
  echo "publish: pushed $N item draft(s) -> https://github.com/$SLUG"
fi
