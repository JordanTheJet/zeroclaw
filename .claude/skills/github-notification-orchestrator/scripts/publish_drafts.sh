#!/usr/bin/env bash
# Publish local gh-notif triage drafts to a PRIVATE drafts repo so the digest can
# link to rendered summaries (reachable from chat / mobile), and so you can ACCEPT
# a draft (set `status: accepted`) from the repo for the shipper to post.
#
# DRAFT-ONLY: mirrors LOCAL drafts to YOUR OWN PRIVATE repo. It NEVER posts to any
# upstream issue/PR. ADD-ONLY: once a draft is in the repo, the REPO owns it — your
# accept/edits and the shipper's `posted` status are never clobbered; only NEW
# local drafts are added. INDEX.md is regenerated from the repo's OWN items, so it
# reflects accepted/posted state.
#
# Target repo = first line of <workspace>/.drafts-remote  ("owner/repo" or a repo
# URL, optional "#branch"); absent -> publishing disabled (no-op).
#
#   usage: publish_drafts.sh <gh-notif-workspace-dir>
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
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

# ADD-ONLY: never overwrite/delete an item the repo already has (preserves your
# accept/edits + the shipper's posted status). Skip raw snapshots and INDEX.md
# (INDEX is regenerated from the repo's own items just below).
mkdir -p "$CLONE/triage"
rsync -a --ignore-existing \
  --exclude='new.tsv' --exclude='notifications.json' --exclude='notifications.tsv' \
  --exclude='INDEX.md' \
  "$TRIAGE/" "$CLONE/triage/"

# Regenerate each day's INDEX from the REPO's own items (so links + status reflect
# what is actually in the repo, including accepted/posted drafts).
for d in "$CLONE"/triage/*/; do
  [ -d "${d}items" ] && bash "$HERE/build_index.sh" "$d" >/dev/null || true
done

git -C "$CLONE" add -A
if git -C "$CLONE" diff --cached --quiet; then
  echo "publish: no changes to push"
else
  N=$(find "$CLONE/triage" -type f -path '*/items/*' -name '*.md' | wc -l | tr -d ' ')
  git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' \
    commit -q -m "drafts: sync $(date +%F) ($N item drafts)"
  git -C "$CLONE" push -q origin "$BRANCH"
  echo "publish: pushed -> https://github.com/$SLUG ($N item drafts)"
fi
