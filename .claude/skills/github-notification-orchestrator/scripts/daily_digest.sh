#!/usr/bin/env bash
# Deterministic daily "notification to-do list" for Discord — NO LLM, NO drafts.
# A concise SUMMARY (not a dump): top review requests + direct asks shown with
# tappable links; the long tail as counts with "see all" links. Pure bash + gh/jq,
# ~0 tokens. Output IS the Discord message (masked links suppress preview cards).
#
#   usage: daily_digest.sh [--reviews N]   (N = how many reviews to list, default 8)
set -uo pipefail
MAXREV=8
[ "${1:-}" = "--reviews" ] && MAXREV="${2:-8}"
DATE="$(date +%F)"
TAB="$(printf '\t')"

reviews="$(gh search prs --review-requested=@me --state=open --limit 60 \
  --json number,title,repository,url \
  --jq '.[] | [.repository.nameWithOwner, (.number|tostring), .url, .title] | @tsv' 2>/dev/null)"

notifs="$(gh api notifications --paginate \
  --jq '.[] | select(.subject.url != null)
        | [ .reason, .repository.full_name,
            (.subject.url | sub("https://api.github.com/repos/";"https://github.com/") | sub("/pulls/";"/pull/")),
            .subject.title ] | @tsv' 2>/dev/null)"

rc="$(printf '%s' "$reviews" | grep -c .)"
# direct = someone needs YOU (mentioned or assigned). review_requested is already in
# the Reviews section above; everything else (author/comment/ci/subscribed) is the tail.
direct="$(printf '%s\n' "$notifs" | grep -E "^(mention|assign)$TAB" )"
tail_n="$(printf '%s\n' "$notifs" | grep -vE "^(mention|assign|review_requested)$TAB" | grep -c .)"
dc="$(printf '%s' "$direct" | grep -c .)"
MAXDIRECT=6

{
  printf '**📋 GitHub to-do — %s**\n' "$DATE"
  printf '🔍 %s reviews requested · 💬 %s direct asks · 📄 %s threads active\n' "$rc" "$dc" "${tail_n:-0}"

  if [ -n "$reviews" ]; then
    printf '\n**🔍 Reviews requested from you** — top %s of %s → [see all](<https://github.com/pulls/review-requested>)\n' "$MAXREV" "$rc"
    printf '%s\n' "$reviews" | head -n "$MAXREV" | while IFS="$TAB" read -r repo num url title; do
      [ -n "$url" ] && printf '• [%s#%s](<%s>) — %s\n' "$repo" "$num" "$url" "$title"
    done
  fi

  if [ -n "$direct" ]; then
    printf '\n**💬 Needs your response** — top %s of %s\n' "$( [ "$dc" -lt "$MAXDIRECT" ] && echo "$dc" || echo "$MAXDIRECT")" "$dc"
    printf '%s\n' "$direct" | sort -t"$TAB" -k1,1 | head -n "$MAXDIRECT" | while IFS="$TAB" read -r reason repo url title; do
      [ -n "$url" ] && printf '• `%s` [%s](<%s>) — %s\n' "$reason" "$repo" "$url" "$title"
    done
    [ "$dc" -gt "$MAXDIRECT" ] && printf '…and %s more → [inbox](<https://github.com/notifications>)\n' "$((dc - MAXDIRECT))"
  fi

  [ "${tail_n:-0}" -gt 0 ] && printf '\n📄 %s more threads with activity on your/subscribed items → [inbox](<https://github.com/notifications>)\n' "$tail_n"
  [ -z "$reviews$notifs" ] && printf '\n✅ Inbox clear — nothing awaiting you.\n'

  printf '\n_`/gh review #N` opus review · `/gh reply #N` draft comment · `/gh clear resolved` tidy_\n'
}
