#!/usr/bin/env bash
# List open PRs awaiting MY review that need a freshly-staged pending review.
# READ-ONLY: just queries GitHub and prints work to do; stages nothing.
#
# Output (TSV): repo<TAB>number<TAB>head_sha<TAB>title
# A PR is emitted only if ALL hold:
#   - it is OPEN and review is requested from me (review-requested:@me),
#   - I have NOT already staged a review for its CURRENT head SHA (state file), and
#   - it has NO existing PENDING review (so we never clobber a review in progress —
#     yours or one we staged earlier for this same head).
# New commits (new head SHA) make a PR eligible again → the review re-stages.
#
#   usage: review_list.sh <gh-notif-workspace-dir>
set -uo pipefail

WS="${1:?usage: review_list.sh <gh-notif-workspace-dir>}"
STATE="$WS/state"; SEEN="$STATE/review-staged.tsv"
mkdir -p "$STATE"; touch "$SEEN"

# Open PRs where review is requested from me, across all repos I can see.
gh search prs --review-requested=@me --state=open --limit 50 \
    --json number,repository,title 2>/dev/null \
  | jq -r '.[] | [.repository.nameWithOwner, (.number|tostring), .title] | @tsv' \
  | while IFS="$(printf '\t')" read -r repo num title; do
      [ -n "$repo" ] && [ -n "$num" ] || continue
      sha="$(gh pr view "$num" -R "$repo" --json headRefOid --jq .headRefOid 2>/dev/null)"
      [ -n "$sha" ] || continue
      key="$repo#$num@$sha"
      grep -qxF "$key" "$SEEN" 2>/dev/null && continue          # already staged for this head
      pend="$(gh api "repos/$repo/pulls/$num/reviews" --paginate \
                --jq '[.[]|select(.state=="PENDING")]|length' 2>/dev/null)"
      [ "${pend:-0}" != "0" ] && continue                       # a pending review exists -> don't clobber
      printf '%s\t%s\t%s\t%s\n' "$repo" "$num" "$sha" "$title"
    done
