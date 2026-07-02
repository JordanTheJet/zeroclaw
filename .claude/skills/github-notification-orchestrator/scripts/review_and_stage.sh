#!/usr/bin/env bash
# Opus-review a review-requested PR and STAGE it as a pending GitHub review.
# Shared engine for (a) the once-a-day cron (auto-picks the backlog) and (b) the
# on-demand `/gh review #N` skill (a specific PR). The verdict is never submitted —
# it stages a pending review; you Submit Approve/Request-changes/Comment in GitHub.
#
#   review_and_stage.sh <ws>                      # auto-pick the next un-reviewed PR
#   review_and_stage.sh <ws> <owner/repo> <num>   # review a specific PR
#   ... --verify                                  # also run the opus verifier gate
#
# The review body is produced by the opus `gh_notif_pr_reviewer` agent (run as a
# one-shot subprocess), optionally checked by `gh_notif_verifier`. No LLM is in the
# posting path (stage_review.sh is deterministic).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

WS="${1:?usage: review_and_stage.sh <ws> [<owner/repo> <num>] [--verify]}"; shift
REPO=""; NUM=""; VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) VERIFY=1;;
    */*)      REPO="$1";;
    *[0-9]*)  NUM="$1";;
  esac
  shift
done

# pick the target
if [ -z "$REPO" ] || [ -z "$NUM" ]; then
  IFS="$(printf '\t')" read -r REPO NUM SHA _REST < <(bash "$HERE/review_list.sh" "$WS" | head -1)
  [ -n "${REPO:-}" ] && [ -n "${NUM:-}" ] || { echo "review_and_stage: nothing awaiting review"; exit 0; }
else
  SHA="$(gh pr view "$NUM" -R "$REPO" --json headRefOid --jq .headRefOid 2>/dev/null)"
fi
echo "review_and_stage: $REPO#$NUM (head ${SHA:-?})"

RPROMPT="Review pull request $REPO#$NUM. Use READ-ONLY gh only (gh pr view $NUM -R $REPO --json title,body,author,additions,deletions,changedFiles ; gh pr diff $NUM -R $REPO ; gh pr view $NUM -R $REPO --comments). Write a PR REVIEW BODY the human can submit verbatim: a 1-2 sentence summary, then findings as bullets tagged [blocking]/[non-blocking]/[nit] each grounded in a specific file:line, and note what is good. Be concise. Reply with ONLY the review body markdown — no preamble, no 'here is', nothing else."

body="$(zeroclaw agent -a gh_notif_pr_reviewer -m "$RPROMPT" 2>/dev/null)"
[ -n "$(printf '%s' "$body" | tr -d '[:space:]')" ] || { echo "review_and_stage: reviewer produced no body — skipping"; exit 1; }

if [ "$VERIFY" = 1 ]; then
  VPROMPT="Here is a draft review for PR $REPO#$NUM:

$body

Adversarially verify each claim against the live PR using READ-ONLY gh. Return the FINAL corrected review body — drop or fix any unsupported/overstated claim, keep it concise and fair. Reply with ONLY the final review body markdown, nothing else."
  vbody="$(zeroclaw agent -a gh_notif_verifier -m "$VPROMPT" 2>/dev/null)"
  [ -n "$(printf '%s' "$vbody" | tr -d '[:space:]')" ] && body="$vbody"
fi

printf '%s' "$body" | bash "$HERE/stage_review.sh" --repo "$REPO" --pr "$NUM" --post --skip-if-pending
rc=$?
if [ "$rc" -eq 0 ]; then
  mkdir -p "$WS/state"
  printf '%s#%s@%s\n' "$REPO" "$NUM" "${SHA:-}" >> "$WS/state/review-staged.tsv"
fi
exit "$rc"
