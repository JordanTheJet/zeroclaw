#!/usr/bin/env bash
# Stage a PENDING pull-request review on GitHub — pure bash, no Python.
#
# This is the safe, copy-paste-free path for PR reviews: it creates a review in
# the **PENDING** state (POST a review with NO `event`), which GitHub shows only
# to YOU, pre-filled in the PR's review box. You open the PR, edit if you like,
# and pick Approve / Request-changes / Comment and Submit — all in GitHub's own
# UI. The verdict + the public submit are 100% yours; this script NEVER submits a
# verdict and never posts anything other people can see. There is no draft repo.
#
# The review body comes from stdin (or --body-file) — the on-demand drafter pipes
# the freshly-written review notes straight in; nothing is stored in a repo.
#
# SAFE BY DEFAULT: dry-run unless --post. Idempotent: GitHub allows only one
# pending review per PR per user, so --post replaces any existing pending review
# (delete + recreate) rather than erroring.
#
#   usage:
#     stage_review.sh --repo OWNER/REPO --pr N            # dry-run (shows what it would stage)
#     printf '%s' "$BODY" | stage_review.sh --repo O/R --pr N --post
#     stage_review.sh --repo O/R --pr N --body-file notes.md --post
set -uo pipefail

REPO=""; PR=""; BODYFILE="-"; POST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)      REPO="${2:-}"; shift;;
    --pr)        PR="${2:-}"; shift;;
    --body-file) BODYFILE="${2:-}"; shift;;
    --post)      POST=1;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *)  echo "unexpected arg: $1" >&2; exit 2;;
  esac
  shift
done
[ -n "$REPO" ] || { echo "refuse: --repo OWNER/REPO required" >&2; exit 2; }
[ -n "$PR" ]   || { echo "refuse: --pr N required" >&2; exit 2; }
case "$REPO" in */*) :;; *) echo "refuse: --repo must be OWNER/REPO" >&2; exit 2;; esac
case "$PR"   in *[!0-9]*) echo "refuse: --pr must be a number" >&2; exit 2;; esac

# read the review body (stdin by default)
if [ "$BODYFILE" = "-" ]; then BODY="$(cat)"; else BODY="$(cat "$BODYFILE")"; fi
ATTR_RE='generated[ _-]+with[ _-]+claude|co-authored[ _-]+by:?[ _-]+claude|🤖|noreply@anthropic'
BODY="$(printf '%s\n' "$BODY" | grep -ivE "$ATTR_RE")"          # strip AI-attribution lines
HAS="$(printf '%s' "$BODY" | tr -d '[:space:]')"
[ -n "$HAS" ] || { echo "refuse: empty review body (nothing to stage)" >&2; exit 2; }

# validate the PR exists + capture state/author/url
read -r STATE AUTHOR URL < <(gh pr view "$PR" -R "$REPO" --json state,author,url \
  --jq '[.state, .author.login, .url] | @tsv' 2>/tmp/stage_err) || {
  echo "refuse: cannot read $REPO#$PR: $(cat /tmp/stage_err 2>/dev/null)" >&2; exit 2; }
[ "$STATE" = "OPEN" ] || echo "note: $REPO#$PR is $STATE (a pending review still attaches, but you usually review OPEN PRs)" >&2

echo "PR     : $REPO#$PR  ($URL)"
echo "state  : $STATE   author: $AUTHOR"
echo "action : stage a PENDING review (you submit Approve/Request-changes/Comment in GitHub)"
printf '%s\n' "$BODY" | sed 's/^/  | /'

if [ "$POST" != 1 ]; then
  echo; echo "(dry-run — pass --post to stage the pending review)"; exit 0
fi

# one-pending-review-per-PR-per-user: remove any existing pending review first
me="$(gh api user --jq .login 2>/dev/null)"
if [ -n "$me" ]; then
  existing="$(gh api "repos/$REPO/pulls/$PR/reviews" --paginate \
    --jq ".[] | select(.user.login==\"$me\" and .state==\"PENDING\") | .id" 2>/dev/null | head -1)"
  if [ -n "$existing" ]; then
    echo "note: replacing your existing pending review ($existing)"
    gh api -X DELETE "repos/$REPO/pulls/$PR/reviews/$existing" >/dev/null 2>&1 || true
  fi
fi

# create the PENDING review: POST with body and NO `event` field
rid="$(gh api "repos/$REPO/pulls/$PR/reviews" -X POST -f body="$BODY" --jq '.id' 2>/tmp/stage_err)"
if [ -z "$rid" ]; then
  echo "ERROR staging review on $REPO#$PR: $(cat /tmp/stage_err 2>/dev/null)" >&2; exit 1
fi
echo
echo "staged pending review #$rid on $REPO#$PR"
echo "  -> open $URL/files (or the PR), edit if needed, then Finish your review → Submit."
exit 0
