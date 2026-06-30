#!/usr/bin/env bash
# Post a comment to a GitHub issue or PR — pure bash, no Python, no draft repo.
#
# The repo-less `[Send]` path: the on-demand drafter writes the reply, shows it to
# you in Discord, and on confirm pipes that exact text here to post it as a
# conversation COMMENT (never a review/approve/merge/label/close). Deterministic —
# no LLM in the posting path; what you saw is what gets posted, verbatim.
#
# Works for issues AND PRs (uses the issues-comments endpoint, which PRs share).
# SAFE BY DEFAULT: dry-run unless --post.
#
#   usage:
#     post_comment.sh --repo O/R --number N                 # dry-run
#     printf '%s' "$BODY" | post_comment.sh --repo O/R --number N --post
#     post_comment.sh --repo O/R --number N --body-file f --post
set -uo pipefail

REPO=""; NUM=""; BODYFILE="-"; POST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)      REPO="${2:-}"; shift;;
    --number)    NUM="${2:-}"; shift;;
    --body-file) BODYFILE="${2:-}"; shift;;
    --post)      POST=1;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *)  echo "unexpected arg: $1" >&2; exit 2;;
  esac
  shift
done
[ -n "$REPO" ] || { echo "refuse: --repo OWNER/REPO required" >&2; exit 2; }
[ -n "$NUM" ]  || { echo "refuse: --number N required" >&2; exit 2; }
case "$REPO" in */*) :;; *) echo "refuse: --repo must be OWNER/REPO" >&2; exit 2;; esac
case "$NUM"  in *[!0-9]*) echo "refuse: --number must be numeric" >&2; exit 2;; esac

if [ "$BODYFILE" = "-" ]; then BODY="$(cat)"; else BODY="$(cat "$BODYFILE")"; fi
ATTR_RE='generated[ _-]+with[ _-]+claude|co-authored[ _-]+by:?[ _-]+claude|🤖|noreply@anthropic'
BODY="$(printf '%s\n' "$BODY" | grep -ivE "$ATTR_RE")"
HAS="$(printf '%s' "$BODY" | tr -d '[:space:]')"
[ -n "$HAS" ] || { echo "refuse: empty comment body" >&2; exit 2; }

echo "target : $REPO#$NUM"
printf '%s\n' "$BODY" | sed 's/^/  | /'
if [ "$POST" != 1 ]; then
  echo; echo "(dry-run — pass --post to comment)"; exit 0
fi

url="$(gh api "repos/$REPO/issues/$NUM/comments" -f body="$BODY" --jq '.html_url' 2>/tmp/pc_err)"
if [ -z "$url" ]; then
  echo "ERROR commenting on $REPO#$NUM: $(cat /tmp/pc_err 2>/dev/null)" >&2; exit 1
fi
echo; echo "posted: $url"
exit 0
