#!/usr/bin/env bash
# Clear (mark-as-read) addressed GitHub notifications — pure bash, read-only until --apply.
#
# "Addressed" is your call — pick a mode:
#   --repo O/R --number N   clear the notification for one PR/issue you've handled
#   --thread THREAD_ID      clear one notification thread by id
#   --resolved              clear every unread notification whose PR/issue is CLOSED or MERGED
#   --all                   clear ALL notifications (mark everything read)
#
# SAFE BY DEFAULT: dry-run (lists what it WOULD clear) unless --apply is given.
# Marking read is reversible-ish (the thread reappears if it gets new activity) and
# never touches issues/PRs themselves — it only clears YOUR notification inbox.
#
#   usage: mark_read.sh (--repo O/R --number N | --thread ID | --resolved | --all) [--apply]
set -uo pipefail

REPO=""; NUM=""; THREAD=""; MODE=""; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)     REPO="${2:-}"; shift;;
    --number)   NUM="${2:-}"; shift;;
    --thread)   THREAD="${2:-}"; MODE="thread"; shift;;
    --resolved) MODE="resolved";;
    --all)      MODE="all";;
    --apply)    APPLY=1;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *)  echo "unexpected arg: $1" >&2; exit 2;;
  esac
  shift
done
[ -n "$REPO" ] && [ -n "$NUM" ] && MODE="one"
[ -n "$MODE" ] || { echo "refuse: pick a mode — --repo O/R --number N | --thread ID | --resolved | --all" >&2; exit 2; }

mark() { # $1=thread_id $2=label
  if [ "$APPLY" = 1 ]; then
    if gh api -X PATCH "notifications/threads/$1" >/dev/null 2>/tmp/mr_err; then echo "  cleared: $2 (thread $1)"
    else echo "  ERROR clearing $2: $(cat /tmp/mr_err 2>/dev/null)"; fi
  else
    echo "  would clear: $2 (thread $1)"
  fi
}

case "$MODE" in
  all)
    n="$(gh api notifications --jq 'length' 2>/dev/null || echo '?')"
    echo "mode: ALL — $n unread notification(s)"
    if [ "$APPLY" = 1 ]; then
      gh api -X PUT notifications -f read=true >/dev/null 2>/tmp/mr_err \
        && echo "  cleared ALL notifications" || echo "  ERROR: $(cat /tmp/mr_err 2>/dev/null)"
    else echo "  (dry-run — pass --apply to mark all read)"; fi
    ;;
  thread)
    mark "$THREAD" "thread $THREAD"
    ;;
  one)
    # find the unread thread whose subject belongs to REPO and ends at /NUM
    tid="$(gh api notifications --paginate \
      --jq ".[] | select(.repository.full_name==\"$REPO\" and (.subject.url|test(\"/$NUM\$\"))) | .id" 2>/dev/null | head -1)"
    if [ -z "$tid" ]; then echo "no unread notification found for $REPO#$NUM (already clear?)"; exit 0; fi
    mark "$tid" "$REPO#$NUM"
    ;;
  resolved)
    echo "mode: RESOLVED — clearing notifications whose PR/issue is closed/merged"
    count=0
    # columns: thread_id, repo, subject_url, type
    gh api notifications --paginate \
      --jq '.[] | select(.subject.type=="PullRequest" or .subject.type=="Issue") | [.id, .repository.full_name, .subject.url, .subject.type] | @tsv' 2>/dev/null \
      | while IFS="$(printf '\t')" read -r tid repo surl typ; do
          num="${surl##*/}"
          [ -n "$num" ] || continue
          if [ "$typ" = "PullRequest" ]; then
            st="$(gh pr view "$num" -R "$repo" --json state,isDraft --jq 'if .state=="MERGED" then "merged" elif .state=="CLOSED" then "closed" else "open" end' 2>/dev/null)"
          else
            st="$(gh issue view "$num" -R "$repo" --json state --jq '.state|ascii_downcase' 2>/dev/null)"
          fi
          case "$st" in merged|closed) mark "$tid" "$repo#$num ($st)"; count=$((count+1));; esac
        done
    ;;
esac
[ "$APPLY" = 1 ] || { echo; echo "(dry-run — re-run with --apply to actually clear)"; }
exit 0
