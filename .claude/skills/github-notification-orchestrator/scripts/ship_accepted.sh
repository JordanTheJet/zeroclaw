#!/usr/bin/env bash
# Post ACCEPTED gh-notif drafts to GitHub as COMMENTS — pure bash, no Python.
#
# Finds drafts in the private drafts-repo clone whose frontmatter says
# `status: accepted`, extracts the verbatim text between <!-- REPLY:BEGIN --> and
# <!-- REPLY:END -->, and posts it as a COMMENT via `gh` — never a review,
# approval, request-changes, merge, close, or label. On success it flips the draft
# to `status: posted` and records `posted_at` + `posted_comment_url`, then commits
# and pushes the clone.
#
# SAFE BY DEFAULT: dry-run unless --post is given. Only `status: accepted` drafts
# are touched; only issue/PR comments are posted; nothing else is mutated. There is
# no LLM in this path — the text posted is exactly the marked block.
#
#   usage: ship_accepted.sh <gh-notif-workspace-dir> [--post] [--repo O/R] [--only SUBSTR]
set -uo pipefail

WS=""; POST=0; ONLY=""; ONLYREPO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --post) POST=1;;
    --only) ONLY="${2:-}"; shift;;
    --repo) ONLYREPO="${2:-}"; shift;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *) if [ -z "$WS" ]; then WS="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi;;
  esac
  shift
done
[ -n "$WS" ] || { echo "usage: ship_accepted.sh <gh-notif-workspace-dir> [--post] [--repo O/R] [--only SUBSTR]" >&2; exit 2; }

CLONE="$WS/drafts-repo"
[ -d "$CLONE/.git" ] || { echo "ship: no drafts-repo clone at $CLONE; nothing to do" >&2; exit 0; }
git -C "$CLONE" pull --ff-only --quiet 2>/dev/null || true

PLACEHOLDER="REPLACE_WITH_PUBLIC_REPLY_OR_LEAVE_EMPTY"

fm_get() { # $1=file $2=key -> value (first match in leading frontmatter)
  awk -v key="$2" '
    BEGIN{n=0}
    /^---[[:space:]]*$/ {n++; if(n>=2) exit; next}
    n==1 {
      i=index($0,":"); if(i==0) next
      k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k)
      if(k==key){
        v=substr($0,i+1); sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v)
        if(v ~ /^".*"$/) v=substr(v,2,length(v)-2)
        print v; exit
      }
    }
  ' "$1"
}

extract_reply() { # $1=file -> text strictly between the REPLY markers (leading blank lines trimmed)
  awk '
    /<!--[[:space:]]*REPLY:BEGIN[[:space:]]*-->/ {inb=1; next}
    /<!--[[:space:]]*REPLY:END[[:space:]]*-->/   {inb=0}
    inb {print}
  ' "$1" | sed -e '/[^[:space:]]/,$!d'
}

set_posted() { # $1=file $2=url $3=when -> flip status->posted, record posted_at/url
  awk -v url="$2" -v when="$3" '
    BEGIN{n=0}
    /^---[[:space:]]*$/ {
      n++
      if(n==2){ print "posted_at: \"" when "\""; print "posted_comment_url: \"" url "\""; print; next }
      print; next
    }
    n==1 {
      if($0 ~ /^status:/){ print "status: \"posted\""; next }
      if($0 ~ /^posted_at:/ || $0 ~ /^posted_comment_url:/) next
      print; next
    }
    { print }
  ' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

posted=0; skipped=0; errors=0; changed=0
shopt -s nullglob
for f in "$CLONE"/triage/*/items/*.md; do
  if [ -n "$ONLY" ]; then case "$f" in *"$ONLY"*) :;; *) continue;; esac; fi
  [ "$(fm_get "$f" status)" = "accepted" ] || continue
  repo="$(fm_get "$f" repo)"; number="$(fm_get "$f" number)"; typ="$(fm_get "$f" type)"
  if [ -n "$ONLYREPO" ] && [ "$repo" != "$ONLYREPO" ]; then continue; fi
  case "$typ" in
    PullRequest) kind=pr;;
    Issue)       kind=issue;;
    *) echo "SKIP  $repo#$number ($typ): not a commentable issue/PR — $(basename "$f")"; skipped=$((skipped+1)); continue;;
  esac
  if [ -z "$number" ]; then echo "SKIP  $repo ($typ): no number — $(basename "$f")"; skipped=$((skipped+1)); continue; fi
  reply="$(extract_reply "$f")"
  if [ -z "$reply" ] || [ "$reply" = "$PLACEHOLDER" ]; then
    echo "SKIP  $repo#$number: empty REPLY block (accepted but nothing to post) — $(basename "$f")"; skipped=$((skipped+1)); continue
  fi
  echo
  if [ "$POST" = 1 ]; then echo "POST -> $repo#$number ($typ)  [$(basename "$f")]"; else echo "WOULD POST -> $repo#$number ($typ)  [$(basename "$f")]"; fi
  printf '%s\n' "$reply" | sed 's/^/  | /'
  if [ "$POST" = 1 ]; then
    if url="$(printf '%s' "$reply" | gh "$kind" comment "$number" --repo "$repo" --body-file - 2>/tmp/gh_ship_err | tail -n1)"; then
      set_posted "$f" "$url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      changed=1; posted=$((posted+1)); echo "  posted: $url"
    else
      echo "  ERROR: $(cat /tmp/gh_ship_err 2>/dev/null)"; errors=$((errors+1)); continue
    fi
  else
    posted=$((posted+1))
  fi
done

if [ "$POST" = 1 ] && [ "$changed" = 1 ]; then
  git -C "$CLONE" add -A
  git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' commit -q -m "ship: posted $posted accepted draft(s)" || true
  git -C "$CLONE" push -q || true
fi

echo
if [ "$POST" = 1 ]; then
  echo "ship: posted $posted, skipped $skipped, errors $errors"
else
  echo "ship: would post $posted, skipped $skipped, errors $errors  (dry-run — pass --post to actually comment)"
fi
if [ "$errors" -gt 0 ]; then exit 1; fi
exit 0
