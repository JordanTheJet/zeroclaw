#!/usr/bin/env bash
# Submit a gh-notif PR-review draft to GitHub as a FORMAL REVIEW — pure bash.
#
# Sibling of ship_accepted.sh (which posts a plain comment). This submits a formal
# PULL-REQUEST REVIEW via `gh pr review` — Comment / Approve / Request-changes —
# using the text between <!-- REPLY:BEGIN --> / <!-- REPLY:END --> as the body.
# It NEVER merges, closes, labels, or assigns. Reviews are ALWAYS an explicit
# human action: there is no cron path and no unscoped run.
#
# SECURITY MODEL (hardened after an adversarial review):
#   - The VERDICT is supplied by the human at ship-time via --verdict; it is NOT
#     read from draft frontmatter. The drafting agent cannot stage a verdict, so
#     prompt-injected PR content cannot reach an Approve through the draft.
#   - --only must resolve to EXACTLY ONE draft (matched on basename). No mass-fire.
#   - approve / request-changes are CONSEQUENTIAL and require a TWO-PHASE confirm:
#       phase 1 (no --confirm): validate + arm (write a random review_nonce), print it.
#       phase 2 (--post --confirm <nonce>): submit iff the nonce matches, then consume it.
#     A `comment` review needs only --post (non-consequential).
#   - Self-review (PR you authored) FAILS CLOSED: if authorship can't be confirmed
#     for a consequential verdict, it refuses.
#   - Target coherence: the draft's url must contain repo + /pull/number; duplicate
#     repo/number/url keys are rejected (no first-match smuggling).
#   - AI-attribution stripped (best-effort, defense-in-depth). Idempotent (status->posted).
#
#   RESIDUAL: the worker agents run with a full shell + the gh token, so a fully
#   prompt-injected worker could call `gh pr review --approve` directly, bypassing
#   this script. The real boundary for that case is the worker sandbox (scope the
#   gh token read-only / restrict the worker shell). See references/safety.md.
#
#   usage:
#     ship_review.sh <ws> --only <draft-substr> --verdict comment [--post]
#     ship_review.sh <ws> --only <draft-substr> --verdict approve            # phase 1: arm, prints nonce
#     ship_review.sh <ws> --only <draft-substr> --verdict approve --post --confirm <nonce>   # phase 2
set -uo pipefail

WS=""; POST=0; ONLY=""; VERDICT=""; CONFIRM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --post)    POST=1;;
    --only)    ONLY="${2:-}"; shift;;
    --verdict) VERDICT="${2:-}"; shift;;
    --confirm) CONFIRM="${2:-}"; shift;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *) if [ -z "$WS" ]; then WS="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi;;
  esac
  shift
done
[ -n "$WS" ]   || { echo "usage: ship_review.sh <ws> --only <draft> --verdict comment|approve|request-changes [--post] [--confirm <nonce>]" >&2; exit 2; }
[ -n "$ONLY" ] || { echo "refuse: --only <draft> is required (reviews are never unscoped)" >&2; exit 2; }
case "$VERDICT" in
  comment)                          FLAG="--comment";         CONSEQUENTIAL=0;;
  approve)                          FLAG="--approve";         CONSEQUENTIAL=1;;
  request-changes|request_changes)  FLAG="--request-changes"; VERDICT="request-changes"; CONSEQUENTIAL=1;;
  "") echo "refuse: --verdict comment|approve|request-changes is required" >&2; exit 2;;
  *)  echo "refuse: unknown --verdict '$VERDICT' (use comment|approve|request-changes)" >&2; exit 2;;
esac

CLONE="$WS/drafts-repo"
[ -d "$CLONE/.git" ] || { echo "review: no drafts-repo clone at $CLONE; nothing to do" >&2; exit 0; }
git -C "$CLONE" pull --ff-only --quiet 2>/dev/null || true

PLACEHOLDER="REPLACE_WITH_PUBLIC_REPLY_OR_LEAVE_EMPTY"
# best-effort attribution strip (defense-in-depth, NOT a containment boundary)
ATTR_RE='generated[ _-]+with[ _-]+claude|co-authored[ _-]+by:?[ _-]+claude|🤖|noreply@anthropic'

fm_get() { # $1=file $2=key -> first value in leading frontmatter
  awk -v key="$2" '
    BEGIN{n=0}
    /^---[[:space:]]*$/ {n++; if(n>=2) exit; next}
    n==1 { i=index($0,":"); if(i==0) next
      k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k)
      if(k==key){ v=substr($0,i+1); sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v)
        if(v ~ /^".*"$/) v=substr(v,2,length(v)-2); print v; exit } }
  ' "$1"
}
fm_count() { # $1=file $2=key -> number of frontmatter lines defining that key
  awk -v key="$2" '
    BEGIN{n=0;c=0}
    /^---[[:space:]]*$/ {n++; if(n>=2) exit; next}
    n==1 { i=index($0,":"); if(i){k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k); if(k==key)c++} }
    END{print c+0}
  ' "$1"
}
extract_reply() { awk '
    /<!--[[:space:]]*REPLY:BEGIN[[:space:]]*-->/ {inb=1; next}
    /<!--[[:space:]]*REPLY:END[[:space:]]*-->/   {inb=0}
    inb {print}' "$1" | sed -e '/[^[:space:]]/,$!d'; }

fm_set() { # $1=file $2=key $3=value ("" to delete) -> upsert key in frontmatter
  awk -v key="$2" -v val="$3" '
    BEGIN{n=0;done=0}
    /^---[[:space:]]*$/ { n++
      if(n==2){ if(!done && val!=""){ print key ": \"" val "\"" } print; next }
      print; next }
    n==1 { i=index($0,":"); if(i){k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k)
        if(k==key){ if(val!=""){ print key ": \"" val "\""; done=1 } next } }
      print; next }
    { print }
  ' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

# ---- select EXACTLY ONE draft by basename substring -------------------------
matches=()
shopt -s nullglob
for f in "$CLONE"/triage/*/items/*.md; do
  case "$(basename "$f")" in *"$ONLY"*) matches+=("$f");; esac
done
nm="${#matches[@]}"
if [ "$nm" -ne 1 ]; then
  echo "refuse: --only '$ONLY' matched $nm drafts (need exactly 1)." >&2
  [ "$nm" -gt 0 ] && { echo "  candidates:" >&2; for m in "${matches[@]}"; do echo "    $(basename "$m")" >&2; done; }
  exit 2
fi
f="${matches[0]}"
base="$(basename "$f")"

# ---- per-draft validation ---------------------------------------------------
[ "$(fm_get "$f" status)" = "posted" ] && { echo "skip: $base already posted (idempotent)"; exit 0; }
typ="$(fm_get "$f" type)";   [ "$typ" = "PullRequest" ] || { echo "refuse: $base is $typ, reviews apply to PRs only" >&2; exit 2; }
repo="$(fm_get "$f" repo)";  number="$(fm_get "$f" number)";  url="$(fm_get "$f" url)"
[ -n "$repo" ] && [ -n "$number" ] || { echo "refuse: $base missing repo/number" >&2; exit 2; }
for k in repo number url; do
  [ "$(fm_count "$f" "$k")" -le 1 ] || { echo "refuse: $base has duplicate '$k' frontmatter key (smuggling guard)" >&2; exit 2; }
done
case "$url" in
  *"$repo/pull/$number"*) : ;;
  *) echo "refuse: $base url ('$url') does not match $repo/pull/$number — possible mis-target" >&2; exit 2;;
esac

# ---- body -------------------------------------------------------------------
body="$(extract_reply "$f")"
case "$body" in *"$PLACEHOLDER"*) body="";; esac          # any placeholder presence => treat as empty
body="$(printf '%s\n' "$body" | grep -ivE "$ATTR_RE")"     # strip attribution lines
body="$(printf '%s' "$body" | sed -e '/[^[:space:]]/,$!d')" # trim leading blank lines
has_content="$(printf '%s' "$body" | tr -d '[:space:]')"
if [ "$FLAG" != "--approve" ] && [ -z "$has_content" ]; then
  echo "refuse: $base — '$VERDICT' needs a non-empty review body" >&2; exit 2
fi

echo "draft : $base"
echo "target: $repo#$number  ($url)"
echo "verdict: $VERDICT"
printf '%s\n' "${has_content:+$body}" | sed 's/^/  | /'
[ -z "$has_content" ] && echo "  | (approve with no body)"

# ---- consequential verdicts: fail-closed self-PR + two-phase nonce ----------
if [ "$CONSEQUENTIAL" = 1 ]; then
  me="$(gh api user --jq .login 2>/dev/null)"; rc_me=$?
  author="$(gh pr view "$number" -R "$repo" --json author --jq .author.login 2>/dev/null)"; rc_au=$?
  if [ "$rc_me" -ne 0 ] || [ -z "$me" ] || [ "$rc_au" -ne 0 ] || [ -z "$author" ]; then
    echo "refuse: cannot confirm authorship of $repo#$number (you=$me author=$author) — won't $VERDICT without verification" >&2; exit 2
  fi
  if [ "$author" = "$me" ]; then
    echo "refuse: cannot $VERDICT your OWN PR ($repo#$number) — use ship_accepted.sh for a comment" >&2; exit 2
  fi
  stored="$(fm_get "$f" review_nonce)"
  if [ -z "$CONFIRM" ] || [ "$POST" != 1 ]; then
    # PHASE 1: arm
    nonce="$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    [ -n "$nonce" ] || nonce="$(date -u +%s)$$"
    fm_set "$f" review_nonce "$nonce"
    git -C "$CLONE" add -A >/dev/null 2>&1
    git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' commit -q -m "arm review: $base ($VERDICT)" >/dev/null 2>&1 || true
    echo
    echo "⚠ CONSEQUENTIAL ($VERDICT) — armed but NOT submitted."
    echo "  To submit, re-run:"
    echo "    ship_review.sh \"$WS\" --only \"$ONLY\" --verdict $VERDICT --post --confirm $nonce"
    exit 0
  fi
  # PHASE 2: verify nonce
  if [ -z "$stored" ] || [ "$stored" != "$CONFIRM" ]; then
    echo "refuse: --confirm nonce does not match the armed value for $base (re-run without --confirm to re-arm)" >&2; exit 2
  fi
fi

# ---- dry-run vs submit ------------------------------------------------------
if [ "$POST" != 1 ]; then
  echo; echo "(dry-run — pass --post to submit$([ "$CONSEQUENTIAL" = 1 ] && echo ' --confirm <nonce>'))"
  exit 0
fi

rc=0
if [ -n "$has_content" ]; then
  printf '%s' "$body" | gh pr review "$number" --repo "$repo" "$FLAG" --body-file - 2>/tmp/gh_review_err || rc=$?
else
  gh pr review "$number" --repo "$repo" "$FLAG" 2>/tmp/gh_review_err || rc=$?
fi
if [ "$rc" -ne 0 ]; then
  echo "ERROR submitting $repo#$number: $(cat /tmp/gh_review_err 2>/dev/null)" >&2; exit 1
fi

rurl="$(gh api "repos/$repo/pulls/$number/reviews" --jq "[.[]|select(.user.login==\"${me:-}\")]|last|.html_url" 2>/dev/null)"
when="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fm_set "$f" status "posted"
fm_set "$f" reviewed_at "$when"
fm_set "$f" review_submitted "$VERDICT"
fm_set "$f" posted_review_url "${rurl:-}"
fm_set "$f" review_nonce ""        # consume
git -C "$CLONE" add -A >/dev/null 2>&1
if git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' commit -q -m "review: submitted $VERDICT on $repo#$number"; then
  if ! git -C "$CLONE" push -q; then
    echo "WARN: review submitted ($repo#$number) but git push FAILED — the shared drafts repo still shows this draft un-posted." >&2
    echo "      Run: git -C \"$CLONE\" pull --rebase && git -C \"$CLONE\" push   (else another host may re-submit)." >&2
    exit 1
  fi
fi
echo
echo "submitted: $VERDICT on $repo#$number  ${rurl:-(review posted)}"
exit 0
