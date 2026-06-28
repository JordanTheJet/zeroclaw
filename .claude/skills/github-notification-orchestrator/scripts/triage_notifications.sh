#!/usr/bin/env bash
# Triage notifications BEFORE drafting: cheaply classify each unread notification
# as STALE (resolved/old/low-value) vs KEEP (open + actionable), so the expensive
# LLM drafting only runs on what's live. Deterministic — read-only `gh` state
# lookups + age + reason; no model calls.
#
# Report-only by default. With --apply, the STALE thread_ids are written to
# seen.tsv (so neither this drain nor future polls draft them) — it NEVER marks
# anything read on GitHub (draft-only contract).
#
#   usage: triage_notifications.sh <gh-notif-workspace-dir> [--days N] [--apply]
set -uo pipefail

WS=""; DAYS=14; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="${2:?--days needs N}"; shift;;
    --apply) APPLY=1;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *) WS="$1";;
  esac; shift
done
[ -n "$WS" ] || { echo "usage: triage_notifications.sh <ws> [--days N] [--apply]" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="$WS/state"; BINDER="$WS/triage/$(date +%F)"
echo "refreshing notification snapshot (read-only gh)…"
bash "$HERE/notifications_delta.sh" delta "$STATE" "$BINDER" >/dev/null 2>&1 || true
TSV="$BINDER/notifications.tsv"
[ -s "$TSV" ] || { echo "no notifications.tsv at $TSV" >&2; exit 1; }

now="$(date +%s)"
age_days() { # ISO8601 Z -> whole days old
  local e; e="$(date -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null)" || { echo 9999; return; }
  echo $(( (now - e) / 86400 ))
}

keep="$BINDER/triage-keep.tsv"; stale="$BINDER/triage-stale.tsv"; : > "$keep"; : > "$stale"
declare -i c_resolved=0 c_old=0 c_low=0 c_keep=0 n=0
echo "classifying $(grep -c '' "$TSV") notifications (gh state lookups; ~1-2 min)…"
# columns: reason  type  repo  number  title  updated_at  url  thread_id
while IFS=$'\t' read -r reason type repo number title updated url thread; do
  [ -n "${thread:-}" ] || continue
  n+=1
  age="$(age_days "$updated")"
  state="n/a"
  case "$type" in
    PullRequest) state="$(gh pr view "$number" -R "$repo" --json state,isDraft --jq 'if .state=="MERGED" then "merged" elif .state=="CLOSED" then "closed" else "open" end' 2>/dev/null || echo unknown)";;
    Issue)       state="$(gh issue view "$number" -R "$repo" --json state --jq '.state|ascii_downcase' 2>/dev/null || echo unknown)";;
  esac
  bucket=""; why=""
  if [ "$state" = "merged" ] || [ "$state" = "closed" ]; then bucket=stale; why="$type $state"; c_resolved+=1
  elif [ "$reason" = "ci_activity" ] || [ "$reason" = "state_change" ]; then bucket=stale; why="low-value ($reason)"; c_low+=1
  elif [ "$age" -gt "$DAYS" ] && { [ "$reason" = "comment" ] || [ "$reason" = "subscribed" ] || [ "$type" = "Discussion" ]; }; then bucket=stale; why="old ${age}d ($reason)"; c_old+=1
  else bucket=keep; why="open/${reason} ${age}d"; c_keep+=1
  fi
  printf '%s\t%s\t%s#%s\t%s\t%s\t%s\n' "$thread" "$reason" "$repo" "$number" "$age" "$state" "$title" >> "$BINDER/triage-$bucket.tsv"
done < "$TSV"

echo
echo "════════ TRIAGE — $n notifications (stale threshold: >${DAYS}d) ════════"
echo "  STALE (skip drafting): $((c_resolved+c_low+c_old))"
echo "     • resolved (closed/merged): $c_resolved"
echo "     • low-value (ci/state_change): $c_low"
echo "     • old (>${DAYS}d, comment/sub/discussion): $c_old"
echo "  KEEP (actionable, will draft): $c_keep"
echo
echo "  top KEEP items:"; sort -t$'\t' -k4,4n "$keep" 2>/dev/null | head -12 | awk -F'\t' '{printf "     %s  %s  %sd  [%s]  %s\n",$3,$2,$4,$5,substr($6,1,60)}'
echo "  sample STALE:"; head -8 "$stale" 2>/dev/null | awk -F'\t' '{printf "     %s  %s  %sd  [%s]  %s\n",$3,$2,$4,$5,substr($6,1,50)}'
echo
echo "  lists: keep=$keep  stale=$stale"
if [ "$APPLY" = 1 ]; then
  cut -f1 "$stale" | while IFS= read -r t; do [ -n "$t" ] && printf '%s\t%s\n' "$t" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; done >> "$STATE/seen.tsv"
  # de-dup seen.tsv (keep last per thread)
  awk -F'\t' '{a[$1]=$0} END{for(k in a) print a[k]}' "$STATE/seen.tsv" > "$STATE/seen.tsv.tmp" && mv "$STATE/seen.tsv.tmp" "$STATE/seen.tsv"
  echo "  --apply: marked $((c_resolved+c_low+c_old)) stale threads as seen (skipped); $c_keep KEEP remain to draft."
else
  echo "  (report only — re-run with --apply to skip-draft the stale ones; nothing was changed or marked read)"
fi
exit 0
