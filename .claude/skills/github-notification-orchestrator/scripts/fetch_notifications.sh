#!/usr/bin/env bash
# Fetch unread GitHub notifications into a run folder.
#
#   Usage: fetch_notifications.sh <output-dir>
#
# Writes:
#   <output-dir>/notifications.json   raw unread notifications (cache)
#   <output-dir>/notifications.tsv    one shaped row per unread thread:
#       reason  type  repo  number  title  updated_at  html_url  thread_id
#
# This is a DRAFT-ONLY skill: every gh call here is READ-ONLY. The script never
# marks anything read or mutates GitHub state. It caches the raw fetch so
# re-running within a session does not re-hit the API.
set -euo pipefail

OUT="${1:?usage: fetch_notifications.sh <output-dir>}"
mkdir -p "$OUT/items"

RAW="$OUT/notifications.json"
TSV="$OUT/notifications.tsv"

# One fetch per run — reuse the cache if it already exists this session.
if [[ ! -s "$RAW" ]]; then
  gh api notifications --paginate \
    | jq -s '(add // []) | map(select(.unread == true))' > "$RAW"
fi

# Shape a TSV for the orchestrator's plan. Derive the issue/PR number from the
# subject API url, and build the human (github.com) url from repo + type + number.
jq -r '
  .[]
  | (.subject.url // "") as $surl
  | (if $surl == "" then "" else ($surl | split("/") | last) end) as $num
  | (if .subject.type == "PullRequest" then "pull"
     elif .subject.type == "Discussion" then "discussions"
     else "issues" end) as $seg
  | (if $num == "" then "https://github.com/\(.repository.full_name)"
     else "https://github.com/\(.repository.full_name)/\($seg)/\($num)" end) as $html
  | [ .reason, .subject.type, .repository.full_name, $num,
      .subject.title, .updated_at, $html, (.id // "") ]
  | @tsv
' "$RAW" > "$TSV"

COUNT=$(jq 'length' "$RAW")
echo "Fetched ${COUNT} unread notification(s) → ${RAW}"
if [[ "$COUNT" -gt 0 ]]; then
  echo "By reason:"
  jq -r 'group_by(.reason)[] | "\(length)\t\(.[0].reason)"' "$RAW" | sort -rn | sed 's/^/  /'
fi
echo "Shaped TSV → ${TSV}"
