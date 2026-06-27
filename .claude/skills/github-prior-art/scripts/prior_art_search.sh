#!/usr/bin/env bash
# Prior-art search: find pre-existing issues AND PRs (by anyone) that already
# cover a topic, BEFORE the user files an issue, opens a PR, or drafts a reply.
#
#   Usage: prior_art_search.sh <query> <owner/repo> [output-dir]
#
# Example:
#   prior_art_search.sh "context budget" zeroclaw-labs/zeroclaw
#   prior_art_search.sh "dream mode" zeroclaw-labs/zeroclaw /tmp/prior-art
#
# Runs three READ-ONLY gh searches (the script never files, comments, labels,
# closes, or marks anything read):
#   1. gh search issues --include-prs  — global index: issues AND PRs, open + closed
#   2. gh issue list --search          — repo-local issue fallback (catches index lag)
#   3. gh pr list --search             — repo-local PR fallback (incl. merged)
# Then dedupes by number+type and emits a candidates table.
#
# Writes (to output-dir, default a mktemp dir, path echoed at the end):
#   candidates.tsv   number<TAB>type<TAB>state<TAB>author<TAB>updated<TAB>title<TAB>url
#   candidates.json  same rows as a JSON array (for programmatic ranking)
#   query.txt        the query + repo, for the record
#
# Robust to ZERO results: emits empty (header-only) files and exits 0 so a
# caller can always read the outputs.
set -euo pipefail

QUERY="${1:?usage: prior_art_search.sh <query> <owner/repo> [output-dir]}"
REPO="${2:?usage: prior_art_search.sh <query> <owner/repo> [output-dir]}"
OUT="${3:-$(mktemp -d -t prior-art-XXXXXX)}"
mkdir -p "$OUT"

command -v gh  >/dev/null || { echo "error: gh not found on PATH" >&2; exit 2; }
command -v jq  >/dev/null || { echo "error: jq not found on PATH" >&2; exit 2; }

RAW="$OUT/raw.json"
TSV="$OUT/candidates.tsv"
JSON="$OUT/candidates.json"
printf '%s\nrepo: %s\n' "$QUERY" "$REPO" > "$OUT/query.txt"

# --- Run the three searches, tolerating individual failures ---------------
# gh exits non-zero on a query it dislikes; we never want one bad search to
# sink the run, so each is guarded and its output normalized to a JSON array.
: > "$RAW"

emit() {
  # Append a JSON array (or nothing) to the raw accumulator, one obj per line.
  # $1 = a jq program that maps each element to the common shape.
  jq -c "$1" 2>/dev/null >> "$RAW" || true
}

# 1: GitHub-wide search scoped to the repo (open AND closed in one call;
# search returns both states by default). isPullRequest distinguishes type.
gh search issues "$QUERY" --repo "$REPO" --include-prs --limit 40 \
  --json number,title,state,author,url,updatedAt,isPullRequest 2>/dev/null \
  | emit '.[] | {
      number, title, state,
      author: (.author.login // ""),
      url, updated: .updatedAt,
      type: (if .isPullRequest then "pr" else "issue" end)
    }'

# 2: repo-local issue search — catches matches the global index lags on.
gh issue list --repo "$REPO" --search "$QUERY" --state all --limit 30 \
  --json number,title,state,author,url,updatedAt 2>/dev/null \
  | emit '.[] | {
      number, title, state: (.state | ascii_downcase),
      author: (.author.login // ""),
      url, updated: .updatedAt, type: "issue"
    }'

# 3: repo-local PR search — including merged (state merged is a closed PR).
gh pr list --repo "$REPO" --search "$QUERY" --state all --limit 30 \
  --json number,title,state,author,url,updatedAt 2>/dev/null \
  | emit '.[] | {
      number, title, state: (.state | ascii_downcase),
      author: (.author.login // ""),
      url, updated: .updatedAt, type: "pr"
    }'

# --- Dedupe by (type,number); keep the most recently updated row ----------
# slurp the per-line objects, group, sort newest-first inside the run.
jq -s '
  map(select(. != null))
  | group_by([.type, .number])
  | map(sort_by(.updated) | last)
  | sort_by(.updated) | reverse
' "$RAW" > "$JSON"

# --- TSV with a header (always written, even when empty) -------------------
{
  printf 'number\ttype\tstate\tauthor\tupdated\ttitle\turl\n'
  jq -r '.[] | [.number, .type, .state, .author, .updated, .title, .url] | @tsv' "$JSON"
} > "$TSV"

COUNT=$(jq 'length' "$JSON")
echo "Prior-art search: \"$QUERY\" in $REPO"
echo "Found ${COUNT} unique candidate(s) (issues + PRs, open + closed)."
if [[ "$COUNT" -gt 0 ]]; then
  echo "By type/state:"
  jq -r 'group_by([.type,.state])[] | "  \(length)\t\(.[0].type)/\(.[0].state)"' "$JSON" | sort -rn
fi
echo "Candidates TSV  → $TSV"
echo "Candidates JSON → $JSON"
echo "(read-only — nothing was filed, commented, labeled, closed, or marked read)"
