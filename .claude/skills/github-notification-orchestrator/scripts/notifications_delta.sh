#!/usr/bin/env bash
# notifications_delta.sh — Piece A of the ZeroClaw proactive poll-and-delegate loop.
#
#   Usage:
#     notifications_delta.sh delta  <state-dir> <out-dir>
#     notifications_delta.sh commit <state-dir> <out-dir>
#
# WHY THIS EXISTS — keeping compute flat
# --------------------------------------
# A ~10-minute cron tick should NOT re-draft the entire inbox every time; if it
# did, compute would grow with inbox size and never settle. Instead this script
# computes the DELTA of unread notifications since the last tick, so each run
# only surfaces NEW or RE-ACTIVATED threads. A quiet inbox => empty delta =>
# zero downstream drafting work.
#
# THE LOOP (orchestration contract)
# ---------------------------------
#     delta  ->  draft each new item  ->  commit
#
#   1. `delta`  refreshes notifications.tsv (read-only gh) and diffs it against a
#               durable seen-file (<state-dir>/seen.tsv: thread_id -> last-drafted
#               updated_at). It writes <out-dir>/new.tsv with ONLY the rows that
#               are new (thread_id unseen) or re-activated (updated_at strictly
#               newer than what we last drafted). It NEVER touches seen.tsv.
#   2. caller   drafts a file per row in new.tsv (this happens outside this script).
#   3. `commit` folds the CURRENT notifications.tsv into seen.tsv atomically, so
#               the next tick's delta excludes everything we just drafted.
#
# AT-LEAST-ONCE, AND WHY THAT'S SAFE
# ----------------------------------
# Because `delta` and `commit` are separate steps, a crash between "draft" and
# "commit" means the next tick re-emits those rows and re-drafts them. That is
# AT-LEAST-ONCE delivery. It is SAFE here because the whole skill is DRAFT-ONLY:
# a duplicate "draft" just overwrites a local file — nothing is posted to GitHub,
# no comment, no review, nothing is marked read. So a daemon restart with
# catch_up_on_startup=true does NOT replay a backlog of POSTED side effects; at
# worst it re-writes a few draft files that get harmlessly overwritten.
#
# Every gh call in the path is READ-ONLY (it all flows through
# fetch_notifications.sh, which only reads `gh api notifications`).
#
# STATE & OUTPUT FILES
#   <state-dir>/seen.tsv          durable: <thread_id>\t<updated_at> (one per line)
#   <out-dir>/notifications.tsv   current unread snapshot (written by fetch script)
#   <out-dir>/new.tsv             the delta: rows from notifications.tsv to draft
#
# notifications.tsv columns (shared with fetch_notifications.sh):
#   1 reason  2 type  3 repo  4 number  5 title  6 updated_at  7 html_url  8 thread_id
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FETCH="$SCRIPT_DIR/fetch_notifications.sh"

# Column indices within notifications.tsv / new.tsv (1-based, tab-separated).
COL_UPDATED_AT=6
COL_THREAD_ID=8

usage() {
  echo "usage: notifications_delta.sh {delta|commit} <state-dir> <out-dir>" >&2
  exit 2
}

# --- delta ------------------------------------------------------------------
# Refresh the snapshot, then emit rows that are new or re-activated vs seen.tsv.
# Does NOT modify seen.tsv.
cmd_delta() {
  local state_dir="$1" out_dir="$2"
  mkdir -p "$state_dir" "$out_dir"

  local seen="$state_dir/seen.tsv"
  local notifs="$out_dir/notifications.tsv"
  local new="$out_dir/new.tsv"

  # Refresh the current unread snapshot (read-only gh inside).
  "$FETCH" "$out_dir" >&2

  # First run / never committed: treat seen as empty.
  [[ -f "$seen" ]] || : > "$seen"
  # Zero unread: notifications.tsv may be absent or empty -> empty delta, exit 0.
  [[ -f "$notifs" ]] || : > "$notifs"

  # awk does the join: load seen (thread_id -> updated_at), then for each current
  # row, keep it if the thread_id is unseen OR its updated_at is strictly newer.
  # updated_at is RFC3339 (e.g. 2026-06-27T18:04:11Z); lexical string compare is
  # a correct chronological compare for that fixed-width UTC format.
  #
  # NOTE: we discriminate the seen-file from the snapshot via FILENAME, NOT the
  # classic `FNR==NR` idiom. When the seen-file is empty (first run), it yields
  # zero records, so `FNR==NR` would still be true on the snapshot's first row
  # and mis-load it as "seen" — silently dropping a real notification. FILENAME
  # is immune to an empty first file.
  awk -F'\t' \
    -v seenfile="$seen" -v idc="$COL_THREAD_ID" -v upc="$COL_UPDATED_AT" \
    'FILENAME == seenfile {
       # The seen-file. Field 1 = thread_id, field 2 = updated_at.
       if (NF >= 1 && $1 != "") seen[$1] = $2
       next
     }
     {
       tid = $idc
       up  = $upc
       if (tid == "") next                       # skip malformed rows
       if (!(tid in seen) || up > seen[tid]) print
     }' "$seen" "$notifs" > "$new"

  local count
  count=$(wc -l < "$new" | tr -d ' ')
  echo "delta: ${count} new/updated notification(s) -> ${new}"
}

# --- commit -----------------------------------------------------------------
# Fold the CURRENT snapshot into seen.tsv with an atomic temp-file + mv.
# Idempotent: re-running with the same snapshot leaves seen.tsv unchanged.
cmd_commit() {
  local state_dir="$1" out_dir="$2"
  mkdir -p "$state_dir"

  local seen="$state_dir/seen.tsv"
  local notifs="$out_dir/notifications.tsv"

  [[ -f "$seen" ]] || : > "$seen"
  [[ -f "$notifs" ]] || : > "$notifs"

  # Build the merged seen map: start from existing seen, then upsert each current
  # thread to the MAX(seen_updated_at, current_updated_at) so we never regress.
  local tmp
  tmp="$(mktemp "${seen}.XXXXXX")"
  # Clean up the temp file if we die before the atomic mv.
  trap 'rm -f "$tmp"' RETURN

  # Same FILENAME discriminator as cmd_delta — robust to an empty seen-file on
  # the very first commit (see the note in cmd_delta).
  awk -F'\t' \
    -v seenfile="$seen" -v idc="$COL_THREAD_ID" -v upc="$COL_UPDATED_AT" \
    'FILENAME == seenfile {
       if (NF >= 1 && $1 != "") { seen[$1] = $2; if (!($1 in order)) { order[$1]=1; ord[++n]=$1 } }
       next
     }
     {
       tid = $idc; up = $upc
       if (tid == "") next
       if (!(tid in seen) || up > seen[tid]) seen[tid] = up
       if (!(tid in order)) { order[tid]=1; ord[++n]=tid }
     }
     END {
       for (i = 1; i <= n; i++) printf "%s\t%s\n", ord[i], seen[ord[i]]
     }' "$seen" "$notifs" \
    | LC_ALL=C sort > "$tmp"

  # Atomic publish: a reader either sees the old or the new file, never a partial.
  mv -f "$tmp" "$seen"
  trap - RETURN

  local count
  count=$(wc -l < "$seen" | tr -d ' ')
  echo "commit: seen.tsv now tracks ${count} thread(s) -> ${seen}"
}

main() {
  [[ $# -ge 1 ]] || usage
  local mode="$1"; shift
  case "$mode" in
    delta)
      [[ $# -eq 2 ]] || usage
      cmd_delta "$1" "$2"
      ;;
    commit)
      [[ $# -eq 2 ]] || usage
      cmd_commit "$1" "$2"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
