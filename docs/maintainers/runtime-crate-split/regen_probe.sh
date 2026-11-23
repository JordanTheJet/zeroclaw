#!/bin/bash
# regen_probe.sh <base-ref> [worktree]
#
# Rebuilds the three-commit proof stack from scratch on <base-ref>, with no hand edits:
#   1. util            -> zeroclaw-infra            (extract_module.py)
#   2. redaction prep  -> zeroclaw-providers::redact (prep_redact.py)
#   3. observability   -> zeroclaw-observability     (extract_module.py)
#
# Safety: it only runs in a clean worktree on a detached HEAD, and it never resets or cleans
# one. It makes local commits there and pushes nothing. If a run fails part-way the worktree
# is left as it stood, for inspection; discard it yourself before the next run.
#
# Every check must be clean or the script stops with a non-zero exit. Clean means exactly the
# line cargo_diag.py calls CLEAN: no compiler error or warning, cargo's closing message
# received, and no warning on cargo's own stderr. CI denies warnings, so a warning here is a
# failure there. The script prints ALL CHECKS PASSED only at the very end.
#
# This is a proof driver for one disposable worktree. It stages everything under the paths it
# works in; tooling meant for the repository should stage an explicit list instead.
set -uo pipefail
T="$(cd "$(dirname "$0")" && pwd)"
WT="${2:-$HOME/git/zeroclaw-worktrees/runtime-detangle-probe}"
cd "$WT" || { echo "no such worktree: $WT"; exit 1; }
G="git -c user.name=runtime-detangle-probe -c user.email=probe@localhost -c gc.auto=0"
CLEAN="errors: none  warnings: none  finished: ok  cargo warnings: 0"

fail() { echo "FAILED: $*"; exit 1; }
refuse() { echo "REFUSING: $*"; exit 1; }
step() { echo "== $1"; }

# worktree_state: every change git can see, untracked files included whatever the user's
# status.showUntrackedFiles setting says. Fails if git itself fails.
worktree_state() { git -c status.showUntrackedFiles=all status --porcelain --untracked-files=all; }

# The base is pinned to a commit id here, so a moving name such as HEAD cannot change meaning
# once the script starts committing.
BASE=$(git rev-parse --verify --quiet "${1:?usage: regen_probe.sh <base-ref> [worktree]}^{commit}") \
  || refuse "unknown base ${1:-}"
state=$(worktree_state) || refuse "git status failed in $WT"
if [ -n "$state" ]; then
  echo "REFUSING: $WT has uncommitted or untracked changes."
  echo "This script rewrites the worktree. Use a disposable one, or discard the changes yourself first."
  exit 1
fi
git symbolic-ref -q HEAD > /dev/null; sr=$?      # 0: on a branch, 1: detached, anything else: git failed
case $sr in
  1) ;;
  0) refuse "$WT is on a branch. Use a disposable worktree on a detached HEAD." ;;
  *) refuse "cannot tell whether HEAD is detached in $WT (git symbolic-ref exited $sr)" ;;
esac

start=$(date +%s)
J=$(mktemp /tmp/rdp-check.XXXXXX.json) || exit 1
ERR=$(mktemp /tmp/rdp-check.XXXXXX.err) || exit 1
OUT=$(mktemp /tmp/rdp-step.XXXXXX.out) || exit 1
trap 'rm -f "$J" "$ERR" "$OUT"' EXIT
git checkout -q --detach "$BASE" || fail "git checkout $BASE"
git log --oneline -1 > "$OUT" || fail "git log"
echo "base: $(cut -c1-80 "$OUT")"

# run <cmd...>: run a generator, show its first line, stop on failure (and then show everything).
run() {
  if ! "$@" > "$OUT" 2>&1; then cat "$OUT"; fail "$1 $(basename "${2:-}")"; fi
  head -1 "$OUT"
}

# cargo_check <args...>: one cargo check; compiler messages in $J, cargo's own output in $ERR;
# returns cargo's exit code.
cargo_check() {
  CARGO_TERM_COLOR=never CARGO_PROFILE_DEV_DEBUG=0 cargo check "$@" --message-format=json > "$J" 2> "$ERR"
}

# diag: the one-line verdict on the last check ($J and $ERR).
diag() { python3 "$T/cargo_diag.py" "$J" "$ERR"; }

# clean_or_fail <label>: the last check must be exactly clean.
clean_or_fail() {
  local d; d=$(diag) || fail "cargo_diag.py"
  [ "$d" = "$CLEAN" ] || fail "$1 is not clean: $d"
}

# must_check <label> <args...>: a check that has to compile and be clean.
must_check() {
  local label="$1"; shift
  cargo_check "$@"; local rc=$?
  local d; d=$(diag) || fail "cargo_diag.py"
  echo "  $label: rc=$rc $d"
  [ $rc -eq 0 ] || { tail -5 "$ERR"; fail "$label did not compile"; }
  [ "$d" = "$CLEAN" ] || fail "$label is not clean"
}

WS=(--workspace --exclude zeroclaw-desktop --all-targets)

# loop <crate dir that may be edited>: check with the OTel feature on, letting widen_vis.py
# apply what the compiler names, until the check compiles. Only the round that compiles is
# inspected for warnings, because that round is the code that gets committed.
loop() {
  local r out d
  for r in 1 2 3 4 5; do
    if cargo_check "${WS[@]}" --features zeroclaw-runtime/observability-otel; then
      d=$(diag) || fail "cargo_diag.py"
      echo "  check ok (round $r): $d"
      [ "$d" = "$CLEAN" ] || fail "workspace check with OTel is not clean"
      return 0
    fi
    out=$(python3 "$T/widen_vis.py" --repo . --only "$1" --from-crate crates/zeroclaw-runtime < "$J") || fail "widen_vis.py"
    echo "$out" | sed 's/^/  /' | tail -6
    case "$out" in *$'\n'"0 edits"*|"0 edits"*) d=$(diag); fail "check is stuck: $d";; esac
  done
  fail "check did not converge in 5 rounds"
}

# commit <message>: format, then stage only the places these recipes write to.
commit() {
  cargo fmt --all || fail "cargo fmt"
  git add -A -- Cargo.toml Cargo.lock crates tests/fixtures/runtime-composition-consumer || fail "git add"
  state=$(worktree_state) || fail "git status"
  local line
  while IFS= read -r line; do     # after staging, nothing may be left unstaged or untracked
    [ -z "$line" ] && continue
    [ "${line:1:1}" = " " ] || { echo "$state"; fail "a change outside the expected paths: $line"; }
  done <<< "$state"
  $G commit -q -m "$1" || fail "git commit"
}

step "1. util -> zeroclaw-infra"
run python3 "$T/extract_module.py" --repo . --modules util --to-crate zeroclaw-infra
loop crates/zeroclaw-infra
commit "refactor(infra): move runtime util helpers into zeroclaw-infra"

step "2. redaction prep"
run python3 "$T/prep_redact.py" .
loop crates/zeroclaw-providers
commit "refactor(providers): give credential redaction one owner below the agent loop"

step "3. observability -> zeroclaw-observability"
run python3 "$T/extract_module.py" --repo . --modules observability --new-crate zeroclaw-observability \
  --description "Observer backends for ZeroClaw: log, verbose, Prometheus and OpenTelemetry export." \
  --retained-reason "Observer backends (log, verbose, Prometheus, OpenTelemetry) extracted from this crate; the runtime re-exports the module so existing zeroclaw_runtime::observability paths keep resolving." \
  --alias util=zeroclaw_infra::util
loop crates/zeroclaw-observability
commit "refactor(observability): extract observer backends into zeroclaw-observability"

step "final checks on the finished stack (each must be clean)"
[ "$(git rev-parse HEAD~3)" = "$BASE" ] || fail "the stack is not three commits on the base"
cargo fmt --all -- --check > /dev/null 2>&1 || fail "cargo fmt --check"
echo "  cargo fmt --check: ok"
must_check "workspace, all targets, with OTel" "${WS[@]}" --features zeroclaw-runtime/observability-otel
must_check "workspace, all targets, default features (CI row)" "${WS[@]}"
must_check "workspace, no default features (CI row)" --workspace --exclude zeroclaw-desktop --no-default-features
for feats in "" "observability-prometheus" "observability-otel" "test-util" "observability-otel,observability-prometheus,test-util"; do
  if [ -z "$feats" ]; then
    must_check "zeroclaw-observability alone, no features" -p zeroclaw-observability --all-targets
  else
    must_check "zeroclaw-observability alone, $feats" -p zeroclaw-observability --all-targets --features "$feats"
  fi
done
retained=$(python3 "$T/check_retained.py" .) || { echo "  $retained"; fail "retained-dependency list"; }
echo "  $retained"
state=$(worktree_state) || fail "git status"
[ -z "$state" ] || fail "the checks left the worktree dirty"

echo "  every file in the stack that is not an exact rename:"
git diff -M --name-status "$BASE" HEAD > "$OUT" || fail "git diff"
[ -s "$OUT" ] || fail "the stack changed nothing"
grep -v '^R100' "$OUT" | sed 's/^/    /'
echo "regenerated and checked in $(( $(date +%s) - start ))s"
for c in HEAD~2 HEAD~1 HEAD; do
  git show --stat -M --format="%h %s" "$c" > "$OUT" || fail "git show $c"
  sed -n '1p;$p' "$OUT"
done
echo "ALL CHECKS PASSED"
