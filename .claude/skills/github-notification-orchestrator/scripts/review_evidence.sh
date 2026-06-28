#!/usr/bin/env bash
# Review WITH EVIDENCE: check out a PR's head into a throwaway workspace, run the
# validation battery in a SANDBOX, and append the captured results to the PR's
# review draft. READ-ONLY on GitHub — it fetches the PR head and runs cargo; it
# NEVER posts, reviews, or opens a PR. The workspace (worktree) is always deleted.
#
# SANDBOX: building/testing a PR EXECUTES that PR's code (build.rs, proc-macros,
# and — with --deep — its tests). So the battery runs inside an EPHEMERAL container
# (docker/podman) with ONLY the PR worktree mounted (host secrets never exposed).
# If no container runtime is present this REFUSES, unless --allow-host is given
# (run on the host directly — only for authors you trust).
#
#   usage: review_evidence.sh <gh-notif-workspace-dir> --only <draft-filename>
#                             [--deep] [--allow-host] [--repo OWNER/REPO]
#   default battery: cargo check     --deep: cargo fmt --check + clippy -D warnings + test
set -uo pipefail

WS=""; ONLY=""; ONLYREPO=""; DEEP=0; ALLOW_HOST=0
need_val() { [ -n "${2:-}" ] || { echo "flag $1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --deep) DEEP=1;;
    --allow-host) ALLOW_HOST=1;;
    --only) need_val "$1" "${2:-}"; ONLY="$2"; shift;;
    --repo) need_val "$1" "${2:-}"; ONLYREPO="$2"; shift;;
    -*) echo "unknown flag: $1" >&2; exit 2;;
    *) if [ -z "$WS" ]; then WS="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi;;
  esac
  shift
done
[ -n "$WS" ] || { echo "usage: review_evidence.sh <ws> --only <draft-filename> [--deep] [--allow-host] [--repo O/R]" >&2; exit 2; }
[ -n "$ONLY" ] || { echo "review_evidence: --only <draft-filename> is required (one PR at a time)" >&2; exit 2; }

CLONE="$WS/drafts-repo"
[ -d "$CLONE/.git" ] || { echo "no drafts-repo clone at $CLONE" >&2; exit 0; }
git -C "$CLONE" pull --ff-only --quiet 2>/dev/null || true
CODE_BASE="$WS/code-repos"; GH_USER="$(gh api user --jq .login 2>/dev/null || echo "")"
[ -n "$GH_USER" ] || { echo "ERROR: not authenticated to gh" >&2; exit 2; }

fm_get() { awk -v key="$2" 'BEGIN{n=0} /^---[[:space:]]*$/{n++; if(n>=2)exit; next} n==1{i=index($0,":"); if(i==0)next; k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k); if(k==key){v=substr($0,i+1); sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v); if(v ~ /^".*"$/)v=substr(v,2,length(v)-2); print v; exit}}' "$1"; }

draft=""
shopt -s nullglob
for f in "$CLONE"/triage/*/items/*.md; do [ "$(basename "$f")" = "$ONLY" ] && { draft="$f"; break; }; done
[ -n "$draft" ] || { echo "review_evidence: no draft named $ONLY" >&2; exit 2; }
repo="$(fm_get "$draft" repo)"; number="$(fm_get "$draft" number)"; typ="$(fm_get "$draft" type)"
[ -z "$ONLYREPO" ] || [ "$repo" = "$ONLYREPO" ] || { echo "draft repo $repo != --repo $ONLYREPO" >&2; exit 2; }
[ "$typ" = "PullRequest" ] || { echo "review_evidence: $(basename "$draft") is type '$typ', not a PullRequest" >&2; exit 2; }
[ -n "$number" ] || { echo "review_evidence: draft has no PR number" >&2; exit 2; }

reponame="${repo#*/}"; fork="$GH_USER/$reponame"; clone="$CODE_BASE/$reponame"
if [ ! -d "$clone/.git" ]; then
  mkdir -p "$CODE_BASE"; echo "cloning $fork (first time; large repo — a few minutes)…"
  git clone "https://github.com/$fork.git" "$clone" || { echo "ERROR: clone $fork failed"; exit 1; }
fi
git -C "$clone" remote get-url upstream >/dev/null 2>&1 || git -C "$clone" remote add upstream "https://github.com/$repo.git"
echo "fetching PR #$number head from $repo (read-only)…"
git -C "$clone" fetch upstream "pull/$number/head" --quiet || { echo "ERROR: fetch PR #$number failed"; exit 1; }
head_sha="$(git -C "$clone" rev-parse FETCH_HEAD)"
wt="$clone.wt/pr-$number"
git -C "$clone" worktree remove --force "$wt" 2>/dev/null || true
[ -n "$reponame" ] && [ -n "$number" ] && rm -rf "$wt"
git -C "$clone" worktree add --detach "$wt" "$head_sha" >/dev/null 2>&1 || { echo "ERROR: worktree add failed"; exit 1; }
echo "PR #$number @ ${head_sha:0:12} checked out in $wt"
cleanup() { git -C "$clone" worktree remove --force "$wt" 2>/dev/null || true; }   # always delete the workspace

if [ "$DEEP" = 1 ]; then
  BATT='set +e; cargo fmt --all -- --check; echo "[fmt exit $?]"; cargo clippy --all-targets -- -D warnings; echo "[clippy exit $?]"; cargo test; echo "[test exit $?]"'
  battery_label='cargo fmt --check + clippy -D warnings + test'
else
  BATT='set +e; cargo check --all-targets; echo "[check exit $?]"'
  battery_label='cargo check --all-targets'
fi

RT=""
for c in docker podman; do command -v "$c" >/dev/null 2>&1 && "$c" info >/dev/null 2>&1 && { RT="$c"; break; }; done
log="$(mktemp)"
if [ -n "$RT" ]; then
  sandbox_note="$RT container (ephemeral; only the PR worktree mounted; host secrets not exposed)"
  echo "sandbox: $sandbox_note"
  "$RT" run --rm --pull=missing \
    -v "$wt":/work -w /work \
    -v ghnotif-cargo:/usr/local/cargo/registry \
    rust:slim bash -lc "$BATT" > "$log" 2>&1 || true
elif [ "$ALLOW_HOST" = 1 ]; then
  sandbox_note="HOST (no container — ran with --allow-host)"
  echo "⚠️  $sandbox_note: executing PR code directly on the host"
  ( cd "$wt" && bash -lc "$BATT" ) > "$log" 2>&1 || true
else
  echo "REFUSING: building/testing a PR runs its code, and no container runtime (docker/podman) is available." >&2
  echo "  Install one — e.g.  brew install colima docker && colima start   (or podman) — then re-run." >&2
  echo "  Or pass --allow-host to run on the host directly (ONLY for authors you trust)." >&2
  rm -f "$log"; cleanup; exit 3
fi
overall="$(grep -oE '\[(fmt|clippy|test|check) exit [0-9]+\]' "$log" | grep -qvE 'exit 0\]' && echo '⚠️ FAIL/warnings' || echo '✅ PASS')"
echo "result: $overall ($sandbox_note)"

when="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  printf '\n## Build evidence (ran locally %s)\n' "$when"
  printf '%s · PR #%s head `%s` · `%s` · sandbox: %s\n\n' "$overall" "$number" "${head_sha:0:12}" "$battery_label" "$sandbox_note"
  printf '```\n'; tail -n 25 "$log"; printf '\n```\n'
} >> "$draft"
rm -f "$log"; cleanup

git -C "$CLONE" add -A
git -C "$CLONE" -c user.name='gh_notif' -c user.email='gh-notif@local' commit -q -m "review evidence: PR #$number ($overall)" || true
git -C "$CLONE" push -q || true
echo "appended Build-evidence to $(basename "$draft") and pushed. $overall"
exit 0
