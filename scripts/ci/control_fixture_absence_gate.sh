#!/usr/bin/env bash
# Assert the control-plane fixture-credential identifiers are absent from a
# built `zeroclaw` artifact, and that real control-plane strings are present.
#
# Usage: control_fixture_absence_gate.sh [binary_path]
#
# Arguments:
#   binary_path  Artifact to inspect. Defaults to the profile's `zeroclaw`
#                binary under `target/`. Pass a path to point the gate at the
#                artifact a release job actually produced, the way
#                `check_binary_size.sh` is reused across workflows.
#
# Environment:
#   CONTROL_FIXTURE_GATE_PROFILE  Cargo profile to locate/build (default: release)
#   CONTROL_FIXTURE_GATE_BUILD    Set to 1 to build the artifact when missing
#   CONTROL_FIXTURE_GATE_CARGO    Cargo binary to build with (default: cargo)
#   CI / GITHUB_ACTIONS           When set, a missing artifact is an error,
#                                 never a skip
#
# Why this gate exists
#
# `crates/zeroclaw-control/src/principal.rs` compiles every fixture-grant
# constructor under the `fixture-grants` Cargo feature, which only the
# workspace's `[dev-dependencies]` entry enables. That is a compile-time
# argument, and it is a good one, but it is an argument about the build graph
# rather than a measurement of the artifact. This gate measures the artifact.
#
# It searches for stored *strings*, not symbols, on purpose. `[profile.release]`
# sets `strip = true`, so symbol names such as `RequesterGrant::fixture` are not
# in a shipped binary whether or not the fixture path compiled — a symbol search
# would pass vacuously. `FIXTURE_CREDENTIAL_MARKER` is stored in every fixture
# grant rather than merely declared precisely so that linking the fixture path
# necessarily puts a byte sequence in `.rodata` that this gate can find.
#
# The positive control is what stops the negative assertions from passing on an
# empty, truncated, or wrong-target file: a binary with no control-plane strings
# at all trivially contains no fixture strings either.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${CONTROL_FIXTURE_GATE_PROFILE:-release}"
# Cargo writes `--release` output to target/release and every other profile to
# target/<profile>.
if [ "$PROFILE" = "release" ]; then
    PROFILE_DIR="release"
else
    PROFILE_DIR="$PROFILE"
fi

BIN="${1:-target/${PROFILE_DIR}/zeroclaw}"

# Fixture-only identifiers. Every one of these is behind `#[cfg(feature =
# "fixture-grants")]` in crates/zeroclaw-control/src/principal.rs, so finding
# one in an artifact means a released build linked the fixture path.
#
# Deliberately NOT listed: the bare word `fixture`. A release binary legitimately
# contains it (eval trace-fixture help text, sample config values), so it would
# fail every run without indicating anything.
FORBIDDEN=(
    # principal.rs: FIXTURE_ASSURANCE_CLASS
    'test_only'
    # principal.rs: FIXTURE_CREDENTIAL_MARKER
    'zeroclaw-control-fixture-grant-test-only-do-not-ship'
)

# Positive control: real control-plane strings that a correctly built artifact
# must contain, so the absence assertions above cannot pass vacuously.
REQUIRED=(
    # protocol.rs: TOOL_REGISTRATION_HELP
    'control.registration_help'
    # protocol.rs: ControlErrorCode::UnregisteredClient
    'unregistered_client'
)

in_ci() {
    [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]
}

echo "==> control fixture-absence gate: profile '${PROFILE}'"

if [ ! -f "$BIN" ]; then
    if [ "${CONTROL_FIXTURE_GATE_BUILD:-}" = "1" ]; then
        cargo_bin="${CONTROL_FIXTURE_GATE_CARGO:-cargo}"
        echo "==> building ${BIN} (profile ${PROFILE})"
        if [ "$PROFILE" = "release" ]; then
            "$cargo_bin" build --release --locked --bin zeroclaw
        else
            "$cargo_bin" build --profile "$PROFILE" --locked --bin zeroclaw
        fi
    elif in_ci; then
        echo "::error::control fixture-absence gate: artifact not found at ${BIN}"
        echo "The gate cannot vouch for an artifact it never inspected, so a" >&2
        echo "missing binary is a failure in CI rather than a skip. Build it" >&2
        echo "first, or set CONTROL_FIXTURE_GATE_BUILD=1 to have the gate" >&2
        echo "build it, or pass the artifact path as the first argument." >&2
        exit 1
    else
        echo "SKIP: control fixture-absence gate did not run."
        echo "  Reason:   no artifact at ${BIN}"
        echo "  Verified: nothing — this run proves nothing about any binary."
        echo "  To run it: CONTROL_FIXTURE_GATE_BUILD=1 $0"
        echo "  Or:        cargo build --release --bin zeroclaw && $0"
        echo "  In CI this same condition is a hard failure, not a skip."
        exit 0
    fi
fi

if [ ! -r "$BIN" ]; then
    echo "::error::control fixture-absence gate: ${BIN} exists but is not readable"
    exit 1
fi

echo "==> inspecting ${BIN}"

# `grep -a` treats the artifact as text; `-F` keeps the '.' in
# 'control.registration_help' a literal dot rather than a wildcard.
#
# Called only as an `if` condition, never in a command substitution, so a
# failure can abort the gate rather than exiting a subshell unnoticed. grep
# distinguishes "no match" (1) from a real error (2+), and the difference
# matters here: treating an I/O error as "not found" would report a fixture
# identifier as absent from a binary the gate never managed to read.
contains() {
    LC_ALL=C grep -a -q -F -e "$1" -- "$BIN"
}

fatal_unless_clean_miss() {
    local status="$1" marker="$2"
    if [ "$status" -ne 1 ]; then
        echo "::error::failed to scan ${BIN} for '${marker}' (grep exit ${status})" >&2
        echo "  The gate cannot report absence from a scan that did not run." >&2
        exit 1
    fi
}

failed=0

for marker in "${FORBIDDEN[@]}"; do
    if contains "$marker"; then
        echo "::error file=crates/zeroclaw-control/src/principal.rs::fixture identifier '${marker}' found in ${BIN}"
        echo "  A released artifact linked the fixture-grant path." >&2
        failed=1
    else
        fatal_unless_clean_miss "$?" "$marker"
        echo "  absent (ok): ${marker}"
    fi
done

for marker in "${REQUIRED[@]}"; do
    if contains "$marker"; then
        echo "  present (ok): ${marker}"
    else
        fatal_unless_clean_miss "$?" "$marker"
        echo "::error::positive control '${marker}' missing from ${BIN}"
        echo "  Without it the absence checks above prove nothing: an empty or" >&2
        echo "  wrong artifact contains no fixture strings either. Confirm this" >&2
        echo "  is a zeroclaw build carrying the control plane." >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "control fixture-absence gate FAILED for ${BIN}" >&2
    exit 1
fi

echo "control fixture-absence gate passed: no fixture identifiers, control plane present."
