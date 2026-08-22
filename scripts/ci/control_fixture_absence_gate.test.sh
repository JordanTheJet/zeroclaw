#!/usr/bin/env bash
# Fixtures for control_fixture_absence_gate.sh.
#
# The gate's whole value is that it fails when a fixture identifier is present.
# A gate that always passes looks identical to a working one on a clean tree, so
# these cases plant each identifier in a synthetic artifact and assert the gate
# rejects it — including the positive-control cases, which prove the absence
# assertions cannot pass on an empty or wrong file.
#
# Synthetic artifacts stand in for a real 23MB binary here on purpose: the gate
# reads its input as an opaque byte stream, so a small file exercises exactly the
# same detector without a fat-LTO release build per case.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="${script_dir}/control_fixture_absence_gate.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# A well-formed artifact: both positive controls, no fixture identifiers, and
# some binary noise so the gate is never fed a tidy text file.
write_clean_artifact() {
    local path="$1"
    {
        printf 'control.registration_help\0unregistered_client\0'
        printf 'isolated_descriptor\0sandbox_isolated_store\0'
        printf '\x7fELF\x02\x01\x01\x00some unrelated trace fixture help text\0'
    } >"$path"
}

# Runs the gate with CI set, so a missing artifact can never be scored as a pass.
run_gate() {
    CI=true "$gate" "$@" >"${workdir}/out" 2>&1
}

expect_pass() {
    local name="$1"
    shift
    if run_gate "$@"; then
        return 0
    fi
    echo "FAIL: expected the gate to PASS for ${name}, but it failed:" >&2
    cat "${workdir}/out" >&2
    exit 1
}

expect_fail() {
    local name="$1"
    local needle="$2"
    shift 2
    if run_gate "$@"; then
        echo "FAIL: expected the gate to FAIL for ${name}, but it passed:" >&2
        cat "${workdir}/out" >&2
        exit 1
    fi
    if ! grep -qF -- "$needle" "${workdir}/out"; then
        echo "FAIL: ${name} failed, but not for the expected reason." >&2
        echo "  expected output to mention: ${needle}" >&2
        cat "${workdir}/out" >&2
        exit 1
    fi
}

# --- baseline -------------------------------------------------------------
# Establishes that the fixtures below fail because of what they plant, not
# because the gate rejects everything.
clean="${workdir}/clean"
write_clean_artifact "$clean"
expect_pass "a clean artifact" "$clean"

# --- forbidden identifiers ------------------------------------------------
# One case per `#[cfg(feature = "fixture-grants")]` string constant in
# crates/zeroclaw-control/src/principal.rs.
assurance="${workdir}/assurance_class"
write_clean_artifact "$assurance"
printf 'test_only\0' >>"$assurance"
expect_fail "FIXTURE_ASSURANCE_CLASS planted" "test_only" "$assurance"

marker="${workdir}/credential_marker"
write_clean_artifact "$marker"
printf 'zeroclaw-control-fixture-grant-test-only-do-not-ship\0' >>"$marker"
expect_fail "FIXTURE_CREDENTIAL_MARKER planted" \
    "zeroclaw-control-fixture-grant-test-only-do-not-ship" "$marker"

# A marker split across the artifact must still be caught wherever it lands, so
# the detector is not accidentally anchored to the head of the file.
trailing="${workdir}/trailing"
write_clean_artifact "$trailing"
head -c 4096 /dev/zero >>"$trailing"
printf 'test_only\0' >>"$trailing"
head -c 4096 /dev/zero >>"$trailing"
expect_fail "identifier planted deep in the artifact" "test_only" "$trailing"

# --- positive control -----------------------------------------------------
# Without these the absence assertions are vacuous: a file with no control-plane
# strings contains no fixture strings either.
empty="${workdir}/empty"
: >"$empty"
expect_fail "an empty artifact" "control.registration_help" "$empty"

no_help="${workdir}/no_registration_help"
printf 'unregistered_client\0' >"$no_help"
expect_fail "artifact missing control.registration_help" \
    "control.registration_help" "$no_help"

no_code="${workdir}/no_unregistered_client"
printf 'control.registration_help\0' >"$no_code"
expect_fail "artifact missing unregistered_client" "unregistered_client" "$no_code"

# The positive control must match literally: '.' is a regex wildcard, and a gate
# that let it stay one would accept an artifact that never mentions the tool.
wildcard="${workdir}/wildcard_only"
printf 'controlXregistration_help\0unregistered_client\0' >"$wildcard"
expect_fail "artifact with only a wildcard-shaped near miss" \
    "control.registration_help" "$wildcard"

# --- unreadable artifact --------------------------------------------------
# An artifact the gate cannot read must be an error, never an "absent (ok)".
# Reporting a fixture identifier as absent from a scan that never ran is the
# one failure mode that would make this gate worse than no gate at all.
# Skipped when running as root, for whom the mode bits below are advisory.
if [ "$(id -u)" -ne 0 ]; then
    unreadable="${workdir}/unreadable"
    write_clean_artifact "$unreadable"
    chmod 000 "$unreadable"
    expect_fail "an unreadable artifact" "not readable" "$unreadable"
    chmod 644 "$unreadable"
fi

# --- missing artifact -----------------------------------------------------
# In CI a missing artifact is a failure: the gate must never report success for
# a binary it did not inspect.
expect_fail "a missing artifact under CI" "artifact not found" \
    "${workdir}/does-not-exist"

# Locally the same condition is a clearly labelled skip rather than a silent
# pass, so a developer is told the run proved nothing.
if ! out="$(env -u CI -u GITHUB_ACTIONS "$gate" "${workdir}/does-not-exist" 2>&1)"; then
    echo "FAIL: expected a local skip to exit 0 for a missing artifact:" >&2
    echo "$out" >&2
    exit 1
fi
for phrase in "SKIP" "proves nothing" "hard failure"; do
    if ! grep -qF -- "$phrase" <<<"$out"; then
        echo "FAIL: local skip must report itself; missing '${phrase}' in:" >&2
        echo "$out" >&2
        exit 1
    fi
done

echo "control_fixture_absence_gate.sh fixtures passed."
