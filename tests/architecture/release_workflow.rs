//! Architecture gates for release-workflow artifact identity.
//!
//! The macOS desktop job must notarize, staple, validate, and upload the same
//! DMG. Discovering the file independently in multiple steps can notarize one
//! image while publishing another.

use std::fs;
use std::path::Path;

fn release_workflow() -> String {
    let workflow_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release-stable-manual.yml");
    fs::read_to_string(&workflow_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", workflow_path.display()))
}

fn job_block<'a>(workflow: &'a str, name: &str) -> &'a str {
    let marker = format!("\n  {name}:\n");
    let (_, remainder) = workflow
        .split_once(&marker)
        .unwrap_or_else(|| panic!("release workflow must contain job {name}"));

    let mut offset = 0;
    for line in remainder.split_inclusive('\n') {
        let candidate = line.trim_end().strip_prefix("  ");
        if let Some(candidate) = candidate
            && !candidate.starts_with(' ')
            && let Some(candidate) = candidate.strip_suffix(':')
            && candidate
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
        {
            return &remainder[..offset];
        }
        offset += line.len();
    }

    remainder
}

fn job_names(workflow: &str) -> Vec<&str> {
    let (_, jobs) = workflow
        .split_once("\njobs:\n")
        .expect("release workflow must contain jobs");
    jobs.lines()
        .filter_map(|line| {
            let candidate = line.strip_prefix("  ")?;
            if candidate.starts_with(' ') {
                return None;
            }
            let candidate = candidate.strip_suffix(':')?;
            candidate
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
                .then_some(candidate)
        })
        .collect()
}

fn job_permissions(job: &str) -> Vec<&str> {
    let mut lines = job.lines();
    if !lines.any(|line| line == "    permissions:") {
        return Vec::new();
    }
    lines
        .take_while(|line| line.starts_with("      ") && !line.starts_with("        "))
        .map(str::trim)
        .collect()
}

#[test]
fn macos_desktop_release_notarizes_published_dmg() {
    let workflow = release_workflow();
    let macos_job = job_block(&workflow, "build-desktop");

    assert_eq!(
        macos_job.matches("MACOS_DMG_PATH:").count(),
        1,
        "the published DMG path must have exactly one source of truth"
    );
    for required in [
        "MACOS_DMG_PATH: desktop-assets/ZeroClaw.dmg",
        "dmg_dir=\"target/universal-apple-darwin/release/bundle/dmg\"",
        "dmg_candidates=(\"$dmg_dir\"/*.dmg)",
        "\"${#dmg_candidates[@]}\" -ne 1",
        "mv \"${dmg_candidates[0]}\" \"$MACOS_DMG_PATH\"",
        "notarytool submit \"$MACOS_DMG_PATH\"",
        "stapler staple \"$MACOS_DMG_PATH\"",
        "stapler validate \"$MACOS_DMG_PATH\"",
        "${{ env.MACOS_DMG_PATH }}",
    ] {
        assert!(
            macos_job.contains(required),
            "macOS desktop job is missing release invariant: {required}"
        );
    }

    assert!(
        !macos_job.contains("find target -name '*.dmg'"),
        "the macOS desktop job must not rediscover DMGs from the whole target tree"
    );

    let positions = [
        "mv \"${dmg_candidates[0]}\" \"$MACOS_DMG_PATH\"",
        "notarytool submit \"$MACOS_DMG_PATH\"",
        "stapler staple \"$MACOS_DMG_PATH\"",
        "stapler validate \"$MACOS_DMG_PATH\"",
        "uses: actions/upload-artifact@",
    ]
    .map(|needle| {
        macos_job
            .find(needle)
            .unwrap_or_else(|| panic!("macOS desktop job is missing ordered step: {needle}"))
    });
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "the final DMG must be prepared, notarized, stapled, validated, then uploaded"
    );
}

#[test]
fn macos_proof_release_only_publishes_the_verified_dmg() {
    let workflow = release_workflow();

    assert!(
        workflow.contains(
            "macos_proof_release:\n        description: \"Publish only a macOS CI proof prerelease\"\n        required: false\n        default: false\n        type: boolean"
        ),
        "the manual proof mode must be an explicit boolean that defaults off"
    );
    assert!(
        job_block(&workflow, "validate").contains("REF: ${{ github.ref }}")
            && job_block(&workflow, "validate")
                .contains("MACOS_PROOF_RELEASE: ${{ inputs.macos_proof_release }}")
            && job_block(&workflow, "validate").contains(
                "if [[ \"$MACOS_PROOF_RELEASE\" == \"true\" && \"$REF\" != \"refs/heads/master\" ]]"
            ),
        "proof releases must reject every source ref except master"
    );

    for job in ["validate", "web", "build-desktop"] {
        assert_eq!(
            job_permissions(job_block(&workflow, job)),
            ["contents: read"],
            "proof build job {job} must have read-only repository permissions"
        );
    }
    assert_eq!(
        job_permissions(job_block(&workflow, "publish-macos-proof")),
        ["contents: write"],
        "the proof publisher must only receive release-write permission"
    );

    let proof_jobs = ["validate", "web", "build-desktop", "publish-macos-proof"];
    let jobs = job_names(&workflow);
    for proof_job in proof_jobs {
        assert!(
            jobs.contains(&proof_job),
            "proof job allowlist entry {proof_job} must exist"
        );
    }
    for job in jobs.into_iter().filter(|job| !proof_jobs.contains(job)) {
        let job_if = job_block(&workflow, job)
            .lines()
            .find_map(|line| line.strip_prefix("    if: "));
        assert!(
            job_if.is_some_and(|condition| condition.contains("!inputs.macos_proof_release")),
            "job {job} must have a job-level guard disabling it during a macOS proof release"
        );
    }

    let macos_job = job_block(&workflow, "build-desktop");
    for required in [
        "MACOS_PROOF_RELEASE: ${{ inputs.macos_proof_release }}",
        "APPLE_CERTIFICATE is required for a macOS proof release",
        "APPLE_CERTIFICATE_PASSWORD is required for a macOS proof release",
        "APPLE_SIGNING_IDENTITY is required for a macOS proof release",
        "APPLE_ID is required for a macOS proof release",
        "APPLE_PASSWORD is required for a macOS proof release",
        "APPLE_TEAM_ID is required for a macOS proof release",
        "- name: Verify Developer ID app signature\n        if: ${{ inputs.macos_proof_release }}",
        "Authority=Developer ID Application:",
    ] {
        assert!(
            macos_job.contains(required),
            "proof build must enforce signing invariant: {required}"
        );
    }
    assert!(
        !macos_job.contains("continue-on-error:"),
        "the signed, notarized proof build must fail closed"
    );
    let positions = [
        "APPLE_CERTIFICATE is required for a macOS proof release",
        "cargo tauri build --target universal-apple-darwin",
        "codesign --verify --deep --strict",
        "mv \"${dmg_candidates[0]}\" \"$MACOS_DMG_PATH\"",
        "notarytool submit \"$MACOS_DMG_PATH\"",
        "stapler staple \"$MACOS_DMG_PATH\"",
        "stapler validate \"$MACOS_DMG_PATH\"",
        "uses: actions/upload-artifact@",
    ]
    .map(|needle| {
        macos_job
            .find(needle)
            .unwrap_or_else(|| panic!("proof build is missing ordered invariant: {needle}"))
    });
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "proof build must require credentials, sign, notarize, validate, then upload"
    );

    let proof_job = job_block(&workflow, "publish-macos-proof");
    for required in [
        "needs: [validate, build-desktop]",
        "if: ${{ inputs.macos_proof_release }}",
        "permissions:\n      contents: write",
        "name: desktop-macos",
        "find release-assets -type f -name '*.dmg' -print",
        "Expected exactly one macOS DMG",
        "\"${dmg_candidates[0]}\" != \"release-assets/ZeroClaw.dmg\"",
        "sha256sum ZeroClaw.dmg > SHA256SUMS",
        "desktop-ci-proof-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
        "Bundled kernel features: %s",
        "gh release create \"$proof_tag\"",
        "release-assets/ZeroClaw.dmg",
        "release-assets/SHA256SUMS",
        "--target \"$GITHUB_SHA\"",
        "--prerelease",
        "--latest=false",
    ] {
        assert!(
            proof_job.contains(required),
            "macOS proof publisher is missing invariant: {required}"
        );
    }
    for forbidden in ["run-id:", "repository:", "release-assets/*", "--draft"] {
        assert!(
            !proof_job.contains(forbidden),
            "macOS proof publisher must not contain: {forbidden}"
        );
    }
    assert_eq!(
        proof_job.matches("gh release create").count(),
        1,
        "the proof job must have exactly one release mutation"
    );
    assert!(
        !proof_job.lines().any(|line| line.trim() == "--latest"),
        "proof releases must never become the latest release"
    );
}
