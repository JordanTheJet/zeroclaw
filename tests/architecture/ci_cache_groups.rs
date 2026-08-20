//! Architecture invariants for the Blacksmith Rust cache families.

use std::{fs, path::Path};

fn quality_gate() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect("Quality Gate workflow should be readable")
}

fn top_level_job<'a>(workflow: &'a str, name: &str) -> &'a str {
    let marker = format!("\n  {name}:\n");
    let (_, rest) = workflow
        .split_once(&marker)
        .unwrap_or_else(|| panic!("workflow must contain the {name} job"));
    let end = rest
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let line = rest[offset + 1..].lines().next()?;
            (line.starts_with("  ")
                && !line.starts_with("    ")
                && !line.trim_start().starts_with('#')
                && line.trim_end().ends_with(':'))
            .then_some(offset)
        })
        .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn blacksmith_cache_families_are_shared_without_cross_target_pollution() {
    let workflow = quality_gate();
    let stable_key =
        "shared-key: ${{ vars.CI_USE_BLACKSMITH == 'true' && 'blacksmith-linux-stable-v1' || '' }}";

    for job in [
        "lint",
        "check",
        "check-plugin-backends",
        "bench",
        "test",
        "installer-drift",
    ] {
        assert!(
            top_level_job(&workflow, job).contains(stable_key),
            "{job} must use the shared stable-native Blacksmith cache"
        );
    }

    let build = top_level_job(&workflow, "build");
    assert!(build.contains(
        "shared-key: ${{ vars.CI_USE_BLACKSMITH == 'true' && matrix.target == 'x86_64-unknown-linux-gnu' && 'blacksmith-linux-stable-v1' || '' }}"
    ));

    let parallel = top_level_job(&workflow, "parallel-runtime-test");
    assert!(parallel.contains(
        "shared-key: ${{ vars.CI_USE_BLACKSMITH == 'true' && 'blacksmith-linux-stable-v1' || 'test' }}"
    ));

    assert!(top_level_job(&workflow, "check-32bit").contains(
        "shared-key: ${{ vars.CI_USE_BLACKSMITH == 'true' && 'blacksmith-linux-i686-v1' || '' }}"
    ));
    assert!(top_level_job(&workflow, "msrv").contains(
        "shared-key: ${{ vars.CI_USE_BLACKSMITH == 'true' && 'blacksmith-linux-msrv-v1' || '' }}"
    ));

    for job in ["windows-clippy-tools", "test-landlock", "security"] {
        assert!(
            !top_level_job(&workflow, job).contains("blacksmith-linux-"),
            "{job} must keep its existing non-Blacksmith cache isolation"
        );
    }
}
