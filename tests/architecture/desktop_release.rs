//! Release invariant: the macOS desktop sidecar must contain the dashboard.

use std::{fs, path::Path};

#[test]
fn windows_desktop_manifest_selects_common_controls_v6() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("apps/tauri/windows/app.manifest"))
        .expect("Windows desktop manifest should be readable");

    for required in [
        "name=\"Microsoft.Windows.Common-Controls\"",
        "version=\"6.0.0.0\"",
        "publicKeyToken=\"6595b64144ccf1df\"",
    ] {
        assert!(
            manifest.contains(required),
            "Windows desktop manifest must select Common Controls v6: missing {required}"
        );
    }

    let build_script = fs::read_to_string(root.join("apps/tauri/build.rs"))
        .expect("Tauri build script should be readable");
    assert!(
        build_script.contains("app_manifest(include_str!(\"windows/app.manifest\"))"),
        "Tauri must embed the guarded Windows application manifest"
    );
}

#[test]
fn macos_desktop_sidecar_embeds_the_web_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow = fs::read_to_string(root.join(".github/workflows/release-stable-manual.yml"))
        .expect("release workflow should be readable");
    let macos_job = workflow
        .split_once("\n  build-desktop:\n")
        .and_then(|(_, rest)| rest.split_once("\n  build-desktop-linux:\n"))
        .map(|(job, _)| job)
        .expect("macOS desktop release job should exist");

    assert!(
        macos_job.contains("needs: [validate, web]"),
        "macOS desktop release must wait for the canonical web-dist artifact"
    );
    assert!(
        macos_job.contains("uses: actions/download-artifact@")
            && macos_job.contains("name: web-dist")
            && macos_job.contains("path: web/dist/"),
        "macOS desktop release must restore web-dist at the embedded-web source path"
    );
    assert!(
        macos_job
            .contains("prepare-kernel.sh --target universal-apple-darwin --features embedded-web"),
        "macOS desktop kernel must enable the existing embedded-web Cargo feature"
    );
    let stage_position = macos_job
        .find("- name: Stage bundled kernel sidecar (universal)")
        .expect("macOS desktop release should stage its sidecar");
    let smoke_position = macos_job
        .find("- name: Smoke test embedded dashboard from an empty directory")
        .expect("macOS desktop release should smoke test the staged sidecar");
    let signing_position = macos_job
        .find("- name: Enable macOS signing")
        .expect("macOS desktop release should configure signing");
    assert!(
        stage_position < smoke_position && smoke_position < signing_position,
        "embedded dashboard smoke test must run immediately after sidecar staging"
    );

    let smoke_step = &macos_job[smoke_position..signing_position];
    assert!(
        smoke_step.contains("cd \"$smoke_cwd\"")
            && smoke_step.contains("--config-dir \"$config_dir\"")
            && smoke_step.contains("HOME=\"$smoke_home\"")
            && smoke_step.contains("XDG_DATA_HOME=\"$xdg_data_home\"")
            && smoke_step.contains("host=\"127.0.0.1\"")
            && smoke_step.contains("port=\"42618\"")
            && smoke_step.contains("origin=\"http://$host:$port\"")
            && smoke_step.contains("--host \"$host\" --port \"$port\""),
        "embedded dashboard smoke test must launch from an empty cwd with isolated config"
    );
    assert!(
        smoke_step.contains("curl --fail --silent --connect-timeout 1 --max-time 2")
            && smoke_step.contains("\"$origin/\"")
            && smoke_step.contains("id=\"root\""),
        "embedded dashboard smoke test must require a successful SPA response"
    );

    let prepare = fs::read_to_string(root.join("scripts/desktop/prepare-kernel.sh"))
        .expect("desktop kernel preparation script should be readable");
    assert!(
        prepare.lines().any(|line| {
            line.contains("cargo build") && line.contains("--features \"$FEATURES\"")
        }),
        "prepare-kernel.sh must forward the requested Cargo features"
    );
}

#[test]
fn desktop_bundle_dry_run_uses_the_real_dashboard_and_smoke_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workflow = fs::read_to_string(root.join(".github/workflows/desktop-bundle-check.yml"))
        .expect("desktop bundle dry-run workflow should be readable");

    assert!(
        workflow.contains("run: cargo web build")
            && workflow.contains("name: web-dist")
            && workflow.contains("path: web/dist/"),
        "the dry run must build and restore the real web dashboard"
    );
    assert!(
        !workflow.contains(".gitkeep"),
        "the dry run must not substitute a placeholder for the dashboard"
    );

    let bundle_job = workflow
        .split_once("\n  bundle:\n")
        .map(|(_, job)| job)
        .expect("desktop bundle dry run should have a bundle job");
    assert!(
        bundle_job.contains("needs: [web]"),
        "the bundle job must wait for the web dashboard build"
    );
    for os in ["macos-14", "ubuntu-22.04", "windows-latest"] {
        assert!(
            bundle_job.contains(&format!("os: {os}")),
            "the bundle dry run must cover {os}"
        );
    }

    let restore = bundle_job
        .find("uses: actions/download-artifact@")
        .expect("the bundle job must restore the web dashboard");
    let stage = bundle_job
        .find(
            "scripts/desktop/prepare-kernel.sh --target ${{ matrix.target }} --features embedded-web",
        )
        .expect("the bundle job must stage the kernel with embedded-web");
    let smoke = bundle_job
        .find("scripts/desktop/smoke-dashboard.sh \"apps/tauri/binaries/${{ matrix.kernel }}\"")
        .expect("the bundle job must smoke test the staged kernel");
    let bundle = bundle_job
        .find("cargo tauri build --config tauri.bundled.conf.json")
        .expect("the bundle job must build with the sidecar overlay");
    assert!(
        restore < stage && stage < smoke && smoke < bundle,
        "the dry run must restore the dashboard, stage, smoke test, then bundle"
    );
}

#[test]
fn desktop_dashboard_smoke_launches_like_a_fresh_install() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = fs::read_to_string(root.join("scripts/desktop/smoke-dashboard.sh"))
        .expect("desktop dashboard smoke script should be readable");

    assert!(
        script.contains("cd \"$smoke_cwd\"")
            && script.contains("--config-dir \"$(native_path \"$config_dir\")\"")
            && script.contains("HOME=\"$smoke_home\"")
            && script.contains("XDG_DATA_HOME=\"$xdg_data_home\"")
            && script.contains("host=\"127.0.0.1\"")
            && script.contains("--host \"$host\" --port \"$port\""),
        "the dashboard smoke must launch from an empty cwd with isolated config"
    );
    assert!(
        script.contains("\"$origin/\"")
            && script.contains("[[ \"$status_code\" == \"200\" ]]")
            && script.contains("grep -Fq 'id=\"root\"'"),
        "the dashboard smoke must require a successful SPA response"
    );
}
