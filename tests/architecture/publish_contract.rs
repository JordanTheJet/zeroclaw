//! Architecture gates for the crates.io publish contract.
//!
//! Publishing is irreversible — a version can be yanked but never replaced — and
//! every invariant here corresponds to a failure that is invisible during normal
//! development and only surfaces mid-publish, after earlier crates in the
//! dependency order have already uploaded.
//!
//! Each gate below encodes a defect that actually occurred:
//!
//! * a `publish = false` crate inside the root's dependency closure (#5811,
//!   which blocked every release after the microkernel split)
//! * a git dependency with no `version`, which crates.io rejects outright
//! * an `include_str!` reaching outside its own crate directory, which packages
//!   fine and then fails to compile from the tarball

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// The crate the world installs. Renamed from `zeroclawlabs` so that
/// `cargo install zeroclaw` matches the binary name.
const ROOT_PACKAGE: &str = "zeroclaw";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct Crate {
    name: String,
    dir: PathBuf,
    manifest: toml::Table,
    publishable: bool,
}

/// `publish` is absent when unrestricted, `false` when private. crates.io also
/// accepts a registry allow-list, which this workspace does not use.
fn is_publishable(manifest: &toml::Table) -> bool {
    manifest
        .get("package")
        .and_then(|p| p.get("publish"))
        .is_none_or(|v| v.as_bool() != Some(false))
}

fn workspace_crates() -> Vec<Crate> {
    let root = repo_root();
    let root_manifest: toml::Table = fs::read_to_string(root.join("Cargo.toml"))
        .expect("read workspace Cargo.toml")
        .parse()
        .expect("workspace Cargo.toml is valid TOML");

    let members = root_manifest["workspace"]["members"]
        .as_array()
        .expect("[workspace] members must be an array");

    members
        .iter()
        .map(|m| {
            let rel = m.as_str().expect("member entries are strings");
            let dir = if rel == "." {
                root.clone()
            } else {
                root.join(rel)
            };
            let manifest: toml::Table = fs::read_to_string(dir.join("Cargo.toml"))
                .unwrap_or_else(|e| panic!("read {rel}/Cargo.toml: {e}"))
                .parse()
                .unwrap_or_else(|e| panic!("{rel}/Cargo.toml is valid TOML: {e}"));
            let name = manifest["package"]["name"]
                .as_str()
                .expect("package name is a string")
                .to_owned();
            let publishable = is_publishable(&manifest);
            Crate {
                name,
                dir,
                manifest,
                publishable,
            }
        })
        .collect()
}

/// Internal dependency edges that affect publish order. Dev-dependencies are
/// excluded: cargo strips them when packaging, so a dev-only cycle is legal.
fn internal_deps(krate: &Crate, workspace_names: &BTreeSet<String>) -> BTreeSet<String> {
    ["dependencies", "build-dependencies"]
        .iter()
        .filter_map(|section| krate.manifest.get(*section))
        .filter_map(|v| v.as_table())
        .flat_map(|t| t.keys())
        .filter(|k| workspace_names.contains(*k))
        .cloned()
        .collect()
}

/// Resolve `base/relative` without touching the filesystem, so the comparison
/// is about the declared path rather than whatever happens to exist locally.
fn normalize(base: &Path, relative: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Rust sources belonging to the crate rooted at `dir`.
///
/// Skips any subdirectory that has its own `Cargo.toml`, mirroring cargo: a
/// nested package is a separate crate and its files are excluded from the parent's
/// tarball. Without this the root package (whose directory is the repo root) would
/// vacuum up every other member's sources and misattribute their includes.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default();
            // `target/` is build output; `.`-prefixed dirs are tooling.
            if name == "target" || name.to_string_lossy().starts_with('.') {
                continue;
            }
            if path.join("Cargo.toml").is_file() {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// One compile-time file reference and the directory its path is relative to.
struct Include {
    /// Path as written, with any `CARGO_MANIFEST_DIR` prefix already stripped.
    path: String,
    /// True when the path is anchored at the crate root rather than the source file.
    from_crate_root: bool,
}

/// Every compile-time file reference in `source`.
///
/// Handles the four spellings that appear in this workspace. The naive "first
/// string literal" scan this replaced silently missed the `concat!` form and let
/// seven escaping includes through in `zeroclaw-hardware`; `bindgen!` was missed
/// in turn because it is not an `include_*` macro at all, yet reads a directory
/// from disk at compile time exactly like one:
///
/// ```ignore
/// include_str!("../locales/en/tools.ftl")                     // file-relative
/// include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/x"))   // crate-root-relative
/// include_dir!("$CARGO_MANIFEST_DIR/../../web/dist")          // crate-root-relative
/// bindgen!({ world: "w", path: "wit/v0" })                    // crate-root-relative
/// ```
fn compile_time_includes(source: &str) -> Vec<Include> {
    const MACROS: [&str; 4] = ["include_str!", "include_bytes!", "include_dir!", "bindgen!"];
    let mut found = Vec::new();

    for macro_name in MACROS {
        let mut cursor = 0usize;
        while let Some(idx) = source[cursor..].find(macro_name) {
            let at = cursor + idx;
            let args_start = at + macro_name.len();
            cursor = args_start;

            // Skip a match that is itself inside a string literal — otherwise this
            // scanner reports its own `MACROS` array as a finding.
            if source[..at].ends_with('"') {
                continue;
            }

            // Take the macro's full argument list, balancing parens so a nested
            // `concat!(env!(..), "..")` is captured whole.
            let bytes = source.as_bytes();
            let mut i = args_start;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'(' {
                continue;
            }
            let mut depth = 0usize;
            let mut end = None;
            let mut in_str = false;
            let mut escaped = false;
            for (offset, &b) in bytes[i..].iter().enumerate() {
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        in_str = false;
                    }
                    continue;
                }
                match b {
                    b'"' => in_str = true,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { continue };
            let args = &source[i..=end];
            cursor = end;

            // `bindgen!` takes a struct-like arg list with several string values,
            // only one of which is a path. Pull `path:` specifically; wasmtime
            // resolves it from CARGO_MANIFEST_DIR, so it is always crate-anchored.
            let (literals, anchored) = if macro_name == "bindgen!" {
                let Some(key) = args.find("path:") else {
                    continue;
                };
                let after = &args[key + "path:".len()..];
                let Some(open) = after.find('"') else {
                    continue;
                };
                let rest = &after[open + 1..];
                let Some(close) = rest.find('"') else {
                    continue;
                };
                (rest[..close].to_owned(), true)
            } else {
                // Concatenate every string literal in the argument list. For the
                // `concat!` form that yields the path fragment after the env var;
                // for a plain literal it is the literal itself.
                let mut lits = String::new();
                let mut rest = args;
                while let Some(open) = rest.find('"') {
                    let after = &rest[open + 1..];
                    let Some(close) = after.find('"') else { break };
                    lits.push_str(&after[..close]);
                    rest = &after[close + 1..];
                }
                // `$CARGO_MANIFEST_DIR/...` (include_dir) and
                // `env!("CARGO_MANIFEST_DIR")` (concat) both anchor at the crate root.
                let anchored = args.contains("CARGO_MANIFEST_DIR");
                (lits, anchored)
            };
            if literals.is_empty() {
                continue;
            }

            let path = literals
                .replace("$CARGO_MANIFEST_DIR", "")
                .replace("CARGO_MANIFEST_DIR", "");
            let path = path.trim_start_matches('/').to_owned();
            if path.is_empty() {
                continue;
            }
            found.push(Include {
                path,
                from_crate_root: anchored,
            });
        }
    }
    found
}

#[test]
fn root_package_is_the_installable_crate() {
    let crates = workspace_crates();
    let root = crates
        .iter()
        .find(|c| c.dir == repo_root())
        .expect("workspace has a root package");

    assert_eq!(
        root.name, ROOT_PACKAGE,
        "the root package must stay `{ROOT_PACKAGE}` so `cargo install {ROOT_PACKAGE}` \
         matches the binary name"
    );
    assert!(
        root.publishable,
        "the root package must remain publishable; `publish = false` here silently \
         removes ZeroClaw from crates.io"
    );
}

#[test]
fn publishable_crates_never_depend_on_private_crates() {
    let crates = workspace_crates();
    let by_name: BTreeMap<&str, &Crate> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let names: BTreeSet<String> = crates.iter().map(|c| c.name.clone()).collect();

    // Walk the root's closure rather than checking crates in isolation: a
    // private crate is only a problem when something published reaches it.
    let mut reachable = BTreeSet::new();
    let mut stack = vec![ROOT_PACKAGE.to_owned()];
    while let Some(name) = stack.pop() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        let Some(krate) = by_name.get(name.as_str()) else {
            continue;
        };
        stack.extend(internal_deps(krate, &names));
    }

    let private: Vec<&str> = reachable
        .iter()
        .filter(|n| by_name.get(n.as_str()).is_some_and(|c| !c.publishable))
        .map(String::as_str)
        .collect();

    assert!(
        private.is_empty(),
        "these crates are reachable from `{ROOT_PACKAGE}` but are not publishable: {private:?}.\n\
         cargo strips `path` when publishing and resolves the `version` from crates.io, so the \
         publish fails partway through — after earlier crates have irreversibly uploaded.\n\
         Either publish them or remove the dependency edge."
    );
}

#[test]
fn publishable_crates_pin_git_dependencies_to_a_version() {
    for krate in workspace_crates().iter().filter(|c| c.publishable) {
        for section in ["dependencies", "build-dependencies", "target"] {
            let Some(table) = krate.manifest.get(section).and_then(|v| v.as_table()) else {
                continue;
            };
            // `[target.<cfg>.dependencies]` nests one level deeper.
            let dep_tables: Vec<&toml::Table> = if section == "target" {
                table
                    .values()
                    .filter_map(|v| v.as_table())
                    .filter_map(|t| t.get("dependencies"))
                    .filter_map(|v| v.as_table())
                    .collect()
            } else {
                vec![table]
            };

            for deps in dep_tables {
                for (dep_name, spec) in deps {
                    let Some(spec) = spec.as_table() else {
                        continue;
                    };
                    if spec.contains_key("git") && !spec.contains_key("version") {
                        panic!(
                            "{}: dependency `{dep_name}` has a `git` source but no `version`.\n\
                             crates.io rejects git sources; cargo drops `git`/`rev` at publish \
                             time and keeps only the version requirement, so one is required.",
                            krate.name
                        );
                    }
                }
            }
        }
    }
}

/// Top-level entries of a manifest's `package.include`, if it has one.
///
/// Returns `None` when the crate ships everything cargo would collect by default.
/// Entries are reduced to their first path segment (`/src/**/*` -> `src`), which is
/// all this test needs to decide which directories to walk.
fn packaged_roots(krate: &Crate) -> Option<Vec<String>> {
    let include = krate.manifest["package"].get("include")?.as_array()?;
    Some(
        include
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|entry| {
                entry
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .filter(|s| !s.is_empty() && !s.contains('*'))
                    .map(str::to_owned)
            })
            .collect(),
    )
}

/// The one compile-time include allowed to escape its crate, with the reason.
///
/// `embedded-web` bakes the built dashboard into the gateway. `web/dist` is
/// gitignored build output, so it cannot be in a registry tarball at all unless
/// the crate grows a full `include` allowlist — no path fix helps. The feature is
/// declared a non-user-selectable meta toggle in the root manifest's
/// `[package.metadata.zeroclaw] non_row_features`, is off by default in both the
/// gateway and the root crate, and its `build.rs` fails loudly with an actionable
/// message ("run: cargo web build") rather than producing a broken binary. It is
/// therefore source-checkout-only by design.
///
/// Do not add entries here to silence a new violation — fix the include instead.
const ESCAPE_EXCEPTIONS: &[(&str, &str)] = &[(
    "crates/zeroclaw-gateway/src/static_files.rs",
    "../../web/dist",
)];

#[test]
fn published_crates_never_include_files_outside_their_own_directory() {
    let mut violations = Vec::new();

    for krate in workspace_crates().iter().filter(|c| c.publishable) {
        let mut sources = Vec::new();
        // Scan what the crate actually ships. When the manifest carries an
        // `include` allowlist (the root crate does, and it deliberately omits
        // `tests/`), honour it — scanning unpackaged files produces findings about
        // code no consumer ever compiles. Otherwise scan the whole crate, since
        // build.rs and any other in-crate Rust file is packaged and compiled too.
        match packaged_roots(krate) {
            Some(roots) => {
                for root in roots {
                    let path = krate.dir.join(&root);
                    if path.is_dir() {
                        rust_sources(&path, &mut sources);
                    } else if path.extension().is_some_and(|e| e == "rs") && path.is_file() {
                        sources.push(path);
                    }
                }
            }
            None => rust_sources(&krate.dir, &mut sources),
        }

        for source_path in sources {
            let text = fs::read_to_string(&source_path).expect("read source file");
            for include in compile_time_includes(&text) {
                let base = if include.from_crate_root {
                    krate.dir.clone()
                } else {
                    source_path
                        .parent()
                        .expect("source file has a parent")
                        .to_path_buf()
                };
                let resolved = normalize(&base, &include.path);
                let rel = source_path
                    .strip_prefix(repo_root())
                    .unwrap_or(&source_path)
                    .to_string_lossy()
                    .into_owned();
                let excepted = ESCAPE_EXCEPTIONS
                    .iter()
                    .any(|(f, p)| *f == rel && *p == include.path);

                // Inside the crate directory is necessary but not sufficient. When
                // the manifest has an `include` allowlist, the file must also fall
                // under one of those entries — otherwise it is inside the crate and
                // still absent from the tarball. This matters most for the root
                // package, whose directory is the whole repository: without it,
                // an include reaching into `crates/` would look contained.
                let inside_crate = resolved.starts_with(&krate.dir);
                let shipped = match packaged_roots(krate) {
                    Some(roots) => roots
                        .iter()
                        .any(|r| resolved.starts_with(krate.dir.join(r))),
                    None => true,
                };
                if (!inside_crate || !shipped) && !excepted {
                    violations.push(format!(
                        "  {} ({})\n      includes `{}`\n      -> {}",
                        source_path
                            .strip_prefix(repo_root())
                            .unwrap_or(&source_path)
                            .display(),
                        krate.name,
                        include.path,
                        resolved.display(),
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "these compile-time includes reference files the published crate will not contain:\n{}\n\n\
         `cargo package` archives only files under the crate root, and only those matching the \
         manifest's `include` list when it has one — so each of these compiles in the workspace \
         and then fails from the published tarball. Feature-gated ones are especially dangerous: \
         `cargo publish --dry-run` verifies default features only, so they pass preflight and \
         ship broken.\n\
         Fix by including through an in-crate symlink (see crates/zeroclaw-hardware/firmware \
         and crates/zeroclaw-tools/locales) rather than reaching up out of the crate.",
        violations.join("\n"),
    );
}
