//! Filesystem RPC methods for remote directory browsing (WSS ACP CWD picker).
//!
//! `fs/list_dir` requires the `Files:Read` grant, and the dispatcher confines
//! it with [`listing_is_authorized`] before the handler touches the path: an
//! operator-level principal may list anything the daemon account can read,
//! and every other principal only absolute paths, without '..' components or
//! Windows network and device prefixes, that an enabled agent it is entitled
//! to use may read under that agent's resolved policy.

use std::path::{Path, PathBuf};
use zeroclaw_api::grants::ResolvedGrants;
use zeroclaw_api::jsonrpc::error_codes::*;
use zeroclaw_api::jsonrpc::{FsEntry, FsListDirRequest, FsListDirResponse};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::schema::Config;

/// Whether resolving `path` stays on local storage and cannot climb out of what
/// it names: no `..` components and, on Windows, no UNC, verbatim-UNC, or
/// device-namespace prefix. Resolving such a path would make the daemon open a
/// network share or device while merely checking it, so a scoped principal's
/// path is tested lexically first and refused without being resolved.
pub fn resolves_locally(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    path.components().all(|component| match component {
        Component::ParentDir => false,
        Component::Prefix(prefix) => {
            matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => true,
    })
}

/// Whether a principal holding `grants` may list the directory at `requested`.
///
/// Operator-level principals may list anything. Every other principal may list
/// only a path that an enabled agent it is entitled to use may read, judged by
/// that agent's resolved policy: its workspace, readable allowed roots,
/// readable sibling workspaces, and the shared skills directory when the
/// policy is workspace-only, and anything outside its forbidden paths when it
/// is not. The policy resolves the path first, so a symlink is judged by its
/// target and a path that cannot be resolved is refused rather than assumed
/// benign.
///
/// Resolving an agent's policy creates its workspace directory if it is
/// missing, as every other use of that policy does.
pub fn listing_is_authorized(config: &Config, grants: &ResolvedGrants, requested: &Path) -> bool {
    authorize_listing(config, grants, requested).is_some()
}

/// What a listing is confined to once authorized.
pub enum ListingAuthorization {
    /// Operator-level principal, or a policy that bounds no root for the path:
    /// the daemon account's own access governs, as it did before confinement.
    Unconfined,
    /// Scoped principal: enumeration must stay beneath this approved root.
    Confined(PathBuf),
}

/// Authorize a listing and report the boundary enumeration must be bound to.
///
/// `None` refuses. Returning the boundary rather than a bare `bool` is what
/// lets the handler enumerate through a directory handle opened beneath the
/// approved root: re-walking the pathname after this check would let a writable
/// component be swapped for a link to another directory in between, exposing
/// names the principal may not read.
pub fn authorize_listing(
    config: &Config,
    grants: &ResolvedGrants,
    requested: &Path,
) -> Option<ListingAuthorization> {
    if grants.admin {
        return Some(ListingAuthorization::Unconfined);
    }
    config
        .agents
        .iter()
        .filter(|(alias, agent)| agent.enabled && grants.may_use_agent(alias))
        .find_map(|(alias, _)| {
            let policy = SecurityPolicy::for_agent(config, alias).ok()?;
            if !policy.is_resolved_path_readable(requested) {
                return None;
            }
            Some(match policy.approved_read_root(requested) {
                Some(root) => ListingAuthorization::Confined(root),
                None => ListingAuthorization::Unconfined,
            })
        })
}

/// One directory entry, reduced to what the response needs, so a confined
/// (cap-std) and an unconfined (std) enumeration can share the shaping below.
struct RawEntry {
    name: String,
    is_dir: bool,
    size: u64,
    mtime: Option<std::time::SystemTime>,
}

/// Handle `fs/list_dir`, bound to what `authorize_listing` allowed.
pub async fn handle_fs_list_dir(
    params: &serde_json::Value,
    auth: &ListingAuthorization,
) -> Result<serde_json::Value, zeroclaw_api::jsonrpc::JsonRpcError> {
    let req: FsListDirRequest = serde_json::from_value(params.clone())
        .map_err(|e| rpc_err(INVALID_PARAMS, e.to_string()))?;

    let path = Path::new(&req.path);

    // Basic traversal guard (more sophisticated policy can be added later)
    if path.components().any(|c| c.as_os_str() == "..") {
        return Err(rpc_err(FS_INVALID_PATH, "Path traversal not allowed"));
    }

    let unreadable =
        |e: std::io::Error| rpc_err(FS_NOT_FOUND, format!("Cannot read {}: {e}", req.path));

    let raw: Vec<RawEntry> = match auth {
        // Enumerate through a handle opened beneath the approved root. cap-std
        // refuses any component that escapes it, so a directory swapped in
        // after authorization cannot redirect this listing.
        ListingAuthorization::Confined(root) => {
            use cap_std::ambient_authority;
            use cap_std::fs::Dir;

            let rel = path
                .strip_prefix(root)
                .map_err(|_| rpc_err(FS_INVALID_PATH, "Path escapes its approved root"))?;
            let dir = Dir::open_ambient_dir(root, ambient_authority()).map_err(unreadable)?;
            let dir = if rel.as_os_str().is_empty() {
                dir
            } else {
                dir.open_dir(rel).map_err(unreadable)?
            };
            dir.entries()
                .map_err(unreadable)?
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let meta = entry.metadata().ok()?;
                    Some(RawEntry {
                        name: entry.file_name().to_string_lossy().to_string(),
                        is_dir: meta.is_dir(),
                        size: meta.len(),
                        mtime: meta.modified().ok().map(|t| t.into_std()),
                    })
                })
                .collect()
        }
        ListingAuthorization::Unconfined => {
            if !path.is_dir() {
                return Err(rpc_err(
                    FS_NOT_FOUND,
                    format!("Not a directory: {}", req.path),
                ));
            }
            std::fs::read_dir(path)
                .map_err(unreadable)?
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let meta = entry.metadata().ok()?;
                    Some(RawEntry {
                        name: entry.file_name().to_string_lossy().to_string(),
                        is_dir: meta.is_dir(),
                        size: meta.len(),
                        mtime: meta.modified().ok(),
                    })
                })
                .collect()
        }
    };

    let mut entries = Vec::with_capacity(raw.len());
    for entry in raw {
        let is_hidden = entry.name.starts_with('.');
        if is_hidden && !req.show_hidden {
            continue;
        }
        let full_path = path.join(&entry.name).to_string_lossy().to_string();
        entries.push(FsEntry {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
            is_hidden,
            full_path,
            mtime: entry.mtime.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            }),
        });
    }

    // Sort: directories first, then files, case-insensitive
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    let cwd = path.to_string_lossy().to_string();
    let resp = FsListDirResponse { entries, cwd };
    serde_json::to_value(resp).map_err(|e| rpc_err(INTERNAL_ERROR, e.to_string()))
}

fn rpc_err(code: i32, msg: impl Into<String>) -> zeroclaw_api::jsonrpc::JsonRpcError {
    zeroclaw_api::jsonrpc::JsonRpcError {
        code,
        message: msg.into(),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::resolves_locally;
    use std::path::Path;

    #[test]
    fn resolves_locally_refuses_parent_components() {
        assert!(resolves_locally(Path::new("/srv/agent/workspace")));
        assert!(resolves_locally(Path::new("relative/dir")));
        assert!(!resolves_locally(Path::new("/srv/agent/../other")));
        assert!(!resolves_locally(Path::new("..")));
    }

    #[cfg(windows)]
    #[test]
    fn resolves_locally_refuses_network_and_device_prefixes() {
        assert!(resolves_locally(Path::new(r"C:\agents\workspace")));
        assert!(resolves_locally(Path::new(r"\\?\C:\agents\workspace")));
        assert!(!resolves_locally(Path::new(r"\\attacker.example\share\x")));
        assert!(!resolves_locally(Path::new(r"\\attacker.example@80\x")));
        assert!(!resolves_locally(Path::new(
            r"\\?\UNC\attacker.example\share"
        )));
        assert!(!resolves_locally(Path::new(r"\\.\pipe\zeroclaw")));
    }

    /// Authorization judges one pathname; enumeration must then run through a
    /// handle bound to the approved root, so a directory swapped in for a
    /// writable entry cannot expose another directory's names.
    #[tokio::test]
    async fn confined_listing_refuses_an_entry_swapped_outside_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("real").join("inside.txt"), b"x").unwrap();

        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"x").unwrap();

        let swapped = root.join("swapped");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &swapped).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside, &swapped).unwrap();

        let auth = super::ListingAuthorization::Confined(root.clone());
        let escaping = serde_json::json!({
            "path": swapped.to_string_lossy(),
            "show_hidden": false,
        });
        let err = super::handle_fs_list_dir(&escaping, &auth)
            .await
            .expect_err("a directory escaping the approved root must not be listed");
        assert!(
            !format!("{err:?}").contains("secret.txt"),
            "refusal must not leak the other directory's names: {err:?}"
        );

        // Control: a real directory beneath the root still lists.
        let allowed = serde_json::json!({
            "path": root.join("real").to_string_lossy(),
            "show_hidden": false,
        });
        let listed = super::handle_fs_list_dir(&allowed, &auth)
            .await
            .expect("a directory inside the approved root must still list");
        assert!(
            listed.to_string().contains("inside.txt"),
            "expected the real entry: {listed}"
        );
    }
}
