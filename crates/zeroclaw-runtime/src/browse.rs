//! Scoped one-level directory browser. Gateway (`api_browse.rs`), CLI
//! (`src/browse.rs`), and the future TUI directory picker all reach the
//! same canonical implementation here.

use std::path::PathBuf;

use serde::Serialize;

use zeroclaw_config::paths::{RootEscapeError, resolve_under};
use zeroclaw_config::schema::Config;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowseEntry {
    pub name: String,
    /// `"dir"` or `"file"`. Symlinks resolve through their target.
    pub kind: &'static str,
    /// File size in bytes. `None` for directories.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Set when this entry is on the runtime's protected list and the
    /// dashboard must hide delete/rename affordances. Server-side checks
    /// (delete/move/mkdir) reject mutations on these regardless of UI.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub protected: bool,
}

#[derive(Debug, Clone)]
pub struct BrowseResult {
    /// Path relative to `<install>/shared/` that the result describes.
    /// Useful for breadcrumb rendering.
    pub path: String,
    pub entries: Vec<BrowseEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum BrowseError {
    #[error(transparent)]
    Escape(#[from] RootEscapeError),
    #[error("'{0}' is not an agent alias")]
    InvalidAgent(String),
    #[error("path '{0}' does not exist")]
    NotFound(String),
    #[error("path '{0}' is not a directory")]
    NotADirectory(String),
    #[error("'{0}' is a system directory and cannot be removed via the dashboard")]
    Protected(String),
    #[error("'{0}' is a system file and cannot be modified or removed via the dashboard")]
    ProtectedFile(String),
    #[error("file '{0}' exceeds the {1}-byte read cap; download via CLI or zeroclaw shell")]
    TooLarge(String, u64),
    #[error("'{0}' passes through a link; it cannot be modified or removed through a link")]
    LinkedPath(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Browse one level of `<install>/shared/<raw>`. Returns entries sorted by
/// (kind, name) — directories first, then files, alphabetical within each.
pub fn list_directory(config: &Config, raw: &str) -> Result<BrowseResult, BrowseError> {
    let mut result = list_under_root(&config.shared_workspace_dir(), raw)?;
    if raw.trim_matches('/').is_empty() {
        for entry in &mut result.entries {
            if entry.kind == "dir" && PROTECTED_SHARED_TOP_LEVEL.contains(&entry.name.as_str()) {
                entry.protected = true;
            }
        }
    }
    Ok(result)
}

fn list_under_root(root: &std::path::Path, raw: &str) -> Result<BrowseResult, BrowseError> {
    let (_, relative) = resolve_relative(root, raw)?;
    let dir = open_root(root, raw)?;
    let target = here(&relative);
    let metadata = dir.metadata(target).map_err(confined(raw, root))?;
    if !metadata.is_dir() {
        return Err(BrowseError::NotADirectory(raw.to_string()));
    }
    let listed = if relative.is_empty() {
        dir
    } else {
        dir.open_dir(target).map_err(confined(raw, root))?
    };

    let mut entries: Vec<BrowseEntry> = Vec::new();
    for child in listed.entries().map_err(confined(raw, root))?.flatten() {
        let Ok(file_type) = child.file_type() else {
            continue;
        };
        let name = child.file_name().to_string_lossy().into_owned();
        if file_type.is_dir() {
            entries.push(BrowseEntry {
                name,
                kind: "dir",
                size: None,
                protected: false,
            });
        } else if file_type.is_file() {
            let size = child.metadata().ok().map(|m| m.len());
            entries.push(BrowseEntry {
                name,
                kind: "file",
                size,
                protected: false,
            });
        }
    }
    entries.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));

    Ok(BrowseResult {
        path: raw.trim_matches('/').to_string(),
        entries,
    })
}

const PROTECTED_SHARED_TOP_LEVEL: &[&str] = &["skills", "skill-bundles", "knowledge"];

/// Create a new directory at `<install>/shared/<raw>`. Idempotent — if the
/// path already exists as a directory, returns Ok without re-creating.
/// Rejects path traversal and refuses to create over an existing file.
pub fn make_directory(config: &Config, raw: &str) -> Result<(), BrowseError> {
    let shared = config.shared_workspace_dir();
    make_directory_under(&shared, raw)
}

/// Create `raw` beneath `root`, creating the configured root itself first
/// when it is missing. Idempotent for an existing directory.
fn make_directory_under(root: &std::path::Path, raw: &str) -> Result<(), BrowseError> {
    use cap_fs_ext::DirExt;
    let (_, relative) = resolve_relative(root, raw)?;
    std::fs::create_dir_all(root)?;
    let dir = open_root(root, raw)?;
    // Created one component at a time without following a link, the last
    // one included, so the protected-entry checks the caller ran on the
    // lexical path judged the entry this creates: `via/SOUL.md` with
    // `via -> .` cannot create a directory at a protected name.
    let mut current = dir;
    for component in relative.split('/').filter(|c| !c.is_empty()) {
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(BrowseError::LinkedPath(raw.to_string()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(BrowseError::NotADirectory(raw.to_string()));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match current.create_dir(component) {
                    Ok(()) => {}
                    // Created by someone else meanwhile: the no-follow open
                    // below decides whether it is a usable directory.
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(confined(raw, root)(err)),
                }
            }
            Err(err) => return Err(confined(raw, root)(err)),
        }
        current = current
            .open_dir_nofollow(component)
            .map_err(confined(raw, root))?;
    }
    Ok(())
}

/// Delete the directory at `<install>/shared/<raw>` recursively. Refuses
/// to remove protected top-level entries (skills/, skill-bundles/,
/// knowledge/) or the shared root itself. Rejects path traversal.
pub fn remove_directory(config: &Config, raw: &str) -> Result<(), BrowseError> {
    let shared = config.shared_workspace_dir();
    let (_, relative) = resolve_relative(&shared, raw)?;
    if relative.is_empty() {
        return Err(BrowseError::Protected("shared".to_string()));
    }
    if PROTECTED_SHARED_TOP_LEVEL.contains(&relative.as_str()) {
        return Err(BrowseError::Protected(format!("shared/{relative}")));
    }
    let dir = open_root(&shared, raw)?;
    let (parent, name) = open_parent_nofollow(&dir, &relative, raw, &shared)?;
    let metadata = parent
        .symlink_metadata(&name)
        .map_err(confined(raw, &shared))?;
    if !metadata.is_dir() {
        return Err(BrowseError::NotADirectory(raw.to_string()));
    }
    parent
        .remove_dir_all(&name)
        .map_err(confined(raw, &shared))?;
    Ok(())
}

/// Hard byte cap on file-read responses. Anything larger surfaces as
/// `BrowseError::TooLarge`; the dashboard can offer a CLI hint.
pub const AGENT_WORKSPACE_READ_CAP: u64 = 4 * 1024 * 1024; // 4 MiB

const AGENT_WORKSPACE_PROTECTED_FILES: &[&str] = &[
    "IDENTITY.md",
    "SOUL.md",
    "USER.md",
    "AGENTS.md",
    "MEMORY.md",
    "DAILY.md",
];

/// Top-level agent-workspace directories the runtime owns. `sessions/`
/// holds the per-agent session DB (`sessions/sessions.db`) created on first
/// session write by `zeroclaw_infra::session_sqlite`. Deleting it wipes
/// session history.
const AGENT_WORKSPACE_PROTECTED_DIRS: &[&str] = &["sessions"];

/// Open `root` as a directory handle. Every path handed to it is resolved
/// beneath it: `..`, an absolute path, or a symlink, intermediate or final,
/// that would lead outside is refused by the handle, so a link planted in a
/// workspace cannot reach another agent's files or anything else on the host.
/// The lexical checks in [`resolve_relative`] decide which entries are
/// protected; this decides what the filesystem calls can reach.
fn open_root(root: &std::path::Path, raw: &str) -> Result<cap_std::fs::Dir, BrowseError> {
    cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
        .map_err(confined(raw, root))
}

/// Open the directory that holds the last component of `relative`, one
/// component at a time and never following a link, and return it with that
/// last component's name.
///
/// The root handle keeps a path inside the root, but on its own it still
/// follows links that stay inside, so `via/SOUL.md` with `via -> .` names the
/// protected `SOUL.md` while its text passes the protected-entry checks.
/// Mutations act through the handle this returns instead: every directory on
/// the way was opened as a real directory, so the path the checks ran on is
/// the path the operation touches, and a link swapped in afterwards cannot
/// redirect a handle already opened.
fn open_parent_nofollow(
    dir: &cap_std::fs::Dir,
    relative: &str,
    raw: &str,
    root: &std::path::Path,
) -> Result<(cap_std::fs::Dir, String), BrowseError> {
    use cap_fs_ext::DirExt;
    let mut components: Vec<&str> = relative.split('/').filter(|c| !c.is_empty()).collect();
    let Some(name) = components.pop() else {
        return Err(BrowseError::NotFound(raw.to_string()));
    };
    let mut parent = dir.try_clone().map_err(confined(raw, root))?;
    for component in components {
        if parent
            .symlink_metadata(component)
            .is_ok_and(|metadata| metadata.is_symlink())
        {
            return Err(BrowseError::LinkedPath(raw.to_string()));
        }
        parent = parent
            .open_dir_nofollow(component)
            .map_err(confined(raw, root))?;
    }
    Ok((parent, name.to_string()))
}

/// Create every missing directory along `relative` without following a
/// link, for a move whose destination names directories that do not exist
/// yet. An existing component that is a link is refused, as in
/// [`open_parent_nofollow`].
fn create_dirs_nofollow(
    dir: &cap_std::fs::Dir,
    relative: &str,
    raw: &str,
    root: &std::path::Path,
) -> Result<(), BrowseError> {
    use cap_fs_ext::DirExt;
    let mut current = dir.try_clone().map_err(confined(raw, root))?;
    for component in relative.split('/').filter(|c| !c.is_empty()) {
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(BrowseError::LinkedPath(raw.to_string()));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                current.create_dir(component).map_err(confined(raw, root))?;
            }
            Err(err) => return Err(confined(raw, root)(err)),
        }
        current = current
            .open_dir_nofollow(component)
            .map_err(confined(raw, root))?;
    }
    Ok(())
}

/// The path to hand a root handle for `relative`: the root itself when empty.
fn here(relative: &str) -> &str {
    if relative.is_empty() { "." } else { relative }
}

/// Map an error from a confined filesystem call. A path that led outside
/// the root surfaces as `PermissionDenied`, and is reported as an escape.
fn confined<'a>(
    raw: &'a str,
    root: &'a std::path::Path,
) -> impl Fn(std::io::Error) -> BrowseError + 'a {
    move |err| match err.kind() {
        std::io::ErrorKind::NotFound => BrowseError::NotFound(raw.to_string()),
        std::io::ErrorKind::PermissionDenied => BrowseError::Escape(RootEscapeError {
            input: raw.to_string(),
            root: root.display().to_string(),
        }),
        _ => BrowseError::Io(err),
    }
}

/// Resolve `raw` under `root` and return the resolved path together with its
/// normalized path relative to `root`: `/`-separated, and empty for the root
/// itself.
///
/// Every check on what an operation may touch runs on that relative form,
/// never on the raw input. `resolve_under` folds `..` lexically, so a raw
/// path such as `x/..` or `x/../SOUL.md` passes a check on its own text
/// while resolving to the root or a protected entry.
fn resolve_relative(root: &std::path::Path, raw: &str) -> Result<(PathBuf, String), BrowseError> {
    let resolved = resolve_under(root, raw)?;
    let normalized_root = resolve_under(root, "")?;
    let relative = resolved
        .strip_prefix(&normalized_root)
        .unwrap_or(resolved.as_path())
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    Ok((resolved, relative))
}

/// The workspace root for `agent_alias`. The alias becomes a path component
/// under `<install>/agents/`, so it must be exactly one plain component:
/// `..`, a separator, or an absolute path would otherwise select a directory
/// outside the agents tree, which `PathBuf::join` would happily produce.
fn agent_root(config: &Config, agent_alias: &str) -> Result<PathBuf, BrowseError> {
    use std::path::Component;
    let mut components = std::path::Path::new(agent_alias).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(config.agent_workspace_dir(agent_alias)),
        _ => Err(BrowseError::InvalidAgent(agent_alias.to_string())),
    }
}

/// Whether `rel` names the reserved top-level entry `reserved` on whatever
/// filesystem holds the workspace. A case-insensitive volume (the default on
/// macOS and Windows) resolves `soul.md` to `SOUL.md`, and Windows drops a
/// trailing dot or space, so an exact comparison would let either spelling
/// through to the entry it was meant to refuse.
fn names_reserved(rel: &str, reserved: &str) -> bool {
    let fold = |name: &str| {
        name.trim_end_matches(['.', ' '])
            .to_uppercase()
            .to_lowercase()
    };
    fold(rel) == fold(reserved)
}

fn protected_file(rel: &str) -> bool {
    AGENT_WORKSPACE_PROTECTED_FILES
        .iter()
        .any(|reserved| names_reserved(rel, reserved))
}

fn protected_dir(rel: &str) -> bool {
    AGENT_WORKSPACE_PROTECTED_DIRS
        .iter()
        .any(|reserved| names_reserved(rel, reserved))
}

/// The first leading run of `relative`'s components that is a protected
/// file, if any.
///
/// Creating `SOUL.md/child` creates a `SOUL.md` directory on the way, which
/// then stands where the bootstrap file belongs, although the whole path is
/// not a protected name. Every operation that creates the directories along
/// a path, or moves an entry out of one, checks each of them here.
fn protected_file_along(relative: &str) -> Option<&str> {
    relative
        .match_indices('/')
        .map(|(end, _)| &relative[..end])
        .chain(std::iter::once(relative))
        .find(|prefix| protected_file(prefix))
}

/// One-level listing inside the agent's workspace. Top-level entries that
/// match the protected file/dir lists are tagged so the dashboard hides
/// destructive affordances; server-side mutations still re-check.
pub fn list_agent_workspace(
    config: &Config,
    agent_alias: &str,
    raw: &str,
) -> Result<BrowseResult, BrowseError> {
    let mut result = list_under_root(&agent_root(config, agent_alias)?, raw)?;
    if raw.trim_matches('/').is_empty() {
        for entry in &mut result.entries {
            entry.protected = match entry.kind {
                "file" => protected_file(&entry.name),
                "dir" => protected_dir(&entry.name),
                _ => false,
            };
        }
    }
    Ok(result)
}

/// Create a directory under the agent's workspace. Idempotent — if the
/// path already exists as a directory, returns Ok. Rejects path traversal
/// and refuses to create over an existing file or to create any directory
/// along the path at a protected top-level file path.
pub fn make_agent_workspace_directory(
    config: &Config,
    agent_alias: &str,
    raw: &str,
) -> Result<(), BrowseError> {
    let root = agent_root(config, agent_alias)?;
    let (_, relative) = resolve_relative(&root, raw)?;
    if relative.is_empty() {
        return Err(BrowseError::NotFound(raw.to_string()));
    }
    if let Some(protected) = protected_file_along(&relative) {
        return Err(BrowseError::ProtectedFile(protected.to_string()));
    }
    make_directory_under(&root, raw)
}

/// Result of reading a file from the agent workspace.
#[derive(Debug, Clone)]
pub struct FileReadResult {
    pub path: String,
    pub bytes: Vec<u8>,
    pub size: u64,
    /// True when the bytes look like UTF-8 text. Drives whether the
    /// dashboard renders inline or offers a download.
    pub is_text: bool,
}

/// A directory listing as it goes over the wire. The dashboard's HTTP
/// adapter and the `workspace/list` RPC method both serialize this, so the
/// two bodies cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowseListing {
    pub path: String,
    pub entries: Vec<BrowseEntry>,
}

impl From<BrowseResult> for BrowseListing {
    fn from(result: BrowseResult) -> Self {
        Self {
            path: result.path,
            entries: result.entries,
        }
    }
}

/// A single-file read as it goes over the wire, shared by the HTTP adapter
/// and the `fs/read` RPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReadBody {
    pub path: String,
    pub size: u64,
    pub is_text: bool,
    /// UTF-8 text when `is_text` is true, base64 when false, so a client can
    /// render inline without a second round-trip for a binary preview.
    pub content: String,
    pub encoding: &'static str,
}

impl From<FileReadResult> for FileReadBody {
    fn from(result: FileReadResult) -> Self {
        use base64::Engine;
        let (content, encoding) = if result.is_text {
            (String::from_utf8(result.bytes).unwrap_or_default(), "utf8")
        } else {
            (
                base64::engine::general_purpose::STANDARD.encode(&result.bytes),
                "base64",
            )
        };
        Self {
            path: result.path,
            size: result.size,
            is_text: result.is_text,
            content,
            encoding,
        }
    }
}

/// Read a file from the agent's workspace. Refuses paths that don't
/// resolve to a regular file; enforces the size cap.
pub fn read_agent_workspace_file(
    config: &Config,
    agent_alias: &str,
    raw: &str,
) -> Result<FileReadResult, BrowseError> {
    use std::io::Read;
    let root = agent_root(config, agent_alias)?;
    let (_, relative) = resolve_relative(&root, raw)?;
    let dir = open_root(&root, raw)?;
    let target = here(&relative);
    let metadata = dir.metadata(target).map_err(confined(raw, &root))?;
    if !metadata.is_file() {
        return Err(BrowseError::NotADirectory(raw.to_string()));
    }
    if metadata.len() > AGENT_WORKSPACE_READ_CAP {
        return Err(BrowseError::TooLarge(
            raw.to_string(),
            AGENT_WORKSPACE_READ_CAP,
        ));
    }
    // Read through the opened handle, bounded, so a file swapped or grown
    // after the size check cannot be read past the cap.
    let file = dir.open(target).map_err(confined(raw, &root))?;
    let mut bytes = Vec::new();
    file.take(AGENT_WORKSPACE_READ_CAP + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > AGENT_WORKSPACE_READ_CAP {
        return Err(BrowseError::TooLarge(
            raw.to_string(),
            AGENT_WORKSPACE_READ_CAP,
        ));
    }
    let is_text = std::str::from_utf8(&bytes).is_ok();
    Ok(FileReadResult {
        path: raw.trim_matches('/').to_string(),
        size: bytes.len() as u64,
        bytes,
        is_text,
    })
}

/// Delete a file or directory inside the agent's workspace. Recursive
/// for directories. Refuses to delete the workspace root itself or any
/// of the protected bootstrap files.
pub fn delete_agent_workspace_path(
    config: &Config,
    agent_alias: &str,
    raw: &str,
) -> Result<(), BrowseError> {
    let root = agent_root(config, agent_alias)?;
    let (_, relative) = resolve_relative(&root, raw)?;
    if relative.is_empty() {
        return Err(BrowseError::Protected(format!(
            "agents/{agent_alias}/workspace"
        )));
    }
    if protected_file(&relative) {
        return Err(BrowseError::ProtectedFile(relative));
    }
    if protected_dir(&relative) {
        return Err(BrowseError::Protected(format!(
            "agents/{agent_alias}/workspace/{relative}"
        )));
    }
    let dir = open_root(&root, raw)?;
    // No intermediate link is followed, so the protected-entry checks above
    // judged the entry this removes. The final component is examined without
    // following it, so a link is removed as a link and never deletes what it
    // points at.
    let (parent, name) = open_parent_nofollow(&dir, &relative, raw, &root)?;
    let metadata = parent
        .symlink_metadata(&name)
        .map_err(confined(raw, &root))?;
    if metadata.is_dir() {
        parent.remove_dir_all(&name).map_err(confined(raw, &root))?;
    } else {
        parent.remove_file(&name).map_err(confined(raw, &root))?;
    }
    Ok(())
}

/// Move (rename) a path inside the agent's workspace. Both `from` and
/// `to` are relative to the workspace root; both must stay inside it.
/// Refuses to touch protected files on either side.
pub fn move_agent_workspace_path(
    config: &Config,
    agent_alias: &str,
    from: &str,
    to: &str,
) -> Result<(), BrowseError> {
    let root = agent_root(config, agent_alias)?;
    let (_, from_relative) = resolve_relative(&root, from)?;
    let (_, to_relative) = resolve_relative(&root, to)?;
    let (from_trimmed, to_trimmed) = (from_relative.as_str(), to_relative.as_str());
    if from_trimmed.is_empty() || to_trimmed.is_empty() {
        return Err(BrowseError::NotFound(from.to_string()));
    }
    // `to`'s parents are created below, so every directory along it is
    // checked, not only the entry it names.
    if let Some(protected) = protected_file_along(from_trimmed).or(protected_file_along(to_trimmed))
    {
        return Err(BrowseError::ProtectedFile(protected.to_string()));
    }
    if protected_dir(from_trimmed) || protected_dir(to_trimmed) {
        return Err(BrowseError::Protected(format!(
            "agents/{agent_alias}/workspace/{}",
            if protected_dir(from_trimmed) {
                from_trimmed
            } else {
                to_trimmed
            }
        )));
    }
    let dir = open_root(&root, from)?;
    // Both sides are reached without following an intermediate link, so the
    // protected-entry checks above judged the entries this moves.
    let (from_parent, from_name) = open_parent_nofollow(&dir, from_trimmed, from, &root)?;
    match from_parent.symlink_metadata(&from_name) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(BrowseError::NotFound(from.to_string()));
        }
        Err(err) => return Err(confined(from, &root)(err)),
    }
    if let Some(parent) = std::path::Path::new(to_trimmed).parent()
        && !parent.as_os_str().is_empty()
    {
        create_dirs_nofollow(&dir, &parent.to_string_lossy(), to, &root)?;
    }
    let (to_parent, to_name) = open_parent_nofollow(&dir, to_trimmed, to, &root)?;
    if to_parent.symlink_metadata(&to_name).is_ok() {
        return Err(BrowseError::NotADirectory(format!(
            "target '{to_trimmed}' already exists"
        )));
    }
    from_parent
        .rename(&from_name, &to_parent, &to_name)
        .map_err(confined(from, &root))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("shared/skills/alpha")).unwrap();
        std::fs::create_dir_all(dir.path().join("shared/skills/beta")).unwrap();
        std::fs::write(dir.path().join("shared/readme.txt"), b"hi").unwrap();

        let cfg = Config {
            config_path: dir.path().join("config.toml"),
            ..Config::default()
        };
        (dir, cfg)
    }

    /// An alias is spliced into `<install>/agents/<alias>/workspace`, so any
    /// alias that is not one plain component would select a directory outside
    /// the agents tree. A `workspace` directory is planted where each escape
    /// would land; every operation must refuse the alias before touching it.
    #[test]
    fn agent_workspace_operations_refuse_an_alias_that_escapes_the_agents_tree() {
        let (dir, cfg) = fixture();
        let outside = dir.path().join("elsewhere");
        std::fs::create_dir_all(outside.join("workspace")).unwrap();
        std::fs::write(outside.join("workspace/secret.txt"), b"s3cret").unwrap();
        std::fs::create_dir_all(dir.path().join("workspace")).unwrap();
        std::fs::write(dir.path().join("workspace/secret.txt"), b"s3cret").unwrap();

        let absolute = outside.to_string_lossy().to_string();
        for alias in ["..", "../elsewhere", "a/b", ".", "", absolute.as_str()] {
            assert!(
                matches!(
                    list_agent_workspace(&cfg, alias, ""),
                    Err(BrowseError::InvalidAgent(_))
                ),
                "list must refuse alias {alias:?}"
            );
            assert!(
                matches!(
                    read_agent_workspace_file(&cfg, alias, "secret.txt"),
                    Err(BrowseError::InvalidAgent(_))
                ),
                "read must refuse alias {alias:?}"
            );
            assert!(
                matches!(
                    delete_agent_workspace_path(&cfg, alias, "secret.txt"),
                    Err(BrowseError::InvalidAgent(_))
                ),
                "delete must refuse alias {alias:?}"
            );
            assert!(
                matches!(
                    move_agent_workspace_path(&cfg, alias, "secret.txt", "moved.txt"),
                    Err(BrowseError::InvalidAgent(_))
                ),
                "move must refuse alias {alias:?}"
            );
            assert!(
                matches!(
                    make_agent_workspace_directory(&cfg, alias, "made"),
                    Err(BrowseError::InvalidAgent(_))
                ),
                "mkdir must refuse alias {alias:?}"
            );
        }
        assert!(outside.join("workspace/secret.txt").exists());
        assert!(dir.path().join("workspace/secret.txt").exists());
        assert!(!outside.join("workspace/made").exists());

        // A plain alias still resolves under the agents tree.
        std::fs::create_dir_all(dir.path().join("agents/alpha/workspace")).unwrap();
        assert!(list_agent_workspace(&cfg, "alpha", "").is_ok());
    }

    /// Guards run on the path as resolved, not as written: `..` folded into a
    /// path must not reach the root or a protected entry that the same path
    /// written plainly is refused.
    #[test]
    fn mutations_check_the_resolved_path_not_the_raw_one() {
        let (dir, cfg) = fixture();
        std::fs::create_dir_all(dir.path().join("shared/knowledge")).unwrap();
        let workspace = dir.path().join("agents/alpha/workspace");
        std::fs::create_dir_all(workspace.join("notes")).unwrap();
        std::fs::create_dir_all(workspace.join("sessions")).unwrap();
        std::fs::write(workspace.join("SOUL.md"), b"soul").unwrap();

        // Shared area: the root and protected top-level directories.
        for raw in [
            "skills/..",
            "x/..",
            "x/../skills",
            "skills/alpha/../..",
            "./knowledge",
        ] {
            assert!(
                matches!(remove_directory(&cfg, raw), Err(BrowseError::Protected(_))),
                "rmdir {raw:?}"
            );
        }
        assert!(dir.path().join("shared/skills/alpha").exists());
        assert!(dir.path().join("shared/knowledge").exists());

        // Agent workspace: the root, a protected file and a protected directory.
        for raw in ["notes/..", "x/..", "./"] {
            assert!(
                matches!(
                    delete_agent_workspace_path(&cfg, "alpha", raw),
                    Err(BrowseError::Protected(_))
                ),
                "delete {raw:?}"
            );
        }
        assert!(matches!(
            delete_agent_workspace_path(&cfg, "alpha", "notes/../SOUL.md"),
            Err(BrowseError::ProtectedFile(_))
        ));
        assert!(matches!(
            delete_agent_workspace_path(&cfg, "alpha", "notes/../sessions"),
            Err(BrowseError::Protected(_))
        ));
        assert!(workspace.join("SOUL.md").exists());
        assert!(workspace.join("sessions").exists());

        // Move: from or to the root, or onto or off a protected name.
        assert!(move_agent_workspace_path(&cfg, "alpha", "notes/..", "moved").is_err());
        assert!(matches!(
            move_agent_workspace_path(&cfg, "alpha", "notes/../SOUL.md", "soul-copy.md"),
            Err(BrowseError::ProtectedFile(_))
        ));
        assert!(matches!(
            move_agent_workspace_path(&cfg, "alpha", "notes", "x/../SOUL.md"),
            Err(BrowseError::ProtectedFile(_))
        ));
        assert!(matches!(
            move_agent_workspace_path(&cfg, "alpha", "notes", "x/../sessions"),
            Err(BrowseError::Protected(_))
        ));
        assert!(workspace.join("notes").exists());
        assert!(workspace.join("SOUL.md").exists());

        // mkdir cannot squat a protected file name through `..` either.
        assert!(matches!(
            make_agent_workspace_directory(&cfg, "alpha", "notes/../SOUL.md"),
            Err(BrowseError::ProtectedFile(_))
        ));

        // Ordinary nested paths still work.
        std::fs::create_dir_all(dir.path().join("shared/scratch/inner")).unwrap();
        remove_directory(&cfg, "scratch/inner/..").unwrap();
        assert!(!dir.path().join("shared/scratch").exists());
    }

    /// A link inside one agent's workspace that points into another's must
    /// not carry any operation across: the root handle refuses to resolve a
    /// path through it. A link that stays inside the root still works, and
    /// deleting a link removes the link, not its target.
    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_workspace_is_not_followed() {
        let (dir, cfg) = fixture();
        let alpha = dir.path().join("agents/alpha/workspace");
        let beta = dir.path().join("agents/beta/workspace");
        std::fs::create_dir_all(alpha.join("notes")).unwrap();
        std::fs::create_dir_all(&beta).unwrap();
        std::fs::write(beta.join("private.txt"), b"beta only").unwrap();
        std::fs::write(alpha.join("notes/own.txt"), b"alpha").unwrap();
        std::os::unix::fs::symlink(&beta, alpha.join("export")).unwrap();
        // A relative link that stays inside the root, and an absolute one
        // that happens to point inside it too.
        std::os::unix::fs::symlink("notes", alpha.join("inner")).unwrap();
        std::os::unix::fs::symlink(alpha.join("notes"), alpha.join("absolute")).unwrap();

        let escaped = |r: &Result<_, BrowseError>| matches!(r, Err(BrowseError::Escape(_)));
        // Mutations refuse any link on the way before the root handle is
        // asked to resolve it; either refusal keeps beta out of reach.
        let refused = |r: &Result<_, BrowseError>| {
            matches!(r, Err(BrowseError::Escape(_) | BrowseError::LinkedPath(_)))
        };
        assert!(escaped(
            &read_agent_workspace_file(&cfg, "alpha", "export/private.txt").map(|_| ())
        ));
        assert!(escaped(
            &list_agent_workspace(&cfg, "alpha", "export").map(|_| ())
        ));
        assert!(refused(&delete_agent_workspace_path(
            &cfg,
            "alpha",
            "export/private.txt"
        )));
        assert!(refused(&move_agent_workspace_path(
            &cfg,
            "alpha",
            "export/private.txt",
            "stolen.txt"
        )));
        assert!(refused(&make_agent_workspace_directory(
            &cfg,
            "alpha",
            "export/planted"
        )));
        assert!(
            beta.join("private.txt").exists(),
            "beta's file is untouched"
        );
        assert!(!beta.join("planted").exists());
        assert!(!alpha.join("stolen.txt").exists());

        // A relative link that stays inside the root resolves normally. An
        // absolute target cannot be resolved beneath the root handle, so it
        // is refused even when it points inside: fail closed.
        let own = read_agent_workspace_file(&cfg, "alpha", "inner/own.txt").unwrap();
        assert_eq!(own.bytes, b"alpha");
        assert!(escaped(
            &read_agent_workspace_file(&cfg, "alpha", "absolute/own.txt").map(|_| ())
        ));

        // Deleting the link removes the link only.
        delete_agent_workspace_path(&cfg, "alpha", "export").unwrap();
        assert!(!alpha.join("export").exists());
        assert!(beta.join("private.txt").exists());
    }

    /// A link that stays inside the workspace cannot alias a protected
    /// entry. `via -> .` makes `via/SOUL.md` name the real `SOUL.md` while its
    /// text passes the protected-entry checks, so mutations refuse to follow
    /// any link on the way and every protected entry stays as it was.
    #[cfg(unix)]
    #[test]
    fn an_internal_link_cannot_alias_a_protected_entry() {
        let (dir, cfg) = fixture();
        let alpha = dir.path().join("agents/alpha/workspace");
        std::fs::create_dir_all(alpha.join("sessions")).unwrap();
        std::fs::create_dir_all(alpha.join("notes")).unwrap();
        std::fs::write(alpha.join("SOUL.md"), b"soul").unwrap();
        std::fs::write(alpha.join("sessions/sessions.db"), b"db").unwrap();
        std::fs::write(alpha.join("notes/draft.md"), b"draft").unwrap();
        std::os::unix::fs::symlink(".", alpha.join("via")).unwrap();

        let linked = |r: &Result<(), BrowseError>| matches!(r, Err(BrowseError::LinkedPath(_)));
        assert!(linked(&delete_agent_workspace_path(
            &cfg,
            "alpha",
            "via/SOUL.md"
        )));
        assert!(linked(&delete_agent_workspace_path(
            &cfg,
            "alpha",
            "via/sessions"
        )));
        assert!(linked(&move_agent_workspace_path(
            &cfg,
            "alpha",
            "via/SOUL.md",
            "notes/soul-copy.md"
        )));
        assert!(linked(&move_agent_workspace_path(
            &cfg,
            "alpha",
            "via/sessions",
            "notes/old-sessions"
        )));
        // Nor can a move land on a protected entry through the alias.
        assert!(linked(&move_agent_workspace_path(
            &cfg,
            "alpha",
            "notes/draft.md",
            "via/SOUL.md"
        )));
        assert_eq!(std::fs::read(alpha.join("SOUL.md")).unwrap(), b"soul");
        assert_eq!(
            std::fs::read(alpha.join("sessions/sessions.db")).unwrap(),
            b"db"
        );
        assert_eq!(
            std::fs::read(alpha.join("notes/draft.md")).unwrap(),
            b"draft"
        );

        // Paths without a link on the way still work, including a move whose
        // destination directories do not exist yet.
        move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "archive/2026/draft.md")
            .unwrap();
        assert_eq!(
            std::fs::read(alpha.join("archive/2026/draft.md")).unwrap(),
            b"draft"
        );
        delete_agent_workspace_path(&cfg, "alpha", "archive/2026/draft.md").unwrap();
        assert!(!alpha.join("archive/2026/draft.md").exists());
    }

    /// Creating a directory cannot take a protected name through an internal
    /// link either. With `SOUL.md` absent, `via/SOUL.md` with `via -> .`
    /// would otherwise create a directory where the bootstrap file belongs.
    #[cfg(unix)]
    #[test]
    fn mkdir_through_an_internal_link_cannot_take_a_protected_name() {
        let (dir, cfg) = fixture();
        let alpha = dir.path().join("agents/alpha/workspace");
        std::fs::create_dir_all(&alpha).unwrap();
        std::os::unix::fs::symlink(".", alpha.join("via")).unwrap();

        assert!(matches!(
            make_agent_workspace_directory(&cfg, "alpha", "via/SOUL.md"),
            Err(BrowseError::LinkedPath(_))
        ));
        assert!(matches!(
            make_agent_workspace_directory(&cfg, "alpha", "via/fresh/inner"),
            Err(BrowseError::LinkedPath(_))
        ));
        assert!(
            !alpha.join("SOUL.md").exists(),
            "no protected name was taken"
        );
        assert!(!alpha.join("fresh").exists());
        assert!(matches!(
            make_agent_workspace_directory(&cfg, "alpha", "SOUL.md"),
            Err(BrowseError::ProtectedFile(_))
        ));

        // A path without a link on the way is created, idempotently.
        make_agent_workspace_directory(&cfg, "alpha", "notes/2026").unwrap();
        make_agent_workspace_directory(&cfg, "alpha", "notes/2026").unwrap();
        assert!(alpha.join("notes/2026").is_dir());
    }

    /// The shared area's protected top-level directories cannot be removed
    /// through a link that stays inside the shared root either.
    #[cfg(unix)]
    #[test]
    fn an_internal_link_cannot_alias_a_protected_shared_directory() {
        let (dir, cfg) = fixture();
        let shared = dir.path().join("shared");
        std::os::unix::fs::symlink(".", shared.join("via")).unwrap();
        assert!(matches!(
            remove_directory(&cfg, "via/skills"),
            Err(BrowseError::LinkedPath(_))
        ));
        assert!(shared.join("skills/alpha").is_dir());
    }

    #[test]
    fn lists_shared_root_when_path_empty() {
        let (_dir, cfg) = fixture();
        let result = list_directory(&cfg, "").unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].name, "skills");
        assert_eq!(result.entries[0].kind, "dir");
        assert_eq!(result.entries[1].name, "readme.txt");
        assert_eq!(result.entries[1].kind, "file");
    }

    #[test]
    fn descends_one_level() {
        let (_dir, cfg) = fixture();
        let result = list_directory(&cfg, "skills").unwrap();
        let names: Vec<_> = result.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn rejects_escape() {
        let (_dir, cfg) = fixture();
        let err = list_directory(&cfg, "../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn errors_on_missing_path() {
        let (_dir, cfg) = fixture();
        let err = list_directory(&cfg, "ghost").unwrap_err();
        assert!(matches!(err, BrowseError::NotFound(_)));
    }

    #[test]
    fn errors_when_path_is_a_file() {
        let (_dir, cfg) = fixture();
        let err = list_directory(&cfg, "readme.txt").unwrap_err();
        assert!(matches!(err, BrowseError::NotADirectory(_)));
    }

    #[test]
    fn make_directory_creates_nested_path() {
        let (dir, cfg) = fixture();
        make_directory(&cfg, "skills/gamma/sub").unwrap();
        assert!(dir.path().join("shared/skills/gamma/sub").is_dir());
    }

    #[test]
    fn make_directory_is_idempotent() {
        let (_dir, cfg) = fixture();
        make_directory(&cfg, "skills/alpha").unwrap();
        make_directory(&cfg, "skills/alpha").unwrap();
    }

    #[test]
    fn make_directory_rejects_escape() {
        let (_dir, cfg) = fixture();
        let err = make_directory(&cfg, "../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn make_directory_refuses_over_existing_file() {
        let (_dir, cfg) = fixture();
        let err = make_directory(&cfg, "readme.txt").unwrap_err();
        assert!(matches!(err, BrowseError::NotADirectory(_)));
    }

    #[test]
    fn remove_directory_recursively_drops_subtree() {
        let (dir, cfg) = fixture();
        make_directory(&cfg, "skills/alpha/nested/deep").unwrap();
        remove_directory(&cfg, "skills/alpha").unwrap();
        assert!(!dir.path().join("shared/skills/alpha").exists());
        assert!(dir.path().join("shared/skills/beta").is_dir());
    }

    #[test]
    fn remove_directory_refuses_protected_top_level() {
        let (_dir, cfg) = fixture();
        for name in ["skills", "skill-bundles", "knowledge"] {
            let err = remove_directory(&cfg, name).unwrap_err();
            assert!(
                matches!(err, BrowseError::Protected(_)),
                "must refuse to remove protected top-level '{name}', got {err:?}"
            );
        }
    }

    #[test]
    fn remove_directory_refuses_empty_path() {
        let (_dir, cfg) = fixture();
        let err = remove_directory(&cfg, "").unwrap_err();
        assert!(matches!(err, BrowseError::Protected(_)));
    }

    #[test]
    fn remove_directory_rejects_escape() {
        let (_dir, cfg) = fixture();
        let err = remove_directory(&cfg, "../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn remove_directory_errors_on_missing() {
        let (_dir, cfg) = fixture();
        let err = remove_directory(&cfg, "skills/ghost").unwrap_err();
        assert!(matches!(err, BrowseError::NotFound(_)));
    }

    #[test]
    fn remove_directory_allows_nested_under_protected_top_level() {
        // skills/ is protected, but skills/alpha is operator-owned.
        let (dir, cfg) = fixture();
        remove_directory(&cfg, "skills/alpha").unwrap();
        assert!(!dir.path().join("shared/skills/alpha").exists());
        assert!(dir.path().join("shared/skills").is_dir());
    }

    // ── agent workspace ──────────────────────────────────────────────

    fn workspace_fixture() -> (TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("agents/alpha/workspace");
        std::fs::create_dir_all(ws.join("notes/sub")).unwrap();
        std::fs::write(ws.join("notes/draft.md"), b"draft content").unwrap();
        std::fs::write(ws.join("IDENTITY.md"), b"identity").unwrap();
        std::fs::write(ws.join("SOUL.md"), b"soul").unwrap();
        let cfg = Config {
            config_path: dir.path().join("config.toml"),
            ..Config::default()
        };
        (dir, cfg)
    }

    #[test]
    fn list_agent_workspace_returns_one_level() {
        let (_dir, cfg) = workspace_fixture();
        let result = list_agent_workspace(&cfg, "alpha", "").unwrap();
        let names: Vec<_> = result.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"notes"));
        assert!(names.contains(&"IDENTITY.md"));
    }

    #[test]
    fn list_agent_workspace_rejects_escape() {
        let (_dir, cfg) = workspace_fixture();
        let err = list_agent_workspace(&cfg, "alpha", "../../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn read_agent_workspace_file_returns_bytes_and_text_flag() {
        let (_dir, cfg) = workspace_fixture();
        let r = read_agent_workspace_file(&cfg, "alpha", "notes/draft.md").unwrap();
        assert_eq!(r.bytes, b"draft content");
        assert!(r.is_text);
        assert_eq!(r.size, 13);
    }

    #[test]
    fn read_agent_workspace_file_errors_on_directory() {
        let (_dir, cfg) = workspace_fixture();
        let err = read_agent_workspace_file(&cfg, "alpha", "notes").unwrap_err();
        assert!(matches!(err, BrowseError::NotADirectory(_)));
    }

    #[test]
    fn read_agent_workspace_file_enforces_size_cap() {
        let (dir, cfg) = workspace_fixture();
        let ws = dir.path().join("agents/alpha/workspace");
        let big = vec![b'x'; (AGENT_WORKSPACE_READ_CAP + 1) as usize];
        std::fs::write(ws.join("big.bin"), &big).unwrap();
        let err = read_agent_workspace_file(&cfg, "alpha", "big.bin").unwrap_err();
        assert!(matches!(err, BrowseError::TooLarge(_, _)));
    }

    #[test]
    fn delete_agent_workspace_path_removes_file() {
        let (dir, cfg) = workspace_fixture();
        delete_agent_workspace_path(&cfg, "alpha", "notes/draft.md").unwrap();
        assert!(
            !dir.path()
                .join("agents/alpha/workspace/notes/draft.md")
                .exists()
        );
    }

    #[test]
    fn delete_agent_workspace_path_removes_directory_recursively() {
        let (dir, cfg) = workspace_fixture();
        delete_agent_workspace_path(&cfg, "alpha", "notes").unwrap();
        assert!(!dir.path().join("agents/alpha/workspace/notes").exists());
    }

    #[test]
    fn delete_agent_workspace_path_refuses_protected_files() {
        let (_dir, cfg) = workspace_fixture();
        for name in ["IDENTITY.md", "SOUL.md"] {
            let err = delete_agent_workspace_path(&cfg, "alpha", name).unwrap_err();
            assert!(
                matches!(err, BrowseError::ProtectedFile(_)),
                "must refuse {name}, got {err:?}"
            );
        }
    }

    #[test]
    fn delete_agent_workspace_path_refuses_root() {
        let (_dir, cfg) = workspace_fixture();
        let err = delete_agent_workspace_path(&cfg, "alpha", "").unwrap_err();
        assert!(matches!(err, BrowseError::Protected(_)));
    }

    #[test]
    fn delete_agent_workspace_path_rejects_escape() {
        let (_dir, cfg) = workspace_fixture();
        let err = delete_agent_workspace_path(&cfg, "alpha", "../../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn move_agent_workspace_path_renames_within_jail() {
        let (dir, cfg) = workspace_fixture();
        move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "notes/final.md").unwrap();
        assert!(
            !dir.path()
                .join("agents/alpha/workspace/notes/draft.md")
                .exists()
        );
        assert!(
            dir.path()
                .join("agents/alpha/workspace/notes/final.md")
                .is_file()
        );
    }

    #[test]
    fn move_agent_workspace_path_creates_intermediate_dirs() {
        let (dir, cfg) = workspace_fixture();
        move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "archive/2026/draft.md")
            .unwrap();
        assert!(
            dir.path()
                .join("agents/alpha/workspace/archive/2026/draft.md")
                .is_file()
        );
    }

    #[test]
    fn move_agent_workspace_path_refuses_protected_src() {
        let (_dir, cfg) = workspace_fixture();
        let err = move_agent_workspace_path(&cfg, "alpha", "IDENTITY.md", "id.md").unwrap_err();
        assert!(matches!(err, BrowseError::ProtectedFile(_)));
    }

    #[test]
    fn move_agent_workspace_path_refuses_protected_dst() {
        let (_dir, cfg) = workspace_fixture();
        let err =
            move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "IDENTITY.md").unwrap_err();
        assert!(matches!(err, BrowseError::ProtectedFile(_)));
    }

    #[test]
    fn move_agent_workspace_path_rejects_escape() {
        let (_dir, cfg) = workspace_fixture();
        let err = move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "../../etc/draft.md")
            .unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn move_agent_workspace_path_refuses_overwrite() {
        let (_dir, cfg) = workspace_fixture();
        let err =
            move_agent_workspace_path(&cfg, "alpha", "notes/draft.md", "notes/sub").unwrap_err();
        assert!(matches!(err, BrowseError::NotADirectory(_)));
    }

    #[test]
    fn list_agent_workspace_tags_protected_top_level_entries() {
        let (dir, cfg) = workspace_fixture();
        std::fs::create_dir_all(dir.path().join("agents/alpha/workspace/sessions")).unwrap();
        let result = list_agent_workspace(&cfg, "alpha", "").unwrap();
        let sessions = result
            .entries
            .iter()
            .find(|e| e.name == "sessions")
            .unwrap();
        assert!(sessions.protected, "sessions/ must be tagged protected");
        let identity = result
            .entries
            .iter()
            .find(|e| e.name == "IDENTITY.md")
            .unwrap();
        assert!(identity.protected, "IDENTITY.md must be tagged protected");
        let notes = result.entries.iter().find(|e| e.name == "notes").unwrap();
        assert!(!notes.protected, "operator dirs must not be tagged");
    }

    #[test]
    fn list_agent_workspace_does_not_tag_protected_names_below_root() {
        let (dir, cfg) = workspace_fixture();
        std::fs::create_dir_all(dir.path().join("agents/alpha/workspace/notes/sessions")).unwrap();
        let result = list_agent_workspace(&cfg, "alpha", "notes").unwrap();
        let sessions = result
            .entries
            .iter()
            .find(|e| e.name == "sessions")
            .unwrap();
        assert!(
            !sessions.protected,
            "protection only applies at workspace root"
        );
    }

    #[test]
    fn delete_agent_workspace_path_refuses_protected_dir() {
        let (dir, cfg) = workspace_fixture();
        std::fs::create_dir_all(dir.path().join("agents/alpha/workspace/sessions")).unwrap();
        let err = delete_agent_workspace_path(&cfg, "alpha", "sessions").unwrap_err();
        assert!(matches!(err, BrowseError::Protected(_)));
        assert!(dir.path().join("agents/alpha/workspace/sessions").is_dir());
    }

    #[test]
    fn move_agent_workspace_path_refuses_protected_src_dir() {
        let (dir, cfg) = workspace_fixture();
        std::fs::create_dir_all(dir.path().join("agents/alpha/workspace/sessions")).unwrap();
        let err = move_agent_workspace_path(&cfg, "alpha", "sessions", "old_sessions").unwrap_err();
        assert!(matches!(err, BrowseError::Protected(_)));
    }

    #[test]
    fn move_agent_workspace_path_refuses_protected_dst_dir() {
        let (_dir, cfg) = workspace_fixture();
        let err = move_agent_workspace_path(&cfg, "alpha", "notes", "sessions").unwrap_err();
        assert!(matches!(err, BrowseError::Protected(_)));
    }

    #[test]
    fn make_agent_workspace_directory_creates_nested_path() {
        let (dir, cfg) = workspace_fixture();
        make_agent_workspace_directory(&cfg, "alpha", "archive/2026").unwrap();
        assert!(
            dir.path()
                .join("agents/alpha/workspace/archive/2026")
                .is_dir()
        );
    }

    #[test]
    fn make_agent_workspace_directory_is_idempotent() {
        let (_dir, cfg) = workspace_fixture();
        make_agent_workspace_directory(&cfg, "alpha", "notes").unwrap();
        make_agent_workspace_directory(&cfg, "alpha", "notes").unwrap();
    }

    #[test]
    fn make_agent_workspace_directory_rejects_escape() {
        let (_dir, cfg) = workspace_fixture();
        let err = make_agent_workspace_directory(&cfg, "alpha", "../../etc").unwrap_err();
        assert!(matches!(err, BrowseError::Escape(_)));
    }

    #[test]
    fn make_agent_workspace_directory_refuses_over_existing_file() {
        let (_dir, cfg) = workspace_fixture();
        let err = make_agent_workspace_directory(&cfg, "alpha", "notes/draft.md").unwrap_err();
        assert!(matches!(err, BrowseError::NotADirectory(_)));
    }

    #[test]
    fn make_agent_workspace_directory_refuses_protected_file_path() {
        let (_dir, cfg) = workspace_fixture();
        let err = make_agent_workspace_directory(&cfg, "alpha", "IDENTITY.md").unwrap_err();
        assert!(matches!(err, BrowseError::ProtectedFile(_)));
    }

    /// `SOUL.md/child` is not itself a protected name, but creating it
    /// creates a `SOUL.md` directory where the bootstrap file belongs. Each
    /// spelling a case-insensitive or Windows volume maps to `SOUL.md` is
    /// refused too, and nothing is created.
    #[test]
    fn make_agent_workspace_directory_refuses_a_protected_file_along_the_path() {
        let (dir, cfg) = workspace_fixture();
        let soul = dir.path().join("agents/alpha/workspace/SOUL.md");
        std::fs::remove_file(&soul).unwrap();
        for raw in [
            "SOUL.md/child",
            "SOUL.md/a/b",
            "soul.md/child",
            "SOUL.md./child",
            "SOUL.md",
            "Soul.MD",
        ] {
            let err = make_agent_workspace_directory(&cfg, "alpha", raw).unwrap_err();
            assert!(
                matches!(&err, BrowseError::ProtectedFile(name) if protected_file(name)),
                "mkdir {raw:?} must be refused as a protected file, got {err:?}"
            );
            assert!(
                std::fs::symlink_metadata(&soul).is_err(),
                "mkdir {raw:?} must not create anything at SOUL.md"
            );
        }
        // A protected name deeper down is an ordinary directory.
        make_agent_workspace_directory(&cfg, "alpha", "notes/SOUL.md").unwrap();
    }

    /// A move creates its destination's parents, so a destination under a
    /// protected file name would create that directory; a source under one is
    /// refused the same way.
    #[test]
    fn move_agent_workspace_path_refuses_a_protected_file_along_either_path() {
        let (dir, cfg) = workspace_fixture();
        let ws = dir.path().join("agents/alpha/workspace");
        std::fs::remove_file(ws.join("SOUL.md")).unwrap();
        for to in ["SOUL.md/a", "soul.md/a/b"] {
            let err = move_agent_workspace_path(&cfg, "alpha", "notes", to).unwrap_err();
            assert!(
                matches!(&err, BrowseError::ProtectedFile(name) if protected_file(name)),
                "move to {to:?} must be refused as a protected file, got {err:?}"
            );
            assert!(std::fs::symlink_metadata(ws.join("SOUL.md")).is_err());
            assert!(ws.join("notes/draft.md").is_file());
        }
        let err = move_agent_workspace_path(&cfg, "alpha", "SOUL.md/x", "notes/x").unwrap_err();
        assert!(matches!(err, BrowseError::ProtectedFile(_)));
    }

    #[test]
    fn make_agent_workspace_directory_refuses_empty_path() {
        let (_dir, cfg) = workspace_fixture();
        let err = make_agent_workspace_directory(&cfg, "alpha", "").unwrap_err();
        assert!(matches!(err, BrowseError::NotFound(_)));
    }
}
