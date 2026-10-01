//! Where the daemon's local RPC endpoint lives.
//!
//! One resolver for the daemon and every client (the runtime, the RPC client
//! and zerocode), so a client always dials the endpoint the daemon bound:
//!
//! - `ZEROCLAW_SOCKET`, when set to a non-blank value, wins on every platform.
//! - Otherwise, on Unix, `<data_dir>/daemon.sock`.
//! - Otherwise, on Windows, a named pipe whose name is a stable hash of the
//!   data directory: named pipes live in one flat kernel namespace, so two
//!   data directories on one machine need different names.
//!
//! The Windows name used to come from `std`'s `DefaultHasher`, whose output
//! the standard library does not promise to keep across releases, so two
//! binaries built by different toolchains could derive different names for
//! one data directory. The name now comes from FNV-1a, a fixed published
//! function. For one release a client also tries the old name, so it still
//! reaches a daemon that was started by an older binary and not yet
//! restarted. The daemon itself binds only the new name.

use std::path::{Path, PathBuf};

/// Environment variable that overrides the daemon endpoint on every platform.
pub const SOCKET_ENV: &str = "ZEROCLAW_SOCKET";

/// The endpoint the daemon binds for `data_dir`, and the first one a client
/// dials. Honors a non-blank `ZEROCLAW_SOCKET`.
#[must_use]
pub fn resolve_endpoint(data_dir: &Path) -> PathBuf {
    resolve_endpoint_with(std::env::var(SOCKET_ENV).ok().as_deref(), data_dir)
}

/// [`resolve_endpoint`] with the override passed in rather than read from
/// the environment. A blank override is ignored; surrounding whitespace is
/// trimmed.
#[must_use]
pub fn resolve_endpoint_with(socket_override: Option<&str>, data_dir: &Path) -> PathBuf {
    match socket_override
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        Some(path) => PathBuf::from(path),
        None => default_endpoint(data_dir),
    }
}

/// The platform default endpoint under `data_dir`, ignoring the override.
#[cfg(not(windows))]
#[must_use]
pub fn default_endpoint(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon.sock")
}

/// The platform default endpoint under `data_dir`, ignoring the override.
#[cfg(windows)]
#[must_use]
pub fn default_endpoint(data_dir: &Path) -> PathBuf {
    PathBuf::from(pipe_name(data_dir))
}

/// The named-pipe name for `data_dir`. Defined on every platform so its
/// stability can be tested anywhere; only Windows uses it.
///
/// The key is the data directory's exact bytes with ASCII letters folded to
/// lower case, because Windows compares paths case-insensitively. Non-ASCII
/// bytes are kept as they are, so the name never depends on Unicode case
/// tables that change between toolchains.
#[must_use]
pub fn pipe_name(data_dir: &Path) -> String {
    let key = data_dir.as_os_str().as_encoded_bytes().to_ascii_lowercase();
    format!(r"\\.\pipe\zeroclaw-daemon-{:016x}", fnv1a_64(&key))
}

/// The named-pipe name daemons used before the stable hash, derived with
/// `DefaultHasher` exactly as they did. Clients still try it for one release
/// so they reach a daemon an older binary started; remove it after that.
#[must_use]
pub fn legacy_pipe_name(data_dir: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data_dir.hash(&mut hasher);
    format!(r"\\.\pipe\zeroclaw-{:x}", hasher.finish())
}

/// The endpoints a client dials, in order: `primary` is where a current
/// daemon listens; `legacy` is the pre-stable-hash pipe name, tried only when
/// nothing listens at `primary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEndpoints {
    pub primary: PathBuf,
    /// Set only on Windows when no `ZEROCLAW_SOCKET` override is in effect.
    pub legacy: Option<PathBuf>,
}

impl ClientEndpoints {
    /// Every endpoint to try, primary first.
    pub fn iter(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.primary.as_path()).chain(self.legacy.as_deref())
    }
}

/// The endpoints a client dials for `data_dir`. Honors a non-blank
/// `ZEROCLAW_SOCKET`, which disables the legacy fallback.
#[must_use]
pub fn client_endpoints(data_dir: &Path) -> ClientEndpoints {
    client_endpoints_with(std::env::var(SOCKET_ENV).ok().as_deref(), data_dir)
}

/// [`client_endpoints`] with the override passed in rather than read from
/// the environment.
#[must_use]
pub fn client_endpoints_with(socket_override: Option<&str>, data_dir: &Path) -> ClientEndpoints {
    let primary = resolve_endpoint_with(socket_override, data_dir);
    let overridden = primary != default_endpoint(data_dir);
    let legacy = (cfg!(windows) && !overridden).then(|| PathBuf::from(legacy_pipe_name(data_dir)));
    ClientEndpoints { primary, legacy }
}

/// Data directories every endpoint caller's agreement test resolves. One
/// list keeps the runtime, the RPC client and zerocode checking the same
/// cases.
#[doc(hidden)]
pub const AGREEMENT_DATA_DIRS: &[&str] = &[
    "/home/alice/.zeroclaw/data",
    "/srv/zeroclaw/profiles/ops/data",
    "relative/data",
    r"C:\Users\Alice\.zeroclaw\data",
    r"c:\users\alice\.zeroclaw\data",
    r"D:\ZeroClaw\Data",
];

/// 64-bit FNV-1a: a fixed, published hash, so the pipe name is the same for
/// every binary that ever computes it.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names_are_fixed_values() {
        // These names are what every daemon and client, on any toolchain,
        // derives for these directories. Changing one strands every running
        // daemon from new clients; do not update them to make a test pass.
        assert_eq!(
            pipe_name(Path::new(r"C:\Users\Alice\.zeroclaw\data")),
            r"\\.\pipe\zeroclaw-daemon-1ec1cf469dce10fd"
        );
        assert_eq!(
            pipe_name(Path::new("/home/alice/.zeroclaw/data")),
            r"\\.\pipe\zeroclaw-daemon-916a747457f5883f"
        );
        assert_eq!(
            pipe_name(Path::new(r"D:\ZeroClaw\Data")),
            r"\\.\pipe\zeroclaw-daemon-c5c6349b4cd0d584"
        );
    }

    #[test]
    fn pipe_names_fold_case_and_separate_directories() {
        assert_eq!(
            pipe_name(Path::new(r"C:\Users\Alice\.zeroclaw\data")),
            pipe_name(Path::new(r"c:\users\alice\.zeroclaw\data"))
        );
        assert_ne!(
            pipe_name(Path::new(r"C:\a\data")),
            pipe_name(Path::new(r"C:\b\data"))
        );
    }

    #[test]
    fn stable_and_legacy_pipe_names_never_coincide() {
        // The stable name carries `daemon-`, which is not hex, so it can never
        // equal a legacy `zeroclaw-<hex>` name a client also tries.
        for dir in AGREEMENT_DATA_DIRS {
            let dir = Path::new(dir);
            assert_ne!(pipe_name(dir), legacy_pipe_name(dir));
            assert!(legacy_pipe_name(dir).starts_with(r"\\.\pipe\zeroclaw-"));
        }
    }

    #[test]
    fn a_non_blank_override_wins_and_a_blank_one_is_ignored() {
        let dir = Path::new("/home/alice/.zeroclaw/data");
        assert_eq!(
            resolve_endpoint_with(Some("/tmp/zc.sock"), dir),
            PathBuf::from("/tmp/zc.sock")
        );
        assert_eq!(
            resolve_endpoint_with(Some("  /tmp/zc.sock \n"), dir),
            PathBuf::from("/tmp/zc.sock")
        );
        for blank in [None, Some(""), Some("   ")] {
            assert_eq!(resolve_endpoint_with(blank, dir), default_endpoint(dir));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_endpoint_stays_daemon_sock_under_the_data_dir() {
        assert_eq!(
            default_endpoint(Path::new("/home/alice/.zeroclaw/data")),
            PathBuf::from("/home/alice/.zeroclaw/data/daemon.sock")
        );
    }

    #[test]
    fn clients_fall_back_to_the_legacy_pipe_only_on_windows_without_an_override() {
        let dir = Path::new(r"C:\Users\Alice\.zeroclaw\data");
        let defaults = client_endpoints_with(None, dir);
        assert_eq!(defaults.primary, default_endpoint(dir));
        if cfg!(windows) {
            assert_eq!(defaults.legacy, Some(PathBuf::from(legacy_pipe_name(dir))));
        } else {
            assert_eq!(defaults.legacy, None);
        }
        assert_eq!(defaults.iter().count(), 1 + usize::from(cfg!(windows)));

        let overridden = client_endpoints_with(Some(r"\\.\pipe\mine"), dir);
        assert_eq!(overridden.primary, PathBuf::from(r"\\.\pipe\mine"));
        assert_eq!(
            overridden.legacy, None,
            "an explicit endpoint has no fallback"
        );
    }
}
