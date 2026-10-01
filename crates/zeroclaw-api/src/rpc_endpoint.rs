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
//! one data directory. The name now comes from FNV-1a over a specified
//! encoding of the directory; see [`pipe_name`]. For one release a client
//! also tries the old name when nothing listens at the new one, so it still
//! finds a daemon that an older binary started and nobody has restarted yet.
//! Finding that daemon is all the fallback does: whether the client can then
//! use it is up to the client's handshake. The daemon binds only the new name.

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
    explicit_endpoint(socket_override).unwrap_or_else(|| default_endpoint(data_dir))
}

/// The endpoint an override names, if it names one: trimmed, and `None` when
/// blank.
fn explicit_endpoint(socket_override: Option<&str>) -> Option<PathBuf> {
    socket_override
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
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

/// The named-pipe name for `data_dir`: `\\.\pipe\zeroclaw-daemon-` followed
/// by 16 hex digits of a 64-bit FNV-1a hash. Every binary derives the same
/// name because the hash input is fixed:
///
/// 1. The path as UTF-16 code units. On Windows these come from
///    `encode_wide`, which is lossless, unpaired surrogates included.
/// 2. Spellings Windows treats as one directory are made equal. `\` and `/`
///    are both separators (after a verbatim `\\?\` prefix only `\` is), a
///    run of separators inside the path counts as one, a trailing separator
///    is dropped, and `.` components are dropped (verbatim paths keep them).
///    A leading `\` or `\\` is kept, so rooted, UNC and drive-relative paths
///    stay distinct.
/// 3. ASCII letters are lower-cased, so drive letters and ASCII names match
///    in either case. Other letters are left alone: Windows folds them with a
///    per-volume table that cannot be reproduced stably, and a directory can
///    be case-sensitive.
/// 4. Each unit is hashed as two little-endian bytes.
///
/// `..` is not resolved and links are not followed; both need the
/// filesystem. The function is defined on every platform so its values can
/// be tested anywhere. Off Windows the units come from the path's Unicode
/// form, which equals `encode_wide` for every path that is valid Unicode.
#[must_use]
pub fn pipe_name(data_dir: &Path) -> String {
    pipe_name_from_units(&path_units(data_dir))
}

#[cfg(windows)]
fn path_units(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().collect()
}

#[cfg(not(windows))]
fn path_units(path: &Path) -> Vec<u16> {
    path.to_string_lossy().encode_utf16().collect()
}

fn pipe_name_from_units(units: &[u16]) -> String {
    let key = pipe_key(units);
    let hash = fnv1a_64(key.iter().flat_map(|unit| unit.to_le_bytes()));
    format!(r"\\.\pipe\zeroclaw-daemon-{hash:016x}")
}

/// Steps 2 and 3 of [`pipe_name`]: one spelling per directory.
fn pipe_key(units: &[u16]) -> Vec<u16> {
    const BACKSLASH: u16 = b'\\' as u16;
    const SLASH: u16 = b'/' as u16;
    const DOT: u16 = b'.' as u16;
    const VERBATIM_PREFIX: [u16; 4] = [BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];

    let verbatim = units.starts_with(&VERBATIM_PREFIX);
    let is_separator = |unit: &u16| *unit == BACKSLASH || (!verbatim && *unit == SLASH);
    let leading = units
        .iter()
        .take_while(|unit| is_separator(unit))
        .count()
        .min(2);

    let mut key = vec![BACKSLASH; leading];
    let components = units
        .split(is_separator)
        .filter(|component| !component.is_empty() && (verbatim || component[..] != [DOT]));
    for (index, component) in components.enumerate() {
        if index > 0 {
            key.push(BACKSLASH);
        }
        key.extend(component.iter().map(|&unit| fold_ascii(unit)));
    }
    key
}

fn fold_ascii(unit: u16) -> u16 {
    match u8::try_from(unit) {
        Ok(byte) => u16::from(byte.to_ascii_lowercase()),
        Err(_) => unit,
    }
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
    endpoints_with_fallback(socket_override, data_dir, cfg!(windows))
}

/// [`client_endpoints_with`] with the platform's legacy fallback passed in,
/// so the Windows rule is tested on every platform.
fn endpoints_with_fallback(
    socket_override: Option<&str>,
    data_dir: &Path,
    legacy_fallback: bool,
) -> ClientEndpoints {
    // Whether an override was given is read from the override itself: one
    // that happens to name the default endpoint is still an explicit choice
    // and must not open a second one.
    match explicit_endpoint(socket_override) {
        Some(primary) => ClientEndpoints {
            primary,
            legacy: None,
        },
        None => ClientEndpoints {
            primary: default_endpoint(data_dir),
            legacy: legacy_fallback.then(|| PathBuf::from(legacy_pipe_name(data_dir))),
        },
    }
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
fn fnv1a_64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.into_iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
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
            r"\\.\pipe\zeroclaw-daemon-811bcf3aa85679f9"
        );
        assert_eq!(
            pipe_name(Path::new("/home/alice/.zeroclaw/data")),
            r"\\.\pipe\zeroclaw-daemon-679420572319782d"
        );
        assert_eq!(
            pipe_name(Path::new(r"D:\ZeroClaw\Data")),
            r"\\.\pipe\zeroclaw-daemon-c58e01b43a3f5ca0"
        );
        assert_eq!(
            pipe_name(Path::new(r"\\server\share\zeroclaw\data")),
            r"\\.\pipe\zeroclaw-daemon-e9dc363b4b04616a"
        );
    }

    #[test]
    fn spellings_of_one_windows_directory_share_a_pipe() {
        let canonical = pipe_name(Path::new(r"C:\Users\Alice\.zeroclaw\data"));
        for spelling in [
            r"c:\users\alice\.zeroclaw\data",
            "C:/Users/Alice/.zeroclaw/data",
            "C:\\Users\\Alice\\.zeroclaw\\data\\",
            r"C:\Users\\Alice\.zeroclaw\\\data",
            r"C:\Users\.\Alice\.zeroclaw/./data/",
            r"C:\Users/Alice\.zeroclaw/data",
        ] {
            assert_eq!(pipe_name(Path::new(spelling)), canonical, "{spelling}");
        }
    }

    #[test]
    fn distinct_windows_directories_get_distinct_pipes() {
        let names = [
            r"C:\a\data",
            r"C:\b\data",
            r"C:data",
            r"\data",
            r"\\data\share",
            "data",
            r"C:\a\..\data",
            r"C:\data",
            r"\\?\C:\a\.\data",
            r"\\?\C:\a\data",
            r"\\?\C:/a/data",
        ]
        .map(|name| pipe_name(Path::new(name)));
        for (i, left) in names.iter().enumerate() {
            for right in &names[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn only_ascii_letters_are_case_folded() {
        // The supported identity: ASCII case folds, other letters do not.
        // Windows folds those with a per-volume table, and a directory can
        // be case-sensitive, so no fixed rule matches it for every volume.
        assert_ne!(
            pipe_name(Path::new(r"C:\Users\Émile\.zeroclaw\data")),
            pipe_name(Path::new(r"C:\Users\émile\.zeroclaw\data"))
        );
        // The ASCII letters around a non-ASCII one still fold.
        assert_eq!(
            pipe_name(Path::new(r"C:\Users\ÉMILE\.zeroclaw\data")),
            pipe_name(Path::new(r"c:\users\Émile\.zeroclaw\data"))
        );
    }

    #[test]
    fn every_utf16_unit_reaches_the_hash() {
        // Two unpaired surrogates: a lossy conversion would turn both into
        // U+FFFD and give them one pipe.
        let drive = [u16::from(b'C'), u16::from(b':'), u16::from(b'\\')];
        let first = [drive.as_slice(), &[0xd800]].concat();
        let second = [drive.as_slice(), &[0xd801]].concat();
        assert_ne!(pipe_name_from_units(&first), pipe_name_from_units(&second));
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_are_read_without_loss() {
        use std::os::windows::ffi::OsStringExt;
        let path = |unit| {
            PathBuf::from(std::ffi::OsString::from_wide(&[
                u16::from(b'C'),
                u16::from(b':'),
                u16::from(b'\\'),
                unit,
            ]))
        };
        assert_ne!(pipe_name(&path(0xd800)), pipe_name(&path(0xd801)));
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
        assert_eq!(defaults.legacy.is_some(), cfg!(windows));
        assert_eq!(defaults.iter().count(), 1 + usize::from(cfg!(windows)));

        // The Windows rule, on every platform.
        for blank in [None, Some(""), Some(" \t")] {
            let endpoints = endpoints_with_fallback(blank, dir, true);
            assert_eq!(endpoints.primary, default_endpoint(dir), "{blank:?}");
            assert_eq!(
                endpoints.legacy,
                Some(PathBuf::from(legacy_pipe_name(dir))),
                "{blank:?}"
            );
        }
        let overridden = endpoints_with_fallback(Some(r"\\.\pipe\mine"), dir, true);
        assert_eq!(overridden.primary, PathBuf::from(r"\\.\pipe\mine"));
        assert_eq!(
            overridden.legacy, None,
            "an explicit endpoint has no fallback"
        );
    }

    #[test]
    fn an_explicit_override_naming_the_default_endpoint_has_no_fallback() {
        // Naming the default endpoint explicitly is still an explicit choice:
        // the client dials that endpoint and nothing else.
        let dir = Path::new(r"C:\Users\Alice\.zeroclaw\data");
        let default = default_endpoint(dir);
        let default = default.to_str().expect("the default endpoint is Unicode");
        for explicit in [default.to_string(), format!("  {default}\n")] {
            for endpoints in [
                endpoints_with_fallback(Some(&explicit), dir, true),
                client_endpoints_with(Some(&explicit), dir),
            ] {
                assert_eq!(endpoints.primary, PathBuf::from(default), "{explicit:?}");
                assert_eq!(endpoints.legacy, None, "{explicit:?}");
                assert_eq!(endpoints.iter().count(), 1);
            }
        }
    }
}
