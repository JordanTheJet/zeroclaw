//! Shared TOML comment-writing helpers used by both the gateway HTTP CRUD
//! handlers and the CLI `zeroclaw config set --comment` / `zeroclaw config patch`
//! flow. Walks a `toml_edit::DocumentMut` to a leaf key by dotted path and
//! decorates its leading whitespace with `# {comment}\n`. Empty comment string

use std::path::Path;

use anyhow::{Context as _, Result};

/// Decorate the keys named in `annotations` with `# {comment}` lines.
///
/// This is a read-modify-write of `config.toml`, so it runs under the same
/// cross-process [`ConfigWriteLock`](crate::schema::ConfigWriteLock) as every
/// other config writer and replaces the file through the shared atomic
/// tmp-write-plus-rename pipeline. Before that it did neither, which made it
/// the one in-tree writer able to land inside another writer's compare-then-
/// rename window (notably the `config_patch` tool's own expected-source
/// compare-and-swap, which calls this immediately after committing), and made
/// an interrupted comment write able to truncate `config.toml`.
///
/// Callers must not already hold a `ConfigWriteLock`: the lock is per open
/// file description, so a nested acquisition blocks forever. Every current
/// caller applies comments only after its save has returned and released.
pub async fn apply_comments(config_path: &Path, annotations: &[(String, String)]) -> Result<()> {
    if annotations.is_empty() {
        return Ok(());
    }
    let write_lock = crate::schema::acquire_config_write_lock(config_path).await?;
    // Read under the lock: this content is the merge base for the decorated
    // document written below, so a read outside the lock would let a writer
    // that commits in between be silently reverted by our write.
    let raw = tokio::fs::read_to_string(config_path)
        .await
        .with_context(|| {
            format!(
                "failed to read config for comment annotation: {}",
                config_path.display()
            )
        })?;
    let mut doc: toml_edit::DocumentMut = match raw.parse() {
        Ok(d) => d,
        Err(_) => return Ok(()), // unparseable; bail without touching file
    };
    for (path, comment) in annotations {
        decorate_key(doc.as_table_mut(), path, comment);
    }
    crate::schema::write_config_atomically_under_lock(config_path, &doc.to_string(), &write_lock)
        .await
}

/// Walk to the leaf key for `dotted` and decorate it with `# {comment}\n`,
/// preserving any non-comment whitespace already in the prefix. Empty comment
/// strips comment lines from the existing prefix while leaving blank lines.
pub fn decorate_key(root: &mut toml_edit::Table, dotted: &str, comment: &str) {
    let segments: Vec<&str> = dotted.split('.').collect();
    let (last, rest) = match segments.split_last() {
        Some(s) => s,
        None => return,
    };
    fn walk<'a>(
        table: &'a mut toml_edit::Table,
        segs: &[&str],
    ) -> Option<&'a mut toml_edit::Table> {
        let mut cursor = table;
        for seg in segs {
            cursor = cursor.get_mut(seg)?.as_table_mut()?;
        }
        Some(cursor)
    }
    let table = match walk(root, rest) {
        Some(t) => t,
        None => return,
    };
    if let Some(mut key) = table.key_mut(last) {
        let decor = key.leaf_decor_mut();
        let new_prefix = build_comment_prefix(decor.prefix(), comment);
        decor.set_prefix(new_prefix);
    }
}

/// Build the new leading decor for a leaf, applying `# {comment}\n` while
/// preserving any non-comment whitespace already in the prefix. Empty `comment`
/// strips `#`-prefixed lines from the existing prefix.
pub fn build_comment_prefix(existing: Option<&toml_edit::RawString>, comment: &str) -> String {
    let prev = existing.and_then(|r| r.as_str()).unwrap_or("");
    let mut kept = String::new();
    for line in prev.split_inclusive('\n') {
        if !line.trim_start().starts_with('#') {
            kept.push_str(line);
        }
    }
    if !comment.is_empty() {
        for line in comment.lines() {
            kept.push_str("# ");
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_comment_prefix_appends_to_blank() {
        assert_eq!(build_comment_prefix(None, "why"), "# why\n");
    }

    #[test]
    fn build_comment_prefix_replaces_existing_comment() {
        let raw = toml_edit::RawString::from("\n# old\n");
        let out = build_comment_prefix(Some(&raw), "new");
        assert!(out.contains("# new\n"));
        assert!(!out.contains("old"));
        assert!(out.starts_with('\n')); // blank line preserved
    }

    #[test]
    fn build_comment_prefix_empty_strips() {
        let raw = toml_edit::RawString::from("\n# stale\n");
        let out = build_comment_prefix(Some(&raw), "");
        assert!(!out.contains('#'));
        assert_eq!(out, "\n");
    }

    #[test]
    fn build_comment_prefix_preserves_multi_blank_lines() {
        let raw = toml_edit::RawString::from("\n\n# inline\n");
        let out = build_comment_prefix(Some(&raw), "fresh");
        assert!(out.starts_with("\n\n"));
        assert!(out.contains("# fresh\n"));
        assert!(!out.contains("inline"));
    }

    #[test]
    fn build_comment_prefix_handles_multiline_comment() {
        let out = build_comment_prefix(None, "first\nsecond\nthird");
        assert_eq!(out, "# first\n# second\n# third\n");
    }
}
