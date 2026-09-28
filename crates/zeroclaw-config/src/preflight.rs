//! Pre-load config check: report what loading a `config.toml` will do to it
//! before anything is loaded or written.
//!
//! The schema validates shape, not whether any code reads a key, and the
//! loader tolerates keys it does not know. A config can therefore load
//! "successfully" while parts of it are discarded, renamed, or accepted and
//! then never read. [`check`] surfaces each of those, plus a missing
//! `schema_version`, which makes the loader treat the file as V1 and rewrite
//! it (collapsing hand-written channel aliases into `default`).
//!
//! It is read-only: it parses the given text, runs the migration chain and a
//! deserialize/serialize round trip in memory, and never touches disk.
//!
//! Findings carry stable `reason` keys, not prose: the CLI renders each as the
//! Fluent message `cli-config-check-<reason>`, and `--json` consumers match on
//! the key.
//!
//! Two tables drive the key-specific findings:
//! - [`RETIRED_KEYS`]: keys that were removed or renamed. The next
//!   retirement is a new row here.
//! - [`INERT_KEYS`]: keys the schema accepts that no code reads. The
//!   systemic audit of every schema key is expected to extend this list.

use serde::Serialize;

use crate::migration::{CURRENT_SCHEMA_VERSION, detect_version, run_chain};
use crate::schema::Config;

/// How a retired key is handled.
#[derive(Debug, Clone, Copy)]
pub enum Disposition {
    /// The key is discarded; nothing replaces it one-for-one.
    Drop,
    /// The value belongs under this dotted path instead.
    Rename(&'static str),
}

/// A key that was removed from, or moved within, the schema.
#[derive(Debug, Clone, Copy)]
pub struct RetiredKey {
    /// Dotted path; `*` matches any single segment. Matched against the file
    /// as written, before migration can erase it, and after migration.
    pub pattern: &'static str,
    pub disposition: Disposition,
    /// Stable reason key; the CLI message is `cli-config-check-<reason>`.
    pub reason: &'static str,
}

/// Keys that were retired. Loading either drops them or accepts them inertly.
pub const RETIRED_KEYS: &[RetiredKey] = &[
    RetiredKey {
        pattern: "security.nevis",
        disposition: Disposition::Drop,
        reason: "retired-security-nevis",
    },
    RetiredKey {
        pattern: "node_transport",
        disposition: Disposition::Drop,
        reason: "retired-node-transport",
    },
    RetiredKey {
        pattern: "channels.wati",
        disposition: Disposition::Drop,
        reason: "retired-wati",
    },
    RetiredKey {
        pattern: "channels_config.wati",
        disposition: Disposition::Drop,
        reason: "retired-wati",
    },
];

/// A key the schema accepts that no code reads.
#[derive(Debug, Clone, Copy)]
pub struct InertKey {
    /// Dotted path; `*` matches any single segment.
    pub pattern: &'static str,
    /// Stable reason key; the CLI message is `cli-config-check-<reason>`.
    pub reason: &'static str,
}

/// Keys that validate and serialize but have no consumer.
pub const INERT_KEYS: &[InertKey] = &[InertKey {
    // Every reader uses risk_profiles.<profile>.excluded_tools (policy.rs,
    // orchestrator effective_non_cli_tool_names, tools/delegate.rs).
    pattern: "channels.*.*.excluded_tools",
    reason: "inert-channel-excluded-tools",
}];

/// Reason keys emitted by [`check`] itself (the tables add their own).
pub const BUILTIN_REASONS: &[&str] = &[
    "parse-error",
    "invalid-schema-version",
    "missing-schema-version",
    "newer-schema-version",
    "migration-failed",
    "migration-moved",
    "migration-removed",
    "load-error",
    "legacy-spelling",
    "unknown-key",
];

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// What kind of problem a finding describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// The file is not valid TOML.
    ParseError,
    /// No `schema_version`: the loader assumes V1 and migrates.
    MissingSchemaVersion,
    /// `schema_version` is not a positive integer, or is newer than supported.
    InvalidSchemaVersion,
    /// The value is discarded when the config loads.
    Dropped,
    /// The value is kept but moves to another key.
    Renamed,
    /// The key is accepted but no code reads it.
    Inert,
    /// The config would fail to load.
    LoadError,
}

/// One thing loading the config will do that the author may not expect.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: FindingKind,
    /// Dotted key path the finding is about (empty for whole-file findings).
    pub path: String,
    /// Destination path for [`FindingKind::Renamed`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Stable reason key; the CLI message is `cli-config-check-<reason>`.
    pub reason: &'static str,
    /// Parser, migration, or deserializer error text, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The result of [`check`].
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The version the loader will treat the file as, if it could tell.
    pub detected_version: Option<u32>,
    /// Whether the file carries an explicit `schema_version`.
    pub schema_version_present: bool,
    pub current_version: u32,
    pub findings: Vec<Finding>,
}

impl Report {
    /// True when anything at warning level or above was found.
    pub fn has_problems(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity <= Severity::Warning)
    }
}

/// Check `input` (the text of a `config.toml`) without loading it.
pub fn check(input: &str) -> Report {
    let mut report = Report {
        detected_version: None,
        schema_version_present: false,
        current_version: CURRENT_SCHEMA_VERSION,
        findings: Vec::new(),
    };

    let original: toml::Value = match toml::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            report
                .push(
                    Severity::Error,
                    FindingKind::ParseError,
                    "",
                    None,
                    "parse-error",
                )
                .detail = Some(e.to_string());
            return report;
        }
    };
    report.schema_version_present = original
        .as_table()
        .is_some_and(|t| t.contains_key("schema_version"));

    let from = match detect_version(&original) {
        Ok(v) => v,
        Err(e) => {
            report
                .push(
                    Severity::Error,
                    FindingKind::InvalidSchemaVersion,
                    "schema_version",
                    None,
                    "invalid-schema-version",
                )
                .detail = Some(e.to_string());
            return report;
        }
    };
    report.detected_version = Some(from);

    if !report.schema_version_present {
        report.push(
            Severity::Error,
            FindingKind::MissingSchemaVersion,
            "schema_version",
            None,
            "missing-schema-version",
        );
    }
    if from > CURRENT_SCHEMA_VERSION {
        report.push(
            Severity::Error,
            FindingKind::InvalidSchemaVersion,
            "schema_version",
            None,
            "newer-schema-version",
        );
        return report;
    }

    // Retired keys, matched as written (before migration can erase them).
    let mut explained: Vec<Vec<String>> = Vec::new();
    report.retired(&original, &mut explained);

    // Migration: what the chain would move or remove on the way to current.
    let migrated = if from < CURRENT_SCHEMA_VERSION {
        match run_chain(original.clone(), from) {
            Ok(m) => {
                report.migration_diff(&original, &m, &explained);
                m
            }
            Err(e) => {
                report
                    .push(
                        Severity::Error,
                        FindingKind::LoadError,
                        "",
                        None,
                        "migration-failed",
                    )
                    .detail = Some(e.to_string());
                return report;
            }
        }
    } else {
        original
    };
    report.retired(&migrated, &mut explained);

    // Keys the schema does not know: dropped, or renamed via a serde alias.
    let schema = schemars::schema_for!(Config).to_value();
    let mut unknown = Vec::new();
    walk(
        &schema,
        &migrated,
        &[&schema],
        &mut Vec::new(),
        &mut unknown,
    );
    unknown.retain(|p| !explained.iter().any(|e| p.starts_with(e)));
    if !unknown.is_empty() {
        let round_trip = migrated
            .clone()
            .try_into::<Config>()
            .map_err(|e| e.to_string())
            .and_then(|cfg| toml::Value::try_from(&cfg).map_err(|e| e.to_string()));
        match round_trip {
            Err(e) => {
                report
                    .push(
                        Severity::Error,
                        FindingKind::LoadError,
                        "",
                        None,
                        "load-error",
                    )
                    .detail = Some(e);
            }
            Ok(loaded) => {
                for path in unknown {
                    report.classify_unknown(&migrated, &loaded, &path);
                }
            }
        }
    }

    // Inert keys (explicit table): accepted, never read.
    for inert in INERT_KEYS {
        for (path, value) in matches(&migrated, inert.pattern) {
            if !is_empty_value(value) {
                report.push(
                    Severity::Warning,
                    FindingKind::Inert,
                    &dotted(&path),
                    None,
                    inert.reason,
                );
            }
        }
    }

    report.findings.sort_by_key(|f| f.severity);
    report
}

impl Report {
    fn push(
        &mut self,
        severity: Severity,
        kind: FindingKind,
        path: &str,
        to: Option<String>,
        reason: &'static str,
    ) -> &mut Finding {
        self.findings.push(Finding {
            severity,
            kind,
            path: path.to_string(),
            to,
            reason,
            detail: None,
        });
        let last = self.findings.len() - 1;
        &mut self.findings[last]
    }

    /// Report [`RETIRED_KEYS`] matches in `value` not already reported.
    fn retired(&mut self, value: &toml::Value, explained: &mut Vec<Vec<String>>) {
        for retired in RETIRED_KEYS {
            for (path, _) in matches(value, retired.pattern) {
                if explained.contains(&path) {
                    continue;
                }
                let (kind, to) = match retired.disposition {
                    Disposition::Drop => (FindingKind::Dropped, None),
                    Disposition::Rename(dest) => (FindingKind::Renamed, Some(dest.to_string())),
                };
                self.push(Severity::Warning, kind, &dotted(&path), to, retired.reason);
                explained.push(path);
            }
        }
    }

    /// Leaves the migration removes are renamed when the same value reappears
    /// at exactly one new leaf, and dropped otherwise. Leaves under an already
    /// explained (retired) path are skipped.
    fn migration_diff(
        &mut self,
        before: &toml::Value,
        after: &toml::Value,
        explained: &[Vec<String>],
    ) {
        let before_leaves = leaves(before);
        let after_leaves = leaves(after);
        let added: Vec<&(Vec<String>, &toml::Value)> = after_leaves
            .iter()
            .filter(|(p, _)| !before_leaves.iter().any(|(q, _)| q == p))
            .collect();
        for (path, value) in &before_leaves {
            if path.first().is_some_and(|s| s == "schema_version")
                || explained.iter().any(|e| path.starts_with(e))
                || after_leaves.iter().any(|(q, _)| q == path)
            {
                continue;
            }
            let dests: Vec<_> = added.iter().filter(|(_, v)| *v == *value).collect();
            if let [(dest, _)] = dests.as_slice() {
                self.push(
                    Severity::Warning,
                    FindingKind::Renamed,
                    &dotted(path),
                    Some(dotted(dest)),
                    "migration-moved",
                );
            } else {
                self.push(
                    Severity::Warning,
                    FindingKind::Dropped,
                    &dotted(path),
                    None,
                    "migration-removed",
                );
            }
        }
    }

    /// A key missing from the schema either reappears under a sibling name
    /// after a real deserialize/serialize round trip (a serde alias: renamed),
    /// survives under its own name (the schema is incomplete: fine), or is gone
    /// (dropped).
    fn classify_unknown(&mut self, input: &toml::Value, loaded: &toml::Value, path: &[String]) {
        let Some((key, parent)) = path.split_last() else {
            return;
        };
        let Some(value) = get(input, path) else {
            return;
        };
        let input_parent = get(input, parent).and_then(toml::Value::as_table);
        if let Some(lp) = get(loaded, parent).and_then(toml::Value::as_table) {
            if lp.contains_key(key.as_str()) {
                return;
            }
            let renamed = lp.iter().find(|(k, v)| {
                *v == value && input_parent.is_none_or(|ip| !ip.contains_key(k.as_str()))
            });
            if let Some((new_key, _)) = renamed {
                let mut dest = parent.to_vec();
                dest.push(new_key.clone());
                self.push(
                    Severity::Info,
                    FindingKind::Renamed,
                    &dotted(path),
                    Some(dotted(&dest)),
                    "legacy-spelling",
                );
                return;
            }
        }
        self.push(
            Severity::Warning,
            FindingKind::Dropped,
            &dotted(path),
            None,
            "unknown-key",
        );
    }
}

fn dotted(path: &[String]) -> String {
    path.join(".")
}

fn get<'a>(value: &'a toml::Value, path: &[String]) -> Option<&'a toml::Value> {
    path.iter()
        .try_fold(value, |cur, seg| cur.as_table()?.get(seg.as_str()))
}

fn is_empty_value(value: &toml::Value) -> bool {
    match value {
        toml::Value::Array(a) => a.is_empty(),
        toml::Value::Table(t) => t.is_empty(),
        toml::Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// Every (path, value) in `value` matching a dotted pattern (`*` = any segment).
fn matches<'a>(value: &'a toml::Value, pattern: &str) -> Vec<(Vec<String>, &'a toml::Value)> {
    let segs: Vec<&str> = pattern.split('.').collect();
    let mut out = Vec::new();
    collect_matches(value, &segs, &mut Vec::new(), &mut out);
    out
}

fn collect_matches<'a>(
    value: &'a toml::Value,
    segs: &[&str],
    path: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, &'a toml::Value)>,
) {
    let Some((head, rest)) = segs.split_first() else {
        out.push((path.clone(), value));
        return;
    };
    let Some(table) = value.as_table() else {
        return;
    };
    for (k, v) in table {
        if *head == "*" || head == k {
            path.push(k.clone());
            collect_matches(v, rest, path, out);
            path.pop();
        }
    }
}

/// Every leaf (non-table value) with its path. Arrays are leaves.
fn leaves(value: &toml::Value) -> Vec<(Vec<String>, &toml::Value)> {
    fn go<'a>(
        v: &'a toml::Value,
        path: &mut Vec<String>,
        out: &mut Vec<(Vec<String>, &'a toml::Value)>,
    ) {
        match v.as_table() {
            Some(t) => {
                for (k, child) in t {
                    path.push(k.clone());
                    go(child, path, out);
                    path.pop();
                }
            }
            None => out.push((path.clone(), v)),
        }
    }
    let mut out = Vec::new();
    go(value, &mut Vec::new(), &mut out);
    out
}

// ── JSON Schema walk ──────────────────────────────────────────────

/// Follow `$ref`s and expand `anyOf` / `oneOf` / `allOf` into their branches.
fn branches<'a>(
    root: &'a serde_json::Value,
    node: &'a serde_json::Value,
) -> Vec<&'a serde_json::Value> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    let mut guard = 0;
    while let Some(n) = stack.pop() {
        guard += 1;
        if guard > 512 {
            break;
        }
        if let Some(target) = n.get("$ref").and_then(|r| r.as_str()) {
            if let Some(resolved) = resolve_ref(root, target) {
                stack.push(resolved);
            }
            continue;
        }
        let mut composite = false;
        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(arr) = n.get(key).and_then(|a| a.as_array()) {
                composite = true;
                stack.extend(arr.iter());
            }
        }
        if !composite || n.get("properties").is_some() {
            out.push(n);
        }
    }
    out
}

fn resolve_ref<'a>(root: &'a serde_json::Value, target: &str) -> Option<&'a serde_json::Value> {
    let pointer = target.strip_prefix('#')?;
    root.pointer(pointer)
}

enum Lookup<'a> {
    /// The key is defined; recurse with these schemas.
    Known(Vec<&'a serde_json::Value>),
    /// The schema says nothing about this object's keys (free-form).
    Open,
    /// The object has declared properties and this is not one of them.
    Unknown,
}

fn lookup<'a>(
    root: &'a serde_json::Value,
    schemas: &[&'a serde_json::Value],
    key: &str,
) -> Lookup<'a> {
    let mut subs = Vec::new();
    let mut open = false;
    let mut declared = false;
    for schema in schemas {
        for b in branches(root, schema) {
            if b.as_bool() == Some(true) {
                open = true;
                continue;
            }
            let props = b.get("properties").and_then(|p| p.as_object());
            if let Some(props) = props {
                declared = true;
                if let Some(p) = props.get(key) {
                    subs.push(p);
                }
            }
            match b.get("additionalProperties") {
                Some(serde_json::Value::Bool(true)) => open = true,
                Some(ap @ serde_json::Value::Object(_)) => subs.push(ap),
                Some(_) => {}
                None if props.is_none() => open = true,
                None => {}
            }
            if let Some(pp) = b.get("patternProperties").and_then(|p| p.as_object()) {
                subs.extend(pp.values());
            }
        }
    }
    if !subs.is_empty() {
        Lookup::Known(subs)
    } else if open || !declared {
        Lookup::Open
    } else {
        Lookup::Unknown
    }
}

fn walk<'a>(
    root: &'a serde_json::Value,
    value: &toml::Value,
    schemas: &[&'a serde_json::Value],
    path: &mut Vec<String>,
    unknown: &mut Vec<Vec<String>>,
) {
    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                if path.is_empty() && k == "schema_version" {
                    continue;
                }
                path.push(k.clone());
                match lookup(root, schemas, k) {
                    Lookup::Known(subs) => walk(root, v, &subs, path, unknown),
                    Lookup::Open => {}
                    Lookup::Unknown => unknown.push(path.clone()),
                }
                path.pop();
            }
        }
        toml::Value::Array(items) => {
            let item_schemas: Vec<&serde_json::Value> = schemas
                .iter()
                .flat_map(|s| branches(root, s))
                .filter_map(|b| b.get("items"))
                .collect();
            if item_schemas.is_empty() {
                return;
            }
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                walk(root, item, &item_schemas, path, unknown);
                path.pop();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(report: &Report) -> Vec<(FindingKind, String)> {
        report
            .findings
            .iter()
            .map(|f| (f.kind, f.path.clone()))
            .collect()
    }

    fn current(body: &str) -> String {
        format!("schema_version = {CURRENT_SCHEMA_VERSION}\n{body}")
    }

    #[test]
    fn clean_current_config_has_no_problems() {
        let report = check(&current(""));
        assert!(!report.has_problems(), "{:#?}", report.findings);
        assert_eq!(report.detected_version, Some(CURRENT_SCHEMA_VERSION));
    }

    #[test]
    fn missing_schema_version_is_a_loud_error() {
        let report = check("");
        let f = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::MissingSchemaVersion)
            .expect("missing schema_version must be reported");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.reason, "missing-schema-version");
        assert!(!report.schema_version_present);
        assert_eq!(report.detected_version, Some(1));
    }

    #[test]
    fn newer_schema_version_refuses() {
        let report = check(&format!(
            "schema_version = {}\n",
            CURRENT_SCHEMA_VERSION + 1
        ));
        assert_eq!(
            kinds(&report),
            vec![(FindingKind::InvalidSchemaVersion, "schema_version".into())]
        );
    }

    #[test]
    fn unparsable_toml_is_reported() {
        let report = check("this is = = not toml");
        assert_eq!(report.findings[0].kind, FindingKind::ParseError);
    }

    #[test]
    fn retired_nevis_table_is_reported_dropped() {
        let report = check(&current(
            "[security.nevis]\nenabled = true\ninstance_url = \"https://nevis.example\"\n",
        ));
        let dropped: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Dropped)
            .collect();
        assert_eq!(dropped.len(), 1, "{:#?}", report.findings);
        assert_eq!(dropped[0].path, "security.nevis");
        assert_eq!(dropped[0].reason, "retired-security-nevis");
    }

    #[test]
    fn unknown_key_is_reported_dropped() {
        let report = check(&current("[security]\ntotally_not_a_key = 1\n"));
        assert!(
            kinds(&report).contains(&(FindingKind::Dropped, "security.totally_not_a_key".into())),
            "{:#?}",
            report.findings
        );
    }

    #[test]
    fn unknown_top_level_key_is_reported_dropped() {
        let report = check(&current("no_such_section_at_all = true\n"));
        assert!(
            kinds(&report).contains(&(FindingKind::Dropped, "no_such_section_at_all".into())),
            "{:#?}",
            report.findings
        );
    }

    #[test]
    fn channel_excluded_tools_is_reported_inert() {
        let report = check(&current(
            "[channels.telegram.default]\nbot_token = \"123:abc\"\nexcluded_tools = [\"shell\"]\n",
        ));
        let inert: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Inert)
            .collect();
        assert_eq!(inert.len(), 1, "{:#?}", report.findings);
        assert_eq!(inert[0].path, "channels.telegram.default.excluded_tools");
        assert_eq!(inert[0].reason, "inert-channel-excluded-tools");
    }

    #[test]
    fn empty_channel_excluded_tools_is_not_noise() {
        let report = check(&current(
            "[channels.telegram.default]\nbot_token = \"123:abc\"\nexcluded_tools = []\n",
        ));
        assert!(
            !report.findings.iter().any(|f| f.kind == FindingKind::Inert),
            "{:#?}",
            report.findings
        );
    }

    #[test]
    fn risk_profile_excluded_tools_is_not_inert() {
        let report = check(&current(
            "[risk_profiles.default]\nexcluded_tools = [\"shell\"]\n",
        ));
        assert!(
            !report.findings.iter().any(|f| f.kind == FindingKind::Inert),
            "{:#?}",
            report.findings
        );
    }

    #[test]
    fn serde_alias_is_reported_as_a_rename_not_a_drop() {
        // `composio.enable` is a serde alias for `composio.enabled`.
        let report = check(&current("[composio]\nenable = true\n"));
        let f = report
            .findings
            .iter()
            .find(|f| f.path == "composio.enable")
            .unwrap_or_else(|| panic!("alias not reported: {:#?}", report.findings));
        assert_eq!(f.kind, FindingKind::Renamed);
        assert_eq!(f.to.as_deref(), Some("composio.enabled"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn retired_wati_channel_is_reported_once() {
        let report = check(&current("[channels.wati.default]\napi_token = \"t\"\n"));
        let wati: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.path.starts_with("channels.wati"))
            .collect();
        assert_eq!(wati.len(), 1, "{:#?}", report.findings);
        assert_eq!(wati[0].reason, "retired-wati");
        assert_eq!(wati[0].kind, FindingKind::Dropped);
    }

    #[test]
    fn pattern_matching_uses_single_segment_wildcards() {
        let v: toml::Value =
            toml::from_str("[channels.slack.ops]\nexcluded_tools = [\"x\"]\n").unwrap();
        let found = matches(&v, "channels.*.*.excluded_tools");
        assert_eq!(found.len(), 1);
        assert_eq!(dotted(&found[0].0), "channels.slack.ops.excluded_tools");
        assert!(matches(&v, "channels.*.excluded_tools").is_empty());
    }

    #[test]
    fn v1_config_reports_migration_moves() {
        // A V1 root key the migration relocates.
        let report = check("default_temperature = 0.4\n");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.path == "default_temperature"
                    && matches!(f.kind, FindingKind::Renamed | FindingKind::Dropped)),
            "{:#?}",
            report.findings
        );
    }
}
