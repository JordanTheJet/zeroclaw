//! The plugin egress grant ceremony: the pure half.
//!
//! The manifest **declares**; the operator's config **grants**. Installation is
//! the one moment where those two can be reconciled without an operator typing
//! anything, so `zeroclaw plugin install` seeds a *newly created*
//! `[[plugins.entries]]` row from the declaration and prints what it granted.
//!
//! Everything after that is a diff, never a write: a package upgrade whose
//! declaration grew does **not** extend an entry that already exists. The CLI
//! prints the difference with the exact command, and the operator applies it
//! deliberately. That is the security property of the ceremony — a package
//! update must not be able to widen its own network reach — so the "existing
//! entry" branch in [`crate::plugins::egress_ceremony`]'s callers is
//! deliberately write-free.
//!
//! This module owns only the comparison and command construction; every
//! user-facing string stays in the CLI so it routes through Fluent.

use zeroclaw_infra::net_guard::{egress_pattern_contains, normalize_egress_pattern};

/// The config path holding an instance's granted allowlist.
///
/// `instance_key` is the opaque `zpi1_` key from
/// `PluginInstanceScope::config_entry_key()` — the same key the instance's
/// private `config` map resolves against. One `[[plugins.entries]]` row per
/// instance carries both, so the grant and the config an operator edits are
/// never split across two rows.
#[must_use]
pub fn egress_hosts_path(instance_key: &str) -> String {
    format!("plugins.entries.{instance_key}.egress_hosts")
}

/// The exact `zeroclaw config set` invocation that makes `hosts` the instance
/// row's granted allowlist.
///
/// `config set` on a string array **replaces** the list rather than appending
/// to it, so a command that is meant to *add* a destination has to carry the
/// full resulting list. Callers building an "apply this addition" command must
/// therefore pass the union (see [`EgressDeclarationDiff::union`]), not just the
/// additions. The value is double-quoted because suffix patterns start with `*`
/// and a bare `*.example.com` would be glob-expanded by the operator's shell.
#[must_use]
pub fn egress_set_command(instance_key: &str, hosts: &[String]) -> String {
    format!(
        "zeroclaw config set {} \"{}\"",
        egress_hosts_path(instance_key),
        hosts.join(",")
    )
}

/// The legacy `[[plugins.entries]]` row an instance's grant is stranded on, if
/// any.
///
/// [`egress_set_command`] addresses the canonical `zpi1_` row, and dotted
/// `plugins.entries.<key>.…` paths resolve through natural-key lookup, which
/// only matches rows **already present in live config**. So on a pre-typed-config
/// install, where the row is still keyed by the package name, that command
/// targets a row that does not exist and fails with `Unknown property` instead
/// of writing the grant. The row has to be renamed first.
///
/// Returns `Some(row_name)` only when the canonical row is absent *and* one of
/// `legacy_candidates` is present, which is exactly the state that needs the
/// rename step printed before the grant command.
///
/// `legacy_candidates` is the set of names a pre-typed-config row could carry
/// for this instance: the package name, and the binding when a future
/// alias-aware key path makes the two differ. Every key derived today comes
/// from the default tool binding, whose binding string *is* the package name,
/// so callers pass one candidate and get the same answer.
///
/// `None` covers both "the canonical row is present" (the command resolves) and
/// "no row exists at all" (the command fails, but renaming nothing would not
/// help). Only the first is a state the printed grant command can act on.
#[must_use]
pub fn stranded_legacy_grant_row(
    instance_key: &str,
    legacy_candidates: &[String],
    row_names: &[String],
) -> Option<String> {
    if row_names.iter().any(|name| name == instance_key) {
        return None;
    }
    legacy_candidates
        .iter()
        .find(|candidate| row_names.iter().any(|name| name == *candidate))
        .cloned()
}

/// Canonicalize a declared or granted list for comparison and for seeding.
///
/// Uses the same grammar the manifest and the config are validated against, so
/// "declared" and "granted" are compared in one vocabulary and a seeded entry
/// is written in exactly the form `Config::validate` accepts. Sorted and
/// deduplicated, mirroring `net_guard::normalize_egress_patterns`, so output is
/// deterministic regardless of authoring order.
///
/// An entry that fails the grammar is kept verbatim (trimmed) rather than
/// dropped: this runs against config an operator may have hand-edited, and
/// silently hiding an invalid grant would misreport what is on disk. Invalid
/// entries are rejected at config load, not here.
#[must_use]
pub fn canonical_hosts(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = raw
        .iter()
        .map(|h| normalize_egress_pattern(h).unwrap_or_else(|_| h.trim().to_string()))
        .filter(|h| !h.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Declaration-versus-grant comparison for one plugin instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressDeclarationDiff {
    /// Canonical declared destinations (what the manifest asks for).
    pub declared: Vec<String>,
    /// Canonical granted destinations (what the entry actually permits).
    pub granted: Vec<String>,
    /// Declared destinations **no grant covers** — denials waiting to happen.
    /// Wildcard-containment aware: a declared host a granted `*.suffix` reaches
    /// is not listed here, because the runtime would already permit it.
    pub declared_not_granted: Vec<String>,
    /// Granted destinations **the declaration does not cover** — left in place;
    /// informational only. A grant already covered by the declaration is within
    /// it, not beyond it, so it is not listed here.
    pub granted_not_declared: Vec<String>,
}

impl EgressDeclarationDiff {
    /// Nothing to tell the operator about.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declared_not_granted.is_empty() && self.granted_not_declared.is_empty()
    }

    /// The allowlist that grants every declared destination **without revoking
    /// anything already granted**. This is the value the printed apply-command
    /// carries: `config set` replaces the list, and an upgrade prompt that
    /// silently dropped an operator-authored host (a self-hosted Gitea, a LAN
    /// Nextcloud) would be worse than the gap it is closing.
    #[must_use]
    pub fn union(&self) -> Vec<String> {
        let mut out = self.granted.clone();
        out.extend(self.declared.iter().cloned());
        out.sort();
        out.dedup();
        out
    }
}

/// Compare a manifest declaration against an entry's granted allowlist.
///
/// Comparison is by **reachability**, not set membership, so the diagnostic
/// agrees with what the runtime actually enforces. The runtime resolves a
/// destination through wildcard containment
/// ([`net_guard::egress_pattern_contains`][c]) — a granted `*.example.com`
/// reaches `api.example.com` — so a declared host a grant already covers is not
/// a gap. Plain set membership would report it as "declared but not granted"
/// and tell the operator to grant a destination the runtime already permits,
/// which is exactly the false positive this comparison must not produce.
///
/// Both sides use the same predicate, in the covering direction each needs:
/// - `declared_not_granted`: a declared destination **no grant covers** — the
///   actionable gap, a denial waiting to happen. This mirrors runtime
///   reachability exactly.
/// - `granted_not_declared`: a granted destination **the declaration does not
///   cover** — informational only. A grant the declaration already covers is
///   *within* the declaration (an operator who narrowed a declared
///   `*.example.com` to one subdomain has not granted "beyond" it), so only
///   genuinely broader or unrelated grants — a wider `*.example.com`, or the
///   operator's own self-hosted destination — are surfaced.
///
/// Canonicalization still collapses order and duplication first, and the
/// grammar keeps `*.example.com` and its apex `example.com` distinct: a suffix
/// grant never covers its apex, so a declared apex stays a gap.
///
/// [c]: zeroclaw_infra::net_guard::egress_pattern_contains
#[must_use]
pub fn diff_declaration(declared: &[String], granted: &[String]) -> EgressDeclarationDiff {
    let declared = canonical_hosts(declared);
    let granted = canonical_hosts(granted);
    let declared_not_granted: Vec<String> = declared
        .iter()
        .filter(|d| !granted.iter().any(|g| egress_pattern_contains(g, d)))
        .cloned()
        .collect();
    let granted_not_declared: Vec<String> = granted
        .iter()
        .filter(|g| !declared.iter().any(|d| egress_pattern_contains(d, g)))
        .cloned()
        .collect();
    EgressDeclarationDiff {
        declared,
        granted,
        declared_not_granted,
        granted_not_declared,
    }
}

/// Should the upgrade diff be reported at all?
///
/// A manifest that declares nothing produces no diff, even when the entry
/// grants destinations. Those grants are the second, first-class grant
/// path — operator-authored, for plugins whose destination *is* instance
/// configuration (a self-hosted Gitea, a LAN Nextcloud) that no author could
/// have declared. Reporting them as "no longer declared" on every reinstall
/// would train operators to ignore the ceremony.
#[must_use]
pub fn should_report_diff(diff: &EgressDeclarationDiff) -> bool {
    !diff.declared.is_empty() && !diff.is_empty()
}

/// Split a grant list into the entries the runtime will accept and the ones it
/// will reject, keeping the rejected ones verbatim so they can be named.
///
/// [`canonical_hosts`] deliberately preserves grammar-invalid entries so a
/// diff never hides what is on disk. But an invalid entry must not take part
/// in coverage: `egress_pattern_contains` trusts its inputs, so a rejected
/// `*.com` would "cover" `api.com`. And it must not be carried into a printed
/// `config set`, because the runtime's `EgressPolicy::new` rejects the
/// **whole** allowlist on one bad entry and the instance is then denied
/// everything. `Config::load_or_init` warns and continues on validation
/// failure, so this state is reachable in production, not only in a
/// hand-edited file that never loaded.
#[must_use]
pub fn partition_valid_hosts(raw: &[String]) -> (Vec<String>, Vec<String>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for entry in raw {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        match normalize_egress_pattern(trimmed) {
            Ok(canonical) => valid.push(canonical),
            Err(_) => invalid.push(trimmed.to_string()),
        }
    }
    valid.sort();
    valid.dedup();
    invalid.sort();
    invalid.dedup();
    (valid, invalid)
}

/// Where one instance's egress grant lives, and whether the runtime honors it.
///
/// This is the distinction the gap diagnostic has to keep straight. The runtime
/// resolves an instance's allowlist by its canonical `zpi1_` key and nothing
/// else, so a grant an operator authored on a pre-typed-config row (keyed by
/// the package name) is **not in effect** — the plugin has no network reach —
/// even though it is exactly the list the operator wants carried forward. Two
/// questions, two answers:
///
/// - *What does the runtime enforce?* decides whether there is a gap and
///   whether a migration is needed. For a stranded row the answer is "nothing".
/// - *What has the operator authored?* decides what a printed command must
///   carry, because `config set` replaces the list and must not revoke a host
///   the operator wrote themselves.
///
/// Collapsing the two into one list is how both prior defects happened: read
/// the enforced (empty) grant for both and the printed command drops the
/// operator's hosts; read the authored grant for both and a row that already
/// covers the declaration is reported as healthy while every request is still
/// denied. The variants make the split explicit so a caller cannot conflate
/// them by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressGrantState {
    /// The grant the runtime reads: the canonical row's allowlist, or empty
    /// when no row exists. Enforcement and authorship agree here.
    Enforced { granted: Vec<String> },
    /// The canonical row is absent and the operator's grant sits on a legacy
    /// package-name row the runtime does not read. Nothing is enforced until
    /// the row is renamed; `authored` is what the rename brings into effect
    /// and what any grant command must carry forward.
    Stranded {
        legacy_row: String,
        authored: Vec<String>,
    },
}

/// Resolve where an instance's grant lives from the rows present in config.
///
/// `granted_on` reads a row's allowlist by name (the caller's
/// `PluginsConfig::entry_egress`); passing it in keeps this module free of the
/// config types and lets the decision be tested against a plain lookup.
#[must_use]
pub fn resolve_grant_state(
    instance_key: &str,
    legacy_candidates: &[String],
    row_names: &[String],
    granted_on: impl Fn(&str) -> Vec<String>,
) -> EgressGrantState {
    match stranded_legacy_grant_row(instance_key, legacy_candidates, row_names) {
        Some(legacy_row) => {
            let authored = granted_on(&legacy_row);
            EgressGrantState::Stranded {
                legacy_row,
                authored,
            }
        }
        None => EgressGrantState::Enforced {
            granted: granted_on(instance_key),
        },
    }
}

/// What `plugin list` has to tell the operator about one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressGapPlan {
    /// Every declared destination is enforced: nothing to report.
    Nothing,
    /// Declared destinations the runtime denies, plus the one command that
    /// grants them without revoking anything already granted. `invalid` names
    /// granted entries the runtime rejects; they are excluded from `command`,
    /// which therefore doubles as the repair, since one rejected entry makes
    /// the runtime refuse the whole allowlist.
    Grant {
        missing: Vec<String>,
        invalid: Vec<String>,
        command: String,
    },
    /// The grant is stranded on a legacy row, so the rename is always required:
    /// the runtime enforces nothing until it happens. `missing` is what the
    /// declaration still lacks *after* the rename brings the authored grant
    /// into effect, `invalid` names authored entries the runtime would reject
    /// once it does, and `grant` is the command that closes both. It is `None`
    /// only when the authored grant already covers the declaration and every
    /// entry is one the runtime accepts, because then the rename alone
    /// restores reach and an extra `config set` would only risk replacing a
    /// list the operator already has right.
    Migrate {
        legacy_row: String,
        missing: Vec<String>,
        invalid: Vec<String>,
        grant: Option<String>,
    },
}

/// Decide what to report for one instance from its declaration and grant state.
///
/// Pure: the caller renders the plan through Fluent. Keeping the decision here
/// means the "is migration needed?" rule is a unit-testable function rather
/// than control flow interleaved with string formatting.
#[must_use]
pub fn plan_egress_gap(
    instance_key: &str,
    declared: &[String],
    state: &EgressGrantState,
) -> EgressGapPlan {
    match state {
        EgressGrantState::Enforced { granted } => {
            // Only entries the runtime accepts take part in coverage, and only
            // they are carried into the command; a rejected entry is named
            // and forces a repair even when the declaration is covered.
            let (valid, invalid) = partition_valid_hosts(granted);
            let diff = diff_declaration(declared, &valid);
            if diff.declared_not_granted.is_empty() && invalid.is_empty() {
                return EgressGapPlan::Nothing;
            }
            EgressGapPlan::Grant {
                command: egress_set_command(instance_key, &diff.union()),
                missing: diff.declared_not_granted,
                invalid,
            }
        }
        EgressGrantState::Stranded {
            legacy_row,
            authored,
        } => {
            // Compare against what the rename WILL enforce, not against the
            // (empty) grant the runtime enforces today: the rename is planned
            // unconditionally, so the only open question is whether a grant
            // step has to follow it. It must when a declared destination is
            // still uncovered, and it must when the authored list holds an
            // entry the runtime rejects, because the rename alone would then
            // bring an allowlist into effect that the runtime refuses whole.
            let (valid, invalid) = partition_valid_hosts(authored);
            let diff = diff_declaration(declared, &valid);
            let grant = (!diff.declared_not_granted.is_empty() || !invalid.is_empty())
                .then(|| egress_set_command(instance_key, &diff.union()));
            EgressGapPlan::Migrate {
                legacy_row: legacy_row.clone(),
                missing: diff.declared_not_granted,
                invalid,
                grant,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn canonical_hosts_sorts_dedups_and_keeps_invalid_entries_visible() {
        // Sorted + deduplicated so seeded output and diffs are deterministic.
        assert_eq!(
            canonical_hosts(&v(&["b.example.com", "a.example.com", "b.example.com"])),
            v(&["a.example.com", "b.example.com"])
        );
        // Whitespace is normalized away, empties vanish.
        assert_eq!(
            canonical_hosts(&v(&["  a.example.com  ", ""])),
            v(&["a.example.com"])
        );
        // A hand-edited entry that fails the grammar is still surfaced: the
        // operator has to be able to see what is actually on disk.
        assert_eq!(
            canonical_hosts(&v(&["NOT-LOWERCASE.example.com"])),
            v(&["NOT-LOWERCASE.example.com"])
        );
    }

    #[test]
    fn diff_is_empty_when_declaration_matches_grant_in_any_order() {
        let diff = diff_declaration(
            &v(&["b.example.com", "a.example.com"]),
            &v(&["a.example.com", "b.example.com", "a.example.com"]),
        );
        assert!(diff.is_empty(), "same set, different order/dupes: {diff:?}");
        assert!(!should_report_diff(&diff));
    }

    #[test]
    fn diff_splits_declared_not_granted_from_granted_not_declared() {
        let diff = diff_declaration(
            &v(&["api.example.com", "api2.example.com"]),
            &v(&["api.example.com", "gitea.internal.example.com"]),
        );
        assert_eq!(diff.declared_not_granted, v(&["api2.example.com"]));
        assert_eq!(
            diff.granted_not_declared,
            v(&["gitea.internal.example.com"])
        );
        assert!(should_report_diff(&diff));
    }

    #[test]
    fn union_adds_the_declaration_without_revoking_an_operator_authored_grant() {
        // The apply-command's value: `config set` REPLACES the list, so the
        // command must carry the operator's own grant through.
        let diff = diff_declaration(
            &v(&["api.example.com", "api2.example.com"]),
            &v(&["api.example.com", "gitea.internal.example.com"]),
        );
        assert_eq!(
            diff.union(),
            v(&[
                "api.example.com",
                "api2.example.com",
                "gitea.internal.example.com"
            ])
        );
    }

    #[test]
    fn a_manifest_declaring_nothing_never_reports_operator_authored_grants() {
        // The second grant path: the author cannot know a self-hosted
        // destination, so the operator authors it. Silence, not a diff.
        let diff = diff_declaration(&[], &v(&["gitea.internal.example.com"]));
        assert_eq!(
            diff.granted_not_declared,
            v(&["gitea.internal.example.com"])
        );
        assert!(
            !should_report_diff(&diff),
            "an empty declaration must not report the operator's own grants"
        );
    }

    #[test]
    fn set_command_targets_the_instance_row_and_quotes_the_value() {
        // The path is keyed by the opaque `zpi1_` instance key, not the
        // package name: that is the row `entry_config` resolves against, so
        // config and grant stay on one row.
        let key = "zpi1_WyJ3ZWF0aGVyLXRvb2wiLCJ0b29sIiwid2VhdGhlci10b29sIl0";
        let cmd = egress_set_command(key, &v(&["api.example.com", "*.cdn.example.com"]));
        assert_eq!(
            cmd,
            format!(
                "zeroclaw config set plugins.entries.{key}.egress_hosts \"api.example.com,*.cdn.example.com\""
            )
        );
        assert!(
            !cmd.contains("plugins.entries.weather-tool."),
            "the command must not address a package-name-keyed row: {cmd}"
        );
        assert!(
            cmd.contains('"'),
            "an unquoted '*.suffix' would be glob-expanded by the operator's shell"
        );
    }

    #[test]
    fn a_package_name_row_strands_the_grant_only_while_the_canonical_row_is_absent() {
        let key = "zpi1_WyJ3ZWF0aGVyLXRvb2wiLCJ0b29sIiwid2VhdGhlci10b29sIl0";
        let legacy = v(&["weather-tool"]);

        // Pre-typed-config install: the row is still package-name keyed, so the
        // printed `config set ...<key>.egress_hosts` command cannot resolve.
        assert_eq!(
            stranded_legacy_grant_row(key, &legacy, &v(&["weather-tool"])),
            Some("weather-tool".to_string())
        );

        // The canonical row is what the command addresses. Once it exists the
        // command resolves, even if the stale row was left behind.
        assert_eq!(
            stranded_legacy_grant_row(key, &legacy, &v(&[key, "weather-tool"])),
            None,
            "a present canonical row makes the grant command resolvable"
        );

        // Someone else's package-name row is not this instance's grant.
        assert_eq!(
            stranded_legacy_grant_row(key, &legacy, &v(&["other-tool"])),
            None
        );

        // No rows at all: renaming nothing would not help, so there is no
        // migration step to print.
        assert_eq!(stranded_legacy_grant_row(key, &legacy, &[]), None);
    }

    #[test]
    fn suffix_patterns_and_apex_are_distinct_destinations() {
        // The grammar treats `*.example.com` and `example.com` as different
        // entries, and containment never collapses them: a suffix grant does
        // not cover its apex, and an exact grant does not cover a suffix.
        let diff = diff_declaration(&v(&["*.example.com"]), &v(&["example.com"]));
        assert_eq!(diff.declared_not_granted, v(&["*.example.com"]));
        assert_eq!(diff.granted_not_declared, v(&["example.com"]));
    }

    #[test]
    fn a_declared_subdomain_covered_by_a_granted_wildcard_is_not_a_gap() {
        // IftekharUddin's blocker: the runtime reaches `api.example.com` through
        // a granted `*.example.com`, so the declaration-versus-grant diagnostic
        // must NOT report it as an ungranted gap — it must never tell the
        // operator to grant a destination that is already reachable.
        let diff = diff_declaration(&v(&["api.example.com"]), &v(&["*.example.com"]));
        assert!(
            diff.declared_not_granted.is_empty(),
            "a declared host a granted wildcard covers is already reachable, not a gap: {diff:?}"
        );
        // The broader grant is still surfaced informationally (left in place):
        // `*.example.com` reaches more than the declared `api.example.com`.
        assert_eq!(diff.granted_not_declared, v(&["*.example.com"]));

        // Apex is NOT covered by the suffix, so a declared apex stays an
        // actionable gap even when a `*.` of the same domain is granted.
        let apex = diff_declaration(&v(&["example.com"]), &v(&["*.example.com"]));
        assert_eq!(
            apex.declared_not_granted,
            v(&["example.com"]),
            "`*.example.com` never covers its apex `example.com`"
        );
    }

    #[test]
    fn a_grant_within_a_declared_wildcard_is_not_reported_as_beyond_the_declaration() {
        // The informational side, made symmetric with runtime containment: an
        // operator who narrowed a declared `*.example.com` to a single
        // subdomain has granted WITHIN the declaration, not beyond it, so
        // `api.example.com` is not reported as "granted, no longer declared".
        // The unmet remainder of the declared wildcard is still the actionable
        // gap.
        let diff = diff_declaration(&v(&["*.example.com"]), &v(&["api.example.com"]));
        assert!(
            diff.granted_not_declared.is_empty(),
            "a grant the declaration covers is within it, not beyond it: {diff:?}"
        );
        assert_eq!(
            diff.declared_not_granted,
            v(&["*.example.com"]),
            "the rest of the declared wildcard the narrow grant does not cover is still a gap"
        );
    }

    #[test]
    fn grant_state_separates_what_is_enforced_from_what_was_authored() {
        let key = "zpi1_WyJ3ZWF0aGVyLXRvb2wiLCJ0b29sIiwid2VhdGhlci10b29sIl0";
        let legacy = v(&["weather-tool"]);
        // Stands in for `entry_egress`: only the legacy row carries hosts.
        let lookup = |row: &str| {
            if row == "weather-tool" {
                v(&["api.example.com", "gitea.example.net"])
            } else {
                Vec::new()
            }
        };

        // Canonical row absent, legacy row present: stranded, and the
        // authored grant is carried through for the command to preserve.
        assert_eq!(
            resolve_grant_state(key, &legacy, &v(&["weather-tool"]), lookup),
            EgressGrantState::Stranded {
                legacy_row: "weather-tool".to_string(),
                authored: v(&["api.example.com", "gitea.example.net"]),
            }
        );
        // Canonical row present: what is enforced is that row's grant (here
        // nothing), never the leftover legacy row's.
        assert_eq!(
            resolve_grant_state(key, &legacy, &v(&[key, "weather-tool"]), lookup),
            EgressGrantState::Enforced {
                granted: Vec::new()
            }
        );
        // No rows at all: enforced-empty, not stranded — renaming nothing
        // would not help, and the grant command is the right next step.
        assert_eq!(
            resolve_grant_state(key, &legacy, &[], lookup),
            EgressGrantState::Enforced {
                granted: Vec::new()
            }
        );
    }

    #[test]
    fn a_stranded_grant_always_plans_the_rename_even_when_it_covers_the_declaration() {
        // The false negative this split exists to make impossible: the
        // authored grant covers the declaration, so a diff against it is
        // empty — but the runtime enforces nothing until the rename. The plan
        // must be Migrate, and with nothing left to grant, no command.
        let key = "zpi1_k";
        let state = EgressGrantState::Stranded {
            legacy_row: "weather-tool".to_string(),
            authored: v(&["api.example.com", "gitea.example.net"]),
        };
        assert_eq!(
            plan_egress_gap(key, &v(&["api.example.com"]), &state),
            EgressGapPlan::Migrate {
                legacy_row: "weather-tool".to_string(),
                missing: Vec::new(),
                invalid: Vec::new(),
                grant: None,
            }
        );
        // A wildcard that covers the declaration is the same case.
        let wild = EgressGrantState::Stranded {
            legacy_row: "weather-tool".to_string(),
            authored: v(&["*.example.com"]),
        };
        assert!(matches!(
            plan_egress_gap(key, &v(&["api.example.com"]), &wild),
            EgressGapPlan::Migrate { grant: None, .. }
        ));
        // Even with nothing declared: the operator's own grant is inert until
        // the rename, and `config set` cannot target the row until then.
        assert!(matches!(
            plan_egress_gap(key, &[], &state),
            EgressGapPlan::Migrate { grant: None, .. }
        ));
    }

    #[test]
    fn a_stranded_grant_with_an_uncovered_declaration_plans_the_rename_then_a_union_grant() {
        // The grant-loss case: the grant step must carry the operator-only
        // host forward, because `config set` replaces the list.
        let key = "zpi1_k";
        let state = EgressGrantState::Stranded {
            legacy_row: "weather-tool".to_string(),
            authored: v(&["api.example.com", "gitea.example.net"]),
        };
        let plan = plan_egress_gap(key, &v(&["api.example.com", "api2.example.com"]), &state);
        let EgressGapPlan::Migrate {
            legacy_row,
            missing,
            invalid,
            grant: Some(command),
        } = plan
        else {
            panic!("expected a migrate plan with a grant step: {plan:?}");
        };
        assert_eq!(legacy_row, "weather-tool");
        assert_eq!(missing, v(&["api2.example.com"]));
        assert!(invalid.is_empty());
        assert_eq!(
            command,
            egress_set_command(
                key,
                &v(&["api.example.com", "api2.example.com", "gitea.example.net"])
            )
        );
    }

    #[test]
    fn an_enforced_grant_plans_exactly_as_the_canonical_diagnostic_always_did() {
        let key = "zpi1_k";
        // Covered (through the wildcard): nothing to say.
        assert_eq!(
            plan_egress_gap(
                key,
                &v(&["api.example.com"]),
                &EgressGrantState::Enforced {
                    granted: v(&["*.example.com"])
                }
            ),
            EgressGapPlan::Nothing
        );
        // A gap: the union command against the canonical key.
        assert_eq!(
            plan_egress_gap(
                key,
                &v(&["api.example.com", "api2.example.com"]),
                &EgressGrantState::Enforced {
                    granted: v(&["api.example.com"])
                }
            ),
            EgressGapPlan::Grant {
                missing: v(&["api2.example.com"]),
                invalid: Vec::new(),
                command: egress_set_command(key, &v(&["api.example.com", "api2.example.com"])),
            }
        );
        // No row at all reads as enforced-empty: every declared host is a gap.
        assert!(matches!(
            plan_egress_gap(
                key,
                &v(&["api.example.com"]),
                &EgressGrantState::Enforced {
                    granted: Vec::new()
                }
            ),
            EgressGapPlan::Grant { .. }
        ));
    }

    #[test]
    fn partition_keeps_rejected_entries_out_of_the_valid_list_but_names_them() {
        let (valid, invalid) = partition_valid_hosts(&v(&[
            "api.example.com",
            "*.com",
            " api.example.com ",
            "",
            "*.example.com",
        ]));
        assert_eq!(valid, v(&["*.example.com", "api.example.com"]));
        // `*.com` wildcards a single label, which the grammar rejects; it is
        // named verbatim rather than dropped, so the operator can find it.
        assert_eq!(invalid, v(&["*.com"]));
    }

    #[test]
    fn a_rejected_authored_entry_never_covers_and_is_kept_out_of_the_command() {
        // The containment relation trusts its inputs, so a rejected `*.com`
        // would "cover" `api.com` and a naive planner would print the rename
        // alone. After that rename the runtime would build the policy from
        // the row, reject `*.com`, and deny every request. The plan must name
        // the entry, keep the rename, and print a grant that omits it.
        let key = "zpi1_k";
        let state = EgressGrantState::Stranded {
            legacy_row: "weather-tool".to_string(),
            authored: v(&["*.com"]),
        };
        let plan = plan_egress_gap(key, &v(&["api.com"]), &state);
        let EgressGapPlan::Migrate {
            missing,
            invalid,
            grant: Some(command),
            ..
        } = plan
        else {
            panic!("a rejected entry must force the grant step: {plan:?}");
        };
        assert_eq!(missing, v(&["api.com"]), "`*.com` covers nothing");
        assert_eq!(invalid, v(&["*.com"]));
        assert_eq!(command, egress_set_command(key, &v(&["api.com"])));
        assert!(
            !command.contains("*.com"),
            "the repair must not carry the rejected entry forward: {command}"
        );
    }

    #[test]
    fn a_canonical_row_with_a_rejected_entry_is_reported_as_a_repair_even_when_covered() {
        // Enforced path: the declaration is covered by a valid entry, but the
        // row also holds `*.com`, so the runtime refuses the whole allowlist.
        // Silence here would report a fully denied instance as healthy.
        let key = "zpi1_k";
        let state = EgressGrantState::Enforced {
            granted: v(&["api.com", "*.com"]),
        };
        assert_eq!(
            plan_egress_gap(key, &v(&["api.com"]), &state),
            EgressGapPlan::Grant {
                missing: Vec::new(),
                invalid: v(&["*.com"]),
                command: egress_set_command(key, &v(&["api.com"])),
            }
        );
    }
}
