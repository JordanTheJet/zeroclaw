//! The principal envelope: authority for work that runs after its admitting
//! connection is gone.
//!
//! A cron agent job, a SOP run, a headless driver, a delegation target, or a
//! channel-originated turn executes on a scheduler tick or a driver task, not
//! on the connection that admitted it. Copying the submitter's grants onto
//! the job would freeze them: a later narrowing would never apply. Carrying
//! nothing would let the job run under the agent's full policy: a submitter
//! with a tool ceiling would escape it at the next tick.
//!
//! The envelope carries the submitter's non-secret identity and the grants
//! they held at admission as a ceiling. At execution,
//! [`PrincipalEnvelope::resolve_for_execution`] re-resolves the identity
//! against the policy in force now and returns the intersection of the
//! fresh grants with the ceiling: a narrowing always applies, a widening
//! never exceeds what the submitter held when they submitted, and an
//! identity that no longer resolves refuses the run.
//!
//! The envelope never carries a bearer. For native pairing it carries the
//! token hash, which is enough to observe revocation, as the connection
//! binding does.

use serde::{Deserialize, Serialize};
use zeroclaw_api::grants::{ResolvedGrants, WILDCARD};
use zeroclaw_api::principal::{
    AgentAlias, AuthMethod, AuthenticatedIdentity, IdentitySubject, PrincipalId,
};

use crate::rpc::auth::{AuthDenied, ConnectionAuth, RpcInboundAuth};

/// The authority a deferred effect carries.
#[derive(Clone)]
pub struct PrincipalEnvelope {
    identity: AuthenticatedIdentity,
    submitted_by: PrincipalId,
    stamped_generation: u64,
    ceiling: ResolvedGrants,
    native_token_hash: Option<String>,
}

impl std::fmt::Debug for PrincipalEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalEnvelope")
            .field("submitted_by", &self.submitted_by)
            .field("stamped_generation", &self.stamped_generation)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PrincipalEnvelope {
    /// Stamp the envelope from the admitting connection's binding. Call at
    /// admission, with the grants the gate stamped, never later.
    pub fn stamp(conn: &ConnectionAuth) -> Self {
        Self {
            identity: conn.identity.clone(),
            submitted_by: conn.principal.id.clone(),
            stamped_generation: conn.generation,
            ceiling: conn.grants.clone(),
            native_token_hash: conn.native_token_hash.clone(),
        }
    }

    /// Who submitted the work.
    pub fn submitted_by(&self) -> &PrincipalId {
        &self.submitted_by
    }

    /// The grants held at admission. Execution never exceeds them.
    pub fn ceiling(&self) -> &ResolvedGrants {
        &self.ceiling
    }

    /// The authorization generation the ceiling was stamped under.
    pub fn stamped_generation(&self) -> u64 {
        self.stamped_generation
    }

    /// At execution: re-resolve the identity now and intersect with the
    /// ceiling. Refuses when the credential has expired, its native pairing
    /// was revoked, or the identity no longer resolves to any grants.
    pub fn resolve_for_execution(
        &self,
        inbound: &RpcInboundAuth,
    ) -> Result<ResolvedGrants, AuthDenied> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(expires_at) = self.identity.expires_at
            && expires_at <= now
        {
            return Err(AuthDenied::auth_required(
                crate::i18n::get_required_cli_string("rpc-auth-credential-expired"),
            ));
        }
        if let Some(revalidate_by) = self.identity.revalidate_by
            && revalidate_by <= now
        {
            return Err(AuthDenied::auth_required(
                crate::i18n::get_required_cli_string("rpc-auth-revalidation-due"),
            ));
        }
        if let Some(hash) = self.native_token_hash.as_deref()
            && !inbound.pairing().token_hash_is_paired(hash)
        {
            return Err(AuthDenied::auth_required(
                crate::i18n::get_required_cli_string("rpc-auth-pairing-revoked"),
            ));
        }
        let resolved = inbound
            .resolve(&self.identity)
            .map_err(AuthDenied::from_deny_reason)?;
        Ok(intersect_grants(&resolved.grants, &self.ceiling))
    }

    /// The serializable form for a job or run row. Claim values travel with
    /// it because OIDC profile mapping reads them at re-resolution; the row
    /// is operator-private data and the values are the same ones the live
    /// connection already holds.
    pub fn to_persisted(&self) -> PersistedEnvelope {
        PersistedEnvelope {
            subject: PersistedSubject::from_identity(&self.identity.subject),
            method: self.identity.method,
            provider_alias: self.identity.provider_alias.clone(),
            claims: self.identity.claims.clone(),
            mfa_verified: self.identity.mfa_verified,
            expires_at: self.identity.expires_at,
            revalidate_by: self.identity.revalidate_by,
            submitted_by: self.submitted_by.clone(),
            stamped_generation: self.stamped_generation,
            ceiling: self.ceiling.clone(),
            native_token_hash: self.native_token_hash.clone(),
        }
    }

    /// Rebuild from a persisted row. A subject kind this build does not know
    /// fails closed: the row cannot be re-resolved, so the work must not run.
    pub fn from_persisted(persisted: PersistedEnvelope) -> Result<Self, EnvelopeError> {
        let subject = persisted.subject.into_identity()?;
        let mut identity = AuthenticatedIdentity::new(subject, persisted.method)
            .with_claims(persisted.claims)
            .with_mfa_verified(persisted.mfa_verified);
        if let Some(alias) = persisted.provider_alias {
            identity = identity.with_provider_alias(alias);
        }
        if let Some(expires_at) = persisted.expires_at {
            identity = identity.with_expires_at(expires_at);
        }
        if let Some(revalidate_by) = persisted.revalidate_by {
            identity = identity.with_revalidate_by(revalidate_by);
        }
        Ok(Self {
            identity,
            submitted_by: persisted.submitted_by,
            stamped_generation: persisted.stamped_generation,
            ceiling: persisted.ceiling,
            native_token_hash: persisted.native_token_hash,
        })
    }
}

/// Why a persisted envelope could not be rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The subject kind was written by a build this one does not understand.
    UnknownSubject(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSubject(kind) => write!(f, "unknown principal subject kind {kind:?}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// The row form. Field names are the wire contract; add fields with
/// `#[serde(default)]` only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedEnvelope {
    pub subject: PersistedSubject,
    pub method: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_alias: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub claims: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub mfa_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidate_by: Option<u64>,
    pub submitted_by: PrincipalId,
    pub stamped_generation: u64,
    pub ceiling: ResolvedGrants,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_token_hash: Option<String>,
}

/// A serializable mirror of [`IdentitySubject`]. The api enum is
/// `non_exhaustive` and not serde; this mirror pins the row format and
/// refuses kinds it does not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PersistedSubject {
    SharedOperator,
    Oidc {
        issuer: String,
        subject: String,
    },
    Service {
        issuer: String,
        client_id: String,
    },
    Roster {
        principal_id: String,
    },
    /// Written by a newer build; refused on rebuild.
    #[serde(other)]
    Unknown,
}

impl PersistedSubject {
    fn from_identity(subject: &IdentitySubject) -> Self {
        match subject {
            IdentitySubject::SharedOperator => Self::SharedOperator,
            IdentitySubject::Oidc { issuer, subject } => Self::Oidc {
                issuer: issuer.clone(),
                subject: subject.clone(),
            },
            IdentitySubject::Service { issuer, client_id } => Self::Service {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
            },
            IdentitySubject::Roster { principal_id } => Self::Roster {
                principal_id: principal_id.clone(),
            },
            // A subject kind added after this mirror: persist it as unknown so
            // the rebuild refuses rather than guesses.
            _ => Self::Unknown,
        }
    }

    fn into_identity(self) -> Result<IdentitySubject, EnvelopeError> {
        Ok(match self {
            Self::SharedOperator => IdentitySubject::SharedOperator,
            Self::Oidc { issuer, subject } => IdentitySubject::Oidc { issuer, subject },
            Self::Service { issuer, client_id } => IdentitySubject::Service { issuer, client_id },
            Self::Roster { principal_id } => IdentitySubject::Roster { principal_id },
            Self::Unknown => return Err(EnvelopeError::UnknownSubject("unknown".into())),
        })
    }
}

/// The intersection of two grant sets: what both allow.
///
/// `admin` on one side means "everything on this side", so the result is
/// the other side's explicit sets; `admin` on both stays `admin`. A
/// [`WILDCARD`] selector on one side yields the other side's list. Resource
/// verbs intersect per resource.
pub fn intersect_grants(fresh: &ResolvedGrants, ceiling: &ResolvedGrants) -> ResolvedGrants {
    if fresh.admin && ceiling.admin {
        return ResolvedGrants::all();
    }
    let mut out = ResolvedGrants::none();
    out.admin = false;

    out.allowed_agents = intersect_selectors(
        fresh.admin,
        &fresh
            .allowed_agents
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect::<Vec<_>>(),
        ceiling.admin,
        &ceiling
            .allowed_agents
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .map(AgentAlias)
    .collect();
    out.allowed_tools = intersect_selectors(
        fresh.admin,
        &fresh.allowed_tools,
        ceiling.admin,
        &ceiling.allowed_tools,
    );
    // Config paths are prefix selectors, so an exact intersection is the only
    // safe one: keep a path only if BOTH sides grant it verbatim, or one side
    // is unrestricted.
    out.config_write_paths = intersect_selectors(
        fresh.admin,
        &fresh.config_write_paths,
        ceiling.admin,
        &ceiling.config_write_paths,
    );

    out.resources = match (fresh.admin, ceiling.admin) {
        (true, false) => ceiling.resources.clone(),
        (false, true) => fresh.resources.clone(),
        _ => fresh
            .resources
            .iter()
            .filter_map(|(resource, verbs)| {
                let common: std::collections::BTreeSet<_> = ceiling
                    .resources
                    .get(resource)
                    .map(|c| verbs.intersection(c).copied().collect())
                    .unwrap_or_default();
                (!common.is_empty()).then_some((*resource, common))
            })
            .collect(),
    };
    out
}

fn intersect_selectors(
    fresh_admin: bool,
    fresh: &[String],
    ceiling_admin: bool,
    ceiling: &[String],
) -> Vec<String> {
    let fresh_all = fresh_admin || fresh.iter().any(|s| s == WILDCARD);
    let ceiling_all = ceiling_admin || ceiling.iter().any(|s| s == WILDCARD);
    match (fresh_all, ceiling_all) {
        (true, true) => vec![WILDCARD.to_owned()],
        (true, false) => ceiling.to_vec(),
        (false, true) => fresh.to_vec(),
        (false, false) => fresh
            .iter()
            .filter(|s| ceiling.contains(s))
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::pairing::{PairingCodePolicy, PairingGuard};
    use zeroclaw_config::schema::{Config, PermissionProfileConfig, UserConfig};

    use crate::rpc::transport::TransportKind;
    use crate::security::auth_provider::Credential;

    const ALICE_UID: u32 = 4343;

    fn config_with_alice(agents: &[&str], tools: &[&str]) -> Config {
        let mut config = Config::default();
        // The selector validation refuses a profile that names an agent the
        // config does not define, and an invalid policy compiles to deny-all.
        for alias in ["alpha", "beta"] {
            config.agents.insert(
                alias.to_string(),
                zeroclaw_config::schema::AliasedAgentConfig::default(),
            );
        }
        config.permission_profiles.insert(
            "submitter".into(),
            PermissionProfileConfig {
                grants: std::collections::HashMap::from([(
                    Resource::Cron,
                    vec![Verb::Create, Verb::Read],
                )]),
                allowed_agents: agents.iter().map(|a| (*a).to_string()).collect(),
                allowed_tools: tools.iter().map(|t| (*t).to_string()).collect(),
                ..PermissionProfileConfig::default()
            },
        );
        config.users.insert(
            "alice".into(),
            UserConfig {
                principal_id: None,
                uid: Some(ALICE_UID),
                permission_profiles: vec!["submitter".into()],
            },
        );
        config
    }

    fn inbound_for(config: &Config) -> RpcInboundAuth {
        RpcInboundAuth::from_config(
            config,
            Arc::new(PairingGuard::new(true, &[], PairingCodePolicy::default())),
        )
        .expect("valid policy")
    }

    async fn alice_on(inbound: &RpcInboundAuth) -> ConnectionAuth {
        inbound
            .authenticate(
                TransportKind::Local,
                Credential::Peercred { uid: ALICE_UID },
                None,
                None,
            )
            .await
            .expect("alice is on the roster")
    }

    #[tokio::test]
    async fn a_tick_after_the_submitter_is_narrowed_sees_the_narrowing() {
        let inbound = inbound_for(&config_with_alice(&["alpha"], &["file_read"]));
        let conn = alice_on(&inbound).await;
        let envelope = PrincipalEnvelope::stamp(&conn);
        assert!(envelope.ceiling().may_use_tool("file_read"));

        inbound
            .refresh_from_config(&config_with_alice(&["alpha"], &[]))
            .expect("narrowed policy compiles");

        let at_tick = envelope
            .resolve_for_execution(&inbound)
            .expect("identity still resolves");
        assert!(
            !at_tick.may_use_tool("file_read"),
            "the narrowing must apply at the tick"
        );
        assert!(at_tick.may_use_agent("alpha"));
    }

    #[tokio::test]
    async fn a_widening_after_submission_never_exceeds_the_ceiling() {
        let inbound = inbound_for(&config_with_alice(&["alpha"], &["file_read"]));
        let conn = alice_on(&inbound).await;
        let envelope = PrincipalEnvelope::stamp(&conn);

        inbound
            .refresh_from_config(&config_with_alice(
                &["alpha", "beta"],
                &["file_read", "file_write"],
            ))
            .expect("widened policy compiles");

        let at_tick = envelope.resolve_for_execution(&inbound).expect("resolves");
        assert!(
            !at_tick.may_use_tool("file_write"),
            "the ceiling caps a later widening"
        );
        assert!(!at_tick.may_use_agent("beta"));
        assert!(at_tick.may_use_tool("file_read"));
    }

    #[tokio::test]
    async fn a_submitter_removed_from_the_roster_cannot_execute() {
        let inbound = inbound_for(&config_with_alice(&["alpha"], &["file_read"]));
        let conn = alice_on(&inbound).await;
        let envelope = PrincipalEnvelope::stamp(&conn);

        let mut without_alice = config_with_alice(&["alpha"], &["file_read"]);
        without_alice.users.clear();
        inbound
            .refresh_from_config(&without_alice)
            .expect("policy without alice compiles");

        assert!(envelope.resolve_for_execution(&inbound).is_err());
    }

    #[tokio::test]
    async fn the_envelope_round_trips_through_its_persisted_form() {
        let inbound = inbound_for(&config_with_alice(&["alpha"], &["file_read"]));
        let conn = alice_on(&inbound).await;
        let envelope = PrincipalEnvelope::stamp(&conn);
        let json = serde_json::to_string(&envelope.to_persisted()).expect("serializes");
        let back: PersistedEnvelope = serde_json::from_str(&json).expect("deserializes");
        let rebuilt = PrincipalEnvelope::from_persisted(back).expect("rebuilds");
        assert_eq!(rebuilt.submitted_by(), envelope.submitted_by());
        assert_eq!(rebuilt.stamped_generation(), envelope.stamped_generation());
        let at_tick = rebuilt.resolve_for_execution(&inbound).expect("resolves");
        assert!(at_tick.may_use_tool("file_read"));
    }

    #[test]
    fn an_unknown_subject_kind_fails_closed() {
        let json = serde_json::json!({
            "subject": {"kind": "hardware_token", "serial": "x"},
            "method": "oidc",
            "submitted_by": "user:someone",
            "stamped_generation": 3,
            "ceiling": ResolvedGrants::none(),
        });
        let persisted: PersistedEnvelope = serde_json::from_value(json).expect("parses");
        assert_eq!(
            PrincipalEnvelope::from_persisted(persisted).unwrap_err(),
            EnvelopeError::UnknownSubject("unknown".into())
        );
    }

    #[test]
    fn intersection_keeps_only_what_both_allow() {
        let mut fresh = ResolvedGrants::none();
        fresh.allowed_agents = vec![AgentAlias("alpha".into()), AgentAlias("beta".into())];
        fresh.allowed_tools = vec![WILDCARD.into()];
        fresh.resources.insert(
            Resource::Sessions,
            [Verb::Read, Verb::Update].into_iter().collect(),
        );
        let mut ceiling = ResolvedGrants::none();
        ceiling.allowed_agents = vec![AgentAlias("beta".into())];
        ceiling.allowed_tools = vec!["file_read".into()];
        ceiling
            .resources
            .insert(Resource::Sessions, [Verb::Read].into_iter().collect());
        ceiling
            .resources
            .insert(Resource::Cron, [Verb::Read].into_iter().collect());

        let out = intersect_grants(&fresh, &ceiling);
        assert!(!out.admin);
        assert!(out.may_use_agent("beta") && !out.may_use_agent("alpha"));
        assert!(out.may_use_tool("file_read") && !out.may_use_tool("shell"));
        assert!(out.permits(Resource::Sessions, Verb::Read));
        assert!(!out.permits(Resource::Sessions, Verb::Update));
        assert!(
            !out.permits(Resource::Cron, Verb::Read),
            "absent on the fresh side"
        );
    }

    #[test]
    fn admin_on_one_side_yields_the_other_side() {
        let mut fresh = ResolvedGrants::none();
        fresh.allowed_tools = vec!["file_read".into()];
        let out = intersect_grants(&fresh, &ResolvedGrants::all());
        assert!(!out.admin);
        assert!(out.may_use_tool("file_read") && !out.may_use_tool("shell"));
        let both = intersect_grants(&ResolvedGrants::all(), &ResolvedGrants::all());
        assert!(both.admin);
    }
}
