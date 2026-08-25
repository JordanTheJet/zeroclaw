//! Daemon-owned issued-certificate ledger.
//!
//! The single canonical record of which device holds which client certificate
//! (device id + SHA-256 fingerprint + validity + status), the join key back to
//! the gateway pairing `devices.db` (`token_hash`), and the choke point that
//! writes the append-only certificate audit trail. The daemon owns the CA, so it
//! owns this ledger; when the gateway is present it READS the ledger (one store,
//! two readers - no third device store, per AGENTS.md no-duplicate-state).
//!
//! Issuance is a two-phase commit across those two stores: the row lands in a
//! `pending` state that NO reader treats as a credential, and is promoted to
//! its final status only once the completion audit event is durable. A row this
//! ledger vouches for therefore always has a matching completion event, and
//! every failure mode - including a process that dies mid-issuance - leaves at
//! most a `pending` row, which the next open reconciles away
//! ([`CertLedger::record_issued`]).
//!
//! Revocation is sourced here. The renew RPC (`cert/renew`) refuses a
//! revoked-but-unexpired cert immediately by consulting [`CertLedger::status_of`]
//! (threat A5). The WSS handshake-time refusal is wired separately against this
//! ledger via [`CertLedger::revoked_fingerprints`] / [`CertLedger::is_revoked`].

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Arc;

use super::audit::{AuditEvent, AuditEventType, AuditLogger};

/// The `issued_certs.status` value for a row that is committed but whose
/// issuance has not been recorded as complete in the audit trail.
///
/// Deliberately outside [`CertStatus`]: a pending row is a certificate the
/// ledger does NOT vouch for, and no consumer may resolve it to a usable
/// status. Every read either filters it out or reports the fingerprint as
/// unknown; see [`CertLedger::record_issued`] for the state machine.
const PENDING: &str = "pending";

/// The `issued_certs` schema revision this build expects, stamped into
/// `PRAGMA user_version`.
///
/// * 0 - pre-versioned: `CHECK(status IN ('active','revoked'))`, no `pending`.
/// * 1 - `pending` admitted by the CHECK, so the issuance two-phase commit in
///   [`CertLedger::record_issued`] can stage a row.
const SCHEMA_VERSION: i64 = 1;

/// The `issued_certs` column definitions at [`SCHEMA_VERSION`].
///
/// Shared by the fresh-create path and the migration rebuild so a migrated
/// table can never drift from a freshly created one - the classic migration
/// bug, and the one that would silently reintroduce the old CHECK.
const ISSUED_CERTS_COLUMNS: &str = "
     fingerprint TEXT PRIMARY KEY,
     device_id   TEXT NOT NULL,
     token_hash  TEXT NOT NULL DEFAULT '',
     not_before  INTEGER NOT NULL,
     not_after   INTEGER NOT NULL,
     -- 'pending' is the pre-completion state of the issuance two-phase
     -- commit, never a credential; see record_issued.
     status      TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','revoked','pending')),
     issued_at   INTEGER NOT NULL,
     actor       TEXT NOT NULL DEFAULT ''
";

/// Every index the ledger relies on. Recreated verbatim after a rebuild,
/// because `DROP TABLE` takes the old table's indexes with it.
const ISSUED_CERTS_INDEXES: &str = "
     CREATE INDEX IF NOT EXISTS idx_issued_certs_device ON issued_certs(device_id);
     CREATE INDEX IF NOT EXISTS idx_issued_certs_status ON issued_certs(status);
     CREATE INDEX IF NOT EXISTS idx_issued_certs_token  ON issued_certs(token_hash);
";

/// Columns named explicitly for the migration copy, so the rebuild is
/// insensitive to column ORDER and fails loudly rather than silently shifting
/// values if the shape ever changes.
const ISSUED_CERTS_COLUMN_LIST: &str =
    "fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor";

/// Scratch table the rebuild stages into before swapping it in.
const MIGRATION_TABLE: &str = "issued_certs_migrated";

/// Status of an issued certificate the ledger vouches for.
///
/// There is no variant for the transient `pending` state on purpose: readers
/// see a fingerprint this ledger vouches for, or they see nothing at all. See
/// [`CertLedger::record_issued`] for the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Active,
    Revoked,
}

impl CertStatus {
    fn as_str(self) -> &'static str {
        match self {
            CertStatus::Active => "active",
            CertStatus::Revoked => "revoked",
        }
    }

    /// Parse a stored status, or `None` for one this ledger does not vouch for
    /// ([`PENDING`], or any value a future schema adds).
    ///
    /// The permissive `_ => Active` this replaced was the dangerous default: it
    /// would resolve a pending - that is, undelivered - certificate into an
    /// active credential for any reader that forgot to filter it out.
    fn from_db(s: &str) -> Option<CertStatus> {
        match s {
            "active" => Some(CertStatus::Active),
            "revoked" => Some(CertStatus::Revoked),
            _ => None,
        }
    }
}

/// How an issuance was authorized; controls the audit `actor` semantics so the
/// primary (self-service enrollment) path is never recorded with a blank actor.
#[derive(Debug, Clone)]
pub enum IssuanceActor {
    /// Self-service enrollment authorized by a pairing token. The audit actor is
    /// `enroll:<token-hash prefix>` so the evidence ties back to the pairing.
    Enrollment { token_hash: String },
    /// Operator-driven issuance via the `security issue-client-cert` CLI.
    Operator,
}

impl IssuanceActor {
    /// The `actor` string stored in the ledger row and the audit event.
    pub fn label(&self) -> String {
        match self {
            IssuanceActor::Enrollment { token_hash } => {
                let prefix: String = token_hash.chars().take(8).collect();
                format!("enroll:{prefix}")
            }
            IssuanceActor::Operator => "operator".to_string(),
        }
    }

    /// The `token_hash` join key to the pairing `devices.db`, when present.
    pub fn token_hash(&self) -> &str {
        match self {
            IssuanceActor::Enrollment { token_hash } => token_hash,
            IssuanceActor::Operator => "",
        }
    }
}

/// A row in the issued-cert ledger.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// Stable device id; equals the issued cert subject CN (the identity namespace).
    pub device_id: String,
    /// SHA-256 fingerprint (lowercase hex) of the issued cert DER. Primary key.
    pub fingerprint: String,
    /// `notBefore`, unix seconds.
    pub not_before: i64,
    /// `notAfter`, unix seconds.
    pub not_after: i64,
    /// Current status.
    pub status: CertStatus,
    /// Join key to the pairing `devices.db` (empty for operator CLI issuance).
    pub token_hash: String,
    /// Who authorized the issuance (`enroll:<prefix>` or `operator`).
    pub actor: String,
    /// When the cert was issued/recorded, unix seconds.
    pub issued_at: i64,
}

/// The daemon's issued-certificate ledger over SQLite (`<data_dir>/tls/ledger.db`).
pub struct CertLedger {
    conn: Mutex<Connection>,
    audit: Option<Arc<AuditLogger>>,
    /// Where revocations are materialized for the WSS verifier to read
    /// (`<data_dir>/tls/revoked`). `None` for an in-memory ledger.
    revoked_path: Option<std::path::PathBuf>,
}

/// The revoked-fingerprint list the daemon's WSS mTLS verifier reads for
/// connect-time revocation refusal (A5). The ledger materializes it on revoke.
pub fn revoked_list_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("tls").join("revoked")
}

/// The revoked-fingerprint list the WSS verifier will *actually* read: the
/// operator's `[wss.client_auth].crl_path` when set, otherwise the ledger
/// default under `<data_dir>/tls/revoked`.
///
/// Revocation must materialize to THIS path. Materializing to the default while
/// the verifier honours a configured override lets `revoke-client-cert` report
/// success while the next handshake still accepts the certificate — the
/// transport design of record requires revocation to fail closed.
pub fn effective_revoked_list_path(
    data_dir: &Path,
    configured_crl_path: Option<&str>,
) -> std::path::PathBuf {
    match configured_crl_path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => std::path::PathBuf::from(p),
        None => revoked_list_path(data_dir),
    }
}

impl CertLedger {
    /// Open (creating if absent) the ledger at `<data_dir>/tls/ledger.db`. The CA
    /// already lives under `<data_dir>/tls/`, so the ledger sits beside it.
    pub fn open(data_dir: &Path, audit: Option<Arc<AuditLogger>>) -> Result<Self> {
        Self::open_at(data_dir, audit, revoked_list_path(data_dir))
    }

    /// Open the ledger with an explicit materialization target, for callers that
    /// know the verifier reads a configured `crl_path` rather than the default.
    /// See [`effective_revoked_list_path`].
    pub fn open_at(
        data_dir: &Path,
        audit: Option<Arc<AuditLogger>>,
        revoked_path: std::path::PathBuf,
    ) -> Result<Self> {
        let tls_dir = data_dir.join("tls");
        std::fs::create_dir_all(&tls_dir)
            .with_context(|| format!("create tls dir {}", tls_dir.display()))?;
        let db_path = tls_dir.join("ledger.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("open cert ledger DB: {}", db_path.display()))?;
        // Name the file: a migration or reconciliation error is only actionable
        // if the operator knows which ledger to look at.
        Self::init(conn, audit, Some(revoked_path))
            .with_context(|| format!("initialize cert ledger DB: {}", db_path.display()))
    }

    /// In-memory ledger for unit tests.
    pub fn open_in_memory(audit: Option<Arc<AuditLogger>>) -> Result<Self> {
        Self::init(
            Connection::open_in_memory().context("open in-memory cert ledger")?,
            audit,
            None,
        )
    }

    fn init(
        mut conn: Connection,
        audit: Option<Arc<AuditLogger>>,
        revoked_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = MEMORY;",
        )
        .context("set cert-ledger PRAGMAs")?;
        // Bring the schema up to date BEFORE anything reads or writes the
        // table, so a migrated ledger is then reconciled like any other.
        Self::migrate_schema(&mut conn)?;
        let ledger = Self {
            conn: Mutex::new(conn),
            audit,
            revoked_path,
        };
        // Resolve anything a previous process left mid-issuance BEFORE this
        // ledger answers a single query.
        ledger.reconcile_pending_issuances()?;
        // Refresh the materialized revocation list so it reflects the ledger at
        // startup (covers a missing/stale file).
        ledger.materialize_revocations()?;
        Ok(ledger)
    }

    /// Bring `conn` to [`SCHEMA_VERSION`], creating or rebuilding
    /// `issued_certs` as needed.
    ///
    /// `CREATE TABLE IF NOT EXISTS` does NOT touch a table that already exists,
    /// so widening the status CHECK in the schema literal alone left every
    /// ledger written by an earlier revision of this branch stuck on the
    /// two-value constraint. Such a daemon opened its ledger successfully and
    /// then failed EVERY enrollment and renewal at `CHECK constraint failed:
    /// status IN ('active','revoked')` the moment the issuance path staged a
    /// `pending` row. An existing table has to be REBUILT, not merely
    /// re-declared.
    ///
    /// The rebuild is the standard SQLite table rewrite inside ONE transaction:
    /// stage a table at the current schema, copy every column by name, drop the
    /// old table, rename, recreate the indexes `DROP TABLE` removed, and stamp
    /// `user_version`. SQLite gives both DDL and `user_version` full
    /// transactional semantics, so ANY failure rolls the whole thing back and
    /// leaves the original table and its rows exactly as they were - there is
    /// no half-migrated state to recover from.
    ///
    /// Only one shape has ever shipped on this branch (identical columns and
    /// indexes, narrower CHECK), so a single rebuild covers every ledger an
    /// early adopter can be holding.
    fn migrate_schema(conn: &mut Connection) -> Result<()> {
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .context("read cert-ledger schema version")?;
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        if version > SCHEMA_VERSION {
            // Fail closed: a ledger written by a newer build may use states
            // this binary would mis-read, and silently operating on it risks
            // publishing or discarding credentials on bad assumptions.
            bail!(
                "cert ledger is at schema v{version}, newer than the v{SCHEMA_VERSION} this build \
                 understands; upgrade ZeroClaw, or move the ledger aside to start fresh (issued \
                 certificates would then need re-enrollment)"
            );
        }

        let existing: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'issued_certs'",
                [],
                |r| r.get(0),
            )
            .context("probe for an existing issued_certs table")?;

        if existing == 0 {
            // Fresh ledger: create at the current schema and stamp it, so this
            // path never looks like a pre-versioned table on the next open.
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS issued_certs ({ISSUED_CERTS_COLUMNS});
                 {ISSUED_CERTS_INDEXES}
                 PRAGMA user_version = {SCHEMA_VERSION};"
            ))
            .context("create cert-ledger schema")?;
            return Ok(());
        }

        let tx = conn
            .transaction()
            .context("begin cert-ledger schema migration")?;
        tx.execute_batch(&format!(
            "CREATE TABLE {MIGRATION_TABLE} ({ISSUED_CERTS_COLUMNS});
             INSERT INTO {MIGRATION_TABLE} ({ISSUED_CERTS_COLUMN_LIST})
                 SELECT {ISSUED_CERTS_COLUMN_LIST} FROM issued_certs;
             DROP TABLE issued_certs;
             ALTER TABLE {MIGRATION_TABLE} RENAME TO issued_certs;
             {ISSUED_CERTS_INDEXES}
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .with_context(|| {
            format!(
                "rebuild the cert-ledger issued_certs table from schema v{version} to \
                 v{SCHEMA_VERSION}; the existing ledger was rolled back and left unchanged, so \
                 no certificate records were lost"
            )
        })?;
        tx.commit().context("commit cert-ledger schema migration")
    }

    /// Resolve rows a previous process left in the `pending` state.
    ///
    /// The pending -> final flip happens inside the same
    /// [`CertLedger::record_issued`] call that committed the row, so ANY
    /// pending row still present when the ledger is opened belongs to a process
    /// that died - or a compensation that could not run - before the issuance
    /// completed. Such a row is an undelivered certificate by construction:
    /// discard it, and record WHY, so the unmatched `CertIssuanceAttempted` in
    /// the trail is closed out rather than left to inference.
    ///
    /// The audit event is written BEFORE the delete, matching the rest of this
    /// module: a failing audit logger leaves the row pending - invisible to
    /// every reader, and retried at the next open - instead of erasing it with
    /// no record.
    fn reconcile_pending_issuances(&self) -> Result<()> {
        let stale = {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT fingerprint, device_id, not_before, not_after, actor
                         FROM issued_certs WHERE status = ?1",
                )
                .context("prepare pending-issuance reconciliation")?;
            let rows = stmt
                .query_map(params![PENDING], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .context("query pending issuances")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("collect pending issuances")?
        };
        for (fingerprint, device_id, not_before, not_after, actor) in stale {
            self.audit_cert_fields(
                CertFacts {
                    device_id: &device_id,
                    actor: &actor,
                    fingerprint: &fingerprint,
                    not_before,
                    not_after,
                },
                CertAuditStage::Abandoned,
            )?;
            self.conn
                .lock()
                .execute(
                    "DELETE FROM issued_certs WHERE fingerprint = ?1 AND status = ?2",
                    params![fingerprint, PENDING],
                )
                .context("discard a pending issuance")?;
        }
        Ok(())
    }

    /// Rewrite the revoked-fingerprint file from the SQLite truth (atomic temp +
    /// rename). This is what makes a revoke take effect at the next handshake -
    /// the WSS verifier re-reads the file when its mtime changes. No-op for an
    /// in-memory ledger.
    pub fn materialize_revocations(&self) -> Result<()> {
        let conn = self.conn.lock();
        Self::materialize_on(&conn, self.revoked_path.as_deref())
    }

    /// Materialize the revocation file from `conn`'s current view. Taking the
    /// connection explicitly lets [`CertLedger::mark_revoked`] pass its open
    /// transaction, enforcing a pending revocation BEFORE committing it - a
    /// failed file write then rolls the status flip back instead of leaving a
    /// committed revoked row the verifier never sees.
    fn materialize_on(conn: &Connection, revoked_path: Option<&Path>) -> Result<()> {
        let Some(path) = revoked_path else {
            return Ok(());
        };
        let revoked = Self::revoked_fingerprints_on(conn)?;
        let body = if revoked.is_empty() {
            String::new()
        } else {
            format!("{}\n", revoked.join("\n"))
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).context("atomically replace the revocation list")?;
        Ok(())
    }

    /// Record an issuance across both durable surfaces as a two-phase commit.
    /// `renewal` selects `CertRenewed` vs `CertIssued` for the completion
    /// event.
    ///
    /// SQLite and the append-only audit file cannot share one transaction, so
    /// the row carries the protocol instead: it is committed in the `pending`
    /// state - which no reader resolves to a credential - and promoted to
    /// `entry.status` only once the completion event is durable.
    ///
    /// 1. `CertIssuanceAttempted`, BEFORE any row exists. A failure here leaves
    ///    the ledger untouched.
    /// 2. the row, as `pending`. A failure here leaves an attempt with no
    ///    completion and nothing the ledger vouches for.
    /// 3. `CertIssued`/`CertRenewed`, AFTER the row commits, so a completion
    ///    event means the row exists.
    /// 4. the promotion to `entry.status`, which is what publishes the
    ///    certificate to every reader.
    ///
    /// The two invariants this buys, in the order they matter:
    ///
    /// - **A row this ledger vouches for was always audited as complete.**
    ///   Step 4 cannot run before step 3 succeeds, so no failure - of the
    ///   completion write's rotation, open, serialization, write or sync - can
    ///   publish a certificate the caller never delivered. That is the failure
    ///   that used to strand an ACTIVE row for an undelivered credential, and
    ///   because the client's retry carries a fresh CSR (a different
    ///   fingerprint) it left a SECOND active row rather than replacing the
    ///   first.
    /// - **No failure publishes anything.** Every step returns `Err` and
    ///   callers must not hand the certificate to the client unless this
    ///   returns `Ok`. When a failure follows step 2, the pending row this call
    ///   staged is removed on the same connection; if that compensation cannot
    ///   run (or the process dies first) the row stays `pending`, which is
    ///   still invisible to every reader, and `reconcile_pending_issuances`
    ///   discards it at the next open.
    ///
    /// The converse is deliberately NOT claimed: a completion event without a
    /// row is possible, when step 4 fails. The caller still gets `Err` and
    /// still delivers nothing, so the residue is a fingerprint that is audited
    /// but absent - which fails closed - rather than a live credential with no
    /// audit.
    ///
    /// Re-recording a fingerprint the ledger already holds is idempotent and
    /// never downgrades it: step 2 does not disturb an existing row, and step 4
    /// rewrites it. A failed completion for such a call therefore leaves the
    /// established row exactly as it was, with its old validity - correct,
    /// since the caller is returning an error rather than delivering the
    /// renewed certificate.
    pub fn record_issued(&self, entry: &LedgerEntry, renewal: bool) -> Result<()> {
        self.audit_cert(entry, CertAuditStage::Attempted { renewal })?;
        let staged = self.stage_pending(entry)?;
        if let Err(err) = self.audit_cert(entry, CertAuditStage::Completed { renewal }) {
            self.discard_staged(entry, staged);
            return Err(err);
        }
        if let Err(err) = self.promote_staged(entry) {
            self.discard_staged(entry, staged);
            return Err(err);
        }
        Ok(())
    }

    /// Commit the row in the `pending` state, reporting whether THIS call is
    /// the one that staged it.
    ///
    /// `DO NOTHING` on conflict rather than `INSERT OR REPLACE`: an existing
    /// row is an already-completed issuance for that fingerprint, and briefly
    /// demoting it to `pending` would make a live credential vanish from every
    /// reader - including [`CertLedger::is_revoked`] - for the width of the
    /// completion write. Only the caller that created the row may compensate
    /// for it, which is what the returned flag carries.
    fn stage_pending(&self, entry: &LedgerEntry) -> Result<bool> {
        let conn = self.conn.lock();
        let inserted = conn
            .execute(
                "INSERT INTO issued_certs
                    (fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(fingerprint) DO NOTHING",
                params![
                    entry.fingerprint,
                    entry.device_id,
                    entry.token_hash,
                    entry.not_before,
                    entry.not_after,
                    PENDING,
                    entry.issued_at,
                    entry.actor,
                ],
            )
            .context("insert issued cert")?;
        Ok(inserted == 1)
    }

    /// Publish the issuance: rewrite the row with `entry.status`. This is the
    /// single statement that makes the certificate visible to every reader.
    fn promote_staged(&self, entry: &LedgerEntry) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO issued_certs
                (fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.fingerprint,
                entry.device_id,
                entry.token_hash,
                entry.not_before,
                entry.not_after,
                entry.status.as_str(),
                entry.issued_at,
                entry.actor,
            ],
        )
        .context("activate issued cert")?;
        Ok(())
    }

    /// Compensate a failed issuance by removing the row this call staged.
    ///
    /// Best-effort by design, and it never masks the failure that triggered it:
    /// the caller returns that error either way. The `status = pending` guard
    /// makes the delete safe against a concurrent issuance of the same
    /// fingerprint that already promoted the row, and a delete that cannot run
    /// is not a leak - the row is still pending, so still not a credential, and
    /// the next open reconciles it away.
    fn discard_staged(&self, entry: &LedgerEntry, staged: bool) {
        if !staged {
            return;
        }
        let result = self.conn.lock().execute(
            "DELETE FROM issued_certs WHERE fingerprint = ?1 AND status = ?2",
            params![entry.fingerprint, PENDING],
        );
        if let Err(error) = result {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Delete)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "error": format!("{error}"),
                        "fingerprint": entry.fingerprint,
                    })),
                "cert ledger: could not discard a pending issuance; it will be reconciled at the next open"
            );
        }
    }

    /// Fault injection for the issuance ordering contract: detach the table so
    /// the next [`CertLedger::record_issued`] fails at the ledger write, AFTER
    /// its audit event. Lets the callers' interrupted-issuance behaviour be
    /// tested without a production error hook.
    #[cfg(test)]
    pub(crate) fn detach_issued_certs_for_test(&self) -> Result<()> {
        self.conn
            .lock()
            .execute_batch("ALTER TABLE issued_certs RENAME TO issued_certs_detached")
            .context("detach issued_certs")
    }

    /// Undo [`CertLedger::detach_issued_certs_for_test`].
    #[cfg(test)]
    pub(crate) fn reattach_issued_certs_for_test(&self) -> Result<()> {
        self.conn
            .lock()
            .execute_batch("ALTER TABLE issued_certs_detached RENAME TO issued_certs")
            .context("reattach issued_certs")
    }

    /// The status of a cert by fingerprint, or `None` if unknown to the ledger.
    ///
    /// A `pending` row reads as `None`: its issuance has not been recorded as
    /// complete, so the ledger does not vouch for that certificate and callers
    /// must treat it exactly as they treat one they have never seen. For the
    /// renew RPC that means "re-enroll", which is the correct answer for a
    /// certificate that was never delivered.
    pub fn status_of(&self, fingerprint: &str) -> Result<Option<CertStatus>> {
        let conn = self.conn.lock();
        let s: Option<String> = conn
            .query_row(
                "SELECT status FROM issued_certs WHERE fingerprint = ?1 AND status != ?2",
                params![fingerprint, PENDING],
                |r| r.get(0),
            )
            .optional()
            .context("query cert status")?;
        match s {
            None => Ok(None),
            Some(s) => CertStatus::from_db(&s).map(Some).with_context(|| {
                format!("issued_certs.status {s:?} is not a status this ledger vouches for")
            }),
        }
    }

    /// True iff the cert is known to this ledger AND marked revoked.
    ///
    /// A cert this ledger has never seen is NOT revoked here, and that is not a
    /// gap the verifier closes by ledger membership: the WSS verifier's
    /// authority model is CA-based. It authorizes any certificate that chains
    /// to the configured client CA, subject to the optional leaf pins and this
    /// revocation list. Ledger membership is not required for normal RPC
    /// initialization - that is what makes the documented bring-your-own-CA
    /// path work, since certificates minted outside this daemon are legitimate
    /// and never appear in its issued-cert table.
    pub fn is_revoked(&self, fingerprint: &str) -> Result<bool> {
        Ok(matches!(
            self.status_of(fingerprint)?,
            Some(CertStatus::Revoked)
        ))
    }

    /// Look up the full ledger row for a fingerprint. A `pending` row reads as
    /// `None`, for the reason given on [`CertLedger::status_of`].
    pub fn lookup_by_fingerprint(&self, fingerprint: &str) -> Result<Option<LedgerEntry>> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT fingerprint, device_id, token_hash, not_before, not_after, status, actor, issued_at
                 FROM issued_certs WHERE fingerprint = ?1 AND status != ?2",
            params![fingerprint, PENDING],
            row_to_entry,
        )
        .optional()
        .context("lookup cert by fingerprint")
    }

    /// The device id bound to a presenting cert (its subject CN, via the ledger).
    pub fn device_of(&self, fingerprint: &str) -> Result<Option<String>> {
        Ok(self
            .lookup_by_fingerprint(fingerprint)?
            .map(|e| e.device_id))
    }

    /// Mark a cert revoked by fingerprint. Returns true if a row changed.
    /// Writes a `CertRevoked` audit event when a row was actually flipped.
    ///
    /// Ordering guarantee: the status flip and the materialized enforcement
    /// file commit together or not at all. The file is rewritten from the
    /// in-transaction view BEFORE the SQLite commit, so
    /// - a materialization failure rolls the flip back: the ledger never
    ///   reports a revocation the WSS verifier is not enforcing;
    /// - a commit failure after the file write leaves the file over-enforcing
    ///   until the next materialization (fail-closed, never fail-open).
    pub fn mark_revoked(&self, fingerprint: &str, actor: &str) -> Result<bool> {
        let audit_entry = {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().context("begin revocation transaction")?;
            // Only an ACTIVE row is revocable. Revoking a `pending` row would
            // publish - as revoked - a certificate the ledger has not vouched
            // for and whose issuance may still be compensated away; such a
            // fingerprint reads as unknown everywhere else, and reporting a
            // revocation for it here would contradict that.
            let changed = tx
                .execute(
                    "UPDATE issued_certs SET status = 'revoked'
                         WHERE fingerprint = ?1 AND status = 'active'",
                    params![fingerprint],
                )
                .context("revoke cert")?;
            if changed == 0 {
                return Ok(false);
            }
            let entry = tx
                .query_row(
                    "SELECT fingerprint, device_id, token_hash, not_before, not_after, status, actor, issued_at
                         FROM issued_certs WHERE fingerprint = ?1",
                    params![fingerprint],
                    row_to_entry,
                )
                .optional()
                .context("lookup revoked cert")?;
            // Enforce BEFORE the ledger reports it (drives the A5 refusal from
            // the real revoke action); failure here rolls the flip back.
            Self::materialize_on(&tx, self.revoked_path.as_deref())?;
            tx.commit().context("commit revocation")?;
            entry.map(|mut e| {
                e.actor = actor.to_string();
                e
            })
        };
        if let Some(entry) = audit_entry {
            self.audit_cert(&entry, CertAuditStage::Revoked)?;
        }
        Ok(true)
    }

    /// Revoke every active cert held by a device (e.g. a compromised device).
    /// Returns the number of certs revoked.
    pub fn revoke_device(&self, device_id: &str, actor: &str) -> Result<usize> {
        let fingerprints: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare("SELECT fingerprint FROM issued_certs WHERE device_id = ?1 AND status = 'active'")
                .context("prepare device revoke")?;
            let rows = stmt
                .query_map(params![device_id], |r| r.get::<_, String>(0))
                .context("query device certs")?;
            rows.collect::<rusqlite::Result<Vec<String>>>()
                .context("collect device certs")?
        };
        let mut n = 0;
        for fp in fingerprints {
            if self.mark_revoked(&fp, actor)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// All currently-active ledger rows.
    pub fn list_active(&self) -> Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT fingerprint, device_id, token_hash, not_before, not_after, status, actor, issued_at
                     FROM issued_certs WHERE status = 'active'",
            )
            .context("prepare list_active")?;
        let rows = stmt
            .query_map([], row_to_entry)
            .context("query list_active")?;
        rows.collect::<rusqlite::Result<Vec<LedgerEntry>>>()
            .context("collect list_active")
    }

    /// The set of currently-revoked fingerprints - the source the WSS verifier
    /// revocation check (and CRL materialization) consume.
    pub fn revoked_fingerprints(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        Self::revoked_fingerprints_on(&conn)
    }

    /// The revoked set as seen by `conn` - which may be an open transaction,
    /// so [`CertLedger::mark_revoked`] can materialize a pending flip.
    fn revoked_fingerprints_on(conn: &Connection) -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare("SELECT fingerprint FROM issued_certs WHERE status = 'revoked'")
            .context("prepare revoked_fingerprints")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .context("query revoked_fingerprints")?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .context("collect revoked_fingerprints")
    }

    /// Emit a hash-chained audit event for a certificate lifecycle action.
    fn audit_cert(&self, entry: &LedgerEntry, stage: CertAuditStage) -> Result<()> {
        self.audit_cert_fields(
            CertFacts {
                device_id: &entry.device_id,
                actor: &entry.actor,
                fingerprint: &entry.fingerprint,
                not_before: entry.not_before,
                not_after: entry.not_after,
            },
            stage,
        )
    }

    /// Emit a hash-chained audit event from loose facts, for the reconciliation
    /// path - which describes a row that is by definition not a [`LedgerEntry`]
    /// this ledger vouches for, so it has no [`CertStatus`] to carry.
    ///
    /// The security audit log is already separate from operational logs; cert
    /// facts (device id, fingerprint, validity, actor) are recorded in the
    /// existing actor/action fields so the entry is covered by the Merkle
    /// chain.
    ///
    /// Only a stage the durable stores have settled carries an
    /// `ExecutionResult`: a pre-commit attempt has no outcome to report, and
    /// recording one would make the append-only trail claim an issuance the
    /// ledger may still reject.
    fn audit_cert_fields(&self, facts: CertFacts<'_>, stage: CertAuditStage) -> Result<()> {
        let Some(audit) = &self.audit else {
            return Ok(());
        };
        let mut event = AuditEvent::new(stage.event_type())
            .with_actor(
                "cert".to_string(),
                Some(facts.device_id.to_string()),
                Some(facts.actor.to_string()),
            )
            .with_action(
                format!(
                    "{}fingerprint={} not_before={} not_after={}",
                    stage.action_prefix(),
                    facts.fingerprint,
                    facts.not_before,
                    facts.not_after
                ),
                "cert".to_string(),
                true,
                true,
            );
        if let Some(outcome) = stage.outcome() {
            event = event.with_result(outcome.success, None, 0, outcome.error);
        }
        audit
            .log(&event)
            .with_context(|| format!("write certificate audit event for {}", facts.fingerprint))
    }
}

/// The certificate facts every cert audit event carries.
struct CertFacts<'a> {
    device_id: &'a str,
    actor: &'a str,
    fingerprint: &'a str,
    not_before: i64,
    not_after: i64,
}

/// The `ExecutionResult` a settled [`CertAuditStage`] claims.
struct StageOutcome {
    success: bool,
    error: Option<String>,
}

/// Which certificate lifecycle fact an audit event records.
///
/// Issuance spans two events because SQLite and the append-only audit file
/// cannot share one transaction; see [`CertLedger::record_issued`] for the
/// ordering argument and what an unmatched attempt means.
#[derive(Debug, Clone, Copy)]
enum CertAuditStage {
    /// Issuance attempted: the CSR is signed, the ledger has not committed and
    /// the caller has not delivered the certificate.
    Attempted { renewal: bool },
    /// Issuance completed: the ledger row is committed and about to be
    /// promoted out of `pending`.
    Completed { renewal: bool },
    /// An issuance that committed a row but never completed was reconciled
    /// away at open; the row is about to be discarded.
    Abandoned,
    /// Revocation committed together with its enforcement file.
    Revoked,
}

impl CertAuditStage {
    fn event_type(self) -> AuditEventType {
        match self {
            CertAuditStage::Attempted { .. } => AuditEventType::CertIssuanceAttempted,
            CertAuditStage::Completed { renewal: true } => AuditEventType::CertRenewed,
            CertAuditStage::Completed { renewal: false } => AuditEventType::CertIssued,
            CertAuditStage::Abandoned => AuditEventType::CertIssuanceAbandoned,
            CertAuditStage::Revoked => AuditEventType::CertRevoked,
        }
    }

    /// What the event claims, or `None` for a stage whose outcome is not
    /// settled yet.
    fn outcome(self) -> Option<StageOutcome> {
        match self {
            CertAuditStage::Attempted { .. } => None,
            CertAuditStage::Abandoned => Some(StageOutcome {
                success: false,
                error: Some("issuance never completed; the ledger row was discarded".to_string()),
            }),
            CertAuditStage::Completed { .. } | CertAuditStage::Revoked => Some(StageOutcome {
                success: true,
                error: None,
            }),
        }
    }

    /// Names the completion an attempt is waiting on, so an unmatched attempt
    /// reads as an interrupted renewal or an interrupted first issuance, and
    /// marks the reconciliation that closes such an attempt out.
    fn action_prefix(self) -> &'static str {
        match self {
            CertAuditStage::Attempted { renewal: true } => "attempt=renew ",
            CertAuditStage::Attempted { renewal: false } => "attempt=issue ",
            CertAuditStage::Abandoned => "abandoned=reconcile ",
            CertAuditStage::Completed { .. } | CertAuditStage::Revoked => "",
        }
    }
}

/// Map a row this ledger vouches for. A `pending` (or otherwise unrecognized)
/// status is an ERROR here rather than a silent widening to `Active`: every
/// query feeding this mapper filters pending out, and a reader that ever forgot
/// to must fail loudly instead of reporting an undelivered certificate as a
/// usable one.
fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerEntry> {
    let status: String = row.get(5)?;
    let status = CertStatus::from_db(&status).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            format!("issued_certs.status {status:?} is not a status this ledger vouches for")
                .into(),
        )
    })?;
    Ok(LedgerEntry {
        fingerprint: row.get(0)?,
        device_id: row.get(1)?,
        token_hash: row.get(2)?,
        not_before: row.get(3)?,
        not_after: row.get(4)?,
        status,
        actor: row.get(6)?,
        issued_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::AuditConfig;

    fn entry(fp: &str, device: &str) -> LedgerEntry {
        LedgerEntry {
            device_id: device.to_string(),
            fingerprint: fp.to_string(),
            not_before: 1_000,
            not_after: 1_000 + 30 * 86_400,
            status: CertStatus::Active,
            token_hash: "abcdef0123456789".to_string(),
            actor: IssuanceActor::Enrollment {
                token_hash: "abcdef0123456789".to_string(),
            }
            .label(),
            issued_at: 1_000,
        }
    }

    /// An audit logger writing to `<dir>/audit.log`, with that path.
    fn audit_logger(dir: &Path) -> (Arc<AuditLogger>, std::path::PathBuf) {
        let logger = AuditLogger::new(
            AuditConfig {
                enabled: true,
                log_path: "audit.log".to_string(),
                max_size_mb: 100,
                sign_events: false,
            },
            dir.to_path_buf(),
        )
        .unwrap();
        (Arc::new(logger), dir.join("audit.log"))
    }

    fn audit_events(log_path: &Path) -> Vec<AuditEvent> {
        std::fs::read_to_string(log_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<AuditEvent>(l).expect("audit line is a valid event"))
            .collect()
    }

    /// The serialized `event_type`: the readable surface an audit reader sees.
    fn type_name(event: &AuditEvent) -> String {
        serde_json::to_value(&event.event_type)
            .unwrap()
            .as_str()
            .expect("event_type serializes as a string")
            .to_string()
    }

    fn command_of(event: &AuditEvent) -> String {
        event
            .action
            .as_ref()
            .and_then(|a| a.command.clone())
            .unwrap_or_default()
    }

    /// Every (fingerprint, status) pair actually stored, read through a
    /// SEPARATE connection. The ledger's own readers deliberately hide
    /// `pending`, so asserting a row is *gone* rather than merely invisible has
    /// to go around them.
    fn stored_rows(dir: &Path) -> Vec<(String, String)> {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        let mut stmt = conn
            .prepare("SELECT fingerprint, status FROM issued_certs ORDER BY fingerprint")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, String)>>>()
            .unwrap()
    }

    /// Commit a row in the `pending` state through a separate connection:
    /// exactly what a process that died between the ledger commit and the
    /// completion audit event leaves behind. Building the fixture outside the
    /// ledger API keeps the crash-window test independent of the code under
    /// test, and proves the schema CHECK actually admits the state.
    fn stage_pending_row(dir: &Path, fingerprint: &str, device_id: &str) {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        conn.execute(
            "INSERT INTO issued_certs
                (fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor)
             VALUES (?1, ?2, 'abcdef0123456789', 1000, 2592000, 'pending', 1000, 'enroll:abcdef01')",
            params![fingerprint, device_id],
        )
        .unwrap();
    }

    /// The `issued_certs` schema EXACTLY as every pre-versioned revision of
    /// this branch created it: same columns, same indexes, the old two-value
    /// CHECK, and `user_version` left at 0.
    ///
    /// Verified against the branch history - commits a762ced3c through
    /// 0ec59c70e all created this identical shape - so one fixture covers every
    /// ledger an early adopter can be holding.
    const V0_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS issued_certs (
             fingerprint TEXT PRIMARY KEY,
             device_id   TEXT NOT NULL,
             token_hash  TEXT NOT NULL DEFAULT '',
             not_before  INTEGER NOT NULL,
             not_after   INTEGER NOT NULL,
             status      TEXT NOT NULL DEFAULT 'active'
                             CHECK(status IN ('active','revoked')),
             issued_at   INTEGER NOT NULL,
             actor       TEXT NOT NULL DEFAULT ''
         );
         CREATE INDEX IF NOT EXISTS idx_issued_certs_device ON issued_certs(device_id);
         CREATE INDEX IF NOT EXISTS idx_issued_certs_status ON issued_certs(status);
         CREATE INDEX IF NOT EXISTS idx_issued_certs_token  ON issued_certs(token_hash);";

    /// Lay down a pre-versioned ledger holding one active and one revoked cert.
    fn create_v0_ledger(dir: &Path) {
        std::fs::create_dir_all(dir.join("tls")).unwrap();
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        conn.execute_batch(V0_SCHEMA).unwrap();
        conn.execute_batch(
            "INSERT INTO issued_certs
                (fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor)
             VALUES
                ('fpOldActive','devOld','tokOld',100,200,'active',150,'operator'),
                ('fpOldRevoked','devOld2','tokOld2',300,400,'revoked',350,'enroll:deadbeef');",
        )
        .unwrap();
    }

    fn user_version(dir: &Path) -> i64 {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    fn index_names(dir: &Path) -> Vec<String> {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                     WHERE type = 'index' AND tbl_name = 'issued_certs' AND name NOT LIKE 'sqlite_%'
                     ORDER BY name",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap()
    }

    /// The stored CREATE TABLE text, so a test can assert WHICH constraint the
    /// table actually carries rather than inferring it from behaviour.
    fn table_sql(dir: &Path) -> String {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'issued_certs'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn open_migrates_a_pre_versioned_ledger_and_preserves_every_row() {
        // Blocking regression: CREATE TABLE IF NOT EXISTS does NOT widen the
        // CHECK on a table that already exists, so a daemon that ran an earlier
        // revision of this branch opened its ledger fine and then failed EVERY
        // enrollment and renewal at `CHECK constraint failed: status IN
        // ('active','revoked')` the moment the issuance path inserted 'pending'.
        let dir = tempfile::tempdir().unwrap();
        create_v0_ledger(dir.path());
        assert_eq!(user_version(dir.path()), 0, "fixture must be pre-versioned");
        assert!(
            table_sql(dir.path()).contains("'active','revoked')"),
            "fixture must carry the OLD two-value CHECK"
        );

        let led = CertLedger::open(dir.path(), None).unwrap();

        // Every column of every pre-existing row survives the rebuild intact.
        let active = led
            .lookup_by_fingerprint("fpOldActive")
            .unwrap()
            .expect("the pre-existing active cert must survive migration");
        assert_eq!(active.device_id, "devOld");
        assert_eq!(active.token_hash, "tokOld");
        assert_eq!(active.not_before, 100);
        assert_eq!(active.not_after, 200);
        assert_eq!(active.issued_at, 150);
        assert_eq!(active.actor, "operator");
        assert_eq!(active.status, CertStatus::Active);
        let revoked = led
            .lookup_by_fingerprint("fpOldRevoked")
            .unwrap()
            .expect("the pre-existing revoked cert must survive migration");
        assert_eq!(revoked.device_id, "devOld2");
        assert_eq!(revoked.token_hash, "tokOld2");
        assert_eq!(revoked.not_before, 300);
        assert_eq!(revoked.not_after, 400);
        assert_eq!(revoked.issued_at, 350);
        assert_eq!(revoked.actor, "enroll:deadbeef");
        assert_eq!(revoked.status, CertStatus::Revoked);
        // Revocation state survives too - it drives the WSS refusal.
        assert!(led.is_revoked("fpOldRevoked").unwrap());
        assert_eq!(
            led.revoked_fingerprints().unwrap(),
            vec!["fpOldRevoked".to_string()]
        );

        // THE POINT: the pending -> active issuance path now runs on this DB.
        // This is the line that reproduced the reviewer's IntegrityError.
        led.record_issued(&entry("fpNew", "devNew"), false)
            .expect("issuance must succeed against a migrated ledger");
        assert_eq!(led.status_of("fpNew").unwrap(), Some(CertStatus::Active));

        // ... and the new credential coexists with the preserved ones.
        let mut active_fps: Vec<String> = led
            .list_active()
            .unwrap()
            .into_iter()
            .map(|e| e.fingerprint)
            .collect();
        active_fps.sort();
        assert_eq!(active_fps, ["fpNew", "fpOldActive"]);
        assert!(led.is_revoked("fpOldRevoked").unwrap());

        // The schema is stamped, widened, and still carries its indexes.
        assert_eq!(user_version(dir.path()), SCHEMA_VERSION);
        assert!(
            table_sql(dir.path()).contains("'active','revoked','pending')"),
            "migrated table must carry the widened CHECK, got: {}",
            table_sql(dir.path())
        );
        assert_eq!(
            index_names(dir.path()),
            [
                "idx_issued_certs_device",
                "idx_issued_certs_status",
                "idx_issued_certs_token"
            ],
            "the rebuild must recreate every index the old table had"
        );
    }

    /// Occupy the scratch table name the rebuild stages into, so the migration
    /// fails at its very first statement.
    fn obstruct_migration(dir: &Path) {
        let conn = Connection::open(dir.join("tls").join("ledger.db")).unwrap();
        conn.execute_batch("CREATE TABLE issued_certs_migrated (occupied INTEGER);")
            .unwrap();
    }

    #[test]
    fn migration_handles_an_unversioned_ledger_that_already_has_the_wide_check() {
        // The other early-adopter shape: a ledger written by the revision that
        // widened the CHECK but predated versioning. It is v1-shaped yet still
        // stamped 0, so the rebuild runs over it. That must be lossless - and
        // it must carry `pending` rows through the copy, where reconciliation
        // then resolves them exactly as it would on any other open.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tls")).unwrap();
        {
            let conn = Connection::open(dir.path().join("tls").join("ledger.db")).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS issued_certs ({ISSUED_CERTS_COLUMNS});
                 {ISSUED_CERTS_INDEXES}"
            ))
            .unwrap();
            conn.execute_batch(
                "INSERT INTO issued_certs
                    (fingerprint, device_id, token_hash, not_before, not_after, status, issued_at, actor)
                 VALUES
                    ('fpKeep','devK','tokK',100,200,'active',150,'operator'),
                    ('fpGone','devG','tokG',300,400,'pending',350,'enroll:cafe');",
            )
            .unwrap();
        }
        assert_eq!(user_version(dir.path()), 0);

        let led = CertLedger::open(dir.path(), None).unwrap();

        assert_eq!(user_version(dir.path()), SCHEMA_VERSION);
        let kept = led.lookup_by_fingerprint("fpKeep").unwrap().unwrap();
        assert_eq!(kept.actor, "operator");
        assert_eq!(kept.not_after, 200);
        // The pending row survived the rebuild and was then reconciled away.
        assert_eq!(
            stored_rows(dir.path()),
            vec![("fpKeep".to_string(), "active".to_string())],
            "a pending row must migrate, then be reconciled - never block the rebuild"
        );
        led.record_issued(&entry("fpNew", "devNew"), false).unwrap();
        assert_eq!(led.list_active().unwrap().len(), 2);
    }

    #[test]
    fn a_failed_migration_rolls_back_and_leaves_the_old_ledger_intact() {
        // Failure-safety: a migration that dies part-way must leave the ledger
        // exactly as it found it. A half-migrated certificate ledger is worse
        // than an un-migrated one - it can lose or duplicate credentials.
        let dir = tempfile::tempdir().unwrap();
        create_v0_ledger(dir.path());
        obstruct_migration(dir.path());

        let err = CertLedger::open(dir.path(), None)
            .map(|_| ())
            .expect_err("an obstructed migration must fail the open");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("rebuild the cert-ledger issued_certs table"),
            "got: {chain}"
        );
        assert!(
            chain.contains("left unchanged"),
            "the error must tell the operator nothing was lost: {chain}"
        );
        assert!(
            chain.contains("ledger.db"),
            "the error must name the ledger file: {chain}"
        );

        // Everything about the original table survives the rollback.
        assert_eq!(
            user_version(dir.path()),
            0,
            "a failed migration must not stamp the version"
        );
        assert!(
            table_sql(dir.path()).contains("'active','revoked')"),
            "the original CHECK must be intact"
        );
        assert_eq!(
            index_names(dir.path()),
            [
                "idx_issued_certs_device",
                "idx_issued_certs_status",
                "idx_issued_certs_token"
            ]
        );
        assert_eq!(
            stored_rows(dir.path()),
            vec![
                ("fpOldActive".to_string(), "active".to_string()),
                ("fpOldRevoked".to_string(), "revoked".to_string()),
            ],
            "every pre-existing row must survive a failed migration"
        );

        // Clearing the obstruction lets the very same ledger migrate cleanly.
        {
            let conn = Connection::open(dir.path().join("tls").join("ledger.db")).unwrap();
            conn.execute_batch("DROP TABLE issued_certs_migrated;")
                .unwrap();
        }
        let led = CertLedger::open(dir.path(), None).unwrap();
        assert_eq!(user_version(dir.path()), SCHEMA_VERSION);
        led.record_issued(&entry("fpNew", "devNew"), false).unwrap();
        assert_eq!(led.list_active().unwrap().len(), 2);
        assert!(led.is_revoked("fpOldRevoked").unwrap());
    }

    #[test]
    fn reopening_an_already_migrated_ledger_does_not_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        create_v0_ledger(dir.path());
        {
            let led = CertLedger::open(dir.path(), None).unwrap();
            led.record_issued(&entry("fpNew", "devNew"), false).unwrap();
        }
        assert_eq!(user_version(dir.path()), SCHEMA_VERSION);

        // Occupy the scratch table name. If the version check did NOT
        // short-circuit, the rebuild would run and fail on it - so a CLEAN open
        // here is positive proof the migration path was skipped entirely.
        obstruct_migration(dir.path());

        let led = CertLedger::open(dir.path(), None).unwrap();
        assert_eq!(user_version(dir.path()), SCHEMA_VERSION);
        let mut fps: Vec<String> = led
            .list_active()
            .unwrap()
            .into_iter()
            .map(|e| e.fingerprint)
            .collect();
        fps.sort();
        assert_eq!(fps, ["fpNew", "fpOldActive"]);
        assert!(led.is_revoked("fpOldRevoked").unwrap());
    }

    #[test]
    fn a_ledger_from_a_newer_build_is_refused_rather_than_guessed_at() {
        // Fail closed on a forward version: a newer build may use states this
        // one would mis-read, and a certificate ledger is the wrong place to
        // guess.
        let dir = tempfile::tempdir().unwrap();
        create_v0_ledger(dir.path());
        {
            let conn = Connection::open(dir.path().join("tls").join("ledger.db")).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
                .unwrap();
        }

        let err = format!(
            "{:#}",
            CertLedger::open(dir.path(), None)
                .map(|_| ())
                .expect_err("a forward schema version must be refused")
        );
        assert!(err.contains("newer than"), "got: {err}");
        assert!(
            err.contains("re-enrollment"),
            "the refusal must tell the operator what their options are: {err}"
        );
        // Refusing touched nothing.
        assert_eq!(stored_rows(dir.path()).len(), 2);
    }

    #[test]
    fn a_fresh_ledger_is_created_already_stamped() {
        let dir = tempfile::tempdir().unwrap();
        let led = CertLedger::open(dir.path(), None).unwrap();
        assert_eq!(
            user_version(dir.path()),
            SCHEMA_VERSION,
            "a fresh ledger must not look pre-versioned on the next open"
        );
        assert!(table_sql(dir.path()).contains("'active','revoked','pending')"));
        assert_eq!(
            index_names(dir.path()),
            [
                "idx_issued_certs_device",
                "idx_issued_certs_status",
                "idx_issued_certs_token"
            ]
        );
        // And a fresh ledger reopens without rebuilding.
        drop(led);
        obstruct_migration(dir.path());
        let led = CertLedger::open(dir.path(), None).unwrap();
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        assert_eq!(led.list_active().unwrap().len(), 1);
    }

    #[test]
    fn record_lookup_and_status() {
        let led = CertLedger::open_in_memory(None).unwrap();
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        assert_eq!(led.status_of("fp1").unwrap(), Some(CertStatus::Active));
        assert_eq!(led.status_of("missing").unwrap(), None);
        let got = led.lookup_by_fingerprint("fp1").unwrap().unwrap();
        assert_eq!(got.device_id, "dev1");
        assert_eq!(got.actor, "enroll:abcdef01");
        assert_eq!(led.device_of("fp1").unwrap().as_deref(), Some("dev1"));
    }

    #[test]
    fn revoke_flips_status_and_lists() {
        let led = CertLedger::open_in_memory(None).unwrap();
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        assert!(!led.is_revoked("fp1").unwrap());
        assert!(led.mark_revoked("fp1", "operator").unwrap());
        assert!(led.is_revoked("fp1").unwrap());
        assert_eq!(led.status_of("fp1").unwrap(), Some(CertStatus::Revoked));
        assert_eq!(led.revoked_fingerprints().unwrap(), vec!["fp1".to_string()]);
        assert!(led.list_active().unwrap().is_empty());
        // Idempotent: revoking again reports no change.
        assert!(!led.mark_revoked("fp1", "operator").unwrap());
        // Revoking an unknown fingerprint is a no-op.
        assert!(!led.mark_revoked("nope", "operator").unwrap());
    }

    #[test]
    fn mark_revoked_rolls_back_when_materialization_fails() {
        // Fault injection for the revocation atomicity contract: if the
        // enforcement file cannot be written, the status flip must NOT commit.
        // A revoked-in-SQLite row with a stale enforcement file would keep
        // authenticating at the WSS handshake while `security list-client-certs`
        // reports it revoked - exactly the split this ordering forbids.
        let dir = tempfile::tempdir().unwrap();
        let led = CertLedger::open(dir.path(), None).unwrap();
        led.record_issued(&entry("fpA", "dev1"), false).unwrap();

        // Obstruct materialization: replace the enforcement file with a
        // directory so the atomic rename over it fails.
        let crl = revoked_list_path(dir.path());
        std::fs::remove_file(&crl).unwrap();
        std::fs::create_dir(&crl).unwrap();

        let err = led.mark_revoked("fpA", "operator").unwrap_err().to_string();
        assert!(err.contains("revocation list"), "got: {err}");
        // Rolled back: the ledger does not report a revocation it could not
        // enforce, and the revoked set stays empty.
        assert_eq!(led.status_of("fpA").unwrap(), Some(CertStatus::Active));
        assert!(!led.is_revoked("fpA").unwrap());
        assert!(led.revoked_fingerprints().unwrap().is_empty());

        // Clear the fault: the same revoke now commits AND enforces.
        std::fs::remove_dir(&crl).unwrap();
        assert!(led.mark_revoked("fpA", "operator").unwrap());
        assert!(led.is_revoked("fpA").unwrap());
        let body = std::fs::read_to_string(&crl).unwrap();
        assert!(body.contains("fpA"), "enforcement file must carry the fp");
    }

    #[test]
    fn revoke_materializes_the_crl_file_for_the_wss_verifier() {
        // P1 contract: revoking in the ledger writes <data_dir>/tls/revoked so the
        // WSS verifier refuses that cert on the next connect (A5).
        let dir = tempfile::tempdir().unwrap();
        let led = CertLedger::open(dir.path(), None).unwrap();
        led.record_issued(&entry("fpA", "dev1"), false).unwrap();
        led.record_issued(&entry("fpB", "dev2"), false).unwrap();

        let crl = revoked_list_path(dir.path());
        // Nothing revoked yet -> the file exists (materialized at open) but is empty.
        let before = std::fs::read_to_string(&crl).unwrap_or_default();
        assert!(before.trim().is_empty());

        led.mark_revoked("fpA", "operator").unwrap();
        let after = std::fs::read_to_string(&crl).unwrap();
        let revoked: Vec<&str> = after
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            revoked,
            vec!["fpA"],
            "the revoked fingerprint is materialized"
        );
        // The verifier sees it as revoked, the other does not.
        let set = zeroclaw_tls::load_revoked_fingerprints(&crl).unwrap();
        assert!(set.contains("fpa")); // load normalizes to lowercase
        assert!(!set.contains("fpb"));
    }

    #[test]
    fn revoke_materializes_to_a_configured_crl_path_not_the_default() {
        // Regression: with `[wss.client_auth].crl_path` set, the WSS verifier
        // reads THAT file. Materializing to the default instead let
        // `revoke-client-cert` report success while the next handshake still
        // accepted the certificate. Revocation must fail closed.
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("operator-managed.crl");

        let effective = effective_revoked_list_path(dir.path(), Some(custom.to_str().unwrap()));
        assert_eq!(effective, custom, "a configured path wins over the default");

        let led = CertLedger::open_at(dir.path(), None, effective.clone()).unwrap();
        led.record_issued(&entry("fpA", "dev1"), false).unwrap();
        assert!(led.mark_revoked("fpA", "operator").unwrap());

        // The configured file - the one the verifier reads - carries the revocation.
        let set = zeroclaw_tls::load_revoked_fingerprints(&custom).unwrap();
        assert!(
            set.contains("fpa"),
            "revocation must land in the configured CRL path"
        );

        // And it did not silently go only to the default path.
        let default_body =
            std::fs::read_to_string(revoked_list_path(dir.path())).unwrap_or_default();
        assert!(
            !default_body.contains("fpA"),
            "revocation must not be written only to the unused default path"
        );
    }

    #[test]
    fn effective_revoked_list_path_falls_back_when_unset_or_blank() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = revoked_list_path(dir.path());
        assert_eq!(effective_revoked_list_path(dir.path(), None), default_path);
        assert_eq!(
            effective_revoked_list_path(dir.path(), Some("")),
            default_path
        );
        assert_eq!(
            effective_revoked_list_path(dir.path(), Some("   ")),
            default_path,
            "a whitespace-only crl_path is not a real override"
        );
    }

    #[test]
    fn open_refreshes_stale_materialized_revocations_from_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let crl = revoked_list_path(dir.path());
        {
            let led = CertLedger::open(dir.path(), None).unwrap();
            led.record_issued(&entry("fpA", "dev1"), false).unwrap();
            led.mark_revoked("fpA", "operator").unwrap();
        }

        std::fs::write(&crl, "# stale\n").unwrap();
        let reopened = CertLedger::open(dir.path(), None).unwrap();
        assert!(reopened.is_revoked("fpA").unwrap());
        let refreshed = std::fs::read_to_string(&crl).unwrap();
        assert_eq!(refreshed.trim(), "fpA");

        std::fs::remove_file(&crl).unwrap();
        let reopened = CertLedger::open(dir.path(), None).unwrap();
        assert!(reopened.is_revoked("fpA").unwrap());
        let refreshed = std::fs::read_to_string(&crl).unwrap();
        assert_eq!(refreshed.trim(), "fpA");
    }

    #[test]
    fn record_issued_propagates_certificate_audit_write_failure() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLogger::new(
            AuditConfig {
                enabled: true,
                log_path: "missing/audit.log".to_string(),
                max_size_mb: 100,
                sign_events: false,
            },
            dir.path().to_path_buf(),
        )
        .unwrap();
        let led = CertLedger::open_in_memory(Some(Arc::new(audit))).unwrap();

        let err = led
            .record_issued(&entry("fp1", "dev1"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("certificate audit event"), "got: {err}");
    }

    #[test]
    fn record_issued_audits_an_attempt_then_a_completion() {
        let dir = tempfile::tempdir().unwrap();
        let (audit, log) = audit_logger(dir.path());
        let led = CertLedger::open_in_memory(Some(audit)).unwrap();

        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        led.record_issued(&entry("fp2", "dev1"), true).unwrap();

        let events = audit_events(&log);
        let names: Vec<String> = events.iter().map(type_name).collect();
        assert_eq!(
            names,
            [
                "cert_issuance_attempted",
                "cert_issued",
                "cert_issuance_attempted",
                "cert_renewed",
            ],
            "each issuance is an attempt followed by its completion"
        );
        // The attempt claims no outcome and names the completion it is waiting
        // on; only the post-commit event records success.
        assert!(events[0].result.is_none(), "an attempt records no outcome");
        assert!(events[2].result.is_none(), "an attempt records no outcome");
        assert!(command_of(&events[0]).starts_with("attempt=issue fingerprint=fp1 "));
        assert!(command_of(&events[2]).starts_with("attempt=renew fingerprint=fp2 "));
        assert!(events[1].result.as_ref().unwrap().success);
        assert!(events[3].result.as_ref().unwrap().success);
        assert!(command_of(&events[1]).starts_with("fingerprint=fp1 "));
        assert!(command_of(&events[3]).starts_with("fingerprint=fp2 "));
        // The chain sequence is the append order: no completion precedes its attempt.
        assert!(events[0].sequence < events[1].sequence);
        assert!(events[2].sequence < events[3].sequence);
    }

    #[test]
    fn record_issued_ledger_failure_leaves_an_attempt_with_no_completion() {
        // Forced SQLite failure AFTER the audit write. Renaming the INSERT
        // target away is the least invasive stand-in for any commit-time
        // failure (full disk, corruption, lock timeout) and needs no production
        // injection hook. The pre-commit event must not have claimed issuance.
        let dir = tempfile::tempdir().unwrap();
        let (audit, log) = audit_logger(dir.path());
        let led = CertLedger::open_in_memory(Some(audit)).unwrap();
        led.detach_issued_certs_for_test().unwrap();

        let err = led
            .record_issued(&entry("fp1", "dev1"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("insert issued cert"), "got: {err}");

        let events = audit_events(&log);
        let names: Vec<String> = events.iter().map(type_name).collect();
        assert_eq!(
            names,
            ["cert_issuance_attempted"],
            "a failed ledger write must leave an attempt, never a completion"
        );
        assert!(events[0].result.is_none(), "an attempt records no outcome");

        // Nothing usable was delivered: the caller got the retryable error, so
        // it never hands the certificate over, and no row backs that fingerprint.
        led.reattach_issued_certs_for_test().unwrap();
        assert_eq!(led.status_of("fp1").unwrap(), None);
        assert!(led.list_active().unwrap().is_empty());

        // The retry completes, and the completion event is what marks it so.
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        let names: Vec<String> = audit_events(&log).iter().map(type_name).collect();
        assert_eq!(
            names,
            [
                "cert_issuance_attempted",
                "cert_issuance_attempted",
                "cert_issued",
            ]
        );
        assert_eq!(led.status_of("fp1").unwrap(), Some(CertStatus::Active));
    }

    #[test]
    fn completion_audit_failure_publishes_no_certificate_and_no_duplicate_on_retry() {
        // The blocking case. The ATTEMPT event lands, the row commits, and the
        // COMPLETION event fails. Before the pending -> active protocol this
        // returned Err with an ACTIVE row already committed for a certificate
        // the caller never delivered; because the client's retry carries a
        // fresh CSR - and so a different fingerprint - the retry then added a
        // SECOND active credential instead of replacing the first.
        let dir = tempfile::tempdir().unwrap();
        let (audit, log) = audit_logger(dir.path());
        let led = CertLedger::open(dir.path(), Some(audit.clone())).unwrap();

        // Let the attempt write land; fail every write after it. This is the
        // one fault an external manipulation of the log file cannot produce:
        // both writes happen inside a single record_issued call.
        audit.fail_writes_after_for_test(1);
        let err = led
            .record_issued(&entry("fp1", "dev1"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("certificate audit event"), "got: {err}");

        // The trail holds the attempt and no completion.
        let names: Vec<String> = audit_events(&log).iter().map(type_name).collect();
        assert_eq!(
            names,
            ["cert_issuance_attempted"],
            "a failed completion write must not leave a completion event"
        );

        // Nothing was published: no status, no row to look up, no active list
        // entry, and no revocation state for a fingerprint nobody holds.
        assert_eq!(
            led.status_of("fp1").unwrap(),
            None,
            "an undelivered certificate must not be Active - or known at all"
        );
        assert!(led.lookup_by_fingerprint("fp1").unwrap().is_none());
        assert!(!led.is_revoked("fp1").unwrap());
        assert!(led.list_active().unwrap().is_empty());
        // The compensating delete removed the row; it did not merely hide it.
        assert!(
            stored_rows(dir.path()).is_empty(),
            "the staged row must be compensated away, got: {:?}",
            stored_rows(dir.path())
        );

        // The retry - a fresh CSR, so a fresh fingerprint, as the real client
        // does - completes, and leaves exactly ONE active credential.
        audit.clear_write_failure_for_test();
        led.record_issued(&entry("fp2", "dev1"), false).unwrap();
        let active = led.list_active().unwrap();
        assert_eq!(active.len(), 1, "the retry must not multiply active rows");
        assert_eq!(active[0].fingerprint, "fp2");
        assert_eq!(led.status_of("fp1").unwrap(), None);
        let names: Vec<String> = audit_events(&log).iter().map(type_name).collect();
        assert_eq!(
            names,
            [
                "cert_issuance_attempted",
                "cert_issuance_attempted",
                "cert_issued",
            ],
            "the interrupted attempt stays unmatched; only the retry completes"
        );
    }

    #[test]
    fn completion_audit_failure_leaves_an_established_certificate_untouched() {
        // Re-recording a fingerprint the ledger already holds must not use the
        // established row as the compensation target: the certificate behind it
        // WAS delivered. A failed completion leaves it active with its original
        // validity, which is right - the caller is returning an error rather
        // than handing over the renewed certificate.
        let dir = tempfile::tempdir().unwrap();
        let (audit, log) = audit_logger(dir.path());
        let led = CertLedger::open(dir.path(), Some(audit.clone())).unwrap();
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();

        let mut renewed = entry("fp1", "dev1");
        renewed.not_after = 9_999_999;
        audit.fail_writes_after_for_test(1);
        assert!(led.record_issued(&renewed, true).is_err());

        let held = led
            .lookup_by_fingerprint("fp1")
            .unwrap()
            .expect("the established certificate must survive");
        assert_eq!(held.status, CertStatus::Active);
        assert_eq!(
            held.not_after,
            1_000 + 30 * 86_400,
            "an undelivered renewal must not extend the established validity"
        );
        assert_eq!(led.list_active().unwrap().len(), 1);
        let names: Vec<String> = audit_events(&log).iter().map(type_name).collect();
        assert_eq!(
            names,
            [
                "cert_issuance_attempted",
                "cert_issued",
                "cert_issuance_attempted",
            ]
        );
    }

    #[test]
    fn open_reconciles_a_pending_row_left_by_a_crash() {
        // The crash window the compensating delete cannot cover: the process
        // dies between the ledger commit and the completion event. The flip out
        // of `pending` happens inside the same record_issued call, so any
        // pending row seen at open is stale by construction - an undelivered
        // certificate that must be resolved durably, not left to linger.
        let dir = tempfile::tempdir().unwrap();
        let (audit, log) = audit_logger(dir.path());
        {
            let led = CertLedger::open(dir.path(), Some(audit.clone())).unwrap();
            led.record_issued(&entry("fpDone", "dev1"), false).unwrap();
        }
        stage_pending_row(dir.path(), "fpCrash", "dev2");
        assert!(
            stored_rows(dir.path()).contains(&("fpCrash".to_string(), "pending".to_string())),
            "fixture must actually commit a pending row"
        );

        let reopened = CertLedger::open(dir.path(), Some(audit)).unwrap();

        // Resolved durably, and it never surfaces as a credential on the way.
        assert_eq!(reopened.status_of("fpCrash").unwrap(), None);
        assert!(reopened.lookup_by_fingerprint("fpCrash").unwrap().is_none());
        assert!(!reopened.is_revoked("fpCrash").unwrap());
        assert_eq!(
            stored_rows(dir.path()),
            vec![("fpDone".to_string(), "active".to_string())],
            "the stranded row is gone; the completed issuance is untouched"
        );
        let active: Vec<String> = reopened
            .list_active()
            .unwrap()
            .into_iter()
            .map(|e| e.fingerprint)
            .collect();
        assert_eq!(active, ["fpDone"]);

        // And the trail explains the stranded attempt rather than leaving the
        // reader to infer it from a missing completion.
        let events = audit_events(&log);
        let names: Vec<String> = events.iter().map(type_name).collect();
        assert_eq!(
            names,
            [
                "cert_issuance_attempted",
                "cert_issued",
                "cert_issuance_abandoned",
            ]
        );
        let abandoned = events.last().unwrap();
        assert!(
            command_of(abandoned).starts_with("abandoned=reconcile fingerprint=fpCrash "),
            "got: {}",
            command_of(abandoned)
        );
        let result = abandoned
            .result
            .as_ref()
            .expect("a reconciliation has a settled outcome");
        assert!(
            !result.success,
            "the reconciliation must record a FAILED issuance, not a completed one"
        );

        // Reconciliation is not a one-shot: a second open finds nothing left.
        let again = CertLedger::open(dir.path(), None).unwrap();
        assert_eq!(again.list_active().unwrap().len(), 1);
        assert_eq!(audit_events(&log).len(), 3);
    }

    #[test]
    fn a_pending_row_is_never_a_credential_for_any_reader() {
        // The consumer audit, executable: every reader that means "usable
        // credential" must refuse a pending row. Inserted after open, so it is
        // a live pending row rather than one reconciliation already removed.
        let dir = tempfile::tempdir().unwrap();
        let led = CertLedger::open(dir.path(), None).unwrap();
        stage_pending_row(dir.path(), "fpPending", "devP");

        assert_eq!(led.status_of("fpPending").unwrap(), None);
        assert!(led.lookup_by_fingerprint("fpPending").unwrap().is_none());
        assert!(led.device_of("fpPending").unwrap().is_none());
        assert!(!led.is_revoked("fpPending").unwrap());
        assert!(led.list_active().unwrap().is_empty());
        assert!(led.revoked_fingerprints().unwrap().is_empty());
        assert!(
            !led.mark_revoked("fpPending", "operator").unwrap(),
            "a pending row is not revocable: it is not a credential to revoke"
        );
        assert_eq!(led.revoke_device("devP", "operator").unwrap(), 0);
        // Refusing to revoke it did not quietly flip it either.
        assert_eq!(
            stored_rows(dir.path()),
            vec![("fpPending".to_string(), "pending".to_string())]
        );
        // And the enforcement file the WSS verifier reads stays empty.
        let crl = std::fs::read_to_string(revoked_list_path(dir.path())).unwrap_or_default();
        assert!(crl.trim().is_empty());
    }

    #[test]
    fn revoke_device_revokes_all_its_active_certs() {
        let led = CertLedger::open_in_memory(None).unwrap();
        led.record_issued(&entry("fp1", "dev1"), false).unwrap();
        led.record_issued(&entry("fp2", "dev1"), true).unwrap();
        led.record_issued(&entry("fp3", "dev2"), false).unwrap();
        assert_eq!(led.revoke_device("dev1", "operator").unwrap(), 2);
        assert!(led.is_revoked("fp1").unwrap());
        assert!(led.is_revoked("fp2").unwrap());
        assert!(!led.is_revoked("fp3").unwrap());
    }

    #[test]
    fn renewal_replaces_row_on_same_fingerprint() {
        let led = CertLedger::open_in_memory(None).unwrap();
        let mut e = entry("fp1", "dev1");
        led.record_issued(&e, false).unwrap();
        // A renewal that produces the same fingerprint just updates validity.
        e.not_after = 9_999_999;
        led.record_issued(&e, true).unwrap();
        let got = led.lookup_by_fingerprint("fp1").unwrap().unwrap();
        assert_eq!(got.not_after, 9_999_999);
        // Only one row exists for that fingerprint.
        assert_eq!(led.list_active().unwrap().len(), 1);
    }

    #[test]
    fn issuance_actor_labels() {
        assert_eq!(IssuanceActor::Operator.label(), "operator");
        assert_eq!(
            IssuanceActor::Enrollment {
                token_hash: "0123456789abcdef".to_string()
            }
            .label(),
            "enroll:01234567"
        );
    }
}
