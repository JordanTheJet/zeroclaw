//! Architecture gate: every HTTP route the gateway registers is classified
//! against the core's RPC surface, which is the coverage matrix the
//! gateway/core split works from
//! (`docs/book/src/architecture/gateway-ipc-coverage.md`).
//!
//! A source scan reads every `.route(..)` registration in the gateway crate,
//! with the HTTP methods its method router accepts, and checks them against
//! [`ROUTES`]. The gate fails when
//! - the gateway registers a route the table does not classify,
//! - the table classifies a route the gateway no longer registers, or
//! - an `Rpc` entry names a method missing from the runtime's own
//!   `Method::ALL`.
//!
//! The coverage document lists every entry, and the gate checks that too, so
//! the table and the document cannot drift apart. A route whose core method
//! exists only in an open pull request stays `Deferred` until that method
//! is on master.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use zeroclaw_runtime::rpc::dispatch::Method;

/// How the gateway/core split serves a route.
#[derive(Debug, Clone, Copy)]
enum Class {
    /// Served by these core methods, which exist on master. The match may be
    /// partial; the coverage document records what is missing.
    Rpc(&'static [&'static str]),
    /// Served by the gateway itself, with no core state involved.
    GatewayLocal(&'static str),
    /// Inbound webhook or channel traffic, to be verified in the core.
    Ingress,
    /// No core method on master yet: why, and what will serve it.
    Deferred(&'static str),
}

use Class::{Deferred, GatewayLocal, Ingress, Rpc};

impl Class {
    fn label(self) -> &'static str {
        match self {
            Rpc(_) => "rpc",
            GatewayLocal(_) => "gateway-local",
            Ingress => "ingress",
            Deferred(_) => "deferred",
        }
    }
}

/// Every route the gateway registers, by HTTP method and path pattern. `ANY`
/// is a method router's fallback.
#[rustfmt::skip]
const ROUTES: &[(&str, &str, Class)] = &[
    ("POST", "/webhook", Ingress),
    ("GET", "/ws/chat", Rpc(&["session/new", "session/prompt", "session/approve", "session/cancel", "sops/decide"])),
    ("GET", "/api/sessions", Rpc(&["session/list"])),
    ("GET", "/api/sessions/running", Deferred("pending #11132: session/list")),
    ("GET", "/api/sessions/{id}/messages", Rpc(&["session/messages"])),
    ("POST", "/api/sessions/{id}/messages", Deferred("pending #11132: session/append")),
    ("DELETE", "/api/sessions/{id}", Rpc(&["session/delete"])),
    ("PUT", "/api/sessions/{id}", Deferred("pending #11132: session/rename")),
    ("GET", "/api/sessions/{id}/state", Rpc(&["session/state"])),
    ("POST", "/api/sessions/{id}/abort", Deferred("pending #11132: session/abort")),
    ("GET", "/api/memory", Rpc(&["memory/list", "memory/search"])),
    ("POST", "/api/memory", Rpc(&["memory/store"])),
    ("DELETE", "/api/memory/{key}", Rpc(&["memory/delete"])),
    ("GET", "/api/cron", Rpc(&["cron/list"])),
    ("POST", "/api/cron", Rpc(&["cron/add"])),
    ("GET", "/api/cron/settings", Rpc(&["cron/settings"])),
    ("PATCH", "/api/cron/settings", Rpc(&["config/set-many", "cron/settings"])),
    ("DELETE", "/api/cron/{id}", Rpc(&["cron/delete"])),
    ("PATCH", "/api/cron/{id}", Rpc(&["cron/patch"])),
    ("GET", "/api/cron/{id}/runs", Rpc(&["cron/runs"])),
    ("POST", "/api/cron/{id}/run", Rpc(&["cron/trigger"])),
    ("GET", "/api/config", Rpc(&["config/get"])),
    ("PATCH", "/api/config", Rpc(&["config/set-many"])),
    ("OPTIONS", "/api/config", Deferred("proposed: config/schema")),
    ("GET", "/api/config/prop", Rpc(&["config/get"])),
    ("PUT", "/api/config/prop", Rpc(&["config/set"])),
    ("DELETE", "/api/config/prop", Rpc(&["config/delete"])),
    ("OPTIONS", "/api/config/prop", Deferred("proposed: config/schema")),
    ("GET", "/api/config/list", Rpc(&["config/list"])),
    ("GET", "/api/config/drift", Deferred("pending #11172: config/drift")),
    ("GET", "/api/config/reload-status", Deferred("pending #11172: config/reload-status")),
    ("GET", "/api/config/templates", Rpc(&["config/templates"])),
    ("GET", "/api/config/map-keys", Rpc(&["config/map-keys"])),
    ("GET", "/api/config/resolve-alias-source", Rpc(&["config/resolve-alias-source"])),
    ("POST", "/api/config/map-key", Rpc(&["config/map-key-create"])),
    ("DELETE", "/api/config/map-key", Rpc(&["config/map-key-delete"])),
    ("POST", "/api/config/rename-map-key", Rpc(&["config/map-key-rename"])),
    ("POST", "/api/config/model-providers/{type}/{alias}/refresh-context-window", Deferred("pending #11172: providers/refresh-context-window")),
    ("GET", "/api/config/delete-plan", Deferred("pending #11172: config/delete-plan")),
    ("GET", "/api/config/status", Rpc(&["config/status"])),
    ("GET", "/api/config/agent-options", Deferred("pending #11172: config/agent-options")),
    ("GET", "/api/config/sections", Rpc(&["config/sections"])),
    ("GET", "/api/config/sections/{section}", Deferred("pending #11172: config/section-picker")),
    ("POST", "/api/config/sections/{section}/items/{key}", Deferred("pending #11172: config/section-select")),
    ("POST", "/api/config/init", Deferred("pending #11172: config/init")),
    ("POST", "/api/config/migrate", Deferred("pending #11172: config/migrate")),
    ("GET", "/api/quickstart/state", Rpc(&["quickstart/state"])),
    ("POST", "/api/quickstart/fields", Rpc(&["quickstart/fields"])),
    ("POST", "/api/quickstart/validate", Rpc(&["quickstart/validate"])),
    ("POST", "/api/quickstart/apply", Rpc(&["quickstart/apply"])),
    ("POST", "/api/quickstart/dismiss", Rpc(&["quickstart/dismiss"])),
    ("GET", "/api/config/catalog", Rpc(&["config/catalog"])),
    ("GET", "/api/config/catalog/models", Rpc(&["config/catalog-models"])),
    ("GET", "/api/tools", Deferred("pending #11182: tools/list")),
    ("POST", "/api/tools/param-options", Rpc(&["tools/param-options"])),
    ("GET", "/api/integrations", Deferred("pending #11182: integrations/list")),
    ("GET", "/api/integrations/settings", Deferred("pending #11182: integrations/list")),
    ("GET", "/api/cli-tools", Deferred("pending #11182: tools/cli-discover")),
    ("GET", "/admin/sop/pending", Rpc(&["sops/runs"])),
    ("GET", "/admin/sop/logs", Rpc(&["logs/query"])),
    ("POST", "/admin/sop/approve", Rpc(&["sops/decide"])),
    ("POST", "/admin/sop/deny", Rpc(&["sops/decide"])),
    ("POST", "/sop/{*rest}", Ingress),
    ("GET", "/api/sops", Rpc(&["sops/list"])),
    ("POST", "/api/sops", Rpc(&["sops/create"])),
    ("PUT", "/api/sops/{name}", Rpc(&["sops/save"])),
    ("DELETE", "/api/sops/{name}", Rpc(&["sops/delete"])),
    ("GET", "/api/sops/{name}/graph", Rpc(&["sops/graph"])),
    ("POST", "/api/sops/{name}/run", Rpc(&["sops/run"])),
    ("POST", "/api/sops/{name}/rename", Rpc(&["sops/rename"])),
    ("GET", "/api/sops/runs", Rpc(&["sops/runs"])),
    ("GET", "/api/sops/{name}/full", Rpc(&["sops/get"])),
    ("POST", "/api/sops/wire-draft", Rpc(&["sops/wire-draft"])),
    ("POST", "/api/sops/graph-draft", Rpc(&["sops/graph-draft"])),
    ("GET", "/api/sops/trigger-sources", Rpc(&["sops/trigger-sources"])),
    ("GET", "/api/sops/decision-models", Deferred("pending #11169: sops/decision-models")),
    ("GET", "/api/sops/graph-legend", Deferred("pending #11169: sops/graph-legend")),
    ("GET", "/api/sops/{name}/runs/{run_id}/overlay", Rpc(&["sops/run-overlay"])),
    ("POST", "/api/sops/{name}/runs/{run_id}/decide", Rpc(&["sops/decide"])),
    ("POST", "/api/sops/{name}/runs/{run_id}/cancel", Deferred("pending #11169: sops/cancel")),
    ("GET", "/ws/sops/runs", Deferred("proposed: sops/subscribe-runs, sops/run-changed")),
    ("GET", "/api/agents/{alias}/skills", Deferred("pending #11176: skills/effective")),
    ("GET", "/api/skills/bundles", Rpc(&["skills/bundles"])),
    ("GET", "/api/skills/slash-option-kinds", Deferred("pending #11176: skills/slash-option-kinds")),
    ("GET", "/api/skills/bundles/{alias}/skills", Rpc(&["skills/list"])),
    ("POST", "/api/skills/bundles/{alias}/skills", Deferred("pending #11176: skills/create")),
    ("GET", "/api/skills/bundles/{alias}/skills/{name}", Rpc(&["skills/read"])),
    ("PUT", "/api/skills/bundles/{alias}/skills/{name}", Rpc(&["skills/write"])),
    ("DELETE", "/api/skills/bundles/{alias}/skills/{name}", Rpc(&["skills/delete"])),
    ("GET", "/api/personality", Rpc(&["personality/list"])),
    ("GET", "/api/personality/templates", Rpc(&["personality/templates"])),
    ("GET", "/api/personality/{filename}", Rpc(&["personality/get"])),
    ("PUT", "/api/personality/{filename}", Rpc(&["personality/put"])),
    ("GET", "/api/browse", Rpc(&["fs/list_dir"])),
    ("POST", "/api/browse/mkdir", Deferred("pending #11182: fs/mkdir")),
    ("DELETE", "/api/browse/rmdir", Deferred("pending #11182: fs/rmdir")),
    ("GET", "/api/agents/{alias}/workspace/list", Deferred("pending #11182: workspace/list")),
    ("GET", "/api/agents/{alias}/workspace/read", Deferred("pending #11182: fs/read")),
    ("DELETE", "/api/agents/{alias}/workspace/path", Deferred("pending #11182: fs/delete")),
    ("POST", "/api/agents/{alias}/workspace/move", Deferred("pending #11182: fs/move")),
    ("POST", "/api/agents/{alias}/workspace/mkdir", Deferred("pending #11182: fs/mkdir")),
    ("POST", "/api/upload", Rpc(&["file/upload/begin", "file/upload/chunk", "file/upload/commit", "file/attach"])),
    ("GET", "/api/logs", Rpc(&["logs/query"])),
    ("GET", "/api/events", Rpc(&["events/subscribe", "logs/subscribe"])),
    ("GET", "/api/events/history", Rpc(&["events/history"])),
    ("GET", "/api/cost", Rpc(&["cost/query"])),
    ("GET", "/api/status", Rpc(&["status", "agents/status"])),
    ("GET", "/api/tuis", Rpc(&["tui/list"])),
    ("GET", "/health", Rpc(&["health"])),
    ("GET", "/metrics", Deferred("pending #11182: metrics/scrape")),
    ("POST", "/admin/shutdown", GatewayLocal("served by the gateway itself")),
    ("POST", "/admin/reload", Rpc(&["config/reload"])),
    ("GET", "/api/health", Rpc(&["health"])),
    ("GET", "/api/version/check", Deferred("proposed: system/version-check")),
    ("POST", "/api/version/upgrade", Deferred("pending #11182: system/upgrade")),
    ("GET", "/api/version/upgrade/status", Deferred("pending #11182: system/upgrade-status")),
    ("GET", "/api/doctor", Rpc(&["doctor/run"])),
    ("POST", "/api/doctor", Rpc(&["doctor/run"])),
    ("GET", "/admin/paircode", Deferred("proposed: pairing/code")),
    ("POST", "/admin/paircode/new", Deferred("pending #11182: pairing/new-code, pairing/revoke")),
    ("POST", "/pair", Deferred("proposed: pairing/redeem")),
    ("GET", "/pair/code", Deferred("proposed: PairingPosture.require_pairing")),
    ("POST", "/api/pairing/initiate", Deferred("pending #11182: pairing/new-code")),
    ("POST", "/api/pair", Deferred("proposed: pairing/redeem")),
    ("GET", "/api/devices", Deferred("pending #11182: pairing/list")),
    ("POST", "/api/devices/me/capabilities", Deferred("proposed: pairing/device-capabilities")),
    ("DELETE", "/api/devices/{id}", Deferred("pending #11182: pairing/revoke")),
    ("POST", "/api/devices/{id}/token/rotate", Deferred("pending #11182: pairing/revoke, pairing/new-code")),
    ("GET", "/api/oidc/providers", Deferred("decision D10: OIDC relay")),
    ("POST", "/api/oidc/{alias}/device/start", Deferred("decision D10: OIDC relay")),
    ("POST", "/api/oidc/{alias}/device/poll", Deferred("decision D10: OIDC relay")),
    ("GET", "/oidc/login/{alias}", Deferred("decision D10: OIDC relay")),
    ("GET", "/oidc/callback", Deferred("decision D10: OIDC relay")),
    ("POST", "/api/webauthn/register/start", Deferred("decision D10: WebAuthn")),
    ("POST", "/api/webauthn/register/finish", Deferred("decision D10: WebAuthn")),
    ("POST", "/api/webauthn/auth/start", Deferred("decision D10: WebAuthn")),
    ("POST", "/api/webauthn/auth/finish", Deferred("decision D10: WebAuthn")),
    ("GET", "/api/webauthn/credentials", Deferred("decision D10: WebAuthn")),
    ("DELETE", "/api/webauthn/credentials/{id}", Deferred("decision D10: WebAuthn")),
    ("GET", "/whatsapp", Ingress),
    ("POST", "/whatsapp", Ingress),
    ("GET", "/whatsapp/{alias}", Ingress),
    ("POST", "/whatsapp/{alias}", Ingress),
    ("POST", "/linq", Ingress),
    ("POST", "/linq/{alias}", Ingress),
    ("POST", "/nextcloud-talk", Ingress),
    ("POST", "/nextcloud-talk/{alias}", Ingress),
    ("POST", "/webhook/gmail", Ingress),
    ("GET", "/api/channels", Deferred("pending #11182: channels/list")),
    ("POST", "/api/channels/{channel}/relink", Deferred("pending #11182: channels/relink")),
    ("POST", "/api/channels/bind", Deferred("pending #11182: channels/bind")),
    ("GET", "/api/plugins", Deferred("pending #11182: plugins/list")),
    ("GET", "/plugin/{path}", Ingress),
    ("POST", "/plugin/{path}", Ingress),
    ("GET", "/.well-known/agents-card.json", Deferred("pending #11182: a2a/identity")),
    ("GET", "/a2a/.well-known/agents-card.json", Deferred("pending #11182: a2a/identity")),
    ("GET", "/a2a/{alias}/.well-known/agent-card.json", Deferred("pending #11182: a2a/identity")),
    ("POST", "/a2a/{alias}", Deferred("pending #11132: session/run-once")),
    ("GET", "/acp", Deferred("decision D10: ACP")),
    ("GET", "/ws/nodes", Deferred("decision D10: nodes")),
    ("GET", "/api/canvas", Deferred("pending #11182: canvas/list")),
    ("GET", "/api/canvas/{id}", Deferred("pending #11182: canvas/get")),
    ("POST", "/api/canvas/{id}", Deferred("pending #11182: canvas/render")),
    ("DELETE", "/api/canvas/{id}", Deferred("pending #11182: canvas/clear")),
    ("GET", "/api/canvas/{id}/history", Deferred("pending #11182: canvas/history")),
    ("GET", "/ws/canvas/{id}", Deferred("proposed: canvas/subscribe, canvas/frame")),
    ("GET", "/_app/", GatewayLocal("served by the gateway itself")),
    ("GET", "/_app/{*path}", GatewayLocal("served by the gateway itself")),
    ("GET", "/api/openapi.json", GatewayLocal("served by the gateway itself")),
    ("GET", "/api/docs", GatewayLocal("served by the gateway itself")),
    ("POST", "/hooks/claude-code", GatewayLocal("served by the gateway itself")),
    ("HEAD", "/plugin/{path}", GatewayLocal("405 for unsupported methods")),
    ("ANY", "/plugin/{path}", GatewayLocal("405 for unsupported methods")),
];

/// Registrations whose path is only known at runtime, by the source
/// expression that builds it.
const DYNAMIC: &[(&str, &str)] = &[(
    "&format!(\"{prefix}/\")",
    "redirect from the configured gateway.path_prefix",
)];

const GATEWAY_SRC: &str = "crates/zeroclaw-gateway/src";
const COVERAGE_DOC: &str = "docs/book/src/architecture/gateway-ipc-coverage.md";

const HTTP_METHODS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
    ("options", "OPTIONS"),
    ("head", "HEAD"),
    ("fallback", "ANY"),
];

/// A route registration's path: known, or built at runtime by the source
/// expression recorded here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RoutePath {
    Known(String),
    Dynamic(String),
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && path.file_name().is_some_and(|name| name != "tests.rs")
        {
            out.push(path);
        }
    }
}

/// If a string, raw string or character literal starts at `i`, the index
/// just past it.
fn literal_end(bytes: &[u8], i: usize) -> Option<usize> {
    let ident_before = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
    match bytes[i] {
        b'"' => {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            Some((j + 1).min(bytes.len()))
        }
        b'r' if !ident_before => {
            let hashes = bytes[i + 1..].iter().take_while(|b| **b == b'#').count();
            if bytes.get(i + 1 + hashes) != Some(&b'"') {
                return None;
            }
            let mut j = i + 2 + hashes;
            while j < bytes.len() {
                if bytes[j] == b'"'
                    && bytes[j + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|b| **b == b'#')
                        .count()
                        == hashes
                {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(bytes.len())
        }
        b'\'' => match (bytes.get(i + 1), bytes.get(i + 2), bytes.get(i + 3)) {
            (Some(b'\\'), Some(_), Some(b'\'')) => Some(i + 4),
            (Some(c), Some(b'\''), _) if *c != b'\\' => Some(i + 3),
            _ => None,
        },
        _ => None,
    }
}

/// `src` with comments removed and literals kept.
fn without_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = literal_end(bytes, i) {
            out.push_str(&src[i..end]);
            i = end;
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            let ch = src[i..].chars().next().expect("in bounds");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// The index just past the delimiter that closes the one opened before
/// `from`, skipping literals and nested pairs of the same kind.
fn closing(src: &str, from: usize, open: u8, close: u8) -> usize {
    let bytes = src.as_bytes();
    let mut depth = 1usize;
    let mut i = from;
    while i < bytes.len() {
        if let Some(end) = literal_end(bytes, i) {
            i = end;
            continue;
        }
        if bytes[i] == open {
            depth += 1;
        } else if bytes[i] == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    panic!("unbalanced delimiters after offset {from}");
}

/// The index just past the bracket pair that opens at `i`, if one does.
fn pair_end(src: &str, i: usize) -> Option<usize> {
    let (open, close) = match src.as_bytes()[i] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    Some(closing(src, i + 1, open, close))
}

/// Whether a `#[cfg(..)]` attribute names the `test` predicate, ignoring
/// quoted feature names such as `"test-util"`.
fn cfg_names_test(attr: &str) -> bool {
    let mut unquoted = String::new();
    let mut quoted = false;
    for ch in attr.chars() {
        if ch == '"' {
            quoted = !quoted;
        } else if !quoted {
            unquoted.push(ch);
        }
    }
    unquoted
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|token| token == "test")
}

/// `src` without the bodies of modules compiled only for tests.
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(") {
        let attr_end = closing(rest, at + "#[".len(), b'[', b']');
        let attr = &rest[at..attr_end];
        out.push_str(&rest[..at]);
        let after = rest[attr_end..].trim_start();
        let module = after
            .strip_prefix("pub(crate) ")
            .or_else(|| after.strip_prefix("pub "))
            .unwrap_or(after);
        if cfg_names_test(attr)
            && let Some(module) = module.strip_prefix("mod ")
            && let Some(brace) = module.find('{')
            && !module[..brace].contains(';')
        {
            let body_start = rest.len() - module.len() + brace + 1;
            rest = &rest[closing(rest, body_start, b'{', b'}')..];
            continue;
        }
        out.push_str(attr);
        rest = &rest[attr_end..];
    }
    out.push_str(rest);
    out
}

/// `const NAME: &str = "value";` declarations in `src`.
fn string_consts(src: &str) -> HashMap<String, String> {
    let mut consts = HashMap::new();
    for line in src.lines() {
        let line = line.trim_start();
        let line = line.strip_prefix("pub(crate) ").unwrap_or(line);
        let line = line.strip_prefix("pub ").unwrap_or(line);
        let Some(decl) = line.strip_prefix("const ") else {
            continue;
        };
        let Some((name, value)) = decl.split_once(": &str = \"") else {
            continue;
        };
        if let Some(value) = value.strip_suffix("\";") {
            consts.insert(name.trim().to_owned(), value.to_owned());
        }
    }
    consts
}

/// Resolve a route's path argument: a literal, a string constant, or a
/// `format!` over constants. Anything else is reported as dynamic.
fn resolve_path(arg: &str, consts: &HashMap<String, String>) -> RoutePath {
    let arg = arg.trim();
    if let Some(literal) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
        return RoutePath::Known(literal.to_owned());
    }
    if let Some(value) = consts.get(arg) {
        return RoutePath::Known(value.clone());
    }
    let Some(template) = arg
        .strip_prefix("&format!(\"")
        .and_then(|a| a.strip_suffix("\")"))
    else {
        return RoutePath::Dynamic(arg.to_owned());
    };
    let mut path = String::new();
    let mut rest = template;
    while let Some(ch) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix("{{") {
            path.push('{');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("}}") {
            path.push('}');
            rest = after;
        } else if ch == '{' {
            let Some(end) = rest.find('}') else {
                return RoutePath::Dynamic(arg.to_owned());
            };
            match consts.get(&rest[1..end]) {
                Some(value) => path.push_str(value),
                None => return RoutePath::Dynamic(arg.to_owned()),
            }
            rest = &rest[end + 1..];
        } else {
            path.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    RoutePath::Known(path)
}

/// HTTP methods a method-router expression accepts: the routing calls at its
/// top level (`get(..)`, `.post(..)`, `.fallback(..)`), not calls nested in
/// their arguments.
fn router_methods(expr: &str) -> BTreeSet<&'static str> {
    let bytes = expr.as_bytes();
    let mut methods = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = literal_end(bytes, i).or_else(|| pair_end(expr, i)) {
            i = end;
            continue;
        }
        let word_start = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if word_start {
            for (call, method) in HTTP_METHODS {
                if bytes[i..].starts_with(call.as_bytes())
                    && bytes.get(i + call.len()) == Some(&b'(')
                {
                    methods.insert(*method);
                }
            }
        }
        i += 1;
    }
    methods
}

/// The first comma at the top level of a call's argument list.
fn top_level_comma(args: &str) -> Option<usize> {
    let bytes = args.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = literal_end(bytes, i).or_else(|| pair_end(args, i)) {
            i = end;
            continue;
        }
        if bytes[i] == b',' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Every `(method, path)` the source registers through `.route(..)`.
fn registrations(src: &str) -> BTreeSet<(&'static str, RoutePath)> {
    let code = without_test_modules(&without_comments(src));
    let consts = string_consts(&code);
    let bytes = code.as_bytes();
    let mut found = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = literal_end(bytes, i) {
            i = end;
            continue;
        }
        if !bytes[i..].starts_with(b".route(") {
            i += 1;
            continue;
        }
        let args_start = i + ".route(".len();
        let args_end = closing(&code, args_start, b'(', b')') - 1;
        let args = &code[args_start..args_end];
        let split = top_level_comma(args).expect("route takes a path and a method router");
        let path = resolve_path(&args[..split], &consts);
        for method in router_methods(&args[split + 1..]) {
            found.insert((method, path.clone()));
        }
        i = args_end;
    }
    found
}

fn gateway_registrations() -> BTreeSet<(&'static str, RoutePath)> {
    let mut files = Vec::new();
    rust_files(&repo_root().join(GATEWAY_SRC), &mut files);
    files
        .iter()
        .flat_map(|file| {
            let src =
                fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
            registrations(&src)
        })
        .collect()
}

#[test]
fn every_gateway_route_is_classified_against_the_core() {
    let registered = gateway_registrations();
    assert!(
        registered.len() > 150,
        "the scan should find the gateway's router, found {}",
        registered.len()
    );
    let classified: BTreeSet<(&str, &str)> = ROUTES
        .iter()
        .map(|(method, path, _)| (*method, *path))
        .collect();
    assert_eq!(
        classified.len(),
        ROUTES.len(),
        "a route is classified twice"
    );

    let unclassified: Vec<String> = registered
        .iter()
        .filter_map(|(method, path)| match path {
            RoutePath::Known(path) if !classified.contains(&(*method, path.as_str())) => {
                Some(format!("{method} {path}"))
            }
            RoutePath::Dynamic(expr) if !DYNAMIC.iter().any(|(known, _)| known == expr) => {
                Some(format!("{method} {expr}"))
            }
            _ => None,
        })
        .collect();
    assert!(
        unclassified.is_empty(),
        "classify these gateway routes in ROUTES and in {COVERAGE_DOC}: {unclassified:#?}"
    );

    let known: BTreeSet<(&str, &str)> = registered
        .iter()
        .filter_map(|(method, path)| match path {
            RoutePath::Known(path) => Some((*method, path.as_str())),
            RoutePath::Dynamic(_) => None,
        })
        .collect();
    let gone: Vec<String> = classified
        .iter()
        .filter(|route| !known.contains(route))
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert!(
        gone.is_empty(),
        "remove these routes, which the gateway no longer registers, from ROUTES and {COVERAGE_DOC}: {gone:#?}"
    );
    for (expr, _) in DYNAMIC {
        assert!(
            registered
                .iter()
                .any(|(_, path)| *path == RoutePath::Dynamic((*expr).to_owned())),
            "the dynamic registration {expr} is gone; remove it from DYNAMIC"
        );
    }
}

#[test]
fn every_rpc_entry_names_a_method_the_core_serves() {
    let served: BTreeSet<&str> = Method::ALL.iter().map(|(_, wire)| *wire).collect();
    let missing: Vec<String> = ROUTES
        .iter()
        .filter_map(|(method, path, class)| match class {
            Rpc([]) => Some(format!("{method} {path}: no method")),
            Rpc(methods) => {
                let absent: Vec<&str> = methods
                    .iter()
                    .copied()
                    .filter(|wire| !served.contains(wire))
                    .collect();
                (!absent.is_empty()).then(|| format!("{method} {path}: {absent:?}"))
            }
            GatewayLocal(reason) | Deferred(reason) if reason.is_empty() => {
                Some(format!("{method} {path}: no reason"))
            }
            _ => None,
        })
        .collect();
    assert!(
        missing.is_empty(),
        "Rpc entries must name methods in Method::ALL (use Deferred for methods \
         that exist only in open pull requests): {missing:#?}"
    );
}

#[test]
fn the_coverage_document_lists_every_classified_route() {
    let doc = fs::read_to_string(repo_root().join(COVERAGE_DOC))
        .unwrap_or_else(|e| panic!("read {COVERAGE_DOC}: {e}"));
    let rows = doc
        .lines()
        .filter(|line| {
            line.split_once(' ').is_some_and(|(_, rest)| {
                HTTP_METHODS
                    .iter()
                    .any(|(_, m)| rest.starts_with(&format!("{m} `")))
            })
        })
        .count();
    assert_eq!(
        rows,
        ROUTES.len() + DYNAMIC.len(),
        "{COVERAGE_DOC} must have one row per classified route"
    );
    let missing: Vec<String> = ROUTES
        .iter()
        .map(|(method, path, class)| format!("| {method} `{path}` | {} |", class.label()))
        .filter(|row| !doc.contains(row.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "{COVERAGE_DOC} disagrees with ROUTES on: {missing:#?}"
    );
}

#[test]
fn the_scanner_reads_methods_and_skips_comments_and_test_modules() {
    let src = r##"
        const CARD: &str = "/card";
        const QUOTE: char = '"';
        const RAW: &str = r#"{"route": ".route(\"/raw\", get(x))"}"#;
        fn router() {
            Router::new()
                // .route("/commented", get(gone))
                .route("/a/{id}", get(read).patch(update).layer(x.get(1)))
                .route(CARD, post(|| async { headers.get("x") }))
                .route(&format!("/n/{{alias}}{CARD}"), delete(remove))
                .route(&format!("{prefix}/"), get(redirect))
                .route("/p", get(h).head(u).fallback(u));
        }
        #[cfg(feature = "test-util")]
        mod helpers {
            fn h() { Router::new().route("/kept", put(h)); }
        }
        #[cfg(test)]
        mod tests {
            fn t() { Router::new().route("/test-only", get(t)); }
        }
    "##;
    let found: Vec<String> = registrations(src)
        .into_iter()
        .map(|(method, path)| format!("{method} {path:?}"))
        .collect();
    assert_eq!(
        found,
        [
            "ANY Known(\"/p\")",
            "DELETE Known(\"/n/{alias}/card\")",
            "GET Known(\"/a/{id}\")",
            "GET Known(\"/p\")",
            "GET Dynamic(\"&format!(\\\"{prefix}/\\\")\")",
            "HEAD Known(\"/p\")",
            "PATCH Known(\"/a/{id}\")",
            "POST Known(\"/card\")",
            "PUT Known(\"/kept\")",
        ]
    );
}
