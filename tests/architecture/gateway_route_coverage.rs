//! Architecture gate: every HTTP route the gateway registers is classified
//! against the core's RPC surface, which is the coverage matrix the
//! gateway/core split works from
//! (`docs/book/src/architecture/gateway-ipc-coverage.md`).
//!
//! Axum cannot list a router's routes, so the inventory comes from the
//! gateway crate's source. It is parsed from `lib.rs` down its module tree,
//! leaving out code that exists only in test builds. Every router call that
//! registers something (`.route`, `.route_service`, a router's `.fallback`,
//! `.nest`, `.merge`) must resolve completely: its path to a literal, a string
//! constant wherever in the workspace it is declared, or a `format!` over
//! those, and its method router to Axum's method-router constructors. A
//! registration the scan cannot resolve fails the gate instead of dropping
//! out of the inventory. The gate also fails when
//! - the gateway registers a route [`ROUTES`] does not classify,
//! - [`ROUTES`] classifies a route the gateway no longer registers,
//! - an `Rpc` entry names a method missing from the runtime's own
//!   `Method::ALL`, or
//! - the coverage document's route table or counts differ from [`ROUTES`].
//!
//! A route whose core method exists only in an open pull request stays
//! `Deferred` until that method is on master.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprLit, ImplItem, Item, ItemMod, Lit, Meta, Stmt, Token, UseTree};

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

    /// The coverage document's third column.
    fn detail(self) -> String {
        match self {
            Rpc(methods) => methods
                .iter()
                .map(|method| format!("`{method}`"))
                .collect::<Vec<_>>()
                .join(", "),
            Ingress => "core-verified ingress (contract §12)".to_owned(),
            GatewayLocal(reason) | Deferred(reason) => reason.to_owned(),
        }
    }
}

/// Every route the gateway registers, by HTTP method and path pattern. `ANY`
/// is every method: `any(..)`, or a method router's `.fallback(..)`. A path
/// in angle brackets is decided at runtime: [`UNMATCHED`] is the router's
/// fallback for paths no route matches, and `<name>` is the value of the
/// variable `name`.
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
    ("GET", "<unmatched>", GatewayLocal("SPA fallback: the dashboard for unmatched paths")),
    ("GET", "<prefix>/", GatewayLocal("redirect from the configured `gateway.path_prefix`")),
];

/// Paths the gateway nests whole routers under. The nested routes are
/// scanned where they are registered; nesting only moves them.
const MOUNTS: &[(&str, &str)] = &[(
    "<prefix>",
    "the whole router, under the configured gateway.path_prefix",
)];

const GATEWAY_CRATE: &str = "zeroclaw_gateway";
const COVERAGE_DOC: &str = "docs/book/src/architecture/gateway-ipc-coverage.md";

/// The path of a router's own fallback, which answers every path no route
/// matches.
const UNMATCHED: &str = "<unmatched>";

/// Axum's method-router constructors and chain calls (and their `_service`
/// forms), with the HTTP method each adds.
const METHOD_ROUTERS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
    ("head", "HEAD"),
    ("options", "OPTIONS"),
    ("trace", "TRACE"),
    ("connect", "CONNECT"),
    ("any", "ANY"),
];

/// Method-router chain calls that add no method.
const METHOD_ROUTER_WRAPPERS: &[&str] = &["layer", "route_layer", "with_state"];

/// The `MethodFilter` constants `on(..)` takes.
const METHOD_FILTERS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Router calls that register a route, a fallback, a nested router or a
/// merged one.
const REGISTRATION_CALLS: &[&str] = &[
    "route",
    "route_service",
    "fallback",
    "fallback_service",
    "nest",
    "nest_service",
    "merge",
];

/// Where the scan reads source: the workspace, or the scanner test's
/// in-memory files.
struct Sources {
    root: PathBuf,
    files: Option<HashMap<PathBuf, String>>,
}

impl Sources {
    fn workspace() -> Self {
        Self {
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            files: None,
        }
    }

    fn read(&self, path: &Path) -> Option<String> {
        match &self.files {
            Some(files) => files.get(path).cloned(),
            None => fs::read_to_string(path).ok(),
        }
    }

    /// A workspace crate's root file, by crate name.
    fn crate_root(&self, krate: &str) -> PathBuf {
        self.root
            .join("crates")
            .join(krate.replace('_', "-"))
            .join("src")
            .join("lib.rs")
    }

    fn display(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// The value of a `#[cfg(..)]` predicate in a build without `test`: known,
/// or `None` when it depends on features or the target.
fn cfg_value(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let args = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok()?;
            let values: Vec<Option<bool>> = args.iter().map(cfg_value).collect();
            if list.path.is_ident("not") && values.len() == 1 {
                values[0].map(|value| !value)
            } else if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else {
                    values
                        .iter()
                        .all(|value| *value == Some(true))
                        .then_some(true)
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else {
                    values
                        .iter()
                        .all(|value| *value == Some(false))
                        .then_some(false)
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether an item with these attributes exists only in test builds: one of
/// its `#[cfg(..)]` predicates is false whenever `test` is. `cfg(not(test))`
/// and `cfg(any(test, feature = ".."))` can hold in a production build.
fn test_only(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .any(|attr| attr.parse_args::<Meta>().ok().as_ref().and_then(cfg_value) == Some(false))
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

/// A statement's attributes, which for an expression statement sit on the
/// expression.
fn stmt_attrs(stmt: &Stmt) -> &[Attribute] {
    match stmt {
        Stmt::Local(local) => &local.attrs,
        Stmt::Macro(mac) => &mac.attrs,
        Stmt::Item(_) => &[],
        Stmt::Expr(expr, _) => match expr {
            Expr::Assign(expr) => &expr.attrs,
            Expr::Async(expr) => &expr.attrs,
            Expr::Await(expr) => &expr.attrs,
            Expr::Block(expr) => &expr.attrs,
            Expr::Call(expr) => &expr.attrs,
            Expr::ForLoop(expr) => &expr.attrs,
            Expr::If(expr) => &expr.attrs,
            Expr::Loop(expr) => &expr.attrs,
            Expr::Macro(expr) => &expr.attrs,
            Expr::Match(expr) => &expr.attrs,
            Expr::MethodCall(expr) => &expr.attrs,
            Expr::Unsafe(expr) => &expr.attrs,
            Expr::While(expr) => &expr.attrs,
            _ => &[],
        },
    }
}

/// The names a `use` tree imports, each with the path it names, and the
/// paths it glob-imports.
fn flatten_use(
    tree: &UseTree,
    mut prefix: Vec<String>,
    uses: &mut Vec<(String, Vec<String>)>,
    globs: &mut Vec<Vec<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, uses, globs);
        }
        UseTree::Name(name) if name.ident == "self" => {
            if let Some(last) = prefix.last().cloned() {
                uses.push((last, prefix));
            }
        }
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            uses.push((name.ident.to_string(), prefix));
        }
        UseTree::Rename(rename) => {
            if rename.ident != "self" {
                prefix.push(rename.ident.to_string());
            }
            uses.push((rename.rename.to_string(), prefix));
        }
        UseTree::Glob(_) => globs.push(prefix),
        UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(tree, prefix.clone(), uses, globs);
            }
        }
    }
}

/// A module's string constants and imports, including those inside its
/// functions, but not its child modules' or its test-only code's.
#[derive(Default)]
struct Names {
    consts: HashMap<String, String>,
    uses: Vec<(String, Vec<String>)>,
    globs: Vec<Vec<String>>,
}

impl<'ast> Visit<'ast> for Names {
    fn visit_item(&mut self, item: &'ast Item) {
        if matches!(item, Item::Mod(_)) || test_only(item_attrs(item)) {
            return;
        }
        match item {
            Item::Const(item) => {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(value),
                    ..
                }) = &*item.expr
                {
                    self.consts.insert(item.ident.to_string(), value.value());
                }
            }
            Item::Use(item) if item.leading_colon.is_none() => {
                flatten_use(&item.tree, Vec::new(), &mut self.uses, &mut self.globs);
            }
            _ => visit::visit_item(self, item),
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if !test_only(stmt_attrs(stmt)) {
            visit::visit_stmt(self, stmt);
        }
    }
}

/// One parsed module and the names it declares.
struct Module {
    krate: String,
    path: Vec<String>,
    /// The file its items are in.
    file: PathBuf,
    /// The directory its `mod name;` children's files are in.
    dir: PathBuf,
    items: Vec<Item>,
    /// Its child modules outside test-only code.
    children: Vec<String>,
    consts: HashMap<String, String>,
    /// What its `use` items import, by name, as paths from a crate's root.
    uses: HashMap<String, Vec<String>>,
    /// The modules its `use path::*` items import from.
    globs: Vec<Vec<String>>,
}

impl Module {
    fn new(krate: &str, path: Vec<String>, file: PathBuf, dir: PathBuf, items: Vec<Item>) -> Self {
        let children = items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) if !test_only(&module.attrs) => Some(module.ident.to_string()),
                _ => None,
            })
            .collect();
        let mut names = Names::default();
        for item in &items {
            names.visit_item(item);
        }
        let mut module = Self {
            krate: krate.to_owned(),
            path,
            file,
            dir,
            items,
            children,
            consts: names.consts,
            uses: HashMap::new(),
            globs: Vec::new(),
        };
        module.uses = names
            .uses
            .into_iter()
            .map(|(name, path)| (name, module.absolute(&path)))
            .collect();
        module.globs = names
            .globs
            .iter()
            .map(|path| module.absolute(path))
            .collect();
        module
    }

    fn child(&self, name: &str) -> Option<&ItemMod> {
        self.items.iter().find_map(|item| match item {
            Item::Mod(module) if module.ident == name && !test_only(&module.attrs) => Some(module),
            _ => None,
        })
    }

    /// A path written in this module, as a path from its crate's root: the
    /// first segment of the result is a crate name.
    fn absolute(&self, segments: &[String]) -> Vec<String> {
        let Some((first, rest)) = segments.split_first() else {
            return Vec::new();
        };
        let mut base = vec![self.krate.clone()];
        match first.as_str() {
            "crate" => {}
            "self" => base.extend(self.path.iter().cloned()),
            "super" => {
                let mut path = self.path.clone();
                let mut rest = segments;
                while let Some(("super", after)) = rest
                    .split_first()
                    .map(|(first, after)| (first.as_str(), after))
                {
                    path.pop();
                    rest = after;
                }
                base.extend(path);
                base.extend(rest.iter().cloned());
                return base;
            }
            name if self.children.iter().any(|child| child == name) => {
                base.extend(self.path.iter().cloned());
                base.push(first.clone());
            }
            name if self.uses.contains_key(name) => base = self.uses[name].clone(),
            _ => base = vec![first.clone()],
        }
        base.extend(rest.iter().cloned());
        base
    }
}

/// A module by crate name and path within the crate.
type ModuleKey = (String, Vec<String>);

/// The workspace's crates, parsed one module at a time as the scan needs
/// them.
struct Workspace {
    sources: Sources,
    modules: RefCell<HashMap<ModuleKey, Result<Rc<Module>, String>>>,
}

impl Workspace {
    fn new(sources: Sources) -> Self {
        Self {
            sources,
            modules: RefCell::default(),
        }
    }

    fn parse(&self, file: &Path) -> Result<syn::File, String> {
        let source = self
            .sources
            .read(file)
            .ok_or_else(|| format!("cannot read {}", self.sources.display(file)))?;
        syn::parse_file(&source)
            .map_err(|error| format!("cannot parse {}: {error}", self.sources.display(file)))
    }

    /// The module at `path` in the workspace crate `krate`, unless the crate
    /// is not in the workspace or the module exists only in test builds.
    fn module(&self, krate: &str, path: &[String]) -> Result<Rc<Module>, String> {
        let key = (krate.to_owned(), path.to_vec());
        if let Some(cached) = self.modules.borrow().get(&key) {
            return cached.clone();
        }
        let loaded = self.load(krate, path).map(Rc::new);
        self.modules.borrow_mut().insert(key, loaded.clone());
        loaded
    }

    fn load(&self, krate: &str, path: &[String]) -> Result<Module, String> {
        let Some((name, parent_path)) = path.split_last() else {
            let file = self.sources.crate_root(krate);
            let parsed = self.parse(&file)?;
            let dir = file
                .parent()
                .expect("a crate root is in src/")
                .to_path_buf();
            let items = if test_only(&parsed.attrs) {
                Vec::new()
            } else {
                parsed.items
            };
            return Ok(Module::new(krate, Vec::new(), file, dir, items));
        };
        let parent = self.module(krate, parent_path)?;
        let declaration = parent
            .child(name)
            .ok_or_else(|| format!("{krate} has no module {}", path.join("::")))?;
        if let Some((_, items)) = &declaration.content {
            let dir = parent.dir.join(name);
            return Ok(Module::new(
                krate,
                path.to_vec(),
                parent.file.clone(),
                dir,
                items.clone(),
            ));
        }
        let explicit = declaration.attrs.iter().find_map(|attr| match &attr.meta {
            Meta::NameValue(value) if value.path.is_ident("path") => match &value.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(path),
                    ..
                }) => Some(path.value()),
                _ => None,
            },
            _ => None,
        });
        let file = match explicit {
            Some(relative) => parent
                .file
                .parent()
                .expect("a file has a directory")
                .join(relative),
            None => {
                let flat = parent.dir.join(format!("{name}.rs"));
                if self.sources.read(&flat).is_some() {
                    flat
                } else {
                    parent.dir.join(name).join("mod.rs")
                }
            }
        };
        let parsed = self.parse(&file)?;
        let dir = if file.file_name().is_some_and(|file| file == "mod.rs") {
            file.parent().expect("a file has a directory").to_path_buf()
        } else {
            file.with_extension("")
        };
        let items = if test_only(&parsed.attrs) {
            Vec::new()
        } else {
            parsed.items
        };
        Ok(Module::new(krate, path.to_vec(), file, dir, items))
    }

    /// The string constant at `path`, a path from a crate's root, following
    /// re-exports.
    fn constant(&self, path: &[String], depth: usize) -> Option<String> {
        if depth > 16 {
            return None;
        }
        let (krate, rest) = path.split_first()?;
        let (name, modules) = rest.split_last()?;
        let mut module = self.module(krate, &[]).ok()?;
        for (at, segment) in modules.iter().enumerate() {
            if module.children.contains(segment) {
                let mut next = module.path.clone();
                next.push(segment.clone());
                module = self.module(krate, &next).ok()?;
            } else {
                let mut target = module.uses.get(segment)?.clone();
                target.extend(modules[at + 1..].iter().cloned());
                target.push(name.clone());
                return self.constant(&target, depth + 1);
            }
        }
        self.lookup(&module, name, depth)
    }

    /// The string constant `name` as code inside `module` sees it.
    fn lookup(&self, module: &Module, name: &str, depth: usize) -> Option<String> {
        if let Some(value) = module.consts.get(name) {
            return Some(value.clone());
        }
        if let Some(target) = module.uses.get(name) {
            return self.constant(target, depth + 1);
        }
        module.globs.iter().find_map(|glob| {
            let mut target = glob.clone();
            target.push(name.to_owned());
            self.constant(&target, depth + 1)
        })
    }
}

/// What the scan found in the gateway's source.
#[derive(Debug, Default)]
struct Scan {
    /// `(method, path)` of every route, in [`ROUTES`]' notation.
    routes: BTreeSet<(String, String)>,
    /// The paths routers are nested under.
    mounts: BTreeSet<String>,
    /// Router calls the scan could not resolve, with where they are.
    unresolved: Vec<String>,
}

fn scan(sources: Sources) -> Scan {
    let workspace = Workspace::new(sources);
    let mut scan = Scan::default();
    scan_module(&workspace, &[], &mut scan);
    scan
}

fn scan_module(workspace: &Workspace, path: &[String], scan: &mut Scan) {
    let module = match workspace.module(GATEWAY_CRATE, path) {
        Ok(module) => module,
        Err(error) => {
            scan.unresolved.push(error);
            return;
        }
    };
    let mut registrations = Registrations {
        workspace,
        module: &module,
        scan,
    };
    for item in &module.items {
        registrations.visit_item(item);
    }
    for child in &module.children {
        let mut child_path = path.to_vec();
        child_path.push(child.clone());
        scan_module(workspace, &child_path, scan);
    }
}

/// The name of the Axum method-router constructor that `func` names (`get`,
/// `on`, `any_service`, ..), bare or through `routing::` or `axum::routing::`.
fn method_router_constructor(func: &Expr) -> Option<String> {
    let Expr::Path(path) = func else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let (name, prefix) = segments.split_last()?;
    let routing = matches!(
        prefix
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        [] | ["routing"] | ["axum", "routing"]
    );
    let known = http_method(name).is_some() || name == "on" || name == "on_service";
    (routing && known).then(|| name.clone())
}

fn http_method(call: &str) -> Option<&'static str> {
    let call = call.strip_suffix("_service").unwrap_or(call);
    METHOD_ROUTERS
        .iter()
        .find(|(name, _)| *name == call)
        .map(|(_, method)| *method)
}

/// Whether `expr` is a method-router chain: one that starts at an Axum
/// method-router constructor.
fn is_method_router(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => is_method_router(&call.receiver),
        Expr::Call(call) => method_router_constructor(&call.func).is_some(),
        Expr::Paren(expr) => is_method_router(&expr.expr),
        _ => false,
    }
}

/// The HTTP methods a method router accepts.
fn method_router(expr: &Expr) -> Result<BTreeSet<&'static str>, String> {
    match expr {
        Expr::Paren(expr) => method_router(&expr.expr),
        Expr::Call(call) => match method_router_constructor(&call.func) {
            Some(name) if name == "on" || name == "on_service" => method_filter(call.args.first()),
            Some(name) => Ok(http_method(&name).into_iter().collect()),
            None => Err("a method router the scan cannot read".to_owned()),
        },
        Expr::MethodCall(call) => {
            let mut methods = method_router(&call.receiver)?;
            match call.method.to_string().as_str() {
                wrapper if METHOD_ROUTER_WRAPPERS.contains(&wrapper) => {}
                "fallback" | "fallback_service" => {
                    methods.insert("ANY");
                }
                "on" | "on_service" => methods.extend(method_filter(call.args.first())?),
                name => match http_method(name) {
                    Some(method) => {
                        methods.insert(method);
                    }
                    None => return Err(format!("the method-router call `.{name}(..)`")),
                },
            }
            Ok(methods)
        }
        _ => Err("a method router the scan cannot read".to_owned()),
    }
}

/// The HTTP methods a `MethodFilter` expression names.
fn method_filter(expr: Option<&Expr>) -> Result<BTreeSet<&'static str>, String> {
    match expr {
        Some(Expr::Path(path)) => {
            let name = path.path.segments.last().map(|s| s.ident.to_string());
            METHOD_FILTERS
                .iter()
                .find(|method| Some(**method) == name.as_deref())
                .map(|method| BTreeSet::from([*method]))
                .ok_or_else(|| "a MethodFilter the scan cannot read".to_owned())
        }
        Some(Expr::MethodCall(call)) if call.method == "or" => {
            let mut methods = method_filter(Some(&call.receiver))?;
            methods.extend(method_filter(call.args.first())?);
            Ok(methods)
        }
        _ => Err("a MethodFilter the scan cannot read".to_owned()),
    }
}

/// The start of a call chain: the receiver of its first method call, or the
/// function a call calls.
fn chain_root(expr: &Expr) -> &Expr {
    match expr {
        Expr::MethodCall(call) => chain_root(&call.receiver),
        Expr::Call(call) => chain_root(&call.func),
        Expr::Paren(expr) => chain_root(&expr.expr),
        _ => expr,
    }
}

/// Whether a macro's tokens contain a router call, `.route(..)` and the like.
fn calls_registration(tokens: TokenStream) -> bool {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    tokens.iter().enumerate().any(|(at, token)| match token {
        TokenTree::Group(group) => calls_registration(group.stream()),
        TokenTree::Punct(punct) if punct.as_char() == '.' => matches!(
            (tokens.get(at + 1), tokens.get(at + 2)),
            (Some(TokenTree::Ident(name)), Some(TokenTree::Group(_)))
                if REGISTRATION_CALLS.iter().any(|call| name == call)
        ),
        _ => false,
    })
}

/// Records the router calls in one gateway module.
struct Registrations<'a> {
    workspace: &'a Workspace,
    module: &'a Module,
    scan: &'a mut Scan,
}

impl Registrations<'_> {
    fn unresolved(&mut self, span: Span, what: &str) {
        let file = self.workspace.sources.display(&self.module.file);
        let line = span.start().line;
        self.scan.unresolved.push(format!("{file}:{line}: {what}"));
    }

    /// A route path argument, in [`ROUTES`]' notation.
    fn path(&self, expr: &Expr) -> Result<String, String> {
        match expr {
            Expr::Lit(ExprLit {
                lit: Lit::Str(value),
                ..
            }) => Ok(value.value()),
            Expr::Reference(expr) => self.path(&expr.expr),
            Expr::Paren(expr) => self.path(&expr.expr),
            Expr::Path(path) if path.qself.is_none() => {
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                let constant = match segments.as_slice() {
                    [name] => self.workspace.lookup(self.module, name, 0),
                    _ => self.workspace.constant(&self.module.absolute(&segments), 0),
                };
                match (constant, segments.as_slice()) {
                    (Some(value), _) => Ok(value),
                    (None, [name]) if name.starts_with(|c: char| c.is_ascii_lowercase()) => {
                        Ok(format!("<{name}>"))
                    }
                    (None, _) => Err(format!(
                        "the path `{}`, which is not a string constant the scan can find",
                        segments.join("::")
                    )),
                }
            }
            Expr::Macro(expr) if expr.mac.path.is_ident("format") => self.format_path(&expr.mac),
            _ => Err("a path expression the scan cannot resolve".to_owned()),
        }
    }

    /// A `format!` route path, with its arguments resolved as paths.
    fn format_path(&self, mac: &syn::Macro) -> Result<String, String> {
        let unreadable = || "a `format!` path the scan cannot read".to_owned();
        let args = mac
            .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
            .map_err(|_| unreadable())?;
        let mut args = args.into_iter();
        let Some(Expr::Lit(ExprLit {
            lit: Lit::Str(template),
            ..
        })) = args.next()
        else {
            return Err(unreadable());
        };
        let mut named = HashMap::new();
        let mut positional = Vec::new();
        for arg in args {
            match arg {
                Expr::Assign(assign) => match &*assign.left {
                    Expr::Path(name) if name.path.get_ident().is_some() => {
                        named.insert(name.path.segments[0].ident.to_string(), *assign.right);
                    }
                    _ => return Err(unreadable()),
                },
                arg => positional.push(arg),
            }
        }
        let template = template.value();
        let mut path = String::new();
        let mut rest = template.as_str();
        let mut next = positional.iter();
        while let Some(ch) = rest.chars().next() {
            if let Some(after) = rest.strip_prefix("{{") {
                path.push('{');
                rest = after;
            } else if let Some(after) = rest.strip_prefix("}}") {
                path.push('}');
                rest = after;
            } else if ch == '{' {
                let end = rest.find('}').ok_or_else(unreadable)?;
                let name = &rest[1..end];
                let value = if name.is_empty() {
                    self.path(next.next().ok_or_else(unreadable)?)?
                } else if let Some(arg) = named.get(name) {
                    self.path(arg)?
                } else if syn::parse_str::<syn::Ident>(name).is_ok() {
                    self.path(&syn::parse_str(name).map_err(|_| unreadable())?)?
                } else {
                    return Err(unreadable());
                };
                path.push_str(&value);
                rest = &rest[end + 1..];
            } else {
                path.push(ch);
                rest = &rest[ch.len_utf8()..];
            }
        }
        Ok(path)
    }

    /// The crate a merged router is built in, when that is not the gateway.
    fn foreign_router(&self, expr: &Expr) -> Option<String> {
        let Expr::Path(path) = chain_root(expr) else {
            return None;
        };
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        if segments.len() >= 2 && segments[segments.len() - 2] == "Router" {
            return None;
        }
        let absolute = match segments.as_slice() {
            [name] => self.module.uses.get(name)?.clone(),
            _ => self.module.absolute(&segments),
        };
        absolute
            .first()
            .filter(|krate| *krate != GATEWAY_CRATE)
            .cloned()
    }

    fn register(&mut self, call: &syn::ExprMethodCall) {
        let name = call.method.to_string();
        let args: Vec<&Expr> = call.args.iter().collect();
        let registered = match (name.as_str(), args.as_slice()) {
            ("route", [path, router]) => self
                .path(path)
                .and_then(|path| Ok((path, method_router(router)?))),
            ("route_service", [path, _]) => {
                self.path(path).map(|path| (path, BTreeSet::from(["ANY"])))
            }
            ("fallback", [handler]) if !is_method_router(&call.receiver) => {
                if is_method_router(handler) {
                    method_router(handler).map(|methods| (UNMATCHED.to_owned(), methods))
                } else {
                    Ok((UNMATCHED.to_owned(), BTreeSet::from(["ANY"])))
                }
            }
            ("fallback_service", [_]) if !is_method_router(&call.receiver) => {
                Ok((UNMATCHED.to_owned(), BTreeSet::from(["ANY"])))
            }
            ("nest", [path, _]) => match self.path(path) {
                Ok(path) => {
                    self.scan.mounts.insert(path);
                    return;
                }
                Err(why) => Err(why),
            },
            ("nest_service", _) => {
                Err("`.nest_service(..)`, which the scan does not model".to_owned())
            }
            ("merge", [router]) => match self.foreign_router(router) {
                Some(krate) => Err(format!(
                    "a merged router built in {krate}, where the scan does not look"
                )),
                None => return,
            },
            _ => return,
        };
        match registered {
            Ok((path, methods)) => {
                for method in methods {
                    self.scan.routes.insert((method.to_owned(), path.clone()));
                }
            }
            Err(why) => self.unresolved(call.method.span(), &why),
        }
    }
}

impl<'ast> Visit<'ast> for Registrations<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !matches!(item, Item::Mod(_)) && !test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if !test_only(stmt_attrs(stmt)) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.register(call);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !calls_registration(mac.tokens.clone()) {
            return;
        }
        match mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            Ok(exprs) => {
                for expr in &exprs {
                    self.visit_expr(expr);
                }
            }
            Err(_) => self.unresolved(
                mac.span(),
                "a router call inside a macro the scan cannot parse",
            ),
        }
    }
}

/// What is wrong with the gateway's route inventory against [`ROUTES`] and
/// [`MOUNTS`].
fn inventory_problems(sources: Sources) -> Vec<String> {
    let scan = scan(sources);
    let mut problems = Vec::new();
    if !scan.unresolved.is_empty() {
        problems.push(format!(
            "the scan cannot resolve these router calls; register them with a literal or \
             string-constant path and an inline Axum method router, or teach the scan the \
             new form: {:#?}",
            scan.unresolved
        ));
    }
    if scan.routes.len() <= 150 {
        problems.push(format!(
            "the scan should find the gateway's router, found {} routes",
            scan.routes.len()
        ));
    }
    let classified: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|(method, path, _)| ((*method).to_owned(), (*path).to_owned()))
        .collect();
    if classified.len() != ROUTES.len() {
        problems.push("a route is classified twice in ROUTES".to_owned());
    }
    let unclassified: Vec<String> = scan
        .routes
        .difference(&classified)
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    if !unclassified.is_empty() {
        problems.push(format!(
            "classify these gateway routes in ROUTES and in {COVERAGE_DOC}: {unclassified:#?}"
        ));
    }
    let gone: Vec<String> = classified
        .difference(&scan.routes)
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    if !gone.is_empty() {
        problems.push(format!(
            "remove these routes, which the gateway no longer registers, from ROUTES and \
             {COVERAGE_DOC}: {gone:#?}"
        ));
    }
    let mounts: BTreeSet<String> = MOUNTS.iter().map(|(path, _)| (*path).to_owned()).collect();
    if scan.mounts != mounts {
        problems.push(format!(
            "the gateway nests routers under {:?}, MOUNTS lists {mounts:?}",
            scan.mounts
        ));
    }
    problems
}

#[test]
fn every_gateway_route_is_classified_against_the_core() {
    let problems = inventory_problems(Sources::workspace());
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
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

/// The rows of the coverage document's table under `## {heading}`, without
/// its header.
fn doc_table(doc: &str, heading: &str) -> Vec<String> {
    let section = doc
        .split(&format!("\n## {heading}\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("{COVERAGE_DOC} has no `## {heading}` section"));
    section
        .split("\n## ")
        .next()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2)
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_coverage_document_matches_the_table() {
    let doc = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_DOC))
        .unwrap_or_else(|e| panic!("read {COVERAGE_DOC}: {e}"));
    let expected: Vec<String> = ROUTES
        .iter()
        .map(|(method, path, class)| {
            format!(
                "| {method} `{path}` | {} | {} |",
                class.label(),
                class.detail()
            )
        })
        .collect();
    let rows = doc_table(&doc, "Routes");
    let missing: Vec<&String> = expected.iter().filter(|row| !rows.contains(row)).collect();
    let extra: Vec<&String> = rows.iter().filter(|row| !expected.contains(row)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{COVERAGE_DOC}'s route table differs from ROUTES.\nIn ROUTES only: {missing:#?}\n\
         In the document only: {extra:#?}"
    );
    assert_eq!(
        rows, expected,
        "{COVERAGE_DOC} lists the routes in a different order from ROUTES"
    );
    let counts: Vec<String> = ["rpc", "deferred", "ingress", "gateway-local"]
        .iter()
        .map(|label| {
            let count = ROUTES
                .iter()
                .filter(|(_, _, class)| class.label() == *label)
                .count();
            format!("| `{label}` | {count} |")
        })
        .collect();
    assert_eq!(
        doc_table(&doc, "Counts"),
        counts,
        "{COVERAGE_DOC}'s counts differ from ROUTES"
    );
}

#[test]
fn the_scanner_resolves_every_router_call_or_reports_it() {
    let gateway_lib = r##"
        mod card;
        mod opaque;
        #[cfg(not(test))]
        mod production;
        #[cfg(any(test, feature = "test-util"))]
        mod shared;
        #[cfg(test)]
        mod tests;
        #[cfg(all(test, unix))]
        mod unix_tests {
            fn t() { Router::new().route("/unix-test-only", get(t)); }
        }

        const CARD: &str = "/card";
        const QUOTE: char = '"';
        const RAW: &str = r#"{"route": ".route(\"/raw\", get(x))"}"#;

        fn router(prefix: &str) -> Router {
            let inner = Router::new()
                // .route("/commented", get(gone))
                .route("/a/{id}", get(read).patch(update).layer(x.get(1)))
                .route(CARD, post(|| async { headers.get("x") }))
                .route(&format!("/n/{{alias}}{CARD}"), axum::routing::delete(remove))
                .route("/p", get(h).head(u).fallback(u))
                .route("/any", any(h))
                .route("/on", on(MethodFilter::PUT.or(MethodFilter::DELETE), h))
                .route_service("/svc", service)
                .merge(card::routes())
                .fallback(get(spa));
            Router::new().nest(prefix, inner).route(&format!("{prefix}/"), get(redirect))
        }

        #[cfg(test)]
        fn test_router() -> Router {
            Router::new().route("/test-fn", get(t))
        }
    "##;
    // A route whose path constant lives in another crate and is re-exported
    // into the gateway module that registers it.
    let card = r#"
        pub use zeroclaw_runtime::a2a_card::{AgentCard, CATALOG_CARD_PATH};
        pub(crate) fn routes() -> Router {
            Router::new().route(CATALOG_CARD_PATH, get(card))
        }
    "#;
    let opaque = r#"
        use zeroclaw_channels::webhook_routes;
        fn routes(method_router: MethodRouter) -> Router {
            Router::new()
                .route("/variable", method_router)
                .route(MISSING_PATH, get(h))
                .route("/odd", get(h).frobnicate(x))
                .merge(webhook_routes())
                .nest_service("/assets", files)
        }
    "#;
    let root = PathBuf::from("/workspace");
    let gateway = root.join("crates/zeroclaw-gateway/src");
    let runtime = root.join("crates/zeroclaw-runtime/src");
    let files = HashMap::from([
        (gateway.join("lib.rs"), gateway_lib.to_owned()),
        (gateway.join("card.rs"), card.to_owned()),
        (gateway.join("opaque.rs"), opaque.to_owned()),
        (
            gateway.join("production.rs"),
            r#"fn routes() -> Router { Router::new().route("/production-only", get(h)) }"#
                .to_owned(),
        ),
        (
            gateway.join("shared.rs"),
            r#"fn routes() -> Router { Router::new().route("/shared", put(h)) }"#.to_owned(),
        ),
        (
            gateway.join("tests.rs"),
            r#"fn t() { Router::new().route("/test-only", get(t)); }"#.to_owned(),
        ),
        (runtime.join("lib.rs"), "pub mod a2a_card;".to_owned()),
        (
            runtime.join("a2a_card.rs"),
            r#"pub const CATALOG_CARD_PATH: &str = "/.well-known/agents-card.json";"#.to_owned(),
        ),
    ]);
    let found = scan(Sources {
        root,
        files: Some(files),
    });

    let routes: Vec<String> = found
        .routes
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert_eq!(
        routes,
        [
            "ANY /any",
            "ANY /p",
            "ANY /svc",
            "DELETE /n/{alias}/card",
            "DELETE /on",
            "GET /.well-known/agents-card.json",
            "GET /a/{id}",
            "GET /p",
            "GET /production-only",
            "GET <prefix>/",
            "GET <unmatched>",
            "HEAD /p",
            "PATCH /a/{id}",
            "POST /card",
            "PUT /on",
            "PUT /shared",
        ]
    );
    assert_eq!(found.mounts, BTreeSet::from(["<prefix>".to_owned()]));
    let mut unresolved = found.unresolved.clone();
    unresolved.sort();
    assert_eq!(
        unresolved,
        [
            "crates/zeroclaw-gateway/src/opaque.rs:5: a method router the scan cannot read",
            "crates/zeroclaw-gateway/src/opaque.rs:6: the path `MISSING_PATH`, which is not a \
             string constant the scan can find",
            "crates/zeroclaw-gateway/src/opaque.rs:7: the method-router call `.frobnicate(..)`",
            "crates/zeroclaw-gateway/src/opaque.rs:8: a merged router built in \
             zeroclaw_channels, where the scan does not look",
            "crates/zeroclaw-gateway/src/opaque.rs:9: `.nest_service(..)`, which the scan does \
             not model",
        ]
    );
}

#[test]
fn cfg_predicates_are_test_only_only_when_they_need_test() {
    let test_only_cfg = |cfg: &str| {
        let item: syn::ItemMod = syn::parse_str(&format!("#[cfg({cfg})] mod m {{}}"))
            .expect("a module with a cfg attribute");
        test_only(&item.attrs)
    };
    for cfg in [
        "test",
        "all(test, unix)",
        "all(unix, test)",
        "any(test)",
        "not(not(test))",
    ] {
        assert!(test_only_cfg(cfg), "{cfg} is test-only");
    }
    for cfg in [
        "not(test)",
        "any(test, feature = \"test-util\")",
        "feature = \"test-util\"",
        "unix",
        "all(not(test), unix)",
    ] {
        assert!(!test_only_cfg(cfg), "{cfg} can hold in a production build");
    }
}
