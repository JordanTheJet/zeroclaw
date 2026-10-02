# Tools: Overview

**Tools** are the agent's hands. A tool is a capability the model can invoke mid-conversation, run a shell command, fetch an HTTP URL, open a browser, write a file, read a sensor. Every tool call is subject to [security policy](../security/overview.md). Successful executions can include a [tool receipt](../security/tool-receipts.md) when receipts are enabled.

Tools are not to be confused with `zeroclaw` CLI subcommands. CLI commands are for operators; tools are for the agent.

An agent gets its tools through the skill, knowledge, and MCP bundles it references; see [Agents](../agents/overview.md) for how bundles attach to an agent.
For the turn-level path from provider tool call to approval, dispatch, receipt,
observer event, and history entry, see
[Tool execution lifecycle](../architecture/tool-execution-lifecycle.md).

Before adding a built-in tool or replacing one with an external integration,
use the [Built-In Tool Inventory](../developing/tool-inventory.md)
to choose the smallest durable home. Working built-in integrations stay
available until a replacement is real, documented, and independently reviewed;
that replacement-first rule is the accepted
[RFC #6165](https://github.com/zeroclaw-labs/zeroclaw/issues/6165) policy,
recorded in the inventory's
[Replacement-First Policy](../developing/tool-inventory.md#replacement-first-policy)
section.

## Selecting optional tools

New and existing schema-3 configurations expose eleven built-ins by default:
`shell`, `file_read`, `file_write`, `file_edit`, `glob_search`, `content_search`,
`memory_recall`, `memory_store`, `memory_forget`, `web_fetch`, and
`git_operations`. The canonical set is `CORE_TOOL_NAMES` in
`zeroclaw-config/src/builtin_tools.rs`. Existing policy can narrow this set.

Select additional built-ins by their callable names:

```toml
[tools]
optional = ["calculator", "cron_list", "sessions_history"]
```

Selection happens before constructors run. An unselected tool contributes no
schema or tool-catalog prompt text. Selection does not grant permissions:
the tool's own settings, runtime capabilities, risk profile, caller narrowing,
approval, path/network policy and receipts still apply. Reload the daemon
after changing selection. Config schema remains version 3.

Explicitly configured MCP servers, skills, plugins and peripherals keep their
existing activation and permission paths; they are not selected through this
built-in list. No replacement plugin is required or claimed here.

### Builds and upgrade path

| Channel | Standard build | Recovering optional native adapters |
| --- | --- | --- |
| Release archive | `dist`: eleven defaults; vendor/CLI/external adapters compiled out | Download `zeroclaw-<target>-compat.tar.gz` (Windows: `.zip`), which uses `dist-compat`, then select the tools |
| Desktop sidecar | `dist`, resolved for each target, plus requested desktop features | Prepare a compatibility sidecar with `scripts/desktop/prepare-kernel.sh --distribution dist-compat`; users can run a downloaded compatibility daemon and connect the desktop to it |
| Homebrew source build | Cargo defaults: the same eleven-tool policy; optional external adapters compiled out | Use the platform compatibility archive alongside the package-managed binary; adding config cannot change a bottle's compiled features |
| Docker | `dist`: the same eleven-tool policy | Use the `compat-tools` image tag, then select the tools and configure their dependencies |

Standard `dist` and `dist-compat` retain the portable WASM plugin host through
`plugins-wasm-cranelift` on the seven supported native 64-bit targets: GNU and
musl Linux on x86_64 and aarch64, both macOS architectures, and x86_64 Windows
MSVC. ARMv6/ARMv7 builds omit Cranelift and Prometheus; experimental Android
builds omit Cranelift and WhatsApp Web. Cargo defaults do not include a plugin
host. Compiling the host leaves `plugins.enabled` and `plugins.auto_discover`
false; configured plugin activation, consent, trust and grants still apply.
Runtime-only precompiled `.cwasm` support and Pulley alone do not replace the
portable registry `.wasm` compilation contract. Distribution features and
platform exclusions come from `package.metadata.zeroclaw` in `Cargo.toml`.

`dist-compat` adds the `tools-compat` Cargo bundle: `tools-saas`,
`tools-coding-cli`, and `tools-external`. Source users can select an individual
existing `tool-*` feature or the bundle. The compatibility build does not
install vendor CLIs, browsers or credentials. Existing integration `enabled`
settings and dependencies remain necessary. First-party extras such as cron,
sessions and calculator are compiled into both builds and need only runtime
selection plus their existing prerequisites.

The default change is intentional for desktop and Homebrew as well as archives
and Docker. Existing users who need the previous built-ins can select them
individually, or explicitly request the previous selection:

```toml
[tools]
optional = ["*"]
```

Use a compatibility build for vendor/CLI/external adapters. A lean build reports
selected but compiled-out adapters through config validation warnings; it cannot
activate code it does not contain. The wildcard restores availability according
to the previous config and runtime gates, including caller-specific exceptions;
it does not enable disabled integrations, grant permissions, or expose withheld
tools. For ACP attachment delivery, select `deliver_file`; for compact skills,
select `read_skill`; for model-driven scheduling/SOP/delegation, select the
corresponding tool names. Operator scheduling, SOP and approval services retain
their existing lifecycle independently of model-visible selection.

## Built-in tools

The following capabilities are available when compiled and selected; the eleven-tool default is listed above:

| Tool | What it does |
|---|---|
| `shell` | Execute a shell command in the workspace directory. Subject to command allow/deny lists |
| `file_read` | Read a file with line numbers; supports partial reads and base64 encoding for binary files (path must be inside the workspace unless autonomy permits otherwise) |
| `file_write` | Write a file (same path constraint) |
| `file_edit` | Replace an exact string match in a file with new content |
| `glob_search` | List files matching a glob pattern within the workspace |
| `content_search` | Search file contents by regex within the workspace (ripgrep with grep fallback) |
| `http_request` | HTTP GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS to allowlisted domains |
| `web_search_tool` | Web search. Provider is configurable: DuckDuckGo (default, no key), Brave, Tavily, SearXNG, Jina, Bocha, AnySearch, Serply, or Keenable (no key required; optional key lifts rate limits) |
| `web_fetch` | Fetch a page and return clean plain text |
| `browser` | Headless-browser automation. Opt-in: requires `[browser] automation_enabled = true`. See [Browser automation](./browser.md) |
| `memory_recall` | Search long-term memory for relevant facts, preferences, or context |
| `memory_store` | Store a fact, preference, or note in long-term memory |
| `ask_user` | Send a question to the active channel and wait for a reply. Supports optional `choices` for structured responses (inline keyboard on Telegram, numbered list on CLI). On ACP, `choices` are required: free-form ask awaits the ACP elicitation RFD. Parameters: `question` (required), `choices` (optional list), `timeout_secs` (default 600). |
| `escalate_to_human` | Send a structured escalation message with urgency routing. `high` / `critical` urgency additionally notifies any channels listed in `[escalation] alert_channels`. Parameters: `summary` (required), `context` (optional), `urgency` (`low`/`medium`/`high`/`critical`, default `medium`), `wait_for_response` (bool, default false), `timeout_secs` (default 600). On ACP, `wait_for_response: true` fails immediately if the channel cannot receive free-form replies (awaits ACP elicitation RFD). |

### AnySearch provider

AnySearch is an explicit, opt-in backend for `web_search_tool`:

```toml
[web_search]
search_provider = "anysearch"
# Optional; omit to use AnySearch's lower, rate-limited anonymous quota.
anysearch_api_key = "..."
```

Search queries and the configured result limit are sent to
`https://api.anysearch.com/v1/search`. When `anysearch_api_key` is configured,
ZeroClaw sends it only as a Bearer authorization header; without a key, no
`Authorization` header is sent. Selecting this provider therefore sends search
queries to a third-party service even in anonymous mode. It does not change the
default provider and is not used as an automatic fallback.

Additional first-party built-ins require selection:

| Tool | Notes |
|---|---|
| `cron_*` | Manage scheduled jobs: `cron_add`, `cron_list`, `cron_remove`, `cron_update`, `cron_run`, `cron_runs` |
| `schedule` | Shell-only one-shot/recurring scheduling |
| `memory_forget`, `memory_export`, `memory_purge` | Long-term memory management |
| `spawn_subagent`, `delegate` | Run a subtask in a child agent |

Selected tools also retain these prerequisites:

| Tool | Enabled by |
|---|---|
| `knowledge` | `[knowledge].enabled = true`. Stores structured relationship memory; see [Relationship memory](./relationship-memory.md) |
| Hardware probes | `--features hardware`: GPIO reads/writes, device discovery, firmware flashing |
| `sop_*` tools | Registered when the SOP runtime is enabled (`sop.sops_dir` set to a non-empty value; unset by default, which disables it; the documented value is `shared/sops`): run and inspect SOPs |
| `discord_search` | Registered when a Discord alias has `archive` enabled |

## Extension protocols

Beyond built-in tools, ZeroClaw supports the **[MCP](./mcp.md)** (Model Context Protocol) extension surface. Connect any MCP server (Claude Code's filesystem, Playwright, your own) and the agent picks up its tools at startup.

For IDE-side integration where an editor drives ZeroClaw as a subprocess, see [ACP](../channels/acp.md): Agent Client Protocol lives under channels since it's an inbound session-management surface, not a tool the agent invokes.

## Authoring a tool

Implement the `Tool` trait in `zeroclaw-api`:

```rust
#[async_trait]
pub trait Tool: Send + Sync + Attributable {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters_schema(&self) -> serde_json::Value;   // JSON Schema for args
    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult>;
}
```

Every `Tool` is also `Attributable`, so a tool call's log emissions and audit traces carry the same `<kind>.<alias>` attribution the rest of the runtime uses.

Register via the runtime's tool factory. See [Developing → Plugin protocol](../developing/plugin-protocol.md) for the full pattern.

## Describing tools to the model

Tool descriptions are [Mozilla Fluent](https://projectfluent.org/) strings: one per tool, localised per locale. This keeps tool descriptions terse in the model's context window while allowing UI localisation.

Source of truth: `crates/zeroclaw-runtime/locales/en/tools.ftl`. Translations are generated and maintained via `cargo fluent fill --locale <code>` (see [Maintainers → Docs & Translations](../maintainers/docs-and-translations.md)).

## Risk and approval

Every tool invocation is classified by risk:

- **Low** (read-only, no side effects): `file_read`, `memory_recall`, `http_request GET` to allowed domains
- **Medium** (mutates local state): `file_write`, `shell` with known safe commands
- **High** (destructive or remote side effects): `shell` with unknown commands, `http_request POST` to unconstrained URLs

The [autonomy level](../security/autonomy.md) determines what each risk tier can do without operator approval. Default (`Supervised`): low runs, medium asks, high blocks.

When receipts are enabled, successful executions receive a [tool receipt](../security/tool-receipts.md). Denied, blocked, replaced, failed, or interrupted calls do not receive receipts.

## Disabling tools on non-CLI channels

The schema has no per-channel `tools_allow` / `tools_deny` field. Tool gating lives on the agent's risk profile (`[risk_profiles.<alias>]`):

- `excluded_tools` removes the listed tools from every non-CLI channel (Discord, Telegram, Bluesky, Matrix, Slack, etc.) while leaving the local CLI untouched. The granularity is binary (CLI vs non-CLI), not per-channel. It also subtracts from the agentic-delegate allow-list resolved at runtime, which is the only way to block individual `<server>__<tool>` MCP names that would otherwise be auto-admitted by the rule below.
- `allowed_tools` is an allowlist. Omitted and an explicit empty list (`allowed_tools = []`) mean the same legacy state: no authorization constraint. A nonempty list is a closed set for built-ins (and, via the MCP exception below, auto-admits namespaced MCP tools). An empty list does **not** mean deny-all; for that, set the sibling `deny_all_tools = true`, which denies built-ins, MCP tools, and skill-defined tools alike. Setting both `deny_all_tools = true` and a nonempty `allowed_tools` is a configuration error rejected at load.
- **MCP exception**: when `allowed_tools` is non-empty, runtime-discovered MCP tools (any name containing `__`, the `<server>__<tool>` convention) are auto-admitted into the effective allow-list without having to be listed there individually. This keeps the post-#7464 eager-MCP default usable for agents that already pin an explicit allow-list. To block individual MCP tools, list them in `excluded_tools`.
- The MCP exception is scoped to the **risk profile**'s `allowed_tools` only. Caller-supplied per-run allow-lists (cron job `allowed_tools`, narrowed delegate invocations, etc.) are still treated as strict explicit-list intersections. A job that narrows itself to `allowed_tools = ["cron_add"]` will not surface runtime-discovered MCP wrappers it did not name, even when the agent's risk profile would auto-admit them.

If you need finer-grained gating under Full autonomy, put sensitive tools in the per-profile `always_ask` list: they still prompt (or fail closed) even when `level = "full"`. Dropping the profile to `read_only` or `supervised` is only required when you want the whole risk-tier matrix, not when you need a handful of exceptions.

See [Autonomy levels](../security/autonomy.md) for the full set of per-profile fields.

## See also

- [MCP](./mcp.md)
- [Tool execution lifecycle](../architecture/tool-execution-lifecycle.md)
- [ACP](../channels/acp.md)
- [Browser automation](./browser.md)
- [Security → Overview](../security/overview.md)
