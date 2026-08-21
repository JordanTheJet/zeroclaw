# Quickstart

Quickstart is the guided setup that takes you from a fresh install to a working
agent in one pass. It runs on three surfaces: the **CLI**, the **zerocode**
terminal interface, and the **web gateway**. All three drive the same
underlying flow, so the config they produce is identical. Use whichever fits
where you are.

## Install

{{#include ../_snippets/install.md}}

## The steps

> **Important:** if any of these terms are unfamiliar, read
> [Getting Started → Concepts](./concepts.md) first. It defines model
> provider, risk profile, alias, and the rest in one place.

{{#include ../_snippets/quickstart-steps.md}}

## CLI

The fastest path on a headless box or over SSH:

<div class="os-tabs-src">

#### sh

```sh
zeroclaw quickstart
```

</div>

You answer one prompt per step in the terminal. The built-in `cli` channel
works immediately, so Channels and Peer groups can be skipped. For an
all-defaults, no-approvals config, see [YOLO mode](./yolo.md).

## Create another agent with Zerona

After Quickstart has configured at least one model provider, run:

```sh
zeroclaw onboard
```

Zerona requires the on-disk config to use the current schema. If it asks you to
migrate, run `zeroclaw config migrate`, review the saved migration, and start
onboarding again. It will not combine an automatic in-memory migration with a
new-agent write.

Zerona holds a capability-free conversation about one new agent. The host
selects the existing model-provider alias before the conversation. Zerona
receives no tools, memory, skills, MCP servers, file access, shell access, or
configuration writer; every provider request carries `tools: none` and is
pinned to that one alias and model without global routes or fallback aliases.

`zeroclaw onboard` starts the compiled-in `system.zerona.create_agent` SOP
through a typed system-only entry point. User-authored SOPs cannot shadow or
start it. Its interactive step records only status, byte counts, and random
markers;
the bounded conversation transcript, proposal, preview, personality contents,
and exact config source remain process-local in the onboarding host. Closing
the process discards that private state, so an interrupted session restarts
instead of reconstructing sensitive conversation text from the SOP run store.

The model can propose only:

- a new agent alias;
- the `locked_down` or `balanced` risk preset;
- the `tight`, `local_small`, or `balanced` runtime preset;
- `sqlite`, `markdown`, or no memory; and
- `SOUL.md`, `IDENTITY.md`, `USER.md`, and `AGENTS.md` contents.

Channels, peer groups, credentials, provider settings, arbitrary config paths,
workspace overrides, and uncontained profiles are outside this surface. If a
message looks like a credential, ZeroClaw refuses it before a provider request.

When Zerona has enough information, the host validates the proposal against
current typed config and shows the complete personality files, effective
security posture, workspace, config path, and persistence effects. Only the
exact terminal verdict `apply` persists the proposed agent or personality
files. `revise`, `cancel`, `quit`, or end-of-file leaves the proposal
unapplied. The strict new-agent transaction finishes the complete personality
workspace before publishing the config entry. If the config revision check then
refuses the write, that newly-created workspace is removed, so config never
exposes an agent with a partial personality bundle. A per-agent OS lock prevents
two Zerona processes from sharing or deleting each other's workspace, and file
plus directory fsyncs make the personality bundle durable before config is
published. If the platform reports an ambiguous config-rename outcome, ZeroClaw
preserves the complete workspace and asks the operator to inspect both surfaces;
it never deletes files unless the writer proves config did not commit. ZeroClaw
compares the exact
`config.toml` source bytes before apply and again immediately before the atomic
replacement step. Detected configuration drift ends the session; restart
onboarding to build a new conversation and preview against current config.

This focused agent creator supersedes the experimental generic section flow in
[#8033](https://github.com/zeroclaw-labs/zeroclaw/pull/8033). It does not replace
Quickstart's provider, channel, peer-group, web, or zerocode setup surfaces.

### OpenAI Codex subscription auth

Quickstart can configure the OpenAI Codex subscription path without an API key.
Authenticate once, then choose **OpenAI** as the provider and set
**Authentication** to `codex` when prompted:

```sh
# If you already signed in with the Codex CLI:
zeroclaw auth login --model-provider openai-codex --import ~/.codex/auth.json

# Or start ZeroClaw's own OpenAI Codex login flow:
zeroclaw auth login --model-provider openai-codex
```

For scripted setup, `openai-codex` is accepted as a quickstart input alias and
writes the canonical `[providers.models.openai.<alias>]` entry:

```sh
zeroclaw quickstart --model-provider openai-codex --model gpt-5.4 --agent assistant
```

### Claude subscription setup-token auth

Quickstart can also configure Claude/Anthropic with a normal Console API key
or a token generated by Claude Max:

```sh
claude setup-token
zeroclaw quickstart --model-provider anthropic --model claude-sonnet-4-5 --agent assistant
```

Choose **Anthropic**, set **Authentication** to `setup_token`, then paste the
token from `claude setup-token` into the API key/token prompt. Scripted input
may use `--model-provider claude` as an alias. Quickstart still writes the
canonical `[providers.models.anthropic.<alias>]` entry; the token is stored
through the same credential path as `api_key`.

## zerocode

In the [zerocode](./zerocode.md) terminal interface, the Quickstart pane is one of
the tabs. Drive it with the keyboard:

Switch to the **Quickstart** pane:

{{#include ../_snippets/zerocode-pane-nav-keys.md}}

Inside the pane:

{{#include ../_snippets/zerocode-quickstart-pane-keys.md}}

Mouse works too: click a tab in the mode bar to switch panes, click a step to
select and open it, and scroll to move through the list.

Each step opens a modal that mirrors the checklist above, with a "Use existing"
option that lists the matching aliases already in your config.

## Web gateway

With the daemon running, open the dashboard in a browser:

<div class="os-tabs-src">

#### sh

```sh
zeroclaw daemon
```

</div>

`zeroclaw daemon` runs the full runtime: the gateway, your configured channels,
the scheduler, and the heartbeat monitor. (`zeroclaw gateway` starts only the
HTTP gateway if that is all you need.)

Then visit `http://127.0.0.1:42617/quickstart`. A fresh install with no agents
configured redirects there automatically; afterward you can always reach it
from the dashboard navigation.

The web form presents the same steps as cards. On submit it applies your
submission through the daemon (`POST /api/quickstart/apply`), which returns a
structured error list if anything is invalid, then reloads the daemon in place
so the new agent is live without a restart. A separate
`POST /api/quickstart/validate` endpoint runs the same checks without applying,
for clients that want to validate first.

## After Quickstart

- **Drive it from [zerocode](./zerocode.md):** the terminal interface is the best
  way to chat, watch live logs, manage config, and monitor the daemon, all in
  one place. Just run `zerocode`.
- **Quick one-off from the shell:** `zeroclaw agent -a <alias> -m "your message"`.
- **Run always-on:** `zeroclaw service install && zeroclaw service start`.
- **Add channels later:** [Channels → Overview](../channels/overview.md).
- **Tune autonomy and budgets:** [Reference → Config](../reference/config.md).
