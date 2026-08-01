# ZeroClaw v0.8.4

This release spans **271 commits** from **30 contributors**. Two things stand out. ZeroClaw is on crates.io again: `cargo install zeroclaw` works for the first time since the microkernel split, and the workspace publishes as eighteen libraries you can depend on directly. The rest of the cycle went into memory, which gained typed classification, reranking, auditing and content scanning, and into the SOP engine, which grew an approval broker with quorum and per-SOP admission control.

If you run agents in production, the headline items are the memory pipeline's new safety boundaries (content is scanned at both write and recall), the SOP approval broker, and a Landlock fix that could previously restrict ZeroClaw itself.

## Highlights

- **`cargo install zeroclaw` works.** The workspace publishes to crates.io as eighteen crates, with `zeroclaw` as the installable entry point.
- **Scoop publishing is fixed and Homebrew moved to Homebrew Core's autobump**, so `scoop update zeroclaw` resolves the exact binary the release shipped.
- **Memory grew a safety and quality pipeline**: typed classification, an opt-in retrieval cache, a gated rerank stage, an audit trail with observer fan-out, and content scanning at the write and recall boundaries.
- **SOPs gained real approvals**: an approval broker with group membership and quorum at the gate chokepoint, per-SOP admission policy, and checkpoint edit/revise for deterministic pipelines.
- **In-app upgrade from the web dashboard**, with auto-restart.
- **Landlock no longer restricts ZeroClaw itself**, worth picking up if you run with Landlock enabled.

## What's New

### Distribution

**crates.io.** The root package is now named `zeroclaw` (previously `zeroclawlabs`), so `cargo install zeroclaw --locked` installs the binary of the same name. Eighteen workspace crates publish, so downstream projects can depend on `zeroclaw-api`, `zeroclaw-plugins`, `zeroclaw-memory` and the rest directly rather than pinning a git revision.

**Scoop (Windows).** Scoop publishing is repaired (#9295). The manifest renders from the checked-in `dist/scoop/zeroclaw.json` and is pinned to the exact checksum of the published release asset, so `scoop update zeroclaw` resolves the same binary the release actually shipped. The publisher proves write access with a non-mutating `git push --dry-run`, and repeat publishes are idempotent.

**Homebrew (macOS / Linux).** The project's own Homebrew workflow has been removed (#9295). Homebrew Core's [autobump service](https://docs.brew.sh/Autobump) detects the stable GitHub release and opens the formula bump itself. Nothing changes for you as a user; if a bump looks stale, check Homebrew's autobump status rather than expecting a ZeroClaw workflow to have run.

**AUR.** The publisher dropped a brittle `ssh -T` probe and now treats a successful package clone as the authoritative authentication check (#9295).

**Removed crates.** `aardvark-sys` (Total Phase USB adapter bindings) and `zeroclaw-robot-kit` left the workspace. `zeroclaw-hardware` is unaffected apart from losing the Aardvark transport; USB discovery, serial, UF2, Pico flashing and Raspberry Pi GPIO all remain.

### Memory

- Typed memory classification with gated typed-facts extraction (#8900)
- Content scanned at both the write and recall boundaries (#8984)
- A gated rerank stage in engine memory-context injection (#8895)
- An opt-in retrieval cache decorator over agent memory (#8897)
- A gated audit trail with observer fan-out (#8893)
- Config semantics validation and a migration reindex hook (#8899)

### SOP engine

- An approval broker with group membership and quorum over the gate chokepoint (#8880)
- The exec slot is released on HITL approval, with a per-SOP admission policy (#8848)
- Channel gate prompts with checkpoint edit and revise (#8979)
- Fan-in ingress adapters centralized (#9205)

### Channels

- Mattermost WebSocket listener mode (#9141)
- Channel-owned relink hooks behind `POST /api/channels/{channel}/relink` (#8734)
- Structured login lifecycle events for QR pairing (#8622)
- Poll-vote and interactive-reply events, plus `Channel::send_choice` (#6297)
- Per-channel inbound debounce for Telegram (#8440)
- WhatsApp Web persists linked identity into canonical `peer_groups` on connect (#8735)

### Gateway and web

- In-app upgrade with auto-restart from the web dashboard (#8173)
- Channel readiness reports `authenticated` from channel-owned persisted-login probes (#8732)
- ACP sessions select their agent via an `?agent=` query parameter (#9026), and ACP accepts `resource.blob` in prompts with `deliver_file` citation URIs (#9195)
- LAN peer discovery hints (#8325)
- Risk-profile tool permissions unified into one grid (#8879); skills link through to the editor (#8558)

### Runtime, providers, and observability

- Model fallback notices surface on direct-turn surfaces (#8684)
- Memory and RAG spans nest under the turn trace (#8752)
- New OpenAI slots default to `wire_api=responses` (#9021), and model context windows carry from the models.dev catalogue (#9347)
- Web search classifies provider HTTP failures with a precise `search_status` (#8890)
- Cron gained `shell_output_format` for raw stdout (#8438)
- Quickstart recommends capability-safe runtime defaults (#8987)

### zerocode

- Active runtime context in the dashboard (#9011), agent rename flow (#7954), and searchable keybinding help (#9356)

### Security

- Landlock no longer restricts ZeroClaw itself (#9233)
- The webhook channel refuses to start a listener without a configured secret (#8725)
- Shell injection via a `workflow_dispatch` tag input is prevented in CI (#9165)

## Bug Fixes

One hundred and forty-six fixes landed. By area:

| Area | Fixes |
|---|---|
| runtime | 15 |
| channels | 15 |
| zerocode | 13 |
| config | 13 |
| tests | 11 |
| providers | 9 |
| sop | 8 |
| web, docs, ci | 5 each |
| plugins | 4 |
| release, memory, deps | 3 each |
| everything else | the remainder |

The Scoop, Homebrew and AUR packaging changes are described under [Distribution](#distribution).

## Breaking Changes

- **Skills: the built-in ClawHub source is replaced by a `git-catalog --skill` selector** (#8638). Configurations relying on the implicit ClawHub source must move to an explicit git catalog with a `--skill` selector.

## Contributors

@alexandme
@Alix-007
@amrrs
@Audacity88
@bglusman
@Darren2030
@Diwak4r
@drbparadise
@JordanTheJet
@jstar0
@Lusitaniae
@MannXo
@mazhuima
@Nillth
@octo-patch
@palomyates516-alt
@perlowja
@ryanlee486
@singlerider
@Stalesamy
@Super-Cabbage
@tidux
@tomatotomata
@tzy-17
@wangmiao0668000666
@WeeLi-009
@wm0018
@xydt-juyaohui
@yanchenko
@yijunyu

---

**Full diff:** https://github.com/zeroclaw-labs/zeroclaw/compare/v0.8.3...v0.8.4
