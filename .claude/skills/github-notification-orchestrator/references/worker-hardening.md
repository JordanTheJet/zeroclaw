# Worker hardening — making the drafting agents truly read-only

This closes the residual flagged in [`safety.md`](safety.md): the per-profile
worker agents run with a full shell and reach the user's `gh` credential, so a
prompt-injected worker (fed by untrusted PR/issue content it reads) could make a
GitHub *write* — `gh pr review --approve`, a comment, a merge — bypassing the
gated shippers. The shippers harden the *human* path; this hardens the *agents*.

## Why it isn't a one-line config flip

Verified against ZeroClaw 0.8.2 source:

- The shell tool **`env_clear()`s** the child and re-injects only the vars named in
  a profile's `shell_env_passthrough` (`crates/zeroclaw-runtime/src/tools/shell.rs`).
  So the shell environment **is** controllable per-risk-profile.
- BUT `gh` reads its token from the **OS keychain** (macOS) / secret-store, *not*
  from the environment. `env_clear()` does not touch the keychain, so a worker's
  `gh` still finds the full token there.
- There is **no macOS sandbox backend** — `sandbox_backend` resolves to `firejail`
  / `bubblewrap` / `landlock`, all **Linux-only** (`crates/zeroclaw-runtime/src/security/`).
  `gh_notif_worker` ships `sandbox_enabled = false`.

So real containment requires either (A) a **read-only token the workers use via
env**, with writers kept on a separate profile, or (B) the **Linux sandbox** that
hides the credential file from workers. Both need a **read-only fine-grained PAT**
(GitHub has no CLI to mint one — create it in the web UI).

### The read-only PAT (do this once, either approach)

GitHub → Settings → Developer settings → **Fine-grained tokens** → Generate:
- Repository access: the repos you review (or "All repositories").
- Permissions (read-only): **Contents: Read**, **Pull requests: Read**,
  **Issues: Read**, **Metadata: Read**. Nothing with write. (Workers do *not* need
  the `notifications` scope — only the orchestrator polls notifications, and it
  keeps the full token.)

## Approach A — env-split (works on macOS now)

Give the **drafting workers** the read-only token via env; keep the **orchestrator
+ chat** (the legitimate writers) on the full keychain token. `gh` precedence is
`GH_TOKEN` env > keychain, so an env token wins for whoever gets it.

1. Put the read-only PAT in the **daemon's** environment as `GH_TOKEN` (e.g. via
   the systemd unit `Environment=` / an `EnvironmentFile`, or the launch wrapper).
2. On `risk_profiles.gh_notif_worker`, add `GH_TOKEN` to `shell_env_passthrough`
   (alongside `PATH`, `HOME`) → the 5 drafters + verifier resolve the **read-only**
   token.
3. Keep `risk_profiles.gh_notif` (orchestrator) **without** `GH_TOKEN` in
   `shell_env_passthrough` → it falls back to the keychain **full** token (needed
   for the notifications read + the `git push` to the private drafts repo).
4. Move the **chat agent** (`agents.gh_notif_chat`) off `gh_notif_worker` onto its
   own writer profile (identical, but no `GH_TOKEN` passthrough) so `ship_*` can
   still post when *you* drive them from Discord.

**Strength:** workers are read-only by default; accidental/most-injection writes
fail. **Limit (be honest):** a *deliberately* injected worker could still
`GH_TOKEN= gh …` to fall back to the keychain. To close that too, also remove the
keychain token (`gh auth logout`) and supply the full token to writers via a second
env var — at the cost of your interactive `gh` needing that env var. Approach B is
cleaner.

## Approach B — Linux sandbox (the clean version, on the 24/7 remote)

On the Linux box, restrict the workers so the credential file is simply not
reachable, then feed them only the read-only token:

```toml
[risk_profiles.gh_notif_worker]
sandbox_enabled = true
sandbox_backend = "firejail"          # or "bubblewrap"
# hide the gh credential store + the rest of HOME from workers; keep the workspace
firejail_args = ["--private=<HOME>/.zeroclaw/workspace/gh-notif", "--read-only=<HOME>/.zeroclaw/skills"]
shell_env_passthrough = ["PATH", "HOME", "GH_TOKEN"]   # GH_TOKEN = the read-only PAT in the daemon env
```

With `~/.config/gh` (and the keyring) outside the sandbox, a worker's `gh` has no
stored token to fall back to — it can use *only* the read-only `GH_TOKEN` you
inject. The orchestrator + chat run unsandboxed (or in a writer profile) with the
full token. Tune `firejail_args` to your box; verify a worker can still
`gh pr view` (read) but a `gh pr review` 403s.

## Until then

`approve` / `request-changes` are **opt-in** and human-gated (two-phase nonce in
`ship_review.sh`). The drafting workers' prompts are draft-only and the bundled
scripts call `gh` read-only — so in normal operation nothing writes. This file is
the path to making that a *structural* guarantee rather than a behavioral one.
