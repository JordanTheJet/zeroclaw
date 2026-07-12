---
name: configure-local-embeddings
description: Configure ZeroClaw memory to use this installed local embedding provider.
---

# Configure local embeddings

Use this skill only when the operator asks to enable the embedding provider
shipped by this plugin.

1. Read this plugin's installed, verified `manifest.toml`. Treat its `name` and
   `[embedding_provider]` table as canonical. Do not execute the sidecar to
   discover configuration.
2. Explain that native sidecars require explicit operator trust. Only with the
   operator's approval, set `plugins.enabled = true` and
   `plugins.allow_native_sidecars = true`.
3. Set `memory.embedding_provider` to `plugin:<manifest name>`.
4. Set `memory.embedding_model` and `memory.embedding_dimensions` from the
   manifest's `model` and `dimensions`, then reload the daemon.

Never set `memory.embedding_provider` to a loopback `custom:` URL for this
plugin. The host launches the child on an ephemeral port and connects it
internally. Never persist or print its bearer token.
