# Reference local embedding plugin

This is the source template used to exercise ZeroClaw's managed embedding
sidecar path. Packaging builds `zeroclaw-reference-embedding-sidecar`, places
it at the path declared by `embedding_provider.executable.path`, and replaces
the zero placeholder digest with the executable's SHA-256 before running
`zeroclaw plugin install` on the resulting directory. The end-to-end test
performs those packaging steps and installs the completed bundle.

The signed manifest is the canonical source for the model ID, vector
dimensions, executable, arguments, and artifact digests. The reference binary
is compiled from those manifest values, so the bundled skill never needs to
execute an untrusted payload to discover configuration.

Before selecting this provider, the operator must explicitly enable both
`plugins.enabled` and `plugins.allow_native_sidecars`. The plugin may explain
that requirement, but cannot grant itself native process permission. Configure
`memory.embedding_provider = "plugin:reference-local-embedding"`; never put its
ephemeral loopback port or bearer token in configuration.

Real model bundles use the same manifest shape. List weight/tokenizer files or
directories in `embedding_provider.artifacts`; every entry carries a digest.
Local-directory installation streams those payloads without applying the WASM
module-size or linear-memory limits. Registry archives retain the registry's
separate archive-size policy.

## Sidecar launch contract

The host starts the declared executable directly, with the plugin directory as
its working directory and a cleared environment. The child must:

1. Read one newline-terminated 256-bit hexadecimal bearer token from stdin.
2. Bind an ephemeral listener on literal `127.0.0.1` and print one
   newline-terminated readiness JSON object containing `protocol_version`,
   `base_url`, `model`, and `dimensions`.
3. Serve OpenAI-compatible `POST /v1/embeddings` requests authenticated with
   that bearer token.
4. Keep monitoring stdin and exit when it reaches EOF, which ensures that the
   model process does not survive an unexpected host exit.

The readiness URL is an internal transport detail. It is never written into
ZeroClaw configuration or vector-identity metadata.
