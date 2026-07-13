# ZeroRouter

ZeroRouter is a first-class OpenAI-compatible provider slot for routing a
ZeroClaw agent through a ZeroRouter deployment. The deployment remains the
source of truth for its URL, API keys, virtual model catalog, routing policy,
and pricing.

## Configuration

Every deployment has its own endpoint, so `uri` is required and must include
the `/v1` base path. Store the bearer credential through ZeroClaw's secret
store, a schema-mirror environment override, or an `op://` reference; do not
commit it.

```toml
[providers.models.zerorouter.default]
uri = "https://router.example.com/v1"
api_key = "op://platform/zerorouter/api-key"
model = "<virtual-model-from-the-deployment-catalog>"

[agents.router]
model_provider = "zerorouter.default"
risk_profile = "default"

[risk_profiles.default]
```

ZeroRouter supports OpenAI chat completions, streaming, and native tool calls.
The provider reads the deployment's unauthenticated `GET /v1/models` response,
so ZeroClaw does not maintain a second copy of the available model IDs. Network
access controls on the deployment still apply.

## Verify the connection

```sh
zeroclaw config list
zeroclaw models refresh --model-provider zerorouter.default
zeroclaw agent -a router -m "Reply with: ZeroRouter connected"
```

For a process-local credential override, translate the config path with double
underscores:

```sh
export ZEROCLAW_providers__models__zerorouter__default__api_key="$ZEROROUTER_API_KEY"
```

Use HTTPS before sending durable customer keys or production prompt content.
For endpoint overrides, fallbacks, and secret-storage options, see
[Provider configuration](./configuration.md).
