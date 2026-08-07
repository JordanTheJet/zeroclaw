//! Global tracing-subscriber installation. The only public entry
//! point a daemon binary needs. Owns the agent-alias-prefixed
//! formatter and the `LogCaptureLayer` wiring so the rest of the
//! workspace never names a `tracing` or `tracing_subscriber` type.

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::event::ZeroclawAttribution;
use crate::layer::LogCaptureLayer;

/// Install the global tracing subscriber. Two independent axes:
///
/// * **Recording floor** — what reaches the `LogCaptureLayer` (and thus
///   the JSONL writer, broadcast hook, and Observer bridge). Resolved
///   as: `recording_override` (the `--log-level` flag) if `Some`,
///   else `RUST_LOG` from the environment, else `default_filter`.
///
/// * **Terminal display** — the stderr fmt layer. Gated entirely by
///   `verbose`: when `false` the fmt layer is muted (no log lines ever
///   reach the terminal; direct `println!`/stdout is untouched). When
///   `true` it surfaces events down to the same recording floor.
///
/// All filter strings are `RUST_LOG`-compatible directives (e.g.
/// `"info"` or `"debug,matrix_sdk=warn"`).
///
/// Both axes are fixed for the process lifetime — the global subscriber
/// is installed once and cannot be reconfigured without a restart.
///
/// Both axes cover dependencies that log through the `log` crate rather
/// than `tracing`, because installation goes through
/// [`SubscriberInitExt::init`], which also installs the `LogTracer`
/// bridge. That bridge is what makes those records visible at all: it
/// converts them into `tracing` events *before* either filter runs.
/// Without it they are dropped at the `log` facade and no filter or
/// `RUST_LOG` value can recover them. This is not theoretical — every
/// record from `whatsapp-rust` (300+ sites, all `log::*`, targets like
/// `Client/PairCode`) was silently discarded until the bridge was added,
/// which meant failures inside that library produced no diagnostics.
///
/// Panics on subscriber install failure — the daemon cannot operate
/// without logging.
pub fn install_global_subscriber(
    recording_override: Option<&str>,
    default_filter: &str,
    verbose: bool,
) {
    // Recording floor: explicit flag wins, then RUST_LOG, then default.
    let recording_filter = match recording_override {
        Some(flag) => EnvFilter::new(flag),
        None => {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter))
        }
    };

    // The fmt (terminal) layer carries its own filter so display can be
    // muted without touching what the capture layer records. When
    // verbose is off, an OFF filter discards every event before it
    // formats — stdout (println!) is unaffected because it never routes
    // through tracing.
    let fmt_filter = if verbose {
        match recording_override {
            Some(flag) => EnvFilter::new(flag),
            None => {
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter))
            }
        }
    } else {
        EnvFilter::new("off")
    };

    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .event_format(AgentAliasFormatter::new())
        .with_filter(fmt_filter);

    let subscriber = tracing_subscriber::registry()
        .with(LogCaptureLayer.with_filter(recording_filter))
        .with(fmt_layer);

    // `init()` rather than `set_global_default`: it installs the same
    // subscriber AND the `LogTracer` bridge that routes `log` records into
    // tracing. `set_global_default` installs only the subscriber, so
    // `log`-emitting dependencies stay invisible however the filters are set.
    // Enabling the `tracing-log` feature alone does not help — it makes the
    // bridge available, not installed.
    subscriber
        .try_init()
        .expect("setting default subscriber failed");
}

/// Test-only helper: install a minimal global subscriber that routes
/// `record!` emissions through `LogCaptureLayer` (and thus the broadcast
/// hook) without any terminal fmt output. Returns a guard that resets
/// the broadcast hook on drop. Use in combination with
/// [`crate::subscribe`] to capture events from a unit test without
/// the test crate depending on `tracing` / `tracing-subscriber`.
///
/// Idempotent: subsequent calls are no-ops if a subscriber is already
/// installed (the global default cannot be replaced once set). For
/// isolated capture across multiple tests, use the broadcast hook
/// directly without changing the global subscriber.
#[doc(hidden)]
pub fn try_install_capture_subscriber() {
    use tracing_subscriber::Registry;
    let subscriber = Registry::default().with(LogCaptureLayer);
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Tracing event formatter that prefixes each log line with the most
/// specific alias-bound label available in the current span scope.
/// `agent_alias` wins; falls back to the channel composite; finally
/// to `[system]` for boot / migration / install-wide messages.
struct AgentAliasFormatter {
    inner: fmt::format::Format<fmt::format::Full, fmt::time::SystemTime>,
}

impl AgentAliasFormatter {
    fn new() -> Self {
        Self {
            inner: fmt::format::Format::default(),
        }
    }
}

impl<S, N> fmt::FormatEvent<S, N> for AgentAliasFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let label = ctx
            .event_scope()
            .and_then(|scope| {
                scope.into_iter().find_map(|span| {
                    span.extensions()
                        .get::<ZeroclawAttribution>()
                        .and_then(|attribution| {
                            attribution
                                .get("agent_alias")
                                .or_else(|| attribution.get("channel"))
                                .map(str::to_string)
                        })
                })
            })
            .unwrap_or_else(|| "system".to_string());
        write!(writer, "[{label}] ")?;
        self.inner.format_event(ctx, writer, event)
    }
}
