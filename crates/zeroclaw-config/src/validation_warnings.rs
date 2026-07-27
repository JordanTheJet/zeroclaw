//! Non-fatal validation warnings for config that loads and validates
//! successfully (i.e. `Config::validate()` returns `Ok(())`) but needs user
//! attention. Warnings may identify a runtime inconsistency, an inert setting,
//! or a supported configuration that is being deprecated.

use serde::{Deserialize, Serialize};

/// One non-fatal validation issue surfaced after a successful save.
///
/// Stable codes (extend as new warnings are added):
/// - `memory_semantic_search_without_embedder`: `memory.search_mode` requests
///   vector search on sqlite memory, but no effective embedder is configured.
/// - `memory_config_knob_inert`: a `[memory]` knob is set to a non-default
///   value but has no runtime consumer yet, so it currently has no effect
///   (see `validate_memory_semantics` in `schema.rs` for the current list).
/// - `skills_prompt_injection_mode_full_deprecated`: explicit global full skill
///   injection remains supported but is deprecated before Schema V4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct ValidationWarning {
    /// Stable machine-readable identifier for the warning class.
    pub code: String,
    /// Stable English fallback for logs and consumers without a localization catalog.
    /// User-facing surfaces should localize from `code` and use this only for unknown codes.
    pub message: String,
    /// Dotted property path the warning concerns
    /// (e.g. `"agents.researcher.model_provider"`).
    pub path: String,
}

impl ValidationWarning {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            path: path.into(),
        }
    }
}
