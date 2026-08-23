//! Canonical text-mode tool-call formatting guidance.
//!
//! This module is the single source of truth for the `<tool_call>` protocol
//! block that goes into a system prompt when a model is driven with text
//! (XML-tag) tool calling rather than native tool specs.
//!
//! Every prompt builder that advertises the text tool protocol MUST push
//! [`TOOL_CALL_PROTOCOL_INSTRUCTIONS`] verbatim instead of re-typing the
//! wording. Builder-specific material (the `### Available Tools` listing, for
//! example) layers *around* the shared block; it never restates it. Two
//! builders previously carried near-duplicate copies of this text and had
//! already drifted — the XML dispatcher's copy was missing the `CRITICAL:`
//! line and the worked example — so tool-use behavior silently depended on
//! which builder produced the prompt.
//!
//! Consumers:
//! - `agent::dispatcher::XmlToolDispatcher::prompt_instructions`
//! - `agent::loop_::build_tool_instructions` (and its `_for_names` sibling)

/// The canonical tool-call formatting block, including its `## Tool Use
/// Protocol` heading and a trailing blank line.
///
/// The text tells the model to emit real `<tool_call>` tags wrapping a JSON
/// object with a top-level `name` and a nested `arguments` object.
///
/// Callers that need a leading blank line before the heading push `'\n'`
/// themselves; the constant deliberately starts at the heading so it can be
/// embedded in prompts that already end with a separator.
pub(crate) const TOOL_CALL_PROTOCOL_INSTRUCTIONS: &str = r#"## Tool Use Protocol

To use a tool, wrap a JSON object in <tool_call></tool_call> tags:

```
<tool_call>
{"name": "tool_name", "arguments": {"param": "value"}}
</tool_call>
```

CRITICAL: Output actual <tool_call> tags—never describe steps or give examples.

Example: User says "what's the date?". You MUST respond with:
<tool_call>
{"name":"shell","arguments":{"command":"date"}}
</tool_call>

You may use multiple tool calls in a single response. After tool execution, results appear in <tool_result> tags. Continue reasoning with the results until you can give a final answer.

"#;

#[cfg(test)]
mod tests {
    use super::TOOL_CALL_PROTOCOL_INSTRUCTIONS;
    use crate::agent::dispatcher::{ToolDispatcher, XmlToolDispatcher};
    use crate::agent::loop_::build_tool_instructions;
    use crate::security::SecurityPolicy;
    use crate::tools::{Tool, default_tools};

    fn probe_tools() -> Vec<Box<dyn Tool>> {
        let security = std::sync::Arc::new(SecurityPolicy::from_risk_profile(
            &zeroclaw_config::schema::RiskProfileConfig::default(),
            std::path::Path::new("/tmp"),
        ));
        default_tools(security)
    }

    /// Pins the shape of the canonical block: heading first, trailing blank
    /// line last, so call sites can concatenate it without guessing at
    /// separators.
    #[test]
    fn canonical_block_starts_with_heading_and_ends_with_blank_line() {
        assert!(
            TOOL_CALL_PROTOCOL_INSTRUCTIONS.starts_with("## Tool Use Protocol\n\n"),
            "shared block must open with the protocol heading"
        );
        assert!(
            TOOL_CALL_PROTOCOL_INSTRUCTIONS.ends_with("final answer.\n\n"),
            "shared block must end with a trailing blank line"
        );
    }

    /// The acceptance criterion from the issue: the guidance still tells the
    /// model to emit real tags carrying `name` and a nested `arguments`.
    #[test]
    fn canonical_block_demands_real_tags_with_name_and_arguments() {
        for required in [
            "<tool_call>",
            "</tool_call>",
            r#"{"name": "tool_name", "arguments": {"param": "value"}}"#,
            "CRITICAL: Output actual <tool_call> tags",
            "Example: User says",
        ] {
            assert!(
                TOOL_CALL_PROTOCOL_INSTRUCTIONS.contains(required),
                "shared block lost required guidance: {required:?}"
            );
        }
    }

    /// Anti-drift guard. Both text-protocol prompt builders must embed the
    /// shared block byte-for-byte; a builder that re-types the wording (or
    /// keeps a stale copy) fails here.
    #[test]
    fn both_prompt_builders_embed_the_shared_block() {
        let tools = probe_tools();

        let dispatcher_block = XmlToolDispatcher.prompt_instructions(&tools);
        assert!(
            dispatcher_block.contains(TOOL_CALL_PROTOCOL_INSTRUCTIONS),
            "XmlToolDispatcher::prompt_instructions drifted from the shared block:\n{dispatcher_block}"
        );

        let loop_block = build_tool_instructions(&tools);
        assert!(
            loop_block.contains(TOOL_CALL_PROTOCOL_INSTRUCTIONS),
            "build_tool_instructions drifted from the shared block:\n{loop_block}"
        );
    }

    /// Byte-identity pin for the loop_ builder: the shared block plus the
    /// builder's own `### Available Tools` header must reproduce the exact
    /// prefix the builder emitted before the block was extracted.
    #[test]
    fn loop_builder_prefix_is_shared_block_then_tool_listing() {
        let tools = probe_tools();
        let expected_prefix = format!("\n{TOOL_CALL_PROTOCOL_INSTRUCTIONS}### Available Tools\n\n");

        let instructions = build_tool_instructions(&tools);
        assert!(
            instructions.starts_with(&expected_prefix),
            "loop_ tool instructions no longer start with the canonical envelope:\n{instructions}"
        );
    }
}
