//! Canonical hardware tool-name and capability catalog.

/// Built-in hardware tools always present with the `hardware` feature.
pub const BASE_TOOLS: &[&str] = &[
    "gpio_read",
    "gpio_write",
    "pico_flash",
    "device_read_code",
    "device_write_code",
    "device_exec",
];

/// Datasheet lookup, loaded with the `hardware` feature. Previously gated on an
/// Aardvark adapter being present; that adapter support was removed, and the
/// tool is useful for any connected device.
pub const DATASHEET_TOOLS: &[&str] = &["datasheet"];

/// probe-rs backed introspection tools (in `zeroclaw-tools`).
pub const PROBE_TOOLS: &[&str] = &[
    "hardware_board_info",
    "hardware_memory_map",
    "hardware_memory_read",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_tool_count_matches_registry_contract() {
        assert_eq!(BASE_TOOLS.len(), 6);
    }

    #[test]
    fn no_duplicate_tool_names_across_sets() {
        let mut all: Vec<&str> = BASE_TOOLS
            .iter()
            .chain(DATASHEET_TOOLS)
            .chain(PROBE_TOOLS)
            .copied()
            .collect();
        let before = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), before, "duplicate tool name across catalog sets");
    }
}
