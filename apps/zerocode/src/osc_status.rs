//! Turn state reported to the terminal itself, over two standard OSC channels.
//!
//! The input bar already shows the turn state, but only to someone looking at
//! this pane. Writing it to the terminal makes it travel: tmux and zellij
//! surface it in their status lines, emulators put it in the tab and the
//! taskbar, and terminal workspace managers read it to decide whether an agent
//! needs attention.
//!
//! Both channels are terminal conventions, not an integration with any one
//! tool. Nothing here knows what is reading it, and no consumer needs ZeroClaw
//! to know about it.
//!
//! **OSC 2 — window title.** Human-facing. Leads with a status glyph, since the
//! glyph survives translation while the verb after it does not.
//!
//! **OSC 9;4 — progress.** Machine-facing, the ConEmu convention that Windows
//! Terminal, WezTerm, and Ghostty implement to drive a busy/error indicator.
//! Its states are semantic rather than decorative, so a reader gets the turn
//! state without matching glyphs or parsing prose in an unknown locale.
//!
//! | Turn state | OSC 2 glyph | OSC 9;4 |
//! |------------|-------------|---------|
//! | idle — waiting for input | `✓` | `0;0` — cleared |
//! | working — turn in flight | `⏳` | `3;0` — indeterminate |
//! | blocked — awaiting approval | `⚠` | `4;0` — warning |

use std::io::Write;

use crate::turn_status::TurnStatus;

/// Status glyph for a turn state. Leading character of the title.
fn glyph(status: &TurnStatus) -> char {
    match status {
        TurnStatus::Idle => '✓',
        TurnStatus::WaitingForApproval => '⚠',
        _ => '⏳',
    }
}

/// Compose the terminal title for a turn state.
///
/// `agent` is the active agent alias, absent while the agent picker is open.
/// Kept short — terminal tabs truncate aggressively, so the glyph and the alias
/// come first and the verb is the part that gets cut.
pub(crate) fn title_for(status: &TurnStatus, agent: Option<&str>) -> String {
    let glyph = glyph(status);
    let Some(agent) = agent else {
        return format!("{glyph} zerocode");
    };
    match status {
        TurnStatus::Idle => format!("{glyph} {agent}"),
        TurnStatus::WaitingForApproval => format!("{glyph} {agent} — awaiting approval"),
        other => match other.verb() {
            Some(verb) => format!("{glyph} {agent} — {verb}"),
            None => format!("{glyph} {agent}"),
        },
    }
}

/// OSC 9;4 payload for a turn state: `<state>;<progress>`.
///
/// `3` (indeterminate) is the standard "busy, duration unknown" state, which is
/// what an agent turn is. `4` (warning) marks a turn that has stopped and wants
/// the operator — distinct from `2` (error), which would claim the turn failed.
/// `0` clears the indicator so a finished pane stops showing as busy.
pub(crate) fn progress_for(status: &TurnStatus) -> &'static str {
    match status {
        TurnStatus::Idle => "0;0",
        TurnStatus::WaitingForApproval => "4;0",
        _ => "3;0",
    }
}

/// Emits terminal status, skipping writes when nothing changed.
///
/// A turn's verb changes on most frames while the dots animate, but neither
/// payload is built from them, so a steady turn produces no writes after the
/// first.
#[derive(Default)]
pub(crate) struct StatusReporter {
    last_title: Option<String>,
    last_progress: Option<&'static str>,
}

impl StatusReporter {
    /// Sync both channels from the current turn state. `status` is absent
    /// outside an active chat session (agent picker, dashboard-only use), which
    /// reads as idle.
    pub(crate) fn sync(&mut self, status: Option<&TurnStatus>, agent: Option<&str>) {
        let status = status.unwrap_or(&TurnStatus::Idle);

        let title = title_for(status, agent);
        if self.last_title.as_deref() != Some(title.as_str()) {
            emit_title(&title);
            self.last_title = Some(title);
        }

        let progress = progress_for(status);
        if self.last_progress != Some(progress) {
            emit_progress(progress);
            self.last_progress = Some(progress);
        }
    }
}

/// Write an OSC 2 (set window title) sequence to `out`.
fn write_title(out: &mut impl Write, title: &str) {
    // Strip control characters: the sequence is BEL-terminated, so an embedded
    // one would truncate the title and leave the rest to be read as input.
    let sanitized: String = title.chars().filter(|c| !c.is_control()).collect();
    let _ = write!(out, "\x1b]2;{sanitized}\x07");
    let _ = out.flush();
}

/// Write an OSC 9;4 (progress) sequence to `out`. `payload` is
/// `<state>;<progress>`.
fn write_progress(out: &mut impl Write, payload: &str) {
    let _ = write!(out, "\x1b]9;4;{payload}\x07");
    let _ = out.flush();
}

/// Both sequences go straight to the terminal rather than through ratatui: OSC
/// sets terminal state rather than painting cells, so neither disturbs the
/// frame buffer nor moves the cursor, and both must survive the alternate
/// screen. Write failures are ignored — a terminal that ignores these is not an
/// error worth surfacing, and one that does not understand them discards them
/// rather than rendering anything.
fn emit_title(title: &str) {
    write_title(&mut std::io::stdout(), title);
}

fn emit_progress(payload: &str) {
    write_progress(&mut std::io::stdout(), payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_title_is_glyph_and_alias() {
        assert_eq!(title_for(&TurnStatus::Idle, Some("herder")), "✓ herder");
    }

    #[test]
    fn working_title_carries_the_verb() {
        assert_eq!(
            title_for(&TurnStatus::Working, Some("herder")),
            "⏳ herder — working"
        );
    }

    #[test]
    fn tool_call_title_names_the_tool() {
        assert_eq!(
            title_for(&TurnStatus::CallingTool("git_diff".into()), Some("herder")),
            "⏳ herder — calling tool git_diff"
        );
    }

    #[test]
    fn approval_title_is_the_warning_glyph() {
        assert_eq!(
            title_for(&TurnStatus::WaitingForApproval, Some("herder")),
            "⚠ herder — awaiting approval"
        );
    }

    #[test]
    fn without_an_agent_the_title_names_the_app() {
        assert_eq!(title_for(&TurnStatus::Idle, None), "✓ zerocode");
    }

    /// The animated dots must not reach the title: they change on most frames
    /// and would turn a steady turn into a write on every tick.
    #[test]
    fn title_is_stable_while_dots_animate() {
        let first = title_for(&TurnStatus::Thinking, Some("herder"));
        let second = title_for(&TurnStatus::Thinking, Some("herder"));
        assert_eq!(first, second);
        assert!(!first.contains('.'), "title must not carry dots: {first}");
    }

    #[test]
    fn reporter_writes_once_per_distinct_title() {
        let mut reporter = StatusReporter::default();
        reporter.sync(Some(&TurnStatus::Idle), Some("herder"));
        assert_eq!(reporter.last_title.as_deref(), Some("✓ herder"));
        reporter.sync(Some(&TurnStatus::Idle), Some("herder"));
        assert_eq!(reporter.last_title.as_deref(), Some("✓ herder"));
        reporter.sync(Some(&TurnStatus::Working), Some("herder"));
        assert_eq!(reporter.last_title.as_deref(), Some("⏳ herder — working"));
    }

    /// No active session: the picker and dashboard read as idle rather than
    /// leaving a stale `⏳` in the tab from a finished turn.
    #[test]
    fn absent_status_reads_as_idle() {
        let mut reporter = StatusReporter::default();
        reporter.sync(None, None);
        assert_eq!(reporter.last_title.as_deref(), Some("✓ zerocode"));
        assert_eq!(reporter.last_progress, Some("0;0"));
    }

    /// The progress payloads are the contract a reader keys on, so they are
    /// asserted literally rather than through a helper.
    #[test]
    fn progress_states_are_semantic() {
        assert_eq!(progress_for(&TurnStatus::Idle), "0;0");
        assert_eq!(progress_for(&TurnStatus::Working), "3;0");
        assert_eq!(progress_for(&TurnStatus::Thinking), "3;0");
        assert_eq!(progress_for(&TurnStatus::Responding), "3;0");
        assert_eq!(progress_for(&TurnStatus::Cancelling), "3;0");
        assert_eq!(progress_for(&TurnStatus::CallingTool("git".into())), "3;0");
        assert_eq!(progress_for(&TurnStatus::WaitingForApproval), "4;0");
    }

    /// Progress must not churn while a turn moves between working substates:
    /// they are all one indeterminate turn to anything watching from outside.
    #[test]
    fn progress_is_stable_across_working_substates() {
        let mut reporter = StatusReporter::default();
        reporter.sync(Some(&TurnStatus::Working), Some("herder"));
        assert_eq!(reporter.last_progress, Some("3;0"));
        reporter.sync(Some(&TurnStatus::Thinking), Some("herder"));
        assert_eq!(reporter.last_progress, Some("3;0"));
        reporter.sync(Some(&TurnStatus::WaitingForApproval), Some("herder"));
        assert_eq!(reporter.last_progress, Some("4;0"));
        reporter.sync(Some(&TurnStatus::Idle), Some("herder"));
        assert_eq!(reporter.last_progress, Some("0;0"));
    }

    /// The exact bytes on the wire. A reader keys on these, so they are pinned
    /// literally rather than through the helpers that build them.
    #[test]
    fn emitted_sequences_are_well_formed() {
        let mut out = Vec::new();
        write_title(&mut out, "✓ herder");
        assert_eq!(out, "\x1b]2;✓ herder\x07".as_bytes());

        let mut out = Vec::new();
        write_progress(&mut out, progress_for(&TurnStatus::Working));
        assert_eq!(out, b"\x1b]9;4;3;0\x07");

        let mut out = Vec::new();
        write_progress(&mut out, progress_for(&TurnStatus::WaitingForApproval));
        assert_eq!(out, b"\x1b]9;4;4;0\x07");

        let mut out = Vec::new();
        write_progress(&mut out, progress_for(&TurnStatus::Idle));
        assert_eq!(out, b"\x1b]9;4;0;0\x07");
    }

    /// A BEL inside the alias would terminate the OSC string early and leave
    /// the remainder to be read as terminal input.
    #[test]
    fn control_characters_are_stripped_before_emission() {
        let mut out = Vec::new();
        write_title(&mut out, &title_for(&TurnStatus::Idle, Some("her\x07der")));
        assert_eq!(out, "\x1b]2;✓ herder\x07".as_bytes());
    }
}
