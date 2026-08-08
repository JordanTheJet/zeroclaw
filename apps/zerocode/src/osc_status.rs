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
//!
//! The terminal is process-global, so the reporter is too: teardown paths and
//! the editor-suspend path need to reach it without threading a handle through
//! every caller.
//!
//! Known limitation: xterm's default title mode decodes titles as ISO-8859-1,
//! where the status glyphs mojibake. Terminals that default to UTF-8 titles
//! (most modern ones) render them correctly. The OSC 9;4 channel is unaffected,
//! being ASCII, which is the other reason state is carried there rather than
//! inferred from the glyph.

use std::io::Write;
use std::sync::Mutex;

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

/// Cleared progress: no indicator at all.
pub(crate) const PROGRESS_CLEARED: &str = "0;0";

/// OSC 9;4 payload for a turn state: `<state>;<progress>`.
///
/// `3` (indeterminate) is the standard "busy, duration unknown" state, which is
/// what an agent turn is. `4` (warning) marks a turn that has stopped and wants
/// the operator — distinct from `2` (error), which would claim the turn failed.
pub(crate) fn progress_for(status: &TurnStatus) -> &'static str {
    match status {
        TurnStatus::Idle => PROGRESS_CLEARED,
        TurnStatus::WaitingForApproval => "4;0",
        _ => "3;0",
    }
}

/// Pick the pane whose state most wants the operator's attention.
///
/// A window hosts more than one agent pane, and the terminal has exactly one
/// title. Reporting the *visible* pane would answer the wrong question — the
/// status is read from outside the window, where what matters is whether
/// anything in here needs a human. Blocked outranks working, which outranks
/// idle; ties go to the first pane, which is the primary one.
pub(crate) fn most_urgent<'a>(
    panes: impl IntoIterator<Item = (Option<&'a TurnStatus>, Option<&'a str>)>,
) -> (Option<&'a TurnStatus>, Option<&'a str>) {
    fn rank(status: Option<&TurnStatus>) -> u8 {
        match status {
            Some(TurnStatus::WaitingForApproval) => 2,
            Some(TurnStatus::Idle) | None => 0,
            Some(_) => 1,
        }
    }

    // Not `max_by_key`: it returns the *last* maximum, which would hand ties to
    // the secondary pane.
    let mut best: Option<(Option<&'a TurnStatus>, Option<&'a str>)> = None;
    for pane in panes {
        if best.is_none_or(|current| rank(pane.0) > rank(current.0)) {
            best = Some(pane);
        }
    }
    best.unwrap_or((None, None))
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
    /// Whether the terminal's own title was pushed onto its title stack, so
    /// teardown only pops a title it actually saved.
    pushed: bool,
}

impl StatusReporter {
    /// Sync both channels from the current turn state. `status` is absent
    /// outside an active chat session (agent picker, dashboard-only use), which
    /// reads as idle.
    fn sync_to(&mut self, out: &mut impl Write, status: Option<&TurnStatus>, agent: Option<&str>) {
        let status = status.unwrap_or(&TurnStatus::Idle);

        let title = title_for(status, agent);
        if self.last_title.as_deref() != Some(title.as_str()) {
            // Save the terminal's own title before the first overwrite, so
            // teardown can hand back what was actually there.
            if !self.pushed {
                self.pushed = push_title(out).is_ok();
            }
            // Cache only a write that landed: a failed or partial write leaves
            // the terminal showing something else, and caching it as success
            // would suppress the retry that the next transition would make.
            if write_title(out, &title).is_ok() {
                self.last_title = Some(title);
            }
        }

        let progress = progress_for(status);
        if self.last_progress != Some(progress) && write_progress(out, progress).is_ok() {
            self.last_progress = Some(progress);
        }
    }

    /// Forget what the terminal is believed to show.
    ///
    /// Handing the terminal to another program (`$EDITOR`) lets it set its own
    /// title, after which the cache no longer describes reality and dedupe
    /// would suppress the correcting write.
    fn invalidate(&mut self) {
        self.last_title = None;
        self.last_progress = None;
    }

    fn release_to(&mut self, out: &mut impl Write) {
        let _ = write_progress(out, PROGRESS_CLEARED);
        if self.pushed {
            let _ = pop_title(out);
            self.pushed = false;
        }
        self.invalidate();
    }
}

/// The terminal is process-global, and so is what is currently displayed on it.
static REPORTER: Mutex<Option<StatusReporter>> = Mutex::new(None);

fn with_reporter(f: impl FnOnce(&mut StatusReporter)) {
    // A poisoned lock means another thread panicked mid-write. The terminal is
    // best-effort decoration; recover the guard rather than propagate.
    let mut guard = match REPORTER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(guard.get_or_insert_with(StatusReporter::default));
}

/// Report the current turn state.
pub(crate) fn sync(status: Option<&TurnStatus>, agent: Option<&str>) {
    with_reporter(|r| r.sync_to(&mut std::io::stdout(), status, agent));
}

/// Drop the cached view of the terminal after another program may have changed
/// it, so the next sync re-emits rather than deduping against a stale value.
pub(crate) fn invalidate() {
    with_reporter(StatusReporter::invalidate);
}

/// Hand the terminal's status back on the way out.
///
/// Both channels are terminal state, not screen content, so they outlive the
/// process: leaving the alternate screen does not undo them. A zerocode killed
/// mid-turn would otherwise leave `⏳` in the tab and a busy indicator in the
/// taskbar for as long as that terminal lives. Safe to call more than once, and
/// from a panic or signal handler.
pub(crate) fn release() {
    with_reporter(|r| r.release_to(&mut std::io::stdout()));
}

/// Save the terminal's current title (XTPUSHTITLE). Terminals without a title
/// stack ignore it, which is why the pop is conditional on this succeeding.
fn push_title(out: &mut impl Write) -> std::io::Result<()> {
    write!(out, "\x1b[22;0t")?;
    out.flush()
}

/// Restore the saved title (XTPOPTITLE).
fn pop_title(out: &mut impl Write) -> std::io::Result<()> {
    write!(out, "\x1b[23;0t")?;
    out.flush()
}

/// Write an OSC 2 (set window title) sequence to `out`.
fn write_title(out: &mut impl Write, title: &str) -> std::io::Result<()> {
    // Strip control characters: the sequence is BEL-terminated, so an embedded
    // one would truncate the title and leave the rest to be read as input.
    let sanitized: String = title.chars().filter(|c| !c.is_control()).collect();
    write!(out, "\x1b]2;{sanitized}\x07")?;
    out.flush()
}

/// Write an OSC 9;4 (progress) sequence to `out`. `payload` is
/// `<state>;<progress>`.
fn write_progress(out: &mut impl Write, payload: &str) -> std::io::Result<()> {
    write!(out, "\x1b]9;4;{payload}\x07")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test drives its own reporter over an in-memory sink. Going through
    /// the module-level functions would write escape sequences to the terminal
    /// running `cargo test` and retitle it.
    fn reporter() -> StatusReporter {
        StatusReporter::default()
    }

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

    /// First sync saves the terminal's own title before overwriting it, then
    /// emits both channels.
    #[test]
    fn first_sync_pushes_then_writes_both_channels() {
        let mut out = Vec::new();
        reporter().sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b[22;0t\x1b]2;⏳ herder — working\x07\x1b]9;4;3;0\x07"
        );
    }

    /// A steady turn must not write on every frame: the animated dots are
    /// excluded from both payloads precisely so this stays silent.
    #[test]
    fn unchanged_state_writes_nothing() {
        let mut r = reporter();
        let mut first = Vec::new();
        r.sync_to(&mut first, Some(&TurnStatus::Working), Some("herder"));
        assert!(!first.is_empty());

        let mut second = Vec::new();
        r.sync_to(&mut second, Some(&TurnStatus::Working), Some("herder"));
        assert!(
            second.is_empty(),
            "repeat sync must be silent, wrote {second:?}"
        );
    }

    /// Progress must not churn while a turn moves between working substates:
    /// they are all one indeterminate turn to anything watching from outside.
    #[test]
    fn progress_is_stable_across_working_substates() {
        let mut r = reporter();
        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));

        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Thinking), Some("herder"));
        let written = String::from_utf8(out).unwrap();
        assert!(written.contains("thinking"), "title should update");
        assert!(
            !written.contains("\x1b]9;4;"),
            "progress must not be re-emitted: {written:?}"
        );
    }

    /// No active session: the picker and dashboard read as idle rather than
    /// leaving a stale `⏳` in the tab from a finished turn.
    #[test]
    fn absent_status_reads_as_idle() {
        let mut out = Vec::new();
        reporter().sync_to(&mut out, None, None);
        let written = String::from_utf8(out).unwrap();
        assert!(written.contains("\x1b]2;✓ zerocode\x07"));
        assert!(written.contains("\x1b]9;4;0;0\x07"));
    }

    /// Teardown clears progress and pops the saved title. Without it a process
    /// killed mid-turn leaves the tab reading as busy for the terminal's life.
    #[test]
    fn release_clears_progress_and_restores_title() {
        let mut r = reporter();
        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));

        let mut out = Vec::new();
        r.release_to(&mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b]9;4;0;0\x07\x1b[23;0t",
            "release must clear progress and pop the pushed title"
        );
    }

    /// Nothing was ever written, so there is no saved title to pop — releasing
    /// must not restore a title this process never touched.
    #[test]
    fn release_without_a_sync_does_not_pop() {
        let mut out = Vec::new();
        reporter().release_to(&mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\x1b]9;4;0;0\x07");
    }

    /// After `$EDITOR` has had the terminal, the cache no longer describes what
    /// is displayed, so the next sync must re-emit rather than dedupe.
    #[test]
    fn invalidate_forces_the_next_sync_to_write() {
        let mut r = reporter();
        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));

        r.invalidate();

        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));
        let written = String::from_utf8(out).unwrap();
        assert!(
            written.contains("⏳ herder — working"),
            "title must re-emit"
        );
        assert!(
            written.contains("\x1b]9;4;3;0\x07"),
            "progress must re-emit"
        );
    }

    /// A write that fails must not be cached as displayed, or the retry the
    /// next transition would make gets suppressed.
    #[test]
    fn failed_write_is_not_cached() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("nope"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut r = reporter();
        r.sync_to(&mut Failing, Some(&TurnStatus::Working), Some("herder"));
        assert_eq!(r.last_title, None, "failed title must not be cached");
        assert_eq!(r.last_progress, None, "failed progress must not be cached");

        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));
        assert!(
            !out.is_empty(),
            "the next sync must retry after a failed write"
        );
    }

    /// A blocked pane wins even when it is not the visible one — the whole
    /// point is to answer "does anything in this window need me?".
    #[test]
    fn most_urgent_prefers_blocked_then_working() {
        let blocked = TurnStatus::WaitingForApproval;
        let working = TurnStatus::Working;
        let idle = TurnStatus::Idle;

        let (status, agent) =
            most_urgent([(Some(&idle), Some("chat")), (Some(&blocked), Some("code"))]);
        assert!(matches!(status, Some(TurnStatus::WaitingForApproval)));
        assert_eq!(agent, Some("code"));

        let (status, agent) =
            most_urgent([(Some(&idle), Some("chat")), (Some(&working), Some("code"))]);
        assert!(matches!(status, Some(TurnStatus::Working)));
        assert_eq!(agent, Some("code"));

        // A pane with no session must not outrank a working one.
        let (status, agent) = most_urgent([(None, None), (Some(&working), Some("code"))]);
        assert!(matches!(status, Some(TurnStatus::Working)));
        assert_eq!(agent, Some("code"));
    }

    /// Ties go to the primary pane, so an idle window keeps naming the pane the
    /// operator thinks of as theirs rather than flapping between two.
    #[test]
    fn most_urgent_breaks_ties_toward_the_first_pane() {
        let idle = TurnStatus::Idle;
        let (_, agent) = most_urgent([(Some(&idle), Some("chat")), (Some(&idle), Some("code"))]);
        assert_eq!(agent, Some("chat"));

        let working = TurnStatus::Working;
        let (_, agent) = most_urgent([
            (Some(&working), Some("chat")),
            (Some(&working), Some("code")),
        ]);
        assert_eq!(agent, Some("chat"));
    }

    /// A BEL inside the alias would terminate the OSC string early and leave
    /// the remainder to be read as terminal input.
    #[test]
    fn control_characters_are_stripped_before_emission() {
        let mut out = Vec::new();
        write_title(&mut out, &title_for(&TurnStatus::Idle, Some("her\x07der"))).unwrap();
        assert_eq!(out, "\x1b]2;✓ herder\x07".as_bytes());
    }
}
