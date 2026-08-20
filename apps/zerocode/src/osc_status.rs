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
//!
//! Title restoration is best-effort. XTPUSHTITLE has no capability response:
//! a terminal may accept the bytes, ignore the title stack, and still honor
//! OSC 2. Zerocode therefore never treats `Write::is_ok()` as proof of support.
//! It records a restore obligation before the first overwrite, pairs every
//! graceful teardown with a neutral title followed by XTPOPTITLE, and retains
//! that obligation when a pop fails so a later teardown path can retry. A
//! stack-capable terminal restores its saved title; a stack-less terminal keeps
//! the neutral fallback instead of a stale working or blocked title.

use std::io::Write;
use std::sync::{Mutex, TryLockError};

use crate::turn_status::TurnStatus;

/// Terminal tabs are narrow and titles can contain model-influenced tool
/// names. Bound the payload as defense in depth even after controls are removed.
const MAX_TITLE_CHARS: usize = 120;

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
/// idle; a named pane outranks an unnamed one at equal urgency; remaining ties
/// go to the first pane, which is the primary one.
pub(crate) fn most_urgent<'a>(
    panes: impl IntoIterator<Item = (Option<&'a TurnStatus>, Option<&'a str>)>,
) -> (Option<&'a TurnStatus>, Option<&'a str>) {
    fn rank(pane: (Option<&TurnStatus>, Option<&str>)) -> (u8, bool) {
        let urgency = match pane.0 {
            Some(TurnStatus::WaitingForApproval) => 2,
            Some(TurnStatus::Idle) | None => 0,
            Some(_) => 1,
        };
        // Naming breaks an urgency tie only. An unnamed pane knows of no agent,
        // so preferring it would drop a real name from the title for nothing —
        // an idle session on the secondary pane still reads better as
        // `✓ osctest` than as `✓ zerocode`.
        (urgency, pane.1.is_some())
    }

    // Not `max_by_key`: it returns the *last* maximum, which would hand ties to
    // the secondary pane.
    let mut best: Option<(Option<&'a TurnStatus>, Option<&'a str>)> = None;
    for pane in panes {
        if best.is_none_or(|current| rank(pane) > rank(current)) {
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
    /// Whether any title overwrite may have reached the terminal and therefore
    /// needs a best-effort XTPOPTITLE. Set before I/O because a failed write can
    /// still be partial; cleared only after a complete pop and flush.
    title_restore_needed: bool,
}

impl StatusReporter {
    /// Sync both channels from the current turn state. `status` is absent
    /// outside an active chat session (agent picker, dashboard-only use), which
    /// reads as idle.
    fn sync_to(&mut self, out: &mut impl Write, status: Option<&TurnStatus>, agent: Option<&str>) {
        let status = status.unwrap_or(&TurnStatus::Idle);

        let title = title_for(status, agent);
        if self.last_title.as_deref() != Some(title.as_str()) {
            // A successful write cannot prove title-stack support, and a
            // failed write may be partial. Record cleanup ownership before
            // sending either sequence, then always pair it with a later pop.
            if !self.title_restore_needed {
                self.title_restore_needed = true;
                let _ = push_title(out);
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
        if self.title_restore_needed {
            // Neutralize attention state before pop. Terminals with a title
            // stack restore the prior title; terminals that ignored the push
            // retain this harmless fallback instead of stale busy text.
            let _ = write_title(out, "zerocode");
            if pop_title(out).is_ok() {
                self.title_restore_needed = false;
            }
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
    release_reporter_to(&REPORTER, &mut std::io::stdout());
}

/// Release through `reporter` without waiting for its mutex.
///
/// A panic can originate inside a terminal write while `sync` holds this lock;
/// blocking here would deadlock the panic hook before raw mode is restored. In
/// that case emit the idempotent cleanup sequences directly. They may race a
/// write from the failing thread, but the process is already unwinding and a
/// bounded best-effort cleanup is strictly safer than waiting forever.
fn release_reporter_to(reporter: &Mutex<Option<StatusReporter>>, out: &mut impl Write) {
    match reporter.try_lock() {
        Ok(mut guard) => guard
            .get_or_insert_with(StatusReporter::default)
            .release_to(out),
        Err(TryLockError::Poisoned(poisoned)) => poisoned
            .into_inner()
            .get_or_insert_with(StatusReporter::default)
            .release_to(out),
        Err(TryLockError::WouldBlock) => emergency_release_to(out),
    }
}

fn emergency_release_to(out: &mut impl Write) {
    let _ = write_progress(out, PROGRESS_CLEARED);
    let _ = write_title(out, "zerocode");
    let _ = pop_title(out);
}

/// Ask the terminal to save its current title (XTPUSHTITLE). There is no
/// capability acknowledgment; teardown pairs any attempted overwrite with a
/// best-effort pop regardless of this write's result.
fn push_title(out: &mut impl Write) -> std::io::Result<()> {
    out.write_all(b"\x1b[22;0t")?;
    out.flush()
}

/// Restore the saved title (XTPOPTITLE).
fn pop_title(out: &mut impl Write) -> std::io::Result<()> {
    out.write_all(b"\x1b[23;0t")?;
    out.flush()
}

/// Unicode Default_Ignorable format controls that can reorder or hide title
/// text without being `char::is_control()`. Keep this local and dependency-free
/// because the title path needs only a denylist, not full Unicode segmentation.
fn is_format_control(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .filter(|c| !c.is_control() && !is_format_control(*c))
        .take(MAX_TITLE_CHARS)
        .collect()
}

/// Write an OSC 2 (set window title) sequence to `out`.
fn write_title(out: &mut impl Write, title: &str) -> std::io::Result<()> {
    // BEL/ESC could terminate or extend the sequence; bidi and other format
    // controls can visually spoof its source even without injecting bytes.
    let sanitized = sanitize_title(title);
    let sequence = format!("\x1b]2;{sanitized}\x07");
    out.write_all(sequence.as_bytes())?;
    out.flush()
}

/// Write an OSC 9;4 (progress) sequence to `out`. `payload` is
/// `<state>;<progress>`.
fn write_progress(out: &mut impl Write, payload: &str) -> std::io::Result<()> {
    let sequence = format!("\x1b]9;4;{payload}\x07");
    out.write_all(sequence.as_bytes())?;
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

    /// Teardown clears progress, writes a neutral fallback, then pops. A
    /// title-stack terminal restores its saved title; a stack-less terminal
    /// ignores the pop but no longer displays stale busy state.
    #[test]
    fn release_clears_progress_and_restores_title() {
        let mut r = reporter();
        let mut out = Vec::new();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));

        let mut out = Vec::new();
        r.release_to(&mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b]9;4;0;0\x07\x1b]2;zerocode\x07\x1b[23;0t",
            "release must clear progress, neutralize stack-less terminals, then pop"
        );
    }

    /// Terminals are allowed to ignore XTPUSHTITLE/XTPOPTITLE while still
    /// honoring OSC 2. Model that behavior explicitly: release must replace
    /// the stale working title with the neutral fallback before the ignored
    /// pop, rather than relying on a title stack that does not exist.
    #[test]
    fn stackless_terminal_keeps_neutral_title_after_release() {
        struct StacklessTerminal {
            title: String,
        }

        impl Write for StacklessTerminal {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if let Some(payload) = buf
                    .strip_prefix(b"\x1b]2;")
                    .and_then(|payload| payload.strip_suffix(b"\x07"))
                {
                    self.title = String::from_utf8(payload.to_vec()).unwrap();
                }
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut terminal = StacklessTerminal {
            title: "shell".to_string(),
        };
        let mut r = reporter();
        r.sync_to(&mut terminal, Some(&TurnStatus::Working), Some("herder"));
        assert_eq!(terminal.title, "⏳ herder — working");

        r.release_to(&mut terminal);
        assert_eq!(terminal.title, "zerocode");
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

    /// XTPUSHTITLE has no capability response. Even when its write fails, a
    /// later OSC 2 may land, so teardown must still attempt XTPOPTITLE.
    #[test]
    fn failed_push_still_creates_a_restore_obligation() {
        #[derive(Default)]
        struct FailPush {
            bytes: Vec<u8>,
            failed: bool,
        }
        impl Write for FailPush {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.failed && buf == b"\x1b[22;0t" {
                    self.failed = true;
                    return Err(std::io::Error::other("push rejected"));
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut r = reporter();
        let mut out = FailPush::default();
        r.sync_to(&mut out, Some(&TurnStatus::Working), Some("herder"));
        assert!(r.title_restore_needed);
        assert!(out.bytes.starts_with(b"\x1b]2;"));

        let mut released = Vec::new();
        r.release_to(&mut released);
        assert!(released.ends_with(b"\x1b[23;0t"));
        assert!(!r.title_restore_needed);
    }

    /// A `write_all` failure can happen after a prefix reached the terminal.
    /// Cache must stay invalid, while cleanup ownership must remain set.
    #[test]
    fn partial_title_write_is_not_cached_and_is_still_restored() {
        #[derive(Default)]
        struct PartialTitle {
            bytes: Vec<u8>,
            fail_next: bool,
            split_done: bool,
        }
        impl Write for PartialTitle {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.fail_next {
                    self.fail_next = false;
                    return Err(std::io::Error::other("partial title"));
                }
                if !self.split_done && buf.starts_with(b"\x1b]2;") {
                    let written = 3.min(buf.len());
                    self.bytes.extend_from_slice(&buf[..written]);
                    self.split_done = true;
                    self.fail_next = true;
                    return Ok(written);
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut r = reporter();
        r.sync_to(
            &mut PartialTitle::default(),
            Some(&TurnStatus::Working),
            Some("herder"),
        );
        assert_eq!(r.last_title, None);
        assert!(r.title_restore_needed);

        let mut released = Vec::new();
        r.release_to(&mut released);
        assert!(released.ends_with(b"\x1b[23;0t"));
    }

    /// A complete byte write followed by a failed flush is still an uncertain
    /// terminal mutation, so it must not be cached as success or skip cleanup.
    #[test]
    fn failed_title_flush_is_not_cached_and_is_still_restored() {
        #[derive(Default)]
        struct FailSecondFlush {
            flushes: usize,
        }
        impl Write for FailSecondFlush {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    Err(std::io::Error::other("title flush failed"))
                } else {
                    Ok(())
                }
            }
        }

        let mut r = reporter();
        r.sync_to(
            &mut FailSecondFlush::default(),
            Some(&TurnStatus::Working),
            Some("herder"),
        );
        assert_eq!(r.last_title, None);
        assert!(r.title_restore_needed);

        let mut released = Vec::new();
        r.release_to(&mut released);
        assert!(released.ends_with(b"\x1b[23;0t"));
    }

    /// A failed pop keeps the obligation live so a second teardown path can
    /// retry instead of silently declaring the title restored.
    #[test]
    fn failed_pop_is_retried_by_the_next_release() {
        #[derive(Default)]
        struct FailFirstPop {
            bytes: Vec<u8>,
            failed: bool,
        }
        impl Write for FailFirstPop {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.failed && buf == b"\x1b[23;0t" {
                    self.failed = true;
                    return Err(std::io::Error::other("pop failed"));
                }
                self.bytes.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut r = reporter();
        let mut initial = Vec::new();
        r.sync_to(&mut initial, Some(&TurnStatus::Working), Some("herder"));

        let mut out = FailFirstPop::default();
        r.release_to(&mut out);
        assert!(r.title_restore_needed, "failed pop must remain retryable");
        r.release_to(&mut out);
        assert!(!r.title_restore_needed);
        assert!(out.bytes.ends_with(b"\x1b[23;0t"));
    }

    /// Panic cleanup must not wait on the same reporter lock whose critical
    /// section panicked. The fallback is a direct clear + pop pair.
    #[test]
    fn reentrant_release_uses_nonblocking_emergency_cleanup() {
        let reporter = Mutex::new(Some(StatusReporter {
            title_restore_needed: true,
            ..StatusReporter::default()
        }));
        let held = reporter.lock().unwrap();
        let mut out = Vec::new();
        release_reporter_to(&reporter, &mut out);
        drop(held);
        assert_eq!(out, b"\x1b]9;4;0;0\x07\x1b]2;zerocode\x07\x1b[23;0t");
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

    /// Observed live: finishing a turn in the Code pane with no Chat agent
    /// selected settled the title to `✓ zerocode` instead of `✓ osctest`,
    /// because both panes ranked idle and the tie went to the nameless primary.
    #[test]
    fn most_urgent_keeps_a_named_pane_over_a_nameless_tie() {
        let idle = TurnStatus::Idle;
        let (_, agent) = most_urgent([(None, None), (Some(&idle), Some("osctest"))]);
        assert_eq!(agent, Some("osctest"));

        // Same rank, both named: the primary still wins, so this does not
        // reorder panes that both have something to say.
        let (_, agent) = most_urgent([(Some(&idle), Some("chat")), (Some(&idle), Some("code"))]);
        assert_eq!(agent, Some("chat"));
    }

    /// Naming breaks ties; it must never outrank urgency itself.
    #[test]
    fn most_urgent_ranks_urgency_above_naming() {
        let idle = TurnStatus::Idle;
        let working = TurnStatus::Working;
        let blocked = TurnStatus::WaitingForApproval;

        // A nameless working pane still beats a named idle one.
        let (status, agent) = most_urgent([(Some(&idle), Some("chat")), (Some(&working), None)]);
        assert!(matches!(status, Some(TurnStatus::Working)));
        assert_eq!(agent, None);

        // ...and a nameless blocked pane still beats a named working one.
        let (status, _) = most_urgent([(Some(&working), Some("chat")), (Some(&blocked), None)]);
        assert!(matches!(status, Some(TurnStatus::WaitingForApproval)));
    }

    /// A BEL inside the alias would terminate the OSC string early and leave
    /// the remainder to be read as terminal input.
    #[test]
    fn control_characters_are_stripped_before_emission() {
        let mut out = Vec::new();
        write_title(&mut out, &title_for(&TurnStatus::Idle, Some("her\x07der"))).unwrap();
        assert_eq!(out, "\x1b]2;✓ herder\x07".as_bytes());
    }

    #[test]
    fn bidi_and_other_format_controls_are_stripped_from_titles() {
        assert_eq!(sanitize_title("safe\u{202e}txt\u{200d}"), "safetxt");
    }

    #[test]
    fn title_payload_is_bounded_without_splitting_unicode() {
        let input = "界".repeat(MAX_TITLE_CHARS + 20);
        let sanitized = sanitize_title(&input);
        assert_eq!(sanitized.chars().count(), MAX_TITLE_CHARS);
        assert!(sanitized.chars().all(|c| c == '界'));
    }
}
