//! Processes this app instance launched and still holds OS handles for.
//!
//! A process is owned only through the handle this instance's own spawn
//! returned (see [`crate::daemon::Supervisor`]): the supervisor's Unix process
//! group, or the Windows Job Object it was created in, reaches the daemon it
//! runs. Nothing is recorded across app runs, so a daemon left by an earlier
//! run, or one that was already listening when this instance started, is
//! external. It is never adopted, whatever its PID, executable path, or
//! anything it reports about itself, and quitting never signals it.
//!
//! Quitting seals the registry first: a launch that has not started yet is
//! refused, and one already starting is waited for and stopped with the rest,
//! so a supervisor cannot slip past Quit while it is still getting ready.

use crate::daemon::Supervisor;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// How long quitting waits for an owned supervisor to stop its daemon before
/// forcing the tree down. The supervisor allows its daemon 10 seconds to stop
/// and then drains the daemon's output.
pub const QUIT_GRACE: Duration = Duration::from_secs(15);

/// How long quitting waits for launches already underway to be recorded. A
/// launch takes at most the capability probe, the readiness wait and startup
/// cleanup, well within this bound.
pub const LAUNCH_SETTLE_WAIT: Duration = Duration::from_secs(30);

/// Supervisor trees this app instance launched, and the launches in progress.
#[derive(Debug, Default)]
pub struct OwnedProcesses {
    registry: Mutex<Registry>,
    launch_settled: Condvar,
}

#[derive(Debug, Default)]
struct Registry {
    /// Oldest first.
    launched: Vec<Supervisor>,
    /// Launches admitted and not yet recorded or failed.
    pending: usize,
    /// Set when quitting starts; no launch is admitted after it.
    closing: bool,
    /// Set once quitting has taken the launched trees to stop them.
    drained: bool,
}

/// The owned-process registry shared between startup and exit.
pub type SharedOwnedProcesses = Arc<OwnedProcesses>;

impl OwnedProcesses {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether this instance owns any process.
    pub fn is_empty(&self) -> bool {
        self.registry().launched.is_empty()
    }

    /// Launch the desktop supervisor for `binary` and record it as owned. It
    /// is refused once quitting has started. A launch that fails readiness is
    /// cleaned up by [`crate::daemon::spawn_daemon`] and never recorded.
    pub fn launch(&self, binary: &Path, port: u16) -> std::io::Result<()> {
        let pending = {
            let mut registry = self.registry();
            if registry.closing {
                return Err(std::io::Error::other(
                    "the app is quitting, so it does not start a daemon",
                ));
            }
            registry.pending += 1;
            PendingLaunch {
                owned: self,
                settled: false,
            }
        };
        let child = crate::daemon::spawn_daemon(binary, port)?;
        pending.record(child)
    }

    /// Stop every owned tree through its handle, newest first, so a gateway
    /// launched after its core stops before the core. Launch admission is
    /// sealed first, and launches already starting are waited for, up to
    /// `launch_wait`, so their trees are stopped too. Every handle is
    /// released either way; the errors are returned.
    pub fn quit(&self, grace: Duration, launch_wait: Duration) -> Vec<std::io::Error> {
        let mut registry = self.registry();
        registry.closing = true;
        let (mut registry, wait) = self
            .launch_settled
            .wait_timeout_while(registry, launch_wait, |registry| registry.pending > 0)
            .unwrap_or_else(PoisonError::into_inner);
        let mut errors = Vec::new();
        if wait.timed_out() {
            errors.push(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} daemon launch(es) were still starting; each stops its own daemon when it finishes",
                    registry.pending
                ),
            ));
        }
        registry.drained = true;
        let launched = std::mem::take(&mut registry.launched);
        drop(registry);
        for mut child in launched.into_iter().rev() {
            if let Err(error) = crate::daemon::terminate_supervisor_tree(&mut child, grace) {
                errors.push(error);
            }
        }
        errors
    }
}

#[cfg(all(test, unix))]
impl OwnedProcesses {
    fn launched_ids(&self) -> Vec<u32> {
        self.registry()
            .launched
            .iter()
            .map(|child| child.id())
            .collect()
    }

    /// Take the handles out, as an app crash loses them.
    fn lose_handles(&self) -> Vec<Supervisor> {
        std::mem::take(&mut self.registry().launched)
    }
}

/// A launch admitted into the registry. Recording its supervisor, or
/// dropping it when the launch fails, settles it and wakes a waiting quit.
struct PendingLaunch<'a> {
    owned: &'a OwnedProcesses,
    settled: bool,
}

impl PendingLaunch<'_> {
    fn record(mut self, mut child: Supervisor) -> std::io::Result<()> {
        let mut registry = self.owned.registry();
        registry.pending -= 1;
        self.settled = true;
        if !registry.drained {
            registry.launched.push(child);
            drop(registry);
            self.owned.launch_settled.notify_all();
            return Ok(());
        }
        // Quitting gave up waiting and has already stopped the rest: this
        // launch stops its own tree instead of leaving it running.
        drop(registry);
        self.owned.launch_settled.notify_all();
        let stopped = crate::daemon::terminate_supervisor_tree(&mut child, QUIT_GRACE);
        Err(std::io::Error::other(match stopped {
            Ok(()) => "the app quit while the daemon was starting; it was stopped".to_string(),
            Err(error) => {
                format!("the app quit while the daemon was starting; stopping it failed: {error}")
            }
        }))
    }
}

impl Drop for PendingLaunch<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.owned.registry().pending -= 1;
            self.owned.launch_settled.notify_all();
        }
    }
}

/// Whether an exit request should be declined so the app keeps running in the
/// tray. Closing the last window (no exit code) keeps the app, and the
/// processes it owns, running; an explicit exit such as tray Quit proceeds.
pub fn keep_running_on_exit_request(code: Option<i32>) -> bool {
    code.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_the_last_window_keeps_running_but_quit_exits() {
        assert!(keep_running_on_exit_request(None));
        assert!(!keep_running_on_exit_request(Some(0)));
    }

    #[test]
    fn a_new_registry_owns_nothing() {
        let owned = OwnedProcesses::default();
        assert!(owned.is_empty());
        assert!(
            owned
                .quit(Duration::from_millis(10), Duration::from_millis(10))
                .is_empty()
        );
    }

    #[cfg(unix)]
    mod process_trees {
        use super::super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::Instant;

        /// Test fixtures stop quickly; the production grace is not needed.
        const TEST_GRACE: Duration = Duration::from_secs(5);

        struct Fixture {
            dir: PathBuf,
        }

        impl Fixture {
            fn new(label: &str) -> Self {
                let unique = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock should be after the Unix epoch")
                    .as_nanos();
                let dir = std::env::temp_dir()
                    .join(format!("zc-own-{label}-{}-{unique}", std::process::id()));
                fs::create_dir(&dir).expect("create fixture directory");
                Self { dir }
            }

            fn literal(path: &Path) -> String {
                path.to_string_lossy().replace('\'', "'\\''")
            }

            /// A supervisor that answers the capability probe, starts a
            /// descendant in its own process group, reports READY, and on
            /// SIGTERM logs `tag`, stops the descendant, and exits.
            fn supervisor(&self, tag: &str) -> PathBuf {
                let dir = Self::literal(&self.dir);
                self.script(
                    tag,
                    &format!(
                        "#!/bin/sh\n\
                         if [ \"${{1:-}}\" = service ] && [ \"${{2:-}}\" = run-desktop-daemon ] && [ \"${{3:-}}\" = --help ]; then exit 0; fi\n\
                         sleep 30 &\n\
                         child=$!\n\
                         printf '%s' \"$child\" > '{dir}/descendant.'\"$$\"\n\
                         trap 'printf \"%s\\n\" {tag} >> '\\''{dir}/stop-order'\\''; kill \"$child\" 2>/dev/null; wait \"$child\" 2>/dev/null; exit 0' TERM\n\
                         printf '%s\\n' READY\n\
                         wait \"$child\"\n"
                    ),
                )
            }

            /// A supervisor that reports READY and exits at once, leaving a
            /// SIGTERM-ignoring descendant in its process group. Started as
            /// `daemon` (the way a user runs it), it stays up instead.
            fn exiting_supervisor(&self, tag: &str) -> PathBuf {
                let dir = Self::literal(&self.dir);
                self.script(
                    tag,
                    &format!(
                        "#!/bin/sh\n\
                         if [ \"${{1:-}}\" = service ] && [ \"${{2:-}}\" = run-desktop-daemon ] && [ \"${{3:-}}\" = --help ]; then exit 0; fi\n\
                         if [ \"${{1:-}}\" = daemon ]; then\n\
                         sleep 30 &\n\
                         printf '%s' \"$!\" > '{dir}/descendant.'\"$$\"\n\
                         printf '%s\\n' READY\n\
                         wait\n\
                         exit 0\n\
                         fi\n\
                         trap '' TERM\n\
                         sleep 30 &\n\
                         printf '%s' \"$!\" > '{dir}/descendant.'\"$$\"\n\
                         printf '%s\\n' READY\n\
                         exit 0\n"
                    ),
                )
            }

            /// A supervisor that records its PID once started and reports
            /// READY only after [`Fixture::release`], so a test can act while
            /// the launch is in progress.
            fn gated_supervisor(&self, tag: &str) -> PathBuf {
                let dir = Self::literal(&self.dir);
                self.script(
                    tag,
                    &format!(
                        "#!/bin/sh\n\
                         if [ \"${{1:-}}\" = service ] && [ \"${{2:-}}\" = run-desktop-daemon ] && [ \"${{3:-}}\" = --help ]; then exit 0; fi\n\
                         trap 'printf \"%s\\n\" {tag} >> '\\''{dir}/stop-order'\\''; exit 0' TERM\n\
                         printf '%s' \"$$\" > '{dir}/started'\n\
                         while [ ! -f '{dir}/release' ]; do sleep 0.05; done\n\
                         printf '%s\\n' READY\n\
                         while :; do sleep 1; done\n"
                    ),
                )
            }

            fn release(&self) {
                fs::write(self.dir.join("release"), b"").expect("release the gated fixture");
            }

            /// A supervisor that answers the capability probe but reports an
            /// invalid readiness line, so the app cannot verify the launch.
            fn unverifiable_supervisor(&self, tag: &str) -> PathBuf {
                let dir = Self::literal(&self.dir);
                self.script(
                    tag,
                    &format!(
                        "#!/bin/sh\n\
                         if [ \"${{1:-}}\" = service ] && [ \"${{2:-}}\" = run-desktop-daemon ] && [ \"${{3:-}}\" = --help ]; then exit 0; fi\n\
                         sleep 30 &\n\
                         printf '%s' \"$!\" > '{dir}/descendant.'\"$$\"\n\
                         printf '%s\\n' INVALID\n\
                         wait\n"
                    ),
                )
            }

            fn script(&self, tag: &str, body: &str) -> PathBuf {
                let path = self.dir.join(tag);
                fs::write(&path, body).expect("write fixture script");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("make fixture executable");
                // The first exec of a new file can take seconds on a loaded
                // macOS host; run the capability probe once, untimed, so the
                // launch's timed probe is not measuring that.
                let probe = Command::new(&path)
                    .args(["service", "run-desktop-daemon", "--help"])
                    .status()
                    .expect("warm fixture script");
                assert!(probe.success(), "fixture must answer the capability probe");
                path
            }

            fn descendant_of(&self, supervisor_pid: u32) -> i32 {
                fs::read_to_string(self.dir.join(format!("descendant.{supervisor_pid}")))
                    .expect("fixture should record its descendant")
                    .parse()
                    .expect("descendant pid should be numeric")
            }

            fn stop_order(&self) -> String {
                fs::read_to_string(self.dir.join("stop-order")).unwrap_or_default()
            }

            /// Start `binary` the way a user starts an external daemon: not
            /// through the registry, in its own process group.
            fn start_external(&self, binary: &Path) -> Child {
                use std::os::unix::process::CommandExt;
                let mut child = Command::new(binary)
                    .args(["daemon"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .process_group(0)
                    .spawn()
                    .expect("start external daemon");
                let mut line = String::new();
                std::io::BufRead::read_line(
                    &mut std::io::BufReader::new(child.stdout.take().expect("stdout")),
                    &mut line,
                )
                .expect("read external readiness");
                assert_eq!(line.trim(), "READY");
                child
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }

        fn alive(pid: i32) -> bool {
            // SAFETY: signal 0 only checks that `pid` exists.
            unsafe { libc::kill(pid, 0) == 0 }
        }

        fn wait_gone(pid: i32) -> bool {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if !alive(pid) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }

        /// Stop a process tree the test started outside the registry.
        fn stop_external(mut child: Child) {
            let group = i32::try_from(child.id()).expect("pid fits in pid_t");
            // SAFETY: the test launched this process group and has not reaped
            // its leader, so the group ID still names only that tree.
            unsafe { libc::kill(-group, libc::SIGKILL) };
            let _ = child.wait();
        }

        /// Settle wait for tests whose launches finish quickly.
        const TEST_SETTLE: Duration = Duration::from_secs(10);

        #[test]
        fn quit_stops_the_tree_this_instance_launched() {
            let fixture = Fixture::new("owned");
            let binary = fixture.supervisor("core");
            let owned = OwnedProcesses::default();
            owned.launch(&binary, 0).expect("launch owned daemon");

            let supervisor = owned.launched_ids()[0];
            let descendant = fixture.descendant_of(supervisor);
            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());

            assert!(owned.is_empty());
            assert!(wait_gone(descendant), "owned descendant survived Quit");
            assert!(!alive(i32::try_from(supervisor).expect("pid")));
            assert_eq!(fixture.stop_order(), "core\n");
        }

        #[test]
        fn external_daemon_from_the_same_executable_survives_quit() {
            let fixture = Fixture::new("external");
            let binary = fixture.supervisor("core");
            let external = fixture.start_external(&binary);
            let external_descendant = fixture.descendant_of(external.id());
            let owned = OwnedProcesses::default();
            owned.launch(&binary, 0).expect("launch owned daemon");

            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());

            let external_pid = i32::try_from(external.id()).expect("pid");
            assert!(alive(external_pid), "Quit stopped an external daemon");
            assert!(alive(external_descendant));
            stop_external(external);
        }

        #[test]
        fn relaunched_app_owns_nothing_from_an_earlier_run() {
            let fixture = Fixture::new("relaunch");
            let binary = fixture.supervisor("core");
            // The earlier run launched a daemon and ended without Quit (a
            // crash): its handle is gone, the tree keeps running.
            let earlier_run = OwnedProcesses::default();
            earlier_run
                .launch(&binary, 0)
                .expect("launch in earlier run");
            let leftover = earlier_run
                .lose_handles()
                .pop()
                .expect("earlier run launched one");
            let leftover_pid = i32::try_from(leftover.id()).expect("pid");

            // The relaunched instance starts with an empty registry and never
            // adopts the leftover, even though it runs the same executable.
            let relaunched = OwnedProcesses::default();
            assert!(relaunched.is_empty());
            assert!(relaunched.quit(TEST_GRACE, TEST_SETTLE).is_empty());
            assert!(
                alive(leftover_pid),
                "a relaunch stopped an earlier run's daemon"
            );
            stop_external(leftover);
        }

        #[test]
        fn exited_owned_supervisor_keeps_its_pid_reserved_until_quit() {
            let fixture = Fixture::new("reserved");
            let binary = fixture.exiting_supervisor("core");
            let owned = OwnedProcesses::default();
            owned.launch(&binary, 0).expect("launch owned daemon");
            let supervisor = owned.launched_ids()[0];
            let supervisor_pid = i32::try_from(supervisor).expect("pid");
            let descendant = fixture.descendant_of(supervisor);

            let deadline = Instant::now() + Duration::from_secs(3);
            while !crate::daemon::supervisor_exited(supervisor).expect("peek supervisor") {
                assert!(Instant::now() < deadline, "fixture supervisor did not exit");
                std::thread::sleep(Duration::from_millis(20));
            }
            // The exited supervisor stays unreaped, so the OS cannot hand its
            // PID, or its process group ID, to another process before Quit.
            assert!(alive(supervisor_pid), "exited supervisor was reaped early");
            let external = fixture.start_external(&binary);
            let external_descendant = fixture.descendant_of(external.id());

            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());
            assert!(
                wait_gone(descendant),
                "SIGTERM-ignoring descendant of the owned group survived Quit"
            );
            assert!(
                alive(external_descendant),
                "Quit reached an external daemon from the same executable"
            );
            stop_external(external);
        }

        #[test]
        fn unverifiable_launch_is_never_owned() {
            let fixture = Fixture::new("unverified");
            let binary = fixture.unverifiable_supervisor("core");
            let owned = OwnedProcesses::default();
            let error = owned
                .launch(&binary, 0)
                .expect_err("an invalid readiness line must fail the launch");
            assert!(error.to_string().contains("invalid readiness response"));
            assert!(owned.is_empty());
            // The failed launch settled, so Quit does not wait for it.
            let started = Instant::now();
            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());
            assert!(started.elapsed() < Duration::from_secs(1));
        }

        #[test]
        fn quit_stops_the_newest_tree_first() {
            let fixture = Fixture::new("order");
            let core = fixture.supervisor("core");
            let gateway = fixture.supervisor("gateway");
            let owned = OwnedProcesses::default();
            owned.launch(&core, 0).expect("launch core");
            owned.launch(&gateway, 0).expect("launch gateway");

            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());
            assert_eq!(fixture.stop_order(), "gateway\ncore\n");
        }

        /// Wait until the gated fixture has started and recorded its PID.
        fn started_pid(fixture: &Fixture) -> i32 {
            let path = fixture.dir.join("started");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(pid) = fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                {
                    return pid;
                }
                assert!(Instant::now() < deadline, "gated fixture did not start");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        #[test]
        fn quit_waits_for_a_launch_that_is_still_starting() {
            let fixture = Fixture::new("starting");
            let binary = fixture.gated_supervisor("core");
            let owned = std::sync::Arc::new(OwnedProcesses::default());

            let launching = std::sync::Arc::clone(&owned);
            let launch = std::thread::spawn(move || launching.launch(&binary, 0));
            let supervisor = started_pid(&fixture);

            // Quit begins while the supervisor is spawned but not yet ready.
            let quitting = std::sync::Arc::clone(&owned);
            let (quit_done, quit_result) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = quit_done.send(quitting.quit(TEST_GRACE, TEST_SETTLE));
            });
            assert!(
                quit_result
                    .recv_timeout(Duration::from_millis(500))
                    .is_err(),
                "Quit finished while a launch was still starting"
            );

            fixture.release();
            launch
                .join()
                .expect("launch thread")
                .expect("the launch completes and is recorded");
            let errors = quit_result
                .recv_timeout(Duration::from_secs(15))
                .expect("Quit finishes once the launch is recorded");
            assert!(errors.is_empty(), "{errors:?}");
            assert!(
                wait_gone(supervisor),
                "the launch that was starting survived Quit"
            );
            assert_eq!(fixture.stop_order(), "core\n");
            assert!(owned.is_empty());
        }

        #[test]
        fn a_launch_after_quit_began_is_refused() {
            let fixture = Fixture::new("sealed");
            let binary = fixture.supervisor("core");
            let owned = OwnedProcesses::default();
            assert!(owned.quit(TEST_GRACE, TEST_SETTLE).is_empty());

            let error = owned
                .launch(&binary, 0)
                .expect_err("no launch is admitted once quitting started");
            assert!(error.to_string().contains("quitting"));
            assert!(owned.is_empty());
        }

        #[test]
        fn a_launch_that_outlives_the_settle_wait_stops_its_own_tree() {
            let fixture = Fixture::new("late");
            let binary = fixture.gated_supervisor("core");
            let owned = std::sync::Arc::new(OwnedProcesses::default());

            let launching = std::sync::Arc::clone(&owned);
            let launch = std::thread::spawn(move || launching.launch(&binary, 0));
            let supervisor = started_pid(&fixture);

            let errors = owned.quit(TEST_GRACE, Duration::from_millis(200));
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert_eq!(errors[0].kind(), std::io::ErrorKind::TimedOut);

            fixture.release();
            let error = launch
                .join()
                .expect("launch thread")
                .expect_err("a launch that finishes after Quit drained is not kept");
            assert!(error.to_string().contains("it was stopped"), "{error}");
            assert!(
                wait_gone(supervisor),
                "the late launch left its tree running"
            );
            assert!(owned.is_empty());
        }
    }
}
