//! Processes this app instance launched and still holds OS handles for.
//!
//! A process is owned only through the handle this instance's own spawn
//! returned: the desktop supervisor's `Child`, whose Unix process group (or
//! Windows process tree) reaches the daemon it runs. Nothing is recorded across
//! app runs, so a daemon left by an earlier run, or one that was already
//! listening when this instance started, is external. It is never adopted,
//! whatever its PID, executable path, or anything it reports about itself, and
//! quitting never signals it.

use std::path::Path;
use std::process::Child;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How long quitting waits for an owned supervisor to stop its daemon before
/// forcing the tree down. The supervisor allows its daemon 10 seconds to stop
/// and then drains the daemon's output.
pub const QUIT_GRACE: Duration = Duration::from_secs(15);

/// Supervisor trees this app instance launched, oldest first.
#[derive(Debug, Default)]
pub struct OwnedProcesses {
    launched: Vec<Child>,
}

/// The owned-process registry shared between startup and exit.
pub type SharedOwnedProcesses = Arc<Mutex<OwnedProcesses>>;

impl OwnedProcesses {
    /// Keep the handle of a supervisor this instance just launched.
    pub fn record(&mut self, child: Child) {
        self.launched.push(child);
    }

    /// Whether this instance owns any process.
    pub fn is_empty(&self) -> bool {
        self.launched.is_empty()
    }

    /// Stop every owned tree through its handle, newest first, so a gateway
    /// launched after its core stops before the core. Every handle is released
    /// either way; the errors of trees that did not stop cleanly are returned.
    pub fn terminate_all(&mut self, grace: Duration) -> Vec<std::io::Error> {
        let mut errors = Vec::new();
        while let Some(mut child) = self.launched.pop() {
            if let Err(error) = crate::daemon::terminate_supervisor_tree(&mut child, grace) {
                errors.push(error);
            }
        }
        errors
    }
}

/// Launch the desktop supervisor for `binary` and record it as owned. A launch
/// that fails readiness is cleaned up by [`crate::daemon::spawn_daemon`] and
/// never recorded.
pub fn launch_owned_daemon(
    binary: &Path,
    port: u16,
    owned: &Mutex<OwnedProcesses>,
) -> std::io::Result<()> {
    let child = crate::daemon::spawn_daemon(binary, port)?;
    owned
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(child);
    Ok(())
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
        let mut owned = OwnedProcesses::default();
        assert!(owned.is_empty());
        assert!(owned.terminate_all(Duration::from_millis(10)).is_empty());
    }

    #[cfg(unix)]
    mod process_trees {
        use super::super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
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

        #[test]
        fn quit_stops_the_tree_this_instance_launched() {
            let fixture = Fixture::new("owned");
            let binary = fixture.supervisor("core");
            let owned = Mutex::new(OwnedProcesses::default());
            launch_owned_daemon(&binary, 0, &owned).expect("launch owned daemon");

            let mut owned = owned.into_inner().expect("registry lock");
            let supervisor = owned.launched[0].id();
            let descendant = fixture.descendant_of(supervisor);
            assert!(owned.terminate_all(TEST_GRACE).is_empty());

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
            let owned = Mutex::new(OwnedProcesses::default());
            launch_owned_daemon(&binary, 0, &owned).expect("launch owned daemon");

            let mut owned = owned.into_inner().expect("registry lock");
            assert!(owned.terminate_all(TEST_GRACE).is_empty());

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
            let earlier_run = Mutex::new(OwnedProcesses::default());
            launch_owned_daemon(&binary, 0, &earlier_run).expect("launch in earlier run");
            let mut earlier = earlier_run.into_inner().expect("registry lock");
            let leftover = earlier.launched.pop().expect("earlier run launched one");
            let leftover_pid = i32::try_from(leftover.id()).expect("pid");

            // The relaunched instance starts with an empty registry and never
            // adopts the leftover, even though it runs the same executable.
            let mut relaunched = OwnedProcesses::default();
            assert!(relaunched.is_empty());
            assert!(relaunched.terminate_all(TEST_GRACE).is_empty());
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
            let owned = Mutex::new(OwnedProcesses::default());
            launch_owned_daemon(&binary, 0, &owned).expect("launch owned daemon");
            let mut owned = owned.into_inner().expect("registry lock");
            let supervisor = owned.launched[0].id();
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

            assert!(owned.terminate_all(TEST_GRACE).is_empty());
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
            let owned = Mutex::new(OwnedProcesses::default());
            let error = launch_owned_daemon(&binary, 0, &owned)
                .expect_err("an invalid readiness line must fail the launch");
            assert!(error.to_string().contains("invalid readiness response"));
            assert!(owned.lock().expect("registry lock").is_empty());
        }

        #[test]
        fn quit_stops_the_newest_tree_first() {
            let fixture = Fixture::new("order");
            let core = fixture.supervisor("core");
            let gateway = fixture.supervisor("gateway");
            let owned = Mutex::new(OwnedProcesses::default());
            launch_owned_daemon(&core, 0, &owned).expect("launch core");
            launch_owned_daemon(&gateway, 0, &owned).expect("launch gateway");

            let mut owned = owned.into_inner().expect("registry lock");
            assert!(owned.terminate_all(TEST_GRACE).is_empty());
            assert_eq!(fixture.stop_order(), "gateway\ncore\n");
        }
    }
}
