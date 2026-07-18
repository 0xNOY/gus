use std::{
    io,
    mem::MaybeUninit,
    num::NonZeroU32,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    LocalSessionObservation, ObservationError, ObservationResource, OsUserIdentity, PlatformFamily,
    ProcessIdentity, ProcessTimeDomainIdentity,
    bsd_model::{ProcessFacts, TerminalEvidence, TerminalFacts, assemble_observation},
};

pub(super) trait ProcessBackend {
    const FAMILY: PlatformFamily;

    fn time_domain() -> Result<ProcessTimeDomainIdentity, ObservationError>;
    fn current_pid() -> Result<NonZeroU32, ObservationError>;
    fn read_process(
        pid: NonZeroU32,
        resource: ObservationResource,
    ) -> Result<ProcessFacts, ObservationError>;
}

pub(super) fn observe_current<B: ProcessBackend>()
-> Result<LocalSessionObservation, ObservationError> {
    let time_domain = B::time_domain()?;
    let pid = B::current_pid()?;
    let caller_first = B::read_process(pid, ObservationResource::CallerProcess)?;
    let first_terminal = open_terminal()?;

    let (terminal, monitor) = match first_terminal {
        None => (
            TerminalEvidence::Detached {
                second: open_terminal()?.map(|terminal| {
                    terminal
                        .access
                        .with_terminal_device(caller_first.terminal_device)
                }),
            },
            None,
        ),
        Some(first_terminal) => {
            let leader_first = B::read_process(
                caller_first.session_id,
                ObservationResource::TerminalAnchorProcess,
            )?;
            let monitor = ProcessExitMonitor::new(
                caller_first.session_id,
                ObservationResource::TerminalAnchorProcess,
                ObservationError::TerminalAnchorChanged,
            )?;
            let leader_second = normalize_anchor_recheck(B::read_process(
                caller_first.session_id,
                ObservationResource::TerminalAnchorProcess,
            ))?;
            let second = open_terminal()?.map(|terminal| {
                terminal
                    .access
                    .with_terminal_device(caller_first.terminal_device)
            });
            monitor.ensure_live()?;
            (
                TerminalEvidence::Attached {
                    first: first_terminal
                        .access
                        .with_terminal_device(caller_first.terminal_device),
                    leader_first,
                    leader_second,
                    second,
                },
                Some(monitor),
            )
        }
    };

    let caller_second = B::read_process(pid, ObservationResource::CallerProcess)?;
    if B::time_domain()? != time_domain {
        return Err(ObservationError::ProcessChanged);
    }
    let observation = assemble_observation(
        B::FAMILY,
        time_domain,
        caller_first,
        terminal,
        caller_second,
    )?;
    if let Some(monitor) = monitor {
        monitor.ensure_live()?;
    }
    Ok(observation)
}

pub(super) fn observe_process<B: ProcessBackend>(
    pid: NonZeroU32,
) -> Result<ProcessIdentity, ObservationError> {
    let time_domain = B::time_domain()?;
    let monitor = ProcessExitMonitor::new(
        pid,
        ObservationResource::TargetProcess,
        ObservationError::ProcessChanged,
    )?;
    let first = B::read_process(pid, ObservationResource::TargetProcess)?;
    let second =
        normalize_process_recheck(B::read_process(pid, ObservationResource::TargetProcess))?;
    if first != second || first.pid != pid || B::time_domain()? != time_domain {
        return Err(ObservationError::ProcessChanged);
    }
    monitor.ensure_live()?;
    let mut user_native = [0_u8; 8];
    user_native[0..4].copy_from_slice(&first.effective_uid.to_le_bytes());
    user_native[4..8].copy_from_slice(&first.user_namespace.to_le_bytes());
    let user = OsUserIdentity::from_native_bytes(B::FAMILY, &user_native);
    Ok(ProcessIdentity::from_observation(
        time_domain,
        first.pid,
        first.start_time,
        user,
    ))
}

fn normalize_process_recheck<T>(
    result: Result<T, ObservationError>,
) -> Result<T, ObservationError> {
    match result {
        Err(ObservationError::Read {
            resource: ObservationResource::TargetProcess | ObservationResource::TargetUser,
            kind: io::ErrorKind::NotFound,
        }) => Err(ObservationError::ProcessChanged),
        other => other,
    }
}

pub(crate) struct ProcessExitMonitor {
    queue: OwnedFd,
    resource: ObservationResource,
    changed: ObservationError,
    notifications: u32,
    revoked: AtomicBool,
}

impl ProcessExitMonitor {
    pub(crate) fn new(
        pid: NonZeroU32,
        resource: ObservationResource,
        changed: ObservationError,
    ) -> Result<Self, ObservationError> {
        Self::new_with_notifications(pid, resource, changed, libc::NOTE_EXIT)
    }

    pub(crate) fn new_with_notifications(
        pid: NonZeroU32,
        resource: ObservationResource,
        changed: ObservationError,
        notifications: u32,
    ) -> Result<Self, ObservationError> {
        // SAFETY: `kqueue` has no arguments and returns a new descriptor.
        let raw = unsafe { libc::kqueue() };
        if raw == -1 {
            return Err(last_monitor_error(resource, changed));
        }
        // SAFETY: `kqueue` returned a new descriptor transferred exactly once.
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        set_close_on_exec(queue.as_raw_fd(), resource)?;
        let monitor = Self {
            queue,
            resource,
            changed,
            notifications,
            revoked: AtomicBool::new(false),
        };
        let change = process_event(pid, libc::EV_ADD | libc::EV_ENABLE, notifications);
        monitor.poll(Some(&change))?;
        Ok(monitor)
    }

    pub(crate) fn ensure_live(&self) -> Result<(), ObservationError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(self.changed);
        }
        self.poll(None).inspect_err(|_| {
            self.revoked.store(true, Ordering::Release);
        })
    }

    fn poll(&self, change: Option<&libc::kevent>) -> Result<(), ObservationError> {
        let (changes, change_count) = change.map_or((std::ptr::null(), 0), |event| (event, 1));
        let mut event = empty_event();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: all pointers describe live objects for the duration of the
        // call. The event array has capacity one and the timeout is read-only.
        let count = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                changes,
                change_count,
                &raw mut event,
                1,
                &raw const timeout,
            )
        };
        if count == -1 {
            return Err(last_monitor_error(self.resource, self.changed));
        }
        if count == 0 {
            return Ok(());
        }
        let flags = event_flags(&event);
        let data = event_data(&event);
        if flags & libc::EV_ERROR != 0 {
            if data == 0 {
                return Err(ObservationError::Malformed {
                    resource: self.resource,
                });
            }
            if data == i64::from(libc::ESRCH) {
                return Err(self.changed);
            }
            return Err(ObservationError::Read {
                resource: self.resource,
                kind: io::Error::from_raw_os_error(i32::try_from(data).unwrap_or(i32::MAX)).kind(),
            });
        }
        if event_filter(&event) == libc::EVFILT_PROC
            && event_fflags(&event) & self.notifications != 0
        {
            return Err(self.changed);
        }
        Err(ObservationError::Malformed {
            resource: self.resource,
        })
    }
}

fn last_monitor_error(
    resource: ObservationResource,
    changed: ObservationError,
) -> ObservationError {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        changed
    } else {
        ObservationError::Read {
            resource,
            kind: error.kind(),
        }
    }
}

fn set_close_on_exec(
    descriptor: std::os::fd::RawFd,
    resource: ObservationResource,
) -> Result<(), ObservationError> {
    // SAFETY: the descriptor is live and borrowed by the caller.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags == -1 {
        return Err(last_read_error(resource));
    }
    // SAFETY: this updates flags on the same live descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(last_read_error(resource));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const fn process_event(pid: NonZeroU32, registration: u16, notifications: u32) -> libc::kevent {
    libc::kevent {
        ident: pid.get() as usize,
        filter: libc::EVFILT_PROC,
        flags: registration,
        fflags: notifications,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

#[cfg(target_os = "freebsd")]
const fn process_event(pid: NonZeroU32, registration: u16, notifications: u32) -> libc::kevent {
    libc::kevent {
        ident: pid.get() as usize,
        filter: libc::EVFILT_PROC,
        flags: registration,
        fflags: notifications,
        data: 0,
        udata: std::ptr::null_mut(),
        ext: [0; 4],
    }
}

fn empty_event() -> libc::kevent {
    process_event(NonZeroU32::new(1).expect("one is nonzero"), 0, 0)
}

fn event_filter(event: &libc::kevent) -> i16 {
    // SAFETY: `kevent` is packed on Darwin; unaligned reads are required and
    // also valid for the naturally aligned FreeBSD representation.
    unsafe { std::ptr::addr_of!(event.filter).read_unaligned() }
}

fn event_flags(event: &libc::kevent) -> u16 {
    // SAFETY: see `event_filter`.
    unsafe { std::ptr::addr_of!(event.flags).read_unaligned() }
}

fn event_fflags(event: &libc::kevent) -> u32 {
    // SAFETY: see `event_filter`.
    unsafe { std::ptr::addr_of!(event.fflags).read_unaligned() }
}

#[cfg(target_os = "macos")]
fn event_data(event: &libc::kevent) -> i64 {
    // SAFETY: see `event_filter`.
    unsafe { std::ptr::addr_of!(event.data).read_unaligned() as i64 }
}

#[cfg(target_os = "freebsd")]
fn event_data(event: &libc::kevent) -> i64 {
    // SAFETY: see `event_filter`.
    unsafe { std::ptr::addr_of!(event.data).read_unaligned() }
}

fn normalize_anchor_recheck<T>(result: Result<T, ObservationError>) -> Result<T, ObservationError> {
    match result {
        Err(ObservationError::Read {
            resource: ObservationResource::TerminalAnchorProcess,
            kind: io::ErrorKind::NotFound,
        }) => Err(ObservationError::TerminalAnchorChanged),
        other => other,
    }
}

struct OpenTerminal {
    #[allow(dead_code, reason = "keeps the validated access descriptor live")]
    descriptor: OwnedFd,
    access: TerminalAccessFacts,
}

#[derive(Clone, Copy)]
struct TerminalAccessFacts {
    resolved_device: Option<u64>,
    session_id: NonZeroU32,
}

impl TerminalAccessFacts {
    fn with_terminal_device(self, terminal_device: Option<u64>) -> TerminalFacts {
        let terminal_device = terminal_device.unwrap_or(u64::MAX);
        TerminalFacts {
            terminal_device,
            session_id: self.session_id,
            device_binding_matches: self
                .resolved_device
                .is_none_or(|resolved| resolved == terminal_device),
        }
    }
}

fn open_terminal() -> Result<Option<OpenTerminal>, ObservationError> {
    // SAFETY: the path is a static NUL-terminated C string and the flags do
    // not require a mode argument. A successful result is a new descriptor.
    let raw = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw == -1 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENXIO | libc::ENODEV | libc::ENOTTY) => Ok(None),
            _ => Err(ObservationError::Read {
                resource: ObservationResource::TerminalSession,
                kind: error.kind(),
            }),
        };
    }
    // SAFETY: `open` returned a new owned descriptor which is transferred
    // exactly once to `OwnedFd`.
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let access = terminal_facts(&descriptor)?;
    Ok(Some(OpenTerminal { descriptor, access }))
}

fn terminal_facts(descriptor: &OwnedFd) -> Result<TerminalAccessFacts, ObservationError> {
    let mut status = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `status` points to enough writable storage for `fstat`, and the
    // borrowed descriptor remains live for the duration of the call.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), status.as_mut_ptr()) } == -1 {
        return Err(last_read_error(ObservationResource::TerminalSession));
    }
    // SAFETY: successful `fstat` initialized the complete native structure.
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Err(ObservationError::Malformed {
            resource: ObservationResource::TerminalSession,
        });
    }

    // SAFETY: `tcgetsid` only borrows the live terminal descriptor.
    let session_id = unsafe { libc::tcgetsid(descriptor.as_raw_fd()) };
    if session_id == -1 {
        return Err(terminal_session_error(&io::Error::last_os_error()));
    }
    let session_id = u32::try_from(session_id)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(ObservationError::Malformed {
            resource: ObservationResource::TerminalSession,
        })?;
    Ok(TerminalAccessFacts {
        #[cfg(target_os = "macos")]
        resolved_device: None,
        #[cfg(target_os = "freebsd")]
        resolved_device: Some(status.st_rdev),
        session_id,
    })
}

fn terminal_session_error(error: &io::Error) -> ObservationError {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::ENOTTY | libc::ENODEV | libc::ENXIO) => {
            ObservationError::ProcessChanged
        }
        _ => ObservationError::Read {
            resource: ObservationResource::TerminalSession,
            kind: error.kind(),
        },
    }
}

pub(super) fn pid_to_nonzero(
    value: libc::pid_t,
    resource: ObservationResource,
) -> Result<NonZeroU32, ObservationError> {
    u32::try_from(value)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| {
            if value == -1 {
                last_read_error(resource)
            } else {
                ObservationError::Malformed { resource }
            }
        })
}

fn last_read_error(resource: ObservationResource) -> ObservationError {
    ObservationError::Read {
        resource,
        kind: io::Error::last_os_error().kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::CommandExt,
        },
        path::Path,
        path::PathBuf,
        process::{Command, Output, Stdio},
    };

    const CHILD_TEST_NAME: &str = "bsd::tests::native_observation_child_probe";
    const EXPECTATION_ENV: &str = "GUS_BSD_OBSERVER_CHILD_EXPECTATION";
    const MARKER_ENV: &str = "GUS_BSD_OBSERVER_CHILD_MARKER";
    const DESCENDANT_TEST_NAME: &str = "bsd::tests::native_inherited_descendant_probe";
    const DESCENDANT_EXPECTED_ENV: &str = "GUS_BSD_DESCENDANT_EXPECTED_IDENTITY";
    const DESCENDANT_MARKER_ENV: &str = "GUS_BSD_DESCENDANT_MARKER";

    #[test]
    fn current_process_observation_uses_native_bsd_evidence() {
        let observation = crate::CurrentSessionObserver::new()
            .observe()
            .expect("current BSD process observation");
        assert!(matches!(
            observation.caller().user().family(),
            crate::PlatformFamily::MacOs | crate::PlatformFamily::FreeBsd
        ));
    }

    #[test]
    fn terminal_detachment_errors_are_retryable_process_changes() {
        for raw in [libc::EACCES, libc::ENOTTY, libc::ENODEV, libc::ENXIO] {
            assert_eq!(
                super::terminal_session_error(&std::io::Error::from_raw_os_error(raw)),
                crate::ObservationError::ProcessChanged
            );
        }
        assert_eq!(
            super::terminal_session_error(&std::io::Error::from_raw_os_error(libc::EPERM)),
            crate::ObservationError::Read {
                resource: crate::ObservationResource::TerminalSession,
                kind: std::io::ErrorKind::PermissionDenied,
            }
        );
    }

    #[test]
    #[ignore = "internal child process for native BSD session smoke tests"]
    fn native_observation_child_probe() {
        let (Ok(expectation), Some(marker)) =
            (std::env::var(EXPECTATION_ENV), std::env::var_os(MARKER_ENV))
        else {
            return;
        };
        let observation = crate::CurrentSessionObserver::new()
            .observe()
            .expect("child native BSD observation");
        assert_eq!(observation.has_terminal_session(), expectation == "tty");
        if expectation == "tty" {
            let terminal = observation
                .terminal_session()
                .expect("attached child terminal identity");
            let fingerprint = terminal_fingerprint(terminal);
            assert_inherited_descendant(&fingerprint, &marker);
            std::fs::write(marker, fingerprint).expect("write attached native probe marker");
        } else {
            std::fs::write(marker, b"headless").expect("write detached native probe marker");
        }
    }

    #[test]
    #[ignore = "internal descendant for native BSD session smoke tests"]
    fn native_inherited_descendant_probe() {
        let (Ok(expected), Some(marker)) = (
            std::env::var(DESCENDANT_EXPECTED_ENV),
            std::env::var_os(DESCENDANT_MARKER_ENV),
        ) else {
            return;
        };
        let terminal = crate::CurrentSessionObserver::new()
            .observe()
            .expect("inherited descendant observation")
            .terminal_session()
            .expect("inherited descendant terminal identity");
        assert_eq!(terminal_fingerprint(terminal), expected);
        std::fs::write(marker, b"observed").expect("write descendant probe marker");
    }

    #[test]
    fn native_observation_distinguishes_detached_and_pty_sessions() {
        let executable = std::env::current_exe().expect("current test executable");
        let directory = tempfile::tempdir().expect("probe marker directory");
        let detached_marker = directory.path().join("detached.marker");
        let attached_marker = directory.path().join("attached.marker");
        let second_attached_marker = directory.path().join("attached-second.marker");

        let mut detached = native_probe_command(&executable, "headless", &detached_marker);
        detached.stdin(Stdio::null());
        // SAFETY: the callback invokes only async-signal-safe `setsid` and
        // constructs an `io::Error` on failure.
        unsafe {
            detached.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let detached_output = detached.output().expect("detached probe output");
        assert_native_probe(&detached_output, &detached_marker, "detached", b"headless");

        run_attached_probe(&executable, &attached_marker, "first PTY");
        run_attached_probe(&executable, &second_attached_marker, "second PTY");
        assert_ne!(
            std::fs::read(&attached_marker).expect("read first PTY identity"),
            std::fs::read(&second_attached_marker).expect("read second PTY identity"),
            "independently generated PTY sessions must have distinct identities"
        );
    }

    fn run_attached_probe(executable: &Path, marker: &Path, label: &str) {
        let (master, slave) = open_pty().expect("open PTY");
        let slave_fd = slave.as_raw_fd();
        let mut attached = native_probe_command(executable, "tty", marker);
        attached.stdin(Stdio::null());
        // SAFETY: `slave_fd` is an inherited PTY descriptor. `setsid` and
        // `ioctl(TIOCSCTTY)` are async-signal-safe system calls.
        unsafe {
            attached.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if set_controlling_terminal(slave_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let attached_output = attached.output().expect("PTY probe output");
        assert_native_probe_nonempty(&attached_output, marker, label);
        drop(master);
        drop(slave);
    }

    fn assert_inherited_descendant(expected: &str, parent_marker: &std::ffi::OsStr) {
        let executable = std::env::current_exe().expect("current test executable");
        let mut descendant_marker = PathBuf::from(parent_marker);
        descendant_marker.set_extension("descendant.marker");
        let output = Command::new(executable)
            .arg("--exact")
            .arg(DESCENDANT_TEST_NAME)
            .arg("--ignored")
            .env(DESCENDANT_EXPECTED_ENV, expected)
            .env(DESCENDANT_MARKER_ENV, &descendant_marker)
            .output()
            .expect("inherited descendant probe output");
        assert_native_probe(
            &output,
            &descendant_marker,
            "inherited descendant",
            b"observed",
        );
    }

    fn terminal_fingerprint(terminal: crate::TerminalSessionIdentity) -> String {
        let anchor = terminal.anchor_process;
        let mut bytes = Vec::with_capacity(108);
        bytes.extend_from_slice(&terminal.terminal.digest);
        bytes.extend_from_slice(&anchor.time_domain.0);
        bytes.extend_from_slice(&anchor.pid.get().to_le_bytes());
        bytes.extend_from_slice(&anchor.start_time.get().to_le_bytes());
        bytes.extend_from_slice(&anchor.user.digest);
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("write to string");
        }
        encoded
    }

    #[cfg(target_os = "macos")]
    unsafe fn set_controlling_terminal(descriptor: std::os::fd::RawFd) -> libc::c_int {
        // SAFETY: the caller supplies a live PTY slave descriptor.
        unsafe { libc::ioctl(descriptor, libc::TIOCSCTTY.into(), 0) }
    }

    #[cfg(target_os = "freebsd")]
    unsafe fn set_controlling_terminal(descriptor: std::os::fd::RawFd) -> libc::c_int {
        // SAFETY: the caller supplies a live PTY slave descriptor.
        unsafe { libc::ioctl(descriptor, libc::TIOCSCTTY, 0) }
    }

    fn native_probe_command(executable: &Path, expectation: &str, marker: &Path) -> Command {
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg(CHILD_TEST_NAME)
            .arg("--ignored")
            .env(EXPECTATION_ENV, expectation)
            .env(MARKER_ENV, marker);
        command
    }

    fn assert_native_probe(output: &Output, marker: &Path, label: &str, expected: &[u8]) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{label} native probe failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        let contents = std::fs::read(marker).unwrap_or_else(|error| {
                panic!(
                    "{label} native probe did not create its marker: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            });
        assert_eq!(contents, expected);
    }

    fn assert_native_probe_nonempty(output: &Output, marker: &Path, label: &str) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{label} native probe failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        let contents = std::fs::read(marker).unwrap_or_else(|error| {
            panic!(
                "{label} native probe did not create its marker: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        });
        assert!(!contents.is_empty(), "{label} identity marker was empty");
    }

    fn open_pty() -> std::io::Result<(OwnedFd, OwnedFd)> {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: `openpty` initializes both descriptors on success. Optional
        // name and terminal-setting pointers are null.
        let result = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful `openpty` returned two distinct owned descriptors.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        // SAFETY: ownership of the slave descriptor is transferred once.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        set_close_on_exec(master.as_raw_fd())?;
        set_close_on_exec(slave.as_raw_fd())?;
        Ok((master, slave))
    }

    fn set_close_on_exec(descriptor: std::os::fd::RawFd) -> std::io::Result<()> {
        // SAFETY: `descriptor` is live and borrowed by the caller.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: this updates flags on the same live descriptor.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
