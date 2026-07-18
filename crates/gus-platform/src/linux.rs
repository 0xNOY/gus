use std::{
    fs::File,
    io::Read,
    num::{NonZeroU32, NonZeroU64},
    path::Path,
};

use crate::{
    BootIdentity, LocalSessionObservation, ObservationError, ObservationResource, OsUserIdentity,
    PlatformFamily, ProcessIdentity, TerminalIdentity, TerminalSessionIdentity,
};

const MAX_BOOT_ID_BYTES: u64 = 128;
const MAX_PROC_STAT_BYTES: u64 = 4096;
const MAX_PROC_STATUS_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcStat {
    pid: NonZeroU32,
    parent_pid: Option<NonZeroU32>,
    session_id: NonZeroU32,
    terminal_device: Option<u32>,
    start_time: NonZeroU64,
}

pub(super) fn observe_current() -> Result<LocalSessionObservation, ObservationError> {
    let boot_id = read_bounded(
        Path::new("/proc/sys/kernel/random/boot_id"),
        MAX_BOOT_ID_BYTES,
        ObservationResource::BootIdentity,
    )?;
    let boot = parse_boot_identity(&boot_id)?;
    let caller_first = read_proc_stat(
        Path::new("/proc/self/stat"),
        ObservationResource::CallerProcess,
    )?;
    let caller_uid_first = read_effective_uid(
        Path::new("/proc/self/status"),
        ObservationResource::CallerUser,
    )?;

    let terminal = match caller_first.terminal_device {
        Some(device) => {
            let leader_stat_path = format!("/proc/{}/stat", caller_first.session_id);
            let leader_status_path = format!("/proc/{}/status", caller_first.session_id);
            let leader_first = read_proc_stat(
                Path::new(&leader_stat_path),
                ObservationResource::TerminalAnchorProcess,
            )?;
            let leader_uid_first = read_effective_uid(
                Path::new(&leader_status_path),
                ObservationResource::TerminalAnchorUser,
            )?;
            let leader_second = normalize_anchor_recheck(read_proc_stat(
                Path::new(&leader_stat_path),
                ObservationResource::TerminalAnchorProcess,
            ))?;
            let leader_uid_second = normalize_anchor_recheck(read_effective_uid(
                Path::new(&leader_status_path),
                ObservationResource::TerminalAnchorUser,
            ))?;
            Some((
                device,
                leader_first,
                leader_uid_first,
                leader_second,
                leader_uid_second,
            ))
        }
        None => None,
    };

    let caller_uid_second = read_effective_uid(
        Path::new("/proc/self/status"),
        ObservationResource::CallerUser,
    )?;
    let caller_second = read_proc_stat(
        Path::new("/proc/self/stat"),
        ObservationResource::CallerProcess,
    )?;
    assemble_observation(
        boot,
        caller_first,
        caller_uid_first,
        terminal,
        caller_second,
        caller_uid_second,
    )
}

fn normalize_anchor_recheck<T>(result: Result<T, ObservationError>) -> Result<T, ObservationError> {
    match result {
        Err(ObservationError::Read {
            resource:
                ObservationResource::TerminalAnchorProcess | ObservationResource::TerminalAnchorUser,
            kind: std::io::ErrorKind::NotFound,
        }) => Err(ObservationError::TerminalAnchorChanged),
        other => other,
    }
}

fn assemble_observation(
    boot: BootIdentity,
    caller_first: ProcStat,
    caller_uid_first: u32,
    terminal: Option<(u32, ProcStat, u32, ProcStat, u32)>,
    caller_second: ProcStat,
    caller_uid_second: u32,
) -> Result<LocalSessionObservation, ObservationError> {
    if caller_first != caller_second || caller_uid_first != caller_uid_second {
        return Err(ObservationError::ProcessChanged);
    }
    let user =
        OsUserIdentity::from_native_bytes(PlatformFamily::Linux, &caller_uid_first.to_le_bytes());
    let caller =
        ProcessIdentity::from_observation(boot, caller_first.pid, caller_first.start_time, user);
    let terminal = match terminal {
        Some((device, leader_first, leader_uid_first, leader_second, leader_uid_second)) => {
            if leader_first != leader_second || leader_uid_first != leader_uid_second {
                return Err(ObservationError::TerminalAnchorChanged);
            }
            if leader_first.pid != caller_first.session_id
                || leader_first.session_id != caller_first.session_id
                || leader_first.terminal_device != Some(device)
                || leader_uid_first != caller_uid_first
            {
                return Err(ObservationError::TerminalBindingMismatch);
            }
            let leader = ProcessIdentity::from_observation(
                boot,
                leader_first.pid,
                leader_first.start_time,
                user,
            );
            let terminal =
                TerminalIdentity::from_native_bytes(PlatformFamily::Linux, &device.to_le_bytes());
            Some(TerminalSessionIdentity::from_observation(terminal, leader))
        }
        None => None,
    };
    Ok(LocalSessionObservation::from_observation(
        caller,
        caller_first.parent_pid,
        terminal,
    ))
}

fn read_proc_stat(
    path: &Path,
    resource: ObservationResource,
) -> Result<ProcStat, ObservationError> {
    let contents = read_bounded(path, MAX_PROC_STAT_BYTES, resource)?;
    parse_proc_stat(&contents, resource)
}

fn parse_proc_stat(
    contents: &[u8],
    resource: ObservationResource,
) -> Result<ProcStat, ObservationError> {
    let open = contents
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or(ObservationError::Malformed { resource })?;
    let close = contents
        .iter()
        .rposition(|byte| *byte == b')')
        .filter(|close| *close > open)
        .ok_or(ObservationError::Malformed { resource })?;
    let pid = parse_nonzero_u32(trim_ascii(&contents[..open]), resource)?;
    let suffix = std::str::from_utf8(&contents[close + 1..])
        .map_err(|_| ObservationError::Malformed { resource })?;
    let fields: Vec<&str> = suffix.split_ascii_whitespace().collect();
    if fields.len() <= 19 || fields[0].len() != 1 {
        return Err(ObservationError::Malformed { resource });
    }
    let parent_pid = NonZeroU32::new(parse_u32(fields[1].as_bytes(), resource)?);
    let session_id = parse_nonzero_u32(fields[3].as_bytes(), resource)?;
    let terminal_raw = fields[4]
        .parse::<i32>()
        .map_err(|_| ObservationError::Malformed { resource })?;
    let terminal_device =
        (terminal_raw != 0).then_some(u32::from_ne_bytes(terminal_raw.to_ne_bytes()));
    let start_time = fields[19]
        .parse::<u64>()
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(ObservationError::Malformed { resource })?;
    Ok(ProcStat {
        pid,
        parent_pid,
        session_id,
        terminal_device,
        start_time,
    })
}

fn read_effective_uid(path: &Path, resource: ObservationResource) -> Result<u32, ObservationError> {
    let contents = read_bounded(path, MAX_PROC_STATUS_BYTES, resource)?;
    parse_effective_uid(&contents, resource)
}

fn parse_effective_uid(
    contents: &[u8],
    resource: ObservationResource,
) -> Result<u32, ObservationError> {
    let text =
        std::str::from_utf8(contents).map_err(|_| ObservationError::Malformed { resource })?;
    for line in text.lines() {
        let Some(values) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut fields = values.split_ascii_whitespace();
        let _real = fields.next();
        let effective = fields
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(ObservationError::Malformed { resource })?;
        return Ok(effective);
    }
    Err(ObservationError::Malformed { resource })
}

fn parse_boot_identity(contents: &[u8]) -> Result<BootIdentity, ObservationError> {
    let value = trim_ascii(contents);
    if value.len() != 36
        || value.iter().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte != b'-',
            _ => !byte.is_ascii_hexdigit(),
        })
    {
        return Err(ObservationError::Malformed {
            resource: ObservationResource::BootIdentity,
        });
    }
    Ok(BootIdentity::from_native_bytes(
        PlatformFamily::Linux,
        value,
    ))
}

fn parse_nonzero_u32(
    value: &[u8],
    resource: ObservationResource,
) -> Result<NonZeroU32, ObservationError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .and_then(NonZeroU32::new)
        .ok_or(ObservationError::Malformed { resource })
}

fn parse_u32(value: &[u8], resource: ObservationResource) -> Result<u32, ObservationError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(ObservationError::Malformed { resource })
}

fn read_bounded(
    path: &Path,
    maximum: u64,
    resource: ObservationResource,
) -> Result<Vec<u8>, ObservationError> {
    let file = File::open(path).map_err(|error| ObservationError::Read {
        resource,
        kind: error.kind(),
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ObservationError::Read {
            resource,
            kind: error.kind(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(ObservationError::Oversized { resource });
    }
    Ok(bytes)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::CommandExt,
        },
        process::{Command, Output, Stdio},
    };

    use super::*;

    const NATIVE_PROBE_EXPECTATION: &str = "GUS_PLATFORM_NATIVE_PROBE_EXPECTATION";
    const NATIVE_PROBE_MARKER: &str = "GUS_PLATFORM_NATIVE_PROBE_MARKER";

    fn stat(pid: u32, parent: u32, session: u32, tty: i32, start: u64) -> ProcStat {
        ProcStat {
            pid: NonZeroU32::new(pid).expect("pid"),
            parent_pid: NonZeroU32::new(parent),
            session_id: NonZeroU32::new(session).expect("session"),
            terminal_device: (tty != 0).then_some(u32::from_ne_bytes(tty.to_ne_bytes())),
            start_time: NonZeroU64::new(start).expect("start"),
        }
    }

    fn boot() -> BootIdentity {
        parse_boot_identity(b"01234567-89ab-cdef-8123-456789abcdef\n").expect("boot identity")
    }

    #[test]
    fn proc_stat_parser_handles_spaces_parentheses_and_newlines_in_comm() {
        let fields_8_through_21 = ["0"; 14].join(" ");
        let input =
            format!("42 (worker ) name\nwith space) S 7 8 9 34817 {fields_8_through_21} 12345 0");
        assert_eq!(
            parse_proc_stat(input.as_bytes(), ObservationResource::CallerProcess)
                .expect("parsed stat"),
            stat(42, 7, 9, 34817, 12345)
        );
    }

    #[test]
    fn proc_stat_and_status_reject_sentinel_or_incomplete_values() {
        for input in [
            b"0 (zero) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1".as_slice(),
            b"1 (short) S 1".as_slice(),
            b"1 (zero start) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0".as_slice(),
        ] {
            assert_eq!(
                parse_proc_stat(input, ObservationResource::CallerProcess),
                Err(ObservationError::Malformed {
                    resource: ObservationResource::CallerProcess,
                })
            );
        }
        assert_eq!(
            parse_effective_uid(
                b"Name:\ttest\nUid:\t1000\t1001\t1002\t1003\n",
                ObservationResource::CallerUser,
            ),
            Ok(1001)
        );
        assert!(parse_effective_uid(b"Uid:\t1000\n", ObservationResource::CallerUser).is_err());
    }

    #[test]
    fn observation_binds_terminal_to_same_live_session_leader() {
        let caller = stat(42, 7, 9, 34817, 12345);
        let leader = stat(9, 1, 9, 34817, 12000);
        let observation = assemble_observation(
            boot(),
            caller,
            1000,
            Some((34817_u32, leader, 1000, leader, 1000)),
            caller,
            1000,
        )
        .expect("observation");
        assert!(observation.has_terminal_session());
        assert_eq!(observation.caller().pid().get(), 42);
        assert_eq!(observation.parent_pid().expect("parent").get(), 7);
        assert_eq!(
            observation
                .terminal_session()
                .expect("terminal")
                .anchor_process()
                .pid()
                .get(),
            9
        );
    }

    #[test]
    fn observation_rejects_pid_reuse_and_mismatched_leader() {
        let caller = stat(42, 7, 9, 34817, 12345);
        assert_eq!(
            assemble_observation(
                boot(),
                caller,
                1000,
                None,
                stat(42, 7, 9, 34817, 12346),
                1000,
            ),
            Err(ObservationError::ProcessChanged)
        );
        assert_eq!(
            assemble_observation(boot(), caller, 1000, None, caller, 1001),
            Err(ObservationError::ProcessChanged)
        );
        for (leader, uid) in [
            (stat(10, 1, 9, 34817, 12000), 1000),
            (stat(9, 1, 8, 34817, 12000), 1000),
            (stat(9, 1, 9, 34818, 12000), 1000),
            (stat(9, 1, 9, 34817, 12000), 1001),
        ] {
            assert_eq!(
                assemble_observation(
                    boot(),
                    caller,
                    1000,
                    Some((34817, leader, uid, leader, uid)),
                    caller,
                    1000,
                ),
                Err(ObservationError::TerminalBindingMismatch)
            );
        }
        assert_eq!(
            assemble_observation(
                boot(),
                caller,
                1000,
                Some((
                    34817,
                    stat(9, 1, 9, 34817, 12000),
                    1000,
                    stat(9, 1, 9, 34817, 12001),
                    1000,
                )),
                caller,
                1000,
            ),
            Err(ObservationError::TerminalAnchorChanged)
        );
    }

    #[test]
    fn headless_pid_one_has_no_parent_and_no_terminal() {
        let fields_8_through_21 = ["0"; 14].join(" ");
        let input = format!("1 (init) S 0 1 1 0 {fields_8_through_21} 1");
        let parsed = parse_proc_stat(input.as_bytes(), ObservationResource::CallerProcess)
            .expect("PID 1 stat");
        assert_eq!(parsed.parent_pid, None);
        let observation = assemble_observation(boot(), parsed, 1000, None, parsed, 1000)
            .expect("headless PID 1 observation");
        assert_eq!(observation.parent_pid(), None);
        assert_eq!(observation.terminal_session(), None);
        assert!(!observation.has_terminal_session());
    }

    #[test]
    fn current_process_observation_is_native_and_debug_redacted() {
        let observation = crate::CurrentSessionObserver::new()
            .observe()
            .expect("current process observation");
        assert_eq!(observation.caller().user().family(), PlatformFamily::Linux);
        let debug = format!("{observation:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("opaque_digest"));
    }

    #[test]
    #[ignore = "internal child process for native session smoke tests"]
    fn native_observation_child_probe() {
        let expectation = std::env::var(NATIVE_PROBE_EXPECTATION).expect("probe expectation");
        let marker = std::env::var_os(NATIVE_PROBE_MARKER).expect("probe marker");
        let observation = crate::CurrentSessionObserver::new()
            .observe()
            .expect("child native observation");
        assert_eq!(observation.has_terminal_session(), expectation == "tty");
        std::fs::write(marker, b"observed").expect("write probe marker");
    }

    #[test]
    fn native_observation_distinguishes_detached_and_pty_sessions() {
        let executable = std::env::current_exe().expect("current test executable");
        let directory = tempfile::tempdir().expect("probe marker directory");
        let detached_marker = directory.path().join("detached.marker");
        let attached_marker = directory.path().join("attached.marker");

        let mut detached = native_probe_command(&executable, "headless", &detached_marker);
        detached.stdin(Stdio::null());
        // SAFETY: the callback invokes only async-signal-safe `setsid` and
        // constructs an `io::Error` if it fails. It does not allocate on the
        // success path between fork and exec.
        unsafe {
            detached.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let detached_output = detached.output().expect("detached probe output");
        assert_native_probe(&detached_output, &detached_marker, "detached");

        let (master, slave) = open_pty().expect("open PTY");
        let slave_fd = slave.as_raw_fd();
        let mut attached = native_probe_command(&executable, "tty", &attached_marker);
        attached.stdin(Stdio::null());
        // SAFETY: `slave_fd` is an inherited descriptor returned by `openpty`.
        // `setsid` and `ioctl(TIOCSCTTY)` are async-signal-safe system calls;
        // no non-signal-safe work occurs on their success paths.
        unsafe {
            attached.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let attached_output = attached.output().expect("PTY probe output");
        assert_native_probe(&attached_output, &attached_marker, "PTY");
        drop(master);
        drop(slave);
    }

    fn native_probe_command(executable: &Path, expectation: &str, marker: &Path) -> Command {
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg("linux::tests::native_observation_child_probe")
            .arg("--ignored")
            .env(NATIVE_PROBE_EXPECTATION, expectation)
            .env(NATIVE_PROBE_MARKER, marker);
        command
    }

    fn assert_native_probe(output: &Output, marker: &Path, label: &str) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{label} native probe failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        let marker_contents = std::fs::read(marker).unwrap_or_else(|error| {
            panic!(
                "{label} native probe did not create its marker: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        });
        assert_eq!(
            marker_contents, b"observed",
            "{label} native probe did not execute its exact child test\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    fn open_pty() -> std::io::Result<(OwnedFd, OwnedFd)> {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: `openpty` initializes both integer descriptors when it
        // succeeds. Optional name and terminal-setting pointers are null.
        let result = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful `openpty` returned two new owned descriptors.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        // SAFETY: ownership of the distinct slave descriptor is transferred
        // exactly once.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        set_close_on_exec(master.as_raw_fd())?;
        set_close_on_exec(slave.as_raw_fd())?;
        Ok((master, slave))
    }

    fn set_close_on_exec(descriptor: std::os::fd::RawFd) -> std::io::Result<()> {
        // SAFETY: `descriptor` is a live descriptor owned by the caller.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: F_SETFD updates flags on the same live descriptor and does
        // not take ownership of it.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[test]
    fn leader_uid_change_is_distinct_from_binding_mismatch() {
        let caller = stat(42, 7, 9, 34817, 12345);
        let leader = stat(9, 1, 9, 34817, 12000);
        assert_eq!(
            assemble_observation(
                boot(),
                caller,
                1000,
                Some((34817, leader, 1000, leader, 1001)),
                caller,
                1000,
            ),
            Err(ObservationError::TerminalAnchorChanged)
        );
    }

    #[test]
    fn vanished_anchor_recheck_is_classified_as_a_changed_anchor() {
        for resource in [
            ObservationResource::TerminalAnchorProcess,
            ObservationResource::TerminalAnchorUser,
        ] {
            assert_eq!(
                normalize_anchor_recheck::<()>(Err(ObservationError::Read {
                    resource,
                    kind: std::io::ErrorKind::NotFound,
                })),
                Err(ObservationError::TerminalAnchorChanged)
            );
        }
        assert_eq!(
            normalize_anchor_recheck::<()>(Err(ObservationError::Read {
                resource: ObservationResource::TerminalAnchorProcess,
                kind: std::io::ErrorKind::PermissionDenied,
            })),
            Err(ObservationError::Read {
                resource: ObservationResource::TerminalAnchorProcess,
                kind: std::io::ErrorKind::PermissionDenied,
            })
        );
    }

    #[test]
    fn bounded_reads_keep_resource_specific_error_taxonomy() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let oversized = directory.path().join("oversized");
        std::fs::write(&oversized, b"12345").expect("write fixture");
        assert_eq!(
            read_bounded(&oversized, 4, ObservationResource::BootIdentity),
            Err(ObservationError::Oversized {
                resource: ObservationResource::BootIdentity,
            })
        );

        let missing = directory.path().join("missing");
        assert_eq!(
            read_bounded(&missing, 4, ObservationResource::TerminalAnchorUser),
            Err(ObservationError::Read {
                resource: ObservationResource::TerminalAnchorUser,
                kind: std::io::ErrorKind::NotFound,
            })
        );
    }

    #[test]
    fn native_user_boot_and_terminal_values_are_absent_from_every_debug_surface() {
        let native_boot = b"01234567-89ab-cdef-8123-456789abcdef";
        let boot = parse_boot_identity(native_boot).expect("boot identity");
        let native_uid = 4_242_424_u32;
        let user =
            OsUserIdentity::from_native_bytes(PlatformFamily::Linux, &native_uid.to_le_bytes());
        let native_tty = 3_484_817_u32;
        let terminal =
            TerminalIdentity::from_native_bytes(PlatformFamily::Linux, &native_tty.to_le_bytes());
        let process = ProcessIdentity::from_observation(
            boot,
            NonZeroU32::new(42).expect("pid"),
            NonZeroU64::new(12_345).expect("start"),
            user,
        );
        let session = TerminalSessionIdentity::from_observation(terminal, process);
        let observation = LocalSessionObservation::from_observation(process, None, Some(session));
        let debug =
            format!("{boot:?} {user:?} {terminal:?} {process:?} {session:?} {observation:?}");
        assert!(!debug.contains(std::str::from_utf8(native_boot).expect("ASCII boot ID")));
        assert!(!debug.contains(&native_uid.to_string()));
        assert!(!debug.contains(&native_tty.to_string()));
        assert!(debug.matches("[REDACTED]").count() >= 6);
    }
}
