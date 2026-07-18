use std::{io, mem::MaybeUninit, num::NonZeroU32};

use crate::{
    LocalSessionObservation, ObservationError, ObservationResource, PlatformFamily,
    ProcessTimeDomainIdentity,
    bsd::{ProcessBackend, pid_to_nonzero},
    bsd_model::{ProcessFacts, timeval_start},
};

const NO_TERMINAL_DEVICE: u32 = u32::MAX;
const PROC_FLAG_SLEADER: u32 = 0x20;
const PROC_FLAG_CONTROLT: u32 = 0x80;

struct MacOsBackend;

impl ProcessBackend for MacOsBackend {
    const FAMILY: PlatformFamily = PlatformFamily::MacOs;

    fn time_domain() -> Result<ProcessTimeDomainIdentity, ObservationError> {
        Ok(ProcessTimeDomainIdentity::from_native_bytes(
            Self::FAMILY,
            b"unix-timeval-microseconds-v1",
        ))
    }

    fn current_pid() -> Result<NonZeroU32, ObservationError> {
        // SAFETY: `getpid` has no preconditions and cannot fail.
        pid_to_nonzero(
            unsafe { libc::getpid() },
            ObservationResource::CallerProcess,
        )
    }

    fn read_process(
        pid: NonZeroU32,
        resource: ObservationResource,
    ) -> Result<ProcessFacts, ObservationError> {
        read_process(pid, resource)
    }
}

pub(super) fn observe_current() -> Result<LocalSessionObservation, ObservationError> {
    crate::bsd::observe_current::<MacOsBackend>()
}

fn read_process(
    pid: NonZeroU32,
    resource: ObservationResource,
) -> Result<ProcessFacts, ObservationError> {
    let native_pid =
        i32::try_from(pid.get()).map_err(|_| ObservationError::Malformed { resource })?;
    let buffer_size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| ObservationError::Oversized { resource })?;
    let mut information = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    // SAFETY: `information` is correctly sized and aligned writable storage;
    // `proc_pidinfo` receives its exact byte size and does not retain it.
    let bytes = unsafe {
        libc::proc_pidinfo(
            native_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if bytes <= 0 {
        let error = io::Error::last_os_error();
        return Err(ObservationError::Read {
            resource,
            kind: if error.raw_os_error() == Some(libc::ESRCH) {
                io::ErrorKind::NotFound
            } else {
                error.kind()
            },
        });
    }
    if bytes != buffer_size {
        return Err(ObservationError::Malformed { resource });
    }
    // SAFETY: an exact-size successful result initialized the whole structure.
    let information = unsafe { information.assume_init() };
    if information.pbi_pid != pid.get() {
        return Err(ObservationError::Malformed { resource });
    }
    if information.pbi_status == libc::SZOMB {
        return Err(zombie_error(resource));
    }

    // SAFETY: `getsid` only reads process metadata for the requested PID.
    let session_id = unsafe { libc::getsid(native_pid) };
    let session_id = pid_to_nonzero(session_id, resource)?;
    if resource == ObservationResource::CallerProcess {
        validate_current_process(&information, session_id, resource)?;
    }
    let terminal_device =
        (information.e_tdev != NO_TERMINAL_DEVICE).then_some(u64::from(information.e_tdev));
    let start_time = timeval_start(
        i128::from(information.pbi_start_tvsec),
        i128::from(information.pbi_start_tvusec),
        resource,
    )?;

    Ok(ProcessFacts {
        pid,
        parent_pid: NonZeroU32::new(information.pbi_ppid),
        process_group_id: NonZeroU32::new(information.pbi_pgid)
            .ok_or(ObservationError::Malformed { resource })?,
        session_id,
        terminal_device,
        terminal_session_id: terminal_device.map(|_| session_id),
        has_control_terminal: information.pbi_flags & PROC_FLAG_CONTROLT != 0,
        is_session_leader: information.pbi_flags & PROC_FLAG_SLEADER != 0,
        start_time,
        effective_uid: information.pbi_uid,
        user_namespace: 0,
    })
}

fn validate_current_process(
    information: &libc::proc_bsdinfo,
    session_id: NonZeroU32,
    resource: ObservationResource,
) -> Result<(), ObservationError> {
    // SAFETY: these calls query immutable scalar metadata for the current
    // process and have no pointer preconditions.
    let (pid, parent_pid, effective_uid, process_group, session) = unsafe {
        (
            libc::getpid(),
            libc::getppid(),
            libc::geteuid(),
            libc::getpgid(0),
            libc::getsid(0),
        )
    };
    if process_group == -1 || session == -1 {
        return Err(ObservationError::Read {
            resource,
            kind: io::Error::last_os_error().kind(),
        });
    }
    if u32::try_from(pid).ok() != Some(information.pbi_pid)
        || u32::try_from(parent_pid).ok() != Some(information.pbi_ppid)
        || effective_uid != information.pbi_uid
        || u32::try_from(process_group).ok() != Some(information.pbi_pgid)
        || u32::try_from(session).ok() != Some(session_id.get())
    {
        return Err(ObservationError::ProcessChanged);
    }
    Ok(())
}

fn zombie_error(resource: ObservationResource) -> ObservationError {
    if resource == ObservationResource::TerminalAnchorProcess {
        ObservationError::Read {
            resource,
            kind: io::ErrorKind::NotFound,
        }
    } else {
        ObservationError::Malformed { resource }
    }
}
