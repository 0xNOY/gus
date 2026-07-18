use std::{io, num::NonZeroU32, ptr::NonNull};

use crate::{
    LocalSessionObservation, ObservationError, ObservationResource, PlatformFamily,
    ProcessTimeDomainIdentity,
    bsd::{ProcessBackend, pid_to_nonzero},
    bsd_model::{ProcessFacts, timeval_start},
};

struct FreeBsdBackend;

impl ProcessBackend for FreeBsdBackend {
    const FAMILY: PlatformFamily = PlatformFamily::FreeBsd;

    fn time_domain() -> Result<ProcessTimeDomainIdentity, ObservationError> {
        let boot_id = read_boot_id()?;
        Ok(ProcessTimeDomainIdentity::from_native_bytes(
            Self::FAMILY,
            &boot_id,
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
    crate::bsd::observe_current::<FreeBsdBackend>()
}

fn read_boot_id() -> Result<[u8; 16], ObservationError> {
    let resource = ObservationResource::ProcessTimeDomain;
    let mut boot_id = [0_u8; 16];
    let mut length = boot_id.len();
    // SAFETY: the name is static and NUL-terminated; the output pointer and
    // length describe the complete writable byte array. This is a read-only
    // sysctl, so the new-value pointers are null.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.boot_id".as_ptr(),
            boot_id.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == -1 {
        return Err(last_read_error(resource));
    }
    if length != boot_id.len() || boot_id.iter().all(|byte| *byte == 0) {
        return Err(ObservationError::Malformed { resource });
    }
    Ok(boot_id)
}

fn read_process(
    pid: NonZeroU32,
    resource: ObservationResource,
) -> Result<ProcessFacts, ObservationError> {
    let native_pid =
        i32::try_from(pid.get()).map_err(|_| ObservationError::Malformed { resource })?;
    // `kinfo_getproc` can return null from its own exact-size validation
    // without setting errno, so clear it before the call.
    // SAFETY: `__error` returns this thread's writable errno slot.
    unsafe { *libc::__error() = 0 };
    // SAFETY: `kinfo_getproc` borrows the numeric PID and returns either null
    // or one allocation owned by the caller.
    let pointer = unsafe { kinfo_getproc(native_pid) };
    let Some(pointer) = NonNull::new(pointer) else {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(0) {
            Err(ObservationError::Malformed { resource })
        } else {
            Err(ObservationError::Read {
                resource,
                kind: if error.raw_os_error() == Some(libc::ESRCH) {
                    io::ErrorKind::NotFound
                } else {
                    error.kind()
                },
            })
        };
    };
    let allocation = KinfoAllocation(pointer);
    // SAFETY: the RAII allocation is live and points to a `kinfo_proc`
    // returned by libutil for the requested PID.
    let information = unsafe { allocation.0.as_ptr().cast::<libc::kinfo_proc>().as_ref() }
        .ok_or(ObservationError::Malformed { resource })?;
    let expected_size = i32::try_from(size_of::<libc::kinfo_proc>())
        .map_err(|_| ObservationError::Oversized { resource })?;
    if information.ki_structsize != expected_size
        || information.ki_layout != 0
        || information.ki_pid != native_pid
        || information.ki_stat == libc::SZOMB
    {
        return Err(ObservationError::Malformed { resource });
    }

    let session_id = pid_to_nonzero(information.ki_sid, resource)?;
    let terminal_device = (information.ki_tdev != u64::MAX).then_some(information.ki_tdev);
    let terminal_session_id = NonZeroU32::new(
        u32::try_from(information.ki_tsid).map_err(|_| ObservationError::Malformed { resource })?,
    );
    let process_group_id = pid_to_nonzero(information.ki_pgid, resource)?;
    let jail_id =
        u32::try_from(information.ki_jid).map_err(|_| ObservationError::Malformed { resource })?;
    let flags = usize::try_from(information.ki_kiflag)
        .map_err(|_| ObservationError::Malformed { resource })?;
    let start_time = timeval_start(
        i128::from(information.ki_start.tv_sec),
        i128::from(information.ki_start.tv_usec),
        resource,
    )?;
    if resource == ObservationResource::CallerProcess {
        validate_current_process(information, session_id, resource)?;
    }

    Ok(ProcessFacts {
        pid,
        parent_pid: u32::try_from(information.ki_ppid)
            .ok()
            .and_then(NonZeroU32::new),
        process_group_id,
        session_id,
        terminal_device,
        terminal_session_id,
        has_control_terminal: flags & libc::KI_CTTY != 0,
        is_session_leader: flags & libc::KI_SLEADER != 0,
        start_time,
        effective_uid: information.ki_uid,
        user_namespace: jail_id,
    })
}

fn validate_current_process(
    information: &libc::kinfo_proc,
    session_id: NonZeroU32,
    resource: ObservationResource,
) -> Result<(), ObservationError> {
    // SAFETY: these calls query scalar metadata for the current process and
    // have no pointer preconditions.
    let (pid, parent_pid, effective_uid, process_group, session) = unsafe {
        (
            libc::getpid(),
            libc::getppid(),
            libc::geteuid(),
            libc::getpgid(0),
            libc::getsid(0),
        )
    };
    if pid != information.ki_pid
        || parent_pid != information.ki_ppid
        || effective_uid != information.ki_uid
        || process_group != information.ki_pgid
        || u32::try_from(session).ok() != Some(session_id.get())
    {
        return Err(ObservationError::Malformed { resource });
    }
    Ok(())
}

struct KinfoAllocation(NonNull<libc::c_void>);

impl Drop for KinfoAllocation {
    fn drop(&mut self) {
        // SAFETY: this pointer came from `kinfo_getproc` and is freed once.
        unsafe { libc::free(self.0.as_ptr()) };
    }
}

fn last_read_error(resource: ObservationResource) -> ObservationError {
    ObservationError::Read {
        resource,
        kind: io::Error::last_os_error().kind(),
    }
}

#[link(name = "util")]
unsafe extern "C" {
    fn kinfo_getproc(pid: libc::pid_t) -> *mut libc::c_void;
}
