use std::{
    ffi::c_void,
    io,
    mem::{MaybeUninit, size_of},
    num::{NonZeroU32, NonZeroU64},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE,
        ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        SetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::{
        Console::GetConsoleProcessList,
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
        },
    },
};

use crate::{
    LocalSessionObservation, ObservationError, ObservationResource, OsUserIdentity, PlatformFamily,
    ProcessIdentity, ProcessTimeDomainIdentity, TerminalIdentity, TerminalSessionIdentity,
    windows_model::{
        AnchorModelError, ProcessParent, creation_order_is_valid, derive_terminal_chain, parent_of,
    },
};

const WINDOWS_PROCESS_TIME_DOMAIN: &[u8] = b"windows-filetime-1601-utc-100ns-v1";
const INITIAL_CONSOLE_PROCESS_CAPACITY: usize = 16;
const MAX_CONSOLE_PROCESSES: usize = 65_536;
const MAX_PROCESS_SNAPSHOT_ENTRIES: usize = 131_072;
const MAX_SNAPSHOT_ATTEMPTS: usize = 8;
const MAX_TOKEN_INFORMATION_BYTES: usize = 4096;
const MIN_SID_BYTES: usize = 8;
const MAX_SID_BYTES: usize = 68;
// Standard process access right required by `WaitForSingleObject`.
const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn regular(handle: HANDLE, resource: ObservationResource) -> Result<Self, ObservationError> {
        if handle.is_null() {
            Err(last_read_error(resource))
        } else {
            Ok(Self(handle))
        }
    }

    fn snapshot(handle: HANDLE) -> Option<Self> {
        (handle != INVALID_HANDLE_VALUE).then_some(Self(handle))
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `OwnedHandle` is only constructed from a successful Win32
        // handle-returning call and owns that handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessFacts {
    pid: NonZeroU32,
    start_time: NonZeroU64,
    user_sid: Vec<u8>,
    session_id: u32,
}

struct ObservedProcess {
    handle: OwnedHandle,
    facts: ProcessFacts,
}

pub(super) fn observe_current() -> Result<LocalSessionObservation, ObservationError> {
    let time_domain = ProcessTimeDomainIdentity::from_native_bytes(
        PlatformFamily::Windows,
        WINDOWS_PROCESS_TIME_DOMAIN,
    );
    // SAFETY: `GetCurrentProcessId` has no preconditions.
    let caller_pid =
        NonZeroU32::new(unsafe { GetCurrentProcessId() }).ok_or(ObservationError::Malformed {
            resource: ObservationResource::CallerProcess,
        })?;
    let caller_first = observe_process(
        caller_pid,
        ObservationResource::CallerProcess,
        ObservationResource::CallerUser,
    )?;
    let snapshot_first = process_snapshot()?;
    let parent_pid_raw =
        parent_of(caller_pid.get(), &snapshot_first).map_err(map_initial_ancestry_error)?;
    let parent_pid = NonZeroU32::new(parent_pid_raw);
    let console_first = console_processes()?;

    let Some(attached_first) = console_first else {
        let snapshot_second = process_snapshot()?;
        let parent_second = parent_of(caller_pid.get(), &snapshot_second)
            .map_err(|_| ObservationError::ProcessChanged)?;
        let caller_second = observe_process(
            caller_pid,
            ObservationResource::CallerProcess,
            ObservationResource::CallerUser,
        )?;
        if parent_second != parent_pid_raw || caller_first.facts != caller_second.facts {
            return Err(ObservationError::ProcessChanged);
        }
        require_live(&caller_first, ObservationError::ProcessChanged)?;
        require_live(&caller_second, ObservationError::ProcessChanged)?;
        return Ok(LocalSessionObservation::from_observation(
            process_identity(time_domain, &caller_first.facts),
            parent_pid,
            None,
        ));
    };

    let chain_pids_first =
        derive_terminal_chain(caller_pid.get(), &attached_first, &snapshot_first)
            .map_err(map_initial_terminal_error)?;
    let chain_first = observe_chain(&chain_pids_first)?;
    validate_terminal_chain(&caller_first.facts, &chain_first)?;

    let snapshot_second = process_snapshot()?;
    let parent_second = parent_of(caller_pid.get(), &snapshot_second)
        .map_err(|_| ObservationError::ProcessChanged)?;
    let attached_second = console_processes()?.ok_or(ObservationError::TerminalAnchorChanged)?;
    let chain_pids_second =
        derive_terminal_chain(caller_pid.get(), &attached_second, &snapshot_second)
            .map_err(|_| ObservationError::TerminalAnchorChanged)?;
    if parent_second != parent_pid_raw || chain_pids_first != chain_pids_second {
        return Err(ObservationError::TerminalAnchorChanged);
    }

    let chain_second = observe_chain(&chain_pids_second)?;
    validate_terminal_chain(&caller_first.facts, &chain_second)?;
    if !same_process_chain(&chain_first, &chain_second) {
        return Err(ObservationError::TerminalAnchorChanged);
    }
    require_live(&caller_first, ObservationError::ProcessChanged)?;
    for process in chain_first.iter().chain(&chain_second) {
        require_live(process, ObservationError::TerminalAnchorChanged)?;
    }

    let caller = process_identity(time_domain, &caller_first.facts);
    let anchor_facts = &chain_first
        .last()
        .ok_or(ObservationError::TerminalBindingMismatch)?
        .facts;
    let anchor = process_identity(time_domain, anchor_facts);
    let mut terminal_native = Vec::with_capacity(size_of::<u32>() * 2 + size_of::<u64>());
    terminal_native.extend_from_slice(&anchor_facts.session_id.to_le_bytes());
    terminal_native.extend_from_slice(&anchor_facts.pid.get().to_le_bytes());
    terminal_native.extend_from_slice(&anchor_facts.start_time.get().to_le_bytes());
    let terminal = TerminalIdentity::from_native_bytes(PlatformFamily::Windows, &terminal_native);
    Ok(LocalSessionObservation::from_observation(
        caller,
        parent_pid,
        Some(TerminalSessionIdentity::from_observation(terminal, anchor)),
    ))
}

fn process_identity(
    time_domain: ProcessTimeDomainIdentity,
    facts: &ProcessFacts,
) -> ProcessIdentity {
    let user = OsUserIdentity::from_native_bytes(PlatformFamily::Windows, &facts.user_sid);
    ProcessIdentity::from_observation(time_domain, facts.pid, facts.start_time, user)
}

fn observe_chain(pids: &[u32]) -> Result<Vec<ObservedProcess>, ObservationError> {
    pids.iter()
        .copied()
        .map(|pid| {
            let pid = NonZeroU32::new(pid).ok_or(ObservationError::Malformed {
                resource: ObservationResource::ProcessAncestry,
            })?;
            observe_process(
                pid,
                ObservationResource::TerminalAnchorProcess,
                ObservationResource::TerminalAnchorUser,
            )
        })
        .collect()
}

fn observe_process(
    pid: NonZeroU32,
    process_resource: ObservationResource,
    user_resource: ObservationResource,
) -> Result<ObservedProcess, ObservationError> {
    // SAFETY: The access mask and PID are values accepted by `OpenProcess`.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.get(),
        )
    };
    let handle = OwnedHandle::regular(handle, process_resource)?;
    require_handle_live(&handle, process_resource)?;
    let start_time = process_start_time(&handle, process_resource)?;
    let user_sid = process_user_sid(&handle, user_resource)?;
    let session_id = process_session_id(&handle, pid, process_resource)?;
    require_handle_live(&handle, process_resource)?;
    Ok(ObservedProcess {
        handle,
        facts: ProcessFacts {
            pid,
            start_time,
            user_sid,
            session_id,
        },
    })
}

fn process_start_time(
    process: &OwnedHandle,
    resource: ObservationResource,
) -> Result<NonZeroU64, ObservationError> {
    let mut creation = MaybeUninit::<FILETIME>::uninit();
    let mut exit = MaybeUninit::<FILETIME>::uninit();
    let mut kernel = MaybeUninit::<FILETIME>::uninit();
    let mut user = MaybeUninit::<FILETIME>::uninit();
    // SAFETY: All pointers reference writable `FILETIME` storage and the
    // process handle was opened with query access.
    if unsafe {
        GetProcessTimes(
            process.raw(),
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        )
    } == 0
    {
        return Err(last_read_error(resource));
    }
    // SAFETY: A successful `GetProcessTimes` initializes every output.
    let creation = unsafe { creation.assume_init() };
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    NonZeroU64::new(value).ok_or(ObservationError::Malformed { resource })
}

fn process_user_sid(
    process: &OwnedHandle,
    resource: ObservationResource,
) -> Result<Vec<u8>, ObservationError> {
    let mut token = ptr::null_mut();
    // SAFETY: `token` is writable and the process handle is valid.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, ptr::addr_of_mut!(token)) } == 0 {
        return Err(last_read_error(resource));
    }
    let token = OwnedHandle::regular(token, resource)?;
    let mut required = 0_u32;
    // SAFETY: A null buffer with zero length is the documented size query.
    let first_result = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            ptr::null_mut(),
            0,
            ptr::addr_of_mut!(required),
        )
    };
    // SAFETY: `GetLastError` has no preconditions.
    let first_error = unsafe { GetLastError() };
    if first_result != 0 || first_error != ERROR_INSUFFICIENT_BUFFER || required == 0 {
        return Err(if first_result == 0 {
            win32_read_error(resource, first_error)
        } else {
            ObservationError::Malformed { resource }
        });
    }
    let required =
        usize::try_from(required).map_err(|_| ObservationError::Oversized { resource })?;
    if required > MAX_TOKEN_INFORMATION_BYTES {
        return Err(ObservationError::Oversized { resource });
    }
    let mut buffer = vec![0_u8; required];
    let mut returned = 0_u32;
    // SAFETY: `buffer` is writable for its reported length and `returned` is
    // writable. The token handle remains alive.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).map_err(|_| ObservationError::Oversized { resource })?,
            ptr::addr_of_mut!(returned),
        )
    } == 0
    {
        return Err(last_read_error(resource));
    }
    let returned =
        usize::try_from(returned).map_err(|_| ObservationError::Oversized { resource })?;
    if returned < size_of::<TOKEN_USER>() || returned > buffer.len() {
        return Err(ObservationError::Malformed { resource });
    }
    // `Vec<u8>` need not satisfy `TOKEN_USER` alignment.
    // SAFETY: The returned byte count covers a complete `TOKEN_USER` value.
    let token_user = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(returned)
        .ok_or(ObservationError::Malformed { resource })?;
    let sid_start = token_user.User.Sid as usize;
    if sid_start < buffer_start
        || sid_start
            .checked_add(MIN_SID_BYTES)
            .is_none_or(|minimum_end| minimum_end > buffer_end)
    {
        return Err(ObservationError::Malformed { resource });
    }
    // SAFETY: The pointer is inside the returned token buffer with enough
    // bytes for the fixed SID header.
    if unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(ObservationError::Malformed { resource });
    }
    // SAFETY: `IsValidSid` accepted this in-buffer SID pointer.
    let sid_len = usize::try_from(unsafe { GetLengthSid(token_user.User.Sid) })
        .map_err(|_| ObservationError::Malformed { resource })?;
    if !(MIN_SID_BYTES..=MAX_SID_BYTES).contains(&sid_len)
        || sid_start
            .checked_add(sid_len)
            .is_none_or(|sid_end| sid_end > buffer_end)
    {
        return Err(ObservationError::Malformed { resource });
    }
    let offset = sid_start - buffer_start;
    Ok(buffer[offset..offset + sid_len].to_vec())
}

fn process_session_id(
    process: &OwnedHandle,
    pid: NonZeroU32,
    resource: ObservationResource,
) -> Result<u32, ObservationError> {
    require_handle_live(process, resource)?;
    let mut session_id = 0_u32;
    // SAFETY: `session_id` is writable and `pid` identifies the process whose
    // live handle is retained by the caller.
    if unsafe { ProcessIdToSessionId(pid.get(), ptr::addr_of_mut!(session_id)) } == 0 {
        return Err(last_read_error(resource));
    }
    require_handle_live(process, resource)?;
    Ok(session_id)
}

fn validate_terminal_chain(
    caller: &ProcessFacts,
    chain: &[ObservedProcess],
) -> Result<(), ObservationError> {
    let Some(first) = chain.first() else {
        return Err(ObservationError::TerminalBindingMismatch);
    };
    if &first.facts != caller
        || chain.iter().any(|process| {
            process.facts.user_sid != caller.user_sid
                || process.facts.session_id != caller.session_id
        })
        || !creation_order_is_valid(
            &chain
                .iter()
                .map(|process| process.facts.start_time.get())
                .collect::<Vec<_>>(),
        )
    {
        return Err(ObservationError::TerminalBindingMismatch);
    }
    Ok(())
}

fn same_process_chain(first: &[ObservedProcess], second: &[ObservedProcess]) -> bool {
    first.len() == second.len()
        && first
            .iter()
            .zip(second)
            .all(|(first, second)| first.facts == second.facts)
}

fn require_live(
    process: &ObservedProcess,
    changed: ObservationError,
) -> Result<(), ObservationError> {
    match handle_liveness(&process.handle, ObservationResource::TerminalAnchorProcess) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(changed),
    }
}

fn require_handle_live(
    handle: &OwnedHandle,
    resource: ObservationResource,
) -> Result<(), ObservationError> {
    if handle_liveness(handle, resource)? {
        Ok(())
    } else {
        Err(ObservationError::Read {
            resource,
            kind: io::ErrorKind::NotFound,
        })
    }
}

fn handle_liveness(
    handle: &OwnedHandle,
    resource: ObservationResource,
) -> Result<bool, ObservationError> {
    // SAFETY: The handle is owned and remains valid for this call. A zero
    // timeout only probes its signaled state.
    match unsafe { WaitForSingleObject(handle.raw(), 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        WAIT_FAILED => Err(last_read_error(resource)),
        _ => Err(ObservationError::Malformed { resource }),
    }
}

fn process_snapshot() -> Result<Vec<ProcessParent>, ObservationError> {
    let resource = ObservationResource::ProcessAncestry;
    let snapshot = (0..MAX_SNAPSHOT_ATTEMPTS)
        .find_map(|_| {
            // SAFETY: A system-wide process snapshot uses PID zero by contract.
            let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
            if let Some(handle) = OwnedHandle::snapshot(raw) {
                return Some(Ok(handle));
            }
            // SAFETY: `GetLastError` has no preconditions.
            let error = unsafe { GetLastError() };
            (error != ERROR_BAD_LENGTH).then_some(Err(win32_read_error(resource, error)))
        })
        .unwrap_or(Err(ObservationError::Read {
            resource,
            kind: io::ErrorKind::Other,
        }))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
            .map_err(|_| ObservationError::Malformed { resource })?,
        ..PROCESSENTRY32W::default()
    };
    // SAFETY: `entry` is writable, sized as required, and `snapshot` is a live
    // ToolHelp snapshot handle.
    unsafe {
        SetLastError(ERROR_SUCCESS);
    }
    if unsafe { Process32FirstW(snapshot.raw(), ptr::addr_of_mut!(entry)) } == 0 {
        // SAFETY: `GetLastError` has no preconditions.
        let error = unsafe { GetLastError() };
        if error == ERROR_NO_MORE_FILES {
            return Ok(Vec::new());
        }
        return Err(win32_read_error(resource, error));
    }
    let mut processes = Vec::new();
    loop {
        if processes.len() == MAX_PROCESS_SNAPSHOT_ENTRIES {
            return Err(ObservationError::Oversized { resource });
        }
        if entry.th32ProcessID != 0 {
            processes.push(ProcessParent {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
            });
        }
        // SAFETY: The same initialized entry remains writable for iteration.
        unsafe {
            SetLastError(ERROR_SUCCESS);
        }
        if unsafe { Process32NextW(snapshot.raw(), ptr::addr_of_mut!(entry)) } == 0 {
            // SAFETY: `GetLastError` has no preconditions.
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(win32_read_error(resource, error));
        }
    }
    Ok(processes)
}

fn console_processes() -> Result<Option<Vec<u32>>, ObservationError> {
    let resource = ObservationResource::TerminalSession;
    let mut capacity = INITIAL_CONSOLE_PROCESS_CAPACITY;
    loop {
        let mut processes = vec![0_u32; capacity];
        let capacity_u32 =
            u32::try_from(capacity).map_err(|_| ObservationError::Oversized { resource })?;
        // Clearing last-error distinguishes a detached process from an
        // unexpected zero result without trusting stale thread state.
        // SAFETY: Both Win32 calls accept these values, and the vector is
        // writable for `capacity_u32` process identifiers.
        unsafe {
            SetLastError(ERROR_SUCCESS);
        }
        let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), capacity_u32) };
        if count == 0 {
            // SAFETY: `GetLastError` has no preconditions.
            let error = unsafe { GetLastError() };
            if error == ERROR_INVALID_HANDLE {
                return Ok(None);
            }
            return Err(if error == ERROR_SUCCESS {
                ObservationError::Malformed { resource }
            } else {
                win32_read_error(resource, error)
            });
        }
        let count = usize::try_from(count).map_err(|_| ObservationError::Oversized { resource })?;
        if count > MAX_CONSOLE_PROCESSES {
            return Err(ObservationError::Oversized { resource });
        }
        if count > capacity {
            capacity = count;
            continue;
        }
        processes.truncate(count);
        return Ok(Some(processes));
    }
}

fn map_initial_ancestry_error(_error: AnchorModelError) -> ObservationError {
    ObservationError::Malformed {
        resource: ObservationResource::ProcessAncestry,
    }
}

fn map_initial_terminal_error(error: AnchorModelError) -> ObservationError {
    match error {
        AnchorModelError::CallerNotAttached => ObservationError::TerminalBindingMismatch,
        _ => ObservationError::Malformed {
            resource: ObservationResource::ProcessAncestry,
        },
    }
}

fn last_read_error(resource: ObservationResource) -> ObservationError {
    // SAFETY: `GetLastError` has no preconditions.
    win32_read_error(resource, unsafe { GetLastError() })
}

fn win32_read_error(resource: ObservationResource, error: u32) -> ObservationError {
    ObservationError::Read {
        resource,
        kind: io::Error::from_raw_os_error(i32::try_from(error).unwrap_or(i32::MAX)).kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_observation_uses_native_windows_evidence() {
        let observation = observe_current().expect("observe current Windows process");
        assert_eq!(
            observation.caller().user().family(),
            PlatformFamily::Windows
        );
        assert_ne!(observation.caller().pid().get(), 0);
        assert_ne!(observation.caller().start_time().get(), 0);
        if let Some(terminal) = observation.terminal_session() {
            assert_eq!(terminal.terminal().family(), PlatformFamily::Windows);
            assert_eq!(
                terminal.anchor_process().user(),
                observation.caller().user()
            );
        }
    }
}
