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
        ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, GetLastError, HANDLE, HWND,
        INVALID_HANDLE_VALUE, SetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::{
        Console::{GetConsoleProcessList, GetConsoleWindow},
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
    UI::WindowsAndMessaging::GetWindowThreadProcessId,
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

    #[cfg(test)]
    fn into_raw(self) -> HANDLE {
        let raw = self.0;
        std::mem::forget(self);
        raw
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConsoleFacts {
    window_handle: u64,
    host_pid: NonZeroU32,
    host_start_time: NonZeroU64,
    session_id: u32,
}

struct ObservedConsole {
    host_handle: OwnedHandle,
    facts: ConsoleFacts,
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
        let console_second = console_processes()?;
        if parent_second != parent_pid_raw
            || caller_first.facts != caller_second.facts
            || console_second.is_some()
        {
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

    let console_first = observe_console()?;
    if console_first.facts.session_id != caller_first.facts.session_id {
        return Err(ObservationError::TerminalBindingMismatch);
    }

    let chain_pids_first =
        derive_terminal_chain(caller_pid.get(), &attached_first, &snapshot_first)
            .map_err(map_initial_terminal_error)?;
    let chain_first = observe_chain(&chain_pids_first)?;
    validate_terminal_chain(&caller_first.facts, &chain_first)?;

    let snapshot_second = normalize_terminal_recheck(process_snapshot())?;
    let parent_second = parent_of(caller_pid.get(), &snapshot_second)
        .map_err(|_| ObservationError::TerminalAnchorChanged)?;
    let attached_second = normalize_terminal_recheck(console_processes())?
        .ok_or(ObservationError::TerminalAnchorChanged)?;
    let console_second = normalize_terminal_recheck(observe_console())?;
    let chain_pids_second =
        derive_terminal_chain(caller_pid.get(), &attached_second, &snapshot_second)
            .map_err(|_| ObservationError::TerminalAnchorChanged)?;
    if parent_second != parent_pid_raw || chain_pids_first != chain_pids_second {
        return Err(ObservationError::TerminalAnchorChanged);
    }

    let chain_second = normalize_terminal_recheck(observe_chain(&chain_pids_second))?;
    normalize_terminal_recheck(validate_terminal_chain(&caller_first.facts, &chain_second))?;
    if !same_process_chain(&chain_first, &chain_second)
        || console_first.facts != console_second.facts
    {
        return Err(ObservationError::TerminalAnchorChanged);
    }
    require_live(&caller_first, ObservationError::ProcessChanged)?;
    for process in chain_first.iter().chain(&chain_second) {
        require_live(process, ObservationError::TerminalAnchorChanged)?;
    }
    require_console_live(&console_first)?;
    require_console_live(&console_second)?;

    let caller = process_identity(time_domain, &caller_first.facts);
    let anchor_facts = &chain_first
        .last()
        .ok_or(ObservationError::TerminalBindingMismatch)?
        .facts;
    let anchor = process_identity(time_domain, anchor_facts);
    let mut terminal_native = Vec::with_capacity(size_of::<u32>() * 3 + size_of::<u64>() * 3);
    terminal_native.extend_from_slice(&console_first.facts.session_id.to_le_bytes());
    terminal_native.extend_from_slice(&console_first.facts.window_handle.to_le_bytes());
    terminal_native.extend_from_slice(&console_first.facts.host_pid.get().to_le_bytes());
    terminal_native.extend_from_slice(&console_first.facts.host_start_time.get().to_le_bytes());
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
    let handle = open_process_handle(pid, process_resource)?;
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

fn observe_console() -> Result<ObservedConsole, ObservationError> {
    let resource = ObservationResource::TerminalSession;
    // SAFETY: `GetConsoleWindow` has no preconditions and returns the window
    // associated with the calling process's current console.
    let window = unsafe { GetConsoleWindow() };
    if window.is_null() {
        return Err(ObservationError::TerminalBindingMismatch);
    }
    let host_pid = console_window_host_pid(window)?;
    let host_handle = open_process_handle(host_pid, resource)?;
    require_handle_live(&host_handle, resource)?;
    let host_start_time = process_start_time(&host_handle, resource)?;
    let session_id = process_session_id(&host_handle, host_pid, resource)?;

    // Re-read the association after opening its owner. This rejects a window
    // handle that was destroyed and reused while the process was observed.
    // SAFETY: `GetConsoleWindow` has no preconditions.
    let window_second = unsafe { GetConsoleWindow() };
    if window_second != window || console_window_host_pid(window_second)? != host_pid {
        return Err(ObservationError::TerminalAnchorChanged);
    }
    require_handle_live(&host_handle, resource)?;
    Ok(ObservedConsole {
        host_handle,
        facts: ConsoleFacts {
            window_handle: u64::try_from(window as usize)
                .map_err(|_| ObservationError::Malformed { resource })?,
            host_pid,
            host_start_time,
            session_id,
        },
    })
}

fn console_window_host_pid(window: HWND) -> Result<NonZeroU32, ObservationError> {
    let resource = ObservationResource::TerminalSession;
    if window.is_null() {
        return Err(ObservationError::TerminalBindingMismatch);
    }
    let mut pid = 0_u32;
    // SAFETY: `pid` is writable and `window` was returned for the calling
    // process's console association.
    let thread_id = unsafe { GetWindowThreadProcessId(window, ptr::addr_of_mut!(pid)) };
    if thread_id == 0 {
        return Err(last_read_error(resource));
    }
    NonZeroU32::new(pid).ok_or(ObservationError::Malformed { resource })
}

fn open_process_handle(
    pid: NonZeroU32,
    resource: ObservationResource,
) -> Result<OwnedHandle, ObservationError> {
    // SAFETY: The access mask and PID are values accepted by `OpenProcess`.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.get(),
        )
    };
    OwnedHandle::regular(handle, resource)
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
    let sid_offset = sid_start - buffer_start;
    let encoded_sid_len = MIN_SID_BYTES
        .checked_add(usize::from(buffer[sid_offset + 1]) * size_of::<u32>())
        .ok_or(ObservationError::Malformed { resource })?;
    if encoded_sid_len > MAX_SID_BYTES
        || sid_start
            .checked_add(encoded_sid_len)
            .is_none_or(|sid_end| sid_end > buffer_end)
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
    if sid_len != encoded_sid_len
        || !(MIN_SID_BYTES..=MAX_SID_BYTES).contains(&sid_len)
        || sid_start
            .checked_add(sid_len)
            .is_none_or(|sid_end| sid_end > buffer_end)
    {
        return Err(ObservationError::Malformed { resource });
    }
    Ok(buffer[sid_offset..sid_offset + sid_len].to_vec())
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

fn require_console_live(console: &ObservedConsole) -> Result<(), ObservationError> {
    match handle_liveness(&console.host_handle, ObservationResource::TerminalSession) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(ObservationError::TerminalAnchorChanged),
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

fn normalize_terminal_recheck<T>(
    result: Result<T, ObservationError>,
) -> Result<T, ObservationError> {
    result.map_err(|_| ObservationError::TerminalAnchorChanged)
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
    use std::{
        env,
        ffi::c_void,
        fmt::Write as _,
        fs::{self, File},
        io::Read as _,
        os::windows::{ffi::OsStrExt as _, io::FromRawHandle as _},
        path::{Path, PathBuf},
        process::{Command, Output},
        thread,
    };

    use std::os::windows::process::CommandExt;
    use tempfile::tempdir;
    use windows_sys::Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            Console::{
                AllocConsole, COORD, ClosePseudoConsole, CreatePseudoConsole, FreeConsole, HPCON,
            },
            Pipes::CreatePipe,
            Threading::{
                CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList,
                EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW,
                TerminateProcess, UpdateProcThreadAttribute,
            },
        },
    };

    use super::*;
    use crate::IDENTITY_DIGEST_BYTES;

    const CHILD_TEST_NAME: &str = "windows::tests::native_observation_child_probe";
    const CHILD_MODE_ENV: &str = "GUS_WINDOWS_OBSERVER_CHILD_MODE";
    const CHILD_MARKER_ENV: &str = "GUS_WINDOWS_OBSERVER_CHILD_MARKER";
    const CONPTY_COORDINATOR_TEST_NAME: &str = "windows::tests::native_conpty_coordinator_probe";
    const CONPTY_DESCENDANT_TEST_NAME: &str = "windows::tests::native_conpty_descendant_probe";
    const CONPTY_ID_PREFIX: &str = "GUS_CONPTY_ID:";
    const MAX_CONPTY_OUTPUT_BYTES: u64 = 1024 * 1024;
    const CONPTY_CHILD_TIMEOUT_MS: u32 = 30_000;

    #[test]
    fn current_process_observation_uses_native_windows_evidence() {
        // A headless service runner can expose console membership without a
        // verifiable console window. That state must remain fail-closed; the
        // managed fixtures below cover successful classic and pseudo-console
        // observations independently of the runner's ambient host.
        let observation = match observe_current() {
            Ok(observation) => observation,
            Err(ObservationError::TerminalBindingMismatch) => {
                assert!(
                    console_processes()
                        .expect("inspect ambient console membership")
                        .is_some(),
                    "detached ambient process must be observable"
                );
                assert_eq!(
                    observe_console().err(),
                    Some(ObservationError::TerminalBindingMismatch),
                    "only an unverifiable ambient console window may fail closed"
                );
                return;
            }
            Err(error) => panic!("observe current Windows process: {error:?}"),
        };
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

    #[test]
    fn native_observation_distinguishes_detached_and_replaced_consoles() {
        run_native_child("detached", b"detached");
        run_native_child("switch-console", b"switched");
        let first = run_conpty_child();
        let replacement = run_conpty_child();
        assert_ne!(first, replacement, "replacement ConPTY reused identity");
    }

    #[test]
    #[ignore = "internal child process for native Windows session smoke tests"]
    fn native_observation_child_probe() {
        let Ok(mode) = env::var(CHILD_MODE_ENV) else {
            return;
        };
        let marker = env::var_os(CHILD_MARKER_ENV)
            .map(PathBuf::from)
            .expect("child marker path");
        match mode.as_str() {
            "detached" => {
                let observation = observe_current().expect("observe detached child");
                assert_eq!(observation.terminal_session(), None);
                fs::write(marker, b"detached").expect("write detached marker");
            }
            "report-console" => {
                let terminal = observe_current()
                    .expect("observe inherited console child")
                    .terminal_session()
                    .expect("inherited console identity")
                    .terminal();
                fs::write(marker, terminal.digest).expect("write console identity marker");
            }
            "switch-console" => exercise_console_switch(&marker),
            other => panic!("unexpected native child mode: {other}"),
        }
    }

    #[test]
    #[ignore = "internal child process hosted by the ConPTY smoke test"]
    fn native_conpty_coordinator_probe() {
        let terminal = observe_current()
            .expect("observe ConPTY coordinator")
            .terminal_session()
            .expect("ConPTY coordinator identity")
            .terminal();
        let output = Command::new(env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(CONPTY_DESCENDANT_TEST_NAME)
            .arg("--ignored")
            .arg("--nocapture")
            .output()
            .expect("launch inherited ConPTY descendant");
        assert!(
            output.status.success(),
            "ConPTY descendant failed with {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(parse_conpty_identity(&output.stdout), terminal.digest);
        emit_conpty_identity(terminal.digest);
    }

    #[test]
    #[ignore = "internal descendant process hosted by the ConPTY smoke test"]
    fn native_conpty_descendant_probe() {
        let terminal = observe_current()
            .expect("observe inherited ConPTY descendant")
            .terminal_session()
            .expect("inherited ConPTY identity")
            .terminal();
        emit_conpty_identity(terminal.digest);
    }

    fn exercise_console_switch(marker: &Path) {
        // SAFETY: This helper is launched without a console and owns every
        // console allocation/free operation performed here.
        assert_ne!(unsafe { AllocConsole() }, 0, "allocate first console");
        let first = observe_current()
            .expect("observe first console")
            .terminal_session()
            .expect("first console identity");
        let same = observe_current()
            .expect("re-observe first console")
            .terminal_session()
            .expect("stable first console identity");
        assert_eq!(first, same);

        let inherited_marker = marker.with_extension("inherited");
        let inherited = run_exact_child("report-console", &inherited_marker, 0);
        assert_child_success(&inherited, &inherited_marker, "inherited console child");
        assert_eq!(
            fs::read(&inherited_marker).expect("read inherited identity"),
            first.terminal().digest
        );

        // SAFETY: This process is attached to the first allocated console.
        assert_ne!(unsafe { FreeConsole() }, 0, "free first console");
        // SAFETY: The prior call detached this process, so it may allocate a
        // replacement console.
        assert_ne!(unsafe { AllocConsole() }, 0, "allocate second console");
        let second = observe_current()
            .expect("observe replacement console")
            .terminal_session()
            .expect("replacement console identity");
        assert_ne!(first.terminal(), second.terminal());
        // SAFETY: This process owns and remains attached to the replacement.
        assert_ne!(unsafe { FreeConsole() }, 0, "free replacement console");
        fs::write(marker, b"switched").expect("write switch marker");
    }

    fn run_native_child(mode: &str, expected_marker: &[u8]) {
        let directory = tempdir().expect("create native child temp directory");
        let marker = directory.path().join("completed");
        // `DETACHED_PROCESS` has the precise property this fixture needs: the
        // child does not inherit the runner's console and may later create one
        // with `AllocConsole`. `CREATE_NO_WINDOW` only suppresses a console
        // window and proved ambiguous under a service-hosted CI runner.
        let output = run_exact_child(mode, &marker, DETACHED_PROCESS);
        assert_child_success(&output, &marker, mode);
        assert_eq!(
            fs::read(&marker).expect("read native child marker"),
            expected_marker
        );
    }

    fn run_exact_child(mode: &str, marker: &Path, creation_flags: u32) -> Output {
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg(CHILD_TEST_NAME)
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_MODE_ENV, mode)
            .env(CHILD_MARKER_ENV, marker)
            .creation_flags(creation_flags);
        command.output().expect("launch native observer child")
    }

    fn assert_child_success(output: &Output, marker: &Path, context: &str) {
        assert!(
            output.status.success(),
            "{context} failed with {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(marker.is_file(), "{context} did not create its marker");
    }

    fn emit_conpty_identity(identity: [u8; IDENTITY_DIGEST_BYTES]) {
        let mut encoded = String::with_capacity(IDENTITY_DIGEST_BYTES * 2);
        for byte in identity {
            write!(&mut encoded, "{byte:02x}").expect("write identity hex");
        }
        println!("{CONPTY_ID_PREFIX}{encoded}");
    }

    fn parse_conpty_identity(output: &[u8]) -> [u8; IDENTITY_DIGEST_BYTES] {
        let prefix = CONPTY_ID_PREFIX.as_bytes();
        let start = output
            .windows(prefix.len())
            .position(|window| window == prefix)
            .map_or_else(
                || {
                    panic!(
                        "ConPTY identity marker missing from: {}",
                        String::from_utf8_lossy(output)
                    )
                },
                |position| position + prefix.len(),
            );
        let encoded_len = IDENTITY_DIGEST_BYTES * 2;
        let encoded = output
            .get(start..start + encoded_len)
            .expect("complete ConPTY identity marker");
        let mut identity = [0_u8; IDENTITY_DIGEST_BYTES];
        for (index, pair) in encoded.chunks_exact(2).enumerate() {
            identity[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        identity
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid ConPTY identity hex"),
        }
    }

    struct OwnedPseudoConsole(HPCON);

    impl Drop for OwnedPseudoConsole {
        fn drop(&mut self) {
            // SAFETY: The handle came from one successful
            // `CreatePseudoConsole` call and is closed exactly once.
            unsafe {
                ClosePseudoConsole(self.0);
            }
        }
    }

    struct OwnedAttributeList {
        _storage: Vec<usize>,
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    }

    impl OwnedAttributeList {
        fn for_pseudoconsole(pseudoconsole: HPCON) -> Self {
            let mut required = 0_usize;
            // SAFETY: A null list is the documented size-query form.
            unsafe {
                InitializeProcThreadAttributeList(
                    ptr::null_mut(),
                    1,
                    0,
                    ptr::addr_of_mut!(required),
                );
            }
            assert_ne!(required, 0, "attribute list size query");
            let word_count = required.div_ceil(size_of::<usize>());
            let mut storage = vec![0_usize; word_count];
            let pointer = storage.as_mut_ptr().cast::<c_void>();
            // SAFETY: `storage` is aligned and writable for at least the byte
            // count returned by the size query.
            assert_ne!(
                unsafe {
                    InitializeProcThreadAttributeList(pointer, 1, 0, ptr::addr_of_mut!(required))
                },
                0,
                "initialize process attribute list: {:?}",
                io::Error::last_os_error()
            );
            // The ConPTY API contract passes the HPCON value itself as the
            // attribute payload, rather than a pointer to local storage.
            // SAFETY: The initialized list and live pseudoconsole handle meet
            // the attribute contract; optional output pointers are null.
            assert_ne!(
                unsafe {
                    UpdateProcThreadAttribute(
                        pointer,
                        0,
                        usize::try_from(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE)
                            .expect("pseudoconsole attribute fits usize"),
                        pseudoconsole as *const c_void,
                        size_of::<HPCON>(),
                        ptr::null_mut(),
                        ptr::null(),
                    )
                },
                0,
                "set pseudoconsole process attribute: {:?}",
                io::Error::last_os_error()
            );
            Self {
                _storage: storage,
                pointer,
            }
        }
    }

    impl Drop for OwnedAttributeList {
        fn drop(&mut self) {
            // SAFETY: The pointer is an initialized attribute list and its
            // backing storage remains alive through this call.
            unsafe {
                DeleteProcThreadAttributeList(self.pointer);
            }
        }
    }

    fn run_conpty_child() -> [u8; IDENTITY_DIGEST_BYTES] {
        let (input_read, input_write) = create_anonymous_pipe();
        let (output_read, output_write) = create_anonymous_pipe();
        let mut pseudoconsole_raw = 0_isize;
        // SAFETY: All pipe handles are synchronous, the dimensions are valid,
        // and the output handle pointer is writable.
        let result = unsafe {
            CreatePseudoConsole(
                COORD { X: 120, Y: 40 },
                input_read.raw(),
                output_write.raw(),
                0,
                ptr::addr_of_mut!(pseudoconsole_raw),
            )
        };
        assert!(result >= 0, "create pseudoconsole HRESULT {result:#x}");
        assert_ne!(pseudoconsole_raw, 0, "nonzero pseudoconsole handle");
        let pseudoconsole = OwnedPseudoConsole(pseudoconsole_raw);
        let (process, reader) = launch_conpty_child(pseudoconsole.0, output_read);
        drop(input_read);
        drop(output_write);

        // SAFETY: `process` is a live process handle and the timeout is
        // finite, preventing a broken fixture from hanging the CI job.
        match unsafe { WaitForSingleObject(process.raw(), CONPTY_CHILD_TIMEOUT_MS) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                // SAFETY: This is the dedicated test child created above.
                unsafe {
                    TerminateProcess(process.raw(), 1);
                    WaitForSingleObject(process.raw(), CONPTY_CHILD_TIMEOUT_MS);
                }
                panic!("ConPTY child timed out");
            }
            result => panic!("waiting for ConPTY child failed: {result:#x}"),
        }
        let mut exit_code = u32::MAX;
        // SAFETY: `exit_code` is writable and the process has terminated.
        assert_ne!(
            unsafe { GetExitCodeProcess(process.raw(), ptr::addr_of_mut!(exit_code)) },
            0,
            "read ConPTY child exit code"
        );
        drop(input_write);
        drop(pseudoconsole);
        let output = reader.join().expect("join ConPTY output reader");
        assert!(
            output.len() <= usize::try_from(MAX_CONPTY_OUTPUT_BYTES).expect("output bound"),
            "ConPTY child exceeded output bound"
        );
        assert_eq!(
            exit_code,
            0,
            "ConPTY child failed:\n{}",
            String::from_utf8_lossy(&output)
        );
        parse_conpty_identity(&output)
    }

    fn launch_conpty_child(
        pseudoconsole: HPCON,
        output_read: OwnedHandle,
    ) -> (OwnedHandle, thread::JoinHandle<Vec<u8>>) {
        let attributes = OwnedAttributeList::for_pseudoconsole(pseudoconsole);

        let executable = env::current_exe().expect("current test executable");
        let mut application: Vec<u16> = executable.as_os_str().encode_wide().collect();
        application.push(0);
        let mut command_line = Vec::new();
        command_line.push(u16::from(b'"'));
        command_line.extend(executable.as_os_str().encode_wide());
        command_line.push(u16::from(b'"'));
        command_line.extend(
            format!(" --exact {CONPTY_COORDINATOR_TEST_NAME} --ignored --nocapture").encode_utf16(),
        );
        command_line.push(0);
        let startup = STARTUPINFOEXW {
            StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
                cb: u32::try_from(size_of::<STARTUPINFOEXW>()).expect("startup info size fits u32"),
                ..Default::default()
            },
            lpAttributeList: attributes.pointer,
        };
        let mut process_info = PROCESS_INFORMATION::default();

        // SAFETY: Ownership of this valid pipe handle is transferred from
        // `OwnedHandle` to `File` exactly once.
        let output_file = unsafe { File::from_raw_handle(output_read.into_raw()) };
        let reader = thread::spawn(move || {
            let mut output = Vec::new();
            output_file
                .take(MAX_CONPTY_OUTPUT_BYTES + 1)
                .read_to_end(&mut output)
                .expect("read ConPTY output");
            output
        });

        // SAFETY: The mutable command line, initialized extended startup
        // information, application path, and process output are all valid for
        // the duration of this call. No unrelated handles are inherited.
        assert_ne!(
            unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    EXTENDED_STARTUPINFO_PRESENT,
                    ptr::null(),
                    ptr::null(),
                    ptr::addr_of!(startup.StartupInfo),
                    ptr::addr_of_mut!(process_info),
                )
            },
            0,
            "launch ConPTY child: {:?}",
            io::Error::last_os_error()
        );
        let process =
            OwnedHandle::regular(process_info.hProcess, ObservationResource::CallerProcess)
                .expect("own ConPTY child process");
        let thread_handle =
            OwnedHandle::regular(process_info.hThread, ObservationResource::CallerProcess)
                .expect("own ConPTY child thread");
        drop(thread_handle);
        drop(attributes);
        (process, reader)
    }

    fn create_anonymous_pipe() -> (OwnedHandle, OwnedHandle) {
        let mut read = ptr::null_mut();
        let mut write = ptr::null_mut();
        // SAFETY: Both handle outputs are writable. Null security attributes
        // create non-inheritable synchronous handles, as required by ConPTY.
        assert_ne!(
            unsafe {
                CreatePipe(
                    ptr::addr_of_mut!(read),
                    ptr::addr_of_mut!(write),
                    ptr::null(),
                    0,
                )
            },
            0,
            "create ConPTY pipe: {:?}",
            io::Error::last_os_error()
        );
        (
            OwnedHandle::regular(read, ObservationResource::TerminalSession)
                .expect("own ConPTY read pipe"),
            OwnedHandle::regular(write, ObservationResource::TerminalSession)
                .expect("own ConPTY write pipe"),
        )
    }
}
