use std::{
    collections::{HashSet, VecDeque},
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, GetVolumeInformationByHandleW,
    },
    System::{
        IO::DeviceIoControl,
        SystemServices::{
            FILE_PERSISTENT_ACLS, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
        },
    },
};

use super::{
    DiscoveryChainBinding, ExpectedFileKind, NativeFileKey, NativeFileSnapshot,
    RealGitArtifactError, SafelyOpenedPath, final_windows_path, io_error,
    reopen_windows_read_lease, require_local_windows_drive,
};

const FSCTL_GET_REPARSE_POINT: u32 = 589_992;
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
const MAX_REPARSE_HOPS: usize = 32;
const MAX_EXPANDED_COMPONENTS: usize = 256;
const MAX_REPARSE_TARGET_BYTES: usize = 16 * 1024;
const MAX_TOTAL_REPARSE_TARGET_BYTES: usize = 32 * 1024;
const MAX_RETAINED_HANDLES: usize = 64;
const MIN_RETAINED_HANDLES: usize = 16;
const PROCESS_RETAINED_HANDLE_BUDGET: usize = 4096;
const SYMLINK_FLAG_RELATIVE: u32 = 1;

static RESERVED_RESOLVER_HANDLES: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
static RESOLVER_TEST_HOOKS: std::sync::Mutex<Vec<ResolverTestHook>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolverTestStage {
    EntryOpened,
    ReparseRead,
    BeforeReplay,
    BeforeInspection,
    AfterInspection,
}

#[cfg(test)]
type ResolverTestCallback = dyn FnMut(ResolverTestStage, &OsStr) + Send;

#[cfg(test)]
struct ResolverTestHook {
    owner: std::thread::ThreadId,
    callback: Box<ResolverTestCallback>,
}

#[cfg(test)]
struct ResolverTestHookGuard;

#[cfg(test)]
impl Drop for ResolverTestHookGuard {
    fn drop(&mut self) {
        let owner = std::thread::current().id();
        RESOLVER_TEST_HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|installed| installed.owner != owner);
    }
}

#[cfg(test)]
fn install_test_hook(
    callback: impl FnMut(ResolverTestStage, &OsStr) + Send + 'static,
) -> ResolverTestHookGuard {
    let owner = std::thread::current().id();
    let mut hooks = RESOLVER_TEST_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        hooks.iter().all(|installed| installed.owner != owner),
        "only one Windows resolver test hook may be installed per thread"
    );
    hooks.push(ResolverTestHook {
        owner,
        callback: Box::new(callback),
    });
    ResolverTestHookGuard
}

#[cfg(test)]
pub(super) fn run_test_barrier(stage: ResolverTestStage, path: &OsStr) {
    let owner = std::thread::current().id();
    let mut hooks = RESOLVER_TEST_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(installed) = hooks.iter_mut().find(|installed| installed.owner == owner) {
        (installed.callback)(stage, path);
    }
}

pub(super) struct ResolvedWindowsPath {
    pub(super) opened: SafelyOpenedPath,
    pub(super) final_snapshot: NativeFileSnapshot,
    pub(super) chain: WindowsResolutionLeaseSet,
}

pub(super) struct WindowsResolutionLeaseSet {
    original_path: PathBuf,
    original_wide: Vec<u16>,
    bindings: Vec<WindowsNameBinding>,
    final_snapshot: NativeFileSnapshot,
    binding: DiscoveryChainBinding,
    _reservation: HandleReservation,
}

struct WindowsNameBinding {
    logical_path: PathBuf,
    name: OsString,
    entry: File,
    snapshot: NativeFileSnapshot,
    kind: WindowsBindingKind,
}

enum WindowsBindingKind {
    Root,
    Directory,
    Reparse {
        tag: u32,
        data: Vec<u8>,
        target: Vec<u16>,
        relative: bool,
    },
    Terminal,
}

struct HandleReservation {
    handles: usize,
}

impl HandleReservation {
    fn new() -> Result<Self, RealGitArtifactError> {
        let mut reserved = RESERVED_RESOLVER_HANDLES.load(Ordering::Acquire);
        loop {
            let next = reserved
                .checked_add(MIN_RETAINED_HANDLES)
                .ok_or(RealGitArtifactError::PathLimitExceeded)?;
            if next > PROCESS_RETAINED_HANDLE_BUDGET {
                return Err(RealGitArtifactError::PathLimitExceeded);
            }
            match RESERVED_RESOLVER_HANDLES.compare_exchange_weak(
                reserved,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        handles: MIN_RETAINED_HANDLES,
                    });
                }
                Err(current) => reserved = current,
            }
        }
    }

    fn ensure(&mut self, required: usize) -> Result<(), RealGitArtifactError> {
        if required <= self.handles {
            return Ok(());
        }
        let target = required
            .max(self.handles.saturating_mul(2))
            .min(MAX_RETAINED_HANDLES);
        if target < required {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let additional = target - self.handles;
        let mut reserved = RESERVED_RESOLVER_HANDLES.load(Ordering::Acquire);
        loop {
            let next = reserved
                .checked_add(additional)
                .ok_or(RealGitArtifactError::PathLimitExceeded)?;
            if next > PROCESS_RETAINED_HANDLE_BUDGET {
                return Err(RealGitArtifactError::PathLimitExceeded);
            }
            match RESERVED_RESOLVER_HANDLES.compare_exchange_weak(
                reserved,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.handles = target;
                    return Ok(());
                }
                Err(current) => reserved = current,
            }
        }
    }
}

impl Drop for HandleReservation {
    fn drop(&mut self) {
        RESERVED_RESOLVER_HANDLES.fetch_sub(self.handles, Ordering::AcqRel);
    }
}

struct ParsedAbsolutePath {
    drive: u16,
    components: Vec<OsString>,
    original_wide: Vec<u16>,
    normalized: PathBuf,
    trailing_separator: bool,
}

struct ParsedReparseTarget {
    components: Vec<PathToken>,
    absolute: bool,
    drive: Option<u16>,
}

enum PathToken {
    Parent,
    Name(OsString),
}

#[cfg_attr(test, derive(Debug))]
struct ReparseData {
    tag: u32,
    raw: Vec<u8>,
    target: Vec<u16>,
    relative: bool,
}

struct ResolutionBuilder {
    parsed: ParsedAbsolutePath,
    root_snapshot: NativeFileSnapshot,
    resolved_names: Vec<OsString>,
    pending_names: VecDeque<OsString>,
    ancestors: Vec<NativeFileSnapshot>,
    bindings: Vec<WindowsNameBinding>,
    visited: HashSet<[u8; 32]>,
    reparse_hops: usize,
    expanded_components: usize,
    total_target_bytes: usize,
    reservation: HandleReservation,
}

pub(super) fn resolve(path: &Path) -> Result<ResolvedWindowsPath, RealGitArtifactError> {
    let parsed = parse_absolute_path(path)?;
    if parsed.trailing_separator {
        return Err(RealGitArtifactError::UnsafePath);
    }
    require_local_windows_drive(
        u8::try_from(parsed.drive).map_err(|_| RealGitArtifactError::UnsafePath)?,
    )?;
    let mut reservation = HandleReservation::new()?;
    let root_path = path_from_components(parsed.drive, &[])?;
    let root = open_entry(&root_path)?;
    let root_snapshot = NativeFileSnapshot::capture(&root)?;
    ExpectedFileKind::Directory.require(root_snapshot)?;
    require_pinned_ntfs_root(&root)?;
    reservation.ensure(1)?;

    let mut builder = ResolutionBuilder {
        pending_names: parsed.components.iter().cloned().collect(),
        ancestors: vec![root_snapshot],
        bindings: vec![WindowsNameBinding {
            logical_path: root_path,
            name: OsString::from("\\"),
            entry: root,
            snapshot: root_snapshot,
            kind: WindowsBindingKind::Root,
        }],
        parsed,
        root_snapshot,
        resolved_names: Vec::new(),
        visited: HashSet::new(),
        reparse_hops: 0,
        expanded_components: 0,
        total_target_bytes: 0,
        reservation,
    };
    builder.finish()
}

impl ResolutionBuilder {
    fn finish(&mut self) -> Result<ResolvedWindowsPath, RealGitArtifactError> {
        while let Some(name) = self.pending_names.pop_front() {
            self.expanded_components = self
                .expanded_components
                .checked_add(1)
                .ok_or(RealGitArtifactError::PathLimitExceeded)?;
            if self.expanded_components > MAX_EXPANDED_COMPONENTS {
                return Err(RealGitArtifactError::PathLimitExceeded);
            }
            self.reservation.ensure(self.bindings.len() + 2)?;
            let mut candidate_names = self.resolved_names.clone();
            candidate_names.push(name.clone());
            let logical_path = path_from_components(self.parsed.drive, &candidate_names)?;
            let opened = open_entry(&logical_path)?;
            #[cfg(test)]
            run_test_barrier(ResolverTestStage::EntryOpened, logical_path.as_os_str());
            let snapshot = NativeFileSnapshot::capture(&opened)?;
            if snapshot.volume_serial != self.root_snapshot.volume_serial {
                return Err(RealGitArtifactError::RemotePathUnsupported);
            }
            if snapshot.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                self.resolve_reparse(name, logical_path, opened, snapshot)?;
                continue;
            }
            if snapshot.reparse_tag != 0 {
                return Err(RealGitArtifactError::InvalidReparsePoint);
            }
            if self.pending_names.is_empty() {
                return self.finish_terminal(name, logical_path, opened, snapshot);
            }
            ExpectedFileKind::Directory.require(snapshot)?;
            self.ancestors.push(snapshot);
            self.bindings.push(WindowsNameBinding {
                logical_path,
                name: name.clone(),
                entry: opened,
                snapshot,
                kind: WindowsBindingKind::Directory,
            });
            self.resolved_names.push(name);
        }
        Err(RealGitArtifactError::NotExecutable)
    }

    fn resolve_reparse(
        &mut self,
        name: OsString,
        logical_path: PathBuf,
        opened: File,
        snapshot: NativeFileSnapshot,
    ) -> Result<(), RealGitArtifactError> {
        self.reparse_hops = self
            .reparse_hops
            .checked_add(1)
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if self.reparse_hops > MAX_REPARSE_HOPS {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let reparse = read_reparse_data(&opened, snapshot.reparse_tag)?;
        #[cfg(test)]
        run_test_barrier(ResolverTestStage::ReparseRead, logical_path.as_os_str());
        self.total_target_bytes = self
            .total_target_bytes
            .checked_add(reparse.target.len().saturating_mul(size_of::<u16>()))
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if reparse.target.len().saturating_mul(size_of::<u16>()) > MAX_REPARSE_TARGET_BYTES
            || self.total_target_bytes > MAX_TOTAL_REPARSE_TARGET_BYTES
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let target = parse_reparse_target(&reparse)?;
        let state = resolution_state_digest(
            snapshot.file_key(),
            &self.resolved_names,
            &self.pending_names,
            &reparse.target,
        );
        if !self.visited.insert(state) {
            return Err(RealGitArtifactError::ReparsePointLoop);
        }
        self.bindings.push(WindowsNameBinding {
            logical_path,
            name,
            entry: opened,
            snapshot,
            kind: WindowsBindingKind::Reparse {
                tag: reparse.tag,
                data: reparse.raw,
                target: reparse.target,
                relative: reparse.relative,
            },
        });
        self.apply_target(target)
    }

    fn apply_target(&mut self, target: ParsedReparseTarget) -> Result<(), RealGitArtifactError> {
        if target.absolute {
            if target.drive != Some(self.parsed.drive) {
                return Err(RealGitArtifactError::RemotePathUnsupported);
            }
            self.resolved_names.clear();
        }
        let mut target_names = Vec::new();
        for token in target.components {
            match token {
                PathToken::Parent => {
                    if target_names.pop().is_none() {
                        self.resolved_names
                            .pop()
                            .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
                    }
                }
                PathToken::Name(name) => target_names.push(name),
            }
        }
        for name in target_names.into_iter().rev() {
            self.pending_names.push_front(name);
        }
        Ok(())
    }

    fn finish_terminal(
        &mut self,
        name: OsString,
        logical_path: PathBuf,
        opened: File,
        snapshot: NativeFileSnapshot,
    ) -> Result<ResolvedWindowsPath, RealGitArtifactError> {
        ExpectedFileKind::RegularFile.require(snapshot)?;
        let candidate_lease = reopen_windows_read_lease(&opened)?;
        if NativeFileSnapshot::capture(&candidate_lease)? != snapshot {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        self.bindings.push(WindowsNameBinding {
            logical_path,
            name: name.clone(),
            entry: opened,
            snapshot,
            kind: WindowsBindingKind::Terminal,
        });
        self.resolved_names.push(name);
        let normalized_path = final_windows_path(&candidate_lease)?;
        let binding = calculate_binding(
            &self.parsed.original_wide,
            self.parsed.drive,
            &self.bindings,
            snapshot,
            self.reservation.handles,
        );
        let reservation =
            std::mem::replace(&mut self.reservation, HandleReservation { handles: 0 });
        Ok(ResolvedWindowsPath {
            opened: SafelyOpenedPath {
                normalized_path,
                lease: candidate_lease,
                ancestors: std::mem::take(&mut self.ancestors),
            },
            final_snapshot: snapshot,
            chain: WindowsResolutionLeaseSet {
                original_path: self.parsed.normalized.clone(),
                original_wide: self.parsed.original_wide.clone(),
                bindings: std::mem::take(&mut self.bindings),
                final_snapshot: snapshot,
                binding,
                _reservation: reservation,
            },
        })
    }
}

impl WindowsResolutionLeaseSet {
    pub(super) const fn binding(&self) -> DiscoveryChainBinding {
        self.binding
    }

    pub(super) fn revalidate(
        &self,
        expected_final: &NativeFileSnapshot,
    ) -> Result<(), RealGitArtifactError> {
        if !expected_final.same_discovery_artifact(&self.final_snapshot) {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.validate_retained()?;
        #[cfg(test)]
        run_test_barrier(
            ResolverTestStage::BeforeReplay,
            self.original_path.as_os_str(),
        );
        let replay =
            resolve(&self.original_path).map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
        if replay.chain.original_wide != self.original_wide
            || replay.chain.binding != self.binding
            || !replay
                .final_snapshot
                .same_discovery_artifact(&self.final_snapshot)
        {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.validate_retained()
    }

    fn validate_retained(&self) -> Result<(), RealGitArtifactError> {
        for binding in &self.bindings {
            let current = NativeFileSnapshot::capture(&binding.entry)
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            if !current.same_discovery_artifact(&binding.snapshot) {
                return Err(RealGitArtifactError::DiscoveryChainStale);
            }
            match &binding.kind {
                WindowsBindingKind::Root => {
                    ExpectedFileKind::Directory
                        .require(current)
                        .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
                    require_pinned_ntfs_root(&binding.entry)
                        .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
                }
                WindowsBindingKind::Directory => {
                    ExpectedFileKind::Directory
                        .require(current)
                        .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
                }
                WindowsBindingKind::Reparse {
                    tag,
                    data,
                    target,
                    relative,
                } => {
                    if current.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                        || current.reparse_tag != *tag
                    {
                        return Err(RealGitArtifactError::DiscoveryChainStale);
                    }
                    let observed = read_reparse_data(&binding.entry, *tag)
                        .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
                    if observed.raw != *data
                        || observed.target != *target
                        || observed.relative != *relative
                    {
                        return Err(RealGitArtifactError::DiscoveryChainStale);
                    }
                }
                WindowsBindingKind::Terminal => {
                    ExpectedFileKind::RegularFile
                        .require(current)
                        .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
                }
            }
        }
        Ok(())
    }
}

fn parse_absolute_path(path: &Path) -> Result<ParsedAbsolutePath, RealGitArtifactError> {
    let original_wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if original_wide.len() < 3 {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    if is_separator(original_wide[0]) && is_separator(original_wide[1]) {
        return Err(RealGitArtifactError::RemotePathUnsupported);
    }
    let drive = normalize_drive(original_wide[0]).ok_or(RealGitArtifactError::PathNotAbsolute)?;
    if original_wide[1] != u16::from(b':') || !is_separator(original_wide[2]) {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    let trailing_separator =
        original_wide.len() > 3 && original_wide.last().copied().is_some_and(is_separator);
    let components = parse_component_units(&original_wide[3..], true)?;
    if components.len() > super::MAX_PATH_COMPONENTS
        || original_wide.len() > super::MAX_PATH_BYTES / size_of::<u16>()
    {
        return Err(RealGitArtifactError::PathLimitExceeded);
    }
    let normalized = PathBuf::from(OsString::from_wide(&original_wide));
    Ok(ParsedAbsolutePath {
        drive,
        components: normalize_tokens(&[], &components)?,
        original_wide,
        normalized,
        trailing_separator,
    })
}

fn parse_component_units(
    units: &[u16],
    absolute: bool,
) -> Result<Vec<PathToken>, RealGitArtifactError> {
    if units.contains(&0) {
        return Err(if absolute {
            RealGitArtifactError::UnsafePath
        } else {
            RealGitArtifactError::InvalidReparsePoint
        });
    }
    let mut tokens = Vec::new();
    let mut start = 0;
    for end in 0..=units.len() {
        if end != units.len() && !is_separator(units[end]) {
            continue;
        }
        if end == start {
            if end != units.len() {
                return Err(if absolute {
                    RealGitArtifactError::UnsafePath
                } else {
                    RealGitArtifactError::InvalidReparsePoint
                });
            }
            break;
        }
        let component = &units[start..end];
        if component == [u16::from(b'.')] {
            // Dot is normalized without losing any external string bytes in
            // the separately retained original path binding.
        } else if component == [u16::from(b'.'), u16::from(b'.')] {
            tokens.push(PathToken::Parent);
        } else {
            if unsafe_windows_component(component) {
                return Err(if absolute {
                    RealGitArtifactError::UnsafePath
                } else {
                    RealGitArtifactError::InvalidReparsePoint
                });
            }
            tokens.push(PathToken::Name(OsString::from_wide(component)));
        }
        start = end + 1;
    }
    Ok(tokens)
}

fn normalize_tokens(
    base: &[OsString],
    tokens: &[PathToken],
) -> Result<Vec<OsString>, RealGitArtifactError> {
    let mut names = base.to_vec();
    for token in tokens {
        match token {
            PathToken::Parent => {
                names.pop().ok_or(RealGitArtifactError::UnsafePath)?;
            }
            PathToken::Name(name) => names.push(name.clone()),
        }
    }
    Ok(names)
}

fn parse_reparse_target(
    reparse: &ReparseData,
) -> Result<ParsedReparseTarget, RealGitArtifactError> {
    if reparse.relative {
        if reparse.tag != IO_REPARSE_TAG_SYMLINK
            || reparse.target.first().copied().is_some_and(is_separator)
            || has_drive_prefix(&reparse.target)
        {
            return Err(RealGitArtifactError::InvalidReparsePoint);
        }
        return Ok(ParsedReparseTarget {
            components: parse_component_units(&reparse.target, false)?,
            absolute: false,
            drive: None,
        });
    }
    let target = strip_safe_nt_dos_prefix(&reparse.target)
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    if target.len() < 3 {
        return Err(RealGitArtifactError::InvalidReparsePoint);
    }
    let drive = normalize_drive(target[0]).ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    if target[1] != u16::from(b':') || !is_separator(target[2]) {
        return Err(RealGitArtifactError::InvalidReparsePoint);
    }
    Ok(ParsedReparseTarget {
        components: parse_component_units(&target[3..], false)?,
        absolute: true,
        drive: Some(drive),
    })
}

fn read_reparse_data(file: &File, expected_tag: u32) -> Result<ReparseData, RealGitArtifactError> {
    let mut buffer = vec![0_u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    let mut returned = 0_u32;
    // SAFETY: the file handle is live, there is no input buffer, the output
    // vector is writable for its complete capacity, and `returned` is writable.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("reparse buffer length fits u32"),
            &raw mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io_error(io::Error::last_os_error()));
    }
    let returned =
        usize::try_from(returned).map_err(|_| RealGitArtifactError::InvalidReparsePoint)?;
    if returned < 8 || returned > buffer.len() {
        return Err(RealGitArtifactError::InvalidReparsePoint);
    }
    buffer.truncate(returned);
    let tag = read_u32(&buffer, 0)?;
    let data_length = usize::from(read_u16(&buffer, 4)?);
    if tag != expected_tag || data_length.checked_add(8) != Some(returned) {
        return Err(RealGitArtifactError::InvalidReparsePoint);
    }
    let (path_start, flags) = match tag {
        IO_REPARSE_TAG_SYMLINK => {
            if data_length < 12 || returned < 20 {
                return Err(RealGitArtifactError::InvalidReparsePoint);
            }
            let flags = read_u32(&buffer, 16)?;
            if flags & !SYMLINK_FLAG_RELATIVE != 0 {
                return Err(RealGitArtifactError::InvalidReparsePoint);
            }
            (20, flags)
        }
        IO_REPARSE_TAG_MOUNT_POINT => {
            if data_length < 8 || returned < 16 {
                return Err(RealGitArtifactError::InvalidReparsePoint);
            }
            (16, 0)
        }
        _ => return Err(RealGitArtifactError::ReparsePointUnsupported),
    };
    let substitute_offset = usize::from(read_u16(&buffer, 8)?);
    let substitute_length = usize::from(read_u16(&buffer, 10)?);
    let print_offset = usize::from(read_u16(&buffer, 12)?);
    let print_length = usize::from(read_u16(&buffer, 14)?);
    validate_reparse_string(&buffer, path_start, print_offset, print_length, true)?;
    let target = validate_reparse_string(
        &buffer,
        path_start,
        substitute_offset,
        substitute_length,
        false,
    )?;
    Ok(ReparseData {
        tag,
        raw: buffer,
        target,
        relative: flags & SYMLINK_FLAG_RELATIVE != 0,
    })
}

fn validate_reparse_string(
    buffer: &[u8],
    path_start: usize,
    offset: usize,
    length: usize,
    allow_empty: bool,
) -> Result<Vec<u16>, RealGitArtifactError> {
    if offset % 2 != 0 || length % 2 != 0 || (!allow_empty && length == 0) {
        return Err(RealGitArtifactError::InvalidReparsePoint);
    }
    let start = path_start
        .checked_add(offset)
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    let end = start
        .checked_add(length)
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    let bytes = buffer
        .get(start..end)
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return Err(RealGitArtifactError::InvalidReparsePoint);
        }
        units.push(unit);
    }
    Ok(units)
}

fn open_entry(path: &Path) -> Result<File, RealGitArtifactError> {
    let mut options = OpenOptions::new();
    let file = options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(io_error)?;
    // SAFETY: the handle is live and the operation only clears inheritance.
    if unsafe { SetHandleInformation(file.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    Ok(file)
}

fn require_pinned_ntfs_root(file: &File) -> Result<(), RealGitArtifactError> {
    let final_path = final_windows_path(file)?;
    if !is_volume_guid_root(final_path.as_os_str()) {
        return Err(RealGitArtifactError::RemotePathUnsupported);
    }
    let mut volume_serial = 0_u32;
    let mut maximum_component_length = 0_u32;
    let mut flags = 0_u32;
    let mut filesystem = [0_u16; 16];
    // SAFETY: the root handle is live and every scalar/buffer output is
    // writable for the advertised size. The optional volume label is omitted.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            &raw mut volume_serial,
            &raw mut maximum_component_length,
            &raw mut flags,
            filesystem.as_mut_ptr(),
            u32::try_from(filesystem.len()).expect("filesystem buffer size"),
        )
    } == 0
    {
        return Err(io_error(io::Error::last_os_error()));
    }
    let filesystem_end = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(RealGitArtifactError::UnsafePath)?;
    let filesystem = &filesystem[..filesystem_end];
    if flags & FILE_PERSISTENT_ACLS == 0 || !wide_eq_ascii_case_insensitive(filesystem, b"NTFS") {
        return Err(RealGitArtifactError::WindowsFilesystemUnsupported);
    }
    Ok(())
}

fn path_from_components(
    drive: u16,
    components: &[OsString],
) -> Result<PathBuf, RealGitArtifactError> {
    let mut units = vec![drive, u16::from(b':'), u16::from(b'\\')];
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            units.push(u16::from(b'\\'));
        }
        units.extend(component.encode_wide());
        if units.len() > super::MAX_PATH_BYTES / size_of::<u16>() {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
    }
    Ok(PathBuf::from(OsString::from_wide(&units)))
}

fn resolution_state_digest(
    key: NativeFileKey,
    resolved: &[OsString],
    pending: &VecDeque<OsString>,
    target: &[u16],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gus.platform.windows-reparse-state.v1\0");
    key.update_digest(&mut digest);
    update_wide_components(&mut digest, resolved.iter().map(OsString::as_os_str));
    update_wide_components(&mut digest, pending.iter().map(OsString::as_os_str));
    update_wide(&mut digest, target.iter().copied());
    digest.finalize().into()
}

fn calculate_binding(
    original: &[u16],
    drive: u16,
    bindings: &[WindowsNameBinding],
    terminal: NativeFileSnapshot,
    handle_budget: usize,
) -> DiscoveryChainBinding {
    let mut digest = Sha256::new();
    digest.update(b"gus.platform.discovery-chain.windows.v1\0");
    update_wide(&mut digest, original.iter().copied());
    digest.update(drive.to_le_bytes());
    digest.update((super::MAX_PATH_BYTES as u64).to_le_bytes());
    digest.update((MAX_REPARSE_HOPS as u64).to_le_bytes());
    digest.update((MAX_EXPANDED_COMPONENTS as u64).to_le_bytes());
    digest.update((MAX_REPARSE_TARGET_BYTES as u64).to_le_bytes());
    digest.update((MAX_TOTAL_REPARSE_TARGET_BYTES as u64).to_le_bytes());
    digest.update((MAX_RETAINED_HANDLES as u64).to_le_bytes());
    digest.update((MIN_RETAINED_HANDLES as u64).to_le_bytes());
    digest.update((PROCESS_RETAINED_HANDLE_BUDGET as u64).to_le_bytes());
    digest.update((handle_budget as u64).to_le_bytes());
    for binding in bindings {
        update_wide(&mut digest, binding.logical_path.as_os_str().encode_wide());
        update_wide(&mut digest, binding.name.encode_wide());
        update_snapshot(&mut digest, binding.snapshot);
        match &binding.kind {
            WindowsBindingKind::Root => digest.update(b"root\0"),
            WindowsBindingKind::Directory => digest.update(b"directory\0"),
            WindowsBindingKind::Reparse {
                tag,
                data,
                target,
                relative,
            } => {
                digest.update(b"reparse\0");
                digest.update(tag.to_le_bytes());
                digest.update([u8::from(*relative)]);
                update_bytes(&mut digest, data);
                update_wide(&mut digest, target.iter().copied());
            }
            WindowsBindingKind::Terminal => digest.update(b"terminal\0"),
        }
    }
    update_snapshot(&mut digest, terminal);
    DiscoveryChainBinding(digest.finalize().into())
}

fn update_snapshot(digest: &mut Sha256, snapshot: NativeFileSnapshot) {
    digest.update(snapshot.volume_serial.to_le_bytes());
    digest.update(snapshot.file_id);
    digest.update(snapshot.final_path_digest);
    digest.update(snapshot.attributes.to_le_bytes());
    digest.update(snapshot.reparse_tag.to_le_bytes());
    digest.update(snapshot.creation_time.to_le_bytes());
    digest.update(snapshot.last_access_time.to_le_bytes());
    digest.update(snapshot.last_write.to_le_bytes());
    digest.update(snapshot.change_time.to_le_bytes());
    digest.update(snapshot.allocation_size.to_le_bytes());
    digest.update(snapshot.size.to_le_bytes());
    digest.update(snapshot.number_of_links.to_le_bytes());
    digest.update([u8::from(snapshot.delete_pending)]);
    digest.update(snapshot.security_digest);
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn update_wide(digest: &mut Sha256, units: impl IntoIterator<Item = u16>) {
    let units: Vec<u16> = units.into_iter().collect();
    digest.update((units.len() as u64).to_le_bytes());
    for unit in units {
        digest.update(unit.to_le_bytes());
    }
}

fn update_wide_components<'a>(
    digest: &mut Sha256,
    components: impl IntoIterator<Item = &'a OsStr>,
) {
    let components: Vec<&OsStr> = components.into_iter().collect();
    digest.update((components.len() as u64).to_le_bytes());
    for component in components {
        update_wide(digest, component.encode_wide());
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RealGitArtifactError> {
    let bytes = bytes
        .get(offset..offset + size_of::<u16>())
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("checked two-byte reparse field"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RealGitArtifactError> {
    let bytes = bytes
        .get(offset..offset + size_of::<u32>())
        .ok_or(RealGitArtifactError::InvalidReparsePoint)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("checked four-byte reparse field"),
    ))
}

fn strip_safe_nt_dos_prefix(target: &[u16]) -> Option<&[u16]> {
    let nt_prefix = [
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ];
    let win32_prefix = [
        u16::from(b'\\'),
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ];
    target
        .strip_prefix(&nt_prefix)
        .or_else(|| target.strip_prefix(&win32_prefix))
}

fn has_drive_prefix(units: &[u16]) -> bool {
    units.len() >= 2 && normalize_drive(units[0]).is_some() && units[1] == u16::from(b':')
}

fn unsafe_windows_component(component: &[u16]) -> bool {
    const RESERVED: [&[u8]; 4] = [b"CON", b"PRN", b"AUX", b"NUL"];

    if component.is_empty()
        || component
            .iter()
            .any(|unit| *unit == u16::from(b':') || *unit == u16::from(b'"'))
        || component
            .last()
            .is_some_and(|unit| *unit == u16::from(b'.') || *unit == u16::from(b' '))
    {
        return true;
    }
    let base_end = component
        .iter()
        .position(|unit| *unit == u16::from(b'.'))
        .unwrap_or(component.len());
    let base = &component[..base_end];
    if RESERVED
        .iter()
        .any(|name| wide_eq_ascii_case_insensitive(base, name))
    {
        return true;
    }
    if base.len() == 4
        && (wide_eq_ascii_case_insensitive(&base[..3], b"COM")
            || wide_eq_ascii_case_insensitive(&base[..3], b"LPT"))
        && matches!(base[3], value if (u16::from(b'1')..=u16::from(b'9')).contains(&value))
    {
        return true;
    }
    wide_eq_ascii_case_insensitive(base, b"CONIN$")
        || wide_eq_ascii_case_insensitive(base, b"CONOUT$")
}

fn is_volume_guid_root(path: &OsStr) -> bool {
    let units: Vec<u16> = path.encode_wide().collect();
    let prefix: Vec<u16> = r"\\?\Volume{".encode_utf16().collect();
    if units.len() <= prefix.len() + 2
        || !units[..prefix.len()]
            .iter()
            .zip(&prefix)
            .all(|(left, right)| ascii_upper(*left) == ascii_upper(*right))
    {
        return false;
    }
    let Some(close) = units.iter().position(|unit| *unit == u16::from(b'}')) else {
        return false;
    };
    close + 2 == units.len() && is_separator(units[close + 1])
}

fn wide_eq_ascii_case_insensitive(wide: &[u16], ascii: &[u8]) -> bool {
    wide.len() == ascii.len()
        && wide
            .iter()
            .zip(ascii)
            .all(|(left, right)| ascii_upper(*left) == u16::from(right.to_ascii_uppercase()))
}

const fn ascii_upper(unit: u16) -> u16 {
    if unit >= b'a' as u16 && unit <= b'z' as u16 {
        unit - (b'a' - b'A') as u16
    } else {
        unit
    }
}

const fn normalize_drive(unit: u16) -> Option<u16> {
    let upper = ascii_upper(unit);
    if upper >= b'A' as u16 && upper <= b'Z' as u16 {
        Some(upper)
    } else {
        None
    }
}

const fn is_separator(unit: u16) -> bool {
    unit == b'\\' as u16 || unit == b'/' as u16
}

#[cfg(test)]
mod tests {
    use std::{
        os::windows::fs::{symlink_dir, symlink_file},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::*;
    use crate::real_git::{
        CurrentExecutableEvidence, DiscoveryInspection, ExecutableExclusionSet,
        TrustedPrelaunchExecutableLease,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_WRITE};

    #[test]
    fn resolves_direct_hardlink_and_unicode_paths_with_distinct_chain_bindings() {
        let (_owned, exclusions) = exclusion_fixture();
        let directory = tempfile::tempdir().expect("create Windows resolver fixture");
        let original = directory.path().join("git-🦀.exe");
        let alias = directory.path().join("git-alias.exe");
        std::fs::copy(native_fixture_path(), &original).expect("copy native PE fixture");
        std::fs::hard_link(&original, &alias).expect("create hardlink alias");

        let original = DiscoveryInspection::inspect(&original, &exclusions)
            .expect("inspect direct Unicode candidate");
        let alias =
            DiscoveryInspection::inspect(&alias, &exclusions).expect("inspect hardlink candidate");
        assert_eq!(
            original.candidate().identity(),
            alias.candidate().identity()
        );
        assert_ne!(original.chain_binding(), alias.chain_binding());
        assert_ne!(
            original.candidate().path_binding(),
            alias.candidate().path_binding()
        );
        original.revalidate(&exclusions).expect("revalidate direct");
        alias.revalidate(&exclusions).expect("revalidate alias");
    }

    #[test]
    fn resolves_relative_file_and_directory_symbolic_links() {
        let (_owned, exclusions) = exclusion_fixture();
        let directory = tempfile::tempdir().expect("create Windows symlink fixture");
        let target_directory = directory.path().join("target");
        std::fs::create_dir(&target_directory).expect("create target directory");
        let target = target_directory.join("git.exe");
        std::fs::copy(native_fixture_path(), &target).expect("copy symlink target");

        let file_link = directory.path().join("git-file-link.exe");
        symlink_file(Path::new("target").join("git.exe"), &file_link)
            .expect("create relative file symlink");
        let directory_link = directory.path().join("linked-target");
        symlink_dir("target", &directory_link).expect("create relative directory symlink");

        let direct = DiscoveryInspection::inspect(&target, &exclusions).expect("inspect target");
        let file = DiscoveryInspection::inspect(&file_link, &exclusions)
            .expect("resolve relative file symlink");
        let directory = DiscoveryInspection::inspect(&directory_link.join("git.exe"), &exclusions)
            .expect("resolve relative directory symlink");
        assert_eq!(direct.candidate().identity(), file.candidate().identity());
        assert_eq!(
            direct.candidate().identity(),
            directory.candidate().identity()
        );
        assert_ne!(direct.chain_binding(), file.chain_binding());
        assert_ne!(file.chain_binding(), directory.chain_binding());
    }

    #[test]
    fn restrictive_leases_block_write_delete_and_retarget_until_drop() {
        let (_owned, exclusions) = exclusion_fixture();
        let directory = tempfile::tempdir().expect("create lease fixture");
        let target = directory.path().join("git.exe");
        std::fs::copy(native_fixture_path(), &target).expect("copy lease target");
        let link = directory.path().join("git-link.exe");
        symlink_file("git.exe", &link).expect("create lease symlink");

        let write_was_blocked = Arc::new(AtomicBool::new(false));
        let write_result = Arc::clone(&write_was_blocked);
        let target_for_hook = target.clone();
        let hook = install_test_hook(move |stage, _path| {
            if stage == ResolverTestStage::AfterInspection {
                let result = OpenOptions::new()
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(&target_for_hook);
                write_result.store(result.is_err(), Ordering::Release);
            }
        });
        let inspected = DiscoveryInspection::inspect(&link, &exclusions)
            .expect("inspect restrictively leased symlink");
        drop(hook);
        assert!(write_was_blocked.load(Ordering::Acquire));
        assert!(std::fs::remove_file(&link).is_err());
        assert!(std::fs::rename(&target, directory.path().join("moved.exe")).is_err());
        inspected
            .revalidate(&exclusions)
            .expect("blocked replacements preserve inspection");

        drop(inspected);
        std::fs::remove_file(&link).expect("link unlocks after inspection drop");
        std::fs::rename(&target, directory.path().join("moved.exe"))
            .expect("target unlocks after inspection drop");
    }

    #[test]
    fn sealed_resolver_preserves_self_and_owned_exclusions() {
        let (_owned, mut exclusions) = exclusion_fixture();
        let current = std::env::current_exe().expect("current Windows test image");
        assert_eq!(
            DiscoveryInspection::inspect(&current, &exclusions)
                .expect_err("current image must be rejected"),
            RealGitArtifactError::SelfReference
        );

        let directory = tempfile::tempdir().expect("create owned artifact fixture");
        let owned = directory.path().join("gus-owned.exe");
        let alias = directory.path().join("owned-alias.exe");
        std::fs::copy(native_fixture_path(), &owned).expect("copy owned artifact");
        std::fs::hard_link(&owned, &alias).expect("create owned hardlink");
        exclusions
            .add_owned_artifact(&owned)
            .expect("add owned artifact exclusion");
        assert_eq!(
            DiscoveryInspection::inspect(&alias, &exclusions)
                .expect_err("owned hardlink must be rejected"),
            RealGitArtifactError::OwnedArtifact
        );
    }

    #[test]
    fn strict_path_parser_rejects_ambiguous_windows_namespaces_and_names() {
        for path in [
            r"git.exe",
            r"C:git.exe",
            r"\git.exe",
            r"\\server\share\git.exe",
            r"\\?\C:\git.exe",
            r"C:\git.exe:stream",
            r"C:\git.exe.",
            r"C:\NUL.exe",
        ] {
            assert!(
                parse_absolute_path(Path::new(path)).is_err(),
                "ambiguous path must fail: {path}"
            );
        }
    }

    #[test]
    fn reparse_parser_rejects_unknown_truncated_odd_and_embedded_nul_data() {
        let unknown = synthetic_reparse(0xa000_001b, r"\??\C:\git.exe", false);
        assert_eq!(
            parse_reparse_buffer_for_test(&unknown).expect_err("unknown tag"),
            RealGitArtifactError::ReparsePointUnsupported
        );

        let mut truncated = synthetic_reparse(IO_REPARSE_TAG_SYMLINK, r"\??\C:\git.exe", false);
        truncated.pop();
        assert_eq!(
            parse_reparse_buffer_for_test(&truncated).expect_err("truncated data"),
            RealGitArtifactError::InvalidReparsePoint
        );

        let mut odd = synthetic_reparse(IO_REPARSE_TAG_SYMLINK, r"\??\C:\git.exe", false);
        odd[10..12].copy_from_slice(&3_u16.to_le_bytes());
        assert_eq!(
            parse_reparse_buffer_for_test(&odd).expect_err("odd UTF-16 length"),
            RealGitArtifactError::InvalidReparsePoint
        );

        let embedded = synthetic_reparse(IO_REPARSE_TAG_SYMLINK, "\\??\\C:\\git\0.exe", false);
        assert_eq!(
            parse_reparse_buffer_for_test(&embedded).expect_err("embedded NUL"),
            RealGitArtifactError::InvalidReparsePoint
        );
    }

    fn synthetic_reparse(tag: u32, target: &str, relative: bool) -> Vec<u8> {
        let target: Vec<u16> = target.encode_utf16().collect();
        let path_bytes = target.len() * 2;
        let prefix = if tag == IO_REPARSE_TAG_SYMLINK {
            20
        } else {
            16
        };
        let data_prefix = prefix - 8;
        let mut buffer = vec![0_u8; prefix + path_bytes];
        buffer[0..4].copy_from_slice(&tag.to_le_bytes());
        buffer[4..6].copy_from_slice(
            &u16::try_from(data_prefix + path_bytes)
                .expect("synthetic reparse length")
                .to_le_bytes(),
        );
        buffer[10..12].copy_from_slice(
            &u16::try_from(path_bytes)
                .expect("synthetic target length")
                .to_le_bytes(),
        );
        if tag == IO_REPARSE_TAG_SYMLINK {
            buffer[16..20].copy_from_slice(&u32::from(relative).to_le_bytes());
        }
        for (index, unit) in target.into_iter().enumerate() {
            let offset = prefix + index * 2;
            buffer[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        buffer
    }

    fn parse_reparse_buffer_for_test(buffer: &[u8]) -> Result<ReparseData, RealGitArtifactError> {
        let tag = read_u32(buffer, 0)?;
        let data_length = usize::from(read_u16(buffer, 4)?);
        if data_length.checked_add(8) != Some(buffer.len()) {
            return Err(RealGitArtifactError::InvalidReparsePoint);
        }
        let (path_start, flags) = match tag {
            IO_REPARSE_TAG_SYMLINK => (20, read_u32(buffer, 16)?),
            IO_REPARSE_TAG_MOUNT_POINT => (16, 0),
            _ => return Err(RealGitArtifactError::ReparsePointUnsupported),
        };
        let target = validate_reparse_string(
            buffer,
            path_start,
            usize::from(read_u16(buffer, 8)?),
            usize::from(read_u16(buffer, 10)?),
            false,
        )?;
        Ok(ReparseData {
            tag,
            raw: buffer.to_vec(),
            target,
            relative: flags & SYMLINK_FLAG_RELATIVE != 0,
        })
    }

    fn exclusion_fixture() -> (tempfile::TempDir, ExecutableExclusionSet) {
        let owned = tempfile::tempdir().expect("create owned root fixture");
        let current = std::env::current_exe().expect("current Windows test executable");
        let lease = open_entry(&current).expect("open synthetic prelaunch image lease");
        let trusted = TrustedPrelaunchExecutableLease { lease };
        let evidence = CurrentExecutableEvidence::from_trusted_prelaunch_lease(trusted)
            .expect("capture synthetic prelaunch image evidence");
        let exclusions = ExecutableExclusionSet::new_with_current_image(owned.path(), 1, evidence)
            .expect("build Windows exclusions");
        (owned, exclusions)
    }

    fn native_fixture_path() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("Windows SystemRoot"))
            .join("System32")
            .join("where.exe")
    }
}
