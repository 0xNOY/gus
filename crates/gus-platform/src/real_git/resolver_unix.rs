use std::{
    collections::VecDeque,
    ffi::{CString, OsString},
    fs::File,
    io,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
use std::io::Read;

use super::{
    DiscoveryChainBinding, ExpectedFileKind, NativeFileKey, NativeFileSnapshot,
    RealGitArtifactError, SafelyOpenedPath, io_error, open_unix_root,
};

const MAX_SYMLINK_HOPS: usize = 32;
const MAX_EXPANDED_COMPONENTS: usize = 256;
const MAX_SYMLINK_TARGET_BYTES: usize = 16 * 1024;
const MAX_TOTAL_SYMLINK_TARGET_BYTES: usize = 32 * 1024;
const MAX_RETAINED_HANDLES: usize = 64;
const MIN_RETAINED_HANDLES: usize = 16;
const RESERVED_PROCESS_HANDLES: usize = 64;
const TRANSIENT_RESOLUTION_HANDLES: usize = 3;
const INITIAL_LINK_BUFFER_BYTES: usize = 256;
#[cfg(target_os = "linux")]
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
#[cfg(target_os = "linux")]
const ST_NOSYMFOLLOW: libc::c_ulong = 8192;

static RESERVED_RESOLVER_HANDLES: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
static RESOLVER_TEST_HOOKS: std::sync::Mutex<Vec<ResolverTestHook>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolverTestStage {
    EntryObserved,
    LinkOpened,
    LinkRead,
    NormalOpened,
    BeforeReplay,
    BeforeInspection,
    AfterInspection,
}

#[cfg(test)]
type ResolverTestCallback = dyn FnMut(ResolverTestStage, &std::ffi::OsStr) + Send;

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
    callback: impl FnMut(ResolverTestStage, &std::ffi::OsStr) + Send + 'static,
) -> ResolverTestHookGuard {
    let owner = std::thread::current().id();
    let mut hooks = RESOLVER_TEST_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        hooks.iter().all(|installed| installed.owner != owner),
        "only one resolver test hook may be installed per thread"
    );
    hooks.push(ResolverTestHook {
        owner,
        callback: Box::new(callback),
    });
    ResolverTestHookGuard
}

#[cfg(test)]
pub(super) fn run_test_barrier(stage: ResolverTestStage, path: &std::ffi::OsStr) {
    let owner = std::thread::current().id();
    let mut hooks = RESOLVER_TEST_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(installed) = hooks.iter_mut().find(|installed| installed.owner == owner) {
        (installed.callback)(stage, path);
    }
}

#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
#[cfg(target_os = "freebsd")]
const ACL_TYPE_ACCESS: libc::c_int = 0x0000_0002;
#[cfg(target_os = "freebsd")]
const ACL_TYPE_NFS4: libc::c_int = 0x0000_0004;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
unsafe extern "C" {
    #[link_name = "acl_get_fd_np"]
    fn get_native_acl(descriptor: libc::c_int, acl_type: libc::c_int) -> *mut core::ffi::c_void;
    #[link_name = "acl_free"]
    fn free_native_acl(acl: *mut core::ffi::c_void) -> libc::c_int;
}

#[cfg(target_os = "freebsd")]
unsafe extern "C" {
    #[link_name = "acl_is_trivial_np"]
    fn native_acl_is_trivial(
        acl: *const core::ffi::c_void,
        trivial: *mut libc::c_int,
    ) -> libc::c_int;
}

pub(super) struct ResolvedUnixPath {
    pub(super) opened: SafelyOpenedPath,
    pub(super) final_key: NativeFileKey,
    pub(super) chain: UnixResolutionLeaseSet,
}

pub(super) struct UnixResolutionLeaseSet {
    original_path: PathBuf,
    bindings: Vec<UnixNameBinding>,
    binding: DiscoveryChainBinding,
    final_key: NativeFileKey,
    _handle_reservation: HandleReservation,
}

struct DirectoryCursor {
    lease: File,
    snapshot: NativeFileSnapshot,
}

struct UnixNameBinding {
    parent: File,
    parent_snapshot: NativeFileSnapshot,
    name: OsString,
    entry: File,
    snapshot: NativeFileSnapshot,
    kind: UnixBindingKind,
}

enum UnixBindingKind {
    Directory,
    SymbolicLink { target: Vec<u8>, absolute: bool },
    Terminal,
}

enum PathToken {
    Parent,
    Name(OsString),
}

struct ParsedPath {
    tokens: Vec<PathToken>,
    absolute: bool,
    trailing_slash: bool,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
struct NativeAcl(*mut core::ffi::c_void);

struct HandleReservation {
    counter: &'static AtomicUsize,
    handles: usize,
    process_budget: usize,
    max_handles: usize,
}

impl HandleReservation {
    const fn budget(&self) -> usize {
        self.handles
    }

    fn ensure(&mut self, required: usize) -> Result<(), RealGitArtifactError> {
        if required <= self.handles {
            return Ok(());
        }
        let target = required
            .max(self.handles.saturating_mul(2))
            .min(self.max_handles);
        if target < required {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let additional = target - self.handles;
        let mut reserved = self.counter.load(Ordering::Acquire);
        loop {
            let next = reserved
                .checked_add(additional)
                .ok_or(RealGitArtifactError::PathLimitExceeded)?;
            if next > self.process_budget {
                return Err(RealGitArtifactError::PathLimitExceeded);
            }
            match self.counter.compare_exchange_weak(
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
        self.counter.fetch_sub(self.handles, Ordering::AcqRel);
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl Drop for NativeAcl {
    fn drop(&mut self) {
        // SAFETY: the pointer was allocated by `acl_get_fd_np` and is freed
        // exactly once by this owner.
        let _ = unsafe { free_native_acl(self.0) };
    }
}

struct UnixResolver {
    original_path: PathBuf,
    directories: Vec<DirectoryCursor>,
    resolved_names: Vec<OsString>,
    queue: VecDeque<PathToken>,
    terminal_must_be_directory: bool,
    bindings: Vec<UnixNameBinding>,
    ancestors: Vec<NativeFileSnapshot>,
    visited_links: Vec<(NativeFileKey, NativeFileKey, [u8; 32])>,
    symlink_hops: usize,
    processed_components: usize,
    target_bytes: usize,
    handle_reservation: Option<HandleReservation>,
    credential_snapshot: Option<[u8; 32]>,
}

pub(super) fn resolve(path: &Path) -> Result<ResolvedUnixPath, RealGitArtifactError> {
    let original = path.as_os_str().as_bytes();
    if !path.is_absolute() {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    if original.len() > super::MAX_PATH_BYTES {
        return Err(RealGitArtifactError::PathLimitExceeded);
    }
    let parsed = parse_path(original, true)?;
    if parsed.tokens.len() > MAX_EXPANDED_COMPONENTS {
        return Err(RealGitArtifactError::PathLimitExceeded);
    }

    let handle_reservation = reserve_resolver_handles()?;
    let root = open_unix_root()?;
    let root_snapshot = NativeFileSnapshot::capture(&root)?;
    require_trusted_directory(&root, root_snapshot)?;
    UnixResolver {
        original_path: path.to_path_buf(),
        directories: vec![DirectoryCursor {
            lease: root,
            snapshot: root_snapshot,
        }],
        resolved_names: Vec::new(),
        queue: VecDeque::from(parsed.tokens),
        terminal_must_be_directory: parsed.trailing_slash,
        bindings: Vec::new(),
        ancestors: vec![root_snapshot],
        visited_links: Vec::new(),
        symlink_hops: 0,
        processed_components: 0,
        target_bytes: 0,
        handle_reservation: Some(handle_reservation),
        credential_snapshot: None,
    }
    .run()
}

impl UnixResolver {
    fn run(mut self) -> Result<ResolvedUnixPath, RealGitArtifactError> {
        while let Some(token) = self.queue.pop_front() {
            self.record_step()?;
            match token {
                PathToken::Parent => self.ascend(),
                PathToken::Name(name) => {
                    if let Some(resolved) = self.process_name(name)? {
                        return Ok(resolved);
                    }
                }
            }
        }
        Err(RealGitArtifactError::NotExecutable)
    }

    fn record_step(&mut self) -> Result<(), RealGitArtifactError> {
        self.processed_components = self
            .processed_components
            .checked_add(1)
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if self.processed_components > MAX_EXPANDED_COMPONENTS {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let required = retained_handle_count(self.bindings.len(), self.directories.len())
            .saturating_add(TRANSIENT_RESOLUTION_HANDLES);
        self.handle_reservation
            .as_mut()
            .expect("live resolver owns its handle reservation")
            .ensure(required)
    }

    fn handle_budget(&self) -> usize {
        self.handle_reservation
            .as_ref()
            .expect("live resolver owns its handle reservation")
            .budget()
    }

    fn ascend(&mut self) {
        if self.directories.len() > 1 {
            self.directories.pop();
            self.resolved_names.pop();
        }
    }

    fn process_name(
        &mut self,
        name: OsString,
    ) -> Result<Option<ResolvedUnixPath>, RealGitArtifactError> {
        let component =
            CString::new(name.as_bytes()).map_err(|_| RealGitArtifactError::UnsafePath)?;
        let parent = self
            .directories
            .last()
            .ok_or(RealGitArtifactError::UnsafePath)?;
        let parent_snapshot = parent.snapshot;
        let parent_lease = parent.lease.try_clone().map_err(io_error)?;
        let observed = snapshot_at(&parent_lease, &component)?;
        #[cfg(test)]
        run_test_barrier(ResolverTestStage::EntryObserved, &name);
        require_trusted_entry_open(parent_snapshot, observed)?;
        if observed.symbolic_link() {
            self.process_link(name, &component, parent_lease, parent_snapshot, observed)?;
            return Ok(None);
        }
        self.process_normal(name, &component, parent_lease, parent_snapshot, observed)
    }

    fn process_link(
        &mut self,
        name: OsString,
        component: &CString,
        parent_lease: File,
        parent_snapshot: NativeFileSnapshot,
        observed: NativeFileSnapshot,
    ) -> Result<(), RealGitArtifactError> {
        self.symlink_hops = self
            .symlink_hops
            .checked_add(1)
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if self.symlink_hops > MAX_SYMLINK_HOPS {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        self.observe_unprivileged_credentials()?;
        let link = open_symbolic_link(&parent_lease, component)?;
        #[cfg(test)]
        run_test_barrier(ResolverTestStage::LinkOpened, &name);
        let before = NativeFileSnapshot::capture(&link)?;
        if !before.symbolic_link() || !observed.same_link(&before) {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        require_link_mount_policy(&link)?;
        let target = read_retained_link(&link)?;
        #[cfg(test)]
        run_test_barrier(ResolverTestStage::LinkRead, &name);
        if !before.same_link(&NativeFileSnapshot::capture(&link)?) {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.revalidate_credentials()?;
        let visit = (
            parent_snapshot.file_key(),
            before.file_key(),
            self.resolution_state_digest(),
        );
        if self.visited_links.contains(&visit) {
            return Err(RealGitArtifactError::SymbolicLinkLoop);
        }
        self.visited_links.push(visit);
        self.splice_link_target(&target)?;
        let absolute = target.first() == Some(&b'/');
        self.bindings.push(UnixNameBinding {
            parent: parent_lease,
            parent_snapshot,
            name,
            entry: link,
            snapshot: before,
            kind: UnixBindingKind::SymbolicLink { target, absolute },
        });
        Ok(())
    }

    fn observe_unprivileged_credentials(&mut self) -> Result<(), RealGitArtifactError> {
        let current = unprivileged_credential_snapshot()?;
        if self
            .credential_snapshot
            .is_some_and(|initial| initial != current)
        {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.credential_snapshot = Some(current);
        Ok(())
    }

    fn revalidate_credentials(&self) -> Result<(), RealGitArtifactError> {
        if let Some(initial) = self.credential_snapshot {
            if unprivileged_credential_snapshot()? != initial {
                return Err(RealGitArtifactError::DiscoveryChainStale);
            }
        }
        Ok(())
    }

    fn resolution_state_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.discovery-loop-state.unix.v1\0");
        for directory in &self.directories {
            directory.snapshot.file_key().update_digest(&mut digest);
        }
        for token in &self.queue {
            match token {
                PathToken::Parent => digest.update(b"parent\0"),
                PathToken::Name(name) => {
                    digest.update(b"name\0");
                    update_length_prefixed(&mut digest, name.as_bytes());
                }
            }
        }
        digest.update([u8::from(self.terminal_must_be_directory)]);
        digest.finalize().into()
    }

    fn splice_link_target(&mut self, target: &[u8]) -> Result<(), RealGitArtifactError> {
        let parsed = parse_path(target, false)?;
        self.target_bytes = self
            .target_bytes
            .checked_add(target.len())
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if target.len() > MAX_SYMLINK_TARGET_BYTES
            || self.target_bytes > MAX_TOTAL_SYMLINK_TARGET_BYTES
            || parsed.tokens.len().saturating_add(self.queue.len()) > MAX_EXPANDED_COMPONENTS
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        if parsed.absolute {
            self.directories.truncate(1);
            self.resolved_names.clear();
        }
        if parsed.trailing_slash && self.queue.is_empty() {
            self.terminal_must_be_directory = true;
        }
        for token in parsed.tokens.into_iter().rev() {
            self.queue.push_front(token);
        }
        Ok(())
    }

    fn process_normal(
        &mut self,
        name: OsString,
        component: &CString,
        parent_lease: File,
        parent_snapshot: NativeFileSnapshot,
        observed: NativeFileSnapshot,
    ) -> Result<Option<ResolvedUnixPath>, RealGitArtifactError> {
        let is_final = self.queue.is_empty();
        if is_final && self.terminal_must_be_directory && !observed.is_directory() {
            return Err(RealGitArtifactError::NotExecutable);
        }
        let required_kind = if is_final && !self.terminal_must_be_directory {
            ExpectedFileKind::RegularFile
        } else {
            ExpectedFileKind::Directory
        };
        required_kind.require(observed)?;
        let opened = open_normal_entry(&parent_lease, component, required_kind)?;
        #[cfg(test)]
        run_test_barrier(ResolverTestStage::NormalOpened, &name);
        let snapshot = NativeFileSnapshot::capture(&opened)?;
        required_kind.require(snapshot)?;
        if !observed.same_opened_entry(&snapshot, required_kind) {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }

        if matches!(required_kind, ExpectedFileKind::Directory) {
            require_trusted_directory(&opened, snapshot)?;
            self.bindings.push(UnixNameBinding {
                parent: parent_lease,
                parent_snapshot,
                name: name.clone(),
                entry: opened.try_clone().map_err(io_error)?,
                snapshot,
                kind: UnixBindingKind::Directory,
            });
            self.ancestors.push(snapshot);
            self.directories.push(DirectoryCursor {
                lease: opened,
                snapshot,
            });
            self.resolved_names.push(name);
            if is_final {
                return Err(RealGitArtifactError::NotExecutable);
            }
            return Ok(None);
        }
        require_trusted_executable(&opened, snapshot)?;
        self.revalidate_credentials()?;
        self.bindings.push(UnixNameBinding {
            parent: parent_lease,
            parent_snapshot,
            name: name.clone(),
            entry: opened.try_clone().map_err(io_error)?,
            snapshot,
            kind: UnixBindingKind::Terminal,
        });
        self.resolved_names.push(name);
        let normalized_path = path_from_components(&self.resolved_names)?;
        let final_key = snapshot.file_key();
        let handle_budget = self.handle_budget();
        let binding = calculate_binding(
            &self.original_path,
            &self.bindings,
            final_key,
            handle_budget,
            self.credential_snapshot,
        );
        Ok(Some(ResolvedUnixPath {
            opened: SafelyOpenedPath {
                normalized_path,
                lease: opened,
                ancestors: std::mem::take(&mut self.ancestors),
            },
            final_key,
            chain: UnixResolutionLeaseSet {
                original_path: self.original_path.clone(),
                bindings: std::mem::take(&mut self.bindings),
                binding,
                final_key,
                _handle_reservation: self
                    .handle_reservation
                    .take()
                    .expect("completed resolver owns its handle reservation"),
            },
        }))
    }
}

impl UnixResolutionLeaseSet {
    #[cfg(target_os = "macos")]
    pub(super) fn require_root_owned_direct_chain(&self) -> Result<(), RealGitArtifactError> {
        if self.bindings.iter().any(|binding| {
            binding.parent_snapshot.owner != 0
                || binding.snapshot.owner != 0
                || matches!(binding.kind, UnixBindingKind::SymbolicLink { .. })
        }) {
            return Err(RealGitArtifactError::UnsafePath);
        }
        Ok(())
    }

    pub(super) const fn binding(&self) -> DiscoveryChainBinding {
        self.binding
    }

    pub(super) fn revalidate(
        &self,
        expected_final: &NativeFileKey,
    ) -> Result<(), RealGitArtifactError> {
        if self.final_key != *expected_final {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.validate_retained_bindings()?;
        #[cfg(test)]
        run_test_barrier(
            ResolverTestStage::BeforeReplay,
            self.original_path.as_os_str(),
        );
        let replay =
            resolve(&self.original_path).map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
        if replay.final_key != self.final_key || replay.chain.binding != self.binding {
            return Err(RealGitArtifactError::DiscoveryChainStale);
        }
        self.validate_retained_bindings()
    }

    fn validate_retained_bindings(&self) -> Result<(), RealGitArtifactError> {
        for binding in &self.bindings {
            let parent = NativeFileSnapshot::capture(&binding.parent)
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            if !parent.same_owned_directory(&binding.parent_snapshot) {
                return Err(RealGitArtifactError::DiscoveryChainStale);
            }
            require_trusted_directory(&binding.parent, parent)
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            let name = CString::new(binding.name.as_bytes())
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            let named = snapshot_at(&binding.parent, &name)
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            let retained = NativeFileSnapshot::capture(&binding.entry)
                .map_err(|_| RealGitArtifactError::DiscoveryChainStale)?;
            let matches = match &binding.kind {
                UnixBindingKind::Directory => {
                    named.same_owned_directory(&binding.snapshot)
                        && retained.same_owned_directory(&binding.snapshot)
                        && require_trusted_directory(&binding.entry, retained).is_ok()
                }
                UnixBindingKind::SymbolicLink { target, .. } => {
                    named.same_link(&binding.snapshot)
                        && retained.same_link(&binding.snapshot)
                        && require_link_mount_policy(&binding.entry).is_ok()
                        && read_retained_link(&binding.entry)
                            .is_ok_and(|current| current == *target)
                }
                UnixBindingKind::Terminal => {
                    named.same_discovery_artifact(&binding.snapshot)
                        && retained.same_discovery_artifact(&binding.snapshot)
                        && require_trusted_executable(&binding.entry, retained).is_ok()
                }
            };
            if !matches {
                return Err(RealGitArtifactError::DiscoveryChainStale);
            }
        }
        Ok(())
    }
}

fn parse_path(bytes: &[u8], require_absolute: bool) -> Result<ParsedPath, RealGitArtifactError> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(RealGitArtifactError::InvalidSymbolicLink);
    }
    if bytes.starts_with(b"//") {
        return Err(RealGitArtifactError::UnsafePath);
    }
    let absolute = bytes.first() == Some(&b'/');
    if require_absolute && !absolute {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    let trailing_slash = bytes.len() > 1 && bytes.last() == Some(&b'/');
    let mut tokens = Vec::new();
    for component in bytes.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => tokens.push(PathToken::Parent),
            name => tokens.push(PathToken::Name(OsString::from_vec(name.to_vec()))),
        }
    }
    Ok(ParsedPath {
        tokens,
        absolute,
        trailing_slash,
    })
}

fn path_from_components(components: &[OsString]) -> Result<PathBuf, RealGitArtifactError> {
    let mut path = PathBuf::from("/");
    for component in components {
        path.push(component);
        if path.as_os_str().as_bytes().len() > super::MAX_PATH_BYTES {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
    }
    Ok(path)
}

fn retained_handle_count(binding_count: usize, directory_count: usize) -> usize {
    binding_count
        .saturating_mul(2)
        .saturating_add(directory_count)
}

fn reserve_resolver_handles() -> Result<HandleReservation, RealGitArtifactError> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `limit` is exact writable storage for one RLIMIT_NOFILE result.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `getrlimit` initialized the value.
    let soft = unsafe { limit.assume_init() }.rlim_cur;
    let soft = if soft == libc::RLIM_INFINITY {
        usize::MAX
    } else {
        usize::try_from(soft).map_err(|_| RealGitArtifactError::PathLimitExceeded)?
    };
    reserve_resolver_handles_with_limit(&RESERVED_RESOLVER_HANDLES, soft)
}

fn reserve_resolver_handles_with_limit(
    counter: &'static AtomicUsize,
    soft: usize,
) -> Result<HandleReservation, RealGitArtifactError> {
    let process_budget = soft.saturating_sub(RESERVED_PROCESS_HANDLES);
    let max_handles = (process_budget / 2).min(MAX_RETAINED_HANDLES);
    if max_handles < MIN_RETAINED_HANDLES {
        return Err(RealGitArtifactError::PathLimitExceeded);
    }
    let budget = MIN_RETAINED_HANDLES;
    let mut reserved = counter.load(Ordering::Acquire);
    loop {
        let next = reserved
            .checked_add(budget)
            .ok_or(RealGitArtifactError::PathLimitExceeded)?;
        if next > process_budget {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        match counter.compare_exchange_weak(reserved, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Ok(HandleReservation {
                    counter,
                    handles: budget,
                    process_budget,
                    max_handles,
                });
            }
            Err(current) => reserved = current,
        }
    }
}

fn snapshot_at(
    parent: &File,
    component: &CString,
) -> Result<NativeFileSnapshot, RealGitArtifactError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the directory descriptor and component are live, and `status`
    // is exact writable storage for one result.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            component.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `fstatat` initialized the complete structure.
    let status = unsafe { status.assume_init() };
    snapshot_from_stat(&status)
}

fn snapshot_from_stat(status: &libc::stat) -> Result<NativeFileSnapshot, RealGitArtifactError> {
    #[cfg(target_os = "macos")]
    let device =
        super::normalize_macos_device(u64::from(u32::from_ne_bytes(status.st_dev.to_ne_bytes())));
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let device = status.st_dev;

    let (modified_seconds, modified_nanoseconds, changed_seconds, changed_nanoseconds) = (
        status.st_mtime,
        status.st_mtime_nsec,
        status.st_ctime,
        status.st_ctime_nsec,
    );

    Ok(NativeFileSnapshot {
        device,
        inode: status.st_ino,
        mode: u64::from(status.st_mode),
        owner: status.st_uid,
        group: status.st_gid,
        size: u64::try_from(status.st_size).map_err(|_| RealGitArtifactError::UnsafePath)?,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    })
}

fn require_trusted_entry_open(
    parent: NativeFileSnapshot,
    entry: NativeFileSnapshot,
) -> Result<(), RealGitArtifactError> {
    // SAFETY: `geteuid` has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if parent.owner != 0 && parent.owner != effective_user {
        return Err(RealGitArtifactError::UnsafePath);
    }
    if parent.mode & 0o022 == 0 {
        return Ok(());
    }
    // A root-owned sticky directory is safe only for an entry controlled by
    // root or by this effective user. This also avoids macOS opening an
    // attacker-controlled replacement where no O_PATH equivalent exists.
    let sticky = parent.owner == 0 && parent.mode & u64::from(libc::S_ISVTX) != 0;
    if sticky && (entry.owner == 0 || entry.owner == effective_user) {
        Ok(())
    } else {
        Err(RealGitArtifactError::UnsafePath)
    }
}

fn require_trusted_directory(
    directory: &File,
    snapshot: NativeFileSnapshot,
) -> Result<(), RealGitArtifactError> {
    snapshot.require_safe_directory()?;
    // SAFETY: `geteuid` has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if snapshot.owner != 0 && snapshot.owner != effective_user {
        return Err(RealGitArtifactError::UnsafePath);
    }
    require_trivial_acl(directory)?;
    require_directory_mount_policy(directory)
}

fn require_trusted_executable(
    executable: &File,
    snapshot: NativeFileSnapshot,
) -> Result<(), RealGitArtifactError> {
    // The artifact owner can change its mode and contents after inspection,
    // so accepting a different owner would cross the multi-user trust
    // boundary even when the containing directory itself is trusted.
    snapshot.require_executable()?;
    // SAFETY: `geteuid` has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if snapshot.owner != 0 && snapshot.owner != effective_user {
        return Err(RealGitArtifactError::UnsafePath);
    }
    require_trivial_acl(executable)?;
    require_executable_mount_policy(executable)
}

#[cfg(target_os = "linux")]
fn require_trivial_acl(file: &File) -> Result<(), RealGitArtifactError> {
    let name = c"system.posix_acl_access";
    // SAFETY: the descriptor and attribute name are live. A null value with
    // zero size asks only whether an ACL xattr exists.
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    let error = io::Error::last_os_error().raw_os_error();
    if error.is_some_and(|code| code == libc::ENODATA || code == libc::EOPNOTSUPP) {
        Ok(())
    } else {
        Err(RealGitArtifactError::SymbolicLinkPolicyDenied)
    }
}

#[cfg(target_os = "macos")]
fn require_trivial_acl(file: &File) -> Result<(), RealGitArtifactError> {
    // SAFETY: the descriptor is live and the ACL type is defined by macOS.
    let pointer = unsafe { get_native_acl(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if pointer.is_null() {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(RealGitArtifactError::SymbolicLinkPolicyDenied)
        };
    }
    let _acl = NativeAcl(pointer);
    Err(RealGitArtifactError::SymbolicLinkPolicyDenied)
}

#[cfg(target_os = "freebsd")]
fn require_trivial_acl(file: &File) -> Result<(), RealGitArtifactError> {
    // SAFETY: the descriptor is live and both selectors are defined by
    // FreeBSD. A zero result means that ACL model cannot exist on this FS;
    // query failure remains fail-closed.
    let models = unsafe {
        freebsd_acl_types(
            libc::fpathconf(file.as_raw_fd(), libc::_PC_ACL_NFS4),
            libc::fpathconf(file.as_raw_fd(), libc::_PC_ACL_EXTENDED),
        )?
    };
    for acl_type in models.into_iter().flatten() {
        // SAFETY: the descriptor is live and pathconf reported this exact ACL
        // model as supported by the backing filesystem.
        let pointer = unsafe { get_native_acl(file.as_raw_fd(), acl_type) };
        if pointer.is_null() {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
        let acl = NativeAcl(pointer);
        let mut trivial = 0;
        // SAFETY: `acl` is live and `trivial` is writable for the result.
        if unsafe { native_acl_is_trivial(acl.0, &raw mut trivial) } != 0 {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
        if trivial != 1 {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn freebsd_acl_types(
    nfs4: libc::c_long,
    extended: libc::c_long,
) -> Result<[Option<libc::c_int>; 2], RealGitArtifactError> {
    if nfs4 < 0 || extended < 0 {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    Ok(if nfs4 > 0 {
        [Some(ACL_TYPE_NFS4), None]
    } else if extended > 0 {
        [Some(ACL_TYPE_ACCESS), None]
    } else {
        [None, None]
    })
}

fn open_normal_entry(
    parent: &File,
    component: &CString,
    expected: ExpectedFileKind,
) -> Result<File, RealGitArtifactError> {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if matches!(expected, ExpectedFileKind::Directory) {
            libc::O_DIRECTORY
        } else {
            0
        };
    // SAFETY: the parent is a live directory, the component is one
    // NUL-terminated name, and the returned descriptor is owned.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `openat` returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_symbolic_link(parent: &File, component: &CString) -> Result<File, RealGitArtifactError> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = libc::O_SYMLINK | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: the parent is a live directory, the component is one
    // NUL-terminated name, and the returned descriptor is owned.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `openat` returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn read_retained_link(link: &File) -> Result<Vec<u8>, RealGitArtifactError> {
    let mut capacity = INITIAL_LINK_BUFFER_BYTES;
    loop {
        if capacity > MAX_SYMLINK_TARGET_BYTES.saturating_add(1) {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        let mut buffer = vec![0_u8; capacity];
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let read = {
            let empty = c"";
            // SAFETY: `link` is a retained symlink descriptor, `empty`
            // requests empty-path operation, and the buffer is writable.
            unsafe {
                libc::readlinkat(
                    link.as_raw_fd(),
                    empty.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            }
        };
        #[cfg(target_os = "macos")]
        // SAFETY: `link` is an O_SYMLINK descriptor and the buffer is
        // writable for the provided length.
        let read =
            unsafe { libc::freadlink(link.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        let read = usize::try_from(read).map_err(|_| RealGitArtifactError::InvalidSymbolicLink)?;
        if read == 0 {
            return Err(RealGitArtifactError::InvalidSymbolicLink);
        }
        if read > MAX_SYMLINK_TARGET_BYTES {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        if read == capacity {
            if capacity == MAX_SYMLINK_TARGET_BYTES.saturating_add(1) {
                return Err(RealGitArtifactError::PathLimitExceeded);
            }
            capacity = capacity
                .checked_mul(2)
                .map_or(MAX_SYMLINK_TARGET_BYTES + 1, |next| {
                    next.min(MAX_SYMLINK_TARGET_BYTES + 1)
                });
            continue;
        }
        buffer.truncate(read);
        if buffer.contains(&0) {
            return Err(RealGitArtifactError::InvalidSymbolicLink);
        }
        return Ok(buffer);
    }
}

fn unprivileged_credential_snapshot() -> Result<[u8; 32], RealGitArtifactError> {
    // SAFETY: credential getters have no preconditions.
    let (real_user, effective_user, real_group, effective_group) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if real_user != effective_user || real_group != effective_group {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    #[cfg(target_os = "linux")]
    return linux_unprivileged_status_digest();
    #[cfg(target_os = "freebsd")]
    {
        let mut mode = 0_u32;
        // SAFETY: `mode` is writable storage for `cap_getmode`.
        if unsafe { libc::cap_getmode(&raw mut mode) } != 0 || mode != 0 {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.resolver-credentials.unix.v1\0");
        digest.update(real_user.to_le_bytes());
        digest.update(effective_user.to_le_bytes());
        digest.update(real_group.to_le_bytes());
        digest.update(effective_group.to_le_bytes());
        Ok(digest.finalize().into())
    }
}

#[cfg(target_os = "linux")]
fn linux_unprivileged_status_digest() -> Result<[u8; 32], RealGitArtifactError> {
    const MAX_STATUS_BYTES: usize = 64 * 1024;
    let status_file = File::open("/proc/thread-self/status")
        .map_err(|_| RealGitArtifactError::SymbolicLinkPolicyDenied)?;
    require_linux_procfs(&status_file)?;
    let mut status = Vec::with_capacity(MAX_STATUS_BYTES + 1);
    status_file
        .take((MAX_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut status)
        .map_err(|_| RealGitArtifactError::SymbolicLinkPolicyDenied)?;
    if status.len() > MAX_STATUS_BYTES {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    let text =
        std::str::from_utf8(&status).map_err(|_| RealGitArtifactError::SymbolicLinkPolicyDenied)?;
    let mut real_user = 0;
    let mut effective_user = 0;
    let mut saved_user = 0;
    let mut real_group = 0;
    let mut effective_group = 0;
    let mut saved_group = 0;
    // SAFETY: all pointers refer to exact writable uid/gid storage.
    if unsafe { libc::getresuid(&raw mut real_user, &raw mut effective_user, &raw mut saved_user) }
        != 0
        // SAFETY: all pointers refer to exact writable uid/gid storage.
        || unsafe {
            libc::getresgid(
                &raw mut real_group,
                &raw mut effective_group,
                &raw mut saved_group,
            )
        } != 0
    {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    if real_user != effective_user
        || saved_user != effective_user
        || real_group != effective_group
        || saved_group != effective_group
    {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    // SAFETY: `getpid` and the argument-free `gettid` syscall have no
    // preconditions and return identities in the caller's PID namespace.
    let (thread_id, process_id) = unsafe {
        (
            libc::syscall(libc::SYS_gettid),
            libc::c_long::from(libc::getpid()),
        )
    };
    validate_linux_status(
        text,
        thread_id,
        process_id,
        [real_user, effective_user, saved_user, effective_user],
        [real_group, effective_group, saved_group, effective_group],
    )
}

#[cfg(target_os = "linux")]
fn validate_linux_status(
    text: &str,
    expected_thread_id: libc::c_long,
    expected_process_id: libc::c_long,
    expected_users: [libc::uid_t; 4],
    expected_groups: [libc::gid_t; 4],
) -> Result<[u8; 32], RealGitArtifactError> {
    let pid = text.lines().find_map(|line| line.strip_prefix("Pid:\t"));
    let tgid = text.lines().find_map(|line| line.strip_prefix("Tgid:\t"));
    let uid = text.lines().find_map(|line| line.strip_prefix("Uid:\t"));
    let gid = text.lines().find_map(|line| line.strip_prefix("Gid:\t"));
    let capabilities = text.lines().find_map(|line| line.strip_prefix("CapEff:\t"));
    let parse_ids = |value: &str| {
        let mut values = value.split_ascii_whitespace();
        let parsed = [
            values.next()?.parse::<u32>().ok()?,
            values.next()?.parse::<u32>().ok()?,
            values.next()?.parse::<u32>().ok()?,
            values.next()?.parse::<u32>().ok()?,
        ];
        values.next().is_none().then_some(parsed)
    };
    let exact_thread = pid
        .and_then(|value| value.parse::<libc::c_long>().ok())
        .is_some_and(|value| value == expected_thread_id);
    let exact_process = tgid
        .and_then(|value| value.parse::<libc::c_long>().ok())
        .is_some_and(|value| value == expected_process_id);
    let no_capabilities = capabilities
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte == b'0'));
    let uniform_users = expected_users.windows(2).all(|pair| pair[0] == pair[1]);
    let uniform_groups = expected_groups.windows(2).all(|pair| pair[0] == pair[1]);
    if !uniform_users
        || !uniform_groups
        || !exact_thread
        || !exact_process
        || uid.and_then(parse_ids) != Some(expected_users)
        || gid.and_then(parse_ids) != Some(expected_groups)
        || !no_capabilities
    {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    let mut digest = Sha256::new();
    digest.update(b"gus.platform.resolver-credentials.linux.v1\0");
    update_length_prefixed(
        &mut digest,
        uid.expect("validated Linux UID status").as_bytes(),
    );
    update_length_prefixed(
        &mut digest,
        gid.expect("validated Linux GID status").as_bytes(),
    );
    update_length_prefixed(
        &mut digest,
        capabilities
            .expect("validated Linux capability status")
            .as_bytes(),
    );
    Ok(digest.finalize().into())
}

#[cfg(target_os = "linux")]
fn require_linux_procfs(file: &File) -> Result<(), RealGitArtifactError> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is live and `filesystem` is exact writable
    // storage for one filesystem observation.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    // SAFETY: successful `fstatfs` initialized the value.
    if unsafe { filesystem.assume_init() }.f_type != PROC_SUPER_MAGIC {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    Ok(())
}

struct FilesystemPolicy {
    local: bool,
    no_execute: bool,
}

#[cfg(target_os = "linux")]
fn filesystem_policy(file: &File) -> Result<FilesystemPolicy, RealGitArtifactError> {
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the descriptor is live and `status` is exact writable storage.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `fstatvfs` initialized the value.
    let status = unsafe { status.assume_init() };
    Ok(FilesystemPolicy {
        local: true,
        no_execute: status.f_flag & libc::ST_NOEXEC != 0,
    })
}

#[cfg(target_os = "macos")]
fn filesystem_policy(file: &File) -> Result<FilesystemPolicy, RealGitArtifactError> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is live and `status` is exact writable storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `fstatfs` initialized the value.
    let status = unsafe { status.assume_init() };
    Ok(macos_filesystem_policy(status.f_flags))
}

#[cfg(target_os = "macos")]
fn macos_filesystem_policy(flags: u32) -> FilesystemPolicy {
    let local = u32::try_from(libc::MNT_LOCAL).expect("macOS mount flag fits u32");
    let no_execute = u32::try_from(libc::MNT_NOEXEC).expect("macOS mount flag fits u32");
    FilesystemPolicy {
        local: flags & local != 0,
        no_execute: flags & no_execute != 0,
    }
}

#[cfg(target_os = "freebsd")]
fn filesystem_policy(file: &File) -> Result<FilesystemPolicy, RealGitArtifactError> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is live and `status` is exact writable storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `fstatfs` initialized the value.
    let status = unsafe { status.assume_init() };
    Ok(freebsd_filesystem_policy(status.f_flags))
}

#[cfg(target_os = "freebsd")]
fn freebsd_filesystem_policy(flags: u64) -> FilesystemPolicy {
    let no_execute = u64::try_from(libc::MNT_NOEXEC).expect("FreeBSD mount flag fits u64");
    FilesystemPolicy {
        local: flags & libc::MNT_LOCAL != 0,
        no_execute: flags & no_execute != 0,
    }
}

#[cfg(target_os = "freebsd")]
fn freebsd_nosymfollow(flags: u64) -> bool {
    flags & u64::try_from(libc::MNT_NOSYMFOLLOW).expect("FreeBSD mount flag fits u64") != 0
}

fn require_directory_mount_policy(directory: &File) -> Result<(), RealGitArtifactError> {
    if filesystem_policy(directory)?.local {
        Ok(())
    } else {
        Err(RealGitArtifactError::SymbolicLinkPolicyDenied)
    }
}

fn require_executable_mount_policy(executable: &File) -> Result<(), RealGitArtifactError> {
    let policy = filesystem_policy(executable)?;
    if policy.local && !policy.no_execute {
        Ok(())
    } else {
        Err(RealGitArtifactError::NotExecutable)
    }
}

fn require_link_mount_policy(link: &File) -> Result<(), RealGitArtifactError> {
    if !filesystem_policy(link)?.local {
        return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
    }
    #[cfg(target_os = "linux")]
    {
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is live and `status` is exact writable
        // storage for one filesystem observation.
        if unsafe { libc::fstatfs(link.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: successful `fstatfs` initialized the value.
        let status = unsafe { status.assume_init() };
        if status.f_type == PROC_SUPER_MAGIC {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
        let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the descriptor is live and `mount` is exact writable
        // storage for one mount-policy observation.
        if unsafe { libc::fstatvfs(link.as_raw_fd(), mount.as_mut_ptr()) } != 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: successful `fstatvfs` initialized the value.
        if unsafe { mount.assume_init() }.f_flag & ST_NOSYMFOLLOW != 0 {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is live and `status` is writable.
        if unsafe { libc::fstatfs(link.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: successful `fstatfs` initialized the value.
        let status = unsafe { status.assume_init() };
        if freebsd_nosymfollow(status.f_flags) {
            return Err(RealGitArtifactError::SymbolicLinkPolicyDenied);
        }
    }
    Ok(())
}

fn calculate_binding(
    original_path: &Path,
    bindings: &[UnixNameBinding],
    final_key: NativeFileKey,
    handle_budget: usize,
    credential_snapshot: Option<[u8; 32]>,
) -> DiscoveryChainBinding {
    let mut digest = Sha256::new();
    digest.update(b"gus.platform.discovery-chain.unix.v1\0");
    update_length_prefixed(&mut digest, platform_tag());
    update_length_prefixed(&mut digest, original_path.as_os_str().as_bytes());
    digest.update((super::MAX_PATH_BYTES as u64).to_le_bytes());
    digest.update((MAX_SYMLINK_HOPS as u64).to_le_bytes());
    digest.update((MAX_EXPANDED_COMPONENTS as u64).to_le_bytes());
    digest.update((MAX_SYMLINK_TARGET_BYTES as u64).to_le_bytes());
    digest.update((MAX_TOTAL_SYMLINK_TARGET_BYTES as u64).to_le_bytes());
    digest.update((MAX_RETAINED_HANDLES as u64).to_le_bytes());
    digest.update((MIN_RETAINED_HANDLES as u64).to_le_bytes());
    digest.update((RESERVED_PROCESS_HANDLES as u64).to_le_bytes());
    digest.update((TRANSIENT_RESOLUTION_HANDLES as u64).to_le_bytes());
    digest.update((handle_budget as u64).to_le_bytes());
    let symlink_count = bindings
        .iter()
        .filter(|binding| matches!(binding.kind, UnixBindingKind::SymbolicLink { .. }))
        .count();
    digest.update((symlink_count as u64).to_le_bytes());
    digest.update(credential_snapshot.unwrap_or([0; 32]));
    for binding in bindings {
        update_directory_snapshot(&mut digest, binding.parent_snapshot);
        update_length_prefixed(&mut digest, binding.name.as_bytes());
        match &binding.kind {
            UnixBindingKind::Directory => {
                digest.update(b"directory\0");
                update_directory_snapshot(&mut digest, binding.snapshot);
            }
            UnixBindingKind::SymbolicLink { target, absolute } => {
                digest.update(b"symbolic-link\0");
                update_link_snapshot(&mut digest, binding.snapshot);
                digest.update([u8::from(*absolute)]);
                update_length_prefixed(&mut digest, target);
            }
            UnixBindingKind::Terminal => {
                digest.update(b"terminal\0");
                update_terminal_snapshot(&mut digest, binding.snapshot);
            }
        }
    }
    final_key.update_digest(&mut digest);
    DiscoveryChainBinding(digest.finalize().into())
}

#[cfg(target_os = "linux")]
const fn platform_tag() -> &'static [u8] {
    b"linux"
}

#[cfg(target_os = "macos")]
const fn platform_tag() -> &'static [u8] {
    b"macos"
}

#[cfg(target_os = "freebsd")]
const fn platform_tag() -> &'static [u8] {
    b"freebsd"
}

fn update_directory_snapshot(digest: &mut Sha256, snapshot: NativeFileSnapshot) {
    snapshot.file_key().update_digest(digest);
    digest.update(snapshot.mode.to_le_bytes());
    digest.update(snapshot.owner.to_le_bytes());
    digest.update(snapshot.group.to_le_bytes());
}

fn update_link_snapshot(digest: &mut Sha256, snapshot: NativeFileSnapshot) {
    snapshot.file_key().update_digest(digest);
    digest.update(snapshot.mode.to_le_bytes());
    digest.update(snapshot.owner.to_le_bytes());
    digest.update(snapshot.group.to_le_bytes());
    digest.update(snapshot.size.to_le_bytes());
    digest.update(snapshot.modified_seconds.to_le_bytes());
    digest.update(snapshot.modified_nanoseconds.to_le_bytes());
    digest.update(snapshot.changed_seconds.to_le_bytes());
    digest.update(snapshot.changed_nanoseconds.to_le_bytes());
}

fn update_terminal_snapshot(digest: &mut Sha256, snapshot: NativeFileSnapshot) {
    snapshot.file_key().update_digest(digest);
    digest.update(snapshot.mode.to_le_bytes());
    digest.update(snapshot.owner.to_le_bytes());
    digest.update(snapshot.group.to_le_bytes());
    digest.update(snapshot.size.to_le_bytes());
    digest.update(snapshot.modified_seconds.to_le_bytes());
    digest.update(snapshot.modified_nanoseconds.to_le_bytes());
    digest.update(snapshot.changed_seconds.to_le_bytes());
    digest.update(snapshot.changed_nanoseconds.to_le_bytes());
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

trait UnixSnapshotExt {
    fn symbolic_link(self) -> bool;
    fn same_link(self, other: &Self) -> bool;
    fn same_opened_entry(self, other: &Self, kind: ExpectedFileKind) -> bool;
}

impl UnixSnapshotExt for NativeFileSnapshot {
    fn symbolic_link(self) -> bool {
        self.mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFLNK)
    }

    fn same_link(self, other: &Self) -> bool {
        self == *other && self.symbolic_link()
    }

    fn same_opened_entry(self, other: &Self, kind: ExpectedFileKind) -> bool {
        match kind {
            ExpectedFileKind::Directory => self.same_owned_directory(other),
            ExpectedFileKind::RegularFile => self.same_file(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    use std::os::unix::ffi::OsStringExt;

    use super::*;
    use crate::real_git::{DiscoveryInspection, ExecutableExclusionSet};

    static TEST_RESERVATION_HANDLES: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn resolver_handle_reservations_bound_replay_concurrency_and_release() {
        TEST_RESERVATION_HANDLES.store(0, Ordering::Release);
        assert!(matches!(
            reserve_resolver_handles_with_limit(
                &TEST_RESERVATION_HANDLES,
                RESERVED_PROCESS_HANDLES + (MIN_RETAINED_HANDLES * 2) - 1,
            ),
            Err(RealGitArtifactError::PathLimitExceeded)
        ));
        assert_eq!(TEST_RESERVATION_HANDLES.load(Ordering::Acquire), 0);

        let replay_soft_limit = RESERVED_PROCESS_HANDLES + (MIN_RETAINED_HANDLES * 4);
        {
            let mut original =
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit)
                    .expect("reserve original resolver");
            original
                .ensure(MIN_RETAINED_HANDLES * 2)
                .expect("grow original reservation");
            let mut replay =
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit)
                    .expect("reserve replay resolver");
            replay
                .ensure(MIN_RETAINED_HANDLES * 2)
                .expect("grow replay reservation");
            assert_eq!(
                TEST_RESERVATION_HANDLES.load(Ordering::Acquire),
                MIN_RETAINED_HANDLES * 4
            );
            assert!(
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit,)
                    .is_err()
            );
        }
        assert_eq!(TEST_RESERVATION_HANDLES.load(Ordering::Acquire), 0);

        {
            let mut first =
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit)
                    .expect("reserve first resolver");
            first
                .ensure(MIN_RETAINED_HANDLES * 2)
                .expect("grow first reservation");
            let mut second =
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit)
                    .expect("reserve second resolver");
            let _third =
                reserve_resolver_handles_with_limit(&TEST_RESERVATION_HANDLES, replay_soft_limit)
                    .expect("reserve third resolver");
            assert_eq!(
                second
                    .ensure(MIN_RETAINED_HANDLES * 2)
                    .expect_err("growth beyond process reservation must fail"),
                RealGitArtifactError::PathLimitExceeded
            );
            assert_eq!(
                TEST_RESERVATION_HANDLES.load(Ordering::Acquire),
                MIN_RETAINED_HANDLES * 4
            );
        }
        assert_eq!(TEST_RESERVATION_HANDLES.load(Ordering::Acquire), 0);

        let ready = std::sync::Arc::new(std::sync::Barrier::new(5));
        let release = std::sync::Arc::new(std::sync::Barrier::new(5));
        let workers = (0..4)
            .map(|_| {
                let ready = std::sync::Arc::clone(&ready);
                let release = std::sync::Arc::clone(&release);
                std::thread::spawn(move || {
                    let _reservation = reserve_resolver_handles_with_limit(
                        &TEST_RESERVATION_HANDLES,
                        replay_soft_limit,
                    )
                    .expect("reserve concurrent resolver");
                    ready.wait();
                    release.wait();
                })
            })
            .collect::<Vec<_>>();
        ready.wait();
        assert_eq!(
            TEST_RESERVATION_HANDLES.load(Ordering::Acquire),
            MIN_RETAINED_HANDLES * 4
        );
        release.wait();
        for worker in workers {
            worker.join().expect("join reservation worker");
        }
        assert_eq!(TEST_RESERVATION_HANDLES.load(Ordering::Acquire), 0);
    }

    #[test]
    fn resolves_direct_and_absolute_symbolic_link_candidates() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let link = directory.path().join("git");
        symlink(native_fixture_path(), &link).expect("create absolute link");

        let direct = DiscoveryInspection::inspect(&native_fixture_path(), &exclusions)
            .expect("inspect direct candidate");
        let linked =
            DiscoveryInspection::inspect(&link, &exclusions).expect("inspect linked candidate");
        assert_eq!(direct.candidate().identity(), linked.candidate().identity());
        assert_ne!(direct.chain_binding(), linked.chain_binding());
        linked.revalidate(&exclusions).expect("fresh linked chain");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inspection_revalidates_on_another_broker_thread() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let link = directory.path().join("threaded-git");
        symlink(native_fixture_path(), &link).expect("create threaded link");
        let inspection =
            DiscoveryInspection::inspect(&link, &exclusions).expect("inspect threaded link");
        std::thread::scope(|scope| {
            scope
                .spawn(move || inspection.revalidate(&exclusions))
                .join()
                .expect("join broker worker")
                .expect("revalidate on another broker thread");
        });
    }

    #[test]
    fn resolves_relative_intermediate_and_multihop_links() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let real = directory.path().join("real");
        let published = directory.path().join("published");
        fs::create_dir(&real).expect("create real directory");
        fs::create_dir(&published).expect("create published directory");
        fs::copy(native_fixture_path(), real.join("git")).expect("copy executable");
        symlink("../real", published.join("current")).expect("create directory link");
        symlink("../real/", published.join("current-slash"))
            .expect("create trailing-slash directory link");
        symlink("current/git", published.join("git-one")).expect("create first link");
        symlink("git-one", published.join("git-two")).expect("create second link");

        DiscoveryInspection::inspect(&published.join("git-two"), &exclusions)
            .expect("resolve relative multihop chain")
            .revalidate(&exclusions)
            .expect("revalidate relative multihop chain");
        DiscoveryInspection::inspect(&published.join("current-slash/git"), &exclusions)
            .expect("resolve an intermediate trailing-slash link target");
    }

    #[test]
    fn resolves_dot_parent_root_and_non_utf8_targets() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let name = OsString::from_vec(b"git-\xff".to_vec());
        #[cfg(target_os = "macos")]
        let name = OsString::from("git-unicode-\u{e9}");
        let executable = directory.path().join(&name);
        fs::copy(native_fixture_path(), &executable).expect("copy byte-path executable");

        let dot = directory.path().join("dot");
        symlink(".", &dot).expect("create dot link");
        DiscoveryInspection::inspect(&dot.join(&name), &exclusions).expect("resolve dot target");
        DiscoveryInspection::inspect(&dot.join("dot").join(&name), &exclusions)
            .expect("resolve a finite repeated visit to one symlink");

        let child = directory.path().join("child");
        fs::create_dir(&child).expect("create child directory");
        let mut parent_target = OsString::from("../");
        parent_target.push(&name);
        symlink(parent_target, child.join("git")).expect("create byte-path parent link");
        DiscoveryInspection::inspect(&child.join("git"), &exclusions)
            .expect("resolve parent and non-UTF-8 target");

        let root = directory.path().join("root");
        symlink("/", &root).expect("create root link");
        let fixture = native_fixture_path();
        let relative_fixture = fixture.strip_prefix("/").expect("absolute fixture");
        DiscoveryInspection::inspect(&root.join(relative_fixture), &exclusions)
            .expect("resolve absolute root target");
    }

    #[test]
    fn hard_linked_symbolic_links_keep_parent_specific_chain_bindings() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::create_dir(&first).expect("create first directory");
        fs::create_dir(&second).expect("create second directory");
        fs::copy(native_fixture_path(), first.join("git")).expect("copy first executable");
        fs::hard_link(first.join("git"), second.join("git")).expect("link second executable");
        symlink("git", first.join("link")).expect("create first symbolic link");
        fs::hard_link(first.join("link"), second.join("link"))
            .expect("hard-link symbolic link inode");

        let first = DiscoveryInspection::inspect(&first.join("link"), &exclusions)
            .expect("resolve first hard-linked symlink");
        let second = DiscoveryInspection::inspect(&second.join("link"), &exclusions)
            .expect("resolve second hard-linked symlink");
        assert_eq!(first.candidate().identity(), second.candidate().identity());
        assert_ne!(first.chain_binding(), second.chain_binding());
    }

    #[test]
    fn rejects_trailing_slashes_and_excessive_link_hops() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let target = directory.path().join("target");
        fs::copy(native_fixture_path(), &target).expect("copy target");
        let trailing = PathBuf::from(format!("{}/", target.display()));
        assert_eq!(
            DiscoveryInspection::inspect(&trailing, &exclusions)
                .expect_err("trailing slash must require a directory"),
            RealGitArtifactError::NotExecutable
        );

        for index in 0..=MAX_SYMLINK_HOPS {
            let link = directory.path().join(format!("link-{index}"));
            let destination = if index == MAX_SYMLINK_HOPS {
                OsString::from("target")
            } else {
                OsString::from(format!("link-{}", index + 1))
            };
            symlink(destination, link).expect("create bounded link chain");
        }
        assert_eq!(
            DiscoveryInspection::inspect(&directory.path().join("link-0"), &exclusions)
                .expect_err("excessive link chain must fail"),
            RealGitArtifactError::PathLimitExceeded
        );
    }

    #[test]
    fn rejects_a_symbolic_link_escape_from_an_owned_root() {
        let owned = temporary_directory();
        let link = owned.path().join("git");
        symlink(native_fixture_path(), &link).expect("create owned-root escape link");
        let exclusions =
            ExecutableExclusionSet::new(owned.path(), 8).expect("create owned-root exclusions");
        assert_eq!(
            DiscoveryInspection::inspect(&link, &exclusions)
                .expect_err("owned source ancestor must remain excluded"),
            RealGitArtifactError::OwnedRoot
        );
    }

    #[test]
    fn rejects_other_user_owned_ancestors_even_when_mode_is_read_only() {
        // SAFETY: `geteuid` has no preconditions.
        let effective_user = unsafe { libc::geteuid() };
        let parent = synthetic_snapshot(
            u64::from(libc::S_IFDIR) | 0o555,
            effective_user.wrapping_add(1),
        );
        let entry = synthetic_snapshot(u64::from(libc::S_IFREG) | 0o755, effective_user);
        assert_eq!(
            require_trusted_entry_open(parent, entry)
                .expect_err("another owner can chmod and replace entries"),
            RealGitArtifactError::UnsafePath
        );

        let executable = File::open(native_fixture_path()).expect("open native fixture");
        let artifact = synthetic_snapshot(
            u64::from(libc::S_IFREG) | 0o555,
            effective_user.wrapping_add(1),
        );
        assert_eq!(
            require_trusted_executable(&executable, artifact)
                .expect_err("another owner can mutate the retained artifact"),
            RealGitArtifactError::UnsafePath
        );
    }

    #[test]
    fn retained_link_survives_unlink_but_namespace_revalidation_fails() {
        let directory = temporary_directory();
        let link = directory.path().join("git");
        let target = native_fixture_path();
        symlink(&target, &link).expect("create link");
        let resolved = resolve(&link).expect("resolve retained link");
        let retained = resolved
            .chain
            .bindings
            .iter()
            .find(|binding| matches!(binding.kind, UnixBindingKind::SymbolicLink { .. }))
            .expect("symlink binding");
        fs::remove_file(&link).expect("unlink published link");
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(
            read_retained_link(&retained.entry).expect("read unlinked retained symlink"),
            target.as_os_str().as_bytes()
        );
        #[cfg(target_os = "macos")]
        assert!(
            read_retained_link(&retained.entry).is_err(),
            "macOS invalidates freadlink after unlinking an O_SYMLINK vnode"
        );
        assert_eq!(
            resolved
                .chain
                .revalidate(&resolved.final_key)
                .expect_err("unlinked namespace must be stale"),
            RealGitArtifactError::DiscoveryChainStale
        );
    }

    #[test]
    fn rejects_normal_and_link_replacement_at_open_barriers() {
        let (_owned, exclusions) = exclusions();
        for barrier in [
            ResolverTestStage::EntryObserved,
            ResolverTestStage::NormalOpened,
        ] {
            let directory = temporary_directory();
            let candidate = directory.path().join("barrier-candidate");
            let old_candidate = directory.path().join("barrier-candidate-old");
            fs::copy(native_fixture_path(), &candidate).expect("copy barrier candidate");
            let candidate_for_hook = candidate.clone();
            let old_for_hook = old_candidate.clone();
            let fixture_for_hook = native_fixture_path();
            let mut changed = false;
            let hook = install_test_hook(move |stage, name| {
                if !changed && stage == barrier && name.as_bytes() == b"barrier-candidate" {
                    fs::rename(&candidate_for_hook, &old_for_hook).expect("move opened candidate");
                    fs::copy(&fixture_for_hook, &candidate_for_hook).expect("replace candidate");
                    changed = true;
                }
            });
            assert_eq!(
                DiscoveryInspection::inspect(&candidate, &exclusions)
                    .expect_err("normal replacement barrier must fail"),
                RealGitArtifactError::DiscoveryChainStale
            );
            drop(hook);
        }

        for barrier in [
            ResolverTestStage::EntryObserved,
            ResolverTestStage::LinkOpened,
            ResolverTestStage::LinkRead,
            ResolverTestStage::BeforeReplay,
        ] {
            let directory = temporary_directory();
            let link = directory.path().join("barrier-link");
            let old_link = directory.path().join("barrier-link-old");
            let target = native_fixture_path();
            symlink(&target, &link).expect("create barrier link");
            let link_for_hook = link.clone();
            let old_for_hook = old_link.clone();
            let target_for_hook = target.clone();
            let mut changed = false;
            let hook = install_test_hook(move |stage, name| {
                let at_target =
                    stage == ResolverTestStage::BeforeReplay || name.as_bytes() == b"barrier-link";
                if !changed && stage == barrier && at_target {
                    fs::rename(&link_for_hook, &old_for_hook).expect("move opened link");
                    symlink(&target_for_hook, &link_for_hook).expect("replace link");
                    changed = true;
                }
            });
            assert_eq!(
                DiscoveryInspection::inspect(&link, &exclusions)
                    .expect_err("link replacement barrier must fail"),
                RealGitArtifactError::DiscoveryChainStale
            );
            drop(hook);
        }
    }

    #[test]
    fn rejects_chain_change_immediately_before_artifact_inspection() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let link = directory.path().join("inspection-barrier-link");
        symlink(native_fixture_path(), &link).expect("create inspection barrier link");
        let link_for_hook = link.clone();
        let mut changed = false;
        let hook = install_test_hook(move |stage, _name| {
            if !changed && stage == ResolverTestStage::BeforeInspection {
                fs::remove_file(&link_for_hook).expect("remove verified link");
                symlink(native_fixture_path(), &link_for_hook).expect("replace verified link");
                changed = true;
            }
        });
        assert_eq!(
            DiscoveryInspection::inspect(&link, &exclusions)
                .expect_err("pre-inspection chain change must fail"),
            RealGitArtifactError::DiscoveryChainStale
        );
        drop(hook);
    }

    #[test]
    fn rejects_artifact_mutation_immediately_after_inspection() {
        use std::{io::Write, os::unix::fs::PermissionsExt};

        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();

        let mode_candidate = directory.path().join("mode-candidate");
        fs::copy(native_fixture_path(), &mode_candidate).expect("copy mode candidate");
        let mode_for_hook = mode_candidate.clone();
        let mut changed = false;
        let hook = install_test_hook(move |stage, _name| {
            if !changed && stage == ResolverTestStage::AfterInspection {
                fs::set_permissions(&mode_for_hook, fs::Permissions::from_mode(0o777))
                    .expect("make inspected artifact writable");
                changed = true;
            }
        });
        assert_eq!(
            DiscoveryInspection::inspect(&mode_candidate, &exclusions)
                .expect_err("post-inspection mode mutation must fail"),
            RealGitArtifactError::DiscoveryChainStale
        );
        drop(hook);

        let content_candidate = directory.path().join("content-candidate");
        fs::copy(native_fixture_path(), &content_candidate).expect("copy content candidate");
        fs::set_permissions(&content_candidate, fs::Permissions::from_mode(0o755))
            .expect("make content candidate owner-writable");
        let content_for_hook = content_candidate.clone();
        let mut changed = false;
        let hook = install_test_hook(move |stage, _name| {
            if !changed && stage == ResolverTestStage::AfterInspection {
                let mut artifact = fs::OpenOptions::new()
                    .append(true)
                    .open(&content_for_hook)
                    .expect("open inspected artifact for mutation");
                artifact
                    .write_all(b"stale")
                    .expect("mutate inspected artifact");
                changed = true;
            }
        });
        assert_eq!(
            DiscoveryInspection::inspect(&content_candidate, &exclusions)
                .expect_err("post-inspection content mutation must fail"),
            RealGitArtifactError::DiscoveryChainStale
        );
        drop(hook);
    }

    #[test]
    fn rejects_symbolic_link_cycles() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        symlink("second", &first).expect("create first link");
        symlink("first", &second).expect("create second link");
        assert_eq!(
            DiscoveryInspection::inspect(&first, &exclusions).expect_err("cycle must fail"),
            RealGitArtifactError::SymbolicLinkLoop
        );
    }

    #[test]
    fn rejects_dangling_and_empty_link_targets() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let dangling = directory.path().join("dangling");
        symlink("missing", &dangling).expect("create dangling link");
        assert!(DiscoveryInspection::inspect(&dangling, &exclusions).is_err());
    }

    #[test]
    fn detects_replaced_namespace_while_retaining_the_original_artifact() {
        let (_owned, exclusions) = exclusions();
        let directory = temporary_directory();
        let candidate = directory.path().join("candidate");
        let moved = directory.path().join("candidate-old");
        fs::copy(native_fixture_path(), &candidate).expect("copy executable");
        let inspection =
            DiscoveryInspection::inspect(&candidate, &exclusions).expect("inspect candidate");
        fs::rename(&candidate, &moved).expect("move original");
        fs::copy(native_fixture_path(), &candidate).expect("replace candidate");
        assert_eq!(
            inspection
                .revalidate(&exclusions)
                .expect_err("replacement must stale the chain"),
            RealGitArtifactError::DiscoveryChainStale
        );
        inspection
            .candidate()
            .reinspect_retained()
            .expect("original lease remains exact");
    }

    #[test]
    fn detects_equivalent_symlink_retarget_and_ancestor_recreation() {
        let (_owned, exclusions) = exclusions();
        let container = temporary_directory();
        let visible = container.path().join("visible");
        let moved = container.path().join("visible-old");
        fs::create_dir(&visible).expect("create visible directory");
        let link = visible.join("git");
        symlink(native_fixture_path(), &link).expect("create published link");
        let linked = DiscoveryInspection::inspect(&link, &exclusions).expect("inspect link");
        fs::remove_file(&link).expect("remove original link");
        symlink(native_fixture_path(), &link).expect("replace equivalent link");
        assert_eq!(
            linked
                .revalidate(&exclusions)
                .expect_err("new symlink inode must stale the chain"),
            RealGitArtifactError::DiscoveryChainStale
        );

        let direct = visible.join("direct");
        fs::copy(native_fixture_path(), &direct).expect("copy direct candidate");
        let inspected = DiscoveryInspection::inspect(&direct, &exclusions).expect("inspect direct");
        fs::rename(&visible, &moved).expect("rename original ancestor");
        fs::create_dir(&visible).expect("recreate visible ancestor");
        fs::copy(native_fixture_path(), visible.join("direct")).expect("replace direct candidate");
        assert_eq!(
            inspected
                .revalidate(&exclusions)
                .expect_err("ancestor recreation must stale the chain"),
            RealGitArtifactError::DiscoveryChainStale
        );
    }

    #[test]
    fn sealed_entry_preserves_self_and_owned_artifact_exclusions() {
        let (_owned, mut exclusions) = exclusions();
        let directory = temporary_directory();
        let artifact = directory.path().join("owned");
        let artifact_link = directory.path().join("owned-link");
        fs::copy(native_fixture_path(), &artifact).expect("copy owned artifact");
        exclusions
            .add_owned_artifact(&artifact)
            .expect("exclude artifact");
        symlink(&artifact, &artifact_link).expect("link owned artifact");
        assert_eq!(
            DiscoveryInspection::inspect(&artifact_link, &exclusions)
                .expect_err("linked owned artifact must fail"),
            RealGitArtifactError::OwnedArtifact
        );

        let current_executable = std::env::current_exe().expect("current executable");
        let self_directory = tempfile::Builder::new()
            .tempdir_in(
                current_executable
                    .parent()
                    .expect("current executable parent"),
            )
            .expect("create same-filesystem self fixture");
        let self_alias = self_directory.path().join("self-alias");
        fs::hard_link(&current_executable, &self_alias).expect("publish running image hardlink");
        let self_link = directory.path().join("self-link");
        symlink(&self_alias, &self_link).expect("link running image alias");
        let error = DiscoveryInspection::inspect(&self_link, &exclusions)
            .expect_err("linked running image must fail");
        assert!(
            matches!(
                error,
                RealGitArtifactError::SelfReference
                    | RealGitArtifactError::SymbolicLinkPolicyDenied
                    | RealGitArtifactError::UnsafePath
            ),
            "running image must fail by self identity or an earlier trust policy: {error:?}"
        );
    }

    #[test]
    fn sealed_entry_revalidates_exclusions_and_artifact_policy() {
        use std::os::unix::fs::PermissionsExt;

        let (_owned, mut exclusions) = exclusions();
        let directory = temporary_directory();
        let candidate = directory.path().join("candidate");
        fs::copy(native_fixture_path(), &candidate).expect("copy candidate");
        let inspection =
            DiscoveryInspection::inspect(&candidate, &exclusions).expect("inspect candidate");
        let newly_owned = directory.path().join("new-owned");
        fs::copy(native_fixture_path(), &newly_owned).expect("copy new owned artifact");
        exclusions
            .add_owned_artifact(&newly_owned)
            .expect("extend exclusions");
        assert_eq!(
            inspection
                .revalidate(&exclusions)
                .expect_err("changed exclusion snapshot must fail"),
            RealGitArtifactError::ExclusionSnapshotStale
        );

        let writable = directory.path().join("writable");
        let writable_link = directory.path().join("writable-link");
        fs::copy(native_fixture_path(), &writable).expect("copy writable candidate");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("make candidate writable");
        symlink(&writable, &writable_link).expect("link writable candidate");
        assert_eq!(
            DiscoveryInspection::inspect(&writable_link, &exclusions)
                .expect_err("writable artifact must fail"),
            RealGitArtifactError::NotExecutable
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_linux_proc_magic_links() {
        use std::os::fd::AsRawFd;

        let (_owned, exclusions) = exclusions();
        let fixture = File::open(native_fixture_path()).expect("open native fixture");
        assert_eq!(
            require_linux_procfs(&fixture).expect_err("regular file cannot attest credentials"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
        let status = File::open("/proc/thread-self/status").expect("open thread status");
        require_linux_procfs(&status).expect("thread status is procfs-backed");
        let bound_status =
            "Pid:\t7\nTgid:\t8\nUid:\t1\t1\t1\t1\nGid:\t2\t2\t2\t2\nCapEff:\t0000000000000000\n";
        validate_linux_status(bound_status, 7, 8, [1; 4], [2; 4])
            .expect("accept exact caller-bound status");
        assert_eq!(
            validate_linux_status(bound_status, 9, 8, [1; 4], [2; 4])
                .expect_err("another thread status must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
        assert_eq!(
            validate_linux_status(bound_status, 7, 8, [1, 1, 1, 3], [2; 4])
                .expect_err("different fsuid must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
        assert_eq!(
            validate_linux_status(bound_status, 7, 8, [1, 1, 0, 1], [2; 4])
                .expect_err("different saved UID must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
        let magic = PathBuf::from(format!("/proc/self/fd/{}", fixture.as_raw_fd()));
        assert_eq!(
            DiscoveryInspection::inspect(&magic, &exclusions)
                .expect_err("proc magic link must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_macos_extended_acl_and_mount_policy_flags() {
        let directory = temporary_directory();
        set_macos_nontrivial_acl(directory.path());
        let opened = File::open(directory.path()).expect("open macOS ACL directory fixture");
        let snapshot = NativeFileSnapshot::capture(&opened).expect("capture macOS ACL directory");
        assert_eq!(
            require_trusted_directory(&opened, snapshot)
                .expect_err("macOS directory ACL must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );

        let artifact_path = directory.path().join("git");
        fs::copy(native_fixture_path(), &artifact_path).expect("copy macOS ACL artifact fixture");
        set_macos_nontrivial_acl(&artifact_path);
        let artifact = File::open(&artifact_path).expect("open macOS ACL artifact fixture");
        let artifact_snapshot =
            NativeFileSnapshot::capture(&artifact).expect("capture macOS ACL artifact");
        assert_eq!(
            require_trusted_executable(&artifact, artifact_snapshot)
                .expect_err("macOS artifact ACL must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );

        let local = u32::try_from(libc::MNT_LOCAL).expect("macOS local flag fits u32");
        let no_execute = u32::try_from(libc::MNT_NOEXEC).expect("macOS noexec flag fits u32");
        assert!(!macos_filesystem_policy(0).local);
        let noexec_policy = macos_filesystem_policy(local | no_execute);
        assert!(noexec_policy.local);
        assert!(noexec_policy.no_execute);
    }

    #[cfg(target_os = "macos")]
    fn set_macos_nontrivial_acl(path: &Path) {
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow write"])
            .arg(path)
            .status()
            .expect("run macOS chmod ACL fixture");
        assert!(status.success(), "install macOS ACL: {status}");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn rejects_freebsd_nontrivial_acl_and_mount_policy_flags() {
        assert_eq!(freebsd_acl_types(0, 0).expect("no ACL model"), [None, None]);
        assert_eq!(
            freebsd_acl_types(1, 1).expect("NFSv4 takes precedence"),
            [Some(ACL_TYPE_NFS4), None]
        );
        assert_eq!(
            freebsd_acl_types(0, 1).expect("POSIX ACL model"),
            [Some(ACL_TYPE_ACCESS), None]
        );
        assert_eq!(
            freebsd_acl_types(-1, 0).expect_err("ACL query failure must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );

        let directory = temporary_directory();
        let opened = File::open(directory.path()).expect("open ACL fixture directory");
        set_freebsd_nontrivial_acl(directory.path(), &opened, true);
        let snapshot = NativeFileSnapshot::capture(&opened).expect("capture ACL fixture");
        assert_eq!(
            require_trusted_directory(&opened, snapshot)
                .expect_err("nontrivial directory ACL must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );

        let candidate_path = directory.path().join("git");
        fs::copy(native_fixture_path(), &candidate_path).expect("copy ACL artifact fixture");
        let candidate = File::open(&candidate_path).expect("open ACL artifact fixture");
        set_freebsd_nontrivial_acl(&candidate_path, &candidate, false);
        let candidate_snapshot =
            NativeFileSnapshot::capture(&candidate).expect("capture ACL artifact fixture");
        assert_eq!(
            require_trusted_executable(&candidate, candidate_snapshot)
                .expect_err("nontrivial artifact ACL must fail"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );

        let local = libc::MNT_LOCAL;
        let no_execute = u64::try_from(libc::MNT_NOEXEC).expect("FreeBSD noexec flag fits u64");
        assert!(!freebsd_filesystem_policy(0).local);
        let noexec_policy = freebsd_filesystem_policy(local | no_execute);
        assert!(noexec_policy.local);
        assert!(noexec_policy.no_execute);
        assert!(freebsd_nosymfollow(
            local
                | u64::try_from(libc::MNT_NOSYMFOLLOW).expect("FreeBSD nosymfollow flag fits u64")
        ));
    }

    #[cfg(target_os = "freebsd")]
    fn set_freebsd_nontrivial_acl(path: &Path, opened: &File, directory: bool) {
        // SAFETY: the descriptor is live and both selectors are defined by
        // FreeBSD for ACL-brand discovery.
        let (nfs4, extended) = unsafe {
            (
                libc::fpathconf(opened.as_raw_fd(), libc::_PC_ACL_NFS4),
                libc::fpathconf(opened.as_raw_fd(), libc::_PC_ACL_EXTENDED),
            )
        };
        assert!(nfs4 >= 0 && extended >= 0, "query FreeBSD ACL brand");
        let entry = if nfs4 > 0 {
            if directory {
                "user:65534:rx::allow"
            } else {
                "user:65534:rw::allow"
            }
        } else {
            assert!(extended > 0, "fixture filesystem must support ACLs");
            "user:65534:r-x"
        };
        let status = std::process::Command::new("setfacl")
            .args(["-m", entry])
            .arg(path)
            .status()
            .expect("run FreeBSD setfacl");
        assert!(status.success(), "install FreeBSD ACL: {status}");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn rejects_freebsd_capsicum_mode_in_a_child_process() {
        const CHILD_ENV: &str = "GUS_TEST_FREEBSD_CAPSICUM_CHILD";
        let status = std::process::Command::new(
            std::env::current_exe().expect("locate FreeBSD test executable"),
        )
        .arg("--exact")
        .arg("real_git::resolver_unix::tests::freebsd_capsicum_child")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .status()
        .expect("run Capsicum child fixture");
        assert!(status.success(), "Capsicum child fixture failed: {status}");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn freebsd_capsicum_child() {
        const CHILD_ENV: &str = "GUS_TEST_FREEBSD_CAPSICUM_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        // SAFETY: entering capability mode has no pointer preconditions. The
        // irreversible transition is isolated in this short-lived child.
        assert_eq!(unsafe { libc::cap_enter() }, 0, "enter Capsicum mode");
        assert_eq!(
            unprivileged_credential_snapshot()
                .expect_err("Capsicum resolver credentials must fail closed"),
            RealGitArtifactError::SymbolicLinkPolicyDenied
        );
    }

    fn synthetic_snapshot(mode: u64, owner: u32) -> NativeFileSnapshot {
        NativeFileSnapshot {
            device: 1,
            inode: 2,
            mode,
            owner,
            group: 3,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        }
    }

    fn exclusions() -> (tempfile::TempDir, ExecutableExclusionSet) {
        let owned = temporary_directory();
        let exclusions =
            ExecutableExclusionSet::new(owned.path(), 7).expect("create exclusion fixture");
        (owned, exclusions)
    }

    #[cfg(target_os = "macos")]
    fn temporary_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .tempdir_in("/private/tmp")
            .expect("create macOS temporary directory")
    }

    #[cfg(not(target_os = "macos"))]
    fn temporary_directory() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temporary directory")
    }

    #[cfg(target_os = "linux")]
    fn native_fixture_path() -> PathBuf {
        PathBuf::from("/usr/bin/echo")
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn native_fixture_path() -> PathBuf {
        PathBuf::from("/bin/echo")
    }
}
