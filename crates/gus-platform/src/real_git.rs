use std::{
    fmt,
    fs::File,
    io,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
mod resolver_unix;

#[cfg(unix)]
use std::ffi::{CString, OsString};
#[cfg(any(target_os = "linux", windows))]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::mem::size_of;

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(windows)]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileExt, MetadataExt},
    io::{AsRawFd, FromRawFd},
};
#[cfg(windows)]
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    fs::OpenOptionsExt,
    fs::{FileExt, MetadataExt},
    io::{AsRawHandle, FromRawHandle},
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO,
    FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_TYPE_DISK, FileIdInfo, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW, ReOpenFile,
    VOLUME_NAME_GUID,
};
#[cfg(windows)]
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_PATH_COMPONENTS: usize = 1024;
const INSPECTION_BUFFER_BYTES: usize = 16 * 1024;
const NATIVE_HEADER_BYTES: usize = 4096;
const MAX_GUS_OWNED_PATHS: usize = 32;
#[cfg(target_os = "macos")]
const MAX_LOAD_COMMAND_BYTES: usize = 16 * 1024 * 1024;

#[cfg(target_os = "macos")]
const fn normalize_macos_device(device: u64) -> u64 {
    device & 0xffff_ffff_u64
}

/// Stable identity of one inspected executable artifact.
///
/// The digest includes native file identity, metadata, and the complete
/// content digest. It is intentionally opaque so callers cannot treat a path
/// string as equivalent launch authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutableIdentity([u8; 32]);

/// Opaque binding to one GUS ownership-manifest exclusion snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExclusionSnapshotId([u8; 32]);

/// Opaque diagnostic binding to the path observed for an artifact.
///
/// This is deliberately separate from `ExecutableIdentity`, because one file
/// may have several hard-link paths.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutablePathBinding([u8; 32]);

/// Opaque binding to the complete discovery path and symbolic-link chain.
///
/// This is deliberately separate from both artifact identity and the final
/// diagnostic path. Two discovery paths that reach the same inode therefore
/// retain distinct evidence.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiscoveryChainBinding([u8; 32]);

/// Kernel-backed identity of the executable containing this inspector.
///
/// Unix obtains the identity from the live process mapping. Windows cannot
/// recover a race-free file identity from a loaded image, so its evidence must
/// retain the exact worker image handle supplied by a trusted stage-zero
/// launcher before process creation.
pub struct CurrentExecutableEvidence {
    key: NativeFileKey,
    #[cfg(windows)]
    lease: File,
}

/// Opaque worker-image lease issued by the authenticated Windows stage-zero
/// bootstrap.
///
/// This type has no public constructor. A raw inherited handle, command-line
/// value, or environment variable is not sufficient to create it; the future
/// Windows launcher/bootstrap implementation in this crate must issue it only
/// after authenticating the parent and restricted handle transfer.
#[cfg(windows)]
pub struct TrustedPrelaunchExecutableLease {
    lease: File,
}

impl fmt::Debug for ExclusionSnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExclusionSnapshotId([REDACTED])")
    }
}

impl fmt::Debug for ExecutablePathBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutablePathBinding([REDACTED])")
    }
}

impl fmt::Debug for CurrentExecutableEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentExecutableEvidence([REDACTED])")
    }
}

#[cfg(windows)]
impl fmt::Debug for TrustedPrelaunchExecutableLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedPrelaunchExecutableLease([REDACTED])")
    }
}

impl CurrentExecutableEvidence {
    /// Captures the current executable from the live kernel mapping.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed inspection error if the mapping cannot be
    /// identified as one regular native file.
    #[cfg(unix)]
    pub fn capture() -> Result<Self, RealGitArtifactError> {
        Ok(Self {
            key: current_image_key()?,
        })
    }

    /// Converts a trusted pre-launch Windows image lease into current-image
    /// evidence.
    ///
    /// The opaque lease can only be issued after the trusted stage-zero
    /// launcher opened the exact stage-one worker image *before* creating this
    /// process and authenticated its restricted inherited-handle transfer.
    /// This function reopens that same file object with read-only sharing and
    /// retains the restrictive lease.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed inspection error if the handle is not a regular,
    /// non-reparse disk file or cannot be pinned with read-only sharing.
    #[cfg(windows)]
    pub fn from_trusted_prelaunch_lease(
        trusted_lease: TrustedPrelaunchExecutableLease,
    ) -> Result<Self, RealGitArtifactError> {
        let lease = trusted_lease.lease;
        let initial_key = windows_file_key(&lease)?;
        let metadata = lease.metadata().map_err(io_error)?;
        if metadata.file_attributes()
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        {
            return Err(RealGitArtifactError::UnsafePath);
        }
        let restrictive_lease = reopen_windows_read_lease(&lease)?;
        if windows_file_key(&restrictive_lease)? != initial_key {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        drop(lease);
        Ok(Self {
            key: initial_key,
            lease: restrictive_lease,
        })
    }

    #[cfg(windows)]
    fn validate(&self) -> Result<(), RealGitArtifactError> {
        if windows_file_key(&self.lease)? == self.key {
            Ok(())
        } else {
            Err(RealGitArtifactError::ExclusionSnapshotStale)
        }
    }
}

impl ExecutableIdentity {
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutableIdentity([REDACTED])")
    }
}

/// An open, inspected native executable candidate.
///
/// This is deliberately not proof that the file is Git, has trusted
/// provenance, or may be launched. A trusted resolver must separately verify
/// package/vendor/operator evidence, the Git build, GUS-owned exclusions, and
/// an OS-specific launch lease before creating execution authority.
pub struct ExecutableCandidate {
    inspected_path: PathBuf,
    lease: File,
    snapshot: NativeFileSnapshot,
    content_digest: [u8; 32],
    identity: ExecutableIdentity,
    path_binding: ExecutablePathBinding,
    exclusion_snapshot: ExclusionSnapshotId,
    manifest_generation: u64,
}

/// An inspected executable together with every lease needed to revalidate its
/// Unix discovery chain.
///
/// The type has no public constructor, is not cloneable, and exposes neither
/// raw descriptors nor launch authority. Future execution code must consume a
/// higher-level authority derived from this value after provenance and Git
/// probes have also succeeded.
#[cfg(unix)]
pub struct DiscoveryInspection {
    candidate: ExecutableCandidate,
    chain: resolver_unix::UnixResolutionLeaseSet,
}

/// GUS-owned filesystem objects that may never be selected as real Git.
///
/// Construction always records the currently running image and requires one
/// existing primary GUS-owned directory. Installers must add every additional
/// release, staging, rollback, shim, and launcher location before discovery.
pub struct ExecutableExclusionSet {
    current_image: CurrentExecutableEvidence,
    owned_roots: Vec<OwnedPath>,
    owned_artifacts: Vec<OwnedPath>,
    manifest_generation: u64,
}

struct OwnedPath {
    reopen_path: PathBuf,
    lease: File,
    snapshot: NativeFileSnapshot,
    kind: ExpectedFileKind,
}

impl OwnedPath {
    fn inspect(path: &Path, kind: ExpectedFileKind) -> Result<Self, RealGitArtifactError> {
        let opened = open_path_safely(path, kind)?;
        let snapshot = NativeFileSnapshot::capture(&opened.lease)?;
        Ok(Self {
            reopen_path: path.to_path_buf(),
            lease: opened.lease,
            snapshot,
            kind,
        })
    }

    fn validate(&self) -> Result<(), RealGitArtifactError> {
        let retained = NativeFileSnapshot::capture(&self.lease)
            .map_err(|_| RealGitArtifactError::ExclusionSnapshotStale)?;
        let retained_matches = match self.kind {
            ExpectedFileKind::Directory => retained.same_owned_directory(&self.snapshot),
            ExpectedFileKind::RegularFile => retained.same_retained_artifact(&self.snapshot),
        };
        if !retained_matches {
            return Err(RealGitArtifactError::ExclusionSnapshotStale);
        }
        let reopened = open_path_safely(&self.reopen_path, self.kind)
            .map_err(|_| RealGitArtifactError::ExclusionSnapshotStale)?;
        let reopened = NativeFileSnapshot::capture(&reopened.lease)
            .map_err(|_| RealGitArtifactError::ExclusionSnapshotStale)?;
        if self.snapshot.same_file(&reopened) {
            Ok(())
        } else {
            Err(RealGitArtifactError::ExclusionSnapshotStale)
        }
    }
}

impl fmt::Debug for ExecutableExclusionSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutableExclusionSet([REDACTED])")
    }
}

impl ExecutableExclusionSet {
    /// Creates exclusions for the current image, an ownership-manifest
    /// generation, and a primary GUS-owned root.
    ///
    /// On Windows this convenience constructor fails closed because a worker
    /// cannot derive race-free current-image identity after it starts. The
    /// stage-zero launcher must instead call [`Self::new_with_current_image`]
    /// with `CurrentExecutableEvidence::from_trusted_prelaunch_lease`.
    ///
    /// # Errors
    ///
    /// Returns an error if the image or root cannot be inspected without
    /// following a symbolic link, reparse point, or remote Windows volume.
    pub fn new(
        primary_owned_root: &Path,
        manifest_generation: u64,
    ) -> Result<Self, RealGitArtifactError> {
        #[cfg(unix)]
        {
            Self::new_with_current_image(
                primary_owned_root,
                manifest_generation,
                CurrentExecutableEvidence::capture()?,
            )
        }
        #[cfg(windows)]
        {
            let _ = (primary_owned_root, manifest_generation);
            Err(RealGitArtifactError::CurrentImageEvidenceRequired)
        }
    }

    /// Creates exclusions using explicit kernel-backed current-image evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if the owned root cannot be inspected without
    /// following a symbolic link, reparse point, or remote Windows volume.
    pub fn new_with_current_image(
        primary_owned_root: &Path,
        manifest_generation: u64,
        current_image: CurrentExecutableEvidence,
    ) -> Result<Self, RealGitArtifactError> {
        let owned_root = OwnedPath::inspect(primary_owned_root, ExpectedFileKind::Directory)?;
        Ok(Self {
            current_image,
            owned_roots: vec![owned_root],
            owned_artifacts: Vec::new(),
            manifest_generation,
        })
    }

    /// Adds another existing GUS-owned directory tree.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be inspected safely or is not a
    /// directory.
    pub fn add_owned_root(&mut self, path: &Path) -> Result<(), RealGitArtifactError> {
        if self
            .owned_roots
            .len()
            .saturating_add(self.owned_artifacts.len())
            >= MAX_GUS_OWNED_PATHS
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        self.owned_roots
            .push(OwnedPath::inspect(path, ExpectedFileKind::Directory)?);
        Ok(())
    }

    /// Adds one existing GUS-owned file, including hard-link aliases.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be inspected safely or is not a
    /// regular file.
    pub fn add_owned_artifact(&mut self, path: &Path) -> Result<(), RealGitArtifactError> {
        if self
            .owned_roots
            .len()
            .saturating_add(self.owned_artifacts.len())
            >= MAX_GUS_OWNED_PATHS
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
        self.owned_artifacts
            .push(OwnedPath::inspect(path, ExpectedFileKind::RegularFile)?);
        Ok(())
    }

    /// Returns the ownership-manifest generation represented by this set.
    #[must_use]
    pub const fn manifest_generation(&self) -> u64 {
        self.manifest_generation
    }

    /// Returns an opaque ID binding all current exclusion observations.
    ///
    /// # Errors
    ///
    /// Returns [`RealGitArtifactError::ExclusionSnapshotStale`] when an owned
    /// root or artifact no longer matches the retained observation.
    pub fn snapshot_id(&self) -> Result<ExclusionSnapshotId, RealGitArtifactError> {
        self.validate()?;
        Ok(self.calculate_snapshot_id())
    }

    fn validate(&self) -> Result<(), RealGitArtifactError> {
        #[cfg(windows)]
        self.current_image
            .validate()
            .map_err(|_| RealGitArtifactError::ExclusionSnapshotStale)?;
        for entry in self.owned_roots.iter().chain(&self.owned_artifacts) {
            entry.validate()?;
        }
        Ok(())
    }

    fn reject_candidate(
        &self,
        candidate: &NativeFileSnapshot,
        ancestors: &[NativeFileSnapshot],
    ) -> Result<(), RealGitArtifactError> {
        if candidate.file_key() == self.current_image.key {
            return Err(RealGitArtifactError::SelfReference);
        }
        if self
            .owned_artifacts
            .iter()
            .any(|artifact| candidate.same_file(&artifact.snapshot))
        {
            return Err(RealGitArtifactError::OwnedArtifact);
        }
        if self.owned_roots.iter().any(|root| {
            candidate.same_file(&root.snapshot)
                || ancestors
                    .iter()
                    .any(|ancestor| ancestor.same_file(&root.snapshot))
        }) {
            return Err(RealGitArtifactError::OwnedRoot);
        }
        Ok(())
    }

    fn calculate_snapshot_id(&self) -> ExclusionSnapshotId {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.executable-exclusions.v1\0");
        digest.update(self.manifest_generation.to_le_bytes());
        self.current_image.key.update_digest(&mut digest);
        for root in &self.owned_roots {
            digest.update(root.snapshot.identity_digest([0; 32]));
        }
        for artifact in &self.owned_artifacts {
            digest.update(artifact.snapshot.identity_digest([0; 32]));
        }
        ExclusionSnapshotId(digest.finalize().into())
    }
}

impl fmt::Debug for ExecutableCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutableCandidate([REDACTED])")
    }
}

#[cfg(unix)]
impl fmt::Debug for DiscoveryChainBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscoveryChainBinding([REDACTED])")
    }
}

#[cfg(unix)]
impl fmt::Debug for DiscoveryInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscoveryInspection([REDACTED])")
    }
}

#[cfg(unix)]
impl DiscoveryInspection {
    /// Resolves and inspects an absolute Unix discovery path without invoking
    /// it or reopening its final file by pathname.
    ///
    /// Symbolic links are resolved component by component with retained
    /// directory and link leases. The original namespace is replayed before
    /// and after artifact inspection; a changed binding fails closed.
    ///
    /// # Errors
    ///
    /// Returns a bounded, fail-closed discovery or artifact-inspection error.
    pub fn inspect(
        path: &Path,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<Self, RealGitArtifactError> {
        let resolved = resolver_unix::resolve(path)?;
        resolved.chain.revalidate(&resolved.final_key)?;
        #[cfg(test)]
        resolver_unix::run_test_barrier(
            resolver_unix::ResolverTestStage::BeforeInspection,
            path.as_os_str(),
        );
        let candidate = ExecutableCandidate::inspect_opened(resolved.opened, exclusions)?;
        #[cfg(test)]
        resolver_unix::run_test_barrier(
            resolver_unix::ResolverTestStage::AfterInspection,
            path.as_os_str(),
        );
        resolved.chain.revalidate(&candidate.snapshot.file_key())?;
        Ok(Self {
            candidate,
            chain: resolved.chain,
        })
    }

    /// Returns the inspection-only artifact evidence.
    #[must_use]
    pub const fn candidate(&self) -> &ExecutableCandidate {
        &self.candidate
    }

    /// Returns the opaque binding to the complete ordered discovery chain.
    #[must_use]
    pub const fn chain_binding(&self) -> DiscoveryChainBinding {
        self.chain.binding()
    }

    /// Revalidates retained leases, the current root-to-target namespace, the
    /// artifact bytes, and the exclusion snapshot.
    ///
    /// This remains inspection evidence only and grants no launch authority.
    ///
    /// # Errors
    ///
    /// Returns fail-closed if any discovery binding, artifact, or exclusion
    /// observation changed.
    pub fn revalidate(
        &self,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<(), RealGitArtifactError> {
        self.chain.revalidate(&self.candidate.snapshot.file_key())?;
        self.candidate.reinspect_retained()?;
        if !self.candidate.matches_exclusion_snapshot(exclusions)? {
            return Err(RealGitArtifactError::ExclusionSnapshotStale);
        }
        self.chain.revalidate(&self.candidate.snapshot.file_key())
    }
}

impl ExecutableCandidate {
    /// Opens and inspects an already-resolved absolute native executable
    /// without invoking it.
    ///
    /// This low-level artifact inspector intentionally does not resolve a
    /// discovery path. A resolver must first record and validate any bounded
    /// alternatives, symbolic-link, or reparse chain, then pass its final
    /// no-link target here. Every target component is opened without following
    /// links. Relative paths, remote Windows volumes, the running GUS image,
    /// owned artifacts, scripts, oversized files, and changing files fail
    /// closed.
    ///
    /// On Windows this is a temporary inspection-only API until the sealed
    /// reparse resolver is implemented. Its result must never be accepted as
    /// provenance, probe, or launch authority, and the method will become
    /// crate-private when the Windows `DiscoveryInspection` backend lands.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed classification or the underlying bounded I/O
    /// error kind.
    #[cfg(windows)]
    pub fn inspect_resolved(
        path: &Path,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<Self, RealGitArtifactError> {
        exclusions.validate()?;
        let opened = open_path_safely(path, ExpectedFileKind::RegularFile)?;
        Self::inspect_opened(opened, exclusions)
    }

    #[cfg(all(unix, test))]
    pub(crate) fn inspect_resolved(
        path: &Path,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<Self, RealGitArtifactError> {
        exclusions.validate()?;
        let opened = open_path_safely(path, ExpectedFileKind::RegularFile)?;
        Self::inspect_opened(opened, exclusions)
    }

    fn inspect_opened(
        opened: SafelyOpenedPath,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<Self, RealGitArtifactError> {
        exclusions.validate()?;
        let inspected_path = opened.normalized_path;
        let lease = opened.lease;
        let snapshot = NativeFileSnapshot::capture(&lease)?;
        snapshot.require_executable()?;
        exclusions.reject_candidate(&snapshot, &opened.ancestors)?;
        require_native_executable(&lease, snapshot.size())?;
        let content_digest = digest_file(&lease, snapshot.size())?;
        let final_snapshot = NativeFileSnapshot::capture(&lease)?;
        if final_snapshot != snapshot {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        exclusions.validate()?;
        let identity = ExecutableIdentity(snapshot.identity_digest(content_digest));
        let path_binding = ExecutablePathBinding(snapshot.path_binding_digest(&inspected_path));
        let exclusion_snapshot = exclusions.calculate_snapshot_id();
        Ok(Self {
            inspected_path,
            lease,
            snapshot,
            content_digest,
            identity,
            path_binding,
            exclusion_snapshot,
            manifest_generation: exclusions.manifest_generation,
        })
    }

    /// Returns a diagnostic path observed during inspection.
    ///
    /// This path is not launch authority and must never be reopened for exec.
    #[must_use]
    pub fn inspected_path(&self) -> &Path {
        &self.inspected_path
    }

    /// Identifies the exact exclusion observations used for this inspection.
    #[must_use]
    pub const fn exclusion_snapshot(&self) -> ExclusionSnapshotId {
        self.exclusion_snapshot
    }

    /// Returns the ownership-manifest generation supplied by the resolver.
    #[must_use]
    pub const fn manifest_generation(&self) -> u64 {
        self.manifest_generation
    }

    /// Reports whether the candidate still refers to this exact, non-stale
    /// exclusion set.
    ///
    /// # Errors
    ///
    /// Returns `ExclusionSnapshotStale` if any retained owned path changed.
    pub fn matches_exclusion_snapshot(
        &self,
        exclusions: &ExecutableExclusionSet,
    ) -> Result<bool, RealGitArtifactError> {
        exclusions.validate()?;
        Ok(self.manifest_generation == exclusions.manifest_generation
            && self.exclusion_snapshot == exclusions.calculate_snapshot_id())
    }

    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    #[must_use]
    pub const fn identity(&self) -> ExecutableIdentity {
        self.identity
    }

    /// Returns a diagnostic-only binding to the path observed during open.
    #[must_use]
    pub const fn path_binding(&self) -> ExecutablePathBinding {
        self.path_binding
    }

    /// Reports whether this inspection matches an external content digest.
    /// Matching does not create process-launch authority.
    #[must_use]
    pub fn matches_content_digest(&self, expected: [u8; 32]) -> bool {
        self.content_digest == expected
    }

    /// Re-hashes the retained artifact and compares another native metadata
    /// snapshot. This is inspection evidence only; it grants no launch
    /// authority, and callers must never reopen `inspected_path` for launch.
    ///
    /// # Errors
    ///
    /// Returns fail-closed on content or metadata mutation, format loss, or a
    /// bounded I/O failure.
    pub fn reinspect_retained(&self) -> Result<(), RealGitArtifactError> {
        let first = NativeFileSnapshot::capture(&self.lease)?;
        if !first.same_retained_artifact(&self.snapshot) {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        first.require_executable()?;
        require_native_executable(&self.lease, first.size())?;
        let digest = digest_file(&self.lease, first.size())?;
        let final_snapshot = NativeFileSnapshot::capture(&self.lease)?;
        if !final_snapshot.same_retained_artifact(&first) || digest != self.content_digest {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        Ok(())
    }
}

/// Failure to inspect or revalidate a real-Git executable candidate.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RealGitArtifactError {
    #[error("the real Git candidate path must be absolute")]
    PathNotAbsolute,
    #[error("the real Git candidate path is unsafe to inspect")]
    UnsafePath,
    #[error("the real Git candidate path exceeds inspection limits")]
    PathLimitExceeded,
    #[error("symbolic links are unsupported in real Git candidate paths")]
    SymbolicLinkUnsupported,
    #[error("the real Git discovery path contains a symbolic-link loop")]
    SymbolicLinkLoop,
    #[error("the real Git discovery path contains an invalid symbolic link")]
    InvalidSymbolicLink,
    #[error("the real Git discovery chain changed during verification")]
    DiscoveryChainStale,
    #[error(
        "symbolic-link resolution is forbidden by the current filesystem, mount, or process policy"
    )]
    SymbolicLinkPolicyDenied,
    #[error("Windows reparse points are unsupported in real Git candidate paths")]
    ReparsePointUnsupported,
    #[error("remote and non-fixed Windows volumes are unsupported for real Git")]
    RemotePathUnsupported,
    #[error("Windows requires a trusted pre-launch current-image lease")]
    CurrentImageEvidenceRequired,
    #[error("failed to inspect the real Git candidate: {kind:?}")]
    Io { kind: io::ErrorKind },
    #[error("the real Git candidate is not a regular executable file")]
    NotExecutable,
    #[error("the real Git candidate exceeds the executable size limit")]
    Oversized,
    #[error("the real Git candidate is not a native executable for this host")]
    UnsupportedNativeExecutable,
    #[error("the real Git candidate resolves to the running GUS image")]
    SelfReference,
    #[error("the real Git candidate is a GUS-owned artifact")]
    OwnedArtifact,
    #[error("the real Git candidate is below a GUS-owned root")]
    OwnedRoot,
    #[error("the GUS-owned exclusion snapshot is stale")]
    ExclusionSnapshotStale,
    #[error("the real Git candidate changed during verification")]
    ArtifactChanged,
}

fn io_error(error: io::Error) -> RealGitArtifactError {
    let kind = error.kind();
    drop(error);
    RealGitArtifactError::Io { kind }
}

#[derive(Clone, Copy)]
enum ExpectedFileKind {
    Directory,
    RegularFile,
}

struct SafelyOpenedPath {
    normalized_path: PathBuf,
    lease: File,
    ancestors: Vec<NativeFileSnapshot>,
}

#[cfg(unix)]
fn open_path_safely(
    path: &Path,
    expected: ExpectedFileKind,
) -> Result<SafelyOpenedPath, RealGitArtifactError> {
    let (normalized_path, components) = normalized_unix_path(path)?;
    let mut current = open_unix_root()?;
    let mut ancestors = Vec::with_capacity(components.len());

    if components.is_empty() {
        let snapshot = NativeFileSnapshot::capture(&current)?;
        expected.require(snapshot)?;
        if matches!(expected, ExpectedFileKind::Directory) {
            snapshot.require_safe_directory()?;
        }
        return Ok(SafelyOpenedPath {
            normalized_path,
            lease: current,
            ancestors,
        });
    }

    let root_snapshot = NativeFileSnapshot::capture(&current)?;
    root_snapshot.require_safe_directory()?;
    ancestors.push(root_snapshot);
    for (index, component) in components.iter().enumerate() {
        let is_final = index + 1 == components.len();
        let required_kind = if is_final {
            expected
        } else {
            ExpectedFileKind::Directory
        };
        let component =
            CString::new(component.as_bytes()).map_err(|_| RealGitArtifactError::UnsafePath)?;
        let observed = require_unix_entry_kind(&current, &component, required_kind)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if matches!(required_kind, ExpectedFileKind::Directory) {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: `current` is a live directory descriptor, `component` is a
        // NUL-terminated single path component, and the return value is owned.
        let descriptor = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: `openat` returned a new owned descriptor on success.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        let snapshot = NativeFileSnapshot::capture(&opened)?;
        required_kind.require(snapshot)?;
        if !observed.matches(&snapshot) {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        if matches!(required_kind, ExpectedFileKind::Directory) {
            snapshot.require_safe_directory()?;
        }
        if is_final {
            return Ok(SafelyOpenedPath {
                normalized_path,
                lease: opened,
                ancestors,
            });
        }
        ancestors.push(snapshot);
        current = opened;
    }
    Err(RealGitArtifactError::UnsafePath)
}

#[cfg(unix)]
fn normalized_unix_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), RealGitArtifactError> {
    if !path.is_absolute() {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(RealGitArtifactError::UnsafePath);
    }
    let mut normalized_path = PathBuf::from("/");
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(RealGitArtifactError::UnsafePath);
        };
        normalized_path.push(name);
        names.push(name.to_os_string());
        if names.len() > MAX_PATH_COMPONENTS
            || normalized_path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
    }
    Ok((normalized_path, names))
}

#[cfg(unix)]
fn open_unix_root() -> Result<File, RealGitArtifactError> {
    let root = CString::new("/").expect("root has no interior NUL");
    // SAFETY: `root` is a valid NUL-terminated path and the return value is
    // converted to one owned `File` exactly once.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: `open` returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn require_unix_entry_kind(
    parent: &File,
    component: &CString,
    expected: ExpectedFileKind,
) -> Result<UnixEntryIdentity, RealGitArtifactError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `parent` and `component` are live, and `status` points to exact
    // writable storage for one `stat` result.
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
    // SAFETY: successful `fstatat` initialized the complete value.
    let status = unsafe { status.assume_init() };
    let mode = u64::from(status.st_mode);
    if mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFLNK) {
        return Err(RealGitArtifactError::SymbolicLinkUnsupported);
    }
    match expected {
        ExpectedFileKind::Directory
            if mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFDIR) =>
        {
            Ok(UnixEntryIdentity::from_stat(&status))
        }
        ExpectedFileKind::RegularFile
            if mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFREG) =>
        {
            Ok(UnixEntryIdentity::from_stat(&status))
        }
        ExpectedFileKind::RegularFile => Err(RealGitArtifactError::NotExecutable),
        ExpectedFileKind::Directory => Err(RealGitArtifactError::UnsafePath),
    }
}

#[cfg(unix)]
struct UnixEntryIdentity {
    device: u64,
    inode: u64,
    file_type: u64,
}

#[cfg(unix)]
impl UnixEntryIdentity {
    fn from_stat(status: &libc::stat) -> Self {
        #[cfg(target_os = "macos")]
        let device = u64::from(u32::from_ne_bytes(status.st_dev.to_ne_bytes()));
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let device = status.st_dev;
        Self {
            device,
            inode: status.st_ino,
            file_type: u64::from(status.st_mode) & u64::from(libc::S_IFMT),
        }
    }

    fn matches(&self, snapshot: &NativeFileSnapshot) -> bool {
        self.device == snapshot.device
            && self.inode == snapshot.inode
            && self.file_type == snapshot.mode & u64::from(libc::S_IFMT)
    }
}

#[cfg(windows)]
fn open_path_safely(
    path: &Path,
    expected: ExpectedFileKind,
) -> Result<SafelyOpenedPath, RealGitArtifactError> {
    use std::path::Prefix;

    if !path.is_absolute() {
        return Err(RealGitArtifactError::PathNotAbsolute);
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(RealGitArtifactError::UnsafePath);
    };
    let (Prefix::Disk(drive) | Prefix::VerbatimDisk(drive)) = prefix.kind() else {
        return Err(RealGitArtifactError::RemotePathUnsupported);
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(RealGitArtifactError::UnsafePath);
    }
    require_local_windows_drive(drive)?;

    let mut normalized_path = PathBuf::from(prefix.as_os_str());
    normalized_path.push("\\");
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(RealGitArtifactError::UnsafePath);
        };
        if name
            .encode_wide()
            .any(|unit| unit == 0 || unit == u16::from(b':'))
        {
            return Err(RealGitArtifactError::UnsafePath);
        }
        normalized_path.push(name);
        names.push(name.to_os_string());
        if names.len() > MAX_PATH_COMPONENTS
            || normalized_path.as_os_str().encode_wide().count() > MAX_PATH_BYTES / 2
        {
            return Err(RealGitArtifactError::PathLimitExceeded);
        }
    }

    let mut current_path = PathBuf::from(prefix.as_os_str());
    current_path.push("\\");
    let mut ancestors = Vec::with_capacity(names.len());
    let mut pinned_directories = Vec::with_capacity(names.len());
    if names.is_empty() {
        let lease = open_windows_entry(&current_path, ExpectedFileKind::Directory)?;
        expected.require(NativeFileSnapshot::capture(&lease)?)?;
        return Ok(SafelyOpenedPath {
            normalized_path: final_windows_path(&lease)?,
            lease,
            ancestors,
        });
    }

    let root = open_windows_entry(&current_path, ExpectedFileKind::Directory)?;
    let root_snapshot = NativeFileSnapshot::capture(&root)?;
    ExpectedFileKind::Directory.require(root_snapshot)?;
    ancestors.push(root_snapshot);
    pinned_directories.push(root);
    for (index, name) in names.iter().enumerate() {
        current_path.push(name);
        let is_final = index + 1 == names.len();
        let required_kind = if is_final {
            expected
        } else {
            ExpectedFileKind::Directory
        };
        let opened = open_windows_entry(&current_path, required_kind)?;
        let snapshot = NativeFileSnapshot::capture(&opened)?;
        required_kind.require(snapshot)?;
        if snapshot.volume_serial != root_snapshot.volume_serial {
            return Err(RealGitArtifactError::RemotePathUnsupported);
        }
        if is_final {
            return Ok(SafelyOpenedPath {
                normalized_path: final_windows_path(&opened)?,
                lease: opened,
                ancestors,
            });
        }
        ancestors.push(snapshot);
        pinned_directories.push(opened);
    }
    Err(RealGitArtifactError::UnsafePath)
}

#[cfg(windows)]
fn require_local_windows_drive(drive: u8) -> Result<(), RealGitArtifactError> {
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: `root` is a valid, NUL-terminated drive-root UTF-16 string.
    if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED {
        Ok(())
    } else {
        Err(RealGitArtifactError::RemotePathUnsupported)
    }
}

#[cfg(windows)]
fn open_windows_entry(
    path: &Path,
    expected: ExpectedFileKind,
) -> Result<File, RealGitArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RealGitArtifactError::ReparsePointUnsupported);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if matches!(expected, ExpectedFileKind::Directory) {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)
        .map_err(io_error)
}

#[cfg(windows)]
fn reopen_windows_read_lease(file: &File) -> Result<File, RealGitArtifactError> {
    // SAFETY: the source handle is live. `ReOpenFile` returns a distinct owned
    // handle for the same file object or `INVALID_HANDLE_VALUE`.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful `ReOpenFile` returned one newly owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn windows_file_key(file: &File) -> Result<NativeFileKey, RealGitArtifactError> {
    // SAFETY: `file` owns a live kernel handle.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(RealGitArtifactError::UnsafePath);
    }
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: the handle is live and `identity` is exact-size writable storage
    // for the requested information class.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut identity).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits Windows API"),
        )
    } == 0
    {
        return Err(io_error(io::Error::last_os_error()));
    }
    Ok(NativeFileKey {
        volume_serial: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
    })
}

#[cfg(windows)]
fn final_windows_path(file: &File) -> Result<PathBuf, RealGitArtifactError> {
    // SAFETY: the handle is live. A null output buffer with size zero queries
    // the required UTF-16 capacity.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    };
    if required == 0 || usize::try_from(required).unwrap_or(usize::MAX) > MAX_PATH_BYTES / 2 {
        return Err(RealGitArtifactError::UnsafePath);
    }
    let mut buffer = vec![0_u16; usize::try_from(required).expect("bounded Windows path")];
    // SAFETY: `buffer` is writable for the advertised capacity and the handle
    // remains live for the duration of the call.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            required,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    };
    if written == 0 || written >= required {
        return Err(RealGitArtifactError::ArtifactChanged);
    }
    buffer.truncate(usize::try_from(written).expect("bounded Windows path"));
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(windows)]
fn final_windows_path_digest(file: &File) -> Result<[u8; 32], RealGitArtifactError> {
    let path = final_windows_path(file)?;
    let mut digest = Sha256::new();
    digest.update(b"gus.platform.windows-final-path.v1\0");
    for unit in path.as_os_str().encode_wide() {
        digest.update(unit.to_le_bytes());
    }
    Ok(digest.finalize().into())
}

impl ExpectedFileKind {
    fn require(self, snapshot: NativeFileSnapshot) -> Result<(), RealGitArtifactError> {
        #[cfg(windows)]
        if snapshot.is_reparse_point() {
            return Err(RealGitArtifactError::ReparsePointUnsupported);
        }
        match self {
            Self::Directory if snapshot.is_directory() => Ok(()),
            Self::RegularFile if snapshot.is_regular() => Ok(()),
            Self::RegularFile => Err(RealGitArtifactError::NotExecutable),
            Self::Directory => Err(RealGitArtifactError::UnsafePath),
        }
    }
}

#[cfg(target_os = "linux")]
fn current_image_key() -> Result<NativeFileKey, RealGitArtifactError> {
    let image = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/self/exe")
        .map_err(io_error)?;
    let snapshot = NativeFileSnapshot::capture(&image)?;
    ExpectedFileKind::RegularFile.require(snapshot)?;
    Ok(snapshot.file_key())
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsProcessRegionInfo {
    protection: u32,
    maximum_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    reference_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacOsProcessRegionWithPath {
    region: MacOsProcessRegionInfo,
    vnode: libc::vnode_info_path,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "_dyld_get_image_header"]
    fn dyld_get_image_header(image_index: u32) -> *const core::ffi::c_void;
}

#[cfg(target_os = "macos")]
fn current_image_key() -> Result<NativeFileKey, RealGitArtifactError> {
    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;

    let mut region = std::mem::MaybeUninit::<MacOsProcessRegionWithPath>::zeroed();
    let size = std::mem::size_of::<MacOsProcessRegionWithPath>();
    // SAFETY: dyld image zero is the main executable. Unlike a Rust function
    // address, this cannot accidentally anchor a future dylib build.
    let main_header = unsafe { dyld_get_image_header(0) };
    if main_header.is_null() {
        return Err(RealGitArtifactError::UnsafePath);
    }
    let address = main_header as usize as u64;
    // SAFETY: `region` is exact-size writable storage, and `proc_pidinfo`
    // borrows it only for this call. The main Mach-O header lies in the main
    // executable's mapped vnode.
    let read = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            region.as_mut_ptr().cast(),
            libc::c_int::try_from(size).expect("macOS region structure fits c_int"),
        )
    };
    if usize::try_from(read).ok() != Some(size) {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: an exact-size successful call initialized the whole structure.
    let region = unsafe { region.assume_init() };
    let stat = region.vnode.vip_vi.vi_stat;
    if stat.vst_ino == 0
        || u64::from(stat.vst_mode) & u64::from(libc::S_IFMT) != u64::from(libc::S_IFREG)
    {
        return Err(RealGitArtifactError::UnsafePath);
    }
    Ok(NativeFileKey {
        device: normalize_macos_device(u64::from(stat.vst_dev)),
        inode: stat.vst_ino,
    })
}

#[cfg(target_os = "freebsd")]
fn current_image_key() -> Result<NativeFileKey, RealGitArtifactError> {
    const MAX_VM_ENTRIES: usize = 1_048_576;

    // SAFETY: libprocstat returns an owned opaque context or null.
    let handle = unsafe { libc::procstat_open_sysctl() };
    if handle.is_null() {
        return Err(io_error(io::Error::last_os_error()));
    }
    let mut process_count = 0;
    // SAFETY: `handle` is live and `process_count` is writable.
    let processes = unsafe {
        libc::procstat_getprocs(
            handle,
            libc::KERN_PROC_PID,
            libc::getpid(),
            &raw mut process_count,
        )
    };
    let mut map_count = 0;
    let maps = if processes.is_null() || process_count != 1 {
        std::ptr::null_mut()
    } else {
        // SAFETY: `handle`, the one returned process, and `map_count` are live.
        unsafe { libc::procstat_getvmmap(handle, processes, &raw mut map_count) }
    };
    let result = if maps.is_null()
        || usize::try_from(map_count).map_or(true, |count| count > MAX_VM_ENTRIES)
    {
        Err(io_error(io::Error::last_os_error()))
    } else {
        // SAFETY: libprocstat returned `map_count` contiguous entries.
        let maps = unsafe {
            std::slice::from_raw_parts(
                maps,
                usize::try_from(map_count).expect("bounded FreeBSD VM-map count"),
            )
        };
        let address = current_image_key as *const () as usize as u64;
        maps.iter()
            .find(|entry| {
                entry.kve_structsize
                    == libc::c_int::try_from(std::mem::size_of::<libc::kinfo_vmentry>())
                        .expect("FreeBSD VM entry size fits c_int")
                    && entry.kve_start <= address
                    && address < entry.kve_end
                    && entry.kve_type == libc::KVME_TYPE_VNODE
                    && entry.kve_protection & libc::KVME_PROT_EXEC != 0
                    && entry.kve_vn_type == libc::KF_VTYPE_VREG
                    && entry.kve_vn_fileid != 0
            })
            .map_or(Err(RealGitArtifactError::UnsafePath), |entry| {
                Ok(NativeFileKey {
                    device: entry.kve_vn_fsid,
                    inode: entry.kve_vn_fileid,
                })
            })
    };
    if !maps.is_null() {
        // SAFETY: `maps` was returned for this live context and is freed once.
        unsafe { libc::procstat_freevmmap(handle, maps) };
    }
    if !processes.is_null() {
        // SAFETY: `processes` was returned for this live context and is freed once.
        unsafe { libc::procstat_freeprocs(handle, processes) };
    }
    // SAFETY: `handle` is the live context and is closed once.
    unsafe { libc::procstat_close(handle) };
    result
}

fn digest_file(file: &File, expected_size: u64) -> Result<[u8; 32], RealGitArtifactError> {
    if expected_size > MAX_EXECUTABLE_BYTES {
        return Err(RealGitArtifactError::Oversized);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; INSPECTION_BUFFER_BYTES];
    let mut total = 0_u64;
    while total < expected_size {
        let remaining = usize::try_from((expected_size - total).min(buffer.len() as u64))
            .expect("bounded inspection read");
        let read = read_at(file, total, &mut buffer[..remaining])?;
        if read == 0 {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| RealGitArtifactError::Oversized)?)
            .ok_or(RealGitArtifactError::Oversized)?;
        if total > MAX_EXECUTABLE_BYTES || total > expected_size {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn require_native_executable(file: &File, size: u64) -> Result<(), RealGitArtifactError> {
    if size < 64 {
        return Err(RealGitArtifactError::UnsupportedNativeExecutable);
    }
    let mut header = [0_u8; NATIVE_HEADER_BYTES];
    let filled =
        usize::try_from(size.min(NATIVE_HEADER_BYTES as u64)).expect("bounded native header size");
    read_exact_at(file, 0, &mut header[..filled])?;
    let matches = native_executable_matches(file, &header[..filled], size)?;
    if matches {
        Ok(())
    } else {
        Err(RealGitArtifactError::UnsupportedNativeExecutable)
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn native_executable_matches(
    file: &File,
    header: &[u8],
    file_size: u64,
) -> Result<bool, RealGitArtifactError> {
    let expected_header_size = if cfg!(target_pointer_width = "64") {
        64
    } else {
        52
    };
    if header.len() < expected_header_size || &header[..4] != b"\x7fELF" {
        return Ok(false);
    }
    let expected_class = if cfg!(target_pointer_width = "64") {
        2
    } else {
        1
    };
    let expected_data = if cfg!(target_endian = "little") { 1 } else { 2 };
    if header[4] != expected_class || header[5] != expected_data || header[6] != 1 {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    let os_abi_matches = matches!(header[7], 0 | 3);
    #[cfg(target_os = "freebsd")]
    let os_abi_matches = header[7] == 9;
    if !os_abi_matches {
        return Ok(false);
    }
    let read_u16 = if cfg!(target_endian = "little") {
        u16::from_le_bytes
    } else {
        u16::from_be_bytes
    };
    let executable_type = read_u16([header[16], header[17]]);
    let machine = read_u16([header[18], header[19]]);
    let version = read_u32(&header[20..24]);
    let (entry_point, program_offset, header_size, program_entry_size, program_count) =
        if cfg!(target_pointer_width = "64") {
            (
                read_u64(&header[24..32]),
                read_u64(&header[32..40]),
                read_u16([header[52], header[53]]),
                read_u16([header[54], header[55]]),
                read_u16([header[56], header[57]]),
            )
        } else {
            (
                u64::from(read_u32(&header[24..28])),
                u64::from(read_u32(&header[28..32])),
                read_u16([header[40], header[41]]),
                read_u16([header[42], header[43]]),
                read_u16([header[44], header[45]]),
            )
        };
    let expected_program_entry_size = if cfg!(target_pointer_width = "64") {
        56
    } else {
        32
    };
    let program_bytes = u64::from(program_entry_size)
        .checked_mul(u64::from(program_count))
        .and_then(|bytes| program_offset.checked_add(bytes));
    let header_matches = matches!(executable_type, 2 | 3)
        && machine == native_elf_machine()
        && version == 1
        && usize::from(header_size) == expected_header_size
        && usize::from(program_entry_size) == expected_program_entry_size
        && program_count != 0
        && program_offset >= u64::from(header_size)
        && program_bytes.is_some_and(|end| end <= file_size);
    if !header_matches {
        return Ok(false);
    }

    elf_has_executable_load(
        file,
        file_size,
        entry_point,
        program_offset,
        program_entry_size,
        program_count,
    )
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn elf_has_executable_load(
    file: &File,
    file_size: u64,
    entry_point: u64,
    program_offset: u64,
    program_entry_size: u16,
    program_count: u16,
) -> Result<bool, RealGitArtifactError> {
    let mut executable_load = false;
    for index in 0..program_count {
        let offset = program_offset
            .checked_add(u64::from(index) * u64::from(program_entry_size))
            .ok_or(RealGitArtifactError::Oversized)?;
        let mut entry = [0_u8; 56];
        read_exact_at(file, offset, &mut entry[..usize::from(program_entry_size)])?;
        if read_u32(&entry[..4]) != 1 {
            continue;
        }
        let (flags, file_offset, virtual_address, file_bytes, memory_bytes) =
            if cfg!(target_pointer_width = "64") {
                (
                    read_u32(&entry[4..8]),
                    read_u64(&entry[8..16]),
                    read_u64(&entry[16..24]),
                    read_u64(&entry[32..40]),
                    read_u64(&entry[40..48]),
                )
            } else {
                (
                    read_u32(&entry[24..28]),
                    u64::from(read_u32(&entry[4..8])),
                    u64::from(read_u32(&entry[8..12])),
                    u64::from(read_u32(&entry[16..20])),
                    u64::from(read_u32(&entry[20..24])),
                )
            };
        if file_bytes > memory_bytes
            || file_offset
                .checked_add(file_bytes)
                .is_none_or(|end| end > file_size)
        {
            return Ok(false);
        }
        let contains_entry = virtual_address
            .checked_add(memory_bytes)
            .is_some_and(|end| virtual_address <= entry_point && entry_point < end);
        if flags & 1 != 0 && file_bytes != 0 && contains_entry {
            executable_load = true;
        }
    }
    Ok(executable_load)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn read_u32(bytes: &[u8]) -> u32 {
    let bytes: [u8; 4] = bytes.try_into().expect("four-byte ELF field");
    if cfg!(target_endian = "little") {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn read_u64(bytes: &[u8]) -> u64 {
    let bytes: [u8; 8] = bytes.try_into().expect("eight-byte ELF field");
    if cfg!(target_endian = "little") {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const fn native_elf_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        62
    }
    #[cfg(target_arch = "aarch64")]
    {
        183
    }
    #[cfg(target_arch = "x86")]
    {
        3
    }
    #[cfg(target_arch = "arm")]
    {
        40
    }
    #[cfg(target_arch = "riscv64")]
    {
        243
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        0
    }
}

#[cfg(target_os = "macos")]
fn native_executable_matches(
    file: &File,
    header: &[u8],
    file_size: u64,
) -> Result<bool, RealGitArtifactError> {
    if header.len() < 8 {
        return Ok(false);
    }
    let magic = u32::from_be_bytes(header[..4].try_into().expect("four-byte Mach-O magic"));
    match magic {
        0xcffa_edfe => thin_macho_is_native_executable(file, 0, header, file_size),
        0xcafe_babe => fat_macho_contains_native_executable(file, header, file_size, 20),
        0xcafe_babf => fat_macho_contains_native_executable(file, header, file_size, 32),
        _ => Ok(false),
    }
}

#[cfg(target_os = "macos")]
fn thin_macho_is_native_executable(
    file: &File,
    slice_offset: u64,
    header: &[u8],
    slice_size: u64,
) -> Result<bool, RealGitArtifactError> {
    if header.len() < 32
        || u32::from_be_bytes(header[..4].try_into().expect("four-byte Mach-O magic"))
            != 0xcffa_edfe
    {
        return Ok(false);
    }
    let cpu = u32::from_le_bytes(header[4..8].try_into().expect("four-byte CPU type"));
    let file_type = u32::from_le_bytes(header[12..16].try_into().expect("four-byte file type"));
    let command_count =
        u32::from_le_bytes(header[16..20].try_into().expect("four-byte command count"));
    let command_bytes =
        u32::from_le_bytes(header[20..24].try_into().expect("four-byte command size"));
    let command_bytes = usize::try_from(command_bytes).expect("u32 fits usize");
    if cpu != native_macho_cpu()
        || file_type != 2
        || command_count == 0
        || command_bytes > MAX_LOAD_COMMAND_BYTES
        || u64::try_from(command_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(32))
            .is_none_or(|end| end > slice_size)
    {
        return Ok(false);
    }
    let mut commands = vec![0_u8; command_bytes];
    read_exact_at(
        file,
        slice_offset
            .checked_add(32)
            .ok_or(RealGitArtifactError::Oversized)?,
        &mut commands,
    )?;
    let mut cursor = 0_usize;
    let mut executable_segment = false;
    for _ in 0..command_count {
        let Some(command_header) = commands.get(cursor..cursor + 8) else {
            return Ok(false);
        };
        let command = u32::from_le_bytes(
            command_header[..4]
                .try_into()
                .expect("four-byte Mach-O command"),
        );
        let command_size = usize::try_from(u32::from_le_bytes(
            command_header[4..8]
                .try_into()
                .expect("four-byte Mach-O command size"),
        ))
        .expect("u32 fits usize");
        if command_size < 8 || command_size % 8 != 0 {
            return Ok(false);
        }
        let Some(command_bytes) = commands.get(cursor..cursor + command_size) else {
            return Ok(false);
        };
        if command == 0x19 {
            if command_size < 72 {
                return Ok(false);
            }
            let file_offset = u64::from_le_bytes(
                command_bytes[40..48]
                    .try_into()
                    .expect("eight-byte Mach-O file offset"),
            );
            let file_bytes = u64::from_le_bytes(
                command_bytes[48..56]
                    .try_into()
                    .expect("eight-byte Mach-O file size"),
            );
            let initial_protection = u32::from_le_bytes(
                command_bytes[60..64]
                    .try_into()
                    .expect("four-byte Mach-O protection"),
            );
            if file_offset
                .checked_add(file_bytes)
                .is_none_or(|end| end > slice_size)
            {
                return Ok(false);
            }
            if initial_protection & 4 != 0 && file_bytes != 0 {
                executable_segment = true;
            }
        }
        cursor += command_size;
    }
    Ok(cursor == commands.len() && executable_segment)
}

#[cfg(target_os = "macos")]
fn fat_macho_contains_native_executable(
    file: &File,
    header: &[u8],
    file_size: u64,
    entry_bytes: usize,
) -> Result<bool, RealGitArtifactError> {
    let Some(count_bytes) = header.get(4..8) else {
        return Ok(false);
    };
    let count = u32::from_be_bytes(
        count_bytes
            .try_into()
            .expect("four-byte architecture count"),
    );
    if count == 0 || count > 32 {
        return Ok(false);
    }
    for index in 0..usize::try_from(count).expect("bounded architecture count") {
        let offset = 8 + index * entry_bytes;
        let Some(entry) = header.get(offset..offset + entry_bytes) else {
            return Ok(false);
        };
        let cpu = u32::from_be_bytes(entry[..4].try_into().expect("four-byte CPU type"));
        if cpu != native_macho_cpu() {
            continue;
        }
        let (slice_offset, slice_size) = if entry_bytes == 20 {
            (
                u64::from(u32::from_be_bytes(
                    entry[8..12].try_into().expect("four-byte slice offset"),
                )),
                u64::from(u32::from_be_bytes(
                    entry[12..16].try_into().expect("four-byte slice size"),
                )),
            )
        } else {
            (
                u64::from_be_bytes(entry[8..16].try_into().expect("eight-byte slice offset")),
                u64::from_be_bytes(entry[16..24].try_into().expect("eight-byte slice size")),
            )
        };
        if slice_size < 32
            || slice_offset
                .checked_add(slice_size)
                .is_none_or(|end| end > file_size)
        {
            return Ok(false);
        }
        let mut slice_header = [0_u8; 32];
        read_exact_at(file, slice_offset, &mut slice_header)?;
        return thin_macho_is_native_executable(file, slice_offset, &slice_header, slice_size);
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
const fn native_macho_cpu() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        0x0100_0007
    }
    #[cfg(target_arch = "aarch64")]
    {
        0x0100_000c
    }
}

#[cfg(windows)]
fn native_executable_matches(
    file: &File,
    header: &[u8],
    file_size: u64,
) -> Result<bool, RealGitArtifactError> {
    if header.len() < 64 || &header[..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u64::from(u32::from_le_bytes(
        header[60..64].try_into().expect("four-byte PE offset"),
    ));
    if pe_offset.checked_add(26).is_none_or(|end| end > file_size) {
        return Ok(false);
    }
    let mut pe_header = [0_u8; 24];
    read_exact_at(file, pe_offset, &mut pe_header)?;
    if &pe_header[..4] != b"PE\0\0" {
        return Ok(false);
    }
    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let section_count = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let optional_size = u64::from(u16::from_le_bytes([pe_header[20], pe_header[21]]));
    let characteristics = u16::from_le_bytes([pe_header[22], pe_header[23]]);
    let image_end = pe_offset
        .checked_add(24)
        .and_then(|start| start.checked_add(optional_size));
    let section_table_end =
        image_end.and_then(|start| start.checked_add(u64::from(section_count).checked_mul(40)?));
    if section_count == 0
        || optional_size < native_pe_minimum_optional_header()
        || section_table_end.is_none_or(|end| end > file_size)
    {
        return Ok(false);
    }
    let mut optional_header = [0_u8; 20];
    read_exact_at(file, pe_offset + 24, &mut optional_header)?;
    let optional_magic = u16::from_le_bytes([optional_header[0], optional_header[1]]);
    let entry_point = u32::from_le_bytes(
        optional_header[16..20]
            .try_into()
            .expect("four-byte PE entry point"),
    );
    if machine != native_pe_machine()
        || optional_magic != native_pe_optional_magic()
        || characteristics & 0x0002 == 0
        || characteristics & 0x2000 != 0
        || entry_point == 0
    {
        return Ok(false);
    }

    let section_start = image_end.expect("validated PE optional header range");
    let mut executable_entry_section = false;
    for index in 0..section_count {
        let offset = section_start
            .checked_add(u64::from(index) * 40)
            .ok_or(RealGitArtifactError::Oversized)?;
        let mut section = [0_u8; 40];
        read_exact_at(file, offset, &mut section)?;
        let virtual_size = u32::from_le_bytes(
            section[8..12]
                .try_into()
                .expect("four-byte PE virtual size"),
        );
        let virtual_address = u32::from_le_bytes(
            section[12..16]
                .try_into()
                .expect("four-byte PE virtual address"),
        );
        let raw_size =
            u32::from_le_bytes(section[16..20].try_into().expect("four-byte PE raw size"));
        let raw_offset =
            u32::from_le_bytes(section[20..24].try_into().expect("four-byte PE raw offset"));
        let section_flags = u32::from_le_bytes(
            section[36..40]
                .try_into()
                .expect("four-byte PE section flags"),
        );
        if u64::from(raw_offset)
            .checked_add(u64::from(raw_size))
            .is_none_or(|end| end > file_size)
        {
            return Ok(false);
        }
        let mapped_size = virtual_size.max(raw_size);
        let contains_entry = virtual_address
            .checked_add(mapped_size)
            .is_some_and(|end| virtual_address <= entry_point && entry_point < end);
        if section_flags & 0x0000_0020 != 0
            && section_flags & 0x2000_0000 != 0
            && raw_size != 0
            && contains_entry
        {
            executable_entry_section = true;
        }
    }
    Ok(executable_entry_section)
}

#[cfg(windows)]
const fn native_pe_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        0x8664
    }
    #[cfg(target_arch = "aarch64")]
    {
        0xaa64
    }
    #[cfg(target_arch = "x86")]
    {
        0x014c
    }
}

#[cfg(windows)]
const fn native_pe_optional_magic() -> u16 {
    if cfg!(target_pointer_width = "64") {
        0x20b
    } else {
        0x10b
    }
}

#[cfg(windows)]
const fn native_pe_minimum_optional_header() -> u64 {
    if cfg!(target_pointer_width = "64") {
        112
    } else {
        96
    }
}

fn read_exact_at(file: &File, offset: u64, buffer: &mut [u8]) -> Result<(), RealGitArtifactError> {
    let mut filled = 0;
    while filled < buffer.len() {
        let relative = u64::try_from(filled).map_err(|_| RealGitArtifactError::Oversized)?;
        let absolute = offset
            .checked_add(relative)
            .ok_or(RealGitArtifactError::Oversized)?;
        let read = read_at(file, absolute, &mut buffer[filled..])?;
        if read == 0 {
            return Err(RealGitArtifactError::ArtifactChanged);
        }
        filled += read;
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, offset: u64, buffer: &mut [u8]) -> Result<usize, RealGitArtifactError> {
    file.read_at(buffer, offset).map_err(io_error)
}

#[cfg(windows)]
fn read_at(file: &File, offset: u64, buffer: &mut [u8]) -> Result<usize, RealGitArtifactError> {
    file.seek_read(buffer, offset).map_err(io_error)
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileKey {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl NativeFileKey {
    fn update_digest(self, digest: &mut Sha256) {
        digest.update(b"gus.platform.native-file-key.unix.v1\0");
        digest.update(self.device.to_le_bytes());
        digest.update(self.inode.to_le_bytes());
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileSnapshot {
    device: u64,
    inode: u64,
    mode: u64,
    owner: u32,
    group: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl NativeFileSnapshot {
    fn capture(file: &File) -> Result<Self, RealGitArtifactError> {
        let metadata = file.metadata().map_err(io_error)?;
        #[cfg(target_os = "macos")]
        let device = normalize_macos_device(metadata.dev());
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let device = metadata.dev();
        Ok(Self {
            device,
            inode: metadata.ino(),
            mode: u64::from(metadata.mode()),
            owner: metadata.uid(),
            group: metadata.gid(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn require_executable(self) -> Result<(), RealGitArtifactError> {
        if self.mode & u64::from(libc::S_IFMT) != u64::from(libc::S_IFREG)
            || self.mode & 0o111 == 0
            || self.mode & u64::from(libc::S_ISUID | libc::S_ISGID) != 0
            || self.mode & 0o022 != 0
        {
            return Err(RealGitArtifactError::NotExecutable);
        }
        if self.size > MAX_EXECUTABLE_BYTES {
            return Err(RealGitArtifactError::Oversized);
        }
        Ok(())
    }

    const fn size(self) -> u64 {
        self.size
    }

    fn is_directory(self) -> bool {
        self.mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFDIR)
    }

    fn is_regular(self) -> bool {
        self.mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFREG)
    }

    const fn file_key(self) -> NativeFileKey {
        NativeFileKey {
            device: self.device,
            inode: self.inode,
        }
    }

    fn require_safe_directory(self) -> Result<(), RealGitArtifactError> {
        let writable_by_others = self.mode & 0o022 != 0;
        let root_owned_sticky = self.owner == 0 && self.mode & u64::from(libc::S_ISVTX) != 0;
        if self.is_directory() && (!writable_by_others || root_owned_sticky) {
            Ok(())
        } else {
            Err(RealGitArtifactError::UnsafePath)
        }
    }

    fn same_file(self, other: &Self) -> bool {
        self.file_key() == other.file_key()
    }

    fn same_retained_artifact(self, other: &Self) -> bool {
        self.same_file(other)
            && self.mode == other.mode
            && self.owner == other.owner
            && self.group == other.group
            && self.size == other.size
            && self.modified_seconds == other.modified_seconds
            && self.modified_nanoseconds == other.modified_nanoseconds
    }

    fn same_discovery_artifact(self, other: &Self) -> bool {
        self.same_retained_artifact(other)
            && self.changed_seconds == other.changed_seconds
            && self.changed_nanoseconds == other.changed_nanoseconds
    }

    fn same_owned_directory(self, other: &Self) -> bool {
        self.same_file(other)
            && self.is_directory()
            && self.mode == other.mode
            && self.owner == other.owner
            && self.group == other.group
    }

    fn identity_digest(self, content_digest: [u8; 32]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.executable-identity.unix.v1\0");
        digest.update(self.device.to_le_bytes());
        digest.update(self.inode.to_le_bytes());
        digest.update(self.mode.to_le_bytes());
        digest.update(self.owner.to_le_bytes());
        digest.update(self.group.to_le_bytes());
        digest.update(self.size.to_le_bytes());
        digest.update(self.modified_seconds.to_le_bytes());
        digest.update(self.modified_nanoseconds.to_le_bytes());
        digest.update(self.changed_seconds.to_le_bytes());
        digest.update(self.changed_nanoseconds.to_le_bytes());
        digest.update(content_digest);
        digest.finalize().into()
    }

    fn path_binding_digest(self, path: &Path) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.executable-path.unix.v1\0");
        digest.update(self.device.to_le_bytes());
        digest.update(self.inode.to_le_bytes());
        digest.update(path.as_os_str().as_bytes());
        digest.finalize().into()
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileKey {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
impl NativeFileKey {
    fn update_digest(self, digest: &mut Sha256) {
        digest.update(b"gus.platform.native-file-key.windows.v1\0");
        digest.update(self.volume_serial.to_le_bytes());
        digest.update(self.file_id);
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileSnapshot {
    volume_serial: u64,
    file_id: [u8; 16],
    final_path_digest: [u8; 32],
    attributes: u32,
    size: u64,
    last_write: u64,
}

#[cfg(windows)]
impl NativeFileSnapshot {
    fn capture(file: &File) -> Result<Self, RealGitArtifactError> {
        let metadata = file.metadata().map_err(io_error)?;
        let identity = windows_file_key(file)?;
        Ok(Self {
            volume_serial: identity.volume_serial,
            file_id: identity.file_id,
            final_path_digest: final_windows_path_digest(file)?,
            attributes: metadata.file_attributes(),
            size: metadata.file_size(),
            last_write: metadata.last_write_time(),
        })
    }

    fn require_executable(self) -> Result<(), RealGitArtifactError> {
        if self.attributes
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        {
            return Err(RealGitArtifactError::NotExecutable);
        }
        if self.size > MAX_EXECUTABLE_BYTES {
            return Err(RealGitArtifactError::Oversized);
        }
        Ok(())
    }

    const fn size(self) -> u64 {
        self.size
    }

    fn is_directory(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && self.attributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT) == 0
    }

    fn is_regular(self) -> bool {
        self.attributes
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)
            == 0
    }

    fn is_reparse_point(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    const fn file_key(self) -> NativeFileKey {
        NativeFileKey {
            volume_serial: self.volume_serial,
            file_id: self.file_id,
        }
    }

    fn same_file(self, other: &Self) -> bool {
        self.file_key() == other.file_key()
    }

    fn same_retained_artifact(self, other: &Self) -> bool {
        self == *other
    }

    fn same_owned_directory(self, other: &Self) -> bool {
        self.same_file(other) && self.is_directory() && self.attributes == other.attributes
    }

    fn identity_digest(self, content_digest: [u8; 32]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gus.platform.executable-identity.windows.v1\0");
        digest.update(self.volume_serial.to_le_bytes());
        digest.update(self.file_id);
        digest.update(self.attributes.to_le_bytes());
        digest.update(self.size.to_le_bytes());
        digest.update(self.last_write.to_le_bytes());
        digest.update(content_digest);
        digest.finalize().into()
    }

    const fn path_binding_digest(self, _path: &Path) -> [u8; 32] {
        self.final_path_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_relative_candidates() {
        let (_owned_root, exclusions) = exclusion_fixture();
        assert_eq!(
            ExecutableCandidate::inspect_resolved(Path::new("git"), &exclusions)
                .expect_err("relative path must fail"),
            RealGitArtifactError::PathNotAbsolute
        );
    }

    #[test]
    fn rejects_the_running_image_as_real_git() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let executable = std::env::current_exe().expect("current test executable");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&executable, &exclusions)
                .expect_err("self reference must fail"),
            RealGitArtifactError::SelfReference
        );
    }

    #[test]
    fn inspection_reports_content_and_identity_without_granting_authority() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let path = native_fixture_path();
        let candidate = ExecutableCandidate::inspect_resolved(&path, &exclusions)
            .expect("inspect native fixture");
        let content = candidate.content_digest();
        let identity = candidate.identity();
        assert_eq!(format!("{candidate:?}"), "ExecutableCandidate([REDACTED])");
        assert_eq!(format!("{identity:?}"), "ExecutableIdentity([REDACTED])");
        assert_eq!(
            format!("{:?}", candidate.path_binding()),
            "ExecutablePathBinding([REDACTED])"
        );
        assert!(candidate.matches_content_digest(content));
        assert_eq!(candidate.manifest_generation(), 1);
        assert_eq!(
            format!("{:?}", candidate.exclusion_snapshot()),
            "ExclusionSnapshotId([REDACTED])"
        );
        candidate.reinspect_retained().expect("unchanged lease");
    }

    #[test]
    fn digest_matching_does_not_accept_a_wrong_digest() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let candidate = ExecutableCandidate::inspect_resolved(&native_fixture_path(), &exclusions)
            .expect("inspect native fixture");
        let mut wrong = candidate.content_digest();
        wrong[0] ^= 1;
        assert!(!candidate.matches_content_digest(wrong));
    }

    #[test]
    fn rejects_non_native_executable_content() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join(native_fixture_name("script"));
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write script fixture");
        make_executable(&path);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("script must not be native"),
            RealGitArtifactError::UnsupportedNativeExecutable
        );
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn rejects_elf_without_a_loadable_executable_segment() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("malformed-elf");
        let header_size = if cfg!(target_pointer_width = "64") {
            64_usize
        } else {
            52
        };
        let program_size = if cfg!(target_pointer_width = "64") {
            56_usize
        } else {
            32
        };
        let mut bytes = vec![0_u8; header_size + program_size];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        bytes[5] = if cfg!(target_endian = "little") { 1 } else { 2 };
        bytes[6] = 1;
        bytes[7] = if cfg!(target_os = "freebsd") { 9 } else { 0 };
        bytes[16..18].copy_from_slice(&2_u16.to_ne_bytes());
        bytes[18..20].copy_from_slice(&native_elf_machine().to_ne_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_ne_bytes());
        let header_u16 = u16::try_from(header_size).expect("ELF header size fits u16");
        let program_u16 = u16::try_from(program_size).expect("ELF program size fits u16");
        if cfg!(target_pointer_width = "64") {
            bytes[24..32].copy_from_slice(&0x0040_0000_u64.to_ne_bytes());
            bytes[32..40].copy_from_slice(
                &u64::try_from(header_size)
                    .expect("ELF header size fits u64")
                    .to_ne_bytes(),
            );
            bytes[52..54].copy_from_slice(&header_u16.to_ne_bytes());
            bytes[54..56].copy_from_slice(&program_u16.to_ne_bytes());
            bytes[56..58].copy_from_slice(&1_u16.to_ne_bytes());
        } else {
            bytes[24..28].copy_from_slice(&0x0040_0000_u32.to_ne_bytes());
            bytes[28..32].copy_from_slice(
                &u32::try_from(header_size)
                    .expect("ELF header size fits u32")
                    .to_ne_bytes(),
            );
            bytes[40..42].copy_from_slice(&header_u16.to_ne_bytes());
            bytes[42..44].copy_from_slice(&program_u16.to_ne_bytes());
            bytes[44..46].copy_from_slice(&1_u16.to_ne_bytes());
        }
        fs::write(&path, bytes).expect("write malformed ELF");
        make_executable(&path);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("ELF without PT_LOAD must fail"),
            RealGitArtifactError::UnsupportedNativeExecutable
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_device_ids_use_the_kernel_vnode_width() {
        assert_eq!(normalize_macos_device(0xffff_ffff_8000_0001), 0x8000_0001);
        assert_eq!(normalize_macos_device(0x7fff_ffff), 0x7fff_ffff);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_macho_without_an_executable_segment() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("malformed-macho");
        let mut bytes = vec![0_u8; 104];
        bytes[..4].copy_from_slice(&0xcffa_edfe_u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&native_macho_cpu().to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&72_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x19_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        fs::write(&path, bytes).expect("write malformed Mach-O");
        make_executable(&path);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("Mach-O without executable segment must fail"),
            RealGitArtifactError::UnsupportedNativeExecutable
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_pe_without_an_executable_code_section() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("malformed-pe.exe");
        let mut bytes = vec![0_u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&native_pe_machine().to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        let optional_size = u16::try_from(native_pe_minimum_optional_header())
            .expect("PE optional header size fits u16");
        bytes[0x94..0x96].copy_from_slice(&optional_size.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0002_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&native_pe_optional_magic().to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000_u32.to_le_bytes());
        fs::write(&path, bytes).expect("write malformed PE");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("PE without executable code section must fail"),
            RealGitArtifactError::UnsupportedNativeExecutable
        );
    }

    #[test]
    fn rejects_candidates_below_a_gus_owned_root() {
        let directory = temporary_directory();
        let path = directory.path().join(native_fixture_name("git"));
        fs::copy(native_fixture_path(), &path).expect("copy native fixture");
        make_executable(&path);
        let exclusions = new_exclusion_set(directory.path(), 1);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("owned candidate must fail"),
            RealGitArtifactError::OwnedRoot
        );
    }

    #[test]
    fn rejects_hard_link_aliases_of_gus_owned_artifacts() {
        let (_owned_root, mut exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let artifact = directory.path().join(native_fixture_name("shim"));
        let alias = directory.path().join(native_fixture_name("alias"));
        fs::copy(native_fixture_path(), &artifact).expect("copy native fixture");
        make_executable(&artifact);
        fs::hard_link(&artifact, &alias).expect("create hard-link alias");
        exclusions
            .add_owned_artifact(&artifact)
            .expect("exclude owned artifact");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&alias, &exclusions)
                .expect_err("hard-link alias must fail"),
            RealGitArtifactError::OwnedArtifact
        );
    }

    #[test]
    fn hard_link_aliases_share_artifact_identity_but_not_path_binding() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let original = directory
            .path()
            .join(native_fixture_name("native-original"));
        let alias = directory.path().join(native_fixture_name("native-alias"));
        fs::copy(native_fixture_path(), &original).expect("copy native fixture");
        make_executable(&original);
        fs::hard_link(&original, &alias).expect("create hard-link alias");
        let original = ExecutableCandidate::inspect_resolved(&original, &exclusions)
            .expect("inspect original");
        let alias =
            ExecutableCandidate::inspect_resolved(&alias, &exclusions).expect("inspect alias");
        assert_eq!(original.identity(), alias.identity());
        assert_ne!(original.path_binding(), alias.path_binding());
    }

    #[cfg(windows)]
    #[test]
    fn post_open_directory_reparse_snapshot_is_rejected() {
        let snapshot = NativeFileSnapshot {
            volume_serial: 1,
            file_id: [2; 16],
            final_path_digest: [3; 32],
            attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            size: 0,
            last_write: 0,
        };
        assert_eq!(
            ExpectedFileKind::Directory
                .require(snapshot)
                .expect_err("post-open reparse point must fail"),
            RealGitArtifactError::ReparsePointUnsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_replaced_owned_root_as_a_stale_snapshot() {
        let container = temporary_directory();
        let root = container.path().join("gus-owned");
        let old_root = container.path().join("gus-owned-old");
        fs::create_dir(&root).expect("create owned root");
        let exclusions = new_exclusion_set(&root, 1);
        fs::rename(&root, &old_root).expect("rename old root");
        fs::create_dir(&root).expect("recreate owned root");
        let candidate_path = root.join("git");
        fs::copy(native_fixture_path(), &candidate_path).expect("copy replacement candidate");
        make_executable(&candidate_path);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&candidate_path, &exclusions)
                .expect_err("replaced owned root must stale the snapshot"),
            RealGitArtifactError::ExclusionSnapshotStale
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_replaced_owned_artifact_as_a_stale_snapshot() {
        let (_owned_root, mut exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let artifact = directory.path().join("shim");
        let old_artifact = directory.path().join("shim-old");
        fs::copy(native_fixture_path(), &artifact).expect("copy owned artifact");
        make_executable(&artifact);
        exclusions
            .add_owned_artifact(&artifact)
            .expect("add owned artifact");
        fs::rename(&artifact, &old_artifact).expect("rename owned artifact");
        fs::copy(native_fixture_path(), &artifact).expect("replace owned artifact");
        make_executable(&artifact);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&native_fixture_path(), &exclusions)
                .expect_err("replaced artifact must stale the snapshot"),
            RealGitArtifactError::ExclusionSnapshotStale
        );
    }

    #[test]
    fn candidate_binds_the_exact_exclusion_set() {
        let (_owned_root, mut exclusions) = exclusion_fixture();
        let candidate = ExecutableCandidate::inspect_resolved(&native_fixture_path(), &exclusions)
            .expect("inspect candidate");
        assert!(
            candidate
                .matches_exclusion_snapshot(&exclusions)
                .expect("fresh exclusions")
        );

        let directory = temporary_directory();
        let artifact = directory.path().join(native_fixture_name("owned-helper"));
        fs::copy(native_fixture_path(), &artifact).expect("copy owned helper");
        make_executable(&artifact);
        exclusions
            .add_owned_artifact(&artifact)
            .expect("extend exclusions");
        assert!(
            !candidate
                .matches_exclusion_snapshot(&exclusions)
                .expect("extended exclusions remain fresh")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_requires_prelaunch_current_image_evidence() {
        let root = temporary_directory();
        assert_eq!(
            ExecutableExclusionSet::new(root.path(), 1)
                .expect_err("post-launch path discovery must fail closed"),
            RealGitArtifactError::CurrentImageEvidenceRequired
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_owned_leases_deny_windows_replacement() {
        let container = temporary_directory();
        let root = container.path().join("gus-owned");
        fs::create_dir(&root).expect("create owned root");
        let mut exclusions = new_exclusion_set(&root, 1);
        assert!(fs::rename(&root, container.path().join("moved-root")).is_err());

        let artifact = container.path().join("shim.exe");
        fs::copy(native_fixture_path(), &artifact).expect("copy owned artifact");
        exclusions
            .add_owned_artifact(&artifact)
            .expect("retain owned artifact");
        assert!(fs::rename(&artifact, container.path().join("moved-shim.exe")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_components() {
        use std::os::unix::fs::symlink;

        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let link = directory.path().join("git-link");
        symlink(native_fixture_path(), &link).expect("create fixture symlink");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&link, &exclusions)
                .expect_err("symbolic link must fail"),
            RealGitArtifactError::SymbolicLinkUnsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_parent_components() {
        use std::os::unix::fs::symlink;

        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let linked_parent = directory.path().join("linked-parent");
        let fixture = native_fixture_path();
        symlink(
            fixture.parent().expect("native fixture parent"),
            &linked_parent,
        )
        .expect("create parent symlink");
        let path = linked_parent.join(fixture.file_name().expect("native fixture name"));
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("parent symbolic link must fail"),
            RealGitArtifactError::SymbolicLinkUnsupported
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_unc_candidates_before_filesystem_access() {
        let (_owned_root, exclusions) = exclusion_fixture();
        assert_eq!(
            ExecutableCandidate::inspect_resolved(
                Path::new(r"\\server\share\git.exe"),
                &exclusions
            )
            .expect_err("UNC paths must fail"),
            RealGitArtifactError::RemotePathUnsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_candidates_without_blocking() {
        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let fifo = directory.path().join("git-fifo");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path CString");
        // SAFETY: `fifo_path` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o700) }, 0);
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&fifo, &exclusions)
                .expect_err("FIFO must fail without opening for blocking I/O"),
            RealGitArtifactError::NotExecutable
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_executables() {
        use std::os::unix::fs::PermissionsExt;

        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("writable-native");
        fs::copy(native_fixture_path(), &path).expect("copy native fixture");
        let mut permissions = fs::metadata(&path).expect("copy metadata").permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(&path, permissions).expect("set writable permissions");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("writable executable must fail"),
            RealGitArtifactError::NotExecutable
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_lease_detects_in_place_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("native-copy");
        fs::copy(native_fixture_path(), &path).expect("copy native fixture");
        let mut permissions = fs::metadata(&path).expect("copy metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("set executable permissions");
        let candidate = ExecutableCandidate::inspect_resolved(&path, &exclusions)
            .expect("inspect copied fixture");
        let mut bytes = fs::read(&path).expect("read copied fixture");
        let last = bytes.last_mut().expect("non-empty native fixture");
        *last ^= 1;
        fs::write(&path, bytes).expect("mutate fixture in place");
        assert_eq!(
            candidate
                .reinspect_retained()
                .expect_err("mutated lease must fail"),
            RealGitArtifactError::ArtifactChanged
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_lease_does_not_follow_a_replaced_path() {
        use std::os::unix::fs::PermissionsExt;

        let (_owned_root, exclusions) = exclusion_fixture();
        let directory = temporary_directory();
        let path = directory.path().join("candidate");
        let moved = directory.path().join("retained-original");
        fs::copy(native_fixture_path(), &path).expect("copy native fixture");
        let mut permissions = fs::metadata(&path).expect("copy metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("set executable permissions");
        let candidate = ExecutableCandidate::inspect_resolved(&path, &exclusions)
            .expect("inspect copied fixture");

        fs::rename(&path, &moved).expect("move verified path target");
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("replace path with script");
        let mut replacement_permissions = fs::metadata(&path)
            .expect("replacement metadata")
            .permissions();
        replacement_permissions.set_mode(0o755);
        fs::set_permissions(&path, replacement_permissions)
            .expect("set replacement executable permissions");

        candidate
            .reinspect_retained()
            .expect("retained lease must still refer to the original inode");
        assert_eq!(
            ExecutableCandidate::inspect_resolved(&path, &exclusions)
                .expect_err("replacement must fail inspection"),
            RealGitArtifactError::UnsupportedNativeExecutable
        );
    }

    fn exclusion_fixture() -> (tempfile::TempDir, ExecutableExclusionSet) {
        let root = temporary_directory();
        let exclusions = new_exclusion_set(root.path(), 1);
        (root, exclusions)
    }

    fn new_exclusion_set(root: &Path, generation: u64) -> ExecutableExclusionSet {
        #[cfg(unix)]
        {
            ExecutableExclusionSet::new(root, generation).expect("build exclusions")
        }
        #[cfg(windows)]
        {
            let path = std::env::current_exe().expect("current test executable");
            let lease = open_windows_entry(&path, ExpectedFileKind::RegularFile)
                .expect("open synthetic pre-launch test lease");
            let trusted_lease = TrustedPrelaunchExecutableLease { lease };
            let evidence = CurrentExecutableEvidence::from_trusted_prelaunch_lease(trusted_lease)
                .expect("pin synthetic pre-launch test lease");
            ExecutableExclusionSet::new_with_current_image(root, generation, evidence)
                .expect("build exclusions")
        }
    }

    #[cfg(target_os = "macos")]
    fn temporary_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .tempdir_in("/private/tmp")
            .expect("temporary directory below a no-symlink root")
    }

    #[cfg(not(target_os = "macos"))]
    fn temporary_directory() -> tempfile::TempDir {
        tempfile::tempdir().expect("temporary directory")
    }

    #[cfg(target_os = "linux")]
    fn native_fixture_path() -> PathBuf {
        PathBuf::from("/usr/bin/echo")
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn native_fixture_path() -> PathBuf {
        PathBuf::from("/bin/echo")
    }

    #[cfg(windows)]
    fn native_fixture_path() -> PathBuf {
        let root = std::env::var_os("SystemRoot").expect("Windows SystemRoot");
        PathBuf::from(root).join("System32").join("where.exe")
    }

    #[cfg(unix)]
    fn native_fixture_name(name: &str) -> String {
        name.to_owned()
    }

    #[cfg(windows)]
    fn native_fixture_name(name: &str) -> String {
        format!("{name}.exe")
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("script metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("set script executable");
    }

    #[cfg(windows)]
    fn make_executable(_path: &Path) {}
}
