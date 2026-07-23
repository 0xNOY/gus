use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Read as _,
    num::NonZeroU32,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
};

use gus_ipc::Digest32;
use gus_platform::{NativeProcessObserver, ObservationError, ProcessIdentity};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_GITFILE_BYTES: u64 = 4096;
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024;

/// Broker-derived evidence for one Git common directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRepositoryEvidence {
    identity: Digest32,
    label: String,
}

/// Open authority for the common directory observed before a broker prompt.
pub struct LinuxRepositoryLease {
    evidence: LinuxRepositoryEvidence,
    common_dir: File,
}

impl LinuxRepositoryLease {
    #[must_use]
    pub const fn evidence(&self) -> &LinuxRepositoryEvidence {
        &self.evidence
    }

    /// Revalidates the retained common-directory inode and its live namespace.
    ///
    /// # Errors
    ///
    /// Fails if the process, repository namespace, or retained inode changed.
    pub fn revalidate(&self, pid: NonZeroU32) -> Result<(), RepositoryEvidenceError> {
        let first = NativeProcessObserver::new(pid).observe()?;
        let (current, common_dir) = repository_location_for_pid(pid)?;
        let retained = self.common_dir.metadata().map_err(io_error)?;
        let current_metadata = fs::metadata(common_dir).map_err(io_error)?;
        let second = NativeProcessObserver::new(pid).observe()?;
        if first != second
            || current != self.evidence
            || retained.dev() != current_metadata.dev()
            || retained.ino() != current_metadata.ino()
        {
            return Err(RepositoryEvidenceError::ProcessChanged);
        }
        Ok(())
    }
}

impl LinuxRepositoryEvidence {
    #[must_use]
    pub const fn identity(&self) -> Digest32 {
        self.identity
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Repository and invocation evidence derived from a live authenticated shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxShimEvidence {
    repository: LinuxRepositoryEvidence,
    plan_digest: Digest32,
}

impl LinuxShimEvidence {
    #[must_use]
    pub const fn repository(&self) -> &LinuxRepositoryEvidence {
        &self.repository
    }

    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }
}

/// Failure to derive stable repository or invocation evidence from Linux procfs.
#[derive(Debug, Error)]
pub enum RepositoryEvidenceError {
    #[error("the shim process changed while repository evidence was captured")]
    ProcessChanged,
    #[error("the shim process could not be observed: {0}")]
    Observation(#[from] ObservationError),
    #[error("the process working directory is not a supported Git worktree")]
    NotRepository,
    #[error("the Git repository metadata is malformed or unsafe")]
    UnsafeRepository,
    #[error("the process command line is malformed or exceeds the supported limit")]
    UnsafeCommandLine,
    #[error("repository evidence I/O failed: {0:?}")]
    Io(std::io::ErrorKind),
}

/// Derives repository and exact argv evidence from a live process.
///
/// The process identity is sampled before and after all procfs/filesystem
/// reads. Callers must compare the returned observation separately with their
/// authenticated transport peer.
///
/// # Errors
///
/// Fails when the process changes, procfs input is malformed, or repository
/// metadata cannot be resolved safely.
pub fn observe_linux_shim(
    expected_peer: ProcessIdentity,
) -> Result<LinuxShimEvidence, RepositoryEvidenceError> {
    let first = NativeProcessObserver::new(expected_peer.pid()).observe()?;
    if first != expected_peer {
        return Err(RepositoryEvidenceError::ProcessChanged);
    }
    let repository = repository_for_pid(expected_peer.pid())?;
    let arguments = command_arguments(expected_peer.pid())?;
    let second = NativeProcessObserver::new(expected_peer.pid()).observe()?;
    if second != first {
        return Err(RepositoryEvidenceError::ProcessChanged);
    }
    Ok(LinuxShimEvidence {
        repository,
        plan_digest: digest_unix_arguments(&arguments),
    })
}

/// Derives repository evidence for a live process, with a stable identity
/// check around the filesystem observations.
///
/// # Errors
///
/// Fails when the process changes or its working directory is not a safely
/// resolvable Git repository.
pub fn observe_linux_repository(
    pid: NonZeroU32,
) -> Result<LinuxRepositoryEvidence, RepositoryEvidenceError> {
    let first = NativeProcessObserver::new(pid).observe()?;
    let repository = repository_for_pid(pid)?;
    let second = NativeProcessObserver::new(pid).observe()?;
    if first != second {
        return Err(RepositoryEvidenceError::ProcessChanged);
    }
    Ok(repository)
}

/// Retains the exact common-directory inode across an interactive selection.
///
/// # Errors
///
/// Fails when the process changes or the repository cannot be opened without
/// following a final symbolic link.
pub fn retain_linux_repository(
    pid: NonZeroU32,
) -> Result<LinuxRepositoryLease, RepositoryEvidenceError> {
    let first = NativeProcessObserver::new(pid).observe()?;
    let (evidence, common_dir) = repository_location_for_pid(pid)?;
    let common_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(common_dir)
        .map_err(io_error)?;
    let metadata = common_dir.metadata().map_err(io_error)?;
    let second = NativeProcessObserver::new(pid).observe()?;
    if first != second || !metadata.is_dir() {
        return Err(RepositoryEvidenceError::ProcessChanged);
    }
    Ok(LinuxRepositoryLease {
        evidence,
        common_dir,
    })
}

/// Computes the versioned digest used to bind shim argv to a broker request.
#[must_use]
pub fn digest_unix_arguments(arguments: &[OsString]) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(b"gus.shim-plan.v1\0");
    for argument in arguments {
        let bytes = argument.as_os_str().as_bytes();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Digest32::from_bytes(digest.finalize().into())
}

fn repository_for_pid(pid: NonZeroU32) -> Result<LinuxRepositoryEvidence, RepositoryEvidenceError> {
    repository_location_for_pid(pid).map(|(evidence, _)| evidence)
}

fn repository_location_for_pid(
    pid: NonZeroU32,
) -> Result<(LinuxRepositoryEvidence, PathBuf), RepositoryEvidenceError> {
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).map_err(io_error)?;
    if !cwd.is_absolute() {
        return Err(RepositoryEvidenceError::UnsafeRepository);
    }
    let mut worktree = cwd;
    loop {
        let dot_git = worktree.join(".git");
        match fs::symlink_metadata(&dot_git) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(RepositoryEvidenceError::UnsafeRepository);
                }
                let git_dir = if metadata.is_dir() {
                    canonical_directory(&dot_git)?
                } else if metadata.is_file() {
                    resolve_gitfile(&dot_git)?
                } else {
                    return Err(RepositoryEvidenceError::UnsafeRepository);
                };
                let common_dir = resolve_common_dir(&git_dir)?;
                let evidence = repository_evidence(&worktree, &common_dir)?;
                return Ok((evidence, common_dir));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        if !worktree.pop() {
            return Err(RepositoryEvidenceError::NotRepository);
        }
    }
}

fn resolve_gitfile(path: &Path) -> Result<PathBuf, RepositoryEvidenceError> {
    let text = read_bounded_regular(path, MAX_GITFILE_BYTES)?;
    let value = text
        .strip_prefix(b"gitdir: ")
        .and_then(|value| value.strip_suffix(b"\n").or(Some(value)))
        .ok_or(RepositoryEvidenceError::UnsafeRepository)?;
    if value.is_empty() || value.contains(&0) {
        return Err(RepositoryEvidenceError::UnsafeRepository);
    }
    let target = PathBuf::from(std::ffi::OsStr::from_bytes(value));
    let resolved = if target.is_absolute() {
        target
    } else {
        path.parent()
            .ok_or(RepositoryEvidenceError::UnsafeRepository)?
            .join(target)
    };
    canonical_directory(&resolved)
}

fn resolve_common_dir(git_dir: &Path) -> Result<PathBuf, RepositoryEvidenceError> {
    let path = git_dir.join("commondir");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(git_dir.to_owned()),
        Err(error) => Err(io_error(error)),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let value = read_bounded_regular(&path, MAX_GITFILE_BYTES)?;
            let value = value.strip_suffix(b"\n").unwrap_or(&value);
            if value.is_empty() || value.contains(&0) {
                return Err(RepositoryEvidenceError::UnsafeRepository);
            }
            let target = PathBuf::from(std::ffi::OsStr::from_bytes(value));
            let resolved = if target.is_absolute() {
                target
            } else {
                git_dir.join(target)
            };
            canonical_directory(&resolved)
        }
        Ok(_) => Err(RepositoryEvidenceError::UnsafeRepository),
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, RepositoryEvidenceError> {
    let canonical = fs::canonicalize(path).map_err(io_error)?;
    let metadata = fs::metadata(&canonical).map_err(io_error)?;
    if !metadata.is_dir() {
        return Err(RepositoryEvidenceError::UnsafeRepository);
    }
    Ok(canonical)
}

fn repository_evidence(
    worktree: &Path,
    common_dir: &Path,
) -> Result<LinuxRepositoryEvidence, RepositoryEvidenceError> {
    let metadata = fs::metadata(common_dir).map_err(io_error)?;
    let mut digest = Sha256::new();
    digest.update(b"gus.repository-common-dir.v1\0");
    digest.update(metadata.dev().to_le_bytes());
    digest.update(metadata.ino().to_le_bytes());
    let path = common_dir.as_os_str().as_bytes();
    digest.update((path.len() as u64).to_le_bytes());
    digest.update(path);
    let label = worktree
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("Git repository")
        .to_owned();
    Ok(LinuxRepositoryEvidence {
        identity: Digest32::from_bytes(digest.finalize().into()),
        label,
    })
}

fn command_arguments(pid: NonZeroU32) -> Result<Vec<OsString>, RepositoryEvidenceError> {
    let path = format!("/proc/{pid}/cmdline");
    let file = File::open(path).map_err(io_error)?;
    let mut bytes = Vec::new();
    file.take(MAX_COMMAND_LINE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_COMMAND_LINE_BYTES
        || bytes.last() != Some(&0)
        || bytes.starts_with(&[0])
    {
        return Err(RepositoryEvidenceError::UnsafeCommandLine);
    }
    let mut fields = bytes[..bytes.len() - 1].split(|byte| *byte == 0);
    let _program = fields.next();
    let arguments = fields
        .map(|field| OsString::from(std::ffi::OsStr::from_bytes(field)))
        .collect::<Vec<_>>();
    Ok(arguments)
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, RepositoryEvidenceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() {
        return Err(RepositoryEvidenceError::UnsafeRepository);
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > maximum {
        return Err(RepositoryEvidenceError::UnsafeRepository);
    }
    Ok(bytes)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> RepositoryEvidenceError {
    RepositoryEvidenceError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, fs};

    use super::*;

    #[test]
    fn linked_worktree_resolves_the_shared_common_directory() {
        let fixture = tempfile::tempdir().expect("fixture");
        let worktree = fixture.path().join("worktree");
        let common = fixture.path().join("admin");
        let git_dir = common.join("worktrees/feature");
        fs::create_dir_all(&git_dir).expect("worktree metadata");
        fs::create_dir(&worktree).expect("worktree");
        fs::write(
            worktree.join(".git"),
            b"gitdir: ../admin/worktrees/feature\n",
        )
        .expect("gitfile");
        fs::write(git_dir.join("commondir"), b"../..\n").expect("commondir");

        let resolved_git = resolve_gitfile(&worktree.join(".git")).expect("resolve gitfile");
        let resolved_common = resolve_common_dir(&resolved_git).expect("resolve common dir");
        assert_eq!(
            resolved_common,
            fs::canonicalize(&common).expect("canonical common dir")
        );
        let linked =
            repository_evidence(&worktree, &resolved_common).expect("linked worktree evidence");
        let direct = repository_evidence(&worktree, &common).expect("direct evidence");
        assert_eq!(linked.identity(), direct.identity());
        assert_eq!(linked.label(), "worktree");
    }

    #[test]
    fn invocation_digest_preserves_empty_argument_boundaries() {
        let with_empty = digest_unix_arguments(&[OsString::from("commit"), OsString::new()]);
        let without_empty = digest_unix_arguments(&[OsString::from("commit")]);
        assert_ne!(with_empty, without_empty);
    }
}
