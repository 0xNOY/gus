use std::{
    fs, io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

use gus_platform::{AuthenticatedUnixStream, PeerAuthenticationError};
use thiserror::Error;

use crate::{PendingUnixProvider, ProviderConnectionError};

/// Owner-private provider endpoint on Linux, macOS, or FreeBSD.
///
/// Binding never replaces an existing filesystem entry. The containing
/// directory must already be owned by the current effective user with no
/// group or other permissions; setup/runtime initialization owns creating it.
pub struct UnixProviderListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl UnixProviderListener {
    /// Binds a new owner-private Unix socket without removing stale entries.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, writable resolved ancestor paths, non-private
    /// parent directories, existing entries, unsafe socket metadata, and
    /// operating-system failures.
    pub fn bind(
        path: impl AsRef<Path>,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, UnixEndpointError> {
        let path = validated_endpoint_path(path.as_ref())?;
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(UnixEndpointError::EndpointExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(UnixEndpointError::Io(error.kind())),
        }

        let listener =
            UnixListener::bind(&path).map_err(|error| UnixEndpointError::Io(error.kind()))?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&path);
            return Err(UnixEndpointError::Io(error.kind()));
        }
        if let Err(error) = require_close_on_exec(&listener) {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = fs::remove_file(&path);
                return Err(UnixEndpointError::Io(error.kind()));
            }
        };
        // SAFETY: `geteuid` has no preconditions and reads process credentials.
        let effective_user = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket()
            || metadata.uid() != effective_user
            || metadata.mode() & 0o777 != 0o600
        {
            let _ = fs::remove_file(&path);
            return Err(UnixEndpointError::UnsafeEndpoint);
        }

        Ok(Self {
            listener,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            read_timeout,
            write_timeout,
        })
    }

    fn accept(&self) -> Result<AuthenticatedUnixStream, UnixEndpointError> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|error| UnixEndpointError::Io(error.kind()))?;
        let authenticated = AuthenticatedUnixStream::authenticate_incoming(stream)?;
        authenticated
            .set_read_timeout(Some(self.read_timeout))
            .map_err(|error| UnixEndpointError::Io(error.kind()))?;
        authenticated
            .set_write_timeout(Some(self.write_timeout))
            .map_err(|error| UnixEndpointError::Io(error.kind()))?;
        Ok(authenticated)
    }

    /// Accepts, authenticates, and reads one untrusted provider registration.
    ///
    /// # Errors
    ///
    /// Returns endpoint/authentication failures before framing, or a
    /// connection error for a slow, malformed, or non-registration frame.
    pub fn accept_registration(&self) -> Result<PendingUnixProvider, UnixProviderAcceptError> {
        let stream = self.accept()?;
        PendingUnixProvider::read(stream, self.read_timeout, self.write_timeout)
            .map_err(UnixProviderAcceptError::Connection)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for UnixProviderListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixProviderListener")
            .field("path", &self.path)
            .field("listener", &"<retained>")
            .finish_non_exhaustive()
    }
}

impl Drop for UnixProviderListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validated_endpoint_path(path: &Path) -> Result<PathBuf, UnixEndpointError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(UnixEndpointError::InvalidPath);
    }
    let file_name = path.file_name().ok_or(UnixEndpointError::InvalidPath)?;
    let parent = path.parent().ok_or(UnixEndpointError::InvalidPath)?;
    let parent = validated_private_directory(parent)?;
    Ok(parent.join(file_name))
}

pub(crate) fn validated_private_directory(path: &Path) -> Result<PathBuf, UnixEndpointError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(UnixEndpointError::InvalidPath);
    }
    // Resolve platform-owned aliases such as macOS `/var` once, then perform
    // all validation and binding through the resulting symlink-free path.
    let parent = fs::canonicalize(path).map_err(|error| UnixEndpointError::Io(error.kind()))?;
    validate_ancestor_chain(&parent)?;
    let metadata =
        fs::symlink_metadata(&parent).map_err(|error| UnixEndpointError::Io(error.kind()))?;
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
        return Err(UnixEndpointError::UnsafeParent);
    }
    Ok(parent)
}

fn validate_ancestor_chain(path: &Path) -> Result<(), UnixEndpointError> {
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(UnixEndpointError::InvalidPath);
            }
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|error| UnixEndpointError::Io(error.kind()))?;
        if !metadata.is_dir() {
            return Err(UnixEndpointError::UnsafeAncestor);
        }
        if !trusted_ancestor(metadata.uid(), metadata.mode(), effective_user) {
            return Err(UnixEndpointError::UnsafeAncestor);
        }
    }
    Ok(())
}

const fn trusted_ancestor(owner: u32, mode: u32, effective_user: u32) -> bool {
    if owner != 0 && owner != effective_user {
        return false;
    }
    mode & 0o022 == 0 || (owner == 0 && mode & 0o1000 != 0)
}

fn require_close_on_exec(listener: &UnixListener) -> Result<(), UnixEndpointError> {
    // SAFETY: `F_GETFD` only reads flags from the live borrowed descriptor.
    let flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(UnixEndpointError::Io(io::Error::last_os_error().kind()));
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Err(UnixEndpointError::MissingCloseOnExec);
    }
    Ok(())
}

/// Failure to create or accept an owner-private Unix provider endpoint.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnixEndpointError {
    #[error("provider endpoint path must be absolute and contain no parent traversal")]
    InvalidPath,
    #[error("provider endpoint path contains an unsafe ancestor")]
    UnsafeAncestor,
    #[error("provider endpoint parent must be an owner-private directory")]
    UnsafeParent,
    #[error("provider endpoint already exists and was not replaced")]
    EndpointExists,
    #[error("created provider endpoint metadata is unsafe")]
    UnsafeEndpoint,
    #[error("provider listener is inheritable across exec")]
    MissingCloseOnExec,
    #[error("provider endpoint I/O failed: {0:?}")]
    Io(io::ErrorKind),
    #[error(transparent)]
    PeerAuthentication(#[from] PeerAuthenticationError),
}

/// Failure while accepting a complete Unix provider registration.
#[derive(Debug, Error)]
pub enum UnixProviderAcceptError {
    #[error(transparent)]
    Endpoint(#[from] UnixEndpointError),
    #[error(transparent)]
    Connection(#[from] ProviderConnectionError),
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    use gus_ipc::{
        BrokerProviderMessage, Digest32, Generation, ProviderCapability, ProviderKind,
        ProviderRegistrationRequest, ProviderRequestFrame, read_provider_response,
        write_provider_request,
    };
    use tempfile::TempDir;

    use super::*;

    fn private_runtime() -> TempDir {
        let directory = tempfile::Builder::new()
            .prefix("gus-runtime-")
            .tempdir()
            .expect("temporary runtime directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private runtime permissions");
        directory
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("nonzero generation")
    }

    #[test]
    fn bind_is_private_exclusive_and_removed_on_drop() {
        let runtime = private_runtime();
        let path = runtime.path().join("provider.sock");
        let listener =
            UnixProviderListener::bind(&path, Duration::from_secs(1), Duration::from_secs(1))
                .expect("bind private endpoint");
        let metadata = fs::symlink_metadata(&path).expect("endpoint metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(matches!(
            UnixProviderListener::bind(&path, Duration::from_secs(1), Duration::from_secs(1)),
            Err(UnixEndpointError::EndpointExists)
        ));
        drop(listener);
        assert!(!path.exists());
    }

    #[test]
    fn drop_does_not_remove_a_replacement_socket() {
        let runtime = private_runtime();
        let path = runtime.path().join("provider.sock");
        let listener =
            UnixProviderListener::bind(&path, Duration::from_secs(1), Duration::from_secs(1))
                .expect("bind private endpoint");
        fs::remove_file(&path).expect("unlink original endpoint");
        let replacement = UnixListener::bind(&path).expect("bind replacement endpoint");
        drop(listener);
        assert!(
            fs::symlink_metadata(&path)
                .expect("replacement remains")
                .file_type()
                .is_socket()
        );
        drop(replacement);
    }

    #[test]
    fn rejects_relative_and_non_private_parents_through_aliases() {
        let runtime = private_runtime();
        assert!(matches!(
            UnixProviderListener::bind(
                "relative.sock",
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(UnixEndpointError::InvalidPath)
        ));

        let public = runtime.path().join("public");
        fs::create_dir(&public).expect("public directory");
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))
            .expect("public permissions");
        assert!(matches!(
            UnixProviderListener::bind(
                public.join("provider.sock"),
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(UnixEndpointError::UnsafeParent)
        ));

        let target = runtime.path().join("target");
        fs::create_dir(&target).expect("target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .expect("target permissions");
        let link = runtime.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("directory symlink");
        assert!(matches!(
            UnixProviderListener::bind(
                link.join("provider.sock"),
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(UnixEndpointError::UnsafeParent)
        ));
    }

    #[test]
    fn ancestor_policy_rejects_every_third_party_owner() {
        let effective_user = 1_000;
        assert!(trusted_ancestor(0, 0o755, effective_user));
        assert!(trusted_ancestor(0, 0o1777, effective_user));
        assert!(trusted_ancestor(effective_user, 0o700, effective_user));
        assert!(!trusted_ancestor(2_000, 0o755, effective_user));
        assert!(!trusted_ancestor(2_000, 0o555, effective_user));
        assert!(!trusted_ancestor(effective_user, 0o770, effective_user));
        assert!(!trusted_ancestor(0, 0o777, effective_user));
    }

    #[test]
    fn accepted_provider_authenticates_and_registers_before_returning() {
        let runtime = private_runtime();
        let path = runtime.path().join("provider.sock");
        let listener =
            UnixProviderListener::bind(&path, Duration::from_secs(2), Duration::from_secs(2))
                .expect("bind private endpoint");
        let connector = thread::spawn(move || {
            let stream = UnixStream::connect(path).expect("connect endpoint");
            let mut stream = AuthenticatedUnixStream::authenticate_outgoing(stream)
                .expect("authenticate server");
            let registration = ProviderRequestFrame::registration(
                ProviderRegistrationRequest::new(
                    ProviderKind::Vscode,
                    "window-1".into(),
                    digest(1),
                    vec![digest(2)],
                    vec![ProviderCapability::ProfileQuickPick],
                )
                .expect("registration"),
            )
            .expect("registration frame");
            write_provider_request(&mut stream, &registration).expect("write registration");
            let response = read_provider_response(&mut stream).expect("read registration response");
            assert_eq!(response.request_id(), registration.request_id());
            assert!(matches!(
                response.message(),
                BrokerProviderMessage::Registered(_)
            ));
        });
        let connection = listener
            .accept_registration()
            .expect("read provider registration")
            .admit(digest(1), &[digest(2)], generation(7), 15_000)
            .expect("admit registered provider");
        assert_eq!(connection.provider_generation(), generation(7));
        connector.join().expect("connector thread");
    }
}
