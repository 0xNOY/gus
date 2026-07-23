use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};

use gus_platform::{AuthenticatedUnixStream, PeerAuthenticationError};
use thiserror::Error;

use crate::{
    PendingUnixProvider, UnixEndpointError, UnixProviderAcceptError, UnixProviderListener,
    unix_endpoint::validated_private_directory,
};

const LOCK_FILE: &str = "provider.lock";
const DISCOVERY_FILE: &str = "provider.current";
const ENDPOINT_PREFIX: &str = "provider-";
const ENDPOINT_SUFFIX: &str = ".sock";
// 128 random bits provide collision resistance while leaving room for normal
// runtime-directory prefixes under the smallest supported sockaddr_un limit.
const GENERATION_BYTES: usize = 16;
const MAX_GENERATION_ATTEMPTS: usize = 16;
const MAX_DISCOVERY_BYTES: u64 = 128;

/// One published generation of the owner-private Unix provider endpoint.
///
/// The retained advisory lock admits exactly one broker for the runtime
/// directory and is released by the kernel on crash. Each start uses a fresh
/// socket name, so a stale socket cannot prevent restart. `provider.current`
/// is atomically replaced only after the new listener is ready.
pub struct PublishedUnixProviderEndpoint {
    listener: UnixProviderListener,
    _lock: File,
    discovery_path: PathBuf,
    discovery_device: u64,
    discovery_inode: u64,
}

impl PublishedUnixProviderEndpoint {
    /// Acquires the broker lock, reconciles a valid stale generation, binds a
    /// fresh endpoint, and atomically publishes it.
    ///
    /// # Errors
    ///
    /// Rejects unsafe runtime paths/files, a live broker, malformed stale
    /// publication state, unavailable entropy, and filesystem/socket errors.
    pub fn bind(
        runtime_directory: impl AsRef<Path>,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, UnixRuntimeError> {
        let runtime_directory = validated_runtime_directory(runtime_directory.as_ref())?;
        let lock = acquire_lock(&runtime_directory)?;
        reconcile_stale_publication(&runtime_directory)?;

        let listener = bind_fresh_listener(&runtime_directory, read_timeout, write_timeout)?;
        let endpoint_name = listener
            .path()
            .file_name()
            .ok_or(UnixRuntimeError::UnsafePublication)?;
        let (discovery_path, discovery_device, discovery_inode) =
            publish_generation(&runtime_directory, endpoint_name)?;
        Ok(Self {
            listener,
            _lock: lock,
            discovery_path,
            discovery_device,
            discovery_inode,
        })
    }

    #[must_use]
    pub fn endpoint_path(&self) -> &Path {
        self.listener.path()
    }

    #[must_use]
    pub fn discovery_path(&self) -> &Path {
        &self.discovery_path
    }

    /// Accepts and reads one untrusted provider registration.
    ///
    /// # Errors
    ///
    /// See [`UnixProviderListener::accept_registration`].
    pub fn accept_registration(&self) -> Result<PendingUnixProvider, UnixProviderAcceptError> {
        self.listener.accept_registration()
    }
}

impl std::fmt::Debug for PublishedUnixProviderEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedUnixProviderEndpoint")
            .field("endpoint", &self.listener.path())
            .field("discovery", &self.discovery_path)
            .field("lock", &"<retained>")
            .finish_non_exhaustive()
    }
}

impl Drop for PublishedUnixProviderEndpoint {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.discovery_path) else {
            return;
        };
        if metadata.is_file()
            && metadata.dev() == self.discovery_device
            && metadata.ino() == self.discovery_inode
        {
            let _ = fs::remove_file(&self.discovery_path);
        }
    }
}

/// Discovers and authenticates the currently published Unix provider broker.
///
/// The discovery file and endpoint are accepted only below the owner-private
/// runtime directory and must match the broker's generated-name grammar.
/// Peer authentication completes before application framing is returned.
///
/// # Errors
///
/// Rejects unsafe or malformed publication state, connection failures, and
/// unavailable or inconsistent kernel peer evidence.
pub fn connect_published_provider(
    runtime_directory: impl AsRef<Path>,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<AuthenticatedUnixStream, UnixRuntimeError> {
    let runtime_directory = validated_runtime_directory(runtime_directory.as_ref())?;
    let endpoint = discover_published_endpoint(&runtime_directory)?;
    let stream = UnixStream::connect(endpoint).map_err(io_error)?;
    let authenticated = AuthenticatedUnixStream::authenticate_outgoing(stream)?;
    authenticated
        .set_read_timeout(Some(read_timeout))
        .map_err(io_error)?;
    authenticated
        .set_write_timeout(Some(write_timeout))
        .map_err(io_error)?;
    Ok(authenticated)
}

fn validated_runtime_directory(path: &Path) -> Result<PathBuf, UnixRuntimeError> {
    validated_private_directory(path).map_err(|_| UnixRuntimeError::UnsafeRuntimeDirectory)
}

fn discover_published_endpoint(runtime_directory: &Path) -> Result<PathBuf, UnixRuntimeError> {
    let discovery_path = runtime_directory.join(DISCOVERY_FILE);
    let mut publication = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&discovery_path)
        .map_err(|_| UnixRuntimeError::UnsafePublication)?;
    validate_private_regular(&publication, &discovery_path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut publication)
        .take(MAX_DISCOVERY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_DISCOVERY_BYTES {
        return Err(UnixRuntimeError::UnsafePublication);
    }
    let name = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|name| valid_endpoint_name(name))
        .ok_or(UnixRuntimeError::UnsafePublication)?;
    let endpoint = runtime_directory.join(name);
    let metadata =
        fs::symlink_metadata(&endpoint).map_err(|_| UnixRuntimeError::UnsafePublication)?;
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(UnixRuntimeError::UnsafePublication);
    }
    Ok(endpoint)
}

fn acquire_lock(runtime_directory: &Path) -> Result<File, UnixRuntimeError> {
    let path = runtime_directory.join(LOCK_FILE);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(io_error)?;
    validate_private_regular(&lock, &path)?;
    // SAFETY: `flock` operates on the live retained descriptor and stores no
    // pointer. The lock is automatically released when this file is dropped.
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
        {
            return Err(UnixRuntimeError::BrokerActive);
        }
        return Err(io_error(error));
    }
    Ok(lock)
}

fn reconcile_stale_publication(runtime_directory: &Path) -> Result<(), UnixRuntimeError> {
    let discovery_path = runtime_directory.join(DISCOVERY_FILE);
    let mut publication = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&discovery_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(UnixRuntimeError::UnsafePublication),
    };
    validate_private_regular(&publication, &discovery_path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut publication)
        .take(MAX_DISCOVERY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_DISCOVERY_BYTES {
        return Err(UnixRuntimeError::UnsafePublication);
    }
    let name = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|name| valid_endpoint_name(name))
        .ok_or(UnixRuntimeError::UnsafePublication)?;
    let stale_path = runtime_directory.join(name);
    match fs::symlink_metadata(&stale_path) {
        Ok(metadata) => {
            // SAFETY: `geteuid` has no preconditions and reads credentials.
            let effective_user = unsafe { libc::geteuid() };
            if !metadata.file_type().is_socket()
                || metadata.uid() != effective_user
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(UnixRuntimeError::UnsafePublication);
            }
            fs::remove_file(&stale_path).map_err(io_error)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }
    fs::remove_file(discovery_path).map_err(io_error)
}

fn bind_fresh_listener(
    runtime_directory: &Path,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<UnixProviderListener, UnixRuntimeError> {
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let name = generate_endpoint_name()?;
        match UnixProviderListener::bind(runtime_directory.join(name), read_timeout, write_timeout)
        {
            Ok(listener) => return Ok(listener),
            Err(UnixEndpointError::EndpointExists) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(UnixRuntimeError::GenerationCollision)
}

fn generate_endpoint_name() -> Result<String, UnixRuntimeError> {
    let mut generation = [0_u8; GENERATION_BYTES];
    getrandom::fill(&mut generation).map_err(|_| UnixRuntimeError::EntropyUnavailable)?;
    if generation == [0; GENERATION_BYTES] {
        return Err(UnixRuntimeError::EntropyUnavailable);
    }
    let mut name =
        String::with_capacity(ENDPOINT_PREFIX.len() + GENERATION_BYTES * 2 + ENDPOINT_SUFFIX.len());
    name.push_str(ENDPOINT_PREFIX);
    for byte in generation {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to String is infallible");
    }
    name.push_str(ENDPOINT_SUFFIX);
    Ok(name)
}

fn publish_generation(
    runtime_directory: &Path,
    endpoint_name: &std::ffi::OsStr,
) -> Result<(PathBuf, u64, u64), UnixRuntimeError> {
    let endpoint_name = endpoint_name
        .to_str()
        .filter(|name| valid_endpoint_name(name))
        .ok_or(UnixRuntimeError::UnsafePublication)?;
    let temporary_name = format!(".{endpoint_name}.current.tmp");
    let temporary_path = runtime_directory.join(temporary_name);
    let discovery_path = runtime_directory.join(DISCOVERY_FILE);
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary_path)
        .map_err(io_error)?;
    let result = (|| {
        writeln!(temporary, "{endpoint_name}").map_err(io_error)?;
        temporary.sync_all().map_err(io_error)?;
        fs::rename(&temporary_path, &discovery_path).map_err(io_error)?;
        File::open(runtime_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        let metadata = fs::symlink_metadata(&discovery_path).map_err(io_error)?;
        Ok((discovery_path, metadata.dev(), metadata.ino()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    result
}

fn valid_endpoint_name(name: &str) -> bool {
    name.strip_prefix(ENDPOINT_PREFIX)
        .and_then(|name| name.strip_suffix(ENDPOINT_SUFFIX))
        .is_some_and(|generation| {
            generation.len() == GENERATION_BYTES * 2
                && generation.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn validate_private_regular(file: &File, _path: &Path) -> Result<(), UnixRuntimeError> {
    let metadata = file.metadata().map_err(io_error)?;
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
        return Err(UnixRuntimeError::UnsafeRuntimeFile);
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // Exact adapter shape required by Result::map_err.
fn io_error(error: io::Error) -> UnixRuntimeError {
    UnixRuntimeError::Io(error.kind())
}

/// Failure to publish or recover the Unix provider runtime endpoint.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnixRuntimeError {
    #[error("provider runtime directory is not owner-private")]
    UnsafeRuntimeDirectory,
    #[error("provider runtime file is unsafe")]
    UnsafeRuntimeFile,
    #[error("another provider broker owns the runtime lock")]
    BrokerActive,
    #[error("stale provider publication is malformed or unsafe")]
    UnsafePublication,
    #[error("provider endpoint generation entropy is unavailable")]
    EntropyUnavailable,
    #[error("provider endpoint generation repeatedly collided")]
    GenerationCollision,
    #[error("provider runtime I/O failed: {0:?}")]
    Io(io::ErrorKind),
    #[error(transparent)]
    PeerAuthentication(#[from] PeerAuthenticationError),
    #[error(transparent)]
    Endpoint(#[from] UnixEndpointError),
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::{fs::PermissionsExt as _, net::UnixListener},
        thread,
    };

    use gus_ipc::{
        BrokerProviderMessage, Digest32, Generation, ProviderCapability, ProviderKind,
        ProviderRegistrationRequest, ProviderRequestFrame, read_provider_response,
        write_provider_request,
    };
    use tempfile::TempDir;

    use super::*;

    fn runtime() -> TempDir {
        let runtime = tempfile::Builder::new()
            .prefix("gpr-")
            .tempdir_in("/tmp")
            .expect("temporary runtime");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("private runtime");
        runtime
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    #[test]
    fn connector_discovers_authenticates_and_registers_with_the_live_broker() {
        let runtime = runtime();
        let published = PublishedUnixProviderEndpoint::bind(
            runtime.path(),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("publish endpoint");
        let connector_runtime = runtime.path().to_owned();
        let connector = thread::spawn(move || {
            let mut stream = connect_published_provider(
                connector_runtime,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .expect("discover and authenticate broker");
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

        let connection = published
            .accept_registration()
            .expect("accept provider")
            .admit(
                digest(1),
                &[digest(2)],
                Generation::new(7).expect("generation"),
                15_000,
            )
            .expect("admit provider");
        assert_eq!(
            connection.provider_generation(),
            Generation::new(7).expect("generation")
        );
        connector.join().expect("connector thread");
    }

    #[test]
    fn publication_serializes_live_brokers_and_is_discoverable() {
        let runtime = runtime();
        let published = PublishedUnixProviderEndpoint::bind(
            runtime.path(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("publish endpoint");
        let discovery = fs::read_to_string(published.discovery_path()).expect("read discovery");
        let name = discovery.trim_end();
        assert!(valid_endpoint_name(name));
        assert_eq!(
            published.endpoint_path(),
            runtime
                .path()
                .canonicalize()
                .expect("canonical runtime")
                .join(name)
        );
        assert!(matches!(
            PublishedUnixProviderEndpoint::bind(
                runtime.path(),
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(UnixRuntimeError::BrokerActive)
        ));
    }

    #[test]
    fn crash_stale_generation_is_reconciled_under_the_lock() {
        let runtime = runtime();
        let name = format!(
            "{ENDPOINT_PREFIX}{}{ENDPOINT_SUFFIX}",
            "a1".repeat(GENERATION_BYTES)
        );
        let stale_path = runtime.path().join(&name);
        let stale = UnixListener::bind(&stale_path).expect("bind stale endpoint");
        fs::set_permissions(&stale_path, fs::Permissions::from_mode(0o600))
            .expect("stale permissions");
        drop(stale);
        fs::write(runtime.path().join(DISCOVERY_FILE), format!("{name}\n"))
            .expect("stale publication");
        fs::set_permissions(
            runtime.path().join(DISCOVERY_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .expect("publication permissions");

        let published = PublishedUnixProviderEndpoint::bind(
            runtime.path(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("recover stale endpoint");
        assert!(!stale_path.exists());
        assert_ne!(
            published
                .endpoint_path()
                .file_name()
                .expect("endpoint name"),
            std::ffi::OsStr::new(&name)
        );
    }

    #[test]
    fn malformed_stale_target_is_never_deleted() {
        let runtime = runtime();
        let name = format!(
            "{ENDPOINT_PREFIX}{}{ENDPOINT_SUFFIX}",
            "b2".repeat(GENERATION_BYTES)
        );
        let target = runtime.path().join(&name);
        fs::write(&target, b"not a socket").expect("regular collision");
        fs::write(runtime.path().join(DISCOVERY_FILE), format!("{name}\n"))
            .expect("stale publication");
        fs::set_permissions(
            runtime.path().join(DISCOVERY_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .expect("publication permissions");
        assert!(matches!(
            PublishedUnixProviderEndpoint::bind(
                runtime.path(),
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(UnixRuntimeError::UnsafePublication)
        ));
        assert_eq!(fs::read(target).expect("target retained"), b"not a socket");
    }
}
