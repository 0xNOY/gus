use std::{
    fmt,
    io::{self, Read, Write},
    mem::{MaybeUninit, size_of},
    num::NonZeroU32,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    time::Duration,
};

use thiserror::Error;

use crate::{
    NativeProcessObserver, ObservationError, OsUserIdentity, PlatformFamily, ProcessIdentity,
};

/// A Unix stream whose peer identity was derived from Linux kernel credentials
/// before any application frame was decoded.
///
/// The identity is connect-time evidence for a connection capability, not
/// proof of which process issued every later `write(2)`. Callers must neither
/// transfer nor intentionally share the socket descriptor. Descriptor holders
/// under the same OS user are not mutually distrusted by GUS; inherited or
/// transferred descriptors act with the original connection's authority.
pub struct AuthenticatedUnixStream {
    stream: UnixStream,
    peer: ProcessIdentity,
    peer_liveness: OwnedFd,
}

impl AuthenticatedUnixStream {
    /// Authenticates a broker-side accepted stream.
    ///
    /// # Errors
    ///
    /// See [`Self::authenticate`].
    pub fn authenticate_incoming(stream: UnixStream) -> Result<Self, PeerAuthenticationError> {
        Self::authenticate(stream)
    }

    /// Authenticates a connector-side stream.
    ///
    /// Linux kernel peer credentials are symmetric, so this performs the same
    /// checks as the incoming path without transferring handshake bytes.
    ///
    /// # Errors
    ///
    /// See [`Self::authenticate`].
    pub fn authenticate_outgoing(stream: UnixStream) -> Result<Self, PeerAuthenticationError> {
        Self::authenticate(stream)
    }

    /// Authenticates a connected Unix stream using symmetric kernel evidence.
    ///
    /// `SO_PEERPIDFD` retains a handle to the original socket peer while the
    /// numeric PID is observed. `SO_PEERCRED` and the process observer must
    /// report the same effective user, and the original pidfd must report a
    /// live process before and after observation.
    ///
    /// # Errors
    ///
    /// Fails closed when the kernel APIs are unavailable, credentials are
    /// malformed, the peer exits, its identity changes, or its effective user
    /// does not match the socket credential.
    pub fn authenticate(stream: UnixStream) -> Result<Self, PeerAuthenticationError> {
        let peer_liveness = peer_pidfd(&stream)?;
        require_live(&peer_liveness)?;
        let credential = peer_credential(&stream)?;
        let pid = u32::try_from(credential.pid)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(PeerAuthenticationError::MalformedCredential)?;
        let peer = NativeProcessObserver::new(pid).observe()?;
        require_live(&peer_liveness)?;
        let credential_user =
            OsUserIdentity::from_native_bytes(PlatformFamily::Linux, &credential.uid.to_le_bytes());
        if peer.user() != credential_user {
            return Err(PeerAuthenticationError::UserMismatch);
        }
        Ok(Self {
            stream,
            peer,
            peer_liveness,
        })
    }

    /// Returns the PID-reuse-resistant kernel-derived peer identity.
    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.peer
    }

    /// Configures the bounded read timeout used by the IPC record layer.
    ///
    /// # Errors
    ///
    /// Returns the operating-system socket error without reading a frame.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// Configures the bounded write timeout used by the IPC record layer.
    ///
    /// # Errors
    ///
    /// Returns the operating-system socket error without writing a frame.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    /// Selects blocking or nonblocking application I/O after authentication.
    ///
    /// # Errors
    ///
    /// Returns the operating-system socket error without transferring bytes.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    fn require_connection_live(&self) -> io::Result<()> {
        require_live(&self.peer_liveness).map_err(|error| match error {
            PeerAuthenticationError::Credential { kind } => io::Error::from(kind),
            PeerAuthenticationError::UnsupportedKernelCapability
            | PeerAuthenticationError::MalformedCredential
            | PeerAuthenticationError::PeerExited
            | PeerAuthenticationError::UserMismatch
            | PeerAuthenticationError::ProcessObservation(_) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticated IPC peer is no longer live",
            ),
        })
    }
}

impl fmt::Debug for AuthenticatedUnixStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedUnixStream")
            .field("peer", &self.peer)
            .field("peer_liveness", &"<retained>")
            .finish_non_exhaustive()
    }
}

impl Read for AuthenticatedUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.require_connection_live()?;
        let read = self.stream.read(buffer)?;
        self.require_connection_live()?;
        Ok(read)
    }
}

impl Write for AuthenticatedUnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.require_connection_live()?;
        let written = self.stream.write(buffer)?;
        self.require_connection_live()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.require_connection_live()?;
        self.stream.flush()?;
        self.require_connection_live()
    }
}

/// Failure to authenticate an accepted native IPC peer.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthenticationError {
    #[error("the Linux kernel does not provide SO_PEERPIDFD")]
    UnsupportedKernelCapability,
    #[error("failed to read a kernel peer credential: {kind:?}")]
    Credential { kind: io::ErrorKind },
    #[error("kernel peer credentials had a malformed representation")]
    MalformedCredential,
    #[error("the original socket peer exited during authentication")]
    PeerExited,
    #[error("socket and process observations reported different users")]
    UserMismatch,
    #[error("failed to observe the authenticated peer process: {0}")]
    ProcessObservation(#[from] ObservationError),
}

fn peer_pidfd(stream: &UnixStream) -> Result<OwnedFd, PeerAuthenticationError> {
    let mut descriptor = -1_i32;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: `descriptor` is aligned writable storage for one `c_int`, the
    // supplied length is exact, and the borrowed socket remains live.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut descriptor).cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(last_credential_error());
    }
    if descriptor < 0 {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    // SAFETY: a successful `SO_PEERPIDFD` returns a new descriptor owned by
    // the caller, validated nonnegative above.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if length as usize != size_of::<libc::c_int>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    Ok(descriptor)
}

fn peer_credential(stream: &UnixStream) -> Result<libc::ucred, PeerAuthenticationError> {
    let mut credential = MaybeUninit::<libc::ucred>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: the output is exact-size aligned storage for `ucred`; the
    // borrowed socket remains live and the kernel does not retain pointers.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(last_credential_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    // SAFETY: exact-size successful `getsockopt` initialized the structure.
    Ok(unsafe { credential.assume_init() })
}

fn require_live(descriptor: &OwnedFd) -> Result<(), PeerAuthenticationError> {
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is a writable one-element array and timeout zero does not
    // block. A pidfd becomes readable when its process exits.
    let result = unsafe { libc::poll(&raw mut poll, 1, 0) };
    if result == -1 {
        return Err(last_credential_error());
    }
    if result == 0 && poll.revents == 0 {
        Ok(())
    } else {
        Err(PeerAuthenticationError::PeerExited)
    }
}

fn last_credential_error() -> PeerAuthenticationError {
    classify_credential_error(&io::Error::last_os_error())
}

fn classify_credential_error(error: &io::Error) -> PeerAuthenticationError {
    if error.raw_os_error() == Some(libc::ENOPROTOOPT) {
        PeerAuthenticationError::UnsupportedKernelCapability
    } else {
        PeerAuthenticationError::Credential { kind: error.kind() }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::Path,
        process::{Command, Stdio},
    };

    use super::*;

    const PEER_SOCKET: &str = "GUS_TEST_AUTHENTICATED_PEER_SOCKET";
    const EXIT_AFTER_CONNECT: &str = "GUS_TEST_AUTHENTICATED_PEER_EXIT";
    const WRITE_THEN_EXIT: &str = "GUS_TEST_AUTHENTICATED_PEER_WRITE_THEN_EXIT";

    #[test]
    fn authenticates_a_live_kernel_socket_peer_before_io() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_linux::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer child");
        let (stream, _) = listener.accept().expect("accept peer child");
        let mut authenticated =
            AuthenticatedUnixStream::authenticate(stream).expect("authenticate peer child");
        assert_eq!(authenticated.peer_identity().pid().get(), child.id());
        authenticated.write_all(&[1]).expect("release peer child");
        authenticated
            .stream
            .write_all(&[2])
            .expect("allow peer child to exit after liveness check");
        assert!(child.wait().expect("wait for peer child").success());
    }

    #[test]
    fn rejects_a_peer_process_that_exited_before_authentication() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("exited-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_linux::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .env(EXIT_AFTER_CONNECT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn exiting peer child");
        let (stream, _) = listener.accept().expect("accept exiting peer child");
        assert!(child.wait().expect("wait for exiting peer child").success());
        assert!(AuthenticatedUnixStream::authenticate(stream).is_err());
    }

    #[test]
    fn rejects_queued_input_after_the_authenticated_peer_exits() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("queued-exited-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_linux::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .env(WRITE_THEN_EXIT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn queued-input peer child");
        let (stream, _) = listener.accept().expect("accept queued-input peer child");
        let mut authenticated =
            AuthenticatedUnixStream::authenticate(stream).expect("authenticate live peer child");
        authenticated
            .stream
            .write_all(&[2])
            .expect("release queued-input peer child");
        assert!(child.wait().expect("wait for queued-input peer").success());

        let mut queued = [0_u8; 1];
        let error = authenticated
            .read(&mut queued)
            .expect_err("dead peer input must not be admitted");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn classifies_an_unsupported_kernel_capability() {
        assert_eq!(
            classify_credential_error(&io::Error::from_raw_os_error(libc::ENOPROTOOPT)),
            PeerAuthenticationError::UnsupportedKernelCapability
        );
    }

    #[test]
    fn debug_output_redacts_the_retained_liveness_handle() {
        let (server, _client) = UnixStream::pair().expect("create peer pair");
        let authenticated =
            AuthenticatedUnixStream::authenticate(server).expect("authenticate live peer");
        let debug = format!("{authenticated:?}");
        assert!(debug.contains("peer_liveness: \"<retained>\""));
    }

    #[test]
    #[ignore = "internal child process for native authenticated-peer test"]
    fn native_authenticated_peer_child() {
        let Some(socket_path) = std::env::var_os(PEER_SOCKET) else {
            return;
        };
        let mut stream = UnixStream::connect(Path::new(&socket_path)).expect("connect to parent");
        if std::env::var_os(EXIT_AFTER_CONNECT).is_some() {
            return;
        }
        let mut release = [0_u8; 1];
        stream.read_exact(&mut release).expect("wait for parent");
        if std::env::var_os(WRITE_THEN_EXIT).is_some() {
            stream
                .write_all(&[0xa5])
                .expect("queue input before child exit");
            return;
        }
        assert_eq!(release, [1]);
        let mut exit_release = [0_u8; 1];
        stream
            .read_exact(&mut exit_release)
            .expect("wait until parent completes its liveness check");
        assert_eq!(exit_release, [2]);
    }
}
