use std::{
    fmt,
    io::{self, Read, Write},
    mem::{MaybeUninit, size_of},
    num::NonZeroU32,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    NativeProcessObserver, ObservationError, ObservationResource, ProcessIdentity,
    bsd::ProcessExitMonitor, process_identity_proof_digest,
};

const AUTH_MAGIC: &[u8; 8] = b"GUSFAUTH";
const AUTH_VERSION: u16 = 1;
const AUTH_HEADER_BYTES: usize = 16;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_DIGEST_BYTES: usize = 32;
const HELLO_MESSAGE_BYTES: usize = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES * 2;
const PROOF_MESSAGE_BYTES: usize = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES + AUTH_DIGEST_BYTES;
const ACK_MESSAGE_BYTES: usize = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES;
const KIND_SERVER_HELLO: u8 = 1;
const KIND_CLIENT_HELLO: u8 = 2;
const KIND_CHALLENGE: u8 = 3;
const KIND_RESPONSE: u8 = 4;
const KIND_ACKNOWLEDGED: u8 = 5;
// `<sys/un.h>` defines the local-domain socket option level as zero; rust-libc
// exposes the options but not this level constant.
const SOL_LOCAL: libc::c_int = 0;
const FREEBSD_14_4_OSRELDATE: libc::c_int = 1_404_000;
const FREEBSD_14_5_OSRELDATE: libc::c_int = 1_405_000;
const FREEBSD_15_1_OSRELDATE: libc::c_int = 1_501_000;
const FREEBSD_15_2_OSRELDATE: libc::c_int = 1_502_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A FreeBSD Unix stream authenticated before any application frame is decoded.
///
/// Authentication binds the `LOCAL_PEERCRED` PID and effective user captured
/// by the kernel at `connect(2)`/`listen(2)` time to a fresh challenge, native
/// process identity, and retained `NOTE_EXIT | NOTE_EXEC` monitor. The stream
/// must be freshly connected or accepted, close-on-exec, and unshared.
/// Processes under one effective OS user in one prison remain outside GUS's
/// mutually-distrustful security boundary.
pub struct AuthenticatedUnixStream {
    stream: UnixStream,
    peer: ProcessIdentity,
    peer_monitor: ProcessExitMonitor,
}

impl fmt::Debug for AuthenticatedUnixStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedUnixStream")
            .field("peer", &self.peer)
            .field("stream", &"[REDACTED]")
            .field("peer_monitor", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedUnixStream {
    /// Authenticates a broker-side accepted stream with a fresh challenge.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, malformed or changing kernel credentials,
    /// PID reuse, peer exit/exec, an invalid proof, or a user/prison mismatch.
    pub fn authenticate_incoming(mut stream: UnixStream) -> Result<Self, PeerAuthenticationError> {
        let handshake = HandshakeIo::begin(&stream)?;
        let result = authenticate_incoming(&mut stream, &handshake);
        let restore = handshake.restore(&stream);
        let (peer, peer_monitor) = result?;
        restore?;
        Ok(Self {
            stream,
            peer,
            peer_monitor,
        })
    }

    /// Authenticates a connector-side stream and answers the broker challenge.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, malformed or changing kernel credentials,
    /// PID reuse, broker exit/exec, an invalid proof, or a user/prison mismatch.
    pub fn authenticate_outgoing(mut stream: UnixStream) -> Result<Self, PeerAuthenticationError> {
        let handshake = HandshakeIo::begin(&stream)?;
        let result = authenticate_outgoing(&mut stream, &handshake);
        let restore = handshake.restore(&stream);
        let (peer, peer_monitor) = result?;
        restore?;
        Ok(Self {
            stream,
            peer,
            peer_monitor,
        })
    }

    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.peer
    }

    /// Configures the bounded read timeout used after authentication.
    ///
    /// # Errors
    ///
    /// Returns the operating-system socket error without reading a frame.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// Configures the bounded write timeout used after authentication.
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
        self.peer_monitor.ensure_live().map_err(monitor_io_error)
    }
}

fn authenticate_incoming(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let connect_credential = peer_credential(stream)?;
    let pending = begin_peer_authentication(stream, connect_credential)?;
    let server_nonce = fresh_nonce()?;
    write_hello_message(
        stream,
        handshake,
        HelloMessage {
            kind: KIND_SERVER_HELLO,
            server_nonce,
            client_nonce: [0; AUTH_NONCE_BYTES],
        },
    )?;
    let client_hello = read_hello_message(stream, handshake, KIND_CLIENT_HELLO)?;
    if client_hello.server_nonce != server_nonce {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let binding = handshake_binding(server_nonce, client_hello.client_nonce);
    write_proof_message(
        stream,
        handshake,
        ProofMessage {
            kind: KIND_CHALLENGE,
            binding,
            proof: current_proof(binding, KIND_CHALLENGE)?,
        },
    )?;
    let response = read_proof_message(stream, handshake, KIND_RESPONSE)?;
    if response.binding != binding {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let (peer, monitor) =
        finish_peer_authentication(stream, pending, response.proof, binding, KIND_RESPONSE)?;
    write_acknowledgement(stream, handshake, binding)?;
    monitor.ensure_live()?;
    Ok((peer, monitor))
}

fn authenticate_outgoing(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let connect_credential = peer_credential(stream)?;
    let pending = begin_peer_authentication(stream, connect_credential)?;
    let server_hello = read_hello_message(stream, handshake, KIND_SERVER_HELLO)?;
    if server_hello.client_nonce.iter().any(|byte| *byte != 0) {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let client_nonce = fresh_nonce()?;
    write_hello_message(
        stream,
        handshake,
        HelloMessage {
            kind: KIND_CLIENT_HELLO,
            server_nonce: server_hello.server_nonce,
            client_nonce,
        },
    )?;
    let binding = handshake_binding(server_hello.server_nonce, client_nonce);
    let challenge = read_proof_message(stream, handshake, KIND_CHALLENGE)?;
    if challenge.binding != binding {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let (peer, monitor) =
        finish_peer_authentication(stream, pending, challenge.proof, binding, KIND_CHALLENGE)?;
    #[cfg(test)]
    tests::maybe_exec_during_handshake(stream, binding);
    write_proof_message(
        stream,
        handshake,
        ProofMessage {
            kind: KIND_RESPONSE,
            binding,
            proof: current_proof(binding, KIND_RESPONSE)?,
        },
    )?;
    read_acknowledgement(stream, handshake, binding)?;
    monitor.ensure_live()?;
    Ok((peer, monitor))
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

/// Failure to authenticate a native FreeBSD IPC peer.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthenticationError {
    #[error("failed to read a kernel peer credential: {kind:?}")]
    Credential { kind: io::ErrorKind },
    #[error("kernel peer credentials had a malformed native representation")]
    MalformedCredential,
    #[error("failed to read the FreeBSD kernel release: {kind:?}")]
    KernelVersion { kind: io::ErrorKind },
    #[error("the FreeBSD kernel release is outside the admitted 14.4/15.1 families")]
    UnsupportedKernelVersion,
    /// Both the absolute handshake deadline and a shorter pre-existing socket
    /// timeout are reported as [`io::ErrorKind::TimedOut`].
    #[error("failed to transfer the bounded peer-authentication handshake: {kind:?}")]
    Handshake { kind: io::ErrorKind },
    #[error("peer-authentication handshake was malformed or unsupported")]
    MalformedHandshake,
    #[error("peer-authentication proof did not match its challenge or kernel evidence")]
    ProofMismatch,
    #[error("the operating system could not generate a peer-authentication challenge")]
    RandomUnavailable,
    #[error("socket and process observations reported different users or prisons")]
    UserMismatch,
    #[error("failed to observe the authenticated peer process: {0}")]
    ProcessObservation(#[from] ObservationError),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerCredential {
    pid: NonZeroU32,
    effective_uid: libc::uid_t,
    group_count: u8,
    groups: [libc::gid_t; libc::XU_NGROUPS as usize],
}

impl fmt::Debug for PeerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerCredential([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerProof {
    identity_digest: [u8; AUTH_DIGEST_BYTES],
}

impl fmt::Debug for PeerProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerProof([REDACTED])")
    }
}

#[derive(Clone, Copy)]
struct ProofMessage {
    kind: u8,
    binding: [u8; AUTH_NONCE_BYTES],
    proof: PeerProof,
}

#[derive(Clone, Copy)]
struct HelloMessage {
    kind: u8,
    server_nonce: [u8; AUTH_NONCE_BYTES],
    client_nonce: [u8; AUTH_NONCE_BYTES],
}

struct PendingPeerAuthentication {
    credential: PeerCredential,
    first_identity: ProcessIdentity,
    local_identity: ProcessIdentity,
    monitor: ProcessExitMonitor,
}

struct HandshakeIo {
    deadline: Instant,
    original_read_timeout: Option<Duration>,
    original_write_timeout: Option<Duration>,
    original_status_flags: libc::c_int,
}

impl HandshakeIo {
    fn begin(stream: &UnixStream) -> Result<Self, PeerAuthenticationError> {
        Self::begin_with_budget(stream, HANDSHAKE_TIMEOUT)
    }

    fn begin_with_budget(
        stream: &UnixStream,
        budget: Duration,
    ) -> Result<Self, PeerAuthenticationError> {
        require_supported_kernel()?;
        require_close_on_exec(stream)?;
        require_local_stream(stream)?;
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(handshake_timeout)?;
        let original_read_timeout = stream
            .read_timeout()
            .map_err(|error| handshake_error(&error))?;
        let original_write_timeout = stream
            .write_timeout()
            .map_err(|error| handshake_error(&error))?;
        let original_status_flags = socket_status_flags(stream)?;
        // SAFETY: the socket is fresh and unshared. `restore` reinstates the
        // exact original status flags before the authenticated stream escapes.
        if unsafe {
            libc::fcntl(
                stream.as_raw_fd(),
                libc::F_SETFL,
                original_status_flags | libc::O_NONBLOCK,
            )
        } == -1
        {
            return Err(handshake_error(&io::Error::last_os_error()));
        }
        Ok(Self {
            deadline,
            original_read_timeout,
            original_write_timeout,
            original_status_flags,
        })
    }

    fn read_exact(
        &self,
        stream: &mut UnixStream,
        mut buffer: &mut [u8],
    ) -> Result<(), PeerAuthenticationError> {
        while !buffer.is_empty() {
            let operation_deadline = self.operation_deadline(self.original_read_timeout)?;
            loop {
                self.wait_ready(stream, libc::POLLIN, operation_deadline)?;
                match stream.read(buffer) {
                    Ok(0) => {
                        return Err(PeerAuthenticationError::Handshake {
                            kind: io::ErrorKind::UnexpectedEof,
                        });
                    }
                    Ok(read) => {
                        buffer = &mut buffer[read..];
                        self.require_deadline(operation_deadline)?;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(self.normalize_io_error(&error)),
                }
                self.require_deadline(operation_deadline)?;
            }
        }
        Ok(())
    }

    fn write_all(
        &self,
        stream: &mut UnixStream,
        mut buffer: &[u8],
    ) -> Result<(), PeerAuthenticationError> {
        while !buffer.is_empty() {
            let operation_deadline = self.operation_deadline(self.original_write_timeout)?;
            loop {
                self.wait_ready(stream, libc::POLLOUT, operation_deadline)?;
                match stream.write(buffer) {
                    Ok(0) => {
                        return Err(PeerAuthenticationError::Handshake {
                            kind: io::ErrorKind::WriteZero,
                        });
                    }
                    Ok(written) => {
                        buffer = &buffer[written..];
                        self.require_deadline(operation_deadline)?;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(self.normalize_io_error(&error)),
                }
                self.require_deadline(operation_deadline)?;
            }
        }
        Ok(())
    }

    fn restore(&self, stream: &UnixStream) -> Result<(), PeerAuthenticationError> {
        // SAFETY: the descriptor remains live and these flags were captured
        // from this exact open file description before authentication.
        if unsafe {
            libc::fcntl(
                stream.as_raw_fd(),
                libc::F_SETFL,
                self.original_status_flags,
            )
        } == -1
        {
            return Err(handshake_error(&io::Error::last_os_error()));
        }
        Ok(())
    }

    fn wait_ready(
        &self,
        stream: &UnixStream,
        events: libc::c_short,
        operation_deadline: Instant,
    ) -> Result<(), PeerAuthenticationError> {
        loop {
            let timeout = operation_deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(handshake_timeout)?;
            let mut descriptor = libc::pollfd {
                fd: stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: one live pollfd is writable for this bounded call.
            let ready = unsafe {
                libc::poll(
                    ptr::addr_of_mut!(descriptor),
                    1,
                    poll_timeout_millis(timeout),
                )
            };
            if ready > 0 {
                self.require_deadline(operation_deadline)?;
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(handshake_error(&io::Error::from_raw_os_error(libc::EBADF)));
                }
                return Ok(());
            }
            if ready == 0 {
                return Err(handshake_timeout());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(handshake_error(&error));
            }
        }
    }

    fn operation_deadline(
        &self,
        original_timeout: Option<Duration>,
    ) -> Result<Instant, PeerAuthenticationError> {
        let now = Instant::now();
        let remaining = self
            .deadline
            .checked_duration_since(now)
            .filter(|duration| !duration.is_zero())
            .ok_or_else(handshake_timeout)?;
        now.checked_add(original_timeout.map_or(remaining, |original| original.min(remaining)))
            .ok_or_else(handshake_timeout)
    }

    fn require_deadline(&self, operation_deadline: Instant) -> Result<(), PeerAuthenticationError> {
        let now = Instant::now();
        if now >= self.deadline || now >= operation_deadline {
            Err(handshake_timeout())
        } else {
            Ok(())
        }
    }

    fn normalize_io_error(&self, error: &io::Error) -> PeerAuthenticationError {
        if self.deadline <= Instant::now()
            && matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        {
            handshake_timeout()
        } else {
            handshake_error(error)
        }
    }
}

fn begin_peer_authentication(
    stream: &UnixStream,
    connect_credential: PeerCredential,
) -> Result<PendingPeerAuthentication, PeerAuthenticationError> {
    let first_credential = peer_credential(stream)?;
    if first_credential != connect_credential {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let monitor = ProcessExitMonitor::new_with_notifications(
        first_credential.pid,
        ObservationResource::TargetProcess,
        ObservationError::ProcessChanged,
        libc::NOTE_EXIT | libc::NOTE_EXEC,
    )?;
    let first_identity = NativeProcessObserver::new(first_credential.pid).observe()?;
    let second_credential = peer_credential(stream)?;
    let local_identity = current_identity()?;
    monitor.ensure_live()?;
    if first_credential != second_credential {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    if first_credential.effective_uid != current_effective_uid()
        || first_identity.user() != local_identity.user()
    {
        return Err(PeerAuthenticationError::UserMismatch);
    }
    Ok(PendingPeerAuthentication {
        credential: first_credential,
        first_identity,
        local_identity,
        monitor,
    })
}

fn finish_peer_authentication(
    stream: &UnixStream,
    pending: PendingPeerAuthentication,
    proof: PeerProof,
    binding: [u8; AUTH_NONCE_BYTES],
    role: u8,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let peer = NativeProcessObserver::new(pending.credential.pid).observe()?;
    let final_credential = peer_credential(stream)?;
    let final_local_identity = current_identity()?;
    pending.monitor.ensure_live()?;
    if final_credential != pending.credential
        || peer != pending.first_identity
        || peer_process_proof(peer, binding, role) != proof.identity_digest
    {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    if final_credential.effective_uid != current_effective_uid()
        || peer.user() != pending.local_identity.user()
        || final_local_identity.user() != pending.local_identity.user()
    {
        return Err(PeerAuthenticationError::UserMismatch);
    }
    Ok((peer, pending.monitor))
}

fn current_identity() -> Result<ProcessIdentity, PeerAuthenticationError> {
    let pid =
        NonZeroU32::new(std::process::id()).ok_or(PeerAuthenticationError::MalformedCredential)?;
    NativeProcessObserver::new(pid)
        .observe()
        .map_err(PeerAuthenticationError::from)
}

fn current_proof(
    binding: [u8; AUTH_NONCE_BYTES],
    role: u8,
) -> Result<PeerProof, PeerAuthenticationError> {
    Ok(PeerProof {
        identity_digest: peer_process_proof(current_identity()?, binding, role),
    })
}

fn peer_process_proof(
    identity: ProcessIdentity,
    binding: [u8; AUTH_NONCE_BYTES],
    role: u8,
) -> [u8; AUTH_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"gus.platform.freebsd-peer-process-proof.v1");
    hasher.update([role]);
    hasher.update(binding);
    hasher.update(process_identity_proof_digest(identity));
    hasher.finalize().into()
}

fn current_effective_uid() -> libc::uid_t {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn peer_credential(stream: &UnixStream) -> Result<PeerCredential, PeerAuthenticationError> {
    let mut credential = MaybeUninit::<libc::xucred>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<libc::xucred>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: exact-size aligned storage is writable and the socket remains
    // live. FreeBSD fills `cr_pid` for connected stream peer credentials.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            credential.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(last_credential_error());
    }
    if length as usize != size_of::<libc::xucred>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    // SAFETY: exact-size successful `getsockopt` initialized the structure.
    let credential = unsafe { credential.assume_init() };
    let group_count = usize::try_from(credential.cr_ngroups)
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    if credential.cr_version != libc::XUCRED_VERSION
        || group_count == 0
        || group_count > credential.cr_groups.len()
    {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    // SAFETY: FreeBSD's active union member for LOCAL_PEERCRED is `cr_pid`.
    let native_pid = unsafe { credential.cr_pid__c_anonymous_union.cr_pid };
    let pid = u32::try_from(native_pid)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(PeerAuthenticationError::MalformedCredential)?;
    Ok(PeerCredential {
        pid,
        effective_uid: credential.cr_uid,
        group_count: u8::try_from(group_count)
            .map_err(|_| PeerAuthenticationError::MalformedCredential)?,
        groups: credential.cr_groups,
    })
}

fn fresh_nonce() -> Result<[u8; AUTH_NONCE_BYTES], PeerAuthenticationError> {
    let mut nonce = [0_u8; AUTH_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| PeerAuthenticationError::RandomUnavailable)?;
    Ok(nonce)
}

fn handshake_binding(
    server_nonce: [u8; AUTH_NONCE_BYTES],
    client_nonce: [u8; AUTH_NONCE_BYTES],
) -> [u8; AUTH_NONCE_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"gus.platform.freebsd-peer-handshake.v1");
    hasher.update(server_nonce);
    hasher.update(client_nonce);
    hasher.finalize().into()
}

fn write_hello_message(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    message: HelloMessage,
) -> Result<(), PeerAuthenticationError> {
    let mut wire = [0_u8; HELLO_MESSAGE_BYTES];
    encode_header(&mut wire[..AUTH_HEADER_BYTES], message.kind);
    wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]
        .copy_from_slice(&message.server_nonce);
    wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..].copy_from_slice(&message.client_nonce);
    handshake.write_all(stream, &wire)
}

fn read_hello_message(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    expected_kind: u8,
) -> Result<HelloMessage, PeerAuthenticationError> {
    let mut wire = [0_u8; HELLO_MESSAGE_BYTES];
    handshake.read_exact(stream, &mut wire)?;
    decode_header(&wire[..AUTH_HEADER_BYTES], expected_kind)?;
    let mut server_nonce = [0_u8; AUTH_NONCE_BYTES];
    server_nonce.copy_from_slice(&wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]);
    let mut client_nonce = [0_u8; AUTH_NONCE_BYTES];
    client_nonce.copy_from_slice(&wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..]);
    Ok(HelloMessage {
        kind: expected_kind,
        server_nonce,
        client_nonce,
    })
}

fn write_proof_message(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    message: ProofMessage,
) -> Result<(), PeerAuthenticationError> {
    let mut wire = [0_u8; PROOF_MESSAGE_BYTES];
    encode_header(&mut wire[..AUTH_HEADER_BYTES], message.kind);
    wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES].copy_from_slice(&message.binding);
    wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..].copy_from_slice(&message.proof.identity_digest);
    handshake.write_all(stream, &wire)
}

fn read_proof_message(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    expected_kind: u8,
) -> Result<ProofMessage, PeerAuthenticationError> {
    let mut wire = [0_u8; PROOF_MESSAGE_BYTES];
    handshake.read_exact(stream, &mut wire)?;
    decode_header(&wire[..AUTH_HEADER_BYTES], expected_kind)?;
    let mut binding = [0_u8; AUTH_NONCE_BYTES];
    binding.copy_from_slice(&wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]);
    let mut identity_digest = [0_u8; AUTH_DIGEST_BYTES];
    identity_digest.copy_from_slice(&wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..]);
    Ok(ProofMessage {
        kind: expected_kind,
        binding,
        proof: PeerProof { identity_digest },
    })
}

fn write_acknowledgement(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    binding: [u8; AUTH_NONCE_BYTES],
) -> Result<(), PeerAuthenticationError> {
    let mut wire = [0_u8; ACK_MESSAGE_BYTES];
    encode_header(&mut wire[..AUTH_HEADER_BYTES], KIND_ACKNOWLEDGED);
    wire[AUTH_HEADER_BYTES..].copy_from_slice(&binding);
    handshake.write_all(stream, &wire)
}

fn read_acknowledgement(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
    expected_binding: [u8; AUTH_NONCE_BYTES],
) -> Result<(), PeerAuthenticationError> {
    let mut wire = [0_u8; ACK_MESSAGE_BYTES];
    handshake.read_exact(stream, &mut wire)?;
    decode_header(&wire[..AUTH_HEADER_BYTES], KIND_ACKNOWLEDGED)?;
    if wire[AUTH_HEADER_BYTES..] != expected_binding {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    Ok(())
}

fn encode_header(header: &mut [u8], kind: u8) {
    header.fill(0);
    header[0..AUTH_MAGIC.len()].copy_from_slice(AUTH_MAGIC);
    header[8..10].copy_from_slice(&AUTH_VERSION.to_be_bytes());
    header[10] = kind;
}

fn decode_header(header: &[u8], expected_kind: u8) -> Result<(), PeerAuthenticationError> {
    if header.len() != AUTH_HEADER_BYTES
        || header[0..AUTH_MAGIC.len()] != *AUTH_MAGIC
        || u16::from_be_bytes([header[8], header[9]]) != AUTH_VERSION
        || header[10] != expected_kind
        || header[11..].iter().any(|byte| *byte != 0)
    {
        return Err(PeerAuthenticationError::MalformedHandshake);
    }
    Ok(())
}

fn require_close_on_exec(stream: &UnixStream) -> Result<(), PeerAuthenticationError> {
    // SAFETY: `F_GETFD` reads descriptor flags from the live socket.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(handshake_error(&io::Error::last_os_error()));
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    Ok(())
}

fn require_supported_kernel() -> Result<(), PeerAuthenticationError> {
    let mut release = 0_i32;
    let mut length = size_of::<libc::c_int>();
    // SAFETY: the name is static and NUL-terminated; the output pointer and
    // length describe one writable c_int. This is a read-only sysctl.
    if unsafe {
        libc::sysctlbyname(
            c"kern.osreldate".as_ptr(),
            (&raw mut release).cast(),
            &raw mut length,
            ptr::null_mut(),
            0,
        )
    } == -1
    {
        return Err(PeerAuthenticationError::KernelVersion {
            kind: io::Error::last_os_error().kind(),
        });
    }
    if length != size_of::<libc::c_int>() || !is_supported_kernel_release(release) {
        return Err(PeerAuthenticationError::UnsupportedKernelVersion);
    }
    Ok(())
}

fn is_supported_kernel_release(release: libc::c_int) -> bool {
    (FREEBSD_14_4_OSRELDATE..FREEBSD_14_5_OSRELDATE).contains(&release)
        || (FREEBSD_15_1_OSRELDATE..FREEBSD_15_2_OSRELDATE).contains(&release)
}

fn require_local_stream(stream: &UnixStream) -> Result<(), PeerAuthenticationError> {
    let socket_type = socket_integer_option(stream, libc::SOL_SOCKET, libc::SO_TYPE)?;
    let domain = socket_integer_option(stream, libc::SOL_SOCKET, libc::SO_DOMAIN)?;
    if socket_type != libc::SOCK_STREAM || domain != libc::AF_UNIX {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    Ok(())
}

fn socket_integer_option(
    stream: &UnixStream,
    level: libc::c_int,
    option: libc::c_int,
) -> Result<libc::c_int, PeerAuthenticationError> {
    let mut value = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: `value` is exact-size writable storage and the socket is live.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            option,
            (&raw mut value).cast(),
            &raw mut length,
        )
    } == -1
    {
        return Err(last_credential_error());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    Ok(value)
}

fn socket_status_flags(stream: &UnixStream) -> Result<libc::c_int, PeerAuthenticationError> {
    // SAFETY: `F_GETFL` reads status flags from the live socket.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        Err(handshake_error(&io::Error::last_os_error()))
    } else {
        Ok(flags)
    }
}

fn poll_timeout_millis(timeout: Duration) -> libc::c_int {
    let rounded = timeout
        .as_millis()
        .saturating_add(u128::from(timeout.subsec_nanos() % 1_000_000 != 0));
    libc::c_int::try_from(rounded).unwrap_or(libc::c_int::MAX)
}

fn last_credential_error() -> PeerAuthenticationError {
    PeerAuthenticationError::Credential {
        kind: io::Error::last_os_error().kind(),
    }
}

fn handshake_error(error: &io::Error) -> PeerAuthenticationError {
    PeerAuthenticationError::Handshake { kind: error.kind() }
}

const fn handshake_timeout() -> PeerAuthenticationError {
    PeerAuthenticationError::Handshake {
        kind: io::ErrorKind::TimedOut,
    }
}

fn monitor_io_error(error: ObservationError) -> io::Error {
    match error {
        ObservationError::Read { kind, .. } => io::Error::from(kind),
        ObservationError::UnsupportedPlatform
        | ObservationError::Oversized { .. }
        | ObservationError::Malformed { .. }
        | ObservationError::ProcessChanged
        | ObservationError::TerminalAnchorChanged
        | ObservationError::TerminalBindingMismatch => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated IPC peer is no longer live",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::{
            fd::FromRawFd,
            unix::{
                net::{UnixListener, UnixStream},
                process::CommandExt,
            },
        },
        path::Path,
        process::{Command, Stdio},
        thread,
    };

    use super::*;

    const PEER_SOCKET: &str = "GUS_TEST_FREEBSD_AUTHENTICATED_PEER_SOCKET";
    const WRITE_THEN_EXIT: &str = "GUS_TEST_FREEBSD_PEER_WRITE_THEN_EXIT";
    const EXEC_DURING_HANDSHAKE: &str = "GUS_TEST_FREEBSD_PEER_EXEC_DURING_HANDSHAKE";
    const INHERITED_SOCKET_FD: &str = "GUS_TEST_FREEBSD_PEER_INHERITED_SOCKET_FD";
    const INHERITED_HANDSHAKE_BINDING: &str = "GUS_TEST_FREEBSD_PEER_INHERITED_HANDSHAKE_BINDING";

    pub(super) fn maybe_exec_during_handshake(
        stream: &UnixStream,
        binding: [u8; AUTH_NONCE_BYTES],
    ) {
        if std::env::var_os(EXEC_DURING_HANDSHAKE).is_none() {
            return;
        }
        let descriptor = stream.as_raw_fd();
        // SAFETY: the descriptor is live and both calls only update its flags.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert_ne!(flags, -1, "read inherited socket flags");
        // SAFETY: the descriptor remains live through the immediate exec.
        assert_ne!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            -1,
            "make test socket survive exec"
        );
        let error = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("peer_freebsd::tests::native_handshake_exec_survivor")
            .arg("--ignored")
            .env(INHERITED_SOCKET_FD, descriptor.to_string())
            .env(INHERITED_HANDSHAKE_BINDING, encode_binding(binding))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .exec();
        panic!("exec handshake survivor failed: {error}");
    }

    fn encode_binding(binding: [u8; AUTH_NONCE_BYTES]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(AUTH_NONCE_BYTES * 2);
        for byte in binding {
            write!(&mut encoded, "{byte:02x}").expect("write binding to String");
        }
        encoded
    }

    fn inherited_binding() -> [u8; AUTH_NONCE_BYTES] {
        let encoded =
            std::env::var(INHERITED_HANDSHAKE_BINDING).expect("inherited handshake binding");
        assert_eq!(
            encoded.len(),
            AUTH_NONCE_BYTES * 2,
            "inherited handshake binding length"
        );
        let mut binding = [0; AUTH_NONCE_BYTES];
        for (index, byte) in binding.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16)
                .expect("hex-encoded inherited handshake binding");
        }
        binding
    }

    #[test]
    fn authenticates_both_sides_before_application_io() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_freebsd::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer child");
        let (stream, _) = listener.accept().expect("accept peer child");
        let mut authenticated = AuthenticatedUnixStream::authenticate_incoming(stream)
            .expect("authenticate peer child");
        assert_eq!(authenticated.peer_identity().pid().get(), child.id());
        authenticated.write_all(&[1]).expect("release peer child");
        assert!(child.wait().expect("wait for peer child").success());
    }

    #[test]
    fn socket_pair_credentials_bind_the_live_process() {
        let (first, second) = UnixStream::pair().expect("create peer pair");
        let first_credential = peer_credential(&first).expect("first peer credential");
        let second_credential = peer_credential(&second).expect("second peer credential");
        let pid = std::process::id();
        assert_eq!(first_credential.pid.get(), pid);
        assert_eq!(second_credential.pid.get(), pid);
        assert_eq!(first_credential.effective_uid, current_effective_uid());
        assert_eq!(second_credential.effective_uid, current_effective_uid());
        assert_eq!(
            format!("{first_credential:?}"),
            "PeerCredential([REDACTED])"
        );
    }

    #[test]
    fn runtime_admission_accepts_only_the_evidenced_release_families() {
        assert!(!is_supported_kernel_release(1_204_000));
        assert!(!is_supported_kernel_release(1_403_999));
        assert!(is_supported_kernel_release(1_404_000));
        assert!(is_supported_kernel_release(1_404_999));
        assert!(!is_supported_kernel_release(1_405_000));
        assert!(!is_supported_kernel_release(1_500_068));
        assert!(!is_supported_kernel_release(1_500_999));
        assert!(is_supported_kernel_release(1_501_000));
        assert!(is_supported_kernel_release(1_501_999));
        assert!(!is_supported_kernel_release(1_502_000));
        assert!(!is_supported_kernel_release(1_600_000));
    }

    #[test]
    fn authenticates_a_socket_pair_and_preserves_application_bytes() {
        let (server, client) = UnixStream::pair().expect("create peer pair");
        let client_thread = thread::spawn(move || {
            let mut authenticated = AuthenticatedUnixStream::authenticate_outgoing(client)
                .expect("authenticate outgoing peer");
            authenticated
                .write_all(&[0xa5])
                .expect("write application byte");
        });
        let mut authenticated = AuthenticatedUnixStream::authenticate_incoming(server)
            .expect("authenticate incoming peer");
        let mut byte = [0];
        authenticated
            .read_exact(&mut byte)
            .expect("read application byte");
        assert_eq!(byte, [0xa5]);
        client_thread.join().expect("join authenticated client");
    }

    #[test]
    fn rejects_a_response_with_the_wrong_handshake_binding() {
        let (server, mut client) = UnixStream::pair().expect("create peer pair");
        let client_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&client).expect("begin client handshake");
            let server_hello = read_hello_message(&mut client, &handshake, KIND_SERVER_HELLO)
                .expect("read server hello");
            let client_nonce = [7; AUTH_NONCE_BYTES];
            write_hello_message(
                &mut client,
                &handshake,
                HelloMessage {
                    kind: KIND_CLIENT_HELLO,
                    server_nonce: server_hello.server_nonce,
                    client_nonce,
                },
            )
            .expect("write client hello");
            let challenge = read_proof_message(&mut client, &handshake, KIND_CHALLENGE)
                .expect("read challenge");
            let mut wrong_binding = challenge.binding;
            wrong_binding[0] ^= 1;
            write_proof_message(
                &mut client,
                &handshake,
                ProofMessage {
                    kind: KIND_RESPONSE,
                    binding: wrong_binding,
                    proof: current_proof(challenge.binding, KIND_RESPONSE).expect("current proof"),
                },
            )
            .expect("write mismatched response");
        });
        assert_eq!(
            AuthenticatedUnixStream::authenticate_incoming(server)
                .expect_err("wrong binding must be rejected"),
            PeerAuthenticationError::ProofMismatch
        );
        client_thread.join().expect("join raw client");
    }

    #[test]
    fn rejects_a_tampered_process_identity_proof() {
        let (server, mut client) = UnixStream::pair().expect("create peer pair");
        let client_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&client).expect("begin client handshake");
            let server_hello = read_hello_message(&mut client, &handshake, KIND_SERVER_HELLO)
                .expect("read server hello");
            let client_nonce = [9; AUTH_NONCE_BYTES];
            write_hello_message(
                &mut client,
                &handshake,
                HelloMessage {
                    kind: KIND_CLIENT_HELLO,
                    server_nonce: server_hello.server_nonce,
                    client_nonce,
                },
            )
            .expect("write client hello");
            let challenge = read_proof_message(&mut client, &handshake, KIND_CHALLENGE)
                .expect("read challenge");
            let mut proof = current_proof(challenge.binding, KIND_RESPONSE).expect("current proof");
            proof.identity_digest[0] ^= 1;
            write_proof_message(
                &mut client,
                &handshake,
                ProofMessage {
                    kind: KIND_RESPONSE,
                    binding: challenge.binding,
                    proof,
                },
            )
            .expect("write tampered response");
            let mut acknowledgement = [0];
            assert!(
                handshake
                    .read_exact(&mut client, &mut acknowledgement)
                    .is_err(),
                "server must close without acknowledging a tampered proof"
            );
        });
        assert_eq!(
            AuthenticatedUnixStream::authenticate_incoming(server)
                .expect_err("tampered proof must be rejected"),
            PeerAuthenticationError::ProofMismatch
        );
        client_thread.join().expect("join tampered client");
    }

    #[test]
    fn rejects_process_proofs_from_another_transcript_or_role() {
        for (use_other_binding, proof_role) in [(true, KIND_RESPONSE), (false, KIND_CHALLENGE)] {
            let (server, mut client) = UnixStream::pair().expect("create peer pair");
            let client_thread = thread::spawn(move || {
                let handshake = HandshakeIo::begin(&client).expect("begin client handshake");
                let server_hello = read_hello_message(&mut client, &handshake, KIND_SERVER_HELLO)
                    .expect("read server hello");
                let client_nonce = [11; AUTH_NONCE_BYTES];
                write_hello_message(
                    &mut client,
                    &handshake,
                    HelloMessage {
                        kind: KIND_CLIENT_HELLO,
                        server_nonce: server_hello.server_nonce,
                        client_nonce,
                    },
                )
                .expect("write client hello");
                let challenge = read_proof_message(&mut client, &handshake, KIND_CHALLENGE)
                    .expect("read challenge");
                let mut proof_binding = challenge.binding;
                if use_other_binding {
                    proof_binding[0] ^= 1;
                }
                write_proof_message(
                    &mut client,
                    &handshake,
                    ProofMessage {
                        kind: KIND_RESPONSE,
                        binding: challenge.binding,
                        proof: current_proof(proof_binding, proof_role)
                            .expect("cross-context proof"),
                    },
                )
                .expect("write cross-context response");
                let mut acknowledgement = [0];
                assert!(
                    handshake
                        .read_exact(&mut client, &mut acknowledgement)
                        .is_err(),
                    "server must close without acknowledging a cross-context proof"
                );
            });
            assert_eq!(
                AuthenticatedUnixStream::authenticate_incoming(server)
                    .expect_err("cross-context proof must be rejected"),
                PeerAuthenticationError::ProofMismatch
            );
            client_thread.join().expect("join cross-context client");
        }
    }

    #[test]
    fn outgoing_rejects_process_proofs_from_another_transcript_or_role() {
        for (use_other_binding, proof_role) in [(true, KIND_CHALLENGE), (false, KIND_RESPONSE)] {
            let (mut server, client) = UnixStream::pair().expect("create peer pair");
            let server_thread = thread::spawn(move || {
                let handshake = HandshakeIo::begin(&server).expect("begin server handshake");
                let server_nonce = [13; AUTH_NONCE_BYTES];
                write_hello_message(
                    &mut server,
                    &handshake,
                    HelloMessage {
                        kind: KIND_SERVER_HELLO,
                        server_nonce,
                        client_nonce: [0; AUTH_NONCE_BYTES],
                    },
                )
                .expect("write server hello");
                let client_hello = read_hello_message(&mut server, &handshake, KIND_CLIENT_HELLO)
                    .expect("read client hello");
                let binding = handshake_binding(server_nonce, client_hello.client_nonce);
                let mut proof_binding = binding;
                if use_other_binding {
                    proof_binding[0] ^= 1;
                }
                write_proof_message(
                    &mut server,
                    &handshake,
                    ProofMessage {
                        kind: KIND_CHALLENGE,
                        binding,
                        proof: current_proof(proof_binding, proof_role)
                            .expect("cross-context proof"),
                    },
                )
                .expect("write cross-context challenge");
                let mut response = [0];
                assert!(
                    handshake.read_exact(&mut server, &mut response).is_err(),
                    "client must close without answering a cross-context proof"
                );
            });
            assert_eq!(
                AuthenticatedUnixStream::authenticate_outgoing(client)
                    .expect_err("cross-context proof must be rejected"),
                PeerAuthenticationError::ProofMismatch
            );
            server_thread.join().expect("join cross-context server");
        }
    }

    #[test]
    fn outgoing_authentication_rejects_a_wrong_acknowledgement() {
        let (mut server, client) = UnixStream::pair().expect("create peer pair");
        let server_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&server).expect("begin server handshake");
            let connect_credential = peer_credential(&server).expect("client credential");
            let pending = begin_peer_authentication(&server, connect_credential)
                .expect("monitor client before first handshake I/O");
            let server_nonce = [5; AUTH_NONCE_BYTES];
            write_hello_message(
                &mut server,
                &handshake,
                HelloMessage {
                    kind: KIND_SERVER_HELLO,
                    server_nonce,
                    client_nonce: [0; AUTH_NONCE_BYTES],
                },
            )
            .expect("write server hello");
            let client_hello = read_hello_message(&mut server, &handshake, KIND_CLIENT_HELLO)
                .expect("read client hello");
            let binding = handshake_binding(server_nonce, client_hello.client_nonce);
            write_proof_message(
                &mut server,
                &handshake,
                ProofMessage {
                    kind: KIND_CHALLENGE,
                    binding,
                    proof: current_proof(binding, KIND_CHALLENGE).expect("server proof"),
                },
            )
            .expect("write server proof");
            let response = read_proof_message(&mut server, &handshake, KIND_RESPONSE)
                .expect("read client proof");
            finish_peer_authentication(&server, pending, response.proof, binding, KIND_RESPONSE)
                .expect("authenticate client proof");
            let mut wrong_binding = binding;
            wrong_binding[0] ^= 1;
            write_acknowledgement(&mut server, &handshake, wrong_binding)
                .expect("write wrong acknowledgement");
        });
        assert_eq!(
            AuthenticatedUnixStream::authenticate_outgoing(client)
                .expect_err("wrong acknowledgement must be rejected"),
            PeerAuthenticationError::ProofMismatch
        );
        server_thread.join().expect("join raw server");
    }

    #[test]
    fn rejects_application_bytes_instead_of_a_handshake() {
        let (server, mut client) = UnixStream::pair().expect("create peer pair");
        let client_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&client).expect("begin client handshake");
            let mut hello = [0_u8; HELLO_MESSAGE_BYTES];
            handshake
                .read_exact(&mut client, &mut hello)
                .expect("read server hello");
            handshake
                .write_all(&mut client, &[0_u8; HELLO_MESSAGE_BYTES])
                .expect("write invalid application bytes");
        });
        assert_eq!(
            AuthenticatedUnixStream::authenticate_incoming(server)
                .expect_err("application bytes must not enter authentication"),
            PeerAuthenticationError::MalformedHandshake
        );
        client_thread.join().expect("join raw client");
    }

    #[test]
    fn handshake_has_one_absolute_deadline_against_slow_drip_input() {
        let (mut server, mut client) = UnixStream::pair().expect("create peer pair");
        let handshake = HandshakeIo::begin_with_budget(&server, Duration::from_millis(80))
            .expect("begin short handshake");
        let client_thread = thread::spawn(move || {
            for byte in 0_u8..16 {
                thread::sleep(Duration::from_millis(20));
                if client.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        let mut input = [0_u8; 16];
        assert_eq!(
            handshake
                .read_exact(&mut server, &mut input)
                .expect_err("slow drip must exceed one total deadline"),
            handshake_timeout()
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(server);
        client_thread.join().expect("join slow client");
    }

    #[test]
    fn successful_handshake_preserves_timeouts_and_status_flags() {
        let (server, client) = UnixStream::pair().expect("create peer pair");
        server
            .set_nonblocking(true)
            .expect("set server nonblocking");
        client
            .set_nonblocking(true)
            .expect("set client nonblocking");
        let server_flags = socket_status_flags(&server).expect("server status flags");
        let client_flags = socket_status_flags(&client).expect("client status flags");
        assert_ne!(server_flags & libc::O_NONBLOCK, 0);
        assert_ne!(client_flags & libc::O_NONBLOCK, 0);
        let server_read_timeout = Duration::from_millis(700);
        let server_write_timeout = Duration::from_millis(750);
        let client_read_timeout = Duration::from_millis(800);
        let client_write_timeout = Duration::from_millis(850);
        server
            .set_read_timeout(Some(server_read_timeout))
            .expect("set server read timeout");
        server
            .set_write_timeout(Some(server_write_timeout))
            .expect("set server write timeout");
        client
            .set_read_timeout(Some(client_read_timeout))
            .expect("set client read timeout");
        client
            .set_write_timeout(Some(client_write_timeout))
            .expect("set client write timeout");
        let client_thread = thread::spawn(move || {
            let authenticated = AuthenticatedUnixStream::authenticate_outgoing(client)
                .expect("authenticate outgoing peer");
            assert_eq!(
                authenticated
                    .stream
                    .read_timeout()
                    .expect("client read timeout"),
                Some(client_read_timeout)
            );
            assert_eq!(
                authenticated
                    .stream
                    .write_timeout()
                    .expect("client write timeout"),
                Some(client_write_timeout)
            );
            assert_eq!(
                socket_status_flags(&authenticated.stream).expect("client flags"),
                client_flags
            );
        });
        let authenticated = AuthenticatedUnixStream::authenticate_incoming(server)
            .expect("authenticate incoming peer");
        assert_eq!(
            authenticated
                .stream
                .read_timeout()
                .expect("server read timeout"),
            Some(server_read_timeout)
        );
        assert_eq!(
            authenticated
                .stream
                .write_timeout()
                .expect("server write timeout"),
            Some(server_write_timeout)
        );
        assert_eq!(
            socket_status_flags(&authenticated.stream).expect("server flags"),
            server_flags
        );
        client_thread.join().expect("join authenticated client");
    }

    #[test]
    fn rejects_a_socket_without_close_on_exec() {
        let (server, _client) = UnixStream::pair().expect("create peer pair");
        // SAFETY: the descriptor is live and both calls only change its flags.
        let flags = unsafe { libc::fcntl(server.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1, "read descriptor flags");
        // SAFETY: the descriptor remains owned by `server`.
        assert_ne!(
            unsafe { libc::fcntl(server.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            -1,
            "clear close-on-exec"
        );
        assert_eq!(
            AuthenticatedUnixStream::authenticate_incoming(server)
                .expect_err("inheritable socket must be rejected"),
            PeerAuthenticationError::MalformedCredential
        );
    }

    #[test]
    fn rejects_queued_input_after_the_authenticated_peer_exits() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("queued-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_freebsd::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .env(WRITE_THEN_EXIT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn queued peer child");
        let (stream, _) = listener.accept().expect("accept queued peer child");
        let mut authenticated = AuthenticatedUnixStream::authenticate_incoming(stream)
            .expect("authenticate queued peer child");
        authenticated
            .stream
            .write_all(&[1])
            .expect("release queued peer child");
        assert!(child.wait().expect("wait for queued peer child").success());
        let mut queued = [0];
        assert_eq!(
            authenticated
                .read_exact(&mut queued)
                .expect_err("queued bytes from an exited peer must be rejected")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let second = authenticated
            .read(&mut queued)
            .expect_err("revoked peer must remain rejected");
        assert_eq!(second.kind(), io::ErrorKind::PermissionDenied);
        let write = authenticated
            .write(&[3])
            .expect_err("writes to a revoked peer must remain rejected");
        assert_eq!(write.kind(), io::ErrorKind::PermissionDenied);
        let flush = authenticated
            .flush()
            .expect_err("flush on a revoked peer must remain rejected");
        assert_eq!(flush.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_exec_after_monitor_registration_and_before_proof() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("exec-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_freebsd::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .env(EXEC_DURING_HANDSHAKE, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn exec peer child");
        let (stream, _) = listener.accept().expect("accept exec peer child");
        assert!(
            AuthenticatedUnixStream::authenticate_incoming(stream).is_err(),
            "an exec after monitor registration must revoke authentication"
        );
        assert!(child.wait().expect("wait for exec peer child").success());
    }

    #[test]
    fn every_debug_surface_redacts_native_authentication_evidence() {
        let (first, _second) = UnixStream::pair().expect("create peer pair");
        let credential = peer_credential(&first).expect("peer credential");
        let proof = current_proof([0; AUTH_NONCE_BYTES], KIND_RESPONSE).expect("current proof");
        assert_eq!(format!("{credential:?}"), "PeerCredential([REDACTED])");
        assert_eq!(format!("{proof:?}"), "PeerProof([REDACTED])");
    }

    #[test]
    fn process_consistency_proof_separates_transcript_and_role() {
        let identity = current_identity().expect("current identity");
        let first_binding = [1; AUTH_NONCE_BYTES];
        let second_binding = [2; AUTH_NONCE_BYTES];
        let server = peer_process_proof(identity, first_binding, KIND_CHALLENGE);
        assert_ne!(
            server,
            peer_process_proof(identity, second_binding, KIND_CHALLENGE)
        );
        assert_ne!(
            server,
            peer_process_proof(identity, first_binding, KIND_RESPONSE)
        );
    }

    #[test]
    #[ignore = "internal child process for native FreeBSD authenticated-peer tests"]
    fn native_authenticated_peer_child() {
        let Some(socket_path) = std::env::var_os(PEER_SOCKET) else {
            return;
        };
        let stream = UnixStream::connect(Path::new(&socket_path)).expect("connect to parent");
        let mut authenticated = AuthenticatedUnixStream::authenticate_outgoing(stream)
            .expect("authenticate parent broker");
        let mut release = [0_u8; 1];
        authenticated
            .read_exact(&mut release)
            .expect("wait for parent");
        if std::env::var_os(WRITE_THEN_EXIT).is_some() {
            authenticated
                .write_all(&[0xa5])
                .expect("queue input before exit");
        }
    }

    #[test]
    #[ignore = "internal exec survivor for native FreeBSD peer-authentication tests"]
    fn native_handshake_exec_survivor() {
        let Some(descriptor) = std::env::var_os(INHERITED_SOCKET_FD) else {
            return;
        };
        let descriptor = descriptor
            .to_string_lossy()
            .parse::<i32>()
            .expect("inherited socket descriptor");
        // SAFETY: the preceding test process deliberately preserved ownership
        // of this exact descriptor across exec and relinquished it by exec.
        let mut stream = unsafe { UnixStream::from_raw_fd(descriptor) };
        // SAFETY: the descriptor is live and this restores the production
        // close-on-exec invariant before any further protocol operation.
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1, "read survivor socket flags");
        // SAFETY: the descriptor remains owned by `stream`.
        assert_ne!(
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            -1,
            "restore close-on-exec"
        );
        let handshake = HandshakeIo::begin(&stream).expect("resume handshake after exec");
        let binding = inherited_binding();
        write_proof_message(
            &mut stream,
            &handshake,
            ProofMessage {
                kind: KIND_RESPONSE,
                binding,
                proof: current_proof(binding, KIND_RESPONSE).expect("post-exec current proof"),
            },
        )
        .expect("write post-exec proof");
        assert!(
            read_acknowledgement(&mut stream, &handshake, binding).is_err(),
            "broker must revoke the connection instead of acknowledging exec"
        );
    }
}
