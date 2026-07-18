use std::{
    fmt,
    io::{self, Read, Write},
    mem::{MaybeUninit, size_of},
    num::NonZeroU32,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    NativeProcessObserver, ObservationError, ObservationResource, OsUserIdentity, PlatformFamily,
    ProcessIdentity, bsd::ProcessExitMonitor,
};

const AUTH_MAGIC: &[u8; 8] = b"GUSPAUTH";
const AUTH_VERSION: u16 = 1;
const AUTH_HEADER_BYTES: usize = 16;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_DIGEST_BYTES: usize = 32;
const AUDIT_TOKEN_WORDS: usize = 8;
const AUDIT_TOKEN_BYTES: usize = AUDIT_TOKEN_WORDS * size_of::<u32>();
const HELLO_MESSAGE_BYTES: usize = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES * 2;
const PROOF_MESSAGE_BYTES: usize =
    AUTH_HEADER_BYTES + AUTH_NONCE_BYTES + AUTH_DIGEST_BYTES + AUDIT_TOKEN_BYTES;
const ACK_MESSAGE_BYTES: usize = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES;
const KIND_SERVER_HELLO: u8 = 1;
const KIND_CLIENT_HELLO: u8 = 2;
const KIND_CHALLENGE: u8 = 3;
const KIND_RESPONSE: u8 = 4;
const KIND_ACKNOWLEDGED: u8 = 5;
const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A macOS Unix stream authenticated before any application frame is decoded.
///
/// Authentication binds the process which last accessed its peer socket during
/// a phased broker challenge to a kernel audit token, effective user, process
/// start identity, and retained `NOTE_EXIT | NOTE_EXEC` monitor. This remains a
/// connection capability, not proof of each later accessor: callers must pass
/// a freshly connected/accepted close-on-exec stream and must not transfer or
/// share its descriptor. Processes under one OS user are outside GUS's
/// mutually-distrustful security boundary.
pub struct AuthenticatedUnixStream {
    stream: UnixStream,
    peer: ProcessIdentity,
    peer_monitor: ProcessExitMonitor,
}

impl AuthenticatedUnixStream {
    /// Authenticates a broker-side accepted stream with a fresh challenge.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, malformed proof, unavailable kernel evidence,
    /// PID reuse, peer exit/exec, or an effective-user mismatch.
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
    /// The connector does not send application bytes until the broker returns
    /// the fixed acknowledgement for this challenge.
    ///
    /// # Errors
    ///
    /// Fails closed on timeout, malformed challenge, unavailable kernel
    /// evidence, PID reuse, broker exit/exec, or an effective-user mismatch.
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

    /// Returns the process identity bound to this connection's authority.
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

    fn require_connection_live(&self) -> io::Result<()> {
        self.peer_monitor.ensure_live().map_err(monitor_io_error)
    }
}

fn authenticate_incoming(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let connect_user = peer_user(stream)?;
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
    let pending_peer = begin_peer_authentication(stream, connect_user)?;
    let binding = handshake_binding(server_nonce, client_hello.client_nonce);
    write_proof_message(
        stream,
        handshake,
        ProofMessage {
            kind: KIND_CHALLENGE,
            binding,
            proof: current_proof()?,
        },
    )?;
    let response = read_proof_message(stream, handshake, KIND_RESPONSE)?;
    if response.binding != binding {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let (peer, peer_monitor) = finish_peer_authentication(stream, pending_peer, response.proof)?;
    write_acknowledgement(stream, handshake, binding)?;
    peer_monitor.ensure_live()?;
    Ok((peer, peer_monitor))
}

fn authenticate_outgoing(
    stream: &mut UnixStream,
    handshake: &HandshakeIo,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let connect_user = peer_user(stream)?;
    let server_hello = read_hello_message(stream, handshake, KIND_SERVER_HELLO)?;
    if server_hello.client_nonce.iter().any(|byte| *byte != 0) {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    let pending_peer = begin_peer_authentication(stream, connect_user)?;
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
    let (peer, peer_monitor) = finish_peer_authentication(stream, pending_peer, challenge.proof)?;
    #[cfg(test)]
    tests::maybe_exec_during_handshake(stream, binding);
    write_proof_message(
        stream,
        handshake,
        ProofMessage {
            kind: KIND_RESPONSE,
            binding,
            proof: current_proof()?,
        },
    )?;
    read_acknowledgement(stream, handshake, binding)?;
    peer_monitor.ensure_live()?;
    Ok((peer, peer_monitor))
}

impl fmt::Debug for AuthenticatedUnixStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedUnixStream")
            .field("peer", &self.peer)
            .field("peer_monitor", &"<retained>")
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

/// Failure to authenticate a native macOS IPC peer.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthenticationError {
    #[error("failed to read a kernel peer credential: {kind:?}")]
    Credential { kind: io::ErrorKind },
    #[error("peer credential had a malformed native representation")]
    MalformedCredential,
    #[error("failed to transfer the bounded peer-authentication handshake: {kind:?}")]
    Handshake { kind: io::ErrorKind },
    #[error("peer-authentication handshake was malformed or unsupported")]
    MalformedHandshake,
    #[error("peer-authentication proof did not match its challenge or kernel evidence")]
    ProofMismatch,
    #[error("the operating system could not generate a peer-authentication challenge")]
    RandomUnavailable,
    #[error("the current process audit token was unavailable")]
    AuditTokenUnavailable,
    #[error("socket and process observations reported different users")]
    UserMismatch,
    #[error("failed to observe the authenticated peer process: {0}")]
    ProcessObservation(#[from] ObservationError),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct AuditToken {
    words: [u32; AUDIT_TOKEN_WORDS],
}

impl fmt::Debug for AuditToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditToken([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerProof {
    identity_digest: [u8; AUTH_DIGEST_BYTES],
    audit_token: AuditToken,
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
    connect_user: OsUserIdentity,
    pid: NonZeroU32,
    audit_token: AuditToken,
    monitor: ProcessExitMonitor,
}

struct HandshakeIo {
    deadline: Instant,
    original_read_timeout: Option<Duration>,
    original_write_timeout: Option<Duration>,
}

impl HandshakeIo {
    fn begin(stream: &UnixStream) -> Result<Self, PeerAuthenticationError> {
        Self::begin_with_budget(stream, HANDSHAKE_TIMEOUT)
    }

    fn begin_with_budget(
        stream: &UnixStream,
        budget: Duration,
    ) -> Result<Self, PeerAuthenticationError> {
        require_close_on_exec(stream)?;
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(handshake_timeout)?;
        let original_read_timeout = stream
            .read_timeout()
            .map_err(|error| handshake_error(&error))?;
        let original_write_timeout = stream
            .write_timeout()
            .map_err(|error| handshake_error(&error))?;
        Ok(Self {
            deadline,
            original_read_timeout,
            original_write_timeout,
        })
    }

    fn read_exact(
        &self,
        stream: &mut UnixStream,
        mut buffer: &mut [u8],
    ) -> Result<(), PeerAuthenticationError> {
        while !buffer.is_empty() {
            stream
                .set_read_timeout(Some(self.remaining(self.original_read_timeout)?))
                .map_err(|error| handshake_error(&error))?;
            match stream.read(buffer) {
                Ok(0) => {
                    return Err(PeerAuthenticationError::Handshake {
                        kind: io::ErrorKind::UnexpectedEof,
                    });
                }
                Ok(read) => buffer = &mut buffer[read..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(self.normalize_io_error(&error)),
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
            stream
                .set_write_timeout(Some(self.remaining(self.original_write_timeout)?))
                .map_err(|error| handshake_error(&error))?;
            match stream.write(buffer) {
                Ok(0) => {
                    return Err(PeerAuthenticationError::Handshake {
                        kind: io::ErrorKind::WriteZero,
                    });
                }
                Ok(written) => buffer = &buffer[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(self.normalize_io_error(&error)),
            }
        }
        Ok(())
    }

    fn restore(&self, stream: &UnixStream) -> Result<(), PeerAuthenticationError> {
        stream
            .set_read_timeout(self.original_read_timeout)
            .map_err(|error| handshake_error(&error))?;
        stream
            .set_write_timeout(self.original_write_timeout)
            .map_err(|error| handshake_error(&error))
    }

    fn remaining(
        &self,
        original_timeout: Option<Duration>,
    ) -> Result<Duration, PeerAuthenticationError> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(handshake_timeout)?;
        Ok(original_timeout.map_or(remaining, |original| original.min(remaining)))
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

fn require_close_on_exec(stream: &UnixStream) -> Result<(), PeerAuthenticationError> {
    // SAFETY: `fcntl(F_GETFD)` only reads descriptor flags from the live
    // borrowed socket and has no pointer arguments.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(last_credential_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    Ok(())
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
    hasher.update(b"gus.platform.macos-peer-handshake.v1");
    hasher.update(server_nonce);
    hasher.update(client_nonce);
    hasher.finalize().into()
}

fn current_proof() -> Result<PeerProof, PeerAuthenticationError> {
    let pid =
        NonZeroU32::new(std::process::id()).ok_or(PeerAuthenticationError::MalformedCredential)?;
    let identity = NativeProcessObserver::new(pid).observe()?;
    Ok(PeerProof {
        identity_digest: process_identity_digest(identity),
        audit_token: current_audit_token()?,
    })
}

fn begin_peer_authentication(
    stream: &UnixStream,
    connect_user: OsUserIdentity,
) -> Result<PendingPeerAuthentication, PeerAuthenticationError> {
    let first_pid = peer_pid(stream)?;
    let first_token = peer_audit_token(stream)?;
    let monitor = ProcessExitMonitor::new_with_notifications(
        first_pid,
        ObservationResource::TargetProcess,
        ObservationError::ProcessChanged,
        libc::NOTE_EXIT | libc::NOTE_EXEC,
    )?;
    let second_pid = peer_pid(stream)?;
    let second_token = peer_audit_token(stream)?;
    let second_user = peer_user(stream)?;
    monitor.ensure_live()?;
    if first_pid != second_pid || first_token != second_token {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    if connect_user != second_user {
        return Err(PeerAuthenticationError::UserMismatch);
    }
    Ok(PendingPeerAuthentication {
        connect_user,
        pid: first_pid,
        audit_token: first_token,
        monitor,
    })
}

fn finish_peer_authentication(
    stream: &UnixStream,
    pending: PendingPeerAuthentication,
    proof: PeerProof,
) -> Result<(ProcessIdentity, ProcessExitMonitor), PeerAuthenticationError> {
    let peer = NativeProcessObserver::new(pending.pid).observe()?;
    let final_pid = peer_pid(stream)?;
    let final_token = peer_audit_token(stream)?;
    let final_user = peer_user(stream)?;
    pending.monitor.ensure_live()?;
    if pending.pid != final_pid
        || pending.audit_token != final_token
        || final_token != proof.audit_token
        || process_identity_digest(peer) != proof.identity_digest
    {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    if pending.connect_user != final_user || peer.user() != pending.connect_user {
        return Err(PeerAuthenticationError::UserMismatch);
    }
    Ok((peer, pending.monitor))
}

fn process_identity_digest(identity: ProcessIdentity) -> [u8; AUTH_DIGEST_BYTES] {
    let mut native = [0_u8; 76];
    native[0..32].copy_from_slice(&identity.time_domain.0);
    native[32..36].copy_from_slice(&identity.pid.get().to_le_bytes());
    native[36..44].copy_from_slice(&identity.start_time.get().to_le_bytes());
    native[44..76].copy_from_slice(&identity.user.digest);
    crate::identity_digest(
        b"gus.platform.peer-process-proof.v1",
        PlatformFamily::MacOs,
        &native,
    )
}

fn current_audit_token() -> Result<AuditToken, PeerAuthenticationError> {
    let mut token = MaybeUninit::<AuditToken>::uninit();
    let mut count = libc::mach_msg_type_number_t::try_from(
        size_of::<AuditToken>() / size_of::<libc::natural_t>(),
    )
    .map_err(|_| PeerAuthenticationError::AuditTokenUnavailable)?;
    // SAFETY: `token` is exact-size aligned writable storage, the count is in
    // native integer units, and `mach_task_self` returns the current task port.
    let result = unsafe {
        libc::task_info(
            current_task(),
            TASK_AUDIT_TOKEN,
            token.as_mut_ptr().cast(),
            &raw mut count,
        )
    };
    let expected_count = libc::mach_msg_type_number_t::try_from(
        size_of::<AuditToken>() / size_of::<libc::natural_t>(),
    )
    .map_err(|_| PeerAuthenticationError::AuditTokenUnavailable)?;
    if result != libc::KERN_SUCCESS || count != expected_count {
        return Err(PeerAuthenticationError::AuditTokenUnavailable);
    }
    // SAFETY: successful `task_info` with the exact count initialized token.
    Ok(unsafe { token.assume_init() })
}

fn peer_pid(stream: &UnixStream) -> Result<NonZeroU32, PeerAuthenticationError> {
    let mut pid = 0_i32;
    let mut length = libc::socklen_t::try_from(size_of::<libc::pid_t>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: `pid` is exact-size writable storage and the socket is live.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(last_credential_error());
    }
    if length as usize != size_of::<libc::pid_t>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    u32::try_from(pid)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(PeerAuthenticationError::MalformedCredential)
}

fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken, PeerAuthenticationError> {
    let mut token = MaybeUninit::<AuditToken>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<AuditToken>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: `token` is exact-size aligned writable storage and the socket is
    // live. The token remains opaque and is only compared byte-for-byte.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(last_credential_error());
    }
    if length as usize != size_of::<AuditToken>() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    // SAFETY: exact-size successful `getsockopt` initialized the token.
    Ok(unsafe { token.assume_init() })
}

fn peer_user(stream: &UnixStream) -> Result<OsUserIdentity, PeerAuthenticationError> {
    let mut credential = MaybeUninit::<libc::xucred>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<libc::xucred>())
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    // SAFETY: `credential` is exact-size aligned writable storage and the
    // socket is live.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
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
    // SAFETY: exact-size successful `getsockopt` initialized the credential.
    let credential = unsafe { credential.assume_init() };
    let group_count = usize::try_from(credential.cr_ngroups)
        .map_err(|_| PeerAuthenticationError::MalformedCredential)?;
    if credential.cr_version != libc::XUCRED_VERSION || group_count > credential.cr_groups.len() {
        return Err(PeerAuthenticationError::MalformedCredential);
    }
    let mut native = [0_u8; 8];
    native[0..4].copy_from_slice(&credential.cr_uid.to_le_bytes());
    Ok(OsUserIdentity::from_native_bytes(
        PlatformFamily::MacOs,
        &native,
    ))
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
    let digest_start = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES;
    wire[digest_start..digest_start + AUTH_DIGEST_BYTES]
        .copy_from_slice(&message.proof.identity_digest);
    let token_start = digest_start + AUTH_DIGEST_BYTES;
    for (index, word) in message.proof.audit_token.words.iter().enumerate() {
        let start = token_start + index * size_of::<u32>();
        wire[start..start + size_of::<u32>()].copy_from_slice(&word.to_be_bytes());
    }
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
    let digest_start = AUTH_HEADER_BYTES + AUTH_NONCE_BYTES;
    let mut identity_digest = [0_u8; AUTH_DIGEST_BYTES];
    identity_digest.copy_from_slice(&wire[digest_start..digest_start + AUTH_DIGEST_BYTES]);
    let token_start = digest_start + AUTH_DIGEST_BYTES;
    let mut words = [0_u32; AUDIT_TOKEN_WORDS];
    for (index, word) in words.iter_mut().enumerate() {
        let start = token_start + index * size_of::<u32>();
        let bytes: [u8; size_of::<u32>()] = wire[start..start + size_of::<u32>()]
            .try_into()
            .map_err(|_| PeerAuthenticationError::MalformedHandshake)?;
        *word = u32::from_be_bytes(bytes);
    }
    Ok(ProofMessage {
        kind: expected_kind,
        binding,
        proof: PeerProof {
            identity_digest,
            audit_token: AuditToken { words },
        },
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

#[allow(
    deprecated,
    reason = "libc exposes the stable mach_task_self trap with a deprecation toward an unnecessary wrapper crate"
)]
fn current_task() -> libc::mach_port_t {
    // SAFETY: `mach_task_self` has no preconditions and returns a borrowed send
    // right for the current task.
    unsafe { libc::mach_task_self() }
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
            fd::{AsRawFd, FromRawFd},
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

    const PEER_SOCKET: &str = "GUS_TEST_MACOS_AUTHENTICATED_PEER_SOCKET";
    const WRITE_THEN_EXIT: &str = "GUS_TEST_MACOS_AUTHENTICATED_PEER_WRITE_THEN_EXIT";
    const EXEC_DURING_HANDSHAKE: &str = "GUS_TEST_MACOS_PEER_EXEC_DURING_HANDSHAKE";
    const INHERITED_SOCKET_FD: &str = "GUS_TEST_MACOS_PEER_INHERITED_SOCKET_FD";
    const INHERITED_HANDSHAKE_BINDING: &str = "GUS_TEST_MACOS_PEER_INHERITED_HANDSHAKE_BINDING";

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
            .arg("peer_macos::tests::native_handshake_exec_survivor")
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
            .arg("peer_macos::tests::native_authenticated_peer_child")
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
                    proof: current_proof().expect("current proof"),
                },
            )
            .expect("write mismatched response");
        });
        assert_eq!(
            AuthenticatedUnixStream::authenticate_incoming(server)
                .expect_err("wrong nonce must be rejected"),
            PeerAuthenticationError::ProofMismatch
        );
        client_thread.join().expect("join raw client");
    }

    #[test]
    fn rejects_tampered_process_digest_and_audit_token_proofs() {
        assert_rejects_tampered_proof(|proof| proof.identity_digest[0] ^= 1);
        assert_rejects_tampered_proof(|proof| proof.audit_token.words[0] ^= 1);
    }

    fn assert_rejects_tampered_proof(tamper: impl FnOnce(&mut PeerProof) + Send + 'static) {
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
            let mut proof = current_proof().expect("current proof");
            tamper(&mut proof);
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
                client.read_exact(&mut acknowledgement).is_err(),
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
    fn outgoing_authentication_rejects_a_wrong_acknowledgement() {
        let (mut server, client) = UnixStream::pair().expect("create peer pair");
        let server_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&server).expect("begin server handshake");
            let connect_user = peer_user(&server).expect("client user");
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
            let pending = begin_peer_authentication(&server, connect_user)
                .expect("monitor client before proof");
            let binding = handshake_binding(server_nonce, client_hello.client_nonce);
            write_proof_message(
                &mut server,
                &handshake,
                ProofMessage {
                    kind: KIND_CHALLENGE,
                    binding,
                    proof: current_proof().expect("server proof"),
                },
            )
            .expect("write server proof");
            let response = read_proof_message(&mut server, &handshake, KIND_RESPONSE)
                .expect("read client proof");
            finish_peer_authentication(&server, pending, response.proof)
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
    fn rejects_application_bytes_instead_of_a_proof() {
        let (server, mut client) = UnixStream::pair().expect("create peer pair");
        let client_thread = thread::spawn(move || {
            let handshake = HandshakeIo::begin(&client).expect("begin client handshake");
            let mut hello = [0_u8; HELLO_MESSAGE_BYTES];
            handshake
                .read_exact(&mut client, &mut hello)
                .expect("read server hello");
            client
                .write_all(&[0_u8; HELLO_MESSAGE_BYTES])
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
    fn rejects_queued_input_after_the_authenticated_peer_exits() {
        let directory = tempfile::tempdir().expect("temporary peer directory");
        let socket_path = directory.path().join("queued-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind peer listener");
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("peer_macos::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_SOCKET, &socket_path)
            .env(WRITE_THEN_EXIT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn queued-input peer child");
        let (stream, _) = listener.accept().expect("accept queued-input child");
        let mut authenticated = AuthenticatedUnixStream::authenticate_incoming(stream)
            .expect("authenticate queued-input child");
        authenticated
            .stream
            .write_all(&[2])
            .expect("release queued-input child");
        assert!(child.wait().expect("wait for queued-input child").success());

        let mut queued = [0_u8; 1];
        let error = authenticated
            .read(&mut queued)
            .expect_err("dead peer input must not be admitted");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
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
            .arg("peer_macos::tests::native_authenticated_peer_child")
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
    fn successful_handshake_restores_both_socket_timeouts() {
        let (server, client) = UnixStream::pair().expect("create peer pair");
        let server_read = Duration::from_millis(700);
        let server_write = Duration::from_millis(900);
        let client_read = Duration::from_millis(800);
        let client_write = Duration::from_millis(950);
        server
            .set_read_timeout(Some(server_read))
            .expect("set server read timeout");
        server
            .set_write_timeout(Some(server_write))
            .expect("set server write timeout");
        client
            .set_read_timeout(Some(client_read))
            .expect("set client read timeout");
        client
            .set_write_timeout(Some(client_write))
            .expect("set client write timeout");
        let client_thread = thread::spawn(move || {
            let authenticated = AuthenticatedUnixStream::authenticate_outgoing(client)
                .expect("authenticate outgoing peer");
            assert_eq!(
                authenticated
                    .stream
                    .read_timeout()
                    .expect("client read timeout"),
                Some(client_read)
            );
            assert_eq!(
                authenticated
                    .stream
                    .write_timeout()
                    .expect("client write timeout"),
                Some(client_write)
            );
        });
        let authenticated = AuthenticatedUnixStream::authenticate_incoming(server)
            .expect("authenticate incoming peer");
        assert_eq!(
            authenticated
                .stream
                .read_timeout()
                .expect("server read timeout"),
            Some(server_read)
        );
        assert_eq!(
            authenticated
                .stream
                .write_timeout()
                .expect("server write timeout"),
            Some(server_write)
        );
        client_thread.join().expect("join authenticated client");
    }

    #[test]
    fn every_debug_surface_redacts_native_authentication_evidence() {
        let token = current_audit_token().expect("current audit token");
        let proof = current_proof().expect("current proof");
        assert_eq!(format!("{token:?}"), "AuditToken([REDACTED])");
        assert_eq!(format!("{proof:?}"), "PeerProof([REDACTED])");
    }

    #[test]
    #[ignore = "internal child process for native macOS authenticated-peer tests"]
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
            return;
        }
        assert_eq!(release, [1]);
    }

    #[test]
    #[ignore = "internal exec survivor for native macOS peer-authentication tests"]
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
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC,) },
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
                proof: current_proof().expect("post-exec current proof"),
            },
        )
        .expect("write post-exec proof");
        assert!(
            read_acknowledgement(&mut stream, &handshake, binding).is_err(),
            "broker must revoke the connection instead of acknowledging exec"
        );
    }
}
