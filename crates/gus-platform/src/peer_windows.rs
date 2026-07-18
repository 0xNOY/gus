use std::{
    ffi::c_void,
    fmt,
    io::{self, Read, Write},
    mem::size_of,
    num::NonZeroU32,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::Mutex,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_NOT_FOUND,
        ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
        GENERIC_READ, GENERIC_WRITE, GetHandleInformation, GetLastError, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeClientSessionId, GetNamedPipeHandleStateW, GetNamedPipeInfo,
            GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_BYTE,
            PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_SERVER_END, PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, SetNamedPipeHandleState, WaitNamedPipeW,
        },
        Threading::{CreateEventW, INFINITE, WaitForMultipleObjects, WaitForSingleObject},
    },
};

use crate::{
    ObservationError, PlatformFamily, ProcessIdentity, process_identity_proof_digest,
    windows::{RetainedProcess, WindowsTokenIdentity, named_pipe_client_token},
};

const AUTH_MAGIC: &[u8; 8] = b"GUSPAUTH";
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
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\gus-";
const ENDPOINT_GENERATION_HEX_BYTES: usize = AUTH_NONCE_BYTES * 2;

/// A one-process, local-only GUS named-pipe listener.
///
/// The listener owns an unpublished first instance for the whole interval in
/// which its random name is usable. Every accepted connection is replaced by
/// the next secured instance before it is returned to the caller.
pub struct NamedPipeListener {
    name: String,
    name_wide: Vec<u16>,
    generation: [u8; AUTH_NONCE_BYTES],
    endpoint_token: WindowsTokenIdentity,
    endpoint_logon_sid: Vec<u8>,
    pending: Option<ConnectedServerPipe>,
}

impl NamedPipeListener {
    /// Creates a fresh local endpoint protected for the current Windows user.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if secure descriptor construction,
    /// randomness, or first-instance creation fails.
    pub fn bind() -> io::Result<Self> {
        let generation = random_generation()?;
        let name = format!("{PIPE_NAME_PREFIX}{}", encode_generation(generation));
        let name_wide = wide_string(&name)?;
        let current = current_process()?;
        let endpoint_token = current.token_identity();
        let endpoint_logon_sid = current.logon_sid().to_vec();
        let pending = create_server_pipe(
            &name_wide,
            generation,
            endpoint_token,
            &endpoint_logon_sid,
            true,
        )?;
        Ok(Self {
            name,
            name_wide,
            generation,
            endpoint_token,
            endpoint_logon_sid,
            pending: Some(pending),
        })
    }

    /// Returns the random local pipe name to publish through the protected GUS
    /// endpoint record.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.name
    }

    /// Waits for one client and installs the next secured instance before
    /// returning the connected server endpoint.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if connection completion or creation
    /// of the replacement instance fails.
    pub fn accept(&mut self) -> io::Result<ConnectedServerPipe> {
        self.accept_with_deadline(None)
    }

    /// Waits for one client until `timeout` expires.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::TimedOut`] if no client connects before the
    /// deadline. A failed wait closes this listener rather than reusing an
    /// instance whose connect operation was cancelled.
    pub fn accept_timeout(&mut self, timeout: Duration) -> io::Result<ConnectedServerPipe> {
        self.accept_with_deadline(Instant::now().checked_add(timeout))
    }

    fn accept_with_deadline(
        &mut self,
        deadline: Option<Instant>,
    ) -> io::Result<ConnectedServerPipe> {
        let connected = self.pending.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "named-pipe listener is closed")
        })?;
        connect_server_pipe(&connected.pipe, deadline)?;
        self.pending = Some(create_server_pipe(
            &self.name_wide,
            self.generation,
            self.endpoint_token,
            &self.endpoint_logon_sid,
            false,
        )?);
        Ok(connected)
    }
}

impl fmt::Debug for NamedPipeListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedPipeListener")
            .field("name", &"<random endpoint>")
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

/// A connected server endpoint created with GUS's required security and I/O
/// flags. It can only be obtained from [`NamedPipeListener::accept`].
pub struct ConnectedServerPipe {
    pipe: OwnedHandle,
    generation: [u8; AUTH_NONCE_BYTES],
    expected_peer_token: WindowsTokenIdentity,
}

impl fmt::Debug for ConnectedServerPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedServerPipe(<owned>)")
    }
}

/// A connected client endpoint opened by [`connect_named_pipe`] with GUS's
/// required local, non-inheritable, overlapped-I/O contract.
pub struct ConnectedClientPipe {
    pipe: OwnedHandle,
    generation: [u8; AUTH_NONCE_BYTES],
    expected_peer_token: WindowsTokenIdentity,
}

impl fmt::Debug for ConnectedClientPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedClientPipe(<owned>)")
    }
}

/// Connects to a fresh GUS local named-pipe endpoint within a bounded wait.
///
/// # Errors
///
/// Rejects malformed or non-local GUS names and returns operating-system
/// connection errors, including timeout while all instances are busy.
pub fn connect_named_pipe(name: &str) -> io::Result<ConnectedClientPipe> {
    let generation = decode_pipe_generation(name)?;
    let name_wide = wide_string(name)?;
    let expected_peer_token = current_process()?.token_identity();
    let deadline = Instant::now().checked_add(PIPE_CONNECT_TIMEOUT);
    loop {
        // SAFETY: the name is NUL-terminated, security attributes are null so
        // the returned handle is non-inheritable, and all flags are documented
        // for a duplex overlapped named-pipe client.
        let raw = unsafe {
            CreateFileW(
                name_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            // SAFETY: successful CreateFileW returned a uniquely owned handle.
            let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
            set_read_mode(&pipe, PIPE_READMODE_MESSAGE)?;
            return Ok(ConnectedClientPipe {
                pipe,
                generation,
                expected_peer_token,
            });
        }
        // SAFETY: `GetLastError` has no preconditions.
        if unsafe { GetLastError() } != ERROR_PIPE_BUSY {
            return Err(io::Error::last_os_error());
        }
        let wait = remaining_millis(deadline);
        if wait == 0 {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        // SAFETY: the name remains NUL-terminated for this bounded wait.
        if unsafe { WaitNamedPipeW(name_wide.as_ptr(), wait) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
}

/// A local Windows named pipe authenticated before application framing.
///
/// Authentication binds the kernel-reported opposite endpoint PID to a
/// retained process handle and a nonce-bound process identity proof. The pipe
/// must be a freshly connected, duplex, message-mode GUS endpoint opened with
/// overlapped I/O, `PIPE_REJECT_REMOTE_CLIENTS`, a session-restricted DACL, and
/// no handle inheritance. The endpoint must not be duplicated or transferred.
/// Those creation invariants are enforced by the GUS endpoint factory; this
/// type additionally verifies the endpoint role and non-inheritance flag.
pub struct AuthenticatedNamedPipe {
    pipe: OwnedHandle,
    peer: RetainedProcess,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    revoked: bool,
}

impl AuthenticatedNamedPipe {
    /// Authenticates the client of a connected server-side pipe instance.
    ///
    /// # Errors
    ///
    /// Fails closed on the wrong pipe end, an inheritable handle, unavailable
    /// kernel PID evidence, PID reuse, peer exit, timeout, or malformed proof.
    pub fn authenticate_incoming(
        connected: ConnectedServerPipe,
    ) -> Result<Self, PeerAuthenticationError> {
        let ConnectedServerPipe {
            pipe,
            generation,
            expected_peer_token,
        } = connected;
        validate_pipe(&pipe, PipeEnd::Server)?;
        let peer = begin_peer_authentication(&pipe, PipeEnd::Server)?;
        if peer.token_identity() != expected_peer_token {
            return Err(PeerAuthenticationError::UserMismatch);
        }
        let handshake = HandshakeIo::begin(&pipe, &peer)?;
        let server_nonce = fresh_nonce()?;
        handshake.write_hello(HelloMessage {
            kind: KIND_SERVER_HELLO,
            server_nonce,
            client_nonce: [0; AUTH_NONCE_BYTES],
        })?;
        let client_hello = handshake.read_hello(KIND_CLIENT_HELLO)?;
        if client_hello.server_nonce != server_nonce {
            return Err(PeerAuthenticationError::ProofMismatch);
        }
        let binding = handshake_binding(server_nonce, client_hello.client_nonce, generation);
        handshake.write_proof(ProofMessage {
            kind: KIND_CHALLENGE,
            binding,
            proof: current_proof()?,
        })?;
        let response = handshake.read_proof(KIND_RESPONSE)?;
        if response.binding != binding {
            return Err(PeerAuthenticationError::ProofMismatch);
        }
        let client_token = named_pipe_client_token(raw_handle(&pipe))?;
        if client_token != peer.token_identity() {
            return Err(PeerAuthenticationError::UserMismatch);
        }
        finish_peer_authentication(&pipe, PipeEnd::Server, &peer, response.proof)?;
        handshake.write_acknowledgement(binding)?;
        peer.ensure_live()?;
        set_byte_read_mode(&pipe)?;
        Ok(Self::new(pipe, peer))
    }

    /// Authenticates the server of a connected client-side pipe instance.
    ///
    /// # Errors
    ///
    /// Fails closed on the wrong pipe end, an inheritable handle, unavailable
    /// kernel PID evidence, PID reuse, peer exit, timeout, or malformed proof.
    pub fn authenticate_outgoing(
        connected: ConnectedClientPipe,
    ) -> Result<Self, PeerAuthenticationError> {
        let ConnectedClientPipe {
            pipe,
            generation,
            expected_peer_token,
        } = connected;
        validate_pipe(&pipe, PipeEnd::Client)?;
        let peer = begin_peer_authentication(&pipe, PipeEnd::Client)?;
        if peer.token_identity() != expected_peer_token {
            return Err(PeerAuthenticationError::UserMismatch);
        }
        let handshake = HandshakeIo::begin(&pipe, &peer)?;
        let server_hello = handshake.read_hello(KIND_SERVER_HELLO)?;
        if server_hello.client_nonce.iter().any(|byte| *byte != 0) {
            return Err(PeerAuthenticationError::ProofMismatch);
        }
        let client_nonce = fresh_nonce()?;
        handshake.write_hello(HelloMessage {
            kind: KIND_CLIENT_HELLO,
            server_nonce: server_hello.server_nonce,
            client_nonce,
        })?;
        let binding = handshake_binding(server_hello.server_nonce, client_nonce, generation);
        let challenge = handshake.read_proof(KIND_CHALLENGE)?;
        if challenge.binding != binding {
            return Err(PeerAuthenticationError::ProofMismatch);
        }
        finish_peer_authentication(&pipe, PipeEnd::Client, &peer, challenge.proof)?;
        handshake.write_proof(ProofMessage {
            kind: KIND_RESPONSE,
            binding,
            proof: current_proof()?,
        })?;
        handshake.read_acknowledgement(binding)?;
        peer.ensure_live()?;
        set_byte_read_mode(&pipe)?;
        Ok(Self::new(pipe, peer))
    }

    fn new(pipe: OwnedHandle, peer: RetainedProcess) -> Self {
        Self {
            pipe,
            peer,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            revoked: false,
        }
    }

    /// Returns the immutable process identity bound during authentication.
    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.peer.identity()
    }

    /// Sets the deadline for each application read. `None` waits until data,
    /// disconnection, or authenticated-peer exit.
    ///
    /// # Errors
    ///
    /// Returns an error if another thread panicked while changing this value.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *self.read_timeout.lock().map_err(|_| timeout_lock_error())? = timeout;
        Ok(())
    }

    /// Sets the deadline for each application write. `None` waits until space,
    /// disconnection, or authenticated-peer exit.
    ///
    /// # Errors
    ///
    /// Returns an error if another thread panicked while changing this value.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *self
            .write_timeout
            .lock()
            .map_err(|_| timeout_lock_error())? = timeout;
        Ok(())
    }

    fn ensure_live(&self) -> io::Result<()> {
        if self.revoked {
            return Err(revoked_io_error());
        }
        self.peer.ensure_live().map_err(peer_changed_io_error)
    }
}

impl fmt::Debug for AuthenticatedNamedPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedNamedPipe")
            .field("peer", &self.peer.identity())
            .field("pipe", &"<owned>")
            .field("peer_process", &"<retained>")
            .finish_non_exhaustive()
    }
}

impl Read for AuthenticatedNamedPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let requested_data = !buffer.is_empty();
        self.ensure_live()?;
        let deadline = operation_deadline(timeout_value(&self.read_timeout)?);
        let read = match overlapped_io(&self.pipe, &self.peer, Operation::Read(buffer), deadline) {
            Ok(read) => read,
            Err(error) => {
                self.revoked = true;
                return Err(error);
            }
        };
        if let Err(error) = self.ensure_live() {
            self.revoked = true;
            return Err(error);
        }
        if requested_data && read == 0 {
            self.revoked = true;
        }
        Ok(read)
    }
}

impl Write for AuthenticatedNamedPipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.ensure_live()?;
        let deadline = operation_deadline(timeout_value(&self.write_timeout)?);
        let written =
            match overlapped_io(&self.pipe, &self.peer, Operation::Write(buffer), deadline) {
                Ok(written) => written,
                Err(error) => {
                    self.revoked = true;
                    return Err(error);
                }
            };
        if let Err(error) = self.ensure_live() {
            self.revoked = true;
            return Err(error);
        }
        if !buffer.is_empty() && written == 0 {
            self.revoked = true;
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_live()
    }
}

/// Failure to authenticate a local Windows named-pipe peer.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuthenticationError {
    #[error("named-pipe endpoint had the wrong role")]
    WrongPipeEnd,
    #[error("named-pipe handle inheritance is forbidden")]
    InheritableHandle,
    #[error("failed to read a kernel named-pipe credential: {kind:?}")]
    Credential { kind: io::ErrorKind },
    #[error("named-pipe peer PID was zero")]
    MalformedCredential,
    #[error("failed to transfer the bounded peer-authentication handshake: {kind:?}")]
    Handshake { kind: io::ErrorKind },
    #[error("peer-authentication handshake was malformed or unsupported")]
    MalformedHandshake,
    #[error("peer-authentication proof did not match its challenge or kernel evidence")]
    ProofMismatch,
    #[error("named-pipe and process observations reported different users")]
    UserMismatch,
    #[error("the operating system could not generate a peer-authentication challenge")]
    RandomUnavailable,
    #[error("failed to observe the authenticated peer process: {0}")]
    ProcessObservation(#[from] ObservationError),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PipeEnd {
    Server,
    Client,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerProof([u8; AUTH_DIGEST_BYTES]);

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

struct HandshakeIo<'a> {
    pipe: &'a OwnedHandle,
    peer: &'a RetainedProcess,
    deadline: Instant,
}

impl<'a> HandshakeIo<'a> {
    fn begin(
        pipe: &'a OwnedHandle,
        peer: &'a RetainedProcess,
    ) -> Result<Self, PeerAuthenticationError> {
        let deadline = Instant::now()
            .checked_add(HANDSHAKE_TIMEOUT)
            .ok_or_else(handshake_timeout)?;
        Ok(Self {
            pipe,
            peer,
            deadline,
        })
    }

    fn read_exact(&self, buffer: &mut [u8]) -> Result<(), PeerAuthenticationError> {
        let expected = buffer.len();
        let read = overlapped_io(
            self.pipe,
            self.peer,
            Operation::Read(buffer),
            Some(self.deadline),
        )
        .map_err(|error| handshake_error(&error))?;
        if read != expected {
            return Err(PeerAuthenticationError::MalformedHandshake);
        }
        Ok(())
    }

    fn write_all(&self, buffer: &[u8]) -> Result<(), PeerAuthenticationError> {
        let written = overlapped_io(
            self.pipe,
            self.peer,
            Operation::Write(buffer),
            Some(self.deadline),
        )
        .map_err(|error| handshake_error(&error))?;
        if written != buffer.len() {
            return Err(PeerAuthenticationError::MalformedHandshake);
        }
        Ok(())
    }

    fn write_hello(&self, message: HelloMessage) -> Result<(), PeerAuthenticationError> {
        let mut wire = [0_u8; HELLO_MESSAGE_BYTES];
        encode_header(&mut wire[..AUTH_HEADER_BYTES], message.kind);
        wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]
            .copy_from_slice(&message.server_nonce);
        wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..].copy_from_slice(&message.client_nonce);
        self.write_all(&wire)
    }

    fn read_hello(&self, expected_kind: u8) -> Result<HelloMessage, PeerAuthenticationError> {
        let mut wire = [0_u8; HELLO_MESSAGE_BYTES];
        self.read_exact(&mut wire)?;
        decode_header(&wire[..AUTH_HEADER_BYTES], expected_kind)?;
        let mut server_nonce = [0; AUTH_NONCE_BYTES];
        server_nonce
            .copy_from_slice(&wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]);
        let mut client_nonce = [0; AUTH_NONCE_BYTES];
        client_nonce.copy_from_slice(&wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..]);
        Ok(HelloMessage {
            kind: expected_kind,
            server_nonce,
            client_nonce,
        })
    }

    fn write_proof(&self, message: ProofMessage) -> Result<(), PeerAuthenticationError> {
        let mut wire = [0_u8; PROOF_MESSAGE_BYTES];
        encode_header(&mut wire[..AUTH_HEADER_BYTES], message.kind);
        wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]
            .copy_from_slice(&message.binding);
        wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..].copy_from_slice(&message.proof.0);
        self.write_all(&wire)
    }

    fn read_proof(&self, expected_kind: u8) -> Result<ProofMessage, PeerAuthenticationError> {
        let mut wire = [0_u8; PROOF_MESSAGE_BYTES];
        self.read_exact(&mut wire)?;
        decode_header(&wire[..AUTH_HEADER_BYTES], expected_kind)?;
        let mut binding = [0; AUTH_NONCE_BYTES];
        binding.copy_from_slice(&wire[AUTH_HEADER_BYTES..AUTH_HEADER_BYTES + AUTH_NONCE_BYTES]);
        let mut proof = [0; AUTH_DIGEST_BYTES];
        proof.copy_from_slice(&wire[AUTH_HEADER_BYTES + AUTH_NONCE_BYTES..]);
        Ok(ProofMessage {
            kind: expected_kind,
            binding,
            proof: PeerProof(proof),
        })
    }

    fn write_acknowledgement(
        &self,
        binding: [u8; AUTH_NONCE_BYTES],
    ) -> Result<(), PeerAuthenticationError> {
        let mut wire = [0_u8; ACK_MESSAGE_BYTES];
        encode_header(&mut wire[..AUTH_HEADER_BYTES], KIND_ACKNOWLEDGED);
        wire[AUTH_HEADER_BYTES..].copy_from_slice(&binding);
        self.write_all(&wire)
    }

    fn read_acknowledgement(
        &self,
        expected_binding: [u8; AUTH_NONCE_BYTES],
    ) -> Result<(), PeerAuthenticationError> {
        let mut wire = [0_u8; ACK_MESSAGE_BYTES];
        self.read_exact(&mut wire)?;
        decode_header(&wire[..AUTH_HEADER_BYTES], KIND_ACKNOWLEDGED)?;
        if wire[AUTH_HEADER_BYTES..] != expected_binding {
            return Err(PeerAuthenticationError::ProofMismatch);
        }
        Ok(())
    }
}

enum Operation<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

fn overlapped_io(
    pipe: &OwnedHandle,
    peer: &RetainedProcess,
    operation: Operation<'_>,
    deadline: Option<Instant>,
) -> io::Result<usize> {
    let requested = match &operation {
        Operation::Read(buffer) => buffer.len(),
        Operation::Write(buffer) => buffer.len(),
    };
    let reading = matches!(&operation, Operation::Read(_));
    if requested == 0 {
        return Ok(0);
    }
    if deadline_is_expired(deadline) {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    let requested = u32::try_from(requested.min(u32::MAX as usize))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: null security/name pointers create one unnamed, non-inheritable
    // manual-reset event owned by this operation.
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call returned a newly owned kernel handle.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut overlapped = OVERLAPPED {
        hEvent: raw_handle(&event),
        ..OVERLAPPED::default()
    };
    let mut transferred = 0_u32;
    let result = match operation {
        Operation::Read(buffer) => {
            // SAFETY: the pipe remains owned, buffer is writable for the
            // requested length, and the OVERLAPPED/event outlive completion.
            unsafe {
                ReadFile(
                    raw_handle(pipe),
                    buffer.as_mut_ptr(),
                    requested,
                    ptr::null_mut(),
                    ptr::addr_of_mut!(overlapped),
                )
            }
        }
        Operation::Write(buffer) => {
            // SAFETY: the pipe remains owned, buffer is readable for the
            // requested length, and the OVERLAPPED/event outlive completion.
            unsafe {
                WriteFile(
                    raw_handle(pipe),
                    buffer.as_ptr(),
                    requested,
                    ptr::null_mut(),
                    ptr::addr_of_mut!(overlapped),
                )
            }
        }
    };
    if result != 0 {
        // SAFETY: an immediate successful overlapped operation is complete and
        // the result call is the authoritative transferred-byte source.
        if unsafe {
            GetOverlappedResult(
                raw_handle(pipe),
                &raw const overlapped,
                ptr::addr_of_mut!(transferred),
                0,
            )
        } != 0
        {
            if deadline_is_expired(deadline) {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            return Ok(transferred as usize);
        }
        // SAFETY: `GetLastError` has no preconditions.
        return completion_error(unsafe { GetLastError() }, reading);
    }
    // SAFETY: `GetLastError` has no preconditions.
    let error = unsafe { GetLastError() };
    if error != ERROR_IO_PENDING {
        return completion_error(error, reading);
    }

    complete_pending_io(
        pipe,
        peer,
        &overlapped,
        raw_handle(&event),
        reading,
        deadline,
    )
}

fn complete_pending_io(
    pipe: &OwnedHandle,
    peer: &RetainedProcess,
    overlapped: &OVERLAPPED,
    event: HANDLE,
    reading: bool,
    deadline: Option<Instant>,
) -> io::Result<usize> {
    let mut transferred = 0_u32;
    let handles = [peer.raw_handle(), event];
    // SAFETY: both handles stay live for the call and the count matches the
    // array. Waiting for either object does not mutate caller-owned memory.
    let wait = unsafe {
        WaitForMultipleObjects(
            u32::try_from(handles.len()).expect("two wait handles"),
            handles.as_ptr(),
            0,
            remaining_millis(deadline),
        )
    };
    match wait {
        WAIT_OBJECT_0 => {
            cancel_and_complete(pipe, overlapped);
            peer.revoke();
            Err(peer_changed_io_error(ObservationError::ProcessChanged))
        }
        value if value == WAIT_OBJECT_0 + 1 => {
            // SAFETY: the event reports completion and all storage remains live.
            if unsafe {
                GetOverlappedResult(
                    raw_handle(pipe),
                    overlapped,
                    ptr::addr_of_mut!(transferred),
                    0,
                )
            } != 0
            {
                if deadline_is_expired(deadline) {
                    Err(io::Error::from(io::ErrorKind::TimedOut))
                } else {
                    Ok(transferred as usize)
                }
            } else {
                // SAFETY: `GetLastError` has no preconditions.
                let error = unsafe { GetLastError() };
                completion_error(error, reading)
            }
        }
        WAIT_TIMEOUT => {
            cancel_and_complete(pipe, overlapped);
            Err(io::Error::from(io::ErrorKind::TimedOut))
        }
        WAIT_FAILED => {
            // SAFETY: capture the wait error before cancellation overwrites it.
            let error = unsafe { GetLastError() };
            cancel_and_complete(pipe, overlapped);
            peer.revoke();
            Err(io_error(error))
        }
        _ => {
            cancel_and_complete(pipe, overlapped);
            peer.revoke();
            Err(io::Error::from(io::ErrorKind::Other))
        }
    }
}

fn cancel_and_complete(pipe: &OwnedHandle, overlapped: &OVERLAPPED) {
    // SAFETY: the OVERLAPPED belongs to the pending operation on this pipe.
    let cancelled = unsafe { CancelIoEx(raw_handle(pipe), overlapped) };
    if cancelled == 0 {
        // SAFETY: `GetLastError` has no preconditions. ERROR_NOT_FOUND means the
        // operation completed concurrently and still must be reaped below.
        let _ = unsafe { GetLastError() } == ERROR_NOT_FOUND;
    }
    let mut transferred = 0_u32;
    // SAFETY: waiting here guarantees the kernel no longer references the
    // caller's buffer or stack OVERLAPPED before either is dropped.
    unsafe {
        GetOverlappedResult(
            raw_handle(pipe),
            overlapped,
            ptr::addr_of_mut!(transferred),
            1,
        );
    }
}

fn completion_error(error: u32, reading: bool) -> io::Result<usize> {
    if reading
        && matches!(
            error,
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA | ERROR_HANDLE_EOF
        )
    {
        Ok(0)
    } else if error == ERROR_OPERATION_ABORTED {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Err(io_error(error))
    }
}

fn validate_pipe(pipe: &OwnedHandle, expected: PipeEnd) -> Result<(), PeerAuthenticationError> {
    let mut flags = 0_u32;
    // SAFETY: `flags` is writable and the owned handle remains live.
    if unsafe {
        GetNamedPipeInfo(
            raw_handle(pipe),
            ptr::addr_of_mut!(flags),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_credential_error());
    }
    let expected_flags = PIPE_TYPE_MESSAGE
        | match expected {
            PipeEnd::Server => PIPE_SERVER_END,
            PipeEnd::Client => 0,
        };
    if flags != expected_flags {
        return Err(PeerAuthenticationError::WrongPipeEnd);
    }
    let mut state = 0_u32;
    // SAFETY: `state` is writable and the typed endpoint remains live.
    if unsafe {
        GetNamedPipeHandleStateW(
            raw_handle(pipe),
            ptr::addr_of_mut!(state),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(last_credential_error());
    }
    if state & PIPE_READMODE_MESSAGE == 0 {
        return Err(PeerAuthenticationError::WrongPipeEnd);
    }
    let mut handle_flags = 0_u32;
    // SAFETY: `handle_flags` is writable and the owned handle remains live.
    if unsafe { GetHandleInformation(raw_handle(pipe), ptr::addr_of_mut!(handle_flags)) } == 0 {
        return Err(last_credential_error());
    }
    if handle_flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(PeerAuthenticationError::InheritableHandle);
    }
    Ok(())
}

fn begin_peer_authentication(
    pipe: &OwnedHandle,
    end: PipeEnd,
) -> Result<RetainedProcess, PeerAuthenticationError> {
    let first_pid = peer_pid(pipe, end)?;
    let first_session = peer_session_id(pipe, end)?;
    let peer = RetainedProcess::new(first_pid)?;
    let second_pid = peer_pid(pipe, end)?;
    let second_session = peer_session_id(pipe, end)?;
    peer.ensure_live()?;
    if first_pid != second_pid
        || peer.identity().pid() != first_pid
        || first_session != second_session
        || peer.session_id() != first_session
    {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    Ok(peer)
}

fn finish_peer_authentication(
    pipe: &OwnedHandle,
    end: PipeEnd,
    peer: &RetainedProcess,
    proof: PeerProof,
) -> Result<(), PeerAuthenticationError> {
    let final_pid = peer_pid(pipe, end)?;
    let final_session = peer_session_id(pipe, end)?;
    peer.ensure_live()?;
    if final_pid != peer.identity().pid()
        || final_session != peer.session_id()
        || proof != retained_process_proof(peer)
    {
        return Err(PeerAuthenticationError::ProofMismatch);
    }
    Ok(())
}

fn peer_session_id(pipe: &OwnedHandle, end: PipeEnd) -> Result<u32, PeerAuthenticationError> {
    let mut session_id = 0_u32;
    // SAFETY: `session_id` is writable, the handle is live, and validation
    // ensures the session-ID query matches the local endpoint role.
    let result = unsafe {
        match end {
            PipeEnd::Server => {
                GetNamedPipeClientSessionId(raw_handle(pipe), ptr::addr_of_mut!(session_id))
            }
            PipeEnd::Client => {
                GetNamedPipeServerSessionId(raw_handle(pipe), ptr::addr_of_mut!(session_id))
            }
        }
    };
    if result == 0 {
        return Err(last_credential_error());
    }
    Ok(session_id)
}

fn peer_pid(pipe: &OwnedHandle, end: PipeEnd) -> Result<NonZeroU32, PeerAuthenticationError> {
    let mut pid = 0_u32;
    // SAFETY: `pid` is writable, the handle is live, and validation ensures the
    // process-ID query matches the local endpoint role.
    let result = unsafe {
        match end {
            PipeEnd::Server => {
                GetNamedPipeClientProcessId(raw_handle(pipe), ptr::addr_of_mut!(pid))
            }
            PipeEnd::Client => {
                GetNamedPipeServerProcessId(raw_handle(pipe), ptr::addr_of_mut!(pid))
            }
        }
    };
    if result == 0 {
        return Err(last_credential_error());
    }
    NonZeroU32::new(pid).ok_or(PeerAuthenticationError::MalformedCredential)
}

fn current_proof() -> Result<PeerProof, PeerAuthenticationError> {
    let pid =
        NonZeroU32::new(std::process::id()).ok_or(PeerAuthenticationError::MalformedCredential)?;
    let process = RetainedProcess::new(pid)?;
    Ok(retained_process_proof(&process))
}

fn retained_process_proof(process: &RetainedProcess) -> PeerProof {
    let process_digest = process_identity_proof_digest(process.identity());
    let token_digest = process.token_identity().proof_digest();
    let mut native = [0_u8; AUTH_DIGEST_BYTES * 2];
    native[..AUTH_DIGEST_BYTES].copy_from_slice(&process_digest);
    native[AUTH_DIGEST_BYTES..].copy_from_slice(&token_digest);
    PeerProof(crate::identity_digest(
        b"gus.platform.windows-peer-proof.v1",
        PlatformFamily::Windows,
        &native,
    ))
}

fn fresh_nonce() -> Result<[u8; AUTH_NONCE_BYTES], PeerAuthenticationError> {
    let mut nonce = [0; AUTH_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| PeerAuthenticationError::RandomUnavailable)?;
    Ok(nonce)
}

fn handshake_binding(
    server_nonce: [u8; AUTH_NONCE_BYTES],
    client_nonce: [u8; AUTH_NONCE_BYTES],
    generation: [u8; AUTH_NONCE_BYTES],
) -> [u8; AUTH_NONCE_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"gus.platform.windows-peer-handshake.v1");
    hasher.update(server_nonce);
    hasher.update(client_nonce);
    hasher.update(generation);
    hasher.finalize().into()
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

fn operation_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|duration| Instant::now().checked_add(duration))
}

fn remaining_millis(deadline: Option<Instant>) -> u32 {
    let Some(deadline) = deadline else {
        return INFINITE;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return 0;
    }
    let millis = remaining.as_millis().saturating_add(1);
    u32::try_from(millis)
        .unwrap_or(INFINITE - 1)
        .min(INFINITE - 1)
}

fn deadline_is_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
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

fn io_error(error: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(error).unwrap_or(i32::MAX))
}

fn peer_changed_io_error(_: ObservationError) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "authenticated IPC peer is no longer live",
    )
}

fn revoked_io_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "authenticated IPC connection has been revoked",
    )
}

fn timeout_lock_error() -> io::Error {
    io::Error::other("named-pipe timeout state is poisoned")
}

fn timeout_value(timeout: &Mutex<Option<Duration>>) -> io::Result<Option<Duration>> {
    timeout
        .lock()
        .map(|timeout| *timeout)
        .map_err(|_| timeout_lock_error())
}

fn create_server_pipe(
    name: &[u16],
    generation: [u8; AUTH_NONCE_BYTES],
    expected_peer_token: WindowsTokenIdentity,
    endpoint_logon_sid: &[u8],
    first: bool,
) -> io::Result<ConnectedServerPipe> {
    let security = logon_security_descriptor(endpoint_logon_sid)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let first_flag = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    // SAFETY: the name and security descriptor remain live for the call. The
    // returned instance is duplex, message-authenticated, overlapped, local
    // only, and explicitly non-inheritable.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first_flag,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            u32::try_from(PIPE_CONNECT_TIMEOUT.as_millis()).unwrap_or(u32::MAX),
            ptr::addr_of_mut!(attributes),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateNamedPipeW returned a uniquely owned handle.
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
    Ok(ConnectedServerPipe {
        pipe,
        generation,
        expected_peer_token,
    })
}

fn connect_server_pipe(pipe: &OwnedHandle, deadline: Option<Instant>) -> io::Result<()> {
    let event = create_event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: raw_handle(&event),
        ..OVERLAPPED::default()
    };
    // SAFETY: the server pipe is overlapped and all operation storage remains
    // live until completion below.
    if unsafe { ConnectNamedPipe(raw_handle(pipe), ptr::addr_of_mut!(overlapped)) } != 0 {
        return Ok(());
    }
    // SAFETY: `GetLastError` has no preconditions.
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => {
            // SAFETY: the event remains live and has SYNCHRONIZE access.
            let wait =
                unsafe { WaitForSingleObject(raw_handle(&event), remaining_millis(deadline)) };
            if wait != WAIT_OBJECT_0 {
                let error = match wait {
                    WAIT_TIMEOUT => io::Error::from(io::ErrorKind::TimedOut),
                    WAIT_FAILED => io::Error::last_os_error(),
                    _ => io::Error::from(io::ErrorKind::Other),
                };
                cancel_and_complete(pipe, &overlapped);
                return Err(error);
            }
            let mut transferred = 0_u32;
            // SAFETY: the event signaled completion and storage remains live.
            if unsafe {
                GetOverlappedResult(
                    raw_handle(pipe),
                    &raw const overlapped,
                    ptr::addr_of_mut!(transferred),
                    0,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        _ => Err(io::Error::last_os_error()),
    }
}

fn set_byte_read_mode(pipe: &OwnedHandle) -> Result<(), PeerAuthenticationError> {
    set_read_mode(pipe, PIPE_READMODE_BYTE)
        .map_err(|error| PeerAuthenticationError::Credential { kind: error.kind() })
}

fn set_read_mode(pipe: &OwnedHandle, mode: u32) -> io::Result<()> {
    // SAFETY: the pipe is live and `mode` remains readable for the call.
    if unsafe {
        SetNamedPipeHandleState(raw_handle(pipe), &raw const mode, ptr::null(), ptr::null())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: null security/name pointers create one unnamed, non-inheritable
    // manual-reset event.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateEventW returned a uniquely owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn current_process() -> io::Result<RetainedProcess> {
    let pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    RetainedProcess::new(pid).map_err(observation_io_error)
}

fn logon_security_descriptor(logon_sid: &[u8]) -> io::Result<LocalSecurityDescriptor> {
    let sid = sid_string(logon_sid)?;
    let sddl = wide_string(&format!(
        "D:P(D;;GA;;;NU)(A;;RC;;;OW)(A;;GA;;;{sid})(A;;GA;;;SY)"
    ))?;
    let mut descriptor = ptr::null_mut();
    // SAFETY: the SDDL is NUL-terminated and `descriptor` is writable. Revision
    // one is the documented SDDL representation accepted by this API.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            ptr::addr_of_mut!(descriptor),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalSecurityDescriptor(descriptor))
}

struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by ConvertString... and is
        // released exactly once with LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn sid_string(sid: &[u8]) -> io::Result<String> {
    use std::fmt::Write as _;

    if sid.len() < 8 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let count = usize::from(sid[1]);
    let expected = 8_usize
        .checked_add(count.saturating_mul(size_of::<u32>()))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    if sid.len() != expected {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let authority = sid[2..8]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut value = format!("S-{}-{authority}", sid[0]);
    for bytes in sid[8..].chunks_exact(size_of::<u32>()) {
        let subauthority = u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        );
        write!(&mut value, "-{subauthority}")
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    }
    Ok(value)
}

fn random_generation() -> io::Result<[u8; AUTH_NONCE_BYTES]> {
    let mut generation = [0; AUTH_NONCE_BYTES];
    getrandom::fill(&mut generation).map_err(|_| io::Error::from(io::ErrorKind::Other))?;
    Ok(generation)
}

fn encode_generation(generation: [u8; AUTH_NONCE_BYTES]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(ENDPOINT_GENERATION_HEX_BYTES);
    for byte in generation {
        write!(&mut encoded, "{byte:02x}").expect("write endpoint generation to String");
    }
    encoded
}

fn decode_pipe_generation(name: &str) -> io::Result<[u8; AUTH_NONCE_BYTES]> {
    let encoded = name
        .strip_prefix(PIPE_NAME_PREFIX)
        .filter(|value| value.len() == ENDPOINT_GENERATION_HEX_BYTES)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut generation = [0; AUTH_NONCE_BYTES];
    for (index, byte) in generation.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    Ok(generation)
}

fn wide_string(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let wide = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    if wide.len() > 257 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(wide)
}

fn observation_io_error(error: ObservationError) -> io::Error {
    match error {
        ObservationError::Read { kind, .. } => io::Error::from(kind),
        _ => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process observation failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        io::{Read, Write},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use super::*;
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorControl, ImpersonateSelf, RevertToSelf, SE_DACL_PROTECTED,
            SECURITY_MAX_SID_SIZE, SecurityImpersonation, TOKEN_QUERY, WinCreatorOwnerRightsSid,
        },
        Storage::FileSystem::{READ_CONTROL, WRITE_DAC},
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    };

    const PEER_PIPE: &str = "GUS_TEST_WINDOWS_AUTHENTICATED_PEER_PIPE";
    const WRITE_THEN_EXIT: &str = "GUS_TEST_WINDOWS_AUTHENTICATED_PEER_WRITE_THEN_EXIT";
    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    #[test]
    fn authenticates_both_sides_before_application_io() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let child = spawn_peer(listener.pipe_name(), false);
        let child_pid = child.id();
        let connected = accept_test(&mut listener, "accept peer child");
        let mut authenticated = AuthenticatedNamedPipe::authenticate_incoming(connected)
            .expect("authenticate peer child");
        assert_eq!(authenticated.peer_identity().pid().get(), child_pid);
        authenticated
            .set_read_timeout(Some(TEST_TIMEOUT))
            .expect("bound marker read");
        let mut marker = [0];
        authenticated
            .read_exact(&mut marker)
            .expect("read authenticated marker");
        assert_eq!(marker, [0xa5]);
        authenticated.write_all(&[1]).expect("release peer child");
        assert_child_success(child);
    }

    #[test]
    fn rejects_queued_input_after_the_authenticated_peer_exits() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let child = spawn_peer(listener.pipe_name(), true);
        let connected = accept_test(&mut listener, "accept peer child");
        let mut authenticated = AuthenticatedNamedPipe::authenticate_incoming(connected)
            .expect("authenticate peer child");
        assert_child_success(child);
        for _ in 0..2 {
            assert_eq!(
                authenticated
                    .read(&mut [0])
                    .expect_err("queued bytes from an exited peer must be rejected")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                authenticated
                    .write(&[1])
                    .expect_err("writes to an exited peer must remain rejected")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                authenticated
                    .flush()
                    .expect_err("flush after peer exit must remain rejected")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn rejects_application_bytes_instead_of_an_authentication_record() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let client_thread = thread::spawn(move || {
            let connected = connect_named_pipe(&pipe_name).expect("connect raw client");
            validate_pipe(&connected.pipe, PipeEnd::Client).expect("validate client pipe");
            let peer = begin_peer_authentication(&connected.pipe, PipeEnd::Client)
                .expect("observe server");
            let handshake = HandshakeIo::begin(&connected.pipe, &peer).expect("begin handshake");
            handshake
                .read_hello(KIND_SERVER_HELLO)
                .expect("read server hello");
            handshake
                .write_all(b"application bytes")
                .expect("write invalid short record");
        });
        let connected = accept_test(&mut listener, "accept raw client");
        assert_eq!(
            AuthenticatedNamedPipe::authenticate_incoming(connected)
                .expect_err("application bytes must not be decoded as authentication"),
            PeerAuthenticationError::MalformedHandshake
        );
        client_thread.join().expect("join raw client");
    }

    #[test]
    fn handshake_read_has_one_absolute_overlapped_deadline() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let client_thread = thread::spawn(move || {
            let client = connect_named_pipe(&pipe_name).expect("connect idle client");
            ready_sender.send(()).expect("report idle client ready");
            release_receiver.recv().expect("hold idle client");
            drop(client);
        });
        let connected = accept_test(&mut listener, "accept idle client");
        ready_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("wait for idle client readiness");
        validate_pipe(&connected.pipe, PipeEnd::Server).expect("validate server pipe");
        let peer = begin_peer_authentication(&connected.pipe, PipeEnd::Server)
            .expect("observe idle client");
        let started = Instant::now();
        let handshake = HandshakeIo {
            pipe: &connected.pipe,
            peer: &peer,
            deadline: started + Duration::from_millis(50),
        };
        let Err(error) = handshake.read_hello(KIND_CLIENT_HELLO) else {
            panic!("idle authentication must time out");
        };
        assert_eq!(
            error,
            PeerAuthenticationError::Handshake {
                kind: io::ErrorKind::TimedOut
            }
        );
        release_sender.send(()).expect("release idle client");
        client_thread.join().expect("join idle client");
    }

    #[test]
    fn application_timeout_permanently_revokes_the_connection() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let client_thread = thread::spawn(move || {
            let connected = connect_named_pipe(&pipe_name).expect("connect client");
            let authenticated = AuthenticatedNamedPipe::authenticate_outgoing(connected)
                .expect("authenticate server");
            ready_sender.send(()).expect("report authenticated client");
            release_receiver.recv().expect("hold authenticated client");
            drop(authenticated);
        });
        let connected = accept_test(&mut listener, "accept client");
        let mut authenticated =
            AuthenticatedNamedPipe::authenticate_incoming(connected).expect("authenticate client");
        ready_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("wait for authenticated client");
        authenticated
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set read timeout");
        assert_eq!(
            authenticated
                .read(&mut [0])
                .expect_err("idle application read must time out")
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            authenticated
                .flush()
                .expect_err("cancelled I/O must permanently revoke framing")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        release_sender.send(()).expect("release client");
        client_thread.join().expect("join authenticated client");
    }

    #[test]
    fn authentication_rejects_tampered_binding_and_process_proof() {
        for mutation in [ResponseMutation::Binding, ResponseMutation::Proof] {
            let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
            let pipe_name = listener.pipe_name().to_owned();
            let client_thread = thread::spawn(move || send_tampered_response(&pipe_name, mutation));
            let connected = accept_test(&mut listener, "accept tampering client");
            assert_eq!(
                AuthenticatedNamedPipe::authenticate_incoming(connected)
                    .expect_err("tampered authentication response must fail"),
                PeerAuthenticationError::ProofMismatch
            );
            client_thread.join().expect("join tampering client");
        }
    }

    #[test]
    fn outgoing_authentication_rejects_tampered_acknowledgement() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let client_thread = thread::spawn(move || {
            let connected = connect_named_pipe(&pipe_name).expect("connect ACK client");
            AuthenticatedNamedPipe::authenticate_outgoing(connected)
                .expect_err("tampered acknowledgement must fail")
        });
        let connected = accept_test(&mut listener, "accept ACK client");
        send_tampered_acknowledgement(connected);
        assert_eq!(
            client_thread.join().expect("join ACK client"),
            PeerAuthenticationError::ProofMismatch
        );
    }

    #[test]
    fn authentication_switches_both_ends_to_byte_mode_and_empty_read_is_safe() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let (client_sender, client_receiver) = mpsc::channel();
        let client_thread = thread::spawn(move || {
            let connected = connect_named_pipe(&pipe_name).expect("connect mode client");
            let authenticated = AuthenticatedNamedPipe::authenticate_outgoing(connected)
                .expect("authenticate mode server");
            client_sender
                .send(authenticated)
                .expect("send authenticated client");
        });
        let connected = accept_test(&mut listener, "accept mode client");
        let mut server =
            AuthenticatedNamedPipe::authenticate_incoming(connected).expect("authenticate client");
        let client = client_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("receive authenticated client");
        assert_read_mode(&server.pipe, PIPE_READMODE_BYTE);
        assert_read_mode(&client.pipe, PIPE_READMODE_BYTE);
        assert_eq!(server.read(&mut []).expect("perform empty read"), 0);
        server
            .flush()
            .expect("empty read must not revoke connection");
        drop(client);
        client_thread.join().expect("join mode client");
    }

    #[test]
    fn token_impersonation_refuses_a_previously_impersonating_thread() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pipe_name = listener.pipe_name().to_owned();
        let (release_sender, release_receiver) = mpsc::channel();
        let client_thread = thread::spawn(move || {
            let client = connect_named_pipe(&pipe_name).expect("connect held client");
            release_receiver.recv().expect("hold connected client");
            drop(client);
        });
        let server = accept_test(&mut listener, "accept held client");
        // SAFETY: this test restores the thread token below and aborts if that
        // restoration fails, matching the production guard's invariant.
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        assert!(matches!(
            named_pipe_client_token(raw_handle(&server.pipe)),
            Err(ObservationError::Read {
                resource: crate::ObservationResource::TargetUser,
                kind: io::ErrorKind::PermissionDenied,
            })
        ));
        let mut token = ptr::null_mut();
        // SAFETY: a successful query proves the pre-existing impersonation was
        // preserved instead of being replaced and reverted by authentication.
        assert_ne!(
            unsafe {
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, ptr::addr_of_mut!(token))
            },
            0
        );
        // SAFETY: the successful query returned a uniquely owned token handle.
        drop(unsafe { OwnedHandle::from_raw_handle(token) });
        // SAFETY: this thread is impersonating due to ImpersonateSelf above.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        release_sender.send(()).expect("release connected client");
        client_thread.join().expect("join held client");
    }

    #[test]
    fn endpoint_factory_enforces_roles_generation_and_noninheritance() {
        let mut listener = NamedPipeListener::bind().expect("bind secured named pipe");
        assert!(decode_pipe_generation(listener.pipe_name()).is_ok());
        assert!(decode_pipe_generation(r"\\server\pipe\gus-00").is_err());
        let pipe_name = listener.pipe_name().to_owned();
        let (client_sender, client_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let client_thread = thread::spawn(move || {
            let client = connect_named_pipe(&pipe_name).expect("connect client");
            client_sender.send(client).expect("send client endpoint");
            release_receiver.recv().expect("hold client endpoint");
        });
        let server = accept_test(&mut listener, "accept client");
        let client = client_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("receive client endpoint");
        validate_pipe(&server.pipe, PipeEnd::Server).expect("server role");
        validate_pipe(&client.pipe, PipeEnd::Client).expect("client role");
        assert_eq!(
            peer_pid(&client.pipe, PipeEnd::Client)
                .expect("query server PID from client endpoint")
                .get(),
            std::process::id()
        );
        assert_noninheritable(&server.pipe);
        assert_noninheritable(&client.pipe);
        assert_eq!(server.generation, client.generation);
        assert_eq!(server.expected_peer_token, client.expected_peer_token);
        drop(client);
        release_sender.send(()).expect("release client thread");
        client_thread.join().expect("join client thread");
    }

    #[test]
    fn endpoint_dacl_is_protected_and_suppresses_implicit_owner_write_dac() {
        let listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let pending = listener.pending.as_ref().expect("pending server instance");
        assert_owner_rights_dacl(&pending.pipe);

        let duplicate = create_server_pipe(
            &listener.name_wide,
            listener.generation,
            listener.endpoint_token,
            &listener.endpoint_logon_sid,
            true,
        )
        .expect_err("a second first pipe instance must be rejected");
        assert_eq!(
            duplicate.raw_os_error(),
            Some(i32::try_from(ERROR_ACCESS_DENIED).expect("Win32 error fits i32"))
        );
    }

    #[test]
    fn every_debug_surface_redacts_native_authentication_evidence() {
        let proof = PeerProof([0xa5; AUTH_DIGEST_BYTES]);
        assert_eq!(format!("{proof:?}"), "PeerProof([REDACTED])");
        let listener = NamedPipeListener::bind().expect("bind secured named pipe");
        let debug = format!("{listener:?}");
        assert!(!debug.contains(listener.pipe_name()));
        assert!(!debug.contains(&encode_generation(listener.generation)));
    }

    #[test]
    #[ignore = "internal child process for native Windows peer-authentication tests"]
    fn native_authenticated_peer_child() {
        let Some(pipe_name) = env::var_os(PEER_PIPE) else {
            return;
        };
        let pipe_name = pipe_name
            .into_string()
            .expect("peer pipe name must be Unicode");
        let connected = connect_named_pipe(&pipe_name).expect("connect to parent pipe");
        let mut authenticated = AuthenticatedNamedPipe::authenticate_outgoing(connected)
            .expect("authenticate parent server");
        authenticated
            .write_all(&[0xa5])
            .expect("write authenticated marker");
        if env::var_os(WRITE_THEN_EXIT).is_some() {
            return;
        }
        let mut release = [0];
        authenticated
            .read_exact(&mut release)
            .expect("wait for parent release");
        assert_eq!(release, [1]);
    }

    fn spawn_peer(pipe_name: &str, write_then_exit: bool) -> std::process::Child {
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("peer_windows::tests::native_authenticated_peer_child")
            .arg("--ignored")
            .env(PEER_PIPE, pipe_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if write_then_exit {
            command.env(WRITE_THEN_EXIT, "1");
        }
        command.spawn().expect("spawn authenticated peer child")
    }

    #[derive(Clone, Copy)]
    enum ResponseMutation {
        Binding,
        Proof,
    }

    fn send_tampered_response(pipe_name: &str, mutation: ResponseMutation) {
        let connected = connect_named_pipe(pipe_name).expect("connect tampering client");
        validate_pipe(&connected.pipe, PipeEnd::Client).expect("validate client pipe");
        let peer = begin_peer_authentication(&connected.pipe, PipeEnd::Client)
            .expect("observe server process");
        let handshake = HandshakeIo::begin(&connected.pipe, &peer).expect("begin handshake");
        let server_hello = handshake
            .read_hello(KIND_SERVER_HELLO)
            .expect("read server hello");
        let client_nonce = fresh_nonce().expect("generate client nonce");
        handshake
            .write_hello(HelloMessage {
                kind: KIND_CLIENT_HELLO,
                server_nonce: server_hello.server_nonce,
                client_nonce,
            })
            .expect("write client hello");
        let binding = handshake_binding(
            server_hello.server_nonce,
            client_nonce,
            connected.generation,
        );
        let challenge = handshake
            .read_proof(KIND_CHALLENGE)
            .expect("read server challenge");
        assert_eq!(challenge.binding, binding);
        let mut response = ProofMessage {
            kind: KIND_RESPONSE,
            binding,
            proof: current_proof().expect("observe client proof"),
        };
        match mutation {
            ResponseMutation::Binding => response.binding[0] ^= 1,
            ResponseMutation::Proof => response.proof.0[0] ^= 1,
        }
        handshake
            .write_proof(response)
            .expect("write tampered response");
    }

    fn send_tampered_acknowledgement(connected: ConnectedServerPipe) {
        let ConnectedServerPipe {
            pipe,
            generation,
            expected_peer_token,
        } = connected;
        validate_pipe(&pipe, PipeEnd::Server).expect("validate ACK server pipe");
        let peer = begin_peer_authentication(&pipe, PipeEnd::Server).expect("observe ACK client");
        assert_eq!(peer.token_identity(), expected_peer_token);
        let handshake = HandshakeIo::begin(&pipe, &peer).expect("begin ACK handshake");
        let server_nonce = fresh_nonce().expect("generate server nonce");
        handshake
            .write_hello(HelloMessage {
                kind: KIND_SERVER_HELLO,
                server_nonce,
                client_nonce: [0; AUTH_NONCE_BYTES],
            })
            .expect("write server hello");
        let client_hello = handshake
            .read_hello(KIND_CLIENT_HELLO)
            .expect("read client hello");
        let binding = handshake_binding(server_nonce, client_hello.client_nonce, generation);
        handshake
            .write_proof(ProofMessage {
                kind: KIND_CHALLENGE,
                binding,
                proof: current_proof().expect("observe server proof"),
            })
            .expect("write server challenge");
        let response = handshake
            .read_proof(KIND_RESPONSE)
            .expect("read client response");
        finish_peer_authentication(&pipe, PipeEnd::Server, &peer, response.proof)
            .expect("verify client response");
        let mut tampered = binding;
        tampered[0] ^= 1;
        handshake
            .write_acknowledgement(tampered)
            .expect("write tampered acknowledgement");
    }

    fn accept_test(listener: &mut NamedPipeListener, context: &str) -> ConnectedServerPipe {
        listener
            .accept_timeout(TEST_TIMEOUT)
            .unwrap_or_else(|error| {
                panic!("{context} within {TEST_TIMEOUT:?}: {error}");
            })
    }

    fn assert_child_success(mut child: std::process::Child) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let output = child.wait_with_output().expect("collect peer child output");
                    assert!(
                        output.status.success(),
                        "peer child failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("collect timed-out peer child output");
                    panic!(
                        "peer child timed out: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(error) => panic!("wait for peer child: {error}"),
            }
        }
    }

    fn assert_noninheritable(pipe: &OwnedHandle) {
        let mut flags = 0_u32;
        // SAFETY: `flags` is writable and the pipe handle remains live.
        assert_ne!(
            unsafe { GetHandleInformation(raw_handle(pipe), ptr::addr_of_mut!(flags)) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }

    fn assert_read_mode(pipe: &OwnedHandle, expected: u32) {
        let mut state = 0_u32;
        // SAFETY: `state` is writable and the pipe remains live.
        assert_ne!(
            unsafe {
                GetNamedPipeHandleStateW(
                    raw_handle(pipe),
                    ptr::addr_of_mut!(state),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                )
            },
            0
        );
        assert_eq!(state & PIPE_READMODE_MESSAGE, expected);
    }

    fn assert_owner_rights_dacl(pipe: &OwnedHandle) {
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: all output pointers are writable and the live pipe grants
        // READ_CONTROL to its creating logon SID.
        let status = unsafe {
            GetSecurityInfo(
                raw_handle(pipe),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::addr_of_mut!(dacl),
                ptr::null_mut(),
                ptr::addr_of_mut!(descriptor),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!descriptor.is_null());
        assert!(!dacl.is_null());
        let _descriptor = LocalSecurityDescriptor(descriptor);

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: GetSecurityInfo returned a live self-relative descriptor and
        // both scalar outputs are writable.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorControl(
                    descriptor,
                    ptr::addr_of_mut!(control),
                    ptr::addr_of_mut!(revision),
                )
            },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);

        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: the returned DACL remains inside the live descriptor and the
        // fixed-size information output is writable.
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    ptr::addr_of_mut!(information).cast::<c_void>(),
                    u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size"),
                    AclSizeInformation,
                )
            },
            0
        );

        let mut owner_rights = [0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut owner_rights_len = u32::try_from(owner_rights.len()).expect("SID buffer size");
        // SAFETY: the fixed output buffer and byte-count pointer are writable.
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinCreatorOwnerRightsSid,
                    ptr::null_mut(),
                    owner_rights.as_mut_ptr().cast::<c_void>(),
                    ptr::addr_of_mut!(owner_rights_len),
                )
            },
            0
        );

        let mut matching_aces = 0_u32;
        for index in 0..information.AceCount {
            let mut raw_ace = ptr::null_mut();
            // SAFETY: `index` is bounded by the queried ACE count and the
            // output pointer is writable.
            assert_ne!(
                unsafe { GetAce(dacl, index, ptr::addr_of_mut!(raw_ace)) },
                0
            );
            // SAFETY: GetAce returned a valid ACE pointer for this DACL.
            let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            // SAFETY: an ACCESS_ALLOWED_ACE_TYPE entry has this fixed prefix;
            // SidStart is the first byte of its variable-length SID.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
            // SAFETY: both SID pointers are valid for the duration of the call.
            if unsafe { EqualSid(ace_sid, owner_rights.as_mut_ptr().cast::<c_void>()) } != 0 {
                matching_aces += 1;
                assert_eq!(ace.Mask, READ_CONTROL);
                assert_eq!(ace.Mask & WRITE_DAC, 0);
            }
        }
        assert_eq!(matching_aces, 1, "DACL must contain one OWNER RIGHTS ACE");
    }
}
