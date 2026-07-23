use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use gus_ipc::{
    Digest32, FRAME_HEADER_BYTES, Generation, MAX_FRAME_BYTES, ProviderRequest,
    ProviderRequestFrame, ProviderResponseFrame, ProviderStatusSnapshot, RequestId,
    SelectionPrompt, ShimRequestFrame, ShimResponseFrame, TransportError, decode_frame_length,
    decode_provider_request, decode_shim_request, encode_provider_response, encode_shim_response,
};
use gus_platform::{AuthenticatedUnixStream, ProcessIdentity};
use thiserror::Error;

use crate::{
    ProviderAdmission, ProviderAdmissionError, ProviderCommandFailure, ProviderCommandOutcome,
    ProviderMembershipAdmission, ProviderSession, ProviderSessionError,
};

/// An authenticated provider and its untrusted registration frame.
///
/// The broker must independently resolve the host instance and repository
/// set, then consume this value with [`Self::admit`]. No application command
/// is processed before admission.
pub struct PendingUnixProvider {
    stream: AuthenticatedUnixStream,
    peer: ProcessIdentity,
    registration: ProviderRequestFrame,
    frame_read_timeout: Duration,
    frame_write_timeout: Duration,
}

/// The first authenticated application request accepted by the broker.
pub enum PendingUnixClient {
    Provider(PendingUnixProvider),
    Shim(PendingUnixShimRequest),
}

/// One authenticated shim request awaiting its correlated broker response.
pub struct PendingUnixShimRequest {
    stream: AuthenticatedUnixStream,
    peer: ProcessIdentity,
    request: ShimRequestFrame,
    frame_write_timeout: Duration,
}

impl PendingUnixClient {
    /// Reads and classifies the first bounded frame after peer authentication.
    ///
    /// # Errors
    ///
    /// Rejects slow, malformed, unsupported, or unexpected first frames.
    pub(crate) fn read(
        mut stream: AuthenticatedUnixStream,
        frame_read_timeout: Duration,
        frame_write_timeout: Duration,
    ) -> Result<Self, ProviderConnectionError> {
        let peer = stream.peer_identity();
        let record = read_record_absolute(&mut stream, frame_read_timeout)
            .map_err(ProviderConnectionError::transport)?;
        if let Ok(registration) = decode_provider_request(&record) {
            if !matches!(registration.message(), ProviderRequest::Register(_)) {
                return Err(ProviderConnectionError::transport(
                    gus_ipc::ProtocolError::InvalidMessageRole.into(),
                ));
            }
            return Ok(Self::Provider(PendingUnixProvider {
                stream,
                peer,
                registration,
                frame_read_timeout,
                frame_write_timeout,
            }));
        }
        let request = decode_shim_request(&record)
            .map_err(|source| ProviderConnectionError::transport(source.into()))?;
        Ok(Self::Shim(PendingUnixShimRequest {
            stream,
            peer,
            request,
            frame_write_timeout,
        }))
    }
}

impl PendingUnixShimRequest {
    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.peer
    }

    #[must_use]
    pub const fn request(&self) -> &ShimRequestFrame {
        &self.request
    }

    /// Sends the single response correlated to this request.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched request ID, invalid response, or failed write.
    pub fn respond(mut self, response: &ShimResponseFrame) -> Result<(), ProviderConnectionError> {
        if response.request_id() != self.request.request_id() {
            return Err(ProviderConnectionError::transport(
                gus_ipc::ProtocolError::InvalidMessageRole.into(),
            ));
        }
        write_shim_response_absolute(&mut self.stream, response, self.frame_write_timeout)
            .map_err(ProviderConnectionError::transport)
    }
}

impl std::fmt::Debug for PendingUnixProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingUnixProvider")
            .field("peer", &self.peer)
            .field("registration_id", &self.registration.request_id())
            .finish_non_exhaustive()
    }
}

impl PendingUnixProvider {
    /// Reads exactly one registration frame under a frame-wide deadline.
    ///
    /// # Errors
    ///
    /// Rejects slow-drip, truncated, malformed, or non-registration input.
    pub(crate) fn read(
        mut stream: AuthenticatedUnixStream,
        frame_read_timeout: Duration,
        frame_write_timeout: Duration,
    ) -> Result<Self, ProviderConnectionError> {
        let peer = stream.peer_identity();
        let record = read_record_absolute(&mut stream, frame_read_timeout)
            .map_err(ProviderConnectionError::transport)?;
        let registration = decode_provider_request(&record)
            .map_err(|source| ProviderConnectionError::transport(source.into()))?;
        if !matches!(registration.message(), ProviderRequest::Register(_)) {
            return Err(ProviderConnectionError::transport(
                gus_ipc::ProtocolError::InvalidMessageRole.into(),
            ));
        }
        Ok(Self {
            stream,
            peer,
            registration,
            frame_read_timeout,
            frame_write_timeout,
        })
    }

    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.peer
    }

    /// Returns the untrusted registration to drive broker-side resolution.
    #[must_use]
    pub const fn registration(&self) -> &ProviderRequestFrame {
        &self.registration
    }

    /// Consumes the pending registration after independent broker resolution.
    ///
    /// # Errors
    ///
    /// Rejects mismatched claims, invalid broker parameters, a failed
    /// registration response, or failure to enter nonblocking command mode.
    pub fn admit(
        mut self,
        authorized_repositories: &[Digest32],
        membership_generation: Generation,
        provider_generation: Generation,
        heartbeat_interval_millis: u32,
    ) -> Result<UnixProviderConnection, ProviderConnectionError> {
        let admission = ProviderAdmission::verify(self.peer, &self.registration)
            .map_err(ProviderConnectionError::admission)?;
        let (mut session, response) = ProviderSession::register(
            &self.registration,
            admission,
            authorized_repositories,
            membership_generation,
            provider_generation,
            heartbeat_interval_millis,
            Instant::now(),
        )
        .map_err(ProviderConnectionError::session)?;
        if let Err(source) =
            write_response_absolute(&mut self.stream, &response, self.frame_write_timeout)
        {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                session.disconnect(),
            ));
        }
        if let Err(error) = self.stream.set_nonblocking(true) {
            return Err(ProviderConnectionError::fatal_transport(
                error.into(),
                session.disconnect(),
            ));
        }
        Ok(UnixProviderConnection {
            stream: self.stream,
            state: ProviderConnectionState {
                peer: self.peer,
                session,
            },
            input: Vec::new(),
            input_deadline: None,
            frame_read_timeout: self.frame_read_timeout,
            frame_write_timeout: self.frame_write_timeout,
        })
    }
}

/// A provider connection after native peer authentication and registration.
///
/// Reads are nonblocking so one owner loop can alternate incoming provider
/// commands with broker-originated prompts/status without sharing or cloning
/// the authenticated socket. Every frame read/write has an absolute deadline.
#[must_use = "the broker owner must call disconnect or shutdown to recover outstanding waiter IDs"]
pub struct UnixProviderConnection {
    stream: AuthenticatedUnixStream,
    state: ProviderConnectionState,
    input: Vec<u8>,
    input_deadline: Option<Instant>,
    frame_read_timeout: Duration,
    frame_write_timeout: Duration,
}

impl UnixProviderConnection {
    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.state.peer
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.state.session.registration_id()
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.state.session.provider_generation()
    }

    /// Attempts to read, apply, and acknowledge one provider command.
    ///
    /// Returns immediately with `Ok(None)` when no complete frame is ready,
    /// allowing the same owner loop to process broker-originated output.
    ///
    /// # Errors
    ///
    /// Slow-drip frames, EOF, malformed input, invalid commands, and ACK
    /// failures are connection-fatal and return all recoverable effects.
    pub fn try_handle_next(
        &mut self,
        authorized_repositories: &[Digest32],
    ) -> Result<Option<ProviderCommandOutcome>, ProviderConnectionError> {
        let Some(record) = self.try_read_record()? else {
            return Ok(None);
        };
        let request = match decode_provider_request(&record) {
            Ok(request) => request,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_transport(
                    source.into(),
                    self.state.session.disconnect(),
                ));
            }
        };
        let outcome = self
            .state
            .handle(&request, Instant::now(), authorized_repositories)?;
        let response = outcome_response(&outcome);
        if let Err(source) = self.write_response(response) {
            let mut revoked_prompt_ids = outcome_revoked_prompt_ids(&outcome).to_vec();
            revoked_prompt_ids.extend(self.state.session.disconnect());
            revoked_prompt_ids.sort_unstable();
            revoked_prompt_ids.dedup();
            return Err(ProviderConnectionError::AcknowledgementWrite {
                source,
                completed_command: Box::new(outcome),
                revoked_prompt_ids,
            });
        }
        Ok(Some(outcome))
    }

    /// Sends one broker prompt exactly once.
    ///
    /// # Errors
    ///
    /// A failed or ambiguous write closes the connection and revokes every
    /// outstanding prompt.
    pub fn send_prompt(
        &mut self,
        prompt: SelectionPrompt,
        now: Instant,
    ) -> Result<SentProviderPrompt, ProviderConnectionError> {
        let issued = match self.state.session.issue_prompt(prompt, now) {
            Ok(issued) => issued,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_session(
                    source,
                    self.state.session.disconnect(),
                ));
            }
        };
        let request_id = issued.frame.request_id();
        if let Err(source) = self.write_response(&issued.frame) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                self.state.session.disconnect(),
            ));
        }
        Ok(SentProviderPrompt {
            request_id,
            expired_prompt_ids: issued.expired_prompt_ids,
        })
    }

    /// Sends a negotiated status snapshot exactly once.
    ///
    /// # Errors
    ///
    /// A validation or write failure closes the connection.
    pub fn send_status(
        &mut self,
        snapshot: ProviderStatusSnapshot,
        now: Instant,
    ) -> Result<(), ProviderConnectionError> {
        let frame = match self.state.session.issue_status(snapshot, now) {
            Ok(frame) => frame,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_session(
                    source,
                    self.state.session.disconnect(),
                ));
            }
        };
        if let Err(source) = self.write_response(&frame) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                self.state.session.disconnect(),
            ));
        }
        Ok(())
    }

    /// Replaces repository membership from broker-authorized native evidence.
    ///
    /// # Errors
    ///
    /// Rejects closed/expired providers and invalid or stale membership.
    pub fn replace_authorized_repositories(
        &mut self,
        repositories: &[Digest32],
        membership_generation: Generation,
        now: Instant,
    ) -> Result<Vec<RequestId>, ProviderConnectionError> {
        self.state
            .session
            .replace_authorized_repositories(repositories, membership_generation, now)
            .map_err(ProviderConnectionError::session)
    }

    /// Expires prompts and returns their waiter IDs.
    ///
    /// # Errors
    ///
    /// Returns a terminal session error after the connection has closed.
    pub fn expire_prompts(
        &mut self,
        now: Instant,
    ) -> Result<Vec<RequestId>, ProviderConnectionError> {
        self.state
            .session
            .expire_prompts(now)
            .map_err(ProviderConnectionError::session)
    }

    /// Closes an expired heartbeat and returns all waiter IDs once.
    #[must_use]
    pub fn expire_heartbeat(&mut self, now: Instant) -> Option<Vec<RequestId>> {
        self.state.session.expire_heartbeat(now)
    }

    /// Closes the connection state and returns all waiter IDs once.
    #[must_use]
    pub fn disconnect(&mut self) -> Vec<RequestId> {
        self.state.session.disconnect()
    }

    /// Consumes the connection and returns every outstanding waiter ID.
    #[must_use]
    pub fn shutdown(mut self) -> Vec<RequestId> {
        self.disconnect()
    }

    fn try_read_record(&mut self) -> Result<Option<Vec<u8>>, ProviderConnectionError> {
        let now = Instant::now();
        if self.input_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(ProviderConnectionError::fatal_transport(
                TransportError::Io(io::ErrorKind::TimedOut),
                self.state.session.disconnect(),
            ));
        }
        if let Some(record) = take_complete_record(
            &mut self.input,
            &mut self.input_deadline,
            self.frame_read_timeout,
            now,
        )
        .map_err(|source| {
            ProviderConnectionError::fatal_transport(source, self.state.session.disconnect())
        })? {
            return Ok(Some(record));
        }

        let capacity = FRAME_HEADER_BYTES
            .checked_add(MAX_FRAME_BYTES)
            .and_then(|maximum| maximum.checked_sub(self.input.len()))
            .ok_or_else(|| {
                ProviderConnectionError::fatal_transport(
                    gus_ipc::ProtocolError::FrameTooLarge.into(),
                    self.state.session.disconnect(),
                )
            })?;
        let mut chunk = [0_u8; 8 * 1024];
        let read_limit = capacity.min(chunk.len());
        let read = match self.stream.read(&mut chunk[..read_limit]) {
            Ok(0) => {
                return Err(ProviderConnectionError::fatal_transport(
                    TransportError::Io(io::ErrorKind::UnexpectedEof),
                    self.state.session.disconnect(),
                ));
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => {
                return Err(ProviderConnectionError::fatal_transport(
                    error.into(),
                    self.state.session.disconnect(),
                ));
            }
        };
        let now = Instant::now();
        if self.input.is_empty() {
            self.input_deadline = Some(deadline_after(now, self.frame_read_timeout).map_err(
                |source| {
                    ProviderConnectionError::fatal_transport(
                        source,
                        self.state.session.disconnect(),
                    )
                },
            )?);
        }
        self.input.extend_from_slice(&chunk[..read]);
        take_complete_record(
            &mut self.input,
            &mut self.input_deadline,
            self.frame_read_timeout,
            now,
        )
        .map_err(|source| {
            ProviderConnectionError::fatal_transport(source, self.state.session.disconnect())
        })
    }

    fn write_response(&mut self, frame: &ProviderResponseFrame) -> Result<(), TransportError> {
        self.stream.set_nonblocking(false)?;
        let result = write_response_absolute(&mut self.stream, frame, self.frame_write_timeout);
        let restore = self
            .stream
            .set_nonblocking(true)
            .map_err(TransportError::from);
        match (result, restore) {
            (Err(source), _) | (Ok(()), Err(source)) => Err(source),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Drop for UnixProviderConnection {
    fn drop(&mut self) {
        let orphaned = self.state.session.disconnect();
        debug_assert!(
            orphaned.is_empty(),
            "UnixProviderConnection dropped without recovering outstanding waiter IDs"
        );
    }
}

struct ProviderConnectionState {
    peer: ProcessIdentity,
    session: ProviderSession,
}

impl ProviderConnectionState {
    fn handle(
        &mut self,
        request: &ProviderRequestFrame,
        now: Instant,
        authorized_repositories: &[Digest32],
    ) -> Result<ProviderCommandOutcome, ProviderConnectionError> {
        let membership_admission =
            if matches!(request.message(), ProviderRequest::UpdateRepositories(_)) {
                match ProviderMembershipAdmission::verify(
                    self.peer,
                    request,
                    authorized_repositories,
                ) {
                    Ok(admission) => Some(admission),
                    Err(source) => {
                        return Err(ProviderConnectionError::fatal_admission(
                            source,
                            self.session.disconnect(),
                        ));
                    }
                }
            } else {
                None
            };
        self.session
            .handle_command(request, now, membership_admission.as_ref())
            .map_err(ProviderConnectionError::Command)
    }
}

fn read_record_absolute(
    stream: &mut AuthenticatedUnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, TransportError> {
    let deadline = deadline_after(Instant::now(), timeout)?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact_absolute(stream, &mut header, deadline)?;
    let payload_length = decode_frame_length(&header)?;
    let mut record = vec![0_u8; FRAME_HEADER_BYTES + payload_length];
    record[..FRAME_HEADER_BYTES].copy_from_slice(&header);
    read_exact_absolute(stream, &mut record[FRAME_HEADER_BYTES..], deadline)?;
    Ok(record)
}

fn read_exact_absolute(
    stream: &mut AuthenticatedUnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), TransportError> {
    while !buffer.is_empty() {
        let timeout_remaining = remaining(deadline)?;
        stream.set_read_timeout(Some(timeout_remaining))?;
        match stream.read(buffer) {
            Ok(0) => return Err(TransportError::Io(io::ErrorKind::UnexpectedEof)),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(TransportError::Io(io::ErrorKind::TimedOut));
            }
            Err(error) => return Err(error.into()),
        }
        remaining(deadline)?;
    }
    Ok(())
}

fn write_response_absolute(
    stream: &mut impl DeadlineWriter,
    frame: &ProviderResponseFrame,
    timeout: Duration,
) -> Result<(), TransportError> {
    let record = encode_provider_response(frame)?;
    let deadline = deadline_after(Instant::now(), timeout)?;
    let mut remaining_record = record.as_slice();
    while !remaining_record.is_empty() {
        let timeout = remaining(deadline)?;
        stream.set_deadline_write_timeout(Some(timeout))?;
        match stream.write(remaining_record) {
            Ok(0) => return Err(TransportError::Io(io::ErrorKind::WriteZero)),
            Ok(written) => remaining_record = &remaining_record[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(TransportError::Io(io::ErrorKind::TimedOut));
            }
            Err(error) => return Err(error.into()),
        }
        remaining(deadline)?;
    }
    Ok(())
}

fn write_shim_response_absolute(
    stream: &mut impl DeadlineWriter,
    frame: &ShimResponseFrame,
    timeout: Duration,
) -> Result<(), TransportError> {
    let record = encode_shim_response(frame)?;
    let deadline = deadline_after(Instant::now(), timeout)?;
    let mut remaining_record = record.as_slice();
    while !remaining_record.is_empty() {
        let timeout = remaining(deadline)?;
        stream.set_deadline_write_timeout(Some(timeout))?;
        match stream.write(remaining_record) {
            Ok(0) => return Err(TransportError::Io(io::ErrorKind::WriteZero)),
            Ok(written) => remaining_record = &remaining_record[written..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(TransportError::Io(io::ErrorKind::TimedOut));
            }
            Err(error) => return Err(error.into()),
        }
        remaining(deadline)?;
    }
    Ok(())
}

trait DeadlineWriter: Write {
    fn set_deadline_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl DeadlineWriter for AuthenticatedUnixStream {
    fn set_deadline_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

fn take_complete_record(
    input: &mut Vec<u8>,
    input_deadline: &mut Option<Instant>,
    timeout: Duration,
    now: Instant,
) -> Result<Option<Vec<u8>>, TransportError> {
    if input_deadline.is_some_and(|deadline| now >= deadline) {
        return Err(TransportError::Io(io::ErrorKind::TimedOut));
    }
    if input.len() < FRAME_HEADER_BYTES {
        return Ok(None);
    }
    let payload_length = decode_frame_length(&input[..FRAME_HEADER_BYTES])?;
    let record_length = FRAME_HEADER_BYTES + payload_length;
    if input.len() < record_length {
        return Ok(None);
    }
    let trailing = input.split_off(record_length);
    let record = std::mem::replace(input, trailing);
    *input_deadline = if input.is_empty() {
        None
    } else {
        Some(deadline_after(now, timeout)?)
    };
    Ok(Some(record))
}

fn deadline_after(now: Instant, timeout: Duration) -> Result<Instant, TransportError> {
    now.checked_add(timeout)
        .ok_or(TransportError::Io(io::ErrorKind::InvalidInput))
}

fn remaining(deadline: Instant) -> Result<Duration, TransportError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(TransportError::Io(io::ErrorKind::TimedOut))
    } else {
        Ok(remaining)
    }
}

fn outcome_response(outcome: &ProviderCommandOutcome) -> &ProviderResponseFrame {
    match outcome {
        ProviderCommandOutcome::Acknowledged { response }
        | ProviderCommandOutcome::MembershipUpdated { response, .. }
        | ProviderCommandOutcome::SelectionDecided { response, .. }
        | ProviderCommandOutcome::Unregistered { response, .. } => response,
    }
}

fn outcome_revoked_prompt_ids(outcome: &ProviderCommandOutcome) -> &[RequestId] {
    match outcome {
        ProviderCommandOutcome::MembershipUpdated {
            revoked_prompt_ids, ..
        }
        | ProviderCommandOutcome::Unregistered {
            revoked_prompt_ids, ..
        } => revoked_prompt_ids,
        ProviderCommandOutcome::Acknowledged { .. }
        | ProviderCommandOutcome::SelectionDecided { .. } => &[],
    }
}

/// Prompt identity returned only after its frame was written successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentProviderPrompt {
    pub request_id: RequestId,
    pub expired_prompt_ids: Vec<RequestId>,
}

/// Fatal provider connection failure with waiter recovery information.
#[derive(Debug, Error)]
pub enum ProviderConnectionError {
    #[error("provider admission failed: {source}")]
    Admission {
        #[source]
        source: ProviderAdmissionError,
        revoked_prompt_ids: Vec<RequestId>,
    },
    #[error(transparent)]
    Command(#[from] ProviderCommandFailure),
    #[error("provider session failed: {source}")]
    Session {
        #[source]
        source: ProviderSessionError,
        revoked_prompt_ids: Vec<RequestId>,
    },
    #[error("provider transport failed: {source}")]
    Transport {
        #[source]
        source: TransportError,
        revoked_prompt_ids: Vec<RequestId>,
    },
    #[error("provider command completed but its acknowledgement write failed: {source}")]
    AcknowledgementWrite {
        #[source]
        source: TransportError,
        completed_command: Box<ProviderCommandOutcome>,
        revoked_prompt_ids: Vec<RequestId>,
    },
}

impl ProviderConnectionError {
    fn admission(source: ProviderAdmissionError) -> Self {
        Self::Admission {
            source,
            revoked_prompt_ids: Vec::new(),
        }
    }

    fn fatal_admission(source: ProviderAdmissionError, revoked_prompt_ids: Vec<RequestId>) -> Self {
        Self::Admission {
            source,
            revoked_prompt_ids,
        }
    }

    fn session(source: ProviderSessionError) -> Self {
        Self::Session {
            source,
            revoked_prompt_ids: Vec::new(),
        }
    }

    fn fatal_session(source: ProviderSessionError, revoked_prompt_ids: Vec<RequestId>) -> Self {
        Self::Session {
            source,
            revoked_prompt_ids,
        }
    }

    fn transport(source: TransportError) -> Self {
        Self::Transport {
            source,
            revoked_prompt_ids: Vec::new(),
        }
    }

    fn fatal_transport(source: TransportError, revoked_prompt_ids: Vec<RequestId>) -> Self {
        Self::Transport {
            source,
            revoked_prompt_ids,
        }
    }

    #[must_use]
    pub fn revoked_prompt_ids(&self) -> &[RequestId] {
        match self {
            Self::Admission {
                revoked_prompt_ids, ..
            }
            | Self::Session {
                revoked_prompt_ids, ..
            }
            | Self::Transport {
                revoked_prompt_ids, ..
            }
            | Self::AcknowledgementWrite {
                revoked_prompt_ids, ..
            } => revoked_prompt_ids,
            Self::Command(error) => error.revoked_prompt_ids(),
        }
    }

    /// Returns a command effect which completed before its ACK write failed.
    ///
    /// The caller must apply this outcome exactly once even though the
    /// provider connection is closed. The provider cannot safely retry it.
    #[must_use]
    pub fn completed_command(&self) -> Option<&ProviderCommandOutcome> {
        match self {
            Self::AcknowledgementWrite {
                completed_command, ..
            } => Some(completed_command),
            Self::Admission { .. }
            | Self::Command(_)
            | Self::Session { .. }
            | Self::Transport { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, os::unix::net::UnixStream, thread, time::Duration};

    use gus_ipc::{
        BrokerProviderMessage, OperationPresentation, ProfilePresentation, ProviderCapability,
        ProviderControlRequest, ProviderKind, ProviderRegistrationRequest,
        ProviderRepositoryMembership, ProviderSelectionDecision, RepositoryPresentation,
        ScopePresentation, SelectionScopePresentation, read_provider_response,
        write_provider_request,
    };
    use gus_profile::ProfileId;

    use super::*;

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("nonzero generation")
    }

    fn registration() -> gus_ipc::ProviderRequestFrame {
        gus_ipc::ProviderRequestFrame::registration(
            ProviderRegistrationRequest::new(
                ProviderKind::Vscode,
                "window-1".into(),
                vec![
                    ProviderCapability::ProfileQuickPick,
                    ProviderCapability::Status,
                ],
            )
            .expect("registration"),
        )
        .expect("registration frame")
    }

    fn prompt(session: &ProviderSession, timeout_millis: u32) -> SelectionPrompt {
        SelectionPrompt::new(
            session.registration_id(),
            session.provider_generation(),
            generation(1),
            ScopePresentation::new(
                SelectionScopePresentation::IdeWindow,
                digest(3),
                "SCM".into(),
            )
            .expect("scope"),
            RepositoryPresentation::new(digest(2), "gus".into()).expect("repository"),
            OperationPresentation::Commit,
            vec![
                ProfilePresentation::new(
                    ProfileId::try_from("work".to_owned()).expect("profile ID"),
                    "Work".into(),
                    Some("work@example.test".into()),
                )
                .expect("profile"),
            ],
            timeout_millis,
        )
        .expect("prompt")
    }

    fn authenticated_pair() -> (AuthenticatedUnixStream, AuthenticatedUnixStream) {
        let (server, client) = UnixStream::pair().expect("Unix stream pair");
        let connector = thread::spawn(move || {
            AuthenticatedUnixStream::authenticate_outgoing(client).expect("authenticate server")
        });
        let server =
            AuthenticatedUnixStream::authenticate_incoming(server).expect("authenticate client");
        (server, connector.join().expect("connector thread"))
    }

    fn registered_connection() -> (
        UnixProviderConnection,
        AuthenticatedUnixStream,
        ProviderRequestFrame,
    ) {
        registered_connection_with_timeouts(Duration::from_secs(1), Duration::from_secs(1))
    }

    fn registered_connection_with_timeouts(
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> (
        UnixProviderConnection,
        AuthenticatedUnixStream,
        ProviderRequestFrame,
    ) {
        let registration = registration();
        let (server, mut client) = authenticated_pair();
        write_provider_request(&mut client, &registration).expect("write registration");
        let pending = PendingUnixProvider::read(server, read_timeout, write_timeout)
            .expect("read registration");
        let connection = pending
            .admit(&[digest(2)], generation(1), generation(7), 15_000)
            .expect("admit registration");
        let registered = read_provider_response(&mut client).expect("registration response");
        assert_eq!(registered.request_id(), registration.request_id());
        assert!(matches!(
            registered.message(),
            BrokerProviderMessage::Registered(_)
        ));
        (connection, client, registration)
    }

    #[test]
    fn registration_and_command_are_read_applied_and_acknowledged() {
        let (mut connection, mut client, registration) = registered_connection();
        let heartbeat = gus_ipc::ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(registration.request_id(), generation(7)),
        ))
        .expect("heartbeat");
        write_provider_request(&mut client, &heartbeat).expect("write heartbeat");
        assert!(matches!(
            connection
                .try_handle_next(&[digest(2)])
                .expect("handle heartbeat"),
            Some(ProviderCommandOutcome::Acknowledged { .. })
        ));
        let acknowledged = read_provider_response(&mut client).expect("heartbeat response");
        assert_eq!(acknowledged.request_id(), heartbeat.request_id());
        assert!(matches!(
            acknowledged.message(),
            BrokerProviderMessage::Acknowledged
        ));
    }

    #[test]
    fn rejected_membership_closes_connection_and_recovers_prompt() {
        let (mut connection, mut client, registration) = registered_connection();
        let membership = ProviderRepositoryMembership::new(
            registration.request_id(),
            generation(7),
            generation(1),
            vec![digest(9)],
        )
        .expect("membership");
        let update =
            gus_ipc::ProviderRequestFrame::control(ProviderRequest::UpdateRepositories(membership))
                .expect("membership frame");
        let now = Instant::now();
        let prompt = prompt(&connection.state.session, 30_000);
        let sent = connection.send_prompt(prompt, now).expect("send prompt");
        read_provider_response(&mut client).expect("read prompt");
        write_provider_request(&mut client, &update).expect("write membership");

        let error = connection
            .try_handle_next(&[digest(2)])
            .expect_err("reject untrusted membership");
        assert_eq!(error.revoked_prompt_ids(), &[sent.request_id]);
        assert!(connection.state.session.disconnect().is_empty());
    }

    #[test]
    fn ambiguous_prompt_write_closes_connection_and_recovers_waiter() {
        let (mut connection, client, _) = registered_connection();
        drop(client);
        let now = Instant::now();
        let prompt = prompt(&connection.state.session, 30_000);
        let error = connection
            .send_prompt(prompt, now)
            .expect_err("prompt write fails");
        assert_eq!(error.revoked_prompt_ids().len(), 1);
        assert!(connection.state.session.disconnect().is_empty());
    }

    #[test]
    fn ack_failure_preserves_completed_selection_effect() {
        let (mut connection, mut client, registration) = registered_connection();
        let now = Instant::now();
        let sent = connection
            .send_prompt(prompt(&connection.state.session, 30_000), now)
            .expect("send prompt");
        read_provider_response(&mut client).expect("read prompt");
        let decision = ProviderSelectionDecision::new(
            registration.request_id(),
            generation(7),
            generation(1),
            gus_ipc::ProviderDecision::Selected(
                ProfileId::try_from("work".to_owned()).expect("profile ID"),
            ),
        )
        .expect("selection decision");
        let response = ProviderRequestFrame::selection_response(sent.request_id, decision)
            .expect("selection response");
        write_provider_request(&mut client, &response).expect("write selection");
        drop(client);

        let error = connection
            .try_handle_next(&[digest(2)])
            .expect_err("ACK write must fail");
        assert!(matches!(
            error.completed_command(),
            Some(ProviderCommandOutcome::SelectionDecided {
                decision: gus_ipc::ProviderDecision::Selected(profile),
                ..
            }) if profile.as_str() == "work"
        ));
    }

    #[test]
    fn idle_provider_does_not_block_an_external_prompt() {
        let (mut connection, mut client, registration) = registered_connection();
        assert!(
            connection
                .try_handle_next(&[digest(2)])
                .expect("nonblocking read")
                .is_none()
        );
        let sent = connection
            .send_prompt(prompt(&connection.state.session, 30_000), Instant::now())
            .expect("send prompt while provider is idle");
        let received = read_provider_response(&mut client).expect("read prompt");
        assert_eq!(received.request_id(), sent.request_id);
        let decision = ProviderSelectionDecision::new(
            registration.request_id(),
            generation(7),
            generation(1),
            gus_ipc::ProviderDecision::Cancelled,
        )
        .expect("selection decision");
        let response = ProviderRequestFrame::selection_response(sent.request_id, decision)
            .expect("selection response");
        write_provider_request(&mut client, &response).expect("write selection");
        assert!(matches!(
            connection
                .try_handle_next(&[digest(2)])
                .expect("handle selection"),
            Some(ProviderCommandOutcome::SelectionDecided { .. })
        ));
        let ack = read_provider_response(&mut client).expect("read ACK");
        assert_eq!(ack.request_id(), sent.request_id);
    }

    #[test]
    fn selection_deadline_is_sampled_after_nonblocking_read() {
        let (mut connection, mut client, registration) = registered_connection();
        let sent = connection
            .send_prompt(prompt(&connection.state.session, 1_000), Instant::now())
            .expect("send prompt");
        read_provider_response(&mut client).expect("read prompt");
        thread::sleep(Duration::from_millis(1_050));
        let decision = ProviderSelectionDecision::new(
            registration.request_id(),
            generation(7),
            generation(1),
            gus_ipc::ProviderDecision::Cancelled,
        )
        .expect("selection decision");
        let response = ProviderRequestFrame::selection_response(sent.request_id, decision)
            .expect("selection response");
        write_provider_request(&mut client, &response).expect("write late selection");
        let error = connection
            .try_handle_next(&[digest(2)])
            .expect_err("late selection rejected");
        assert_eq!(error.revoked_prompt_ids(), &[sent.request_id]);
    }

    #[test]
    fn registration_slow_drip_expires_against_one_absolute_deadline() {
        let registration = registration();
        let record = gus_ipc::encode_provider_request(&registration).expect("encode registration");
        let (server, mut client) = authenticated_pair();
        let reader = thread::spawn(move || {
            PendingUnixProvider::read(server, Duration::from_millis(30), Duration::from_secs(1))
        });
        for byte in record.iter().take(4) {
            if client.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(12));
        }
        let error = reader
            .join()
            .expect("reader thread")
            .expect_err("slow drip times out");
        assert!(
            matches!(
                error,
                ProviderConnectionError::Transport {
                    source: TransportError::Io(io::ErrorKind::TimedOut),
                    ..
                }
            ),
            "unexpected slow-drip error: {error:?}"
        );
    }

    #[test]
    fn partial_command_expires_and_recovers_outstanding_waiter() {
        let (mut connection, mut client, registration) =
            registered_connection_with_timeouts(Duration::from_millis(30), Duration::from_secs(1));
        let sent = connection
            .send_prompt(prompt(&connection.state.session, 30_000), Instant::now())
            .expect("send prompt");
        read_provider_response(&mut client).expect("read prompt");
        let heartbeat = ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(registration.request_id(), generation(7)),
        ))
        .expect("heartbeat");
        let record = gus_ipc::encode_provider_request(&heartbeat).expect("encode heartbeat");
        client
            .write_all(&record[..=FRAME_HEADER_BYTES])
            .expect("write partial command");
        assert!(
            connection
                .try_handle_next(&[digest(2)])
                .expect("buffer partial command")
                .is_none()
        );
        thread::sleep(Duration::from_millis(40));

        let error = connection
            .try_handle_next(&[digest(2)])
            .expect_err("partial command deadline expires");
        assert!(
            matches!(
                error,
                ProviderConnectionError::Transport {
                    source: TransportError::Io(io::ErrorKind::TimedOut),
                    ..
                }
            ),
            "unexpected partial-frame error: {error:?}"
        );
        assert_eq!(error.revoked_prompt_ids(), &[sent.request_id]);
    }

    struct ProgressingWriter {
        delay: Duration,
        calls: usize,
    }

    impl Write for ProgressingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            thread::sleep(self.delay);
            self.calls += 1;
            Ok(usize::from(!buffer.is_empty()))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineWriter for ProgressingWriter {
        fn set_deadline_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn progressing_write_expires_against_one_absolute_deadline() {
        let frame = ProviderResponseFrame::acknowledgement(registration().request_id())
            .expect("acknowledgement");
        let mut writer = ProgressingWriter {
            delay: Duration::from_millis(1),
            calls: 0,
        };
        let error = write_response_absolute(&mut writer, &frame, Duration::from_millis(100))
            .expect_err("progress cannot extend the frame deadline");
        assert_eq!(error, TransportError::Io(io::ErrorKind::TimedOut));
        assert!(writer.calls >= 2, "fixture must make partial progress");
    }
}
