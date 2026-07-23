use std::{
    io::{Read, Write},
    time::Instant,
};

use gus_ipc::{
    Digest32, Generation, ProviderRequest, ProviderResponseFrame, ProviderStatusSnapshot,
    RequestId, SelectionPrompt, TransportError, read_provider_request, write_provider_response,
};
use gus_platform::{AuthenticatedUnixStream, ProcessIdentity};
use thiserror::Error;

use crate::{
    ProviderAdmission, ProviderAdmissionError, ProviderCommandFailure, ProviderCommandOutcome,
    ProviderMembershipAdmission, ProviderSession, ProviderSessionError,
};

/// A provider connection after native peer authentication and registration.
///
/// The stream is owned exclusively by this value so a frame is never retried
/// after an ambiguous write result. Any transport or command failure closes
/// the logical session and returns all prompt IDs the broker must complete.
pub struct UnixProviderConnection {
    inner: ProviderConnection<AuthenticatedUnixStream>,
}

impl UnixProviderConnection {
    /// Reads and accepts the first provider registration frame.
    ///
    /// `authenticated_host_instance` and `authorized_repositories` must be
    /// broker-derived evidence, not values copied from the registration.
    ///
    /// # Errors
    ///
    /// Rejects malformed transport records, mismatched registration claims,
    /// invalid broker parameters, or a failed acknowledgement write.
    pub fn accept(
        stream: AuthenticatedUnixStream,
        authenticated_host_instance: Digest32,
        authorized_repositories: &[Digest32],
        provider_generation: Generation,
        heartbeat_interval_millis: u32,
        now: Instant,
    ) -> Result<Self, ProviderConnectionError> {
        let peer = stream.peer_identity();
        ProviderConnection::accept(
            stream,
            peer,
            authenticated_host_instance,
            authorized_repositories,
            provider_generation,
            heartbeat_interval_millis,
            now,
        )
        .map(|inner| Self { inner })
    }

    #[must_use]
    pub const fn peer_identity(&self) -> ProcessIdentity {
        self.inner.peer
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.inner.session.registration_id()
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.inner.session.provider_generation()
    }

    /// Reads, validates, applies, and acknowledges one provider command.
    ///
    /// The repository slice is consulted only for a membership replacement
    /// and must contain the broker's current independently resolved set.
    ///
    /// # Errors
    ///
    /// Any error is connection-fatal and includes all prompt IDs to complete.
    pub fn handle_next(
        &mut self,
        now: Instant,
        authorized_repositories: &[Digest32],
    ) -> Result<ProviderCommandOutcome, ProviderConnectionError> {
        self.inner.handle_next(now, authorized_repositories)
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
        self.inner.send_prompt(prompt, now)
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
        self.inner.send_status(snapshot, now)
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
        self.inner
            .session
            .expire_prompts(now)
            .map_err(ProviderConnectionError::session)
    }

    /// Closes an expired heartbeat and returns all waiter IDs once.
    #[must_use]
    pub fn expire_heartbeat(&mut self, now: Instant) -> Option<Vec<RequestId>> {
        self.inner.session.expire_heartbeat(now)
    }

    /// Closes the connection state and returns all waiter IDs once.
    #[must_use]
    pub fn disconnect(&mut self) -> Vec<RequestId> {
        self.inner.session.disconnect()
    }
}

struct ProviderConnection<S> {
    stream: S,
    peer: ProcessIdentity,
    session: ProviderSession,
}

impl<S: Read + Write> ProviderConnection<S> {
    #[allow(clippy::too_many_arguments)]
    fn accept(
        mut stream: S,
        peer: ProcessIdentity,
        authenticated_host_instance: Digest32,
        authorized_repositories: &[Digest32],
        provider_generation: Generation,
        heartbeat_interval_millis: u32,
        now: Instant,
    ) -> Result<Self, ProviderConnectionError> {
        let request =
            read_provider_request(&mut stream).map_err(ProviderConnectionError::transport)?;
        let admission = ProviderAdmission::verify(
            peer,
            &request,
            authenticated_host_instance,
            authorized_repositories,
        )
        .map_err(ProviderConnectionError::admission)?;
        let (mut session, response) = ProviderSession::register(
            &request,
            admission,
            provider_generation,
            heartbeat_interval_millis,
            now,
        )
        .map_err(ProviderConnectionError::session)?;
        if let Err(source) = write_provider_response(&mut stream, &response) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                session.disconnect(),
            ));
        }
        Ok(Self {
            stream,
            peer,
            session,
        })
    }

    fn handle_next(
        &mut self,
        now: Instant,
        authorized_repositories: &[Digest32],
    ) -> Result<ProviderCommandOutcome, ProviderConnectionError> {
        let request = match read_provider_request(&mut self.stream) {
            Ok(request) => request,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_transport(
                    source,
                    self.session.disconnect(),
                ));
            }
        };
        let membership_admission =
            if matches!(request.message(), ProviderRequest::UpdateRepositories(_)) {
                match ProviderMembershipAdmission::verify(
                    self.peer,
                    &request,
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
        let outcome = self
            .session
            .handle_command(&request, now, membership_admission.as_ref())
            .map_err(ProviderConnectionError::Command)?;
        let response = outcome_response(&outcome);
        if let Err(source) = write_provider_response(&mut self.stream, response) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                self.session.disconnect(),
            ));
        }
        Ok(outcome)
    }

    fn send_prompt(
        &mut self,
        prompt: SelectionPrompt,
        now: Instant,
    ) -> Result<SentProviderPrompt, ProviderConnectionError> {
        let issued = match self.session.issue_prompt(prompt, now) {
            Ok(issued) => issued,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_session(
                    source,
                    self.session.disconnect(),
                ));
            }
        };
        let request_id = issued.frame.request_id();
        if let Err(source) = write_provider_response(&mut self.stream, &issued.frame) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                self.session.disconnect(),
            ));
        }
        Ok(SentProviderPrompt {
            request_id,
            expired_prompt_ids: issued.expired_prompt_ids,
        })
    }

    fn send_status(
        &mut self,
        snapshot: ProviderStatusSnapshot,
        now: Instant,
    ) -> Result<(), ProviderConnectionError> {
        let frame = match self.session.issue_status(snapshot, now) {
            Ok(frame) => frame,
            Err(source) => {
                return Err(ProviderConnectionError::fatal_session(
                    source,
                    self.session.disconnect(),
                ));
            }
        };
        if let Err(source) = write_provider_response(&mut self.stream, &frame) {
            return Err(ProviderConnectionError::fatal_transport(
                source,
                self.session.disconnect(),
            ));
        }
        Ok(())
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
            } => revoked_prompt_ids,
            Self::Command(error) => error.revoked_prompt_ids(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor},
        num::NonZeroU32,
        time::Duration,
    };

    use gus_ipc::{
        BrokerProviderMessage, OperationPresentation, ProfilePresentation, ProviderCapability,
        ProviderControlRequest, ProviderKind, ProviderRegistrationRequest,
        ProviderRepositoryMembership, RepositoryPresentation, ScopePresentation,
        SelectionScopePresentation, encode_provider_request, read_provider_response,
    };
    use gus_platform::NativeProcessObserver;
    use gus_profile::ProfileId;

    use super::*;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        writes_before_failure: Option<usize>,
        writes: usize,
    }

    impl Duplex {
        fn new(frames: &[gus_ipc::ProviderRequestFrame]) -> Self {
            let input = frames
                .iter()
                .flat_map(|frame| encode_provider_request(frame).expect("encode provider request"))
                .collect();
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
                writes_before_failure: None,
                writes: 0,
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.writes_before_failure == Some(self.writes) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                ));
            }
            self.writes += 1;
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("nonzero generation")
    }

    fn peer() -> ProcessIdentity {
        NativeProcessObserver::new(
            NonZeroU32::new(std::process::id()).expect("current process ID is nonzero"),
        )
        .observe()
        .expect("current process")
    }

    fn registration() -> gus_ipc::ProviderRequestFrame {
        gus_ipc::ProviderRequestFrame::registration(
            ProviderRegistrationRequest::new(
                ProviderKind::Vscode,
                "window-1".into(),
                digest(1),
                vec![digest(2)],
                vec![
                    ProviderCapability::ProfileQuickPick,
                    ProviderCapability::Status,
                ],
            )
            .expect("registration"),
        )
        .expect("registration frame")
    }

    fn prompt(session: &ProviderSession) -> SelectionPrompt {
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
            30_000,
        )
        .expect("prompt")
    }

    #[test]
    fn registration_and_command_are_read_applied_and_acknowledged() {
        let registration = registration();
        let heartbeat = gus_ipc::ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(registration.request_id(), generation(7)),
        ))
        .expect("heartbeat");
        let stream = Duplex::new(&[registration.clone(), heartbeat.clone()]);
        let now = Instant::now();
        let mut connection = ProviderConnection::accept(
            stream,
            peer(),
            digest(1),
            &[digest(2)],
            generation(7),
            15_000,
            now,
        )
        .expect("register connection");

        assert!(matches!(
            connection
                .handle_next(now + Duration::from_secs(1), &[digest(2)])
                .expect("handle heartbeat"),
            ProviderCommandOutcome::Acknowledged { .. }
        ));

        let mut output = Cursor::new(connection.stream.output);
        let registered = read_provider_response(&mut output).expect("registration response");
        assert_eq!(registered.request_id(), registration.request_id());
        assert!(matches!(
            registered.message(),
            BrokerProviderMessage::Registered(_)
        ));
        let acknowledged = read_provider_response(&mut output).expect("heartbeat response");
        assert_eq!(acknowledged.request_id(), heartbeat.request_id());
        assert!(matches!(
            acknowledged.message(),
            BrokerProviderMessage::Acknowledged
        ));
    }

    #[test]
    fn rejected_membership_closes_connection_and_recovers_prompt() {
        let registration = registration();
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
        let mut connection = ProviderConnection::accept(
            Duplex::new(&[registration, update]),
            peer(),
            digest(1),
            &[digest(2)],
            generation(7),
            15_000,
            now,
        )
        .expect("register connection");
        let prompt = prompt(&connection.session);
        let sent = connection.send_prompt(prompt, now).expect("send prompt");

        let error = connection
            .handle_next(now, &[digest(2)])
            .expect_err("reject untrusted membership");
        assert_eq!(error.revoked_prompt_ids(), &[sent.request_id]);
        assert!(connection.session.disconnect().is_empty());
    }

    #[test]
    fn ambiguous_prompt_write_closes_connection_and_recovers_waiter() {
        let registration = registration();
        let now = Instant::now();
        let mut stream = Duplex::new(&[registration]);
        // Registration framing performs one complete-record write. Fail the
        // first write of the subsequent prompt.
        stream.writes_before_failure = Some(1);
        let mut connection = ProviderConnection::accept(
            stream,
            peer(),
            digest(1),
            &[digest(2)],
            generation(7),
            15_000,
            now,
        )
        .expect("register connection");
        let prompt = prompt(&connection.session);
        let error = connection
            .send_prompt(prompt, now)
            .expect_err("prompt write fails");
        assert_eq!(error.revoked_prompt_ids().len(), 1);
        assert!(connection.session.disconnect().is_empty());
    }
}
