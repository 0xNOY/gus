use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use gus_ipc::{
    Digest32, Generation, ProtocolError, ProviderCorrelation, ProviderCorrelationError,
    ProviderDecision, ProviderRequest, ProviderRequestFrame, ProviderResponseFrame,
    ProviderStatusSnapshot, ProviderTerminationError, RegistrationAccepted, RequestId,
    SelectionPrompt,
};
use gus_platform::ProcessIdentity;
use thiserror::Error;

// Exact replay rejection requires retaining request IDs for the connection.
// This bound permits more than 45 days of 15-second heartbeats while keeping
// memory deterministic; reaching it terminates the provider for a fresh
// registration rather than weakening replay protection.
const MAX_PROCESSED_COMMANDS: usize = 262_144;

/// Broker admission which binds an untrusted registration to an authenticated
/// native provider connection.
/// `editor_session_id` remains provider-chosen presentation/correlation data;
/// routing authority and repository membership come only from broker-owned OS
/// observations. The complete frame is retained so the admission cannot be
/// substituted onto another same-ID request.
pub struct ProviderAdmission {
    peer: ProcessIdentity,
    request: ProviderRequestFrame,
}

impl ProviderAdmission {
    /// # Errors
    ///
    /// Rejects non-registration frames.
    pub fn verify(
        peer: ProcessIdentity,
        request: &ProviderRequestFrame,
    ) -> Result<Self, ProviderAdmissionError> {
        let ProviderRequest::Register(_) = request.message() else {
            return Err(ProviderAdmissionError::UnexpectedMessageRole);
        };
        Ok(Self {
            peer,
            request: request.clone(),
        })
    }
}

/// Broker admission for one complete provider repository-membership update.
pub struct ProviderMembershipAdmission {
    peer: ProcessIdentity,
    request: ProviderRequestFrame,
}

impl ProviderMembershipAdmission {
    /// Verifies membership claims against broker-resolved repositories.
    ///
    /// # Errors
    ///
    /// Rejects non-membership frames and any repository mismatch.
    pub fn verify(
        peer: ProcessIdentity,
        request: &ProviderRequestFrame,
        authorized_repositories: &[Digest32],
    ) -> Result<Self, ProviderAdmissionError> {
        let ProviderRequest::UpdateRepositories(membership) = request.message() else {
            return Err(ProviderAdmissionError::UnexpectedMessageRole);
        };
        if as_set(membership.repositories()) != as_set(authorized_repositories)
            || membership.repositories().len() != authorized_repositories.len()
        {
            return Err(ProviderAdmissionError::ClaimMismatch);
        }
        Ok(Self {
            peer,
            request: request.clone(),
        })
    }
}

fn as_set(values: &[Digest32]) -> BTreeSet<Digest32> {
    values.iter().copied().collect()
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAdmissionError {
    #[error("message has the wrong provider admission role")]
    UnexpectedMessageRole,
    #[error("provider claims do not match authenticated broker evidence")]
    ClaimMismatch,
}

/// Broker-owned state for one authenticated IDE provider connection.
///
/// The transport adapter must authenticate the peer before constructing this
/// value and must close the connection after any returned error. This type
/// owns all request-ID and generation correlation after registration.
pub struct ProviderSession {
    correlation: Option<ProviderCorrelation>,
    registration_id: RequestId,
    provider_generation: Generation,
    peer: ProcessIdentity,
    status_subscribed: bool,
    processed_commands: BTreeSet<RequestId>,
    heartbeat_timeout: Duration,
    heartbeat_deadline: Instant,
}

impl ProviderSession {
    /// Accepts the first request on an authenticated provider connection.
    ///
    /// The registration ID is the provider's fresh registration command ID;
    /// the provider generation and heartbeat interval are broker-owned.
    ///
    /// # Errors
    ///
    /// Rejects non-registration messages, invalid broker parameters, and
    /// failures to construct or correlate the response.
    #[allow(clippy::needless_pass_by_value)] // Consume the one registration admission token.
    pub fn register(
        request: &ProviderRequestFrame,
        admission: ProviderAdmission,
        authorized_repositories: &[Digest32],
        membership_generation: Generation,
        provider_generation: Generation,
        heartbeat_interval_millis: u32,
        now: Instant,
    ) -> Result<(Self, ProviderResponseFrame), ProviderSessionError> {
        let ProviderAdmission {
            peer,
            request: admitted_request,
        } = admission;
        if !matches!(request.message(), ProviderRequest::Register(_)) {
            return Err(ProviderCorrelationError::UnexpectedMessageRole.into());
        }
        if admitted_request != *request {
            return Err(ProviderSessionError::AdmissionMismatch);
        }
        let registration_id = request.request_id();
        let accepted = RegistrationAccepted::new(
            registration_id,
            provider_generation,
            heartbeat_interval_millis,
        )?;
        let response = ProviderResponseFrame::registration_response(registration_id, accepted)?;
        let correlation = ProviderCorrelation::from_registration(
            request,
            &response,
            authorized_repositories,
            membership_generation,
        )?;
        let heartbeat_timeout = Duration::from_millis(u64::from(heartbeat_interval_millis) * 2);
        let heartbeat_deadline = now
            .checked_add(heartbeat_timeout)
            .ok_or(ProviderSessionError::HeartbeatDeadlineOverflow)?;
        Ok((
            Self {
                correlation: Some(correlation),
                registration_id,
                provider_generation,
                peer,
                status_subscribed: false,
                processed_commands: BTreeSet::new(),
                heartbeat_timeout,
                heartbeat_deadline,
            },
            response,
        ))
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    /// Emits and tracks a broker-originated prompt before the transport writes it.
    ///
    /// # Errors
    ///
    /// Rejects closed sessions and prompts with invalid framing, binding,
    /// capability, membership, deadline, or capacity.
    pub fn issue_prompt(
        &mut self,
        prompt: SelectionPrompt,
        now: Instant,
    ) -> Result<IssuedProviderPrompt, ProviderSessionError> {
        self.require_heartbeat_live(now)?;
        let frame = ProviderResponseFrame::selection_prompt(prompt)?;
        let expired_prompt_ids = self.correlation_mut()?.track_prompt(&frame, now)?;
        Ok(IssuedProviderPrompt {
            frame,
            expired_prompt_ids,
        })
    }

    /// Builds a status snapshot only when it belongs to this negotiated session.
    ///
    /// # Errors
    ///
    /// Rejects closed sessions, invalid snapshots, unnegotiated status support,
    /// and snapshots outside the registered repository membership.
    pub fn issue_status(
        &self,
        snapshot: ProviderStatusSnapshot,
        now: Instant,
    ) -> Result<ProviderResponseFrame, ProviderSessionError> {
        self.require_heartbeat_live(now)?;
        let frame = ProviderResponseFrame::status_snapshot(snapshot)?;
        if !self.status_subscribed {
            return Err(ProviderSessionError::StatusNotSubscribed);
        }
        self.correlation()?.validate_status(&frame)?;
        Ok(frame)
    }

    /// Replaces repository membership from broker-owned caller observations.
    ///
    /// The provider does not supply these identities. Outstanding prompts are
    /// returned so the broker can complete them as unavailable before routing
    /// against the new snapshot.
    ///
    /// # Errors
    ///
    /// Rejects closed/expired providers and invalid or stale membership.
    pub fn replace_authorized_repositories(
        &mut self,
        repositories: &[Digest32],
        membership_generation: Generation,
        now: Instant,
    ) -> Result<Vec<RequestId>, ProviderSessionError> {
        self.require_heartbeat_live(now)?;
        Ok(self
            .correlation_mut()?
            .replace_authorized_repositories(repositories, membership_generation)?)
    }

    /// Handles one decoded post-registration provider command.
    ///
    /// Every successful command gets exactly one correlated acknowledgement.
    /// Membership changes and termination return all prompts the adapter must
    /// complete without leaving selection waiters stranded.
    ///
    /// # Errors
    ///
    /// Rejects closed sessions, invalid command roles or bindings, stale
    /// membership and selection state, and invalid response construction.
    /// Invalid unregister commands consume the connection and retain revoked
    /// prompt IDs in [`ProviderTerminationError`].
    pub fn handle_command(
        &mut self,
        request: &ProviderRequestFrame,
        now: Instant,
        membership_admission: Option<&ProviderMembershipAdmission>,
    ) -> Result<ProviderCommandOutcome, ProviderCommandFailure> {
        let result = self.try_handle_command(request, now, membership_admission);
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(self.fail_command(request, error)),
        }
    }

    fn try_handle_command(
        &mut self,
        request: &ProviderRequestFrame,
        now: Instant,
        membership_admission: Option<&ProviderMembershipAdmission>,
    ) -> Result<ProviderCommandOutcome, ProviderSessionError> {
        self.require_heartbeat_live(now)?;
        if self.processed_commands.contains(&request.request_id()) {
            return Err(ProviderSessionError::CommandReplay);
        }
        if self.processed_commands.len() >= MAX_PROCESSED_COMMANDS {
            return Err(ProviderSessionError::CommandCapacity);
        }
        let outcome = match request.message() {
            ProviderRequest::Heartbeat(_) | ProviderRequest::SubscribeStatus(_) => {
                self.correlation()?.validate_control(request)?;
                match request.message() {
                    ProviderRequest::Heartbeat(_) => {
                        self.heartbeat_deadline = now
                            .checked_add(self.heartbeat_timeout)
                            .ok_or(ProviderSessionError::HeartbeatDeadlineOverflow)?;
                    }
                    ProviderRequest::SubscribeStatus(_) => self.status_subscribed = true,
                    _ => unreachable!("matched control roles"),
                }
                ProviderCommandOutcome::Acknowledged {
                    response: ProviderResponseFrame::acknowledgement(request.request_id())?,
                }
            }
            ProviderRequest::UpdateRepositories(_) => {
                let admission = membership_admission
                    .ok_or(ProviderSessionError::MembershipAdmissionRequired)?;
                if admission.peer != self.peer || admission.request != *request {
                    return Err(ProviderSessionError::AdmissionMismatch);
                }
                let revoked_prompt_ids = self.correlation_mut()?.accept_membership(request)?;
                ProviderCommandOutcome::MembershipUpdated {
                    response: ProviderResponseFrame::acknowledgement(request.request_id())?,
                    revoked_prompt_ids,
                }
            }
            ProviderRequest::SelectionDecision(_) => {
                let decision = self
                    .correlation_mut()?
                    .accept_selection(request, now)?
                    .clone();
                ProviderCommandOutcome::SelectionDecided {
                    response: ProviderResponseFrame::acknowledgement(request.request_id())?,
                    decision,
                }
            }
            ProviderRequest::Unregister(_) => {
                let correlation = self
                    .correlation
                    .take()
                    .ok_or(ProviderSessionError::Closed)?;
                let revoked_prompt_ids = correlation
                    .accept_unregister(request)
                    .map_err(ProviderSessionError::Termination)?;
                ProviderCommandOutcome::Unregistered {
                    response: ProviderResponseFrame::acknowledgement(request.request_id())?,
                    revoked_prompt_ids,
                }
            }
            ProviderRequest::Register(_) => {
                return Err(ProviderCorrelationError::UnexpectedMessageRole.into());
            }
        };
        self.processed_commands.insert(request.request_id());
        Ok(outcome)
    }

    fn fail_command(
        &mut self,
        request: &ProviderRequestFrame,
        error: ProviderSessionError,
    ) -> ProviderCommandFailure {
        let mut revoked_prompt_ids = match &error {
            ProviderSessionError::Termination(termination) => {
                termination.outstanding_prompt_ids().to_vec()
            }
            _ => self.disconnect(),
        };
        if matches!(
            error,
            ProviderSessionError::Correlation(
                ProviderCorrelationError::PromptExpired
                    | ProviderCorrelationError::PromptMembershipStale
            )
        ) && !revoked_prompt_ids.contains(&request.request_id())
        {
            revoked_prompt_ids.push(request.request_id());
        }
        revoked_prompt_ids.sort_unstable();
        revoked_prompt_ids.dedup();
        ProviderCommandFailure {
            cause: error,
            revoked_prompt_ids,
        }
    }

    /// Expires prompts against the broker's monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSessionError::Closed`] after termination.
    pub fn expire_prompts(&mut self, now: Instant) -> Result<Vec<RequestId>, ProviderSessionError> {
        Ok(self.correlation_mut()?.expire_prompts(now))
    }

    /// Abandons a prompt whose transport write failed.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSessionError::Closed`] after termination.
    pub fn abandon_prompt(&mut self, request_id: RequestId) -> Result<bool, ProviderSessionError> {
        Ok(self.correlation_mut()?.abandon_prompt(request_id))
    }

    /// Closes a provider whose broker-owned heartbeat deadline has elapsed.
    ///
    /// Returns `None` while the connection remains live, otherwise every
    /// outstanding waiter exactly once.
    #[must_use]
    pub fn expire_heartbeat(&mut self, now: Instant) -> Option<Vec<RequestId>> {
        (self.correlation.is_some() && now >= self.heartbeat_deadline).then(|| self.disconnect())
    }

    /// Terminates the connection and returns every outstanding waiter once.
    #[must_use]
    pub fn disconnect(&mut self) -> Vec<RequestId> {
        self.correlation
            .take()
            .map_or_else(Vec::new, ProviderCorrelation::disconnect)
    }

    fn correlation(&self) -> Result<&ProviderCorrelation, ProviderSessionError> {
        self.correlation
            .as_ref()
            .ok_or(ProviderSessionError::Closed)
    }

    fn correlation_mut(&mut self) -> Result<&mut ProviderCorrelation, ProviderSessionError> {
        self.correlation
            .as_mut()
            .ok_or(ProviderSessionError::Closed)
    }

    fn require_heartbeat_live(&self, now: Instant) -> Result<(), ProviderSessionError> {
        if now >= self.heartbeat_deadline {
            Err(ProviderSessionError::HeartbeatExpired)
        } else {
            Ok(())
        }
    }
}

/// Prompt frame plus waiters which expired before it was admitted.
pub struct IssuedProviderPrompt {
    pub frame: ProviderResponseFrame,
    pub expired_prompt_ids: Vec<RequestId>,
}

/// Successful provider command and the broker-side work it completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCommandOutcome {
    Acknowledged {
        response: ProviderResponseFrame,
    },
    MembershipUpdated {
        response: ProviderResponseFrame,
        revoked_prompt_ids: Vec<RequestId>,
    },
    SelectionDecided {
        response: ProviderResponseFrame,
        decision: ProviderDecision,
    },
    Unregistered {
        response: ProviderResponseFrame,
        revoked_prompt_ids: Vec<RequestId>,
    },
}

#[derive(Debug, Error)]
pub enum ProviderSessionError {
    #[error("provider connection is already closed")]
    Closed,
    #[error("provider admission does not belong to this connection or request")]
    AdmissionMismatch,
    #[error("repository membership requires broker-authorized evidence")]
    MembershipAdmissionRequired,
    #[error("provider status was not subscribed")]
    StatusNotSubscribed,
    #[error("provider heartbeat deadline cannot be represented")]
    HeartbeatDeadlineOverflow,
    #[error("provider heartbeat deadline has elapsed")]
    HeartbeatExpired,
    #[error("provider command request ID was replayed")]
    CommandReplay,
    #[error("provider command correlation capacity is exhausted")]
    CommandCapacity,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Correlation(#[from] ProviderCorrelationError),
    #[error(transparent)]
    Termination(ProviderTerminationError),
}

/// Fatal command failure which closes the session and returns every waiter.
#[derive(Debug, Error)]
#[error("{cause}")]
pub struct ProviderCommandFailure {
    cause: ProviderSessionError,
    revoked_prompt_ids: Vec<RequestId>,
}

impl ProviderCommandFailure {
    #[must_use]
    pub const fn cause(&self) -> &ProviderSessionError {
        &self.cause
    }

    #[must_use]
    pub fn revoked_prompt_ids(&self) -> &[RequestId] {
        &self.revoked_prompt_ids
    }
}

impl std::fmt::Debug for ProviderSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSession")
            .field("registration_id", &self.registration_id)
            .field("provider_generation", &self.provider_generation)
            .field("closed", &self.correlation.is_none())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU32,
        time::{Duration, Instant},
    };

    use gus_ipc::{
        BrokerProviderMessage, Digest32, OperationPresentation, ProfilePresentation,
        ProviderCapability, ProviderControlRequest, ProviderKind, ProviderRegistrationRequest,
        ProviderRepositoryMembership, ProviderSelectionDecision, RepositoryPresentation,
        ScopePresentation, SelectionScopePresentation,
    };
    use gus_platform::NativeProcessObserver;
    use gus_profile::ProfileId;

    use super::*;

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("nonzero generation")
    }

    fn digest(value: u8) -> Digest32 {
        Digest32::from_bytes([value; 32])
    }

    fn profile_id(value: &str) -> ProfileId {
        ProfileId::try_from(value.to_owned()).expect("profile id")
    }

    fn registration() -> ProviderRequestFrame {
        ProviderRequestFrame::registration(
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

    fn peer() -> ProcessIdentity {
        NativeProcessObserver::new(
            NonZeroU32::new(std::process::id()).expect("current process ID is nonzero"),
        )
        .observe()
        .expect("current process")
    }

    fn register(request: &ProviderRequestFrame) -> (ProviderSession, ProviderResponseFrame) {
        register_at(request, Instant::now())
    }

    fn register_at(
        request: &ProviderRequestFrame,
        now: Instant,
    ) -> (ProviderSession, ProviderResponseFrame) {
        let admission = ProviderAdmission::verify(peer(), request).expect("admission");
        ProviderSession::register(
            request,
            admission,
            &[digest(2)],
            generation(1),
            generation(7),
            15_000,
            now,
        )
        .expect("register")
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
                    profile_id("work"),
                    "Work".into(),
                    Some("work@example.test".into()),
                )
                .expect("profile"),
            ],
            timeout_millis,
        )
        .expect("prompt")
    }

    #[test]
    fn registration_and_selection_have_exact_ack_correlation() {
        let request = registration();
        let (mut session, response) = register(&request);
        assert_eq!(response.request_id(), request.request_id());
        assert!(matches!(
            response.message(),
            BrokerProviderMessage::Registered(_)
        ));

        let now = Instant::now();
        let issued = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("prompt");
        let decision = ProviderSelectionDecision::new(
            session.registration_id(),
            session.provider_generation(),
            generation(1),
            ProviderDecision::Selected(profile_id("work")),
        )
        .expect("decision");
        let request = ProviderRequestFrame::selection_response(issued.frame.request_id(), decision)
            .expect("decision frame");
        let ProviderCommandOutcome::SelectionDecided { response, decision } = session
            .handle_command(&request, now, None)
            .expect("accepted decision")
        else {
            panic!("selection outcome")
        };
        assert_eq!(response.request_id(), request.request_id());
        assert!(matches!(decision, ProviderDecision::Selected(id) if id.as_str() == "work"));
        assert!(session.disconnect().is_empty());
    }

    #[test]
    fn membership_and_disconnect_return_every_revoked_waiter_once() {
        let request = registration();
        let (mut session, _) = register(&request);
        let now = Instant::now();
        let first = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("first");
        let membership = ProviderRepositoryMembership::new(
            session.registration_id(),
            session.provider_generation(),
            generation(2),
            vec![digest(2)],
        )
        .expect("membership");
        let update = ProviderRequestFrame::control(ProviderRequest::UpdateRepositories(membership))
            .expect("update");
        let admission = ProviderMembershipAdmission::verify(peer(), &update, &[digest(2)])
            .expect("membership admission");
        let ProviderCommandOutcome::MembershipUpdated {
            response,
            revoked_prompt_ids,
        } = session
            .handle_command(&update, now, Some(&admission))
            .expect("membership accepted")
        else {
            panic!("membership outcome")
        };
        assert_eq!(response.request_id(), update.request_id());
        assert_eq!(revoked_prompt_ids, vec![first.frame.request_id()]);

        let second = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("second");
        assert_eq!(session.disconnect(), vec![second.frame.request_id()]);
        assert!(session.disconnect().is_empty());
        assert!(matches!(
            session.expire_prompts(now),
            Err(ProviderSessionError::Closed)
        ));
    }

    #[test]
    fn broker_can_replace_membership_without_provider_claims() {
        let request = registration();
        let (mut session, _) = register(&request);
        let now = Instant::now();
        let issued = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("initial authorized prompt");

        assert_eq!(
            session
                .replace_authorized_repositories(&[digest(9)], generation(2), now)
                .expect("broker-owned replacement"),
            vec![issued.frame.request_id()]
        );
        assert!(matches!(
            session.issue_prompt(prompt(&session, 30_000), now),
            Err(ProviderSessionError::Correlation(
                ProviderCorrelationError::RepositoryNotRegistered
            ))
        ));
        assert!(matches!(
            session.replace_authorized_repositories(&[digest(9)], generation(2), now),
            Err(ProviderSessionError::Correlation(
                ProviderCorrelationError::StaleMembership
            ))
        ));
    }

    #[test]
    fn timeout_and_invalid_unregister_do_not_lose_waiter_ids() {
        let request = registration();
        let (mut session, _) = register(&request);
        let now = Instant::now();
        let issued = session
            .issue_prompt(prompt(&session, 1_000), now)
            .expect("prompt");
        assert_eq!(
            session
                .expire_prompts(now + Duration::from_secs(1))
                .expect("expire"),
            vec![issued.frame.request_id()]
        );

        let issued = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("prompt");
        let invalid = ProviderRequestFrame::control(ProviderRequest::Unregister(
            ProviderControlRequest::new(session.registration_id(), generation(8)),
        ))
        .expect("unregister");
        let error = session
            .handle_command(&invalid, now, None)
            .expect_err("invalid unregister");
        let ProviderSessionError::Termination(error) = error.cause() else {
            panic!("termination error")
        };
        assert_eq!(error.outstanding_prompt_ids(), &[issued.frame.request_id()]);
        assert!(session.disconnect().is_empty());
    }

    #[test]
    fn late_selection_fails_closed_and_returns_the_consumed_waiter() {
        let request = registration();
        let (mut session, _) = register(&request);
        let now = Instant::now();
        let issued = session
            .issue_prompt(prompt(&session, 1_000), now)
            .expect("prompt");
        let decision = ProviderSelectionDecision::new(
            session.registration_id(),
            session.provider_generation(),
            generation(1),
            ProviderDecision::Cancelled,
        )
        .expect("decision");
        let frame = ProviderRequestFrame::selection_response(issued.frame.request_id(), decision)
            .expect("decision frame");
        let failure = session
            .handle_command(&frame, now + Duration::from_secs(1), None)
            .expect_err("late decision");
        assert!(matches!(
            failure.cause(),
            ProviderSessionError::Correlation(ProviderCorrelationError::PromptExpired)
        ));
        assert_eq!(failure.revoked_prompt_ids(), &[issued.frame.request_id()]);
        assert!(session.disconnect().is_empty());
    }

    #[test]
    fn membership_requires_matching_broker_admission() {
        let request = registration();
        let (mut session, _) = register(&request);
        let now = Instant::now();
        let issued = session
            .issue_prompt(prompt(&session, 30_000), now)
            .expect("prompt");
        let membership = ProviderRepositoryMembership::new(
            session.registration_id(),
            session.provider_generation(),
            generation(1),
            vec![digest(2)],
        )
        .expect("membership");
        let update = ProviderRequestFrame::control(ProviderRequest::UpdateRepositories(membership))
            .expect("update");
        let failure = session
            .handle_command(&update, now, None)
            .expect_err("missing admission");
        assert!(matches!(
            failure.cause(),
            ProviderSessionError::MembershipAdmissionRequired
        ));
        assert_eq!(failure.revoked_prompt_ids(), &[issued.frame.request_id()]);
        assert!(session.disconnect().is_empty());
    }

    #[test]
    fn admission_cannot_move_to_a_same_id_frame_with_different_metadata() {
        let request = registration();
        let admission = ProviderAdmission::verify(peer(), &request).expect("admission");
        let mut substituted = serde_json::to_value(&request).expect("serialize frame");
        substituted["message"]["body"]["editor_session_id"] =
            serde_json::Value::String("window-2".into());
        let payload = serde_json::to_vec(&substituted).expect("serialize substituted frame");
        let mut record = Vec::with_capacity(4 + payload.len());
        record.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("small frame")
                .to_be_bytes(),
        );
        record.extend_from_slice(&payload);
        let substituted =
            gus_ipc::decode_provider_request(&record).expect("valid substituted frame");
        assert_eq!(substituted.request_id(), request.request_id());
        assert!(matches!(
            ProviderSession::register(
                &substituted,
                admission,
                &[digest(2)],
                generation(1),
                generation(7),
                15_000,
                Instant::now()
            ),
            Err(ProviderSessionError::AdmissionMismatch)
        ));
    }

    #[test]
    fn status_and_control_require_negotiated_connection_binding() {
        let request = registration();
        let (mut session, _) = register(&request);
        let heartbeat = ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(session.registration_id(), session.provider_generation()),
        ))
        .expect("heartbeat");
        assert!(matches!(
            session.handle_command(&heartbeat, Instant::now(), None),
            Ok(ProviderCommandOutcome::Acknowledged { response })
                if response.request_id() == heartbeat.request_id()
        ));

        let snapshot = ProviderStatusSnapshot::new(
            session.registration_id(),
            session.provider_generation(),
            Vec::new(),
        )
        .expect("snapshot");
        assert!(matches!(
            session.issue_status(snapshot.clone(), Instant::now()),
            Err(ProviderSessionError::StatusNotSubscribed)
        ));
        let subscribe = ProviderRequestFrame::control(ProviderRequest::SubscribeStatus(
            ProviderControlRequest::new(session.registration_id(), session.provider_generation()),
        ))
        .expect("subscribe");
        session
            .handle_command(&subscribe, Instant::now(), None)
            .expect("subscription");
        assert!(session.issue_status(snapshot, Instant::now()).is_ok());

        let replay = session
            .handle_command(&heartbeat, Instant::now(), None)
            .expect_err("heartbeat replay");
        assert!(matches!(
            replay.cause(),
            ProviderSessionError::CommandReplay
        ));
        assert!(session.disconnect().is_empty());

        let (mut session, _) = register(&request);
        let replay_registration = registration();
        assert!(matches!(
            session.handle_command(&replay_registration, Instant::now(), None),
            Err(error) if matches!(
                error.cause(),
                ProviderSessionError::Correlation(
                    ProviderCorrelationError::UnexpectedMessageRole
                )
            )
        ));
    }

    #[test]
    fn heartbeat_deadline_is_broker_owned_renewable_and_terminal() {
        let request = registration();
        let now = Instant::now();
        let (mut session, _) = register_at(&request, now);
        let issued = session
            .issue_prompt(prompt(&session, 60_000), now)
            .expect("prompt");
        assert_eq!(
            session.expire_heartbeat(now + Duration::from_secs(29)),
            None
        );

        let heartbeat = ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(session.registration_id(), session.provider_generation()),
        ))
        .expect("heartbeat");
        session
            .handle_command(&heartbeat, now + Duration::from_secs(20), None)
            .expect("heartbeat accepted");
        assert_eq!(
            session.expire_heartbeat(now + Duration::from_secs(49)),
            None
        );
        assert_eq!(
            session.expire_heartbeat(now + Duration::from_secs(50)),
            Some(vec![issued.frame.request_id()])
        );
        assert_eq!(
            session.expire_heartbeat(now + Duration::from_secs(51)),
            None
        );
    }

    #[test]
    fn late_heartbeat_cannot_resurrect_an_expired_provider() {
        let request = registration();
        let now = Instant::now();
        let (mut session, _) = register_at(&request, now);
        let issued = session
            .issue_prompt(prompt(&session, 60_000), now)
            .expect("prompt");
        let heartbeat = ProviderRequestFrame::control(ProviderRequest::Heartbeat(
            ProviderControlRequest::new(session.registration_id(), session.provider_generation()),
        ))
        .expect("heartbeat");
        let failure = session
            .handle_command(&heartbeat, now + Duration::from_secs(30), None)
            .expect_err("deadline is terminal");
        assert!(matches!(
            failure.cause(),
            ProviderSessionError::HeartbeatExpired
        ));
        assert_eq!(failure.revoked_prompt_ids(), &[issued.frame.request_id()]);
        assert!(session.disconnect().is_empty());
    }
}
