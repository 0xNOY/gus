use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, Instant},
};

use gus_profile::ProfileId;
use thiserror::Error;

use crate::{
    BrokerProviderMessage, Digest32, Generation, ProviderCapability, ProviderDecision,
    ProviderRegistrationRequest, ProviderRequest, ProviderRequestFrame, ProviderResponseFrame,
    RegistrationAccepted, RequestId,
};

const MAX_OUTSTANDING_PROMPTS: usize = 32;

/// Connection-local correlation state for one authenticated provider.
///
/// Construct this state from the registration request accepted on the current
/// IPC connection. Reconnect creates a new instance, so old prompt IDs,
/// capabilities, and repository membership cannot cross the connection
/// boundary.
pub struct ProviderCorrelation {
    registration_id: RequestId,
    provider_generation: Generation,
    capabilities: Vec<ProviderCapability>,
    repositories: BTreeSet<Digest32>,
    outstanding_prompts: BTreeMap<RequestId, OutstandingPrompt>,
    membership_generation: Option<Generation>,
}

struct OutstandingPrompt {
    selection_generation: Generation,
    membership_generation: Option<Generation>,
    repository: Digest32,
    deadline: Instant,
    offered_profiles: Vec<ProfileId>,
}

impl ProviderCorrelation {
    /// Creates state bound to one successfully accepted registration.
    #[must_use]
    pub fn from_registration(
        registration: &ProviderRegistrationRequest,
        accepted: &RegistrationAccepted,
    ) -> Self {
        Self {
            registration_id: accepted.registration_id(),
            provider_generation: accepted.provider_generation(),
            capabilities: registration.capabilities().to_vec(),
            repositories: registration.repositories().iter().copied().collect(),
            outstanding_prompts: BTreeMap::new(),
            membership_generation: None,
        }
    }

    /// Validates a provider-originated heartbeat, status subscription,
    /// or unregister command against this connection and its negotiated
    /// capabilities.
    ///
    /// # Errors
    ///
    /// Rejects registration, selection responses, repository updates, binding
    /// mismatches, and status subscriptions without the status capability.
    pub fn validate_control(
        &self,
        frame: &ProviderRequestFrame,
    ) -> Result<(), ProviderCorrelationError> {
        let (registration_id, provider_generation) = match frame.message() {
            ProviderRequest::Heartbeat(request) | ProviderRequest::Unregister(request) => {
                (request.registration_id(), request.provider_generation())
            }
            ProviderRequest::SubscribeStatus(request) => {
                self.require_capability(ProviderCapability::Status)?;
                (request.registration_id(), request.provider_generation())
            }
            ProviderRequest::Register(_)
            | ProviderRequest::UpdateRepositories(_)
            | ProviderRequest::SelectionDecision(_) => {
                return Err(ProviderCorrelationError::UnexpectedMessageRole);
            }
        };
        self.validate_binding(registration_id, provider_generation)
    }

    /// Tracks one broker-originated prompt before it is written to the provider.
    ///
    /// The caller supplies an [`Instant`] sampled from the broker's monotonic
    /// clock. IDs returned from this method expired before the new prompt was
    /// admitted and must be completed as selection timeouts by the caller.
    ///
    /// # Errors
    ///
    /// Rejects binding/capability/membership mismatches, duplicate request IDs,
    /// non-prompt messages, deadline overflow, or the bounded prompt limit.
    pub fn track_prompt(
        &mut self,
        frame: &ProviderResponseFrame,
        now: Instant,
    ) -> Result<Vec<RequestId>, ProviderCorrelationError> {
        self.require_capability(ProviderCapability::ProfileQuickPick)?;
        let BrokerProviderMessage::SelectionPrompt(prompt) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(prompt.registration_id(), prompt.provider_generation())?;
        if !self.repositories.contains(&prompt.repository().identity()) {
            return Err(ProviderCorrelationError::RepositoryNotRegistered);
        }

        let expired = self.expired_prompt_ids(now);
        if self.outstanding_prompts.contains_key(&frame.request_id()) {
            return Err(ProviderCorrelationError::DuplicatePrompt);
        }
        if self.outstanding_prompts.len() - expired.len() >= MAX_OUTSTANDING_PROMPTS {
            return Err(ProviderCorrelationError::PromptCapacity);
        }
        let deadline = now
            .checked_add(Duration::from_millis(u64::from(prompt.timeout_millis())))
            .ok_or(ProviderCorrelationError::DeadlineOverflow)?;
        for request_id in &expired {
            self.outstanding_prompts.remove(request_id);
        }
        self.outstanding_prompts.insert(
            frame.request_id(),
            OutstandingPrompt {
                selection_generation: prompt.selection_generation(),
                membership_generation: self.membership_generation,
                repository: prompt.repository().identity(),
                deadline,
                offered_profiles: prompt
                    .profiles()
                    .iter()
                    .map(|profile| profile.profile_id().clone())
                    .collect(),
            },
        );
        Ok(expired)
    }

    /// Accepts a complete repository-membership replacement exactly once per
    /// monotonically increasing provider-local generation.
    ///
    /// Every outstanding prompt is revoked because it was presented against
    /// the previous complete membership snapshot. Returned IDs must be failed
    /// by the broker rather than left waiting for a stale UI response.
    ///
    /// # Errors
    ///
    /// Rejects stale/replayed updates and registration binding mismatches.
    pub fn accept_membership(
        &mut self,
        frame: &ProviderRequestFrame,
    ) -> Result<Vec<RequestId>, ProviderCorrelationError> {
        let ProviderRequest::UpdateRepositories(request) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(request.registration_id(), request.provider_generation())?;
        if self
            .membership_generation
            .is_some_and(|generation| generation >= request.membership_generation())
        {
            return Err(ProviderCorrelationError::StaleMembership);
        }
        self.membership_generation = Some(request.membership_generation());
        self.repositories = request.repositories().iter().copied().collect();
        Ok(self.drain_prompts())
    }

    /// Validates a status notification against the current registration and
    /// the capabilities negotiated at registration time.
    ///
    /// # Errors
    ///
    /// Rejects non-status messages, a stale registration/generation, or a
    /// provider that did not negotiate status presentation.
    pub fn validate_status(
        &self,
        frame: &ProviderResponseFrame,
    ) -> Result<(), ProviderCorrelationError> {
        self.require_capability(ProviderCapability::Status)?;
        let BrokerProviderMessage::StatusSnapshot(snapshot) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(snapshot.registration_id(), snapshot.provider_generation())?;
        if snapshot
            .entries()
            .iter()
            .any(|entry| !self.repositories.contains(&entry.repository().identity()))
        {
            return Err(ProviderCorrelationError::RepositoryNotRegistered);
        }
        Ok(())
    }

    /// Consumes exactly one live prompt after validating the provider, prompt
    /// request ID, selection generation, membership snapshot, deadline, and
    /// offered profiles.
    ///
    /// # Errors
    ///
    /// Rejects stale/replayed/cross-provider decisions. An expired or
    /// membership-stale prompt is consumed so it cannot occupy capacity or be
    /// accepted by a later retry.
    pub fn accept_selection<'a>(
        &mut self,
        frame: &'a ProviderRequestFrame,
        now: Instant,
    ) -> Result<&'a ProviderDecision, ProviderCorrelationError> {
        let ProviderRequest::SelectionDecision(response) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(response.registration_id(), response.provider_generation())?;
        let outstanding = self
            .outstanding_prompts
            .get(&frame.request_id())
            .ok_or(ProviderCorrelationError::UnknownPrompt)?;
        if outstanding.deadline <= now {
            self.outstanding_prompts.remove(&frame.request_id());
            return Err(ProviderCorrelationError::PromptExpired);
        }
        if outstanding.membership_generation != self.membership_generation
            || !self.repositories.contains(&outstanding.repository)
        {
            self.outstanding_prompts.remove(&frame.request_id());
            return Err(ProviderCorrelationError::PromptMembershipStale);
        }
        if outstanding.selection_generation != response.selection_generation() {
            return Err(ProviderCorrelationError::SelectionGenerationMismatch);
        }
        if let ProviderDecision::Selected(profile_id) = response.decision() {
            if !outstanding.offered_profiles.contains(profile_id) {
                return Err(ProviderCorrelationError::ProfileNotOffered);
            }
        }
        self.outstanding_prompts.remove(&frame.request_id());
        Ok(response.decision())
    }

    /// Removes all prompts whose broker-owned monotonic deadline has elapsed.
    /// Returned IDs identify waiters that must receive a timeout result.
    pub fn expire_prompts(&mut self, now: Instant) -> Vec<RequestId> {
        let expired = self.expired_prompt_ids(now);
        for request_id in &expired {
            self.outstanding_prompts.remove(request_id);
        }
        expired
    }

    /// Abandons one prompt after a write failure or broker-side cancellation.
    #[must_use]
    pub fn abandon_prompt(&mut self, request_id: RequestId) -> bool {
        self.outstanding_prompts.remove(&request_id).is_some()
    }

    /// Consumes the connection state and returns every waiter that must be
    /// completed as provider-unavailable on disconnect.
    #[must_use]
    pub fn disconnect(mut self) -> Vec<RequestId> {
        self.drain_prompts()
    }

    #[must_use]
    pub fn outstanding_prompt_count(&self) -> usize {
        self.outstanding_prompts.len()
    }

    #[must_use]
    pub fn membership_generation(&self) -> Option<Generation> {
        self.membership_generation
    }

    pub fn repositories(&self) -> impl Iterator<Item = Digest32> + '_ {
        self.repositories.iter().copied()
    }

    fn require_capability(
        &self,
        capability: ProviderCapability,
    ) -> Result<(), ProviderCorrelationError> {
        if !self.capabilities.contains(&capability) {
            return Err(ProviderCorrelationError::CapabilityNotNegotiated);
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        registration_id: RequestId,
        provider_generation: Generation,
    ) -> Result<(), ProviderCorrelationError> {
        if registration_id != self.registration_id {
            return Err(ProviderCorrelationError::RegistrationMismatch);
        }
        if provider_generation != self.provider_generation {
            return Err(ProviderCorrelationError::ProviderGenerationMismatch);
        }
        Ok(())
    }

    fn drain_prompts(&mut self) -> Vec<RequestId> {
        let request_ids = self.outstanding_prompts.keys().copied().collect();
        self.outstanding_prompts.clear();
        request_ids
    }

    fn expired_prompt_ids(&self, now: Instant) -> Vec<RequestId> {
        self.outstanding_prompts
            .iter()
            .filter_map(|(request_id, prompt)| (prompt.deadline <= now).then_some(*request_id))
            .collect()
    }
}

impl fmt::Debug for ProviderCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCorrelation")
            .field("registration_id", &self.registration_id)
            .field("provider_generation", &self.provider_generation)
            .field("capabilities", &self.capabilities)
            .field("repository_count", &self.repositories.len())
            .field("outstanding_prompt_count", &self.outstanding_prompts.len())
            .field("membership_generation", &self.membership_generation)
            .finish()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCorrelationError {
    #[error("message has the wrong provider request/response role")]
    UnexpectedMessageRole,
    #[error("provider registration does not belong to this connection")]
    RegistrationMismatch,
    #[error("provider generation is stale")]
    ProviderGenerationMismatch,
    #[error("provider capability was not negotiated")]
    CapabilityNotNegotiated,
    #[error("selection prompt repository is not registered by this provider")]
    RepositoryNotRegistered,
    #[error("selection prompt request id is already outstanding")]
    DuplicatePrompt,
    #[error("selection prompt capacity is exhausted")]
    PromptCapacity,
    #[error("selection prompt deadline cannot be represented")]
    DeadlineOverflow,
    #[error("selection decision has no outstanding prompt")]
    UnknownPrompt,
    #[error("selection prompt has expired")]
    PromptExpired,
    #[error("selection prompt belongs to a stale repository membership snapshot")]
    PromptMembershipStale,
    #[error("selection decision generation does not match the prompt")]
    SelectionGenerationMismatch,
    #[error("selected profile was not offered by the outstanding prompt")]
    ProfileNotOffered,
    #[error("repository membership generation is stale or replayed")]
    StaleMembership,
}
