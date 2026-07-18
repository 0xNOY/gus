use std::collections::BTreeMap;

use gus_profile::ProfileId;
use thiserror::Error;

use crate::{
    BrokerProviderMessage, Generation, ProviderDecision, ProviderRequest, ProviderRequestFrame,
    ProviderResponseFrame, RequestId,
};

const MAX_OUTSTANDING_PROMPTS: usize = 32;

/// Connection-local correlation state for one authenticated provider.
///
/// A new IPC connection receives a new instance. Consequently, decisions from
/// a disconnected provider cannot be accepted by a replacement connection even
/// when the old request bytes are replayed.
#[derive(Debug)]
pub struct ProviderCorrelation {
    registration_id: RequestId,
    provider_generation: Generation,
    outstanding_prompts: BTreeMap<RequestId, OutstandingPrompt>,
    membership_generation: Option<Generation>,
}

#[derive(Debug)]
struct OutstandingPrompt {
    selection_generation: Generation,
    offered_profiles: Vec<ProfileId>,
}

impl ProviderCorrelation {
    #[must_use]
    pub const fn new(registration_id: RequestId, provider_generation: Generation) -> Self {
        Self {
            registration_id,
            provider_generation,
            outstanding_prompts: BTreeMap::new(),
            membership_generation: None,
        }
    }

    /// Validates a provider-originated heartbeat, status subscription,
    /// repository replacement, or unregister command against this connection.
    ///
    /// # Errors
    ///
    /// Rejects registration, selection responses, and binding mismatches.
    pub fn validate_control(
        &self,
        frame: &ProviderRequestFrame,
    ) -> Result<(), ProviderCorrelationError> {
        let (registration_id, provider_generation) = match frame.message() {
            ProviderRequest::Heartbeat(request)
            | ProviderRequest::SubscribeStatus(request)
            | ProviderRequest::Unregister(request) => {
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
    /// Status notifications do not consume prompt capacity.
    ///
    /// # Errors
    ///
    /// Rejects binding mismatches, duplicate request IDs, non-prompt messages,
    /// or the bounded outstanding-prompt limit.
    pub fn track_prompt(
        &mut self,
        frame: &ProviderResponseFrame,
    ) -> Result<(), ProviderCorrelationError> {
        let BrokerProviderMessage::SelectionPrompt(prompt) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(prompt.registration_id(), prompt.provider_generation())?;
        if self.outstanding_prompts.contains_key(&frame.request_id()) {
            return Err(ProviderCorrelationError::DuplicatePrompt);
        }
        if self.outstanding_prompts.len() >= MAX_OUTSTANDING_PROMPTS {
            return Err(ProviderCorrelationError::PromptCapacity);
        }
        self.outstanding_prompts.insert(
            frame.request_id(),
            OutstandingPrompt {
                selection_generation: prompt.selection_generation(),
                offered_profiles: prompt
                    .profiles()
                    .iter()
                    .map(|profile| profile.profile_id().clone())
                    .collect(),
            },
        );
        Ok(())
    }

    /// Accepts a complete repository-membership replacement exactly once per
    /// monotonically increasing provider-local generation.
    ///
    /// # Errors
    ///
    /// Rejects stale/replayed updates and registration binding mismatches.
    pub fn accept_membership(
        &mut self,
        frame: &ProviderRequestFrame,
    ) -> Result<(), ProviderCorrelationError> {
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
        Ok(())
    }

    /// Validates a status notification against the current registration.
    ///
    /// # Errors
    ///
    /// Rejects non-status messages or a stale registration/generation.
    pub fn validate_status(
        &self,
        frame: &ProviderResponseFrame,
    ) -> Result<(), ProviderCorrelationError> {
        let BrokerProviderMessage::StatusSnapshot(snapshot) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(snapshot.registration_id(), snapshot.provider_generation())
    }

    /// Consumes exactly one outstanding prompt after validating the provider,
    /// prompt request ID, and selection generation.
    ///
    /// # Errors
    ///
    /// Rejects stale/replayed/cross-provider decisions without consuming a
    /// still-valid outstanding prompt on a mere generation mismatch.
    pub fn accept_selection<'a>(
        &mut self,
        frame: &'a ProviderRequestFrame,
    ) -> Result<&'a ProviderDecision, ProviderCorrelationError> {
        let ProviderRequest::SelectionDecision(response) = frame.message() else {
            return Err(ProviderCorrelationError::UnexpectedMessageRole);
        };
        self.validate_binding(response.registration_id(), response.provider_generation())?;
        let outstanding = self
            .outstanding_prompts
            .get(&frame.request_id())
            .ok_or(ProviderCorrelationError::UnknownPrompt)?;
        if outstanding.selection_generation != response.selection_generation() {
            return Err(ProviderCorrelationError::SelectionGenerationMismatch);
        }
        if let ProviderDecision::Selected(profile_id) = response.decision()
            && !outstanding.offered_profiles.contains(profile_id)
        {
            return Err(ProviderCorrelationError::ProfileNotOffered);
        }
        self.outstanding_prompts.remove(&frame.request_id());
        Ok(response.decision())
    }

    #[must_use]
    pub fn outstanding_prompt_count(&self) -> usize {
        self.outstanding_prompts.len()
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
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCorrelationError {
    #[error("message has the wrong provider request/response role")]
    UnexpectedMessageRole,
    #[error("provider registration does not belong to this connection")]
    RegistrationMismatch,
    #[error("provider generation is stale")]
    ProviderGenerationMismatch,
    #[error("selection prompt request id is already outstanding")]
    DuplicatePrompt,
    #[error("selection prompt capacity is exhausted")]
    PromptCapacity,
    #[error("selection decision has no outstanding prompt")]
    UnknownPrompt,
    #[error("selection decision generation does not match the prompt")]
    SelectionGenerationMismatch,
    #[error("selected profile was not offered by the outstanding prompt")]
    ProfileNotOffered,
    #[error("repository membership generation is stale or replayed")]
    StaleMembership,
}
