//! Capability and session invariants for the GUS broker.
//!
//! This crate deliberately contains no IPC or OS process inspection. Platform
//! adapters must derive the identities passed here from authenticated peer and
//! process handles. The state machines then prevent adapters from accidentally
//! treating a multi-process HTTP credential flow as a single-use capability.

use gus_profile::{CanonicalCredentialRequest, ProfileId};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pid: u32,
    start_time: u64,
    executable_identity: [u8; 32],
}

impl ProcessIdentity {
    /// Creates an identity from OS-authenticated process observations.
    ///
    /// # Errors
    ///
    /// Rejects sentinel values which cannot identify a live process.
    pub fn new(
        pid: u32,
        start_time: u64,
        executable_identity: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if pid == 0 || start_time == 0 || executable_identity == [0; 32] {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            pid,
            start_time,
            executable_identity,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileBinding {
    profile_id: ProfileId,
    generation: u64,
}

impl ProfileBinding {
    /// Binds a profile snapshot to its non-zero store generation.
    ///
    /// # Errors
    ///
    /// Rejects generation zero, which denotes an unresolved snapshot.
    pub fn new(profile_id: ProfileId, generation: u64) -> Result<Self, CapabilityError> {
        if generation == 0 {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            profile_id,
            generation,
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleUseRole {
    SshTransport,
    Signing,
    NestedGit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStatus {
    Active,
    Completed,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialAttemptId([u8; 32]);

impl CredentialAttemptId {
    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommonClaims {
    handle: [u8; 32],
    issuer_instance: [u8; 32],
    plan_digest: [u8; 32],
    parent: ProcessIdentity,
    helper_identity: [u8; 32],
    expires_at: u64,
}

impl CommonClaims {
    fn new(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        if handle == [0; 32]
            || issuer_instance == [0; 32]
            || plan_digest == [0; 32]
            || helper_identity == [0; 32]
            || issued_at >= expires_at
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            expires_at,
        })
    }

    fn validate_call(
        &self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        now: u64,
    ) -> Result<(), CapabilityError> {
        if now >= self.expires_at {
            return Err(CapabilityError::Expired);
        }
        if parent != self.parent {
            return Err(CapabilityError::ParentMismatch);
        }
        if plan_digest != self.plan_digest {
            return Err(CapabilityError::PlanMismatch);
        }
        if helper_identity != self.helper_identity {
            return Err(CapabilityError::HelperMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleUseCapability {
    claims: CommonClaims,
    role: SingleUseRole,
    status: CapabilityStatus,
}

impl SingleUseCapability {
    /// Issues a role-specific capability which can be claimed once.
    ///
    /// # Errors
    ///
    /// Rejects missing digests and non-positive validity windows.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        role: SingleUseRole,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        Ok(Self {
            claims: CommonClaims::new(
                handle,
                issuer_instance,
                plan_digest,
                parent,
                helper_identity,
                issued_at,
                expires_at,
            )?,
            role,
            status: CapabilityStatus::Active,
        })
    }

    /// Claims the capability after revalidating the child role and binding.
    ///
    /// # Errors
    ///
    /// Rejects replay, expiry, role confusion, or any binding mismatch.
    pub fn claim(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        role: SingleUseRole,
        now: u64,
    ) -> Result<(), CapabilityError> {
        self.require_active()?;
        if let Err(error) = self
            .claims
            .validate_call(parent, plan_digest, helper_identity, now)
        {
            if error == CapabilityError::Expired {
                self.status = CapabilityStatus::Revoked;
            }
            return Err(error);
        }
        if role != self.role {
            return Err(CapabilityError::RoleMismatch);
        }
        self.status = CapabilityStatus::Completed;
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = CapabilityStatus::Revoked;
    }

    #[must_use]
    pub const fn status(&self) -> CapabilityStatus {
        self.status
    }

    fn require_active(&self) -> Result<(), CapabilityError> {
        match self.status {
            CapabilityStatus::Active => Ok(()),
            CapabilityStatus::Completed => Err(CapabilityError::AlreadyUsed),
            CapabilityStatus::Revoked => Err(CapabilityError::Revoked),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialProtocolRuleset {
    /// Verified Git 2.39--2.45: unknown fields are discarded, so one
    /// outstanding attempt per parent/endpoint is enforced and correlation
    /// remains broker-side.
    LegacySerial,
    /// Verified Git 2.46+ protocol with `capability[]=state` negotiation.
    Stateful,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointStatus {
    Ready,
    Stored,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointState {
    endpoint: CanonicalCredentialRequest,
    attempts: u16,
    latest: Option<CredentialAttemptId>,
    status: EndpointStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HttpProfileState {
    Deferred,
    Bound(ProfileBinding),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCredentialCapability {
    claims: CommonClaims,
    ruleset: CredentialProtocolRuleset,
    profile: HttpProfileState,
    max_get_attempts: u16,
    endpoints: Vec<EndpointState>,
    status: CapabilityStatus,
}

impl HttpCredentialCapability {
    /// Issues a deferred HTTP capability for a fixed non-empty endpoint set.
    ///
    /// # Errors
    ///
    /// Rejects duplicate endpoints, invalid common claims, or a zero attempt
    /// limit. Endpoint canonicalization must have succeeded before this call.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_deferred(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        ruleset: CredentialProtocolRuleset,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        Self::issue(
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            ruleset,
            HttpProfileState::Deferred,
            endpoints,
            max_get_attempts,
            issued_at,
            expires_at,
        )
    }

    /// Issues an HTTP capability already bound by a preflight selection.
    ///
    /// # Errors
    ///
    /// Uses the same validation as [`Self::issue_deferred`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue_bound(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        ruleset: CredentialProtocolRuleset,
        profile: ProfileBinding,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        Self::issue(
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            ruleset,
            HttpProfileState::Bound(profile),
            endpoints,
            max_get_attempts,
            issued_at,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        ruleset: CredentialProtocolRuleset,
        profile: HttpProfileState,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CapabilityError> {
        if endpoints.is_empty()
            || max_get_attempts == 0
            || endpoints
                .iter()
                .enumerate()
                .any(|(index, endpoint)| endpoints[..index].contains(endpoint))
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            claims: CommonClaims::new(
                handle,
                issuer_instance,
                plan_digest,
                parent,
                helper_identity,
                issued_at,
                expires_at,
            )?,
            ruleset,
            profile,
            max_get_attempts,
            endpoints: endpoints
                .into_iter()
                .map(|endpoint| EndpointState {
                    endpoint,
                    attempts: 0,
                    latest: None,
                    status: EndpointStatus::Ready,
                })
                .collect(),
            status: CapabilityStatus::Active,
        })
    }

    /// Starts a credential attempt and binds a deferred capability exactly
    /// once. In the Git 2.39 ruleset, a second outstanding get is rejected.
    ///
    /// # Errors
    ///
    /// Rejects stale bindings, endpoint confusion, retry exhaustion, or an
    /// ambiguous legacy retry.
    #[allow(clippy::too_many_arguments)]
    pub fn get(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: ProfileBinding,
        now: u64,
    ) -> Result<CredentialAttemptId, CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        self.bind_or_validate_profile(profile)?;
        let state = &mut self.endpoints[endpoint_index];
        if state.status != EndpointStatus::Ready {
            return Err(CapabilityError::InvalidTransition);
        }
        if self.ruleset == CredentialProtocolRuleset::LegacySerial && state.latest.is_some() {
            return Err(CapabilityError::AmbiguousLegacyAttempt);
        }
        if state.attempts >= self.max_get_attempts {
            state.status = EndpointStatus::Exhausted;
            self.complete_if_terminal();
            return Err(CapabilityError::RetryLimit);
        }
        state.attempts += 1;
        let attempt = derive_attempt(self.claims.handle, endpoint_index, state.attempts);
        state.latest = Some(attempt);
        Ok(attempt)
    }

    /// Marks the latest attempt accepted and terminal for its endpoint.
    ///
    /// # Errors
    ///
    /// Rejects a superseded/missing attempt or any binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn store(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        attempt: CredentialAttemptId,
        now: u64,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        if self.ruleset != CredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_profile(profile)?;
        let state = self.endpoint_mut(endpoint)?;
        if state.status != EndpointStatus::Ready || state.latest != Some(attempt) {
            return Err(CapabilityError::AttemptMismatch);
        }
        state.latest = None;
        state.status = EndpointStatus::Stored;
        self.complete_if_terminal();
        Ok(())
    }

    /// Erases/rejects the latest attempt. A bounded retry remains possible
    /// until the endpoint's attempt limit is reached.
    ///
    /// # Errors
    ///
    /// Rejects a superseded/missing attempt or any binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn erase(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        attempt: CredentialAttemptId,
        now: u64,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        if self.ruleset != CredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_profile(profile)?;
        let max_get_attempts = self.max_get_attempts;
        let state = self.endpoint_mut(endpoint)?;
        if state.status != EndpointStatus::Ready || state.latest != Some(attempt) {
            return Err(CapabilityError::AttemptMismatch);
        }
        state.latest = None;
        if state.attempts >= max_get_attempts {
            state.status = EndpointStatus::Exhausted;
        }
        self.complete_if_terminal();
        Ok(())
    }

    /// Stores the sole outstanding attempt for a legacy Git credential flow.
    /// The attempt never crosses the helper protocol boundary.
    ///
    /// # Errors
    ///
    /// Rejects stateful rulesets, missing/ambiguous outstanding attempts, and
    /// every normal capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn store_legacy(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        now: u64,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        self.require_legacy()?;
        self.validate_profile(profile)?;
        let state = self.endpoint_mut(endpoint)?;
        if state.status != EndpointStatus::Ready || state.latest.is_none() {
            return Err(CapabilityError::AttemptMismatch);
        }
        state.latest = None;
        state.status = EndpointStatus::Stored;
        self.complete_if_terminal();
        Ok(())
    }

    /// Erases the sole outstanding legacy attempt and reopens the endpoint if
    /// its bounded retry budget remains.
    ///
    /// # Errors
    ///
    /// Rejects stateful rulesets, missing/ambiguous outstanding attempts, and
    /// every normal capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn erase_legacy(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        now: u64,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        self.require_legacy()?;
        self.validate_profile(profile)?;
        let max_get_attempts = self.max_get_attempts;
        let state = self.endpoint_mut(endpoint)?;
        if state.status != EndpointStatus::Ready || state.latest.is_none() {
            return Err(CapabilityError::AttemptMismatch);
        }
        state.latest = None;
        if state.attempts >= max_get_attempts {
            state.status = EndpointStatus::Exhausted;
        }
        self.complete_if_terminal();
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = CapabilityStatus::Revoked;
    }

    #[must_use]
    pub const fn status(&self) -> CapabilityStatus {
        self.status
    }

    #[must_use]
    pub fn profile(&self) -> Option<&ProfileBinding> {
        match &self.profile {
            HttpProfileState::Deferred => None,
            HttpProfileState::Bound(profile) => Some(profile),
        }
    }

    fn validate_call(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        now: u64,
    ) -> Result<(), CapabilityError> {
        match self.status {
            CapabilityStatus::Active => {}
            CapabilityStatus::Completed => return Err(CapabilityError::AlreadyUsed),
            CapabilityStatus::Revoked => return Err(CapabilityError::Revoked),
        }
        if let Err(error) = self
            .claims
            .validate_call(parent, plan_digest, helper_identity, now)
        {
            if error == CapabilityError::Expired {
                self.status = CapabilityStatus::Revoked;
            }
            return Err(error);
        }
        Ok(())
    }

    fn bind_or_validate_profile(
        &mut self,
        requested: ProfileBinding,
    ) -> Result<(), CapabilityError> {
        match &self.profile {
            HttpProfileState::Deferred => {
                self.profile = HttpProfileState::Bound(requested);
                Ok(())
            }
            HttpProfileState::Bound(bound) if *bound == requested => Ok(()),
            HttpProfileState::Bound(_) => Err(CapabilityError::ProfileMismatch),
        }
    }

    fn validate_profile(&self, requested: &ProfileBinding) -> Result<(), CapabilityError> {
        match &self.profile {
            HttpProfileState::Bound(bound) if bound == requested => Ok(()),
            _ => Err(CapabilityError::ProfileMismatch),
        }
    }

    fn endpoint_index(
        &self,
        endpoint: &CanonicalCredentialRequest,
    ) -> Result<usize, CapabilityError> {
        self.endpoints
            .iter()
            .position(|state| state.endpoint == *endpoint)
            .ok_or(CapabilityError::EndpointMismatch)
    }

    fn require_legacy(&self) -> Result<(), CapabilityError> {
        if self.ruleset == CredentialProtocolRuleset::LegacySerial {
            Ok(())
        } else {
            Err(CapabilityError::StateTokenRequired)
        }
    }

    fn endpoint_mut(
        &mut self,
        endpoint: &CanonicalCredentialRequest,
    ) -> Result<&mut EndpointState, CapabilityError> {
        let index = self.endpoint_index(endpoint)?;
        Ok(&mut self.endpoints[index])
    }

    fn complete_if_terminal(&mut self) {
        if self
            .endpoints
            .iter()
            .all(|state| state.status != EndpointStatus::Ready)
        {
            self.status = CapabilityStatus::Completed;
        }
    }
}

fn derive_attempt(handle: [u8; 32], endpoint_index: usize, attempt: u16) -> CredentialAttemptId {
    let mut digest = Sha256::new();
    digest.update(b"gus.http-credential-attempt.v1\0");
    digest.update(handle);
    digest.update((endpoint_index as u64).to_le_bytes());
    digest.update(attempt.to_le_bytes());
    CredentialAttemptId(digest.finalize().into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("capability claim is incomplete or invalid")]
    InvalidClaim,
    #[error("capability has expired")]
    Expired,
    #[error("capability was revoked")]
    Revoked,
    #[error("single-use capability was already consumed")]
    AlreadyUsed,
    #[error("capability parent process does not match")]
    ParentMismatch,
    #[error("capability execution plan does not match")]
    PlanMismatch,
    #[error("capability helper executable does not match")]
    HelperMismatch,
    #[error("capability child role does not match")]
    RoleMismatch,
    #[error("credential endpoint does not match")]
    EndpointMismatch,
    #[error("credential profile snapshot does not match")]
    ProfileMismatch,
    #[error("credential retry limit reached")]
    RetryLimit,
    #[error("credential attempt is missing, stale, or superseded")]
    AttemptMismatch,
    #[error("legacy Git credential flow has an ambiguous outstanding attempt")]
    AmbiguousLegacyAttempt,
    #[error("legacy Git does not round-trip credential state tokens")]
    StateTokenUnsupported,
    #[error("stateful Git requires an authenticated credential state token")]
    StateTokenRequired,
    #[error("capability transition is not valid in the current state")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gus_profile::CredentialProtocol;

    fn process(pid: u32) -> ProcessIdentity {
        ProcessIdentity::new(pid, 100, Sha256::digest(pid.to_le_bytes()).into())
            .expect("valid process")
    }

    fn profile(name: &str, generation: u64) -> ProfileBinding {
        ProfileBinding::new(
            ProfileId::try_from(name.to_owned()).expect("valid profile"),
            generation,
        )
        .expect("valid profile binding")
    }

    fn endpoint(host: &str, path: &str) -> CanonicalCredentialRequest {
        CanonicalCredentialRequest::from_endpoint(
            CredentialProtocol::Https,
            host.to_owned(),
            None,
            path.to_owned(),
            Some("git-user".to_owned()),
        )
        .expect("valid endpoint")
    }

    fn http(
        ruleset: CredentialProtocolRuleset,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
    ) -> HttpCredentialCapability {
        HttpCredentialCapability::issue_deferred(
            [1; 32],
            [2; 32],
            [3; 32],
            process(10),
            [4; 32],
            ruleset,
            endpoints,
            max_get_attempts,
            10,
            100,
        )
        .expect("valid HTTP capability")
    }

    #[test]
    fn single_use_capability_rejects_role_confusion_and_replay() {
        let mut capability = SingleUseCapability::issue(
            [1; 32],
            [2; 32],
            [3; 32],
            process(10),
            [4; 32],
            SingleUseRole::Signing,
            10,
            100,
        )
        .expect("valid capability");
        assert_eq!(
            capability.claim(
                process(10),
                [3; 32],
                [4; 32],
                SingleUseRole::SshTransport,
                20,
            ),
            Err(CapabilityError::RoleMismatch)
        );
        capability
            .claim(process(10), [3; 32], [4; 32], SingleUseRole::Signing, 20)
            .expect("first matching claim succeeds");
        assert_eq!(
            capability.claim(process(10), [3; 32], [4; 32], SingleUseRole::Signing, 21,),
            Err(CapabilityError::AlreadyUsed)
        );
    }

    #[test]
    fn stateful_http_retry_supersedes_old_attempt_and_stores_latest() {
        let endpoint = endpoint("example.test", "/team/repository.git");
        let selected = profile("work", 7);
        let mut capability = http(
            CredentialProtocolRuleset::Stateful,
            vec![endpoint.clone()],
            3,
        );
        let first = capability
            .get(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                selected.clone(),
                20,
            )
            .expect("first get");
        let second = capability
            .get(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                selected.clone(),
                21,
            )
            .expect("stateful retry");
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                &selected,
                first,
                22,
            ),
            Err(CapabilityError::AttemptMismatch)
        );
        assert_eq!(
            capability.store_legacy(process(10), [3; 32], [4; 32], &endpoint, &selected, 22,),
            Err(CapabilityError::StateTokenRequired)
        );
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                &selected,
                second,
                22,
            )
            .expect("latest store");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
    }

    #[test]
    fn git_239_serializes_get_and_reopens_only_after_erase() {
        let endpoint = endpoint("legacy.example.test", "/repository.git");
        let selected = profile("legacy", 4);
        let mut capability = http(
            CredentialProtocolRuleset::LegacySerial,
            vec![endpoint.clone()],
            2,
        );
        let first = capability
            .get(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                selected.clone(),
                20,
            )
            .expect("first get");
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                &selected,
                first,
                20,
            ),
            Err(CapabilityError::StateTokenUnsupported)
        );
        assert_eq!(
            capability.get(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                selected.clone(),
                21,
            ),
            Err(CapabilityError::AmbiguousLegacyAttempt)
        );
        capability
            .erase_legacy(process(10), [3; 32], [4; 32], &endpoint, &selected, 22)
            .expect("erase reopens endpoint");
        capability
            .get(
                process(10),
                [3; 32],
                [4; 32],
                &endpoint,
                selected.clone(),
                23,
            )
            .expect("bounded retry");
        capability
            .erase_legacy(process(10), [3; 32], [4; 32], &endpoint, &selected, 24)
            .expect("final erase");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
    }

    #[test]
    fn every_helper_call_revalidates_parent_plan_helper_endpoint_and_profile() {
        let expected_endpoint = endpoint("example.test", "/one.git");
        let other = endpoint("other.example.test", "/two.git");
        let selected = profile("work", 7);
        let mut capability = http(
            CredentialProtocolRuleset::Stateful,
            vec![expected_endpoint.clone()],
            2,
        );
        for (parent, plan, helper, requested_endpoint, requested_profile, expected) in [
            (
                process(11),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                selected.clone(),
                CapabilityError::ParentMismatch,
            ),
            (
                process(10),
                [9; 32],
                [4; 32],
                &expected_endpoint,
                selected.clone(),
                CapabilityError::PlanMismatch,
            ),
            (
                process(10),
                [3; 32],
                [9; 32],
                &expected_endpoint,
                selected.clone(),
                CapabilityError::HelperMismatch,
            ),
            (
                process(10),
                [3; 32],
                [4; 32],
                &other,
                selected.clone(),
                CapabilityError::EndpointMismatch,
            ),
        ] {
            assert_eq!(
                capability.get(
                    parent,
                    plan,
                    helper,
                    requested_endpoint,
                    requested_profile,
                    20,
                ),
                Err(expected)
            );
        }
        capability
            .get(
                process(10),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                selected,
                20,
            )
            .expect("valid get binds profile");
        assert_eq!(
            capability.get(
                process(10),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                profile("personal", 8),
                21,
            ),
            Err(CapabilityError::ProfileMismatch)
        );
    }

    #[test]
    fn multiple_endpoints_complete_independently_and_ttl_revokes_access() {
        let one = endpoint("one.example.test", "/one.git");
        let two = endpoint("two.example.test", "/two.git");
        let selected = profile("work", 7);
        let mut capability = http(
            CredentialProtocolRuleset::Stateful,
            vec![one.clone(), two.clone()],
            2,
        );
        let attempt_one = capability
            .get(process(10), [3; 32], [4; 32], &one, selected.clone(), 20)
            .expect("first endpoint");
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &one,
                &selected,
                attempt_one,
                21,
            )
            .expect("store first endpoint");
        assert_eq!(capability.status(), CapabilityStatus::Active);
        assert_eq!(
            capability.get(process(10), [3; 32], [4; 32], &two, selected, 100,),
            Err(CapabilityError::Expired)
        );
        assert_eq!(capability.status(), CapabilityStatus::Revoked);
    }
}
