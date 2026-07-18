//! Capability and session invariants for the GUS broker.
//!
//! This crate deliberately contains no IPC or OS process inspection. Platform
//! adapters must derive the identities passed here from authenticated peer and
//! process handles. The state machines then prevent adapters from accidentally
//! treating a multi-process HTTP credential flow as a single-use capability.

use std::fmt;

use gus_core::{GitCredentialProtocolRuleset, VerifiedGitSemantics};
use gus_profile::{
    CanonicalCredentialRequest, CredentialHost, CredentialPathPrefix, CredentialProtocol,
    ProfileId, SigningFormat,
};
use hmac::{Hmac, Mac};
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

/// Milliseconds from an OS monotonic clock. Wall-clock timestamps must never
/// be converted into this type by a platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    #[must_use]
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }
}

pub const MAX_CAPABILITY_TTL_MILLIS: u64 = 5 * 60 * 1_000;

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
pub enum SshService {
    UploadPack,
    ReceivePack,
    UploadArchive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTransportSubject {
    profile: ProfileBinding,
    host: CredentialHost,
    username: String,
    port: u16,
    service: SshService,
    repository_path_digest: [u8; 32],
    argv_digest: [u8; 32],
}

impl SshTransportSubject {
    /// Creates the exact SSH request authorized for one helper child.
    ///
    /// # Errors
    ///
    /// Rejects empty/control usernames, port zero, or missing request digests.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: ProfileBinding,
        host: CredentialHost,
        username: String,
        port: u16,
        service: SshService,
        repository_path_digest: [u8; 32],
        argv_digest: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if username.is_empty()
            || username.len() > 255
            || username.chars().any(char::is_control)
            || port == 0
            || repository_path_digest == [0; 32]
            || argv_digest == [0; 32]
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            profile,
            host,
            username,
            port,
            service,
            repository_path_digest,
            argv_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningSubject {
    profile: ProfileBinding,
    format: SigningFormat,
    signing_key_identity: [u8; 32],
    signer_identity: [u8; 32],
    payload_digest: [u8; 32],
}

impl SigningSubject {
    /// Creates the exact signing request authorized for one adapter child.
    ///
    /// # Errors
    ///
    /// Rejects missing key, signer, or payload identities.
    pub fn new(
        profile: ProfileBinding,
        format: SigningFormat,
        signing_key_identity: [u8; 32],
        signer_identity: [u8; 32],
        payload_digest: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if signing_key_identity == [0; 32]
            || signer_identity == [0; 32]
            || payload_digest == [0; 32]
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            profile,
            format,
            signing_key_identity,
            signer_identity,
            payload_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedGitSubject {
    profile: ProfileBinding,
    repository_identity: [u8; 32],
    invocation_digest: [u8; 32],
}

impl NestedGitSubject {
    /// Creates the exact repository/invocation authorized for nested Git.
    ///
    /// # Errors
    ///
    /// Rejects missing repository or invocation identities.
    pub fn new(
        profile: ProfileBinding,
        repository_identity: [u8; 32],
        invocation_digest: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if repository_identity == [0; 32] || invocation_digest == [0; 32] {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            profile,
            repository_identity,
            invocation_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingleUseSubject {
    Ssh(SshTransportSubject),
    Signing(SigningSubject),
    NestedGit(NestedGitSubject),
}

impl SingleUseSubject {
    const fn role(&self) -> SingleUseRole {
        match self {
            Self::Ssh(_) => SingleUseRole::SshTransport,
            Self::Signing(_) => SingleUseRole::Signing,
            Self::NestedGit(_) => SingleUseRole::NestedGit,
        }
    }
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

#[derive(Debug, PartialEq, Eq)]
struct CommonClaims {
    handle: [u8; 32],
    issuer_instance: [u8; 32],
    plan_digest: [u8; 32],
    parent: ProcessIdentity,
    helper_identity: [u8; 32],
    not_before: MonotonicInstant,
    expires_at: MonotonicInstant,
}

impl CommonClaims {
    fn new(
        handle: [u8; 32],
        issuer_instance: [u8; 32],
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
    ) -> Result<Self, CapabilityError> {
        if handle == [0; 32]
            || issuer_instance == [0; 32]
            || plan_digest == [0; 32]
            || helper_identity == [0; 32]
            || issued_at >= expires_at
            || expires_at.0 - issued_at.0 > MAX_CAPABILITY_TTL_MILLIS
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            not_before: issued_at,
            expires_at,
        })
    }

    fn validate_call(
        &self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        if now < self.not_before {
            return Err(CapabilityError::NotYetValid);
        }
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

#[derive(Debug, PartialEq, Eq)]
pub struct SingleUseCapability {
    claims: CommonClaims,
    subject: SingleUseSubject,
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
        subject: SingleUseSubject,
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
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
            subject,
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
        subject: &SingleUseSubject,
        now: MonotonicInstant,
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
        if subject != &self.subject {
            return Err(if subject.role() == self.subject.role() {
                CapabilityError::SubjectMismatch
            } else {
                CapabilityError::RoleMismatch
            });
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
enum EndpointStatus {
    Ready,
    Stored,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialRoute {
    protocol: CredentialProtocol,
    host: CredentialHost,
    port: u16,
    path: CredentialPathPrefix,
}

impl From<&CanonicalCredentialRequest> for CredentialRoute {
    fn from(request: &CanonicalCredentialRequest) -> Self {
        Self {
            protocol: request.protocol(),
            host: request.host().clone(),
            port: request.port(),
            path: request.path().clone(),
        }
    }
}

/// Transient credential material observed by the owner-only broker. Debug and
/// serialization are intentionally not implemented, and only an HMAC is
/// retained in capability state.
pub struct CredentialMaterial<'a> {
    username: &'a str,
    secret: &'a [u8],
    backend_record_identity: [u8; 32],
    backend_record_version: [u8; 32],
}

impl<'a> CredentialMaterial<'a> {
    /// Creates material after a profile-scoped backend returns a credential.
    ///
    /// # Errors
    ///
    /// Rejects empty/control usernames or secrets and missing backend proof.
    pub fn new(
        username: &'a str,
        secret: &'a [u8],
        backend_record_identity: [u8; 32],
        backend_record_version: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if username.is_empty()
            || username.len() > 255
            || username.chars().any(char::is_control)
            || secret.is_empty()
            || backend_record_identity == [0; 32]
            || backend_record_version == [0; 32]
        {
            return Err(CapabilityError::InvalidCredentialMaterial);
        }
        Ok(Self {
            username,
            secret,
            backend_record_identity,
            backend_record_version,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssuedCredentialProof {
    attempt: CredentialAttemptId,
    username: String,
    backend_record_identity: [u8; 32],
    backend_record_version: [u8; 32],
    material_mac: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttemptState {
    Pending(CredentialAttemptId),
    Issued(IssuedCredentialProof),
}

#[derive(Debug, PartialEq, Eq)]
struct EndpointState {
    route: CredentialRoute,
    configured_username: Option<String>,
    attempts: u16,
    latest: Option<AttemptState>,
    status: EndpointStatus,
}

#[derive(Debug, PartialEq, Eq)]
enum HttpProfileState {
    Deferred,
    Bound(ProfileBinding),
}

#[derive(PartialEq, Eq)]
pub struct HttpCredentialCapability {
    claims: CommonClaims,
    ruleset: GitCredentialProtocolRuleset,
    correlation_key: [u8; 32],
    profile: HttpProfileState,
    max_get_attempts: u16,
    endpoints: Vec<EndpointState>,
    status: CapabilityStatus,
}

impl fmt::Debug for HttpCredentialCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpCredentialCapability")
            .field("claims", &self.claims)
            .field("ruleset", &self.ruleset)
            .field("correlation_key", &"<redacted>")
            .field("profile", &self.profile)
            .field("max_get_attempts", &self.max_get_attempts)
            .field("endpoints", &self.endpoints)
            .field("status", &self.status)
            .finish()
    }
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
        correlation_key: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
    ) -> Result<Self, CapabilityError> {
        Self::issue(
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            correlation_key,
            git_semantics,
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
        correlation_key: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        profile: ProfileBinding,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
    ) -> Result<Self, CapabilityError> {
        Self::issue(
            handle,
            issuer_instance,
            plan_digest,
            parent,
            helper_identity,
            correlation_key,
            git_semantics,
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
        correlation_key: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        profile: HttpProfileState,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
    ) -> Result<Self, CapabilityError> {
        let ruleset = git_semantics.credential_ruleset();
        if endpoints.is_empty()
            || max_get_attempts == 0
            || correlation_key == [0; 32]
            || ruleset == GitCredentialProtocolRuleset::Unsupported
            || endpoints.iter().enumerate().any(|(index, endpoint)| {
                endpoints[..index]
                    .iter()
                    .any(|prior| CredentialRoute::from(prior) == CredentialRoute::from(endpoint))
            })
        {
            return Err(if ruleset == GitCredentialProtocolRuleset::Unsupported {
                CapabilityError::UnsupportedGitCredentialProtocol
            } else {
                CapabilityError::InvalidClaim
            });
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
            correlation_key,
            profile,
            max_get_attempts,
            endpoints: endpoints
                .into_iter()
                .map(|endpoint| EndpointState {
                    route: CredentialRoute::from(&endpoint),
                    configured_username: endpoint.username().map(str::to_owned),
                    attempts: 0,
                    latest: None,
                    status: EndpointStatus::Ready,
                })
                .collect(),
            status: CapabilityStatus::Active,
        })
    }

    /// Starts a stateful Git 2.46+ credential attempt and returns the opaque
    /// token which must round-trip through `state[]`.
    ///
    /// # Errors
    ///
    /// Rejects stale bindings, endpoint confusion, retry exhaustion, or an
    /// ambiguous legacy retry.
    #[allow(clippy::too_many_arguments)]
    pub fn get_stateful(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: ProfileBinding,
        now: MonotonicInstant,
    ) -> Result<CredentialAttemptId, CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.begin_get(parent, plan_digest, helper_identity, endpoint, profile, now)
    }

    /// Starts a Legacy Git 2.39--2.45 attempt without returning a token. The
    /// derived attempt remains exclusively in the broker record.
    ///
    /// # Errors
    ///
    /// Rejects stateful Git, ambiguous outstanding attempts, or any binding
    /// mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn get_legacy(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: ProfileBinding,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::LegacySerial {
            return Err(CapabilityError::StateTokenRequired);
        }
        self.begin_get(parent, plan_digest, helper_identity, endpoint, profile, now)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_get(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: ProfileBinding,
        now: MonotonicInstant,
    ) -> Result<CredentialAttemptId, CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        self.bind_or_validate_profile(profile)?;
        let state = &mut self.endpoints[endpoint_index];
        if state.status != EndpointStatus::Ready {
            return Err(CapabilityError::InvalidTransition);
        }
        Self::validate_request_username(state, endpoint)?;
        if self.ruleset == GitCredentialProtocolRuleset::LegacySerial && state.latest.is_some() {
            return Err(CapabilityError::AmbiguousLegacyAttempt);
        }
        if matches!(state.latest, Some(AttemptState::Pending(_))) {
            return Err(CapabilityError::CredentialNotRegistered);
        }
        if state.attempts >= self.max_get_attempts {
            state.status = EndpointStatus::Exhausted;
            self.complete_if_terminal();
            return Err(CapabilityError::RetryLimit);
        }
        state.attempts += 1;
        let attempt = derive_attempt(self.claims.handle, endpoint_index, state.attempts);
        state.latest = Some(AttemptState::Pending(attempt));
        Ok(attempt)
    }

    /// Registers the credential returned for a stateful attempt. Only its
    /// username, backend identities, and HMAC are retained.
    ///
    /// # Errors
    ///
    /// Rejects a missing/superseded token, wrong username/backend, or any
    /// capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn register_stateful_credential(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        attempt: CredentialAttemptId,
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.register_credential(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            profile,
            Some(attempt),
            material,
            now,
        )
    }

    /// Registers the credential for the sole pending Legacy attempt without
    /// exposing its internal token.
    ///
    /// # Errors
    ///
    /// Rejects stateful Git, missing/ambiguous pending state, wrong username,
    /// or any capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn register_legacy_credential(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::LegacySerial {
            return Err(CapabilityError::StateTokenRequired);
        }
        self.register_credential(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            profile,
            None,
            material,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_credential(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        profile: &ProfileBinding,
        expected_attempt: Option<CredentialAttemptId>,
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        self.validate_profile(profile)?;
        let correlation_key = self.correlation_key;
        let state = self.endpoint_mut(endpoint)?;
        Self::validate_request_username(state, endpoint)?;
        if let Some(configured) = &state.configured_username {
            if configured != material.username {
                return Err(CapabilityError::CredentialUsernameMismatch);
            }
        }
        if let Some(requested) = endpoint.username() {
            if requested != material.username {
                return Err(CapabilityError::CredentialUsernameMismatch);
            }
        }
        let Some(AttemptState::Pending(attempt)) = state.latest else {
            return Err(CapabilityError::CredentialNotRegistered);
        };
        if expected_attempt.is_some_and(|expected| expected != attempt) {
            return Err(CapabilityError::AttemptMismatch);
        }
        state.latest = Some(AttemptState::Issued(make_credential_proof(
            correlation_key,
            attempt,
            material,
        )));
        Ok(())
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
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_profile(profile)?;
        let correlation_key = self.correlation_key;
        let state = self.endpoint_mut(endpoint)?;
        let proof = Self::issued_proof(state, endpoint, Some(attempt), material, correlation_key)?;
        debug_assert_eq!(proof.attempt, attempt);
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
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_profile(profile)?;
        let correlation_key = self.correlation_key;
        let max_get_attempts = self.max_get_attempts;
        let state = self.endpoint_mut(endpoint)?;
        Self::issued_proof(state, endpoint, Some(attempt), material, correlation_key)?;
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
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        self.require_legacy()?;
        self.validate_profile(profile)?;
        let correlation_key = self.correlation_key;
        let state = self.endpoint_mut(endpoint)?;
        Self::issued_proof(state, endpoint, None, material, correlation_key)?;
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
        material: &CredentialMaterial<'_>,
        now: MonotonicInstant,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity, now)?;
        self.require_legacy()?;
        self.validate_profile(profile)?;
        let correlation_key = self.correlation_key;
        let max_get_attempts = self.max_get_attempts;
        let state = self.endpoint_mut(endpoint)?;
        Self::issued_proof(state, endpoint, None, material, correlation_key)?;
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
        now: MonotonicInstant,
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
        let route = CredentialRoute::from(endpoint);
        self.endpoints
            .iter()
            .position(|state| state.route == route)
            .ok_or(CapabilityError::EndpointMismatch)
    }

    fn require_legacy(&self) -> Result<(), CapabilityError> {
        if self.ruleset == GitCredentialProtocolRuleset::LegacySerial {
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

    fn validate_request_username(
        state: &EndpointState,
        request: &CanonicalCredentialRequest,
    ) -> Result<(), CapabilityError> {
        if let (Some(configured), Some(requested)) =
            (&state.configured_username, request.username())
        {
            if configured != requested {
                return Err(CapabilityError::CredentialUsernameMismatch);
            }
        }
        Ok(())
    }

    fn issued_proof<'a>(
        state: &'a EndpointState,
        request: &CanonicalCredentialRequest,
        expected_attempt: Option<CredentialAttemptId>,
        material: &CredentialMaterial<'_>,
        correlation_key: [u8; 32],
    ) -> Result<&'a IssuedCredentialProof, CapabilityError> {
        if state.status != EndpointStatus::Ready {
            return Err(CapabilityError::InvalidTransition);
        }
        Self::validate_request_username(state, request)?;
        let Some(AttemptState::Issued(proof)) = &state.latest else {
            return Err(CapabilityError::CredentialNotRegistered);
        };
        if expected_attempt.is_some_and(|attempt| attempt != proof.attempt) {
            return Err(CapabilityError::AttemptMismatch);
        }
        if request.username() != Some(proof.username.as_str())
            || proof.username != material.username
            || proof.backend_record_identity != material.backend_record_identity
            || proof.backend_record_version != material.backend_record_version
            || !credential_mac_matches(correlation_key, proof, material)
        {
            return Err(CapabilityError::CredentialMaterialMismatch);
        }
        Ok(proof)
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

type HmacSha256 = Hmac<Sha256>;

fn make_credential_proof(
    correlation_key: [u8; 32],
    attempt: CredentialAttemptId,
    material: &CredentialMaterial<'_>,
) -> IssuedCredentialProof {
    let material_mac = credential_mac(correlation_key, attempt, material);
    IssuedCredentialProof {
        attempt,
        username: material.username.to_owned(),
        backend_record_identity: material.backend_record_identity,
        backend_record_version: material.backend_record_version,
        material_mac,
    }
}

fn credential_mac(
    correlation_key: [u8; 32],
    attempt: CredentialAttemptId,
    material: &CredentialMaterial<'_>,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&correlation_key)
        .expect("HMAC accepts a fixed 32-byte correlation key");
    mac.update(b"gus.credential-material.v1\0");
    mac.update(&attempt.0);
    mac.update(&material.backend_record_identity);
    mac.update(&material.backend_record_version);
    mac.update(&(material.username.len() as u64).to_le_bytes());
    mac.update(material.username.as_bytes());
    mac.update(&(material.secret.len() as u64).to_le_bytes());
    mac.update(material.secret);
    mac.finalize().into_bytes().into()
}

fn credential_mac_matches(
    correlation_key: [u8; 32],
    proof: &IssuedCredentialProof,
    material: &CredentialMaterial<'_>,
) -> bool {
    let mut mac = HmacSha256::new_from_slice(&correlation_key)
        .expect("HMAC accepts a fixed 32-byte correlation key");
    mac.update(b"gus.credential-material.v1\0");
    mac.update(&proof.attempt.0);
    mac.update(&material.backend_record_identity);
    mac.update(&material.backend_record_version);
    mac.update(&(material.username.len() as u64).to_le_bytes());
    mac.update(material.username.as_bytes());
    mac.update(&(material.secret.len() as u64).to_le_bytes());
    mac.update(material.secret);
    mac.verify_slice(&proof.material_mac).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("capability claim is incomplete or invalid")]
    InvalidClaim,
    #[error("capability has expired")]
    Expired,
    #[error("capability is not valid yet")]
    NotYetValid,
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
    #[error("capability subject does not match the observed helper request")]
    SubjectMismatch,
    #[error("credential endpoint does not match")]
    EndpointMismatch,
    #[error("credential profile snapshot does not match")]
    ProfileMismatch,
    #[error("credential retry limit reached")]
    RetryLimit,
    #[error("credential attempt is missing, stale, or superseded")]
    AttemptMismatch,
    #[error("credential material is missing or malformed")]
    InvalidCredentialMaterial,
    #[error("credential response was not registered for this attempt")]
    CredentialNotRegistered,
    #[error("credential username does not match the route or profile")]
    CredentialUsernameMismatch,
    #[error("credential material or backend record does not match the issued attempt")]
    CredentialMaterialMismatch,
    #[error("legacy Git credential flow has an ambiguous outstanding attempt")]
    AmbiguousLegacyAttempt,
    #[error("legacy Git does not round-trip credential state tokens")]
    StateTokenUnsupported,
    #[error("stateful Git requires an authenticated credential state token")]
    StateTokenRequired,
    #[error("fixed real Git has no admitted credential protocol ruleset")]
    UnsupportedGitCredentialProtocol,
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

    fn endpoint(host: &str, path: &str, username: Option<&str>) -> CanonicalCredentialRequest {
        CanonicalCredentialRequest::from_endpoint(
            CredentialProtocol::Https,
            host.to_owned(),
            None,
            path.to_owned(),
            username.map(str::to_owned),
        )
        .expect("valid endpoint")
    }

    fn http(
        version: &str,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
    ) -> HttpCredentialCapability {
        HttpCredentialCapability::issue_deferred(
            [1; 32],
            [2; 32],
            [3; 32],
            process(10),
            [4; 32],
            [5; 32],
            &VerifiedGitSemantics::from_version_output([6; 32], version)
                .expect("valid Git semantics"),
            endpoints,
            max_get_attempts,
            time(10),
            time(100),
        )
        .expect("valid HTTP capability")
    }

    const fn time(millis: u64) -> MonotonicInstant {
        MonotonicInstant::from_millis(millis)
    }

    fn material<'a>(username: &'a str, secret: &'a [u8], record: u8) -> CredentialMaterial<'a> {
        CredentialMaterial::new(username, secret, [record; 32], [record + 1; 32])
            .expect("valid credential material")
    }

    fn signing_subject(profile: ProfileBinding, payload: u8) -> SingleUseSubject {
        SingleUseSubject::Signing(
            SigningSubject::new(profile, SigningFormat::Ssh, [7; 32], [8; 32], [payload; 32])
                .expect("valid signing subject"),
        )
    }

    fn ssh_subject(profile: ProfileBinding) -> SingleUseSubject {
        SingleUseSubject::Ssh(
            SshTransportSubject::new(
                profile,
                CredentialHost::try_from("ssh.example.test".to_owned()).expect("valid host"),
                "git".to_owned(),
                22,
                SshService::UploadPack,
                [9; 32],
                [10; 32],
            )
            .expect("valid SSH subject"),
        )
    }

    #[test]
    fn single_use_capability_rejects_role_subject_confusion_and_replay() {
        let selected = profile("signer", 3);
        let expected = signing_subject(selected.clone(), 11);
        let mut capability = SingleUseCapability::issue(
            [1; 32],
            [2; 32],
            [3; 32],
            process(10),
            [4; 32],
            expected.clone(),
            time(10),
            time(100),
        )
        .expect("valid capability");
        assert_eq!(
            capability.claim(
                process(10),
                [3; 32],
                [4; 32],
                &ssh_subject(selected.clone()),
                time(20),
            ),
            Err(CapabilityError::RoleMismatch)
        );
        assert_eq!(
            capability.claim(
                process(10),
                [3; 32],
                [4; 32],
                &signing_subject(selected, 12),
                time(20),
            ),
            Err(CapabilityError::SubjectMismatch)
        );
        capability
            .claim(process(10), [3; 32], [4; 32], &expected, time(20))
            .expect("first matching claim succeeds");
        assert_eq!(
            capability.claim(process(10), [3; 32], [4; 32], &expected, time(21)),
            Err(CapabilityError::AlreadyUsed)
        );
    }

    #[test]
    fn stateful_http_retry_supersedes_old_attempt_and_stores_latest() {
        let get_endpoint = endpoint("example.test", "/team/repository.git", None);
        let store_endpoint = endpoint("example.test", "/team/repository.git", Some("git-user"));
        let selected = profile("work", 7);
        let mut capability = http("git version 2.55.0", vec![get_endpoint.clone()], 3);
        let first_material = material("git-user", b"first secret", 10);
        let first = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(20),
            )
            .expect("first get");
        capability
            .register_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &selected,
                first,
                &first_material,
                time(20),
            )
            .expect("register first credential");
        let second_material = material("git-user", b"second secret", 20);
        let second = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(21),
            )
            .expect("stateful retry");
        capability
            .register_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &selected,
                second,
                &second_material,
                time(21),
            )
            .expect("register second credential");
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &selected,
                first,
                &first_material,
                time(22),
            ),
            Err(CapabilityError::AttemptMismatch)
        );
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &selected,
                second,
                &first_material,
                time(22),
            ),
            Err(CapabilityError::CredentialMaterialMismatch)
        );
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &selected,
                second,
                &second_material,
                time(22),
            )
            .expect("latest store");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
    }

    #[test]
    fn git_239_serializes_get_and_reopens_only_after_erase() {
        let get_endpoint = endpoint("legacy.example.test", "/repository.git", None);
        let response_endpoint = endpoint(
            "legacy.example.test",
            "/repository.git",
            Some("legacy-user"),
        );
        let selected = profile("legacy", 4);
        let mut capability = http("git version 2.43.0", vec![get_endpoint.clone()], 2);
        let first_material = material("legacy-user", b"first legacy secret", 30);
        capability
            .get_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(20),
            )
            .expect("first get");
        capability
            .register_legacy_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &selected,
                &first_material,
                time(20),
            )
            .expect("register first legacy credential");
        assert_eq!(
            capability.get_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(21),
            ),
            Err(CapabilityError::AmbiguousLegacyAttempt)
        );
        capability
            .erase_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &selected,
                &first_material,
                time(22),
            )
            .expect("erase reopens endpoint");
        let second_material = material("legacy-user", b"second legacy secret", 40);
        capability
            .get_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(23),
            )
            .expect("bounded retry");
        capability
            .register_legacy_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &selected,
                &second_material,
                time(23),
            )
            .expect("register second legacy credential");
        assert_eq!(
            capability.store_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &selected,
                &first_material,
                time(24),
            ),
            Err(CapabilityError::CredentialMaterialMismatch),
            "a delayed store from the erased attempt must not match"
        );
        capability
            .store_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &selected,
                &second_material,
                time(24),
            )
            .expect("latest legacy store");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
    }

    #[test]
    fn every_helper_call_revalidates_parent_plan_helper_endpoint_and_profile() {
        let expected_endpoint = endpoint("example.test", "/one.git", Some("git-user"));
        let other = endpoint("other.example.test", "/two.git", Some("git-user"));
        let selected = profile("work", 7);
        let mut capability = http("git version 2.55.0", vec![expected_endpoint.clone()], 2);
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
                capability.get_stateful(
                    parent,
                    plan,
                    helper,
                    requested_endpoint,
                    requested_profile,
                    time(20),
                ),
                Err(expected)
            );
        }
        capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                selected,
                time(20),
            )
            .expect("valid get binds profile");
        assert_eq!(
            capability.get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                profile("personal", 8),
                time(21),
            ),
            Err(CapabilityError::ProfileMismatch)
        );
    }

    #[test]
    fn multiple_endpoints_complete_independently_and_ttl_revokes_access() {
        let one = endpoint("one.example.test", "/one.git", None);
        let one_response = endpoint("one.example.test", "/one.git", Some("git-user"));
        let two = endpoint("two.example.test", "/two.git", None);
        let selected = profile("work", 7);
        let mut capability = http("git version 2.55.0", vec![one.clone(), two.clone()], 2);
        let issued = material("git-user", b"first endpoint secret", 50);
        let attempt_one = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &one,
                selected.clone(),
                time(20),
            )
            .expect("first endpoint");
        capability
            .register_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &one,
                &selected,
                attempt_one,
                &issued,
                time(20),
            )
            .expect("register first endpoint material");
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &one_response,
                &selected,
                attempt_one,
                &issued,
                time(21),
            )
            .expect("store first endpoint");
        assert_eq!(capability.status(), CapabilityStatus::Active);
        assert_eq!(
            capability.get_stateful(process(10), [3; 32], [4; 32], &two, selected, time(100),),
            Err(CapabilityError::Expired)
        );
        assert_eq!(capability.status(), CapabilityStatus::Revoked);
    }

    #[test]
    fn credential_material_must_be_registered_before_store() {
        let get_endpoint = endpoint("example.test", "/repository.git", None);
        let response_endpoint = endpoint("example.test", "/repository.git", Some("git-user"));
        let selected = profile("work", 7);
        let mut capability = http("git version 2.55.0", vec![get_endpoint.clone()], 1);
        let issued = material("git-user", b"credential secret", 60);
        let attempt = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                selected.clone(),
                time(20),
            )
            .expect("get starts one pending attempt");

        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &selected,
                attempt,
                &issued,
                time(21),
            ),
            Err(CapabilityError::CredentialNotRegistered)
        );
    }

    #[test]
    fn capabilities_enforce_monotonic_not_before_and_maximum_ttl() {
        let expected = signing_subject(profile("signer", 3), 11);
        let mut capability = SingleUseCapability::issue(
            [1; 32],
            [2; 32],
            [3; 32],
            process(10),
            [4; 32],
            expected.clone(),
            time(10),
            time(100),
        )
        .expect("valid bounded capability");
        assert_eq!(
            capability.claim(process(10), [3; 32], [4; 32], &expected, time(9)),
            Err(CapabilityError::NotYetValid)
        );
        assert_eq!(capability.status(), CapabilityStatus::Active);

        assert_eq!(
            SingleUseCapability::issue(
                [1; 32],
                [2; 32],
                [3; 32],
                process(10),
                [4; 32],
                expected,
                time(10),
                time(10 + MAX_CAPABILITY_TTL_MILLIS + 1),
            ),
            Err(CapabilityError::InvalidClaim)
        );
    }

    #[test]
    fn fixed_git_without_an_admitted_credential_ruleset_is_rejected() {
        let semantics =
            VerifiedGitSemantics::from_version_output([6; 32], "git version 2.54.1.vendor.2")
                .expect("well-formed but unsupported Git version");
        assert_eq!(
            HttpCredentialCapability::issue_deferred(
                [1; 32],
                [2; 32],
                [3; 32],
                process(10),
                [4; 32],
                [5; 32],
                &semantics,
                vec![endpoint("example.test", "/repository.git", None)],
                1,
                time(10),
                time(100),
            ),
            Err(CapabilityError::UnsupportedGitCredentialProtocol)
        );
    }

    #[test]
    fn http_capability_debug_output_redacts_the_correlation_key() {
        let capability = http(
            "git version 2.55.0",
            vec![endpoint("example.test", "/repository.git", None)],
            1,
        );
        let rendered = format!("{capability:?}");
        assert!(rendered.contains("correlation_key: \"<redacted>\""));
        assert!(!rendered.contains("[5, 5, 5, 5"));
    }
}
