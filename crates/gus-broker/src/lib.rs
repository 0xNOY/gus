//! Capability and session invariants for the GUS broker.
//!
//! This crate deliberately contains no IPC or OS process inspection. Platform
//! adapters must derive the identities passed here from authenticated peer and
//! process handles. The state machines then prevent adapters from accidentally
//! treating a multi-process HTTP credential flow as a single-use capability.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use gus_core::{GitCredentialProtocolRuleset, VerifiedGitSemantics};
use gus_profile::{
    CanonicalCredentialRequest, CredentialBackend, CredentialHost, CredentialPathPrefix,
    CredentialProtocol, ProfileId, SelectedCredentialBinding, SigningFormat,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const RANDOM_ISSUANCE_ATTEMPTS: usize = 32;
#[cfg(not(test))]
const MAX_ACTIVE_CAPABILITIES: usize = 4096;
#[cfg(test)]
const MAX_ACTIVE_CAPABILITIES: usize = 32;

struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    fn random() -> Result<Self, CapabilityError> {
        let mut value = Zeroizing::new([0; 32]);
        getrandom::fill(value.as_mut()).map_err(|_| CapabilityError::EntropyUnavailable)?;
        if value.as_ref() == [0; 32] {
            return Err(CapabilityError::EntropyUnavailable);
        }
        Ok(Self(value))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

struct IssuerState {
    instance: Secret32,
    handle_key: Secret32,
    attempt_key: Secret32,
    clock: Arc<dyn MonotonicClock>,
    active_handle_tags: Mutex<HashMap<[u8; 32], MonotonicInstant>>,
}

trait MonotonicClock: Send + Sync {
    fn now(&self) -> MonotonicInstant;
}

struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// Owner of all capability issuance secrets for one live broker instance.
/// This type is deliberately neither `Clone` nor serializable.
pub struct BrokerIssuer {
    state: Arc<IssuerState>,
}

impl fmt::Debug for BrokerIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerIssuer")
            .field("instance", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BrokerIssuer {
    /// Creates a fresh broker issuer from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Fails closed when secure random bytes are unavailable.
    pub fn new() -> Result<Self, CapabilityError> {
        Self::with_clock(Arc::new(SystemMonotonicClock::new()))
    }

    fn with_clock(clock: Arc<dyn MonotonicClock>) -> Result<Self, CapabilityError> {
        Ok(Self {
            state: Arc::new(IssuerState {
                instance: Secret32::random()?,
                handle_key: Secret32::random()?,
                attempt_key: Secret32::random()?,
                clock,
                active_handle_tags: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Issues one non-replayable SSH, signing, or nested-Git capability.
    /// Handles and issuer identifiers are generated internally and never
    /// accepted from an adapter.
    ///
    /// # Errors
    ///
    /// Rejects invalid claims or unavailable issuer entropy/state.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_single_use(
        &self,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        subject: SingleUseSubject,
        ttl: Duration,
    ) -> Result<SingleUseCapability, CapabilityError> {
        let (handle, issuance, issued_at, expires_at) = self.reserve_issuance(ttl)?;
        SingleUseCapability::issue(
            handle,
            issuance,
            plan_digest,
            parent,
            helper_identity,
            subject,
            issued_at,
            expires_at,
        )
    }

    /// Issues a deferred HTTP credential capability for an exact admitted Git
    /// build and fixed endpoint inventory.
    ///
    /// # Errors
    ///
    /// Rejects unsupported Git builds, duplicate endpoints, invalid claims, or
    /// unavailable issuer entropy/state.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_http_deferred(
        &self,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        ttl: Duration,
    ) -> Result<HttpCredentialCapability, CapabilityError> {
        self.issue_http(
            plan_digest,
            parent,
            helper_identity,
            git_semantics,
            HttpProfileState::Deferred,
            endpoints,
            max_get_attempts,
            ttl,
        )
    }

    /// Issues an HTTP capability already bound to a selected profile.
    ///
    /// # Errors
    ///
    /// Uses the same fail-closed validation as [`Self::issue_http_deferred`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue_http_bound(
        &self,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        profile: ProfileBinding,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        ttl: Duration,
    ) -> Result<HttpCredentialCapability, CapabilityError> {
        self.issue_http(
            plan_digest,
            parent,
            helper_identity,
            git_semantics,
            HttpProfileState::Bound(profile),
            endpoints,
            max_get_attempts,
            ttl,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_http(
        &self,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        git_semantics: &VerifiedGitSemantics,
        profile: HttpProfileState,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        ttl: Duration,
    ) -> Result<HttpCredentialCapability, CapabilityError> {
        let (handle, issuance, issued_at, expires_at) = self.reserve_issuance(ttl)?;
        HttpCredentialCapability::issue(
            handle,
            issuance,
            plan_digest,
            parent,
            helper_identity,
            Secret32::random()?,
            git_semantics,
            profile,
            endpoints,
            max_get_attempts,
            issued_at,
            expires_at,
        )
    }

    fn reserve_issuance(
        &self,
        ttl: Duration,
    ) -> Result<(Secret32, IssuanceLease, MonotonicInstant, MonotonicInstant), CapabilityError>
    {
        let ttl = u64::try_from(ttl.as_millis()).map_err(|_| CapabilityError::InvalidClaim)?;
        if ttl == 0 || ttl > MAX_CAPABILITY_TTL_MILLIS {
            return Err(CapabilityError::InvalidClaim);
        }
        let issued_at = self.state.clock.now();
        let expires_at = MonotonicInstant(
            issued_at
                .0
                .checked_add(ttl)
                .ok_or(CapabilityError::InvalidClaim)?,
        );
        for _ in 0..RANDOM_ISSUANCE_ATTEMPTS {
            let handle = Secret32::random()?;
            let tag = keyed_digest(
                self.state.handle_key.as_bytes(),
                b"gus.capability-handle-tag.v1\0",
                &[handle.as_bytes()],
            );
            let mut active = self
                .state
                .active_handle_tags
                .lock()
                .map_err(|_| CapabilityError::IssuerUnavailable)?;
            active.retain(|_, expiry| issued_at < *expiry);
            if active.len() >= MAX_ACTIVE_CAPABILITIES {
                return Err(CapabilityError::IssuanceLimitReached);
            }
            if active.insert(tag, expires_at).is_none() {
                drop(active);
                return Ok((
                    handle,
                    IssuanceLease {
                        state: Arc::downgrade(&self.state),
                        handle_tag: tag,
                        expires_at,
                        released: false,
                    },
                    issued_at,
                    expires_at,
                ));
            }
        }
        Err(CapabilityError::EntropyUnavailable)
    }

    #[cfg(test)]
    fn active_issuance_count(&self) -> usize {
        let now = self.state.clock.now();
        let mut active = self
            .state
            .active_handle_tags
            .lock()
            .expect("test issuer lock");
        active.retain(|_, expiry| now < *expiry);
        active.len()
    }
}

struct IssuanceLease {
    state: Weak<IssuerState>,
    handle_tag: [u8; 32],
    expires_at: MonotonicInstant,
    released: bool,
}

impl IssuanceLease {
    fn validate(&self) -> Result<(Arc<IssuerState>, MonotonicInstant), CapabilityError> {
        if self.released {
            return Err(CapabilityError::Revoked);
        }
        let state = self
            .state
            .upgrade()
            .ok_or(CapabilityError::IssuerUnavailable)?;
        let now = state.clock.now();
        let mut active = state
            .active_handle_tags
            .lock()
            .map_err(|_| CapabilityError::IssuerUnavailable)?;
        if now >= self.expires_at {
            active.remove(&self.handle_tag);
            return Err(CapabilityError::Expired);
        }
        let Some(expires_at) = active.get(&self.handle_tag).copied() else {
            return Err(CapabilityError::Revoked);
        };
        if now >= expires_at {
            active.remove(&self.handle_tag);
            return Err(CapabilityError::Expired);
        }
        drop(active);
        Ok((state, now))
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        if let Some(state) = self.state.upgrade() {
            match state.active_handle_tags.lock() {
                Ok(mut active) => {
                    active.remove(&self.handle_tag);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(&self.handle_tag);
                }
            }
        }
        self.released = true;
    }
}

impl Drop for IssuanceLease {
    fn drop(&mut self) {
        self.release();
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MonotonicInstant(u64);

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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialAttemptId([u8; 32]);

impl fmt::Debug for CredentialAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialAttemptId(<redacted>)")
    }
}

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

struct CommonClaims {
    handle: Secret32,
    issuance: IssuanceLease,
    plan_digest: [u8; 32],
    parent: ProcessIdentity,
    helper_identity: [u8; 32],
    not_before: MonotonicInstant,
    expires_at: MonotonicInstant,
}

impl CommonClaims {
    fn new(
        handle: Secret32,
        issuance: IssuanceLease,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        issued_at: MonotonicInstant,
        expires_at: MonotonicInstant,
    ) -> Result<Self, CapabilityError> {
        if plan_digest == [0; 32]
            || helper_identity == [0; 32]
            || issued_at >= expires_at
            || expires_at.0 - issued_at.0 > MAX_CAPABILITY_TTL_MILLIS
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            handle,
            issuance,
            plan_digest,
            parent,
            helper_identity,
            not_before: issued_at,
            expires_at,
        })
    }

    fn validate_call(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
    ) -> Result<(), CapabilityError> {
        let (_, now) = self.issuance.validate()?;
        if now < self.not_before {
            return Err(CapabilityError::NotYetValid);
        }
        if now >= self.expires_at {
            self.issuance.release();
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

    fn release(&mut self) {
        self.issuance.release();
    }
}

pub struct SingleUseCapability {
    claims: CommonClaims,
    subject: SingleUseSubject,
    status: CapabilityStatus,
}

impl fmt::Debug for SingleUseCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SingleUseCapability")
            .field("handle", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl SingleUseCapability {
    /// Issues a role-specific capability which can be claimed once.
    ///
    /// # Errors
    ///
    /// Rejects missing digests and non-positive validity windows.
    #[allow(clippy::too_many_arguments)]
    fn issue(
        handle: Secret32,
        issuance: IssuanceLease,
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
                issuance,
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
    ) -> Result<(), CapabilityError> {
        self.require_active()?;
        if let Err(error) = self
            .claims
            .validate_call(parent, plan_digest, helper_identity)
        {
            if matches!(
                error,
                CapabilityError::Expired
                    | CapabilityError::Revoked
                    | CapabilityError::IssuerUnavailable
            ) {
                self.status = CapabilityStatus::Revoked;
                self.claims.release();
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
        self.claims.release();
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = CapabilityStatus::Revoked;
        self.claims.release();
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

/// Opaque lease for the exact open adapter artifact verified by the broker
/// loader. Construction remains inside the broker TCB.
#[derive(PartialEq, Eq)]
pub struct VerifiedBackendAdapterLease {
    configured_backend: CredentialBackend,
    selected_binding_digest: [u8; 32],
    adapter_identity: [u8; 32],
    artifact_lease_digest: [u8; 32],
}

impl fmt::Debug for VerifiedBackendAdapterLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBackendAdapterLease")
            .field("configured_backend", &"<redacted>")
            .field("selected_binding_digest", &"<redacted>")
            .field("adapter_identity", &"<redacted>")
            .field("artifact_lease_digest", &"<redacted>")
            .finish()
    }
}

impl VerifiedBackendAdapterLease {
    #[cfg(test)]
    fn for_test(
        configured_backend: CredentialBackend,
        selected_binding_digest: [u8; 32],
        adapter_identity: [u8; 32],
        artifact_lease_digest: [u8; 32],
    ) -> Self {
        Self {
            configured_backend,
            selected_binding_digest,
            adapter_identity,
            artifact_lease_digest,
        }
    }
}

/// Exact profile/backend and adapter artifact selected by the immutable
/// execution plan.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialBackendPlan {
    selection: SelectedCredentialBinding,
    adapter: Arc<VerifiedBackendAdapterLease>,
    execution_plan_digest: [u8; 32],
}

impl fmt::Debug for CredentialBackendPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBackendPlan")
            .field("selection", &"<redacted>")
            .field("adapter", &"<verified lease redacted>")
            .field("execution_plan_digest", &"<redacted>")
            .finish()
    }
}

impl CredentialBackendPlan {
    /// Binds selection to an opaque adapter artifact lease produced by the
    /// broker loader. The lease has no public constructor, so an IPC/config
    /// caller cannot mint a plan from self-reported identity bytes.
    ///
    /// # Errors
    ///
    /// Rejects a lease for another selected binding/backend or missing
    /// artifact/execution identities.
    pub fn from_verified_adapter(
        selection: SelectedCredentialBinding,
        adapter: VerifiedBackendAdapterLease,
        execution_plan_digest: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        if adapter.adapter_identity == [0; 32]
            || adapter.artifact_lease_digest == [0; 32]
            || execution_plan_digest == [0; 32]
            || selection.backend() != &adapter.configured_backend
            || selection.digest() != adapter.selected_binding_digest
        {
            return Err(CapabilityError::InvalidClaim);
        }
        Ok(Self {
            selection,
            adapter: Arc::new(adapter),
            execution_plan_digest,
        })
    }

    fn profile_binding(&self) -> Result<ProfileBinding, CapabilityError> {
        ProfileBinding::new(
            self.selection.profile_id().clone(),
            self.selection.profile_generation(),
        )
    }
}

mod credential_backend_sealed {
    pub trait Sealed {}
}

/// Security-sensitive backend adapter boundary. Broker code verifies both the
/// selected backend configuration and the loaded adapter artifact identity
/// before invoking this trait. The private sealing module prevents downstream
/// crates and IPC DTOs from implementing the trait by self-reporting those
/// values; concrete adapters must live in the broker TCB.
pub trait TrustedCredentialBackend: credential_backend_sealed::Sealed {
    fn configured_backend(&self) -> &CredentialBackend;

    fn adapter_identity(&self) -> [u8; 32];

    /// Fetches a credential for exactly the supplied canonical request.
    ///
    /// # Errors
    ///
    /// Returns a stable capability error without logging credential material.
    fn get(
        &mut self,
        request: &CanonicalCredentialRequest,
        sink: CredentialResponseSink<'_>,
    ) -> Result<CredentialBackendResponse, CapabilityError>;
}

/// One-use response constructor passed only after the broker verifies the
/// backend configuration and adapter artifact.
pub struct CredentialResponseSink<'a> {
    expected_username: &'a str,
}

impl CredentialResponseSink<'_> {
    /// Accepts an owned response while keeping the secret in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Rejects the wrong username, an empty secret, or missing record proof.
    pub fn accept(
        self,
        username: String,
        secret: Vec<u8>,
        backend_record_identity: [u8; 32],
        backend_record_version: [u8; 32],
    ) -> Result<CredentialBackendResponse, CapabilityError> {
        if username != self.expected_username
            || username.chars().any(char::is_control)
            || secret.is_empty()
            || backend_record_identity == [0; 32]
            || backend_record_version == [0; 32]
        {
            return Err(CapabilityError::InvalidCredentialMaterial);
        }
        Ok(CredentialBackendResponse {
            username,
            secret: Zeroizing::new(secret),
            backend_record_identity,
            backend_record_version,
        })
    }
}

/// Credential returned to the helper after broker-side backend verification.
/// It deliberately implements neither `Clone`, `Debug`, nor serialization.
pub struct CredentialBackendResponse {
    username: String,
    secret: Zeroizing<Vec<u8>>,
    backend_record_identity: [u8; 32],
    backend_record_version: [u8; 32],
}

impl CredentialBackendResponse {
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Credential fields observed later in Git's `store`/`erase` request. Backend
/// record identities are intentionally absent from the wire observation and
/// are recovered only from the broker's issued proof.
pub struct CredentialObservation<'a> {
    username: &'a str,
    secret: &'a [u8],
}

impl<'a> CredentialObservation<'a> {
    /// Validates credential fields received from Git.
    ///
    /// # Errors
    ///
    /// Rejects empty/control usernames or empty secrets.
    pub fn new(username: &'a str, secret: &'a [u8]) -> Result<Self, CapabilityError> {
        if username.is_empty()
            || username.len() > 255
            || username.chars().any(char::is_control)
            || secret.is_empty()
        {
            return Err(CapabilityError::InvalidCredentialMaterial);
        }
        Ok(Self { username, secret })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct IssuedCredentialProof {
    attempt: CredentialAttemptId,
    username: String,
    backend_binding_tag: [u8; 32],
    backend_record_identity: [u8; 32],
    backend_record_version: [u8; 32],
    material_mac: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
enum AttemptState {
    Pending(CredentialAttemptId),
    Issued(IssuedCredentialProof),
}

#[derive(PartialEq, Eq)]
struct EndpointState {
    route: CredentialRoute,
    configured_username: Option<String>,
    backend_plan: Option<CredentialBackendPlan>,
    attempts: u16,
    last_attempt: Option<CredentialAttemptId>,
    latest: Option<AttemptState>,
    status: EndpointStatus,
}

#[derive(PartialEq, Eq)]
enum HttpProfileState {
    Deferred,
    Bound(ProfileBinding),
}

pub struct HttpCredentialCapability {
    claims: CommonClaims,
    ruleset: GitCredentialProtocolRuleset,
    correlation_key: Secret32,
    profile: HttpProfileState,
    max_get_attempts: u16,
    endpoints: Vec<EndpointState>,
    status: CapabilityStatus,
}

impl fmt::Debug for HttpCredentialCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpCredentialCapability")
            .field("handle", &"<redacted>")
            .field("ruleset", &self.ruleset)
            .field("correlation_key", &"<redacted>")
            .field(
                "profile",
                &match &self.profile {
                    HttpProfileState::Deferred => "deferred",
                    HttpProfileState::Bound(_) => "<redacted>",
                },
            )
            .field("max_get_attempts", &self.max_get_attempts)
            .field("endpoint_count", &self.endpoints.len())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl HttpCredentialCapability {
    #[allow(clippy::too_many_arguments)]
    fn issue(
        handle: Secret32,
        issuance: IssuanceLease,
        plan_digest: [u8; 32],
        parent: ProcessIdentity,
        helper_identity: [u8; 32],
        correlation_key: Secret32,
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
                issuance,
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
                    backend_plan: None,
                    attempts: 0,
                    last_attempt: None,
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
        backend_plan: &CredentialBackendPlan,
        previous_state: Option<CredentialAttemptId>,
    ) -> Result<CredentialAttemptId, CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.begin_get(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            backend_plan,
            previous_state,
        )
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
        backend_plan: &CredentialBackendPlan,
    ) -> Result<(), CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::LegacySerial {
            return Err(CapabilityError::StateTokenRequired);
        }
        self.begin_get(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            backend_plan,
            None,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_get(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        backend_plan: &CredentialBackendPlan,
        previous_state: Option<CredentialAttemptId>,
    ) -> Result<CredentialAttemptId, CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        if backend_plan.execution_plan_digest != plan_digest
            || CredentialRoute::from(backend_plan.selection.request())
                != CredentialRoute::from(endpoint)
            || endpoint
                .username()
                .is_some_and(|username| username != backend_plan.selection.username())
        {
            return Err(CapabilityError::BackendBindingMismatch);
        }
        let profile = backend_plan.profile_binding()?;
        self.bind_or_validate_profile(profile)?;
        let (attempt_number, route) = {
            let state = &mut self.endpoints[endpoint_index];
            if state.status != EndpointStatus::Ready {
                return Err(CapabilityError::InvalidTransition);
            }
            Self::validate_request_username(state, endpoint)?;
            if let Some(existing) = &state.backend_plan {
                if existing != backend_plan {
                    return Err(CapabilityError::BackendBindingMismatch);
                }
            } else {
                if state
                    .configured_username
                    .as_ref()
                    .is_some_and(|username| username != backend_plan.selection.username())
                {
                    return Err(CapabilityError::CredentialUsernameMismatch);
                }
                state.backend_plan = Some(backend_plan.clone());
            }
            if self.ruleset == GitCredentialProtocolRuleset::LegacySerial {
                if state.latest.is_some() {
                    return Err(CapabilityError::AmbiguousLegacyAttempt);
                }
            } else if state.attempts == 0 {
                if previous_state.is_some() {
                    return Err(CapabilityError::AttemptMismatch);
                }
            } else {
                let expected = state.last_attempt.ok_or(CapabilityError::AttemptMismatch)?;
                match previous_state {
                    Some(observed) if observed == expected => {}
                    Some(_) => return Err(CapabilityError::AttemptMismatch),
                    None => return Err(CapabilityError::StateTokenRequired),
                }
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
            (state.attempts, state.route.clone())
        };
        let profile = backend_plan.profile_binding()?;
        let attempt = derive_attempt(
            &self.claims,
            endpoint_index,
            attempt_number,
            &profile,
            &route,
        )?;
        let state = &mut self.endpoints[endpoint_index];
        state.last_attempt = Some(attempt);
        state.latest = Some(AttemptState::Pending(attempt));
        Ok(attempt)
    }

    /// Resolves and registers the credential for a stateful attempt through
    /// the exact trusted backend bound by the execution plan.
    ///
    /// # Errors
    ///
    /// Rejects a missing/superseded token, wrong username/backend, or any
    /// capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_stateful_credential<B: TrustedCredentialBackend>(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        backend_plan: &CredentialBackendPlan,
        attempt: CredentialAttemptId,
        backend: &mut B,
    ) -> Result<CredentialBackendResponse, CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.resolve_credential(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            backend_plan,
            Some(attempt),
            backend,
        )
    }

    /// Resolves and registers the credential for the sole pending Legacy
    /// attempt without exposing its internal token.
    ///
    /// # Errors
    ///
    /// Rejects stateful Git, missing/ambiguous pending state, wrong username,
    /// or any capability binding mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_legacy_credential<B: TrustedCredentialBackend>(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        backend_plan: &CredentialBackendPlan,
        backend: &mut B,
    ) -> Result<CredentialBackendResponse, CapabilityError> {
        if self.ruleset != GitCredentialProtocolRuleset::LegacySerial {
            return Err(CapabilityError::StateTokenRequired);
        }
        self.resolve_credential(
            parent,
            plan_digest,
            helper_identity,
            endpoint,
            backend_plan,
            None,
            backend,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_credential<B: TrustedCredentialBackend>(
        &mut self,
        parent: ProcessIdentity,
        plan_digest: [u8; 32],
        helper_identity: [u8; 32],
        endpoint: &CanonicalCredentialRequest,
        backend_plan: &CredentialBackendPlan,
        expected_attempt: Option<CredentialAttemptId>,
        backend: &mut B,
    ) -> Result<CredentialBackendResponse, CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        if backend_plan.execution_plan_digest != plan_digest
            || backend.configured_backend() != backend_plan.selection.backend()
            || backend.adapter_identity() != backend_plan.adapter.adapter_identity
        {
            return Err(CapabilityError::BackendBindingMismatch);
        }
        let profile = backend_plan.profile_binding()?;
        self.validate_profile(&profile)?;
        let attempt = {
            let state = self.endpoint_mut(endpoint)?;
            Self::validate_request_username(state, endpoint)?;
            if state.backend_plan.as_ref() != Some(backend_plan) {
                return Err(CapabilityError::BackendBindingMismatch);
            }
            let Some(AttemptState::Pending(attempt)) = state.latest else {
                return Err(CapabilityError::CredentialNotRegistered);
            };
            if expected_attempt.is_some_and(|expected| expected != attempt) {
                return Err(CapabilityError::AttemptMismatch);
            }
            attempt
        };
        let response = backend.get(
            endpoint,
            CredentialResponseSink {
                expected_username: backend_plan.selection.username(),
            },
        )?;
        let backend_binding_tag =
            backend_binding_tag(self.correlation_key.as_bytes(), backend_plan);
        let proof = make_credential_proof(
            self.correlation_key.as_bytes(),
            attempt,
            backend_binding_tag,
            &response,
        );
        self.endpoint_mut(endpoint)?.latest = Some(AttemptState::Issued(proof));
        Ok(response)
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
        backend_plan: &CredentialBackendPlan,
        attempt: CredentialAttemptId,
        observation: &CredentialObservation<'_>,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_backend_plan(backend_plan, plan_digest)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        let backend_binding_tag =
            backend_binding_tag(self.correlation_key.as_bytes(), backend_plan);
        Self::issued_proof(
            &self.endpoints[endpoint_index],
            endpoint,
            Some(attempt),
            observation,
            self.correlation_key.as_bytes(),
            backend_binding_tag,
            backend_plan,
        )?;
        let state = &mut self.endpoints[endpoint_index];
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
        backend_plan: &CredentialBackendPlan,
        attempt: CredentialAttemptId,
        observation: &CredentialObservation<'_>,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        if self.ruleset != GitCredentialProtocolRuleset::Stateful {
            return Err(CapabilityError::StateTokenUnsupported);
        }
        self.validate_backend_plan(backend_plan, plan_digest)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        let backend_binding_tag =
            backend_binding_tag(self.correlation_key.as_bytes(), backend_plan);
        Self::issued_proof(
            &self.endpoints[endpoint_index],
            endpoint,
            Some(attempt),
            observation,
            self.correlation_key.as_bytes(),
            backend_binding_tag,
            backend_plan,
        )?;
        let max_get_attempts = self.max_get_attempts;
        let state = &mut self.endpoints[endpoint_index];
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
        backend_plan: &CredentialBackendPlan,
        observation: &CredentialObservation<'_>,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        self.require_legacy()?;
        self.validate_backend_plan(backend_plan, plan_digest)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        let backend_binding_tag =
            backend_binding_tag(self.correlation_key.as_bytes(), backend_plan);
        Self::issued_proof(
            &self.endpoints[endpoint_index],
            endpoint,
            None,
            observation,
            self.correlation_key.as_bytes(),
            backend_binding_tag,
            backend_plan,
        )?;
        let state = &mut self.endpoints[endpoint_index];
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
        backend_plan: &CredentialBackendPlan,
        observation: &CredentialObservation<'_>,
    ) -> Result<(), CapabilityError> {
        self.validate_call(parent, plan_digest, helper_identity)?;
        self.require_legacy()?;
        self.validate_backend_plan(backend_plan, plan_digest)?;
        let endpoint_index = self.endpoint_index(endpoint)?;
        let backend_binding_tag =
            backend_binding_tag(self.correlation_key.as_bytes(), backend_plan);
        Self::issued_proof(
            &self.endpoints[endpoint_index],
            endpoint,
            None,
            observation,
            self.correlation_key.as_bytes(),
            backend_binding_tag,
            backend_plan,
        )?;
        let max_get_attempts = self.max_get_attempts;
        let state = &mut self.endpoints[endpoint_index];
        state.latest = None;
        if state.attempts >= max_get_attempts {
            state.status = EndpointStatus::Exhausted;
        }
        self.complete_if_terminal();
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.status = CapabilityStatus::Revoked;
        self.claims.release();
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
    ) -> Result<(), CapabilityError> {
        match self.status {
            CapabilityStatus::Active => {}
            CapabilityStatus::Completed => return Err(CapabilityError::AlreadyUsed),
            CapabilityStatus::Revoked => return Err(CapabilityError::Revoked),
        }
        if let Err(error) = self
            .claims
            .validate_call(parent, plan_digest, helper_identity)
        {
            if matches!(
                error,
                CapabilityError::Expired
                    | CapabilityError::Revoked
                    | CapabilityError::IssuerUnavailable
            ) {
                self.status = CapabilityStatus::Revoked;
                self.claims.release();
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

    fn validate_backend_plan(
        &self,
        backend_plan: &CredentialBackendPlan,
        execution_plan_digest: [u8; 32],
    ) -> Result<ProfileBinding, CapabilityError> {
        if backend_plan.execution_plan_digest != execution_plan_digest {
            return Err(CapabilityError::BackendBindingMismatch);
        }
        let profile = backend_plan.profile_binding()?;
        self.validate_profile(&profile)?;
        Ok(profile)
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
        observation: &CredentialObservation<'_>,
        correlation_key: &[u8; 32],
        backend_binding_tag: [u8; 32],
        backend_plan: &CredentialBackendPlan,
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
        if state.backend_plan.as_ref() != Some(backend_plan)
            || proof.backend_binding_tag != backend_binding_tag
        {
            return Err(CapabilityError::BackendBindingMismatch);
        }
        if request.username() != Some(proof.username.as_str())
            || proof.username != observation.username
            || !credential_mac_matches(correlation_key, proof, observation)
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
            self.claims.release();
        }
    }
}

fn derive_attempt(
    claims: &CommonClaims,
    endpoint_index: usize,
    attempt: u16,
    profile: &ProfileBinding,
    route: &CredentialRoute,
) -> Result<CredentialAttemptId, CapabilityError> {
    let (issuer, _) = claims.issuance.validate()?;
    let endpoint_index = (endpoint_index as u64).to_le_bytes();
    let attempt = attempt.to_le_bytes();
    let generation = profile.generation().to_le_bytes();
    let protocol = [match route.protocol {
        CredentialProtocol::Http => 1,
        CredentialProtocol::Https => 2,
    }];
    let port = route.port.to_le_bytes();
    Ok(CredentialAttemptId(keyed_digest(
        issuer.attempt_key.as_bytes(),
        b"gus.http-credential-attempt.v2\0",
        &[
            issuer.instance.as_bytes(),
            claims.handle.as_bytes(),
            &endpoint_index,
            &attempt,
            profile.profile_id().as_str().as_bytes(),
            &generation,
            &protocol,
            route.host.as_str().as_bytes(),
            &port,
            route.path.as_str().as_bytes(),
        ],
    )))
}

type HmacSha256 = Hmac<Sha256>;

fn keyed_digest(key: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts fixed 32-byte keys");
    mac.update(domain);
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field);
    }
    mac.finalize().into_bytes().into()
}

fn backend_binding_tag(
    correlation_key: &[u8; 32],
    backend_plan: &CredentialBackendPlan,
) -> [u8; 32] {
    keyed_digest(
        correlation_key,
        b"gus.credential-backend-binding.v1\0",
        &[
            &backend_plan.selection.digest(),
            &backend_plan.adapter.adapter_identity,
            &backend_plan.adapter.artifact_lease_digest,
            &backend_plan.execution_plan_digest,
        ],
    )
}

fn make_credential_proof(
    correlation_key: &[u8; 32],
    attempt: CredentialAttemptId,
    backend_binding_tag: [u8; 32],
    response: &CredentialBackendResponse,
) -> IssuedCredentialProof {
    let material_mac = credential_mac(
        correlation_key,
        attempt,
        backend_binding_tag,
        response.backend_record_identity,
        response.backend_record_version,
        &response.username,
        &response.secret,
    );
    IssuedCredentialProof {
        attempt,
        username: response.username.clone(),
        backend_binding_tag,
        backend_record_identity: response.backend_record_identity,
        backend_record_version: response.backend_record_version,
        material_mac,
    }
}

#[allow(clippy::too_many_arguments)]
fn credential_mac(
    correlation_key: &[u8; 32],
    attempt: CredentialAttemptId,
    backend_binding_tag: [u8; 32],
    backend_record_identity: [u8; 32],
    backend_record_version: [u8; 32],
    username: &str,
    secret: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(correlation_key)
        .expect("HMAC accepts a fixed 32-byte correlation key");
    mac.update(b"gus.credential-material.v2\0");
    mac.update(&attempt.0);
    mac.update(&backend_binding_tag);
    mac.update(&backend_record_identity);
    mac.update(&backend_record_version);
    mac.update(&(username.len() as u64).to_le_bytes());
    mac.update(username.as_bytes());
    mac.update(&(secret.len() as u64).to_le_bytes());
    mac.update(secret);
    mac.finalize().into_bytes().into()
}

fn credential_mac_matches(
    correlation_key: &[u8; 32],
    proof: &IssuedCredentialProof,
    observation: &CredentialObservation<'_>,
) -> bool {
    let mut mac = HmacSha256::new_from_slice(correlation_key)
        .expect("HMAC accepts a fixed 32-byte correlation key");
    mac.update(b"gus.credential-material.v2\0");
    mac.update(&proof.attempt.0);
    mac.update(&proof.backend_binding_tag);
    mac.update(&proof.backend_record_identity);
    mac.update(&proof.backend_record_version);
    mac.update(&(observation.username.len() as u64).to_le_bytes());
    mac.update(observation.username.as_bytes());
    mac.update(&(observation.secret.len() as u64).to_le_bytes());
    mac.update(observation.secret);
    mac.verify_slice(&proof.material_mac).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("secure capability entropy is unavailable")]
    EntropyUnavailable,
    #[error("capability issuer instance is unavailable or inconsistent")]
    IssuerUnavailable,
    #[error("active capability issuance limit reached")]
    IssuanceLimitReached,
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
    #[error("credential backend does not match the selected profile execution plan")]
    BackendBindingMismatch,
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
    use gus_core::{
        GitCredentialProbeAction, GitCredentialProbeExchange, GitCredentialProtocolAdmission,
        GitCredentialProtocolProbeTranscript,
    };
    use gus_profile::{CredentialBinding, HttpIdentity, PersonIdentity, Profile};
    use sha2::Digest as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(millis: u64) -> Self {
            Self(AtomicU64::new(millis))
        }

        fn advance(&self, millis: u64) {
            self.0.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant(self.0.load(Ordering::SeqCst))
        }
    }

    fn process(pid: u32) -> ProcessIdentity {
        ProcessIdentity::new(pid, 100, Sha256::digest(pid.to_le_bytes()).into())
            .expect("valid process")
    }

    fn profile_binding(name: &str, generation: u64) -> ProfileBinding {
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

    fn backend_plan(
        profile_name: &str,
        generation: u64,
        request: &CanonicalCredentialRequest,
        username: &str,
        adapter_identity: u8,
    ) -> CredentialBackendPlan {
        let id = ProfileId::try_from(profile_name.to_owned()).expect("valid profile id");
        let person =
            PersonIdentity::new("Work User".into(), "work@example.test".into()).expect("person");
        let backend = CredentialBackend::SecretStore {
            service: format!("gus-{profile_name}"),
            account: username.to_owned(),
        };
        let profile = Profile {
            id,
            author: person.clone(),
            committer: person,
            signing: None,
            ssh_transport: None,
            http: Some(HttpIdentity {
                bindings: vec![CredentialBinding {
                    protocol: request.protocol(),
                    host: request.host().clone(),
                    port: Some(request.port()),
                    path_prefix: Some(request.path().clone()),
                    username: username.to_owned(),
                    backend,
                }],
            }),
            generation,
        };
        let selection = profile
            .select_credential_binding(request)
            .expect("valid profile")
            .expect("matching binding");
        let adapter = VerifiedBackendAdapterLease::for_test(
            selection.backend().clone(),
            selection.digest(),
            [adapter_identity; 32],
            [adapter_identity.wrapping_add(1); 32],
        );
        CredentialBackendPlan::from_verified_adapter(selection, adapter, [3; 32])
            .expect("valid backend plan")
    }

    fn admitted_semantics(version: &str, stateful: bool) -> VerifiedGitSemantics {
        let (capability_output, capability_exit, first_input, first_output, second_input) =
            if stateful {
                (
                b"version 0\ncapability authtype\ncapability state\n".to_vec(),
                0,
                b"capability[]=state\nprotocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                b"capability[]=state\nstate[]=gus-probe-state-v1\ncontinue=true\nusername=probe\npassword=probe\n\n".to_vec(),
                b"capability[]=state\nprotocol=https\nhost=gus-probe.invalid\nstate[]=gus-probe-state-v1\n\n".to_vec(),
            )
            } else {
                (
                    b"git: 'credential capability' is not supported\n".to_vec(),
                    129,
                    b"protocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                    b"state[]=gus-probe-state-v1\nusername=probe\npassword=probe\n\n".to_vec(),
                    b"protocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                )
            };
        let transcript = GitCredentialProtocolProbeTranscript::new(vec![
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Capability,
                Vec::new(),
                capability_output,
                capability_exit,
                1,
                2,
            ),
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Get,
                first_input,
                first_output,
                0,
                3,
                4,
            ),
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Get,
                second_input,
                b"username=probe\npassword=probe\n\n".to_vec(),
                0,
                5,
                6,
            ),
        ]);
        let admission =
            GitCredentialProtocolAdmission::from_transcript([6; 32], version, &transcript)
                .expect("complete probe");
        VerifiedGitSemantics::from_version_output([6; 32], version)
            .expect("valid Git build")
            .with_credential_protocol_admission(&admission)
            .expect("receipt matches exact build")
    }

    fn http(
        issuer: &BrokerIssuer,
        version: &str,
        stateful: bool,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
    ) -> HttpCredentialCapability {
        http_with_ttl(
            issuer,
            version,
            stateful,
            endpoints,
            max_get_attempts,
            Duration::from_secs(60),
        )
    }

    fn http_with_ttl(
        issuer: &BrokerIssuer,
        version: &str,
        stateful: bool,
        endpoints: Vec<CanonicalCredentialRequest>,
        max_get_attempts: u16,
        ttl: Duration,
    ) -> HttpCredentialCapability {
        issuer
            .issue_http_deferred(
                [3; 32],
                process(10),
                [4; 32],
                &admitted_semantics(version, stateful),
                endpoints,
                max_get_attempts,
                ttl,
            )
            .expect("valid HTTP capability")
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

    struct FakeBackend {
        configured: CredentialBackend,
        adapter_identity: [u8; 32],
        username: String,
        secret: Vec<u8>,
        record_identity: [u8; 32],
        record_version: [u8; 32],
    }

    impl FakeBackend {
        fn for_plan(plan: &CredentialBackendPlan, secret: &[u8], record: u8) -> Self {
            Self {
                configured: plan.selection.backend().clone(),
                adapter_identity: plan.adapter.adapter_identity,
                username: plan.selection.username().to_owned(),
                secret: secret.to_vec(),
                record_identity: [record; 32],
                record_version: [record.wrapping_add(1); 32],
            }
        }
    }

    impl credential_backend_sealed::Sealed for FakeBackend {}

    impl TrustedCredentialBackend for FakeBackend {
        fn configured_backend(&self) -> &CredentialBackend {
            &self.configured
        }

        fn adapter_identity(&self) -> [u8; 32] {
            self.adapter_identity
        }

        fn get(
            &mut self,
            _request: &CanonicalCredentialRequest,
            sink: CredentialResponseSink<'_>,
        ) -> Result<CredentialBackendResponse, CapabilityError> {
            sink.accept(
                self.username.clone(),
                self.secret.clone(),
                self.record_identity,
                self.record_version,
            )
        }
    }

    fn observation(response: &CredentialBackendResponse) -> CredentialObservation<'_> {
        CredentialObservation::new(response.username(), response.secret())
            .expect("valid Git credential observation")
    }

    #[test]
    fn issuer_owns_unique_capability_lifetimes_and_invalidates_on_drop() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let selected = profile_binding("signer", 3);
        let expected = signing_subject(selected.clone(), 11);
        let mut capability = issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                expected.clone(),
                Duration::from_secs(60),
            )
            .expect("valid capability");
        assert_eq!(issuer.active_issuance_count(), 1);
        assert_eq!(
            capability.claim(
                process(10),
                [3; 32],
                [4; 32],
                &ssh_subject(selected.clone()),
            ),
            Err(CapabilityError::RoleMismatch)
        );
        assert_eq!(
            capability.claim(
                process(10),
                [3; 32],
                [4; 32],
                &signing_subject(selected, 12),
            ),
            Err(CapabilityError::SubjectMismatch)
        );
        capability
            .claim(process(10), [3; 32], [4; 32], &expected)
            .expect("first matching claim succeeds");
        assert_eq!(issuer.active_issuance_count(), 0);
        assert_eq!(
            capability.claim(process(10), [3; 32], [4; 32], &expected),
            Err(CapabilityError::AlreadyUsed)
        );
        drop(capability);
        assert_eq!(issuer.active_issuance_count(), 0);

        let mut orphaned = issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                expected.clone(),
                Duration::from_secs(60),
            )
            .expect("valid capability");
        drop(issuer);
        assert_eq!(
            orphaned.claim(process(10), [3; 32], [4; 32], &expected),
            Err(CapabilityError::IssuerUnavailable)
        );
    }

    #[test]
    fn issuer_bounds_active_capabilities_and_releases_revocation_immediately() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let subject = signing_subject(profile_binding("signer", 3), 11);
        let mut capabilities = (0..MAX_ACTIVE_CAPABILITIES)
            .map(|_| {
                issuer
                    .issue_single_use(
                        [3; 32],
                        process(10),
                        [4; 32],
                        subject.clone(),
                        Duration::from_secs(60),
                    )
                    .expect("within active issuance bound")
            })
            .collect::<Vec<_>>();
        assert_eq!(issuer.active_issuance_count(), MAX_ACTIVE_CAPABILITIES);
        assert!(matches!(
            issuer.issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                subject.clone(),
                Duration::from_secs(60),
            ),
            Err(CapabilityError::IssuanceLimitReached)
        ));

        capabilities[0].revoke();
        assert_eq!(issuer.active_issuance_count(), MAX_ACTIVE_CAPABILITIES - 1);
        issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                subject,
                Duration::from_secs(60),
            )
            .expect("released slot is reusable");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn stateful_retry_requires_the_previous_state_token_and_latest_material() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let get_endpoint = endpoint("example.test", "/team/repository.git", None);
        let store_endpoint = endpoint("example.test", "/team/repository.git", Some("git-user"));
        let plan = backend_plan("work", 7, &get_endpoint, "git-user", 20);
        let mut capability = http(
            &issuer,
            "git version 2.55.0",
            true,
            vec![get_endpoint.clone()],
            3,
        );

        let first = capability
            .get_stateful(process(10), [3; 32], [4; 32], &get_endpoint, &plan, None)
            .expect("first get");
        let mut first_backend = FakeBackend::for_plan(&plan, b"first secret", 10);
        let first_response = capability
            .resolve_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                first,
                &mut first_backend,
            )
            .expect("first backend response");

        assert_eq!(
            capability.get_stateful(process(10), [3; 32], [4; 32], &get_endpoint, &plan, None,),
            Err(CapabilityError::StateTokenRequired)
        );
        assert_eq!(
            capability.get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                Some(CredentialAttemptId::from_bytes([99; 32])),
            ),
            Err(CapabilityError::AttemptMismatch)
        );

        let second = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                Some(first),
            )
            .expect("authenticated retry");
        let mut second_backend = FakeBackend::for_plan(&plan, b"second secret", 20);
        let second_response = capability
            .resolve_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                second,
                &mut second_backend,
            )
            .expect("second backend response");

        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &plan,
                first,
                &observation(&first_response),
            ),
            Err(CapabilityError::AttemptMismatch)
        );
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &plan,
                second,
                &observation(&first_response),
            ),
            Err(CapabilityError::CredentialMaterialMismatch)
        );
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &store_endpoint,
                &plan,
                second,
                &observation(&second_response),
            )
            .expect("latest store");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
        assert_eq!(issuer.active_issuance_count(), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn legacy_flow_keeps_attempt_internal_and_correlates_backend_response() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let get_endpoint = endpoint("legacy.example.test", "/repository.git", None);
        let response_endpoint = endpoint(
            "legacy.example.test",
            "/repository.git",
            Some("legacy-user"),
        );
        let plan = backend_plan("legacy", 4, &get_endpoint, "legacy-user", 30);
        let mut capability = http(
            &issuer,
            "git version 2.43.0",
            false,
            vec![get_endpoint.clone()],
            2,
        );

        capability
            .get_legacy(process(10), [3; 32], [4; 32], &get_endpoint, &plan)
            .expect("first get");
        let mut first_backend = FakeBackend::for_plan(&plan, b"first legacy secret", 30);
        let first_response = capability
            .resolve_legacy_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                &mut first_backend,
            )
            .expect("first backend response");
        assert_eq!(
            capability.get_legacy(process(10), [3; 32], [4; 32], &get_endpoint, &plan,),
            Err(CapabilityError::AmbiguousLegacyAttempt)
        );
        capability
            .erase_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &plan,
                &observation(&first_response),
            )
            .expect("erase reopens endpoint");

        capability
            .get_legacy(process(10), [3; 32], [4; 32], &get_endpoint, &plan)
            .expect("bounded retry");
        let mut second_backend = FakeBackend::for_plan(&plan, b"second legacy secret", 40);
        let second_response = capability
            .resolve_legacy_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &plan,
                &mut second_backend,
            )
            .expect("second backend response");
        assert_eq!(
            capability.store_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &plan,
                &observation(&first_response),
            ),
            Err(CapabilityError::CredentialMaterialMismatch)
        );
        capability
            .store_legacy(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &plan,
                &observation(&second_response),
            )
            .expect("latest legacy store");
        assert_eq!(capability.status(), CapabilityStatus::Completed);
    }

    #[test]
    fn broker_rejects_wrong_profile_backend_or_adapter_before_secret_use() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let get_endpoint = endpoint("example.test", "/repository.git", None);
        let work_plan = backend_plan("work", 7, &get_endpoint, "work-user", 20);
        let personal_plan = backend_plan("personal", 8, &get_endpoint, "personal-user", 21);
        let mut capability = http(
            &issuer,
            "git version 2.55.0",
            true,
            vec![get_endpoint.clone()],
            1,
        );
        let attempt = capability
            .get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &work_plan,
                None,
            )
            .expect("first get");

        let mut wrong_backend = FakeBackend::for_plan(&personal_plan, b"wrong", 50);
        assert!(matches!(
            capability.resolve_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &work_plan,
                attempt,
                &mut wrong_backend,
            ),
            Err(CapabilityError::BackendBindingMismatch)
        ));

        let mut wrong_adapter = FakeBackend::for_plan(&work_plan, b"wrong", 51);
        wrong_adapter.adapter_identity = [99; 32];
        assert!(matches!(
            capability.resolve_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &work_plan,
                attempt,
                &mut wrong_adapter,
            ),
            Err(CapabilityError::BackendBindingMismatch)
        ));

        assert_eq!(
            capability.get_stateful(
                process(10),
                [3; 32],
                [4; 32],
                &get_endpoint,
                &personal_plan,
                Some(attempt),
            ),
            Err(CapabilityError::ProfileMismatch)
        );
    }

    #[test]
    fn store_before_backend_resolution_is_rejected() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let get_endpoint = endpoint("example.test", "/repository.git", None);
        let response_endpoint = endpoint("example.test", "/repository.git", Some("git-user"));
        let plan = backend_plan("work", 7, &get_endpoint, "git-user", 20);
        let mut capability = http(
            &issuer,
            "git version 2.55.0",
            true,
            vec![get_endpoint.clone()],
            1,
        );
        let attempt = capability
            .get_stateful(process(10), [3; 32], [4; 32], &get_endpoint, &plan, None)
            .expect("pending attempt");
        let observed = CredentialObservation::new("git-user", b"unissued").expect("observation");
        assert_eq!(
            capability.store(
                process(10),
                [3; 32],
                [4; 32],
                &response_endpoint,
                &plan,
                attempt,
                &observed,
            ),
            Err(CapabilityError::CredentialNotRegistered)
        );
    }

    #[test]
    fn every_call_revalidates_parent_plan_helper_endpoint_and_profile() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let expected_endpoint = endpoint("example.test", "/one.git", None);
        let other = endpoint("other.example.test", "/two.git", None);
        let selected = backend_plan("work", 7, &expected_endpoint, "git-user", 20);
        let mut capability = http(
            &issuer,
            "git version 2.55.0",
            true,
            vec![expected_endpoint.clone()],
            2,
        );
        for (parent, plan, helper, requested_endpoint, expected) in [
            (
                process(11),
                [3; 32],
                [4; 32],
                &expected_endpoint,
                CapabilityError::ParentMismatch,
            ),
            (
                process(10),
                [9; 32],
                [4; 32],
                &expected_endpoint,
                CapabilityError::PlanMismatch,
            ),
            (
                process(10),
                [3; 32],
                [9; 32],
                &expected_endpoint,
                CapabilityError::HelperMismatch,
            ),
            (
                process(10),
                [3; 32],
                [4; 32],
                &other,
                CapabilityError::EndpointMismatch,
            ),
        ] {
            assert_eq!(
                capability.get_stateful(parent, plan, helper, requested_endpoint, &selected, None,),
                Err(expected)
            );
        }
    }

    #[test]
    fn multiple_endpoints_complete_independently_and_ttl_revokes_access() {
        let clock = Arc::new(TestClock::new(10));
        let issuer = BrokerIssuer::with_clock(clock.clone()).expect("OS entropy");
        let one = endpoint("one.example.test", "/one.git", None);
        let one_response = endpoint("one.example.test", "/one.git", Some("git-user"));
        let two = endpoint("two.example.test", "/two.git", None);
        let one_plan = backend_plan("work", 7, &one, "git-user", 20);
        let two_plan = backend_plan("work", 7, &two, "git-user", 20);
        let mut capability = http_with_ttl(
            &issuer,
            "git version 2.55.0",
            true,
            vec![one.clone(), two.clone()],
            2,
            Duration::from_millis(50),
        );
        let attempt = capability
            .get_stateful(process(10), [3; 32], [4; 32], &one, &one_plan, None)
            .expect("first endpoint");
        let mut backend = FakeBackend::for_plan(&one_plan, b"first endpoint secret", 60);
        let response = capability
            .resolve_stateful_credential(
                process(10),
                [3; 32],
                [4; 32],
                &one,
                &one_plan,
                attempt,
                &mut backend,
            )
            .expect("backend response");
        capability
            .store(
                process(10),
                [3; 32],
                [4; 32],
                &one_response,
                &one_plan,
                attempt,
                &observation(&response),
            )
            .expect("store first endpoint");
        assert_eq!(capability.status(), CapabilityStatus::Active);
        clock.advance(50);
        assert_eq!(
            capability.get_stateful(process(10), [3; 32], [4; 32], &two, &two_plan, None,),
            Err(CapabilityError::Expired)
        );
        assert_eq!(capability.status(), CapabilityStatus::Revoked);
        assert_eq!(issuer.active_issuance_count(), 0);
    }

    #[test]
    fn broker_owned_clock_enforces_expiry_and_maximum_ttl() {
        let clock = Arc::new(TestClock::new(10));
        let issuer = BrokerIssuer::with_clock(clock.clone()).expect("OS entropy");
        let expected = signing_subject(profile_binding("signer", 3), 11);
        let mut capability = issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                expected.clone(),
                Duration::from_millis(90),
            )
            .expect("valid bounded capability");
        clock.advance(90);
        let mut fresh = issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                expected.clone(),
                Duration::from_millis(90),
            )
            .expect("new issuance sweeps expired registry entries");
        assert_eq!(
            capability.claim(process(10), [3; 32], [4; 32], &expected),
            Err(CapabilityError::Expired)
        );
        assert_eq!(capability.status(), CapabilityStatus::Revoked);
        fresh.revoke();
        assert_eq!(issuer.active_issuance_count(), 0);
        assert!(matches!(
            issuer.issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                expected,
                Duration::from_millis(MAX_CAPABILITY_TTL_MILLIS + 1),
            ),
            Err(CapabilityError::InvalidClaim)
        ));
    }

    #[test]
    fn unadmitted_git_build_cannot_issue_an_http_capability() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let semantics =
            VerifiedGitSemantics::from_version_output([6; 32], "git version 2.54.1.vendor.2")
                .expect("well-formed exact build");
        assert!(matches!(
            issuer.issue_http_deferred(
                [3; 32],
                process(10),
                [4; 32],
                &semantics,
                vec![endpoint("example.test", "/repository.git", None)],
                1,
                Duration::from_secs(60),
            ),
            Err(CapabilityError::UnsupportedGitCredentialProtocol)
        ));
    }

    #[test]
    fn all_debug_surfaces_redact_bearer_handles_state_and_backend_proof() {
        let issuer = BrokerIssuer::new().expect("OS entropy");
        let get_endpoint = endpoint("legacy.example.test", "/repository.git", None);
        let plan = backend_plan("legacy", 4, &get_endpoint, "legacy-user", 30);
        let mut capability = http(
            &issuer,
            "git version 2.43.0",
            false,
            vec![get_endpoint.clone()],
            1,
        );
        capability
            .get_legacy(process(10), [3; 32], [4; 32], &get_endpoint, &plan)
            .expect("legacy attempt");
        let rendered = format!("{capability:?}");
        assert!(rendered.contains("handle: \"<redacted>\""));
        assert!(rendered.contains("correlation_key: \"<redacted>\""));
        assert!(!rendered.contains("CredentialAttemptId"));
        assert!(!rendered.contains("IssuedCredentialProof"));
        assert!(!rendered.contains("legacy-user"));

        let token = CredentialAttemptId::from_bytes([99; 32]);
        assert_eq!(format!("{token:?}"), "CredentialAttemptId(<redacted>)");

        let single = issuer
            .issue_single_use(
                [3; 32],
                process(10),
                [4; 32],
                signing_subject(profile_binding("signer", 3), 11),
                Duration::from_secs(60),
            )
            .expect("single-use capability");
        let rendered = format!("{single:?}");
        assert!(rendered.contains("handle: \"<redacted>\""));
        assert!(!rendered.contains('['));
    }
}
