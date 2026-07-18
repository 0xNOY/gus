use gus_profile::ProfileId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Digest32, RequestId};

pub const PROTOCOL_VERSION: u16 = 1;
const MAX_PRESENTATION_TEXT_CHARS: usize = 256;
const MAX_PROFILE_CHOICES: usize = 256;
const MAX_PROVIDER_REPOSITORIES: usize = 128;
const MAX_PROVIDER_CAPABILITIES: usize = 16;
const MIN_SELECTION_TIMEOUT_MILLIS: u32 = 1_000;
const MAX_SELECTION_TIMEOUT_MILLIS: u32 = 300_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("IPC frame exceeds the maximum encoded size")]
    FrameTooLarge,
    #[error("IPC frame is empty")]
    EmptyFrame,
    #[error("IPC frame is not valid canonical JSON for this direction")]
    InvalidJson,
    #[error("unsupported IPC protocol version {received}")]
    UnsupportedVersion { received: u16 },
    #[error("request id must be a nonzero canonical UUIDv4")]
    InvalidRequestId,
    #[error("digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("IPC field '{field}' is outside its allowed bounds")]
    InvalidField { field: &'static str },
    #[error("secure randomness is unavailable")]
    EntropyUnavailable,
}

pub(crate) trait Validate {
    fn validate(&self) -> Result<(), ProtocolError>;
}

mod wire_message_seal {
    pub trait Sealed {}
}

/// Marker implemented only by the four protocol-direction message families.
///
/// The private supertrait prevents downstream crates from using [`WireFrame`]
/// with a message family that bypasses GUS validation.
pub trait WireMessage: wire_message_seal::Sealed {
    #[doc(hidden)]
    fn validate_wire_message(&self) -> Result<(), ProtocolError>;
}

impl<T> WireMessage for T
where
    T: Validate + wire_message_seal::Sealed,
{
    fn validate_wire_message(&self) -> Result<(), ProtocolError> {
        self.validate()
    }
}

/// A protocol frame. Its request ID is a correlation nonce, not an authority
/// token. The broker must additionally bind it to one authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireFrame<M> {
    protocol_version: u16,
    request_id: RequestId,
    message: M,
}

impl<M: WireMessage> WireFrame<M> {
    /// Creates a new request with an OS-random request ID.
    ///
    /// # Errors
    ///
    /// Rejects an invalid message or unavailable secure randomness.
    pub fn new(message: M) -> Result<Self, ProtocolError> {
        message.validate_wire_message()?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::generate()?,
            message,
        })
    }

    /// Creates a response correlated with an existing request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid message. Connection state must still verify that the
    /// request ID is outstanding and belongs to this peer.
    pub fn correlated(request_id: RequestId, message: M) -> Result<Self, ProtocolError> {
        message.validate_wire_message()?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            message,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                received: self.protocol_version,
            });
        }
        self.message.validate_wire_message()
    }

    pub(crate) const fn from_wire(
        protocol_version: u16,
        request_id: RequestId,
        message: M,
    ) -> Self {
        Self {
            protocol_version,
            request_id,
            message,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn message(&self) -> &M {
        &self.message
    }

    #[must_use]
    pub fn into_message(self) -> M {
        self.message
    }
}

pub type ShimRequestFrame = WireFrame<ShimRequest>;
pub type ShimResponseFrame = WireFrame<BrokerShimMessage>;
pub type ProviderRequestFrame = WireFrame<ProviderRequest>;
pub type ProviderResponseFrame = WireFrame<BrokerProviderMessage>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ShimRequest {
    ResolveSelection(ResolveSelectionRequest),
    ClearSelection(ClearSelectionRequest),
    Status(StatusRequest),
}

impl wire_message_seal::Sealed for ShimRequest {}

impl Validate for ShimRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ResolveSelection(request) => request.validate(),
            Self::ClearSelection(request) => request.validate(),
            Self::Status(request) => request.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveSelectionRequest {
    plan_digest: Digest32,
    repository_identity: Digest32,
    operation: OperationPresentation,
    interaction: InteractionMode,
    explicit_profile: Option<ProfileId>,
}

impl ResolveSelectionRequest {
    #[must_use]
    pub const fn new(
        plan_digest: Digest32,
        repository_identity: Digest32,
        operation: OperationPresentation,
        interaction: InteractionMode,
        explicit_profile: Option<ProfileId>,
    ) -> Self {
        Self {
            plan_digest,
            repository_identity,
            operation,
            interaction,
            explicit_profile,
        }
    }

    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }

    #[must_use]
    pub const fn repository_identity(&self) -> Digest32 {
        self.repository_identity
    }

    #[must_use]
    pub const fn operation(&self) -> OperationPresentation {
        self.operation
    }

    #[must_use]
    pub const fn interaction(&self) -> InteractionMode {
        self.interaction
    }

    #[must_use]
    pub const fn explicit_profile(&self) -> Option<&ProfileId> {
        self.explicit_profile.as_ref()
    }
}

impl Validate for ResolveSelectionRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        // A non-interactive request without an explicit profile is valid wire
        // input so the broker can return the stable fail-closed product error.
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSelectionRequest {
    repository_identity: Digest32,
    expected_session_generation: Option<u64>,
}

impl ClearSelectionRequest {
    #[must_use]
    pub const fn new(
        repository_identity: Digest32,
        expected_session_generation: Option<u64>,
    ) -> Self {
        Self {
            repository_identity,
            expected_session_generation,
        }
    }
}

impl Validate for ClearSelectionRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.expected_session_generation == Some(0) {
            return Err(ProtocolError::InvalidField {
                field: "expected_session_generation",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    repository_identity: Digest32,
}

impl StatusRequest {
    #[must_use]
    pub const fn new(repository_identity: Digest32) -> Self {
        Self {
            repository_identity,
        }
    }
}

impl Validate for StatusRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

/// Display-only operation classification. The broker must never use this enum
/// as policy proof; the retained immutable plan remains authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPresentation {
    LocalRead,
    WorktreeMutation,
    Commit,
    Tag,
    HistoryRewrite,
    Merge,
    RemoteRead,
    Push,
    UnknownProtected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    Foreground,
    Background,
    NonInteractive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ProviderRequest {
    Register(ProviderRegistrationRequest),
    Heartbeat { registration_id: RequestId },
    SelectionDecision(ProviderSelectionDecision),
    Unregister { registration_id: RequestId },
}

impl wire_message_seal::Sealed for ProviderRequest {}

impl Validate for ProviderRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Register(request) => request.validate(),
            Self::Heartbeat { .. } | Self::Unregister { .. } => Ok(()),
            Self::SelectionDecision(decision) => decision.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRegistrationRequest {
    kind: ProviderKind,
    editor_session_id: String,
    host_instance: Digest32,
    repositories: Vec<Digest32>,
    capabilities: Vec<ProviderCapability>,
}

impl ProviderRegistrationRequest {
    /// Builds untrusted provider metadata. The platform broker must bind it to
    /// the authenticated extension-host peer before registration.
    ///
    /// # Errors
    ///
    /// Rejects control characters, excessive collections, and duplicate
    /// capability/repository entries.
    pub fn new(
        kind: ProviderKind,
        editor_session_id: String,
        host_instance: Digest32,
        repositories: Vec<Digest32>,
        capabilities: Vec<ProviderCapability>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            kind,
            editor_session_id,
            host_instance,
            repositories,
            capabilities,
        };
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        self.kind
    }

    #[must_use]
    pub fn editor_session_id(&self) -> &str {
        &self.editor_session_id
    }
}

impl Validate for ProviderRegistrationRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("editor_session_id", &self.editor_session_id, 1)?;
        validate_unique_bounded(
            "repositories",
            &self.repositories,
            MAX_PROVIDER_REPOSITORIES,
        )?;
        validate_unique_bounded(
            "capabilities",
            &self.capabilities,
            MAX_PROVIDER_CAPABILITIES,
        )?;
        if !self
            .capabilities
            .contains(&ProviderCapability::ProfileQuickPick)
        {
            return Err(ProtocolError::InvalidField {
                field: "capabilities",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Vscode,
    JetBrains,
    NativePrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    ProfileQuickPick,
    Status,
    Diagnostics,
    ReloadAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSelectionDecision {
    registration_id: RequestId,
    selection_generation: u64,
    decision: ProviderDecision,
}

impl ProviderSelectionDecision {
    /// Creates a provider response for an outstanding broker prompt.
    ///
    /// # Errors
    ///
    /// Rejects a zero selection generation.
    pub fn new(
        registration_id: RequestId,
        selection_generation: u64,
        decision: ProviderDecision,
    ) -> Result<Self, ProtocolError> {
        let response = Self {
            registration_id,
            selection_generation,
            decision,
        };
        response.validate()?;
        Ok(response)
    }
}

impl Validate for ProviderSelectionDecision {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.selection_generation == 0 {
            return Err(ProtocolError::InvalidField {
                field: "selection_generation",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "profile_id", rename_all = "snake_case")]
pub enum ProviderDecision {
    Selected(ProfileId),
    Cancelled,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum BrokerShimMessage {
    Resolved(ResolvedSelection),
    Cleared { session_generation: u64 },
    Status(SelectionStatus),
    Error(BrokerError),
}

impl wire_message_seal::Sealed for BrokerShimMessage {}

impl Validate for BrokerShimMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Resolved(response) => response.validate(),
            Self::Cleared { session_generation } => validate_generation(*session_generation),
            Self::Status(status) => status.validate(),
            Self::Error(error) => error.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSelection {
    profile_id: ProfileId,
    profile_generation: u64,
    session_generation: u64,
}

impl ResolvedSelection {
    /// Creates a response after broker-side profile and session validation.
    ///
    /// # Errors
    ///
    /// Rejects zero generations.
    pub fn new(
        profile_id: ProfileId,
        profile_generation: u64,
        session_generation: u64,
    ) -> Result<Self, ProtocolError> {
        let response = Self {
            profile_id,
            profile_generation,
            session_generation,
        };
        response.validate()?;
        Ok(response)
    }
}

impl Validate for ResolvedSelection {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_generation(self.profile_generation)?;
        validate_generation(self.session_generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionStatus {
    repository_identity: Digest32,
    selected_profile: Option<ProfileId>,
    session_generation: u64,
}

impl SelectionStatus {
    /// Creates current status for one OS-derived session and repository.
    ///
    /// # Errors
    ///
    /// Rejects a zero session generation.
    pub fn new(
        repository_identity: Digest32,
        selected_profile: Option<ProfileId>,
        session_generation: u64,
    ) -> Result<Self, ProtocolError> {
        let status = Self {
            repository_identity,
            selected_profile,
            session_generation,
        };
        status.validate()?;
        Ok(status)
    }
}

impl Validate for SelectionStatus {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_generation(self.session_generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum BrokerProviderMessage {
    Registered(RegistrationAccepted),
    SelectionPrompt(SelectionPrompt),
    Acknowledged,
    Error(BrokerError),
}

impl wire_message_seal::Sealed for BrokerProviderMessage {}

impl Validate for BrokerProviderMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Registered(accepted) => accepted.validate(),
            Self::SelectionPrompt(prompt) => prompt.validate(),
            Self::Acknowledged => Ok(()),
            Self::Error(error) => error.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationAccepted {
    registration_id: RequestId,
    provider_generation: u64,
    heartbeat_interval_millis: u32,
}

impl RegistrationAccepted {
    /// Creates a broker-owned provider registration response.
    ///
    /// # Errors
    ///
    /// Rejects zero generations and unreasonable heartbeat intervals.
    pub fn new(
        registration_id: RequestId,
        provider_generation: u64,
        heartbeat_interval_millis: u32,
    ) -> Result<Self, ProtocolError> {
        let response = Self {
            registration_id,
            provider_generation,
            heartbeat_interval_millis,
        };
        response.validate()?;
        Ok(response)
    }
}

impl Validate for RegistrationAccepted {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_generation(self.provider_generation)?;
        if !(1_000..=120_000).contains(&self.heartbeat_interval_millis) {
            return Err(ProtocolError::InvalidField {
                field: "heartbeat_interval_millis",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPrompt {
    registration_id: RequestId,
    selection_generation: u64,
    scope: SelectionScopePresentation,
    repository: RepositoryPresentation,
    operation: OperationPresentation,
    profiles: Vec<ProfilePresentation>,
    timeout_millis: u32,
}

impl SelectionPrompt {
    /// Creates a bounded, presentation-only selection prompt.
    ///
    /// # Errors
    ///
    /// Rejects empty/duplicate choices, invalid display text, zero generation,
    /// and timeouts outside the protocol envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: RequestId,
        selection_generation: u64,
        scope: SelectionScopePresentation,
        repository: RepositoryPresentation,
        operation: OperationPresentation,
        profiles: Vec<ProfilePresentation>,
        timeout_millis: u32,
    ) -> Result<Self, ProtocolError> {
        let prompt = Self {
            registration_id,
            selection_generation,
            scope,
            repository,
            operation,
            profiles,
            timeout_millis,
        };
        prompt.validate()?;
        Ok(prompt)
    }
}

impl Validate for SelectionPrompt {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_generation(self.selection_generation)?;
        self.repository.validate()?;
        if self.profiles.is_empty() || self.profiles.len() > MAX_PROFILE_CHOICES {
            return Err(ProtocolError::InvalidField { field: "profiles" });
        }
        if self.profiles.iter().enumerate().any(|(index, profile)| {
            self.profiles[index + 1..]
                .iter()
                .any(|candidate| candidate.profile_id == profile.profile_id)
        }) {
            return Err(ProtocolError::InvalidField { field: "profiles" });
        }
        if !(MIN_SELECTION_TIMEOUT_MILLIS..=MAX_SELECTION_TIMEOUT_MILLIS)
            .contains(&self.timeout_millis)
        {
            return Err(ProtocolError::InvalidField {
                field: "timeout_millis",
            });
        }
        for profile in &self.profiles {
            profile.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionScopePresentation {
    Terminal,
    IdeWindow,
    IdeTask,
    ExplicitAutomation,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPresentation {
    identity: Digest32,
    label: String,
}

impl RepositoryPresentation {
    /// Creates a sanitized UI label paired with a non-authoritative digest.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-containing, or excessively long labels.
    pub fn new(identity: Digest32, label: String) -> Result<Self, ProtocolError> {
        let value = Self { identity, label };
        value.validate()?;
        Ok(value)
    }
}

impl Validate for RepositoryPresentation {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("repository.label", &self.label, 1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePresentation {
    profile_id: ProfileId,
    display_name: String,
    email: Option<String>,
}

impl ProfilePresentation {
    /// Creates profile metadata safe to send to a presentation provider.
    /// Secrets, key paths, and credential backend identifiers are intentionally
    /// not representable.
    ///
    /// # Errors
    ///
    /// Rejects invalid display text or email presentation.
    pub fn new(
        profile_id: ProfileId,
        display_name: String,
        email: Option<String>,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            profile_id,
            display_name,
            email,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }
}

impl Validate for ProfilePresentation {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("profile.display_name", &self.display_name, 1)?;
        if let Some(email) = &self.email {
            validate_text("profile.email", email, 3)?;
            let mut parts = email.split('@');
            if parts.next().is_none_or(str::is_empty)
                || parts.next().is_none_or(str::is_empty)
                || parts.next().is_some()
                || email.contains(['<', '>', ' '])
            {
                return Err(ProtocolError::InvalidField {
                    field: "profile.email",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerError {
    code: ErrorCode,
    phase: ErrorPhase,
    retry: RetryDisposition,
    diagnostic_id: RequestId,
    real_git_started: bool,
    action: RemediationAction,
}

impl BrokerError {
    /// Creates a structured error without free-form context or secrets.
    ///
    /// # Errors
    ///
    /// Rejects a phase/real-Git-started contradiction.
    pub fn new(
        code: ErrorCode,
        phase: ErrorPhase,
        retry: RetryDisposition,
        diagnostic_id: RequestId,
        real_git_started: bool,
        action: RemediationAction,
    ) -> Result<Self, ProtocolError> {
        let error = Self {
            code,
            phase,
            retry,
            diagnostic_id,
            real_git_started,
            action,
        };
        error.validate()?;
        Ok(error)
    }
}

impl Validate for BrokerError {
    fn validate(&self) -> Result<(), ProtocolError> {
        if ((self.phase == ErrorPhase::Preflight || self.phase == ErrorPhase::Provider)
            && self.real_git_started)
            || (self.phase == ErrorPhase::DeferredHelper && !self.real_git_started)
        {
            return Err(ProtocolError::InvalidField {
                field: "real_git_started",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    GusEAmbiguousInvocation,
    GusEProfileRequired,
    GusEProfileInvalid,
    GusESelectionCancelled,
    GusESelectionTimeout,
    GusEProviderUnavailable,
    GusEBrokerUnavailable,
    GusEShimUnverified,
    GusERealGitChanged,
    GusEArtifactChanged,
    GusEHttpCredentialRequired,
    GusECredentialDenied,
    GusEHttpPreflightUnsupported,
    GusESshContextMismatch,
    GusECapabilityInvalid,
    GusECapabilityExpired,
    GusEBrokerCapacity,
    GusEProtocolMismatch,
    GusEVscodeReloadRequired,
    GusENoRemoteContext,
    GusEInstallReservationStale,
    GusEInstallRootConflict,
    GusEReconcileRequired,
    GusERollbackPending,
    GusEOwnedSettingConflict,
    GusEExtensionBlocked,
    GusEExtensionUntrusted,
    GusEExtensionInstallFailed,
    GusEUpdateInProgress,
    GusEUpdateRolledBack,
    GusEInternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPhase {
    Preflight,
    DeferredHelper,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    No,
    Immediate,
    AfterSelection,
    AfterRepair,
    AfterReload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    None,
    Retry,
    SelectProfile,
    SetExplicitProfile,
    RunDoctor,
    Repair,
    ReloadWindow,
    ContactAdministrator,
}

fn validate_generation(generation: u64) -> Result<(), ProtocolError> {
    if generation == 0 {
        Err(ProtocolError::InvalidField {
            field: "generation",
        })
    } else {
        Ok(())
    }
}

fn validate_text(
    field: &'static str,
    value: &str,
    minimum_chars: usize,
) -> Result<(), ProtocolError> {
    let character_count = value.chars().count();
    if character_count < minimum_chars
        || character_count > MAX_PRESENTATION_TEXT_CHARS
        || value.chars().any(is_forbidden_presentation_character)
    {
        return Err(ProtocolError::InvalidField { field });
    }
    Ok(())
}

fn is_forbidden_presentation_character(value: char) -> bool {
    value.is_control()
        || matches!(
            value,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn validate_unique_bounded<T: Eq>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), ProtocolError> {
    if values.len() > maximum
        || values
            .iter()
            .enumerate()
            .any(|(index, value)| values[index + 1..].contains(value))
    {
        return Err(ProtocolError::InvalidField { field });
    }
    Ok(())
}
