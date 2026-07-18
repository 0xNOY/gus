use std::fmt;

use gus_profile::ProfileId;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::{Digest32, Generation, RequestId};

pub const PROTOCOL_VERSION: u16 = 1;
const MAX_PRESENTATION_TEXT_BYTES: usize = 256;
const MAX_PROFILE_CHOICES: usize = 32;
const MAX_STATUS_ENTRIES: usize = 16;
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
    #[error("IPC record header or payload is incomplete")]
    IncompleteFrame,
    #[error("IPC record length does not match its payload")]
    FrameLengthMismatch,
    #[error("IPC frame is not valid canonical JSON for this direction")]
    InvalidJson,
    #[error("unsupported IPC protocol version {received}")]
    UnsupportedVersion { received: u16 },
    #[error("request id must be a nonzero canonical UUIDv4")]
    InvalidRequestId,
    #[error("digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("generation must be a nonzero canonical decimal u64 string")]
    InvalidGeneration,
    #[error("IPC field '{field}' is outside its allowed bounds")]
    InvalidField { field: &'static str },
    #[error("message cannot be used in this request/response role")]
    InvalidMessageRole,
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
    const FAMILY: MessageFamily;

    #[doc(hidden)]
    fn validate_wire_message(&self) -> Result<(), ProtocolError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageFamily {
    ShimRequest,
    ShimResponse,
    ProviderRequest,
    ProviderResponse,
}

/// A protocol frame. Its request ID is a correlation nonce, not an authority
/// token. The broker must additionally bind it to one authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireFrame<M> {
    protocol_version: u16,
    message_family: MessageFamily,
    request_id: RequestId,
    message: M,
}

impl<M: WireMessage> WireFrame<M> {
    fn build(request_id: RequestId, message: M) -> Result<Self, ProtocolError> {
        message.validate_wire_message()?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            message_family: M::FAMILY,
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
        if self.message_family != M::FAMILY {
            return Err(ProtocolError::InvalidField {
                field: "message_family",
            });
        }
        self.message.validate_wire_message()
    }

    pub(crate) const fn from_wire(
        protocol_version: u16,
        message_family: MessageFamily,
        request_id: RequestId,
        message: M,
    ) -> Self {
        Self {
            protocol_version,
            message_family,
            request_id,
            message,
        }
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub const fn message_family(&self) -> MessageFamily {
        self.message_family
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

impl ShimRequestFrame {
    /// Creates a new shim command with an OS-random request ID.
    ///
    /// # Errors
    ///
    /// Rejects invalid content or unavailable secure randomness.
    pub fn request(message: ShimRequest) -> Result<Self, ProtocolError> {
        Self::build(RequestId::generate()?, message)
    }
}

impl ShimResponseFrame {
    /// Creates the one response correlated to a shim request.
    ///
    /// # Errors
    ///
    /// Rejects invalid response content.
    pub fn response(
        request_id: RequestId,
        message: BrokerShimMessage,
    ) -> Result<Self, ProtocolError> {
        Self::build(request_id, message)
    }
}

impl ProviderRequestFrame {
    /// Creates a provider-originated registration command.
    ///
    /// # Errors
    ///
    /// Rejects invalid registration content or unavailable secure randomness.
    pub fn registration(request: ProviderRegistrationRequest) -> Result<Self, ProtocolError> {
        Self::build(RequestId::generate()?, ProviderRequest::Register(request))
    }

    /// Creates a provider-originated post-registration control command.
    ///
    /// # Errors
    ///
    /// Rejects registration/decision roles or unavailable secure randomness.
    pub fn control(message: ProviderRequest) -> Result<Self, ProtocolError> {
        if matches!(
            message,
            ProviderRequest::Register(_) | ProviderRequest::SelectionDecision(_)
        ) {
            return Err(ProtocolError::InvalidMessageRole);
        }
        Self::build(RequestId::generate()?, message)
    }

    /// Creates a one-shot response correlated to a broker selection prompt.
    ///
    /// # Errors
    ///
    /// Rejects invalid response content.
    pub fn selection_response(
        prompt_id: RequestId,
        decision: ProviderSelectionDecision,
    ) -> Result<Self, ProtocolError> {
        Self::build(prompt_id, ProviderRequest::SelectionDecision(decision))
    }
}

impl ProviderResponseFrame {
    /// Creates the broker response correlated to a registration command.
    ///
    /// # Errors
    ///
    /// Rejects invalid registration content.
    pub fn registration_response(
        request_id: RequestId,
        accepted: RegistrationAccepted,
    ) -> Result<Self, ProtocolError> {
        Self::build(request_id, BrokerProviderMessage::Registered(accepted))
    }

    /// Creates an acknowledgement correlated to a provider control command.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing state.
    pub fn acknowledgement(request_id: RequestId) -> Result<Self, ProtocolError> {
        Self::build(request_id, BrokerProviderMessage::Acknowledged)
    }

    /// Creates an error response correlated to any provider command.
    ///
    /// # Errors
    ///
    /// Rejects an invalid catalog error.
    pub fn error_response(
        request_id: RequestId,
        error: BrokerError,
    ) -> Result<Self, ProtocolError> {
        Self::build(request_id, BrokerProviderMessage::Error(error))
    }

    /// Creates a broker-originated selection prompt with a fresh request ID.
    ///
    /// # Errors
    ///
    /// Rejects invalid prompt content or unavailable secure randomness.
    pub fn selection_prompt(prompt: SelectionPrompt) -> Result<Self, ProtocolError> {
        Self::build(
            RequestId::generate()?,
            BrokerProviderMessage::SelectionPrompt(prompt),
        )
    }

    /// Creates a broker-originated scoped status snapshot with a fresh request ID.
    ///
    /// # Errors
    ///
    /// Rejects invalid status content or unavailable secure randomness.
    pub fn status_snapshot(snapshot: ProviderStatusSnapshot) -> Result<Self, ProtocolError> {
        Self::build(
            RequestId::generate()?,
            BrokerProviderMessage::StatusSnapshot(snapshot),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "body",
    rename_all = "snake_case"
)]
pub enum ShimRequest {
    ResolveSelection(ResolveSelectionRequest),
    ClearSelection(ClearSelectionRequest),
    Status(StatusRequest),
}

impl wire_message_seal::Sealed for ShimRequest {}

impl WireMessage for ShimRequest {
    const FAMILY: MessageFamily = MessageFamily::ShimRequest;

    fn validate_wire_message(&self) -> Result<(), ProtocolError> {
        self.validate()
    }
}

impl Validate for ShimRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ResolveSelection(request) => request.validate(),
            Self::ClearSelection(request) => request.validate(),
            Self::Status(request) => request.validate(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveSelectionRequest {
    plan_digest: Digest32,
    repository_identity: Digest32,
    operation: OperationPresentation,
    explicit_profile: Option<ProfileId>,
}

impl ResolveSelectionRequest {
    #[must_use]
    pub const fn new(
        plan_digest: Digest32,
        repository_identity: Digest32,
        operation: OperationPresentation,
        explicit_profile: Option<ProfileId>,
    ) -> Self {
        Self {
            plan_digest,
            repository_identity,
            operation,
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
    pub const fn explicit_profile(&self) -> Option<&ProfileId> {
        self.explicit_profile.as_ref()
    }
}

impl Validate for ResolveSelectionRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        // Interaction eligibility is intentionally absent from the wire. The
        // platform broker derives it from the authenticated peer/session.
        Ok(())
    }
}

impl fmt::Debug for ResolveSelectionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveSelectionRequest")
            .field("plan_digest", &self.plan_digest)
            .field("repository_identity", &self.repository_identity)
            .field("operation", &self.operation)
            .field(
                "explicit_profile",
                &self.explicit_profile.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSelectionRequest {
    repository_identity: Digest32,
    expected_session_generation: Option<Generation>,
}

impl ClearSelectionRequest {
    #[must_use]
    pub const fn new(
        repository_identity: Digest32,
        expected_session_generation: Option<Generation>,
    ) -> Self {
        Self {
            repository_identity,
            expected_session_generation,
        }
    }

    #[must_use]
    pub const fn repository_identity(&self) -> Digest32 {
        self.repository_identity
    }

    #[must_use]
    pub const fn expected_session_generation(&self) -> Option<Generation> {
        self.expected_session_generation
    }
}

impl Validate for ClearSelectionRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
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

    #[must_use]
    pub const fn repository_identity(&self) -> Digest32 {
        self.repository_identity
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "body",
    rename_all = "snake_case"
)]
pub enum ProviderRequest {
    Register(ProviderRegistrationRequest),
    Heartbeat(ProviderControlRequest),
    SubscribeStatus(ProviderControlRequest),
    UpdateRepositories(ProviderRepositoryMembership),
    SelectionDecision(ProviderSelectionDecision),
    Unregister(ProviderControlRequest),
}

impl wire_message_seal::Sealed for ProviderRequest {}

impl WireMessage for ProviderRequest {
    const FAMILY: MessageFamily = MessageFamily::ProviderRequest;

    fn validate_wire_message(&self) -> Result<(), ProtocolError> {
        self.validate()
    }
}

impl Validate for ProviderRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Register(request) => request.validate(),
            Self::Heartbeat(request)
            | Self::SubscribeStatus(request)
            | Self::Unregister(request) => request.validate(),
            Self::UpdateRepositories(request) => request.validate(),
            Self::SelectionDecision(decision) => decision.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlRequest {
    registration_id: RequestId,
    provider_generation: Generation,
}

impl ProviderControlRequest {
    #[must_use]
    pub const fn new(registration_id: RequestId, provider_generation: Generation) -> Self {
        Self {
            registration_id,
            provider_generation,
        }
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }
}

impl Validate for ProviderControlRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderRepositoryMembership {
    registration_id: RequestId,
    provider_generation: Generation,
    membership_generation: Generation,
    repositories: Vec<Digest32>,
}

impl ProviderRepositoryMembership {
    /// Creates a complete replacement for the provider's repository membership.
    ///
    /// # Errors
    ///
    /// Rejects duplicate or excessive repository hints.
    pub fn new(
        registration_id: RequestId,
        provider_generation: Generation,
        membership_generation: Generation,
        repositories: Vec<Digest32>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            registration_id,
            provider_generation,
            membership_generation,
            repositories,
        };
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    #[must_use]
    pub const fn membership_generation(&self) -> Generation {
        self.membership_generation
    }

    #[must_use]
    pub fn repositories(&self) -> &[Digest32] {
        &self.repositories
    }
}

impl Validate for ProviderRepositoryMembership {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_unique_bounded(
            "repositories",
            &self.repositories,
            MAX_PROVIDER_REPOSITORIES,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
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

    #[must_use]
    pub const fn host_instance(&self) -> Digest32 {
        self.host_instance
    }

    #[must_use]
    pub fn repositories(&self) -> &[Digest32] {
        &self.repositories
    }

    #[must_use]
    pub fn capabilities(&self) -> &[ProviderCapability] {
        &self.capabilities
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

impl fmt::Debug for ProviderRegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRegistrationRequest")
            .field("kind", &self.kind)
            .field("editor_session_id", &"<redacted>")
            .field("host_instance", &self.host_instance)
            .field("repository_count", &self.repositories.len())
            .field("capabilities", &self.capabilities)
            .finish()
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
    provider_generation: Generation,
    selection_generation: Generation,
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
        provider_generation: Generation,
        selection_generation: Generation,
        decision: ProviderDecision,
    ) -> Result<Self, ProtocolError> {
        let response = Self {
            registration_id,
            provider_generation,
            selection_generation,
            decision,
        };
        response.validate()?;
        Ok(response)
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    #[must_use]
    pub const fn selection_generation(&self) -> Generation {
        self.selection_generation
    }

    #[must_use]
    pub const fn decision(&self) -> &ProviderDecision {
        &self.decision
    }
}

impl Validate for ProviderSelectionDecision {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "result",
    content = "profile_id",
    rename_all = "snake_case"
)]
pub enum ProviderDecision {
    Selected(ProfileId),
    Cancelled,
    Unavailable,
}

impl fmt::Debug for ProviderDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(_) => formatter.write_str("Selected(<redacted>)"),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::Unavailable => formatter.write_str("Unavailable"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "body",
    rename_all = "snake_case"
)]
pub enum BrokerShimMessage {
    Resolved(ResolvedSelection),
    Cleared { session_generation: Generation },
    Status(SelectionStatus),
    Error(BrokerError),
}

impl wire_message_seal::Sealed for BrokerShimMessage {}

impl WireMessage for BrokerShimMessage {
    const FAMILY: MessageFamily = MessageFamily::ShimResponse;

    fn validate_wire_message(&self) -> Result<(), ProtocolError> {
        self.validate()
    }
}

impl Validate for BrokerShimMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Resolved(response) => response.validate(),
            Self::Cleared { .. } => Ok(()),
            Self::Status(status) => status.validate(),
            Self::Error(error) => error.validate(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSelection {
    profile_id: ProfileId,
    profile_generation: Generation,
    session_generation: Generation,
}

impl ResolvedSelection {
    /// Creates a response after broker-side profile and session validation.
    ///
    /// # Errors
    ///
    /// Rejects zero generations.
    pub fn new(
        profile_id: ProfileId,
        profile_generation: Generation,
        session_generation: Generation,
    ) -> Result<Self, ProtocolError> {
        let response = Self {
            profile_id,
            profile_generation,
            session_generation,
        };
        response.validate()?;
        Ok(response)
    }

    #[must_use]
    pub const fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    #[must_use]
    pub const fn profile_generation(&self) -> Generation {
        self.profile_generation
    }

    #[must_use]
    pub const fn session_generation(&self) -> Generation {
        self.session_generation
    }
}

impl Validate for ResolvedSelection {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl fmt::Debug for ResolvedSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSelection")
            .field("profile_id", &"<redacted>")
            .field("profile_generation", &self.profile_generation)
            .field("session_generation", &self.session_generation)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionStatus {
    repository_identity: Digest32,
    selected_profile: Option<ProfileId>,
    session_generation: Generation,
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
        session_generation: Generation,
    ) -> Result<Self, ProtocolError> {
        let status = Self {
            repository_identity,
            selected_profile,
            session_generation,
        };
        status.validate()?;
        Ok(status)
    }

    #[must_use]
    pub const fn repository_identity(&self) -> Digest32 {
        self.repository_identity
    }

    #[must_use]
    pub const fn selected_profile(&self) -> Option<&ProfileId> {
        self.selected_profile.as_ref()
    }

    #[must_use]
    pub const fn session_generation(&self) -> Generation {
        self.session_generation
    }
}

impl Validate for SelectionStatus {
    fn validate(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl fmt::Debug for SelectionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectionStatus")
            .field("repository_identity", &self.repository_identity)
            .field(
                "selected_profile",
                &self.selected_profile.as_ref().map(|_| "<redacted>"),
            )
            .field("session_generation", &self.session_generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "body",
    rename_all = "snake_case"
)]
pub enum BrokerProviderMessage {
    Registered(RegistrationAccepted),
    SelectionPrompt(SelectionPrompt),
    StatusSnapshot(ProviderStatusSnapshot),
    Acknowledged,
    Error(BrokerError),
}

impl wire_message_seal::Sealed for BrokerProviderMessage {}

impl WireMessage for BrokerProviderMessage {
    const FAMILY: MessageFamily = MessageFamily::ProviderResponse;

    fn validate_wire_message(&self) -> Result<(), ProtocolError> {
        self.validate()
    }
}

impl Validate for BrokerProviderMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Registered(accepted) => accepted.validate(),
            Self::SelectionPrompt(prompt) => prompt.validate(),
            Self::StatusSnapshot(snapshot) => snapshot.validate(),
            Self::Acknowledged => Ok(()),
            Self::Error(error) => error.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrationAccepted {
    registration_id: RequestId,
    provider_generation: Generation,
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
        provider_generation: Generation,
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

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    #[must_use]
    pub const fn heartbeat_interval_millis(&self) -> u32 {
        self.heartbeat_interval_millis
    }
}

impl Validate for RegistrationAccepted {
    fn validate(&self) -> Result<(), ProtocolError> {
        if !(1_000..=120_000).contains(&self.heartbeat_interval_millis) {
            return Err(ProtocolError::InvalidField {
                field: "heartbeat_interval_millis",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectionPrompt {
    registration_id: RequestId,
    provider_generation: Generation,
    selection_generation: Generation,
    scope: ScopePresentation,
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
        provider_generation: Generation,
        selection_generation: Generation,
        scope: ScopePresentation,
        repository: RepositoryPresentation,
        operation: OperationPresentation,
        profiles: Vec<ProfilePresentation>,
        timeout_millis: u32,
    ) -> Result<Self, ProtocolError> {
        let prompt = Self {
            registration_id,
            provider_generation,
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

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    #[must_use]
    pub const fn selection_generation(&self) -> Generation {
        self.selection_generation
    }

    #[must_use]
    pub const fn scope(&self) -> &ScopePresentation {
        &self.scope
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryPresentation {
        &self.repository
    }

    #[must_use]
    pub const fn operation(&self) -> OperationPresentation {
        self.operation
    }

    #[must_use]
    pub fn profiles(&self) -> &[ProfilePresentation] {
        &self.profiles
    }

    #[must_use]
    pub const fn timeout_millis(&self) -> u32 {
        self.timeout_millis
    }
}

impl Validate for SelectionPrompt {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.repository.validate()?;
        self.scope.validate()?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionScopePresentation {
    Terminal,
    IdeWindow,
    IdeTask,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ScopePresentation {
    kind: SelectionScopePresentation,
    opaque_id: Digest32,
    label: String,
}

impl ScopePresentation {
    /// Creates a display-only scope reference. Its digest is broker-derived but
    /// is not an authority token on the provider wire.
    ///
    /// # Errors
    ///
    /// Rejects an invalid display label.
    pub fn new(
        kind: SelectionScopePresentation,
        opaque_id: Digest32,
        label: String,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            kind,
            opaque_id,
            label,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn kind(&self) -> SelectionScopePresentation {
        self.kind
    }

    #[must_use]
    pub const fn opaque_id(&self) -> Digest32 {
        self.opaque_id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Validate for ScopePresentation {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("scope.label", &self.label, 1)
    }
}

impl fmt::Debug for ScopePresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopePresentation")
            .field("kind", &self.kind)
            .field("opaque_id", &self.opaque_id)
            .field("label", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderStatusSnapshot {
    registration_id: RequestId,
    provider_generation: Generation,
    entries: Vec<ProviderStatusEntry>,
}

impl ProviderStatusSnapshot {
    /// Creates one complete, scoped status snapshot for a live provider.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate scope/repository entries.
    pub fn new(
        registration_id: RequestId,
        provider_generation: Generation,
        entries: Vec<ProviderStatusEntry>,
    ) -> Result<Self, ProtocolError> {
        let snapshot = Self {
            registration_id,
            provider_generation,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub const fn registration_id(&self) -> RequestId {
        self.registration_id
    }

    #[must_use]
    pub const fn provider_generation(&self) -> Generation {
        self.provider_generation
    }

    #[must_use]
    pub fn entries(&self) -> &[ProviderStatusEntry] {
        &self.entries
    }
}

impl Validate for ProviderStatusSnapshot {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.entries.len() > MAX_STATUS_ENTRIES {
            return Err(ProtocolError::InvalidField { field: "entries" });
        }
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if self.entries[index + 1..].iter().any(|candidate| {
                candidate.scope.opaque_id == entry.scope.opaque_id
                    && candidate.repository.identity == entry.repository.identity
            }) {
                return Err(ProtocolError::InvalidField { field: "entries" });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderStatusEntry {
    scope: ScopePresentation,
    repository: RepositoryPresentation,
    selected_profile: Option<ProfilePresentation>,
    protection: ProtectionStatus,
}

impl ProviderStatusEntry {
    /// Creates one independently rendered SCM, terminal, or task status row.
    ///
    /// # Errors
    ///
    /// Rejects invalid nested presentation data.
    pub fn new(
        scope: ScopePresentation,
        repository: RepositoryPresentation,
        selected_profile: Option<ProfilePresentation>,
        protection: ProtectionStatus,
    ) -> Result<Self, ProtocolError> {
        let entry = Self {
            scope,
            repository,
            selected_profile,
            protection,
        };
        entry.validate()?;
        Ok(entry)
    }

    #[must_use]
    pub const fn scope(&self) -> &ScopePresentation {
        &self.scope
    }

    #[must_use]
    pub const fn repository(&self) -> &RepositoryPresentation {
        &self.repository
    }

    #[must_use]
    pub const fn selected_profile(&self) -> Option<&ProfilePresentation> {
        self.selected_profile.as_ref()
    }

    #[must_use]
    pub const fn protection(&self) -> ProtectionStatus {
        self.protection
    }
}

impl Validate for ProviderStatusEntry {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.scope.validate()?;
        self.repository.validate()?;
        if let Some(profile) = &self.selected_profile {
            profile.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStatus {
    Verified,
    Unverified,
    Unavailable,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
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

    #[must_use]
    pub const fn identity(&self) -> Digest32 {
        self.identity
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Validate for RepositoryPresentation {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("repository.label", &self.label, 1)
    }
}

impl fmt::Debug for RepositoryPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryPresentation")
            .field("identity", &self.identity)
            .field("label", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
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

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
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

impl fmt::Debug for ProfilePresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfilePresentation")
            .field("profile_id", &"<redacted>")
            .field("display_name", &"<redacted>")
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrokerError {
    code: ErrorCode,
    phase: ErrorPhase,
    retry: RetryDisposition,
    diagnostic_id: RequestId,
    real_git_started: bool,
    action: RemediationAction,
    detail: ErrorDetail,
}

impl BrokerError {
    /// Creates a structured error without free-form context or secrets.
    ///
    /// # Errors
    ///
    /// Rejects a phase or typed-detail combination not defined by the catalog.
    pub fn new(
        code: ErrorCode,
        phase: ErrorPhase,
        diagnostic_id: RequestId,
        detail: ErrorDetail,
    ) -> Result<Self, ProtocolError> {
        let contract = code
            .contract(phase)
            .ok_or(ProtocolError::InvalidField { field: "phase" })?;
        let error = Self {
            code,
            phase,
            retry: contract.retry,
            diagnostic_id,
            real_git_started: phase == ErrorPhase::DeferredHelper,
            action: contract.action,
            detail,
        };
        error.validate()?;
        Ok(error)
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub const fn phase(&self) -> ErrorPhase {
        self.phase
    }

    #[must_use]
    pub const fn retry(&self) -> RetryDisposition {
        self.retry
    }

    #[must_use]
    pub const fn diagnostic_id(&self) -> RequestId {
        self.diagnostic_id
    }

    #[must_use]
    pub const fn real_git_started(&self) -> bool {
        self.real_git_started
    }

    #[must_use]
    pub const fn action(&self) -> RemediationAction {
        self.action
    }

    #[must_use]
    pub const fn detail(&self) -> &ErrorDetail {
        &self.detail
    }
}

impl Validate for BrokerError {
    fn validate(&self) -> Result<(), ProtocolError> {
        let contract = self
            .code
            .contract(self.phase)
            .ok_or(ProtocolError::InvalidField { field: "phase" })?;
        if self.retry != contract.retry
            || self.action != contract.action
            || self.real_git_started != (self.phase == ErrorPhase::DeferredHelper)
        {
            return Err(ProtocolError::InvalidField {
                field: "error_contract",
            });
        }
        if !self.code.accepts_detail(&self.detail) {
            return Err(ProtocolError::InvalidField {
                field: "error.detail",
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

#[derive(Clone, Copy)]
struct ErrorContract {
    retry: RetryDisposition,
    action: RemediationAction,
}

impl ErrorCode {
    fn contract(self, phase: ErrorPhase) -> Option<ErrorContract> {
        use ErrorCode::{
            GusEAmbiguousInvocation, GusEArtifactChanged, GusEBrokerCapacity,
            GusEBrokerUnavailable, GusECapabilityExpired, GusECapabilityInvalid,
            GusECredentialDenied, GusEExtensionBlocked, GusEExtensionInstallFailed,
            GusEExtensionUntrusted, GusEHttpCredentialRequired, GusEHttpPreflightUnsupported,
            GusEInstallReservationStale, GusEInstallRootConflict, GusEInternal,
            GusENoRemoteContext, GusEOwnedSettingConflict, GusEProfileInvalid, GusEProfileRequired,
            GusEProtocolMismatch, GusEProviderUnavailable, GusERealGitChanged,
            GusEReconcileRequired, GusERollbackPending, GusESelectionCancelled,
            GusESelectionTimeout, GusEShimUnverified, GusESshContextMismatch, GusEUpdateInProgress,
            GusEUpdateRolledBack, GusEVscodeReloadRequired,
        };
        use RemediationAction::{
            ContactAdministrator, CorrectInvocation, ReloadWindow, Repair, Retry, RunDoctor,
            SelectProfile,
        };
        use RetryDisposition::{
            AfterCorrection, AfterReload, AfterRepair, AfterSelection, Immediate, No,
        };

        let preflight_only = phase == ErrorPhase::Preflight;
        let deferred_only = phase == ErrorPhase::DeferredHelper;
        let contract = match self {
            GusEAmbiguousInvocation if preflight_only => ErrorContract {
                retry: AfterCorrection,
                action: CorrectInvocation,
            },
            GusEProfileRequired if preflight_only => ErrorContract {
                retry: AfterSelection,
                action: SelectProfile,
            },
            GusEProfileInvalid | GusEProviderUnavailable => ErrorContract {
                retry: AfterRepair,
                action: RunDoctor,
            },
            GusECapabilityInvalid => ErrorContract {
                retry: No,
                action: RunDoctor,
            },
            GusEInternal if preflight_only => ErrorContract {
                retry: No,
                action: RunDoctor,
            },
            GusESelectionCancelled
            | GusESelectionTimeout
            | GusEBrokerUnavailable
            | GusECapabilityExpired => ErrorContract {
                retry: Immediate,
                action: Retry,
            },
            GusEShimUnverified | GusERealGitChanged | GusEProtocolMismatch if preflight_only => {
                ErrorContract {
                    retry: AfterRepair,
                    action: Repair,
                }
            }
            GusEArtifactChanged
            | GusEHttpPreflightUnsupported
            | GusEInstallReservationStale
            | GusEInstallRootConflict
            | GusENoRemoteContext
            | GusEOwnedSettingConflict
            | GusEExtensionInstallFailed
            | GusEUpdateRolledBack
                if preflight_only =>
            {
                ErrorContract {
                    retry: AfterRepair,
                    action: RunDoctor,
                }
            }
            GusEHttpCredentialRequired if deferred_only => ErrorContract {
                retry: AfterSelection,
                action: SelectProfile,
            },
            GusECredentialDenied | GusESshContextMismatch if deferred_only => ErrorContract {
                retry: AfterRepair,
                action: RunDoctor,
            },
            GusEBrokerCapacity | GusEReconcileRequired | GusEUpdateInProgress if preflight_only => {
                ErrorContract {
                    retry: Immediate,
                    action: Retry,
                }
            }
            GusEVscodeReloadRequired if preflight_only => ErrorContract {
                retry: AfterReload,
                action: ReloadWindow,
            },
            GusERollbackPending | GusEExtensionUntrusted if preflight_only => ErrorContract {
                retry: AfterRepair,
                action: Repair,
            },
            GusEExtensionBlocked if preflight_only => ErrorContract {
                retry: AfterRepair,
                action: ContactAdministrator,
            },
            _ => return None,
        };
        Some(contract)
    }

    fn accepts_detail(self, detail: &ErrorDetail) -> bool {
        match self {
            Self::GusEProtocolMismatch => matches!(
                detail,
                ErrorDetail::Protocol(detail)
                    if detail.expected == PROTOCOL_VERSION
                        && detail.received != detail.expected
            ),
            Self::GusEInstallReservationStale
            | Self::GusERollbackPending
            | Self::GusEUpdateRolledBack => matches!(detail, ErrorDetail::Journal(_)),
            Self::GusEVscodeReloadRequired | Self::GusENoRemoteContext => matches!(
                detail,
                ErrorDetail::Provider(detail) if detail.provider == ProviderKind::Vscode
            ),
            Self::GusEExtensionBlocked
            | Self::GusEExtensionUntrusted
            | Self::GusEExtensionInstallFailed => matches!(detail, ErrorDetail::Provider(_)),
            _ => matches!(detail, ErrorDetail::None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPhase {
    Preflight,
    DeferredHelper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    No,
    Immediate,
    AfterCorrection,
    AfterSelection,
    AfterRepair,
    AfterReload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    None,
    Retry,
    CorrectInvocation,
    SelectProfile,
    SetExplicitProfile,
    RunDoctor,
    Repair,
    ReloadWindow,
    ContactAdministrator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "body",
    rename_all = "snake_case"
)]
pub enum ErrorDetail {
    None,
    Provider(ProviderErrorDetail),
    Journal(JournalErrorDetail),
    Protocol(ProtocolErrorDetail),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderErrorDetail {
    provider: ProviderKind,
}

impl ProviderErrorDetail {
    #[must_use]
    pub const fn new(provider: ProviderKind) -> Self {
        Self { provider }
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderKind {
        self.provider
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalErrorDetail {
    journal_id: RequestId,
}

impl JournalErrorDetail {
    #[must_use]
    pub const fn new(journal_id: RequestId) -> Self {
        Self { journal_id }
    }

    #[must_use]
    pub const fn journal_id(&self) -> RequestId {
        self.journal_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolErrorDetail {
    expected: u16,
    received: u16,
}

impl ProtocolErrorDetail {
    #[must_use]
    pub const fn new(expected: u16, received: u16) -> Self {
        Self { expected, received }
    }

    #[must_use]
    pub const fn expected(&self) -> u16 {
        self.expected
    }

    #[must_use]
    pub const fn received(&self) -> u16 {
        self.received
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderRegistrationRequest {
    kind: ProviderKind,
    editor_session_id: String,
    host_instance: Digest32,
    repositories: Vec<Digest32>,
    capabilities: Vec<ProviderCapability>,
}

impl<'de> Deserialize<'de> for ProviderRegistrationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProviderRegistrationRequest::deserialize(deserializer)?;
        Self::new(
            raw.kind,
            raw.editor_session_id,
            raw.host_instance,
            raw.repositories,
            raw.capabilities,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderRepositoryMembership {
    registration_id: RequestId,
    provider_generation: Generation,
    membership_generation: Generation,
    repositories: Vec<Digest32>,
}

impl<'de> Deserialize<'de> for ProviderRepositoryMembership {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProviderRepositoryMembership::deserialize(deserializer)?;
        Self::new(
            raw.registration_id,
            raw.provider_generation,
            raw.membership_generation,
            raw.repositories,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistrationAccepted {
    registration_id: RequestId,
    provider_generation: Generation,
    heartbeat_interval_millis: u32,
}

impl<'de> Deserialize<'de> for RegistrationAccepted {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRegistrationAccepted::deserialize(deserializer)?;
        Self::new(
            raw.registration_id,
            raw.provider_generation,
            raw.heartbeat_interval_millis,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelectionPrompt {
    registration_id: RequestId,
    provider_generation: Generation,
    selection_generation: Generation,
    scope: ScopePresentation,
    repository: RepositoryPresentation,
    operation: OperationPresentation,
    profiles: Vec<ProfilePresentation>,
    timeout_millis: u32,
}

impl<'de> Deserialize<'de> for SelectionPrompt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSelectionPrompt::deserialize(deserializer)?;
        Self::new(
            raw.registration_id,
            raw.provider_generation,
            raw.selection_generation,
            raw.scope,
            raw.repository,
            raw.operation,
            raw.profiles,
            raw.timeout_millis,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScopePresentation {
    kind: SelectionScopePresentation,
    opaque_id: Digest32,
    label: String,
}

impl<'de> Deserialize<'de> for ScopePresentation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawScopePresentation::deserialize(deserializer)?;
        Self::new(raw.kind, raw.opaque_id, raw.label).map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderStatusSnapshot {
    registration_id: RequestId,
    provider_generation: Generation,
    entries: Vec<ProviderStatusEntry>,
}

impl<'de> Deserialize<'de> for ProviderStatusSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProviderStatusSnapshot::deserialize(deserializer)?;
        Self::new(raw.registration_id, raw.provider_generation, raw.entries)
            .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderStatusEntry {
    scope: ScopePresentation,
    repository: RepositoryPresentation,
    selected_profile: Option<ProfilePresentation>,
    protection: ProtectionStatus,
}

impl<'de> Deserialize<'de> for ProviderStatusEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProviderStatusEntry::deserialize(deserializer)?;
        Self::new(
            raw.scope,
            raw.repository,
            raw.selected_profile,
            raw.protection,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepositoryPresentation {
    identity: Digest32,
    label: String,
}

impl<'de> Deserialize<'de> for RepositoryPresentation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRepositoryPresentation::deserialize(deserializer)?;
        Self::new(raw.identity, raw.label).map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfilePresentation {
    profile_id: ProfileId,
    display_name: String,
    email: Option<String>,
}

impl<'de> Deserialize<'de> for ProfilePresentation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProfilePresentation::deserialize(deserializer)?;
        Self::new(raw.profile_id, raw.display_name, raw.email).map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBrokerError {
    code: ErrorCode,
    phase: ErrorPhase,
    retry: RetryDisposition,
    diagnostic_id: RequestId,
    real_git_started: bool,
    action: RemediationAction,
    detail: ErrorDetail,
}

impl<'de> Deserialize<'de> for BrokerError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawBrokerError::deserialize(deserializer)?;
        let error = Self {
            code: raw.code,
            phase: raw.phase,
            retry: raw.retry,
            diagnostic_id: raw.diagnostic_id,
            real_git_started: raw.real_git_started,
            action: raw.action,
            detail: raw.detail,
        };
        error.validate().map_err(de::Error::custom)?;
        Ok(error)
    }
}

fn validate_text(
    field: &'static str,
    value: &str,
    minimum_chars: usize,
) -> Result<(), ProtocolError> {
    let character_count = value.chars().count();
    if character_count < minimum_chars
        || value.len() > MAX_PRESENTATION_TEXT_BYTES
        || value.chars().any(is_forbidden_presentation_character)
    {
        return Err(ProtocolError::InvalidField { field });
    }
    Ok(())
}

fn is_forbidden_presentation_character(value: char) -> bool {
    // Pinned to Unicode 17.0 Default_Ignorable_Code_Point plus all assigned
    // General_Category=Format (Cf) characters. Presentation labels are
    // identifiers in security-sensitive choice UI, so unsupported formatting
    // semantics are rejected rather than rendered ambiguously.
    value.is_control()
        || matches!(
            value,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
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
