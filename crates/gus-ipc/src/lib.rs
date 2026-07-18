//! Versioned, bounded IPC messages shared by GUS native processes and IDE
//! providers.
//!
//! Wire values are untrusted presentation and correlation data. In particular,
//! this crate deliberately has no serializable peer identity, trusted session
//! scope, execution-plan lease, credential material, or capability type. The
//! broker must derive peer and process identity from the operating-system IPC
//! transport before using a decoded request.
//!
//! Provider request-ID transitions are fixed as follows:
//!
//! | Sender | Message | Request ID |
//! |---|---|---|
//! | provider | register/control command | fresh provider ID |
//! | broker | registered/ack/error response | command ID |
//! | broker | selection prompt | fresh broker ID |
//! | provider | selection decision | prompt ID, consumed once |
//! | broker | status snapshot | fresh broker ID |
//!
//! [`ProviderCorrelation`] is created only from a registration command and its
//! exact request-ID-correlated response. It additionally binds capabilities,
//! repository membership, selection decisions, and broker-owned monotonic
//! deadlines to that live registration generation. Timeout, membership
//! replacement, write failure, unregister, and disconnect APIs return the
//! exact outstanding IDs the broker must complete. Reconnect creates a new
//! correlation instance and invalidates all prior outstanding IDs.

mod codec;
mod ids;
mod messages;
mod provider_state;

pub use codec::{
    FRAME_HEADER_BYTES, MAX_FRAME_BYTES, decode_frame_length, decode_provider_request,
    decode_provider_response, decode_shim_request, decode_shim_response, encode_provider_request,
    encode_provider_response, encode_shim_request, encode_shim_response,
};
pub use ids::{Digest32, Generation, RequestId};
pub use messages::{
    BrokerError, BrokerProviderMessage, BrokerShimMessage, ClearSelectionRequest, ErrorCode,
    ErrorDetail, ErrorPhase, JournalErrorDetail, MessageFamily, OperationPresentation,
    PROTOCOL_VERSION, ProfilePresentation, ProtectionStatus, ProtocolError, ProtocolErrorDetail,
    ProviderCapability, ProviderControlRequest, ProviderDecision, ProviderErrorDetail,
    ProviderKind, ProviderRegistrationRequest, ProviderRepositoryMembership, ProviderRequest,
    ProviderRequestFrame, ProviderResponseFrame, ProviderSelectionDecision, ProviderStatusEntry,
    ProviderStatusSnapshot, RegistrationAccepted, RemediationAction, RepositoryPresentation,
    ResolveSelectionRequest, ResolvedSelection, RetryDisposition, ScopePresentation,
    SelectionPrompt, SelectionScopePresentation, SelectionStatus, ShimRequest, ShimRequestFrame,
    ShimResponseFrame, StatusRequest, WireFrame, WireMessage,
};
pub use provider_state::{ProviderCorrelation, ProviderCorrelationError, ProviderTerminationError};
