//! Versioned, bounded IPC messages shared by GUS native processes and IDE
//! providers.
//!
//! Wire values are untrusted presentation and correlation data. In particular,
//! this crate deliberately has no serializable peer identity, trusted session
//! scope, execution-plan lease, credential material, or capability type. The
//! broker must derive peer and process identity from the operating-system IPC
//! transport before using a decoded request.

mod codec;
mod ids;
mod messages;

pub use codec::{
    MAX_FRAME_BYTES, decode_provider_request, decode_provider_response, decode_shim_request,
    decode_shim_response, encode_provider_request, encode_provider_response, encode_shim_request,
    encode_shim_response,
};
pub use ids::{Digest32, RequestId};
pub use messages::{
    BrokerError, BrokerProviderMessage, BrokerShimMessage, ClearSelectionRequest, ErrorCode,
    ErrorPhase, InteractionMode, OperationPresentation, PROTOCOL_VERSION, ProfilePresentation,
    ProtocolError, ProviderCapability, ProviderDecision, ProviderKind, ProviderRegistrationRequest,
    ProviderRequest, ProviderRequestFrame, ProviderResponseFrame, ProviderSelectionDecision,
    RegistrationAccepted, RemediationAction, RepositoryPresentation, ResolveSelectionRequest,
    ResolvedSelection, RetryDisposition, SelectionPrompt, SelectionScopePresentation,
    SelectionStatus, ShimRequest, ShimRequestFrame, ShimResponseFrame, StatusRequest, WireFrame,
    WireMessage,
};
