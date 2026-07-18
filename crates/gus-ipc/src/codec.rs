use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::messages::{
    BrokerProviderMessage, BrokerShimMessage, ProtocolError, ProviderRequest, ProviderRequestFrame,
    ProviderResponseFrame, ShimRequest, ShimRequestFrame, ShimResponseFrame, WireFrame,
    WireMessage,
};

/// Maximum JSON payload accepted before transport framing overhead.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWireFrame<M> {
    protocol_version: u16,
    request_id: crate::RequestId,
    message: M,
}

/// Decodes and validates a shim-to-broker protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_shim_request(bytes: &[u8]) -> Result<ShimRequestFrame, ProtocolError> {
    decode(bytes)
}

/// Decodes and validates a broker-to-shim protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_shim_response(bytes: &[u8]) -> Result<ShimResponseFrame, ProtocolError> {
    decode(bytes)
}

/// Decodes and validates a provider-to-broker protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_provider_request(bytes: &[u8]) -> Result<ProviderRequestFrame, ProtocolError> {
    decode(bytes)
}

/// Decodes and validates a broker-to-provider protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_provider_response(bytes: &[u8]) -> Result<ProviderResponseFrame, ProtocolError> {
    decode(bytes)
}

/// Encodes a validated shim-to-broker protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_shim_request(frame: &ShimRequestFrame) -> Result<Vec<u8>, ProtocolError> {
    encode(frame)
}

/// Encodes a validated broker-to-shim protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_shim_response(frame: &ShimResponseFrame) -> Result<Vec<u8>, ProtocolError> {
    encode(frame)
}

/// Encodes a validated provider-to-broker protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_provider_request(frame: &ProviderRequestFrame) -> Result<Vec<u8>, ProtocolError> {
    encode(frame)
}

/// Encodes a validated broker-to-provider protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_provider_response(frame: &ProviderResponseFrame) -> Result<Vec<u8>, ProtocolError> {
    encode(frame)
}

fn decode<M>(bytes: &[u8]) -> Result<WireFrame<M>, ProtocolError>
where
    M: DeserializeOwned + WireMessage,
{
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = RawWireFrame::<M>::deserialize(&mut deserializer)
        .map_err(|_| ProtocolError::InvalidJson)?;
    deserializer.end().map_err(|_| ProtocolError::InvalidJson)?;
    let frame = WireFrame::from_wire(raw.protocol_version, raw.request_id, raw.message);
    frame.validate()?;
    Ok(frame)
}

fn encode<M>(frame: &WireFrame<M>) -> Result<Vec<u8>, ProtocolError>
where
    M: Serialize + WireMessage,
{
    frame.validate()?;
    let encoded = serde_json::to_vec(frame).map_err(|_| ProtocolError::InvalidJson)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(encoded)
}

// Keep the public directional functions tied to concrete message types. This
// compile-time assertion catches accidental aliases that would allow a provider
// message on the shim decoder or vice versa.
const _: fn(&[u8]) -> Result<WireFrame<ShimRequest>, ProtocolError> = decode_shim_request;
const _: fn(&[u8]) -> Result<WireFrame<BrokerShimMessage>, ProtocolError> = decode_shim_response;
const _: fn(&[u8]) -> Result<WireFrame<ProviderRequest>, ProtocolError> = decode_provider_request;
const _: fn(&[u8]) -> Result<WireFrame<BrokerProviderMessage>, ProtocolError> =
    decode_provider_response;
