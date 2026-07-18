use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, IgnoredAny, MapAccess, Visitor},
};

use crate::messages::{
    BrokerProviderMessage, BrokerShimMessage, PROTOCOL_VERSION, ProtocolError, ProviderRequest,
    ProviderRequestFrame, ProviderResponseFrame, ShimRequest, ShimRequestFrame, ShimResponseFrame,
    WireFrame, WireMessage,
};

/// Maximum JSON payload accepted before transport framing overhead.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Fixed big-endian length prefix used on every byte-stream transport.
pub const FRAME_HEADER_BYTES: usize = 4;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWireFrame<M> {
    protocol_version: u16,
    message_family: crate::MessageFamily,
    request_id: crate::RequestId,
    message: M,
}

struct VersionProbe(u16);

impl<'de> Deserialize<'de> for VersionProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VersionProbeVisitor)
    }
}

struct VersionProbeVisitor;

impl<'de> Visitor<'de> for VersionProbeVisitor {
    type Value = VersionProbe;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a GUS IPC envelope containing one protocol_version")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut protocol_version = None;
        while let Some(field) = map.next_key::<String>()? {
            if field == "protocol_version" {
                if protocol_version.is_some() {
                    return Err(de::Error::duplicate_field("protocol_version"));
                }
                protocol_version = Some(map.next_value()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        protocol_version
            .map(VersionProbe)
            .ok_or_else(|| de::Error::missing_field("protocol_version"))
    }
}

/// Decodes and validates a shim-to-broker protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_shim_request(bytes: &[u8]) -> Result<ShimRequestFrame, ProtocolError> {
    decode_record(bytes)
}

/// Decodes and validates a broker-to-shim protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_shim_response(bytes: &[u8]) -> Result<ShimResponseFrame, ProtocolError> {
    decode_record(bytes)
}

/// Decodes and validates a provider-to-broker protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_provider_request(bytes: &[u8]) -> Result<ProviderRequestFrame, ProtocolError> {
    decode_record(bytes)
}

/// Decodes and validates a broker-to-provider protocol frame.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, unsupported, or semantically invalid frames.
pub fn decode_provider_response(bytes: &[u8]) -> Result<ProviderResponseFrame, ProtocolError> {
    decode_record(bytes)
}

/// Encodes a validated shim-to-broker protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_shim_request(frame: &ShimRequestFrame) -> Result<Vec<u8>, ProtocolError> {
    encode_record(frame)
}

/// Encodes a validated broker-to-shim protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_shim_response(frame: &ShimResponseFrame) -> Result<Vec<u8>, ProtocolError> {
    encode_record(frame)
}

/// Encodes a validated provider-to-broker protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_provider_request(frame: &ProviderRequestFrame) -> Result<Vec<u8>, ProtocolError> {
    encode_record(frame)
}

/// Encodes a validated broker-to-provider protocol frame.
///
/// # Errors
///
/// Rejects semantically invalid or oversized frames.
pub fn encode_provider_response(frame: &ProviderResponseFrame) -> Result<Vec<u8>, ProtocolError> {
    encode_record(frame)
}

/// Decodes the fixed four-byte big-endian record header before allocating a
/// payload buffer.
///
/// # Errors
///
/// Rejects an incomplete header, a zero-length payload, or a declared payload
/// larger than [`MAX_FRAME_BYTES`].
pub fn decode_frame_length(header: &[u8]) -> Result<usize, ProtocolError> {
    let header: [u8; FRAME_HEADER_BYTES] = header
        .try_into()
        .map_err(|_| ProtocolError::IncompleteFrame)?;
    let length =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| ProtocolError::FrameTooLarge)?;
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(length)
}

fn decode_record<M>(record: &[u8]) -> Result<WireFrame<M>, ProtocolError>
where
    M: DeserializeOwned + WireMessage,
{
    if record.len() < FRAME_HEADER_BYTES {
        return Err(ProtocolError::IncompleteFrame);
    }
    let payload_length = decode_frame_length(&record[..FRAME_HEADER_BYTES])?;
    let expected_record_length = FRAME_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(ProtocolError::FrameTooLarge)?;
    if record.len() < expected_record_length {
        return Err(ProtocolError::IncompleteFrame);
    }
    if record.len() != expected_record_length {
        return Err(ProtocolError::FrameLengthMismatch);
    }
    let payload = &record[FRAME_HEADER_BYTES..];
    let mut probe_deserializer = serde_json::Deserializer::from_slice(payload);
    let probe = VersionProbe::deserialize(&mut probe_deserializer)
        .map_err(|_| ProtocolError::InvalidJson)?;
    probe_deserializer
        .end()
        .map_err(|_| ProtocolError::InvalidJson)?;
    if probe.0 != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { received: probe.0 });
    }

    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let raw = RawWireFrame::<M>::deserialize(&mut deserializer)
        .map_err(|_| ProtocolError::InvalidJson)?;
    deserializer.end().map_err(|_| ProtocolError::InvalidJson)?;
    let frame = WireFrame::from_wire(
        raw.protocol_version,
        raw.message_family,
        raw.request_id,
        raw.message,
    );
    frame.validate()?;
    Ok(frame)
}

fn encode_record<M>(frame: &WireFrame<M>) -> Result<Vec<u8>, ProtocolError>
where
    M: Serialize + WireMessage,
{
    frame.validate()?;
    let payload = serde_json::to_vec(frame).map_err(|_| ProtocolError::InvalidJson)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    let mut record = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    record.extend_from_slice(&payload_length.to_be_bytes());
    record.extend_from_slice(&payload);
    Ok(record)
}

// Keep the public directional functions tied to concrete message types. This
// compile-time assertion catches accidental aliases that would allow a provider
// message on the shim decoder or vice versa.
const _: fn(&[u8]) -> Result<WireFrame<ShimRequest>, ProtocolError> = decode_shim_request;
const _: fn(&[u8]) -> Result<WireFrame<BrokerShimMessage>, ProtocolError> = decode_shim_response;
const _: fn(&[u8]) -> Result<WireFrame<ProviderRequest>, ProtocolError> = decode_provider_request;
const _: fn(&[u8]) -> Result<WireFrame<BrokerProviderMessage>, ProtocolError> =
    decode_provider_response;
