use std::{
    fmt,
    io::{self, Read, Write},
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, IgnoredAny, MapAccess, Visitor},
};

use crate::messages::{
    BrokerProviderMessage, BrokerShimMessage, PROTOCOL_VERSION, ProtocolError, ProviderRequest,
    ProviderRequestFrame, ProviderResponseFrame, ShimRequest, ShimRequestFrame, ShimResponseFrame,
    WireFrame, WireMessage,
};

/// Failure while transferring one bounded IPC record over an already
/// authenticated byte stream.
///
/// This type deliberately retains only [`io::ErrorKind`]. Platform paths,
/// pipe names, and other potentially sensitive transport details belong in a
/// local diagnostic sink rather than on the protocol boundary.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("IPC transport failed: {0:?}")]
    Io(io::ErrorKind),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

impl PartialEq for TransportError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => left == right,
            (Self::Protocol(left), Self::Protocol(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for TransportError {}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

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

/// Reads and validates one shim-to-broker record from a byte stream.
///
/// The caller must authenticate the native peer and install a bounded I/O
/// deadline before calling this function. The declared length is validated
/// before allocating the payload buffer.
///
/// # Errors
///
/// Rejects transport failures, truncated records, oversized declarations, and
/// invalid shim requests.
pub fn read_shim_request(reader: &mut impl Read) -> Result<ShimRequestFrame, TransportError> {
    read_record(reader, decode_shim_request)
}

/// Reads and validates one broker-to-shim record from a byte stream.
///
/// The caller must authenticate the native peer and install a bounded I/O
/// deadline before calling this function.
///
/// # Errors
///
/// Rejects transport failures, truncated records, oversized declarations, and
/// invalid shim responses.
pub fn read_shim_response(reader: &mut impl Read) -> Result<ShimResponseFrame, TransportError> {
    read_record(reader, decode_shim_response)
}

/// Reads and validates one provider-to-broker record from a byte stream.
///
/// The caller must authenticate the native peer and install a bounded I/O
/// deadline before calling this function.
///
/// # Errors
///
/// Rejects transport failures, truncated records, oversized declarations, and
/// invalid provider requests.
pub fn read_provider_request(
    reader: &mut impl Read,
) -> Result<ProviderRequestFrame, TransportError> {
    read_record(reader, decode_provider_request)
}

/// Reads and validates one broker-to-provider record from a byte stream.
///
/// The caller must authenticate the native peer and install a bounded I/O
/// deadline before calling this function.
///
/// # Errors
///
/// Rejects transport failures, truncated records, oversized declarations, and
/// invalid provider responses.
pub fn read_provider_response(
    reader: &mut impl Read,
) -> Result<ProviderResponseFrame, TransportError> {
    read_record(reader, decode_provider_response)
}

/// Writes one validated shim-to-broker record completely to a byte stream.
///
/// # Errors
///
/// Rejects invalid records and transport failures.
pub fn write_shim_request(
    writer: &mut impl Write,
    frame: &ShimRequestFrame,
) -> Result<(), TransportError> {
    write_record(writer, frame, encode_shim_request)
}

/// Writes one validated broker-to-shim record completely to a byte stream.
///
/// # Errors
///
/// Rejects invalid records and transport failures.
pub fn write_shim_response(
    writer: &mut impl Write,
    frame: &ShimResponseFrame,
) -> Result<(), TransportError> {
    write_record(writer, frame, encode_shim_response)
}

/// Writes one validated provider-to-broker record completely to a byte stream.
///
/// # Errors
///
/// Rejects invalid records and transport failures.
pub fn write_provider_request(
    writer: &mut impl Write,
    frame: &ProviderRequestFrame,
) -> Result<(), TransportError> {
    write_record(writer, frame, encode_provider_request)
}

/// Writes one validated broker-to-provider record completely to a byte stream.
///
/// # Errors
///
/// Rejects invalid records and transport failures.
pub fn write_provider_response(
    writer: &mut impl Write,
    frame: &ProviderResponseFrame,
) -> Result<(), TransportError> {
    write_record(writer, frame, encode_provider_response)
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

fn read_record<M>(
    reader: &mut impl Read,
    decode: fn(&[u8]) -> Result<WireFrame<M>, ProtocolError>,
) -> Result<WireFrame<M>, TransportError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact_record_part(reader, &mut header)?;
    let payload_length = decode_frame_length(&header)?;
    let record_length = FRAME_HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(ProtocolError::FrameTooLarge)?;
    let mut record = vec![0_u8; record_length];
    record[..FRAME_HEADER_BYTES].copy_from_slice(&header);
    read_exact_record_part(reader, &mut record[FRAME_HEADER_BYTES..])?;
    Ok(decode(&record)?)
}

fn read_exact_record_part(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), TransportError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(ProtocolError::IncompleteFrame.into())
        }
        Err(error) => Err(error.into()),
    }
}

fn write_record<M>(
    writer: &mut impl Write,
    frame: &WireFrame<M>,
    encode: fn(&WireFrame<M>) -> Result<Vec<u8>, ProtocolError>,
) -> Result<(), TransportError> {
    let record = encode(frame)?;
    writer.write_all(&record)?;
    Ok(())
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

#[cfg(test)]
mod stream_tests {
    use std::io::{self, Cursor, Read, Write};

    use super::*;
    use crate::{Digest32, ShimRequest, StatusRequest};

    struct ShortReader<R> {
        inner: R,
        maximum: usize,
    }

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.maximum);
            self.inner.read(&mut buffer[..length])
        }
    }

    #[derive(Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.maximum);
            self.bytes.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn status_frame() -> ShimRequestFrame {
        ShimRequestFrame::request(ShimRequest::Status(StatusRequest::new(
            Digest32::from_bytes([7; 32]),
        )))
        .expect("valid request")
    }

    #[test]
    fn reads_a_record_across_short_reads() {
        let frame = status_frame();
        let record = encode_shim_request(&frame).expect("encode fixture");
        let mut reader = ShortReader {
            inner: Cursor::new(record),
            maximum: 1,
        };

        assert_eq!(read_shim_request(&mut reader), Ok(frame));
    }

    #[test]
    fn writes_a_record_across_short_writes_without_flushing() {
        let frame = status_frame();
        let expected = encode_shim_request(&frame).expect("encode fixture");
        let mut writer = ShortWriter {
            maximum: 2,
            ..ShortWriter::default()
        };

        write_shim_request(&mut writer, &frame).expect("write fixture");

        assert_eq!(writer.bytes, expected);
    }

    #[test]
    fn rejects_an_oversized_declaration_before_reading_a_payload() {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("frame bound fits u32")
            .to_be_bytes();
        let mut reader = Cursor::new(oversized);

        assert_eq!(
            read_shim_request(&mut reader),
            Err(TransportError::Protocol(ProtocolError::FrameTooLarge))
        );
        assert_eq!(reader.position(), FRAME_HEADER_BYTES as u64);
    }

    #[test]
    fn maps_truncated_header_and_payload_to_protocol_errors() {
        let frame = status_frame();
        let mut record = encode_shim_request(&frame).expect("encode fixture");
        record.pop();

        assert_eq!(
            read_shim_request(&mut Cursor::new([0_u8; 3])),
            Err(TransportError::Protocol(ProtocolError::IncompleteFrame))
        );
        assert_eq!(
            read_shim_request(&mut Cursor::new(record)),
            Err(TransportError::Protocol(ProtocolError::IncompleteFrame))
        );
    }

    #[test]
    fn retains_non_eof_transport_error_kind() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::TimedOut, "secret path"))
            }
        }

        assert_eq!(
            read_shim_request(&mut FailingReader),
            Err(TransportError::Io(io::ErrorKind::TimedOut))
        );
    }
}
