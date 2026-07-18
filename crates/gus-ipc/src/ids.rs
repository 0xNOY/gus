use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::messages::ProtocolError;

/// A non-secret 128-bit request nonce rendered as a canonical `UUIDv4`.
///
/// The broker still has to enforce single-use and connection ownership. UUID
/// syntax alone is not proof that a peer generated the value unpredictably.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Generates a fresh request identifier from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| ProtocolError::EntropyUnavailable)?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FromStr for RequestId {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 36
            || value.as_bytes()[8] != b'-'
            || value.as_bytes()[13] != b'-'
            || value.as_bytes()[18] != b'-'
            || value.as_bytes()[23] != b'-'
        {
            return Err(ProtocolError::InvalidRequestId);
        }

        let mut bytes = [0; 16];
        let mut encoded_index = 0;
        let mut output_index = 0;
        while encoded_index < value.len() {
            if matches!(encoded_index, 8 | 13 | 18 | 23) {
                encoded_index += 1;
                continue;
            }
            let pair = &value.as_bytes()[encoded_index..encoded_index + 2];
            bytes[output_index] = (hex_nibble(pair[0]).ok_or(ProtocolError::InvalidRequestId)?
                << 4)
                | hex_nibble(pair[1]).ok_or(ProtocolError::InvalidRequestId)?;
            encoded_index += 2;
            output_index += 1;
        }
        if bytes == [0; 16] || bytes[6] >> 4 != 4 || bytes[8] >> 6 != 2 {
            return Err(ProtocolError::InvalidRequestId);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// A non-secret SHA-256-sized correlation digest.
///
/// Receiving this value never proves that a repository or plan was observed by
/// trusted code. Platform and resolver layers must compare it with their own
/// retained evidence.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Digest32(")?;
        for byte in self.0.iter().take(6) {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_digest(&value).map_err(de::Error::custom)
    }
}

fn parse_digest(value: &str) -> Result<Digest32, ProtocolError> {
    if value.len() != 64 {
        return Err(ProtocolError::InvalidDigest);
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]).ok_or(ProtocolError::InvalidDigest)? << 4)
            | hex_nibble(pair[1]).ok_or(ProtocolError::InvalidDigest)?;
    }
    Ok(Digest32(bytes))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
