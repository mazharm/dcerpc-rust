//! DCOM identifier types (MS-DCOM 2.2.18)
//!
//! These are the core identifiers used throughout DCOM:
//! - OXID: Object Exporter Identifier
//! - OID: Object Identifier
//! - IPID: Interface Pointer Identifier
//! - SETID: Ping Set Identifier

use bytes::{Buf, BufMut};
use std::fmt;

/// Helper to decode a dcerpc::Uuid from a generic Buf
pub fn decode_uuid<B: Buf>(buf: &mut B, little_endian: bool) -> dcerpc::Uuid {
    let time_low = if little_endian { buf.get_u32_le() } else { buf.get_u32() };
    let time_mid = if little_endian { buf.get_u16_le() } else { buf.get_u16() };
    let time_hi_and_version = if little_endian { buf.get_u16_le() } else { buf.get_u16() };
    let clock_seq_hi_and_reserved = buf.get_u8();
    let clock_seq_low = buf.get_u8();
    let mut node = [0u8; 6];
    buf.copy_to_slice(&mut node);
    dcerpc::Uuid {
        time_low,
        time_mid,
        time_hi_and_version,
        clock_seq_hi_and_reserved,
        clock_seq_low,
        node,
    }
}

/// Helper to encode a dcerpc::Uuid to a generic BufMut
pub fn encode_uuid<B: BufMut>(uuid: &dcerpc::Uuid, buf: &mut B, little_endian: bool) {
    if little_endian {
        buf.put_u32_le(uuid.time_low);
        buf.put_u16_le(uuid.time_mid);
        buf.put_u16_le(uuid.time_hi_and_version);
    } else {
        buf.put_u32(uuid.time_low);
        buf.put_u16(uuid.time_mid);
        buf.put_u16(uuid.time_hi_and_version);
    }
    buf.put_u8(uuid.clock_seq_hi_and_reserved);
    buf.put_u8(uuid.clock_seq_low);
    buf.put_slice(&uuid.node);
}

/// Generate a new random v4 UUID
pub fn generate_uuid() -> dcerpc::Uuid {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    dcerpc::Uuid {
        time_low: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        time_mid: u16::from_be_bytes([bytes[4], bytes[5]]),
        time_hi_and_version: u16::from_be_bytes([bytes[6], bytes[7]]),
        clock_seq_hi_and_reserved: bytes[8],
        clock_seq_low: bytes[9],
        node: [bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
    }
}

/// Object Exporter Identifier (8 bytes)
///
/// Uniquely identifies an object exporter within a machine.
/// The OXID is used to locate the RPC binding information for
/// communicating with the object exporter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Oxid(pub u64);

impl Oxid {
    /// Size of OXID in bytes
    pub const SIZE: usize = 8;

    /// Create a new OXID
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Generate a random OXID
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Mix with process ID and random bits
        let pid = std::process::id() as u64;
        Self(timestamp ^ (pid << 48))
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u64_le(self.0);
        } else {
            buf.put_u64(self.0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Self {
        if little_endian {
            Self(buf.get_u64_le())
        } else {
            Self(buf.get_u64())
        }
    }
}

impl fmt::Debug for Oxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OXID({:016x})", self.0)
    }
}

impl fmt::Display for Oxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Object Identifier (8 bytes)
///
/// Uniquely identifies a COM object within an object exporter.
/// The OID is used along with the OXID to uniquely identify
/// an object across the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Oid(pub u64);

impl Oid {
    /// Size of OID in bytes
    pub const SIZE: usize = 8;

    /// Create a new OID
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Generate a random OID
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self(timestamp)
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u64_le(self.0);
        } else {
            buf.put_u64(self.0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Self {
        if little_endian {
            Self(buf.get_u64_le())
        } else {
            Self(buf.get_u64())
        }
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OID({:016x})", self.0)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Interface Pointer Identifier (16 bytes / UUID)
///
/// Uniquely identifies an interface pointer on a specific object.
/// The IPID is a UUID that is generated when an interface is marshaled.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipid(pub dcerpc::Uuid);

impl Ipid {
    /// Size of IPID in bytes (16 bytes, same as UUID)
    pub const SIZE: usize = 16;

    /// Create a new IPID from a UUID
    pub fn new(uuid: dcerpc::Uuid) -> Self {
        Self(uuid)
    }

    /// Generate a random IPID
    pub fn generate() -> Self {
        Self(generate_uuid())
    }

    /// Create a nil IPID
    pub fn nil() -> Self {
        Self(dcerpc::Uuid::NIL)
    }

    /// Check if this is the nil IPID
    pub fn is_nil(&self) -> bool {
        self.0 == dcerpc::Uuid::NIL
    }

    /// Get the underlying UUID
    pub fn uuid(&self) -> &dcerpc::Uuid {
        &self.0
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        encode_uuid(&self.0, buf, little_endian);
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Self {
        Self(decode_uuid(buf, little_endian))
    }
}

impl Default for Ipid {
    fn default() -> Self {
        Self::nil()
    }
}

impl fmt::Debug for Ipid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPID({})", self.0)
    }
}

impl fmt::Display for Ipid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Ping Set Identifier (8 bytes)
///
/// Identifies a set of OIDs that are pinged together for
/// garbage collection purposes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SetId(pub u64);

impl SetId {
    /// Size of SETID in bytes
    pub const SIZE: usize = 8;

    /// Create a new SetId
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Generate a random SetId
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self(timestamp ^ 0xDEADBEEF)
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u64_le(self.0);
        } else {
            buf.put_u64(self.0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Self {
        if little_endian {
            Self(buf.get_u64_le())
        } else {
            Self(buf.get_u64())
        }
    }
}

impl fmt::Debug for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SETID({:016x})", self.0)
    }
}

impl fmt::Display for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_oxid_encode_decode() {
        let oxid = Oxid::new(0x123456789ABCDEF0);
        let mut buf = BytesMut::new();
        oxid.encode(&mut buf, true);
        assert_eq!(buf.len(), 8);

        let decoded = Oxid::decode(&mut buf.freeze(), true);
        assert_eq!(oxid, decoded);
    }

    #[test]
    fn test_oid_encode_decode() {
        let oid = Oid::new(0xFEDCBA9876543210);
        let mut buf = BytesMut::new();
        oid.encode(&mut buf, true);
        assert_eq!(buf.len(), 8);

        let decoded = Oid::decode(&mut buf.freeze(), true);
        assert_eq!(oid, decoded);
    }

    #[test]
    fn test_ipid_generate() {
        let ipid1 = Ipid::generate();
        let ipid2 = Ipid::generate();
        assert_ne!(ipid1, ipid2);
        assert!(!ipid1.is_nil());
    }

    #[test]
    fn test_setid_encode_decode() {
        let setid = SetId::new(0xCAFEBABE12345678);
        let mut buf = BytesMut::new();
        setid.encode(&mut buf, false);
        assert_eq!(buf.len(), 8);

        let decoded = SetId::decode(&mut buf.freeze(), false);
        assert_eq!(setid, decoded);
    }
}
