//! ORPC (Object RPC) header types (MS-DCOM 2.2.13, 2.2.14)
//!
//! These structures are prepended to all ORPC calls and responses.

use bytes::{Buf, BufMut};
use super::identifiers::{decode_uuid, encode_uuid, generate_uuid};

/// COM version structure (MS-DCOM 2.2.11)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ComVersion {
    /// Major version number
    pub major: u16,
    /// Minor version number
    pub minor: u16,
}

impl ComVersion {
    /// Size in bytes
    pub const SIZE: usize = 4;

    /// DCOM version 5.1 (Windows 2000)
    pub const DCOM_5_1: Self = Self { major: 5, minor: 1 };
    /// DCOM version 5.4 (Windows XP/2003)
    pub const DCOM_5_4: Self = Self { major: 5, minor: 4 };
    /// DCOM version 5.6 (Windows Vista)
    pub const DCOM_5_6: Self = Self { major: 5, minor: 6 };
    /// DCOM version 5.7 (Windows 7)
    pub const DCOM_5_7: Self = Self { major: 5, minor: 7 };

    /// Create a new COM version
    pub fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u16_le(self.major);
            buf.put_u16_le(self.minor);
        } else {
            buf.put_u16(self.major);
            buf.put_u16(self.minor);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Self {
        if little_endian {
            Self {
                major: buf.get_u16_le(),
                minor: buf.get_u16_le(),
            }
        } else {
            Self {
                major: buf.get_u16(),
                minor: buf.get_u16(),
            }
        }
    }
}

/// ORPC extension array entry
#[derive(Clone, Debug)]
pub struct OrpcExtent {
    /// Extension UUID identifier
    pub id: dcerpc::Uuid,
    /// Extension data size
    pub size: u32,
    /// Extension data
    pub data: Vec<u8>,
}

impl OrpcExtent {
    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        encode_uuid(&self.id, buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.size);
        } else {
            buf.put_u32(self.size);
        }
        buf.put_slice(&self.data);
        // Pad to 8-byte alignment
        let padding = (8 - (self.data.len() % 8)) % 8;
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    /// Get encoded size including padding
    pub fn encoded_size(&self) -> usize {
        let base = 16 + 4 + self.data.len();
        let padding = (8 - (self.data.len() % 8)) % 8;
        base + padding
    }
}

/// ORPC extent array
#[derive(Clone, Debug, Default)]
pub struct OrpcExtentArray {
    /// Size of extent array
    pub size: u32,
    /// Reserved
    pub reserved: u32,
    /// Array of extents
    pub extents: Vec<OrpcExtent>,
}

impl OrpcExtentArray {
    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u32_le(self.size);
            buf.put_u32_le(self.reserved);
        } else {
            buf.put_u32(self.size);
            buf.put_u32(self.reserved);
        }
        for extent in &self.extents {
            extent.encode(buf, little_endian);
        }
    }
}

/// ORPCTHIS structure (MS-DCOM 2.2.13)
///
/// Sent with every ORPC request from client to server.
#[derive(Clone, Debug)]
pub struct OrpcThis {
    /// COM version
    pub version: ComVersion,
    /// Flags (must be 0)
    pub flags: u32,
    /// Reserved (must be 0)
    pub reserved1: u32,
    /// Causality ID (UUID identifying the call chain)
    pub causality_id: dcerpc::Uuid,
    /// Optional extension array
    pub extensions: Option<OrpcExtentArray>,
}

impl OrpcThis {
    /// Minimum size without extensions
    pub const MIN_SIZE: usize = 4 + 4 + 4 + 16; // version + flags + reserved + causality_id

    /// Create a new ORPCTHIS with default values
    pub fn new() -> Self {
        Self {
            version: ComVersion::DCOM_5_7,
            flags: 0,
            reserved1: 0,
            causality_id: generate_uuid(),
            extensions: None,
        }
    }

    /// Create with a specific causality ID
    pub fn with_causality(causality_id: dcerpc::Uuid) -> Self {
        Self {
            version: ComVersion::DCOM_5_7,
            flags: 0,
            reserved1: 0,
            causality_id,
            extensions: None,
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        self.version.encode(buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.flags);
            buf.put_u32_le(self.reserved1);
        } else {
            buf.put_u32(self.flags);
            buf.put_u32(self.reserved1);
        }
        encode_uuid(&self.causality_id, buf, little_endian);

        // Extensions pointer (conformant array)
        if let Some(ref ext) = self.extensions {
            // Non-null pointer
            if little_endian {
                buf.put_u32_le(1);
            } else {
                buf.put_u32(1);
            }
            ext.encode(buf, little_endian);
        } else {
            // Null pointer
            if little_endian {
                buf.put_u32_le(0);
            } else {
                buf.put_u32(0);
            }
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::MIN_SIZE + 4 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::MIN_SIZE + 4,
                have: buf.remaining(),
            });
        }

        let version = ComVersion::decode(buf, little_endian);
        let flags = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let reserved1 = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let causality_id = decode_uuid(buf, little_endian);

        // Extensions pointer
        let ext_ptr = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let extensions = if ext_ptr != 0 {
            // TODO: Decode extensions when needed
            None
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            reserved1,
            causality_id,
            extensions,
        })
    }
}

impl Default for OrpcThis {
    fn default() -> Self {
        Self::new()
    }
}

/// ORPCTHAT structure (MS-DCOM 2.2.14)
///
/// Sent with every ORPC response from server to client.
#[derive(Clone, Debug, Default)]
pub struct OrpcThat {
    /// Flags (must be 0)
    pub flags: u32,
    /// Optional extension array
    pub extensions: Option<OrpcExtentArray>,
}

impl OrpcThat {
    /// Minimum size without extensions
    pub const MIN_SIZE: usize = 4; // flags only

    /// Create a new empty ORPCTHAT
    pub fn new() -> Self {
        Self {
            flags: 0,
            extensions: None,
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u32_le(self.flags);
        } else {
            buf.put_u32(self.flags);
        }

        // Extensions pointer
        if let Some(ref ext) = self.extensions {
            if little_endian {
                buf.put_u32_le(1);
            } else {
                buf.put_u32(1);
            }
            ext.encode(buf, little_endian);
        } else {
            if little_endian {
                buf.put_u32_le(0);
            } else {
                buf.put_u32(0);
            }
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::MIN_SIZE + 4 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::MIN_SIZE + 4,
                have: buf.remaining(),
            });
        }

        let flags = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        // Extensions pointer
        let ext_ptr = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let extensions = if ext_ptr != 0 {
            // TODO: Decode extensions when needed
            None
        } else {
            None
        };

        Ok(Self { flags, extensions })
    }
}

/// Well-known extension UUIDs
pub mod extent_ids {
    /// Error info extension
    pub const ERROR_INFO: &str = "00000000-0000-0000-c000-000000000046";
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_com_version_encode_decode() {
        let version = ComVersion::DCOM_5_7;
        let mut buf = BytesMut::new();
        version.encode(&mut buf, true);
        assert_eq!(buf.len(), 4);

        let decoded = ComVersion::decode(&mut buf.freeze(), true);
        assert_eq!(version, decoded);
    }

    #[test]
    fn test_orpc_this_new() {
        let orpc = OrpcThis::new();
        assert_eq!(orpc.version, ComVersion::DCOM_5_7);
        assert_eq!(orpc.flags, 0);
        assert_ne!(orpc.causality_id, dcerpc::Uuid::NIL);
    }

    #[test]
    fn test_orpc_that_encode_decode() {
        let orpc = OrpcThat::new();
        let mut buf = BytesMut::new();
        orpc.encode(&mut buf, true);

        let decoded = OrpcThat::decode(&mut buf.freeze(), true).unwrap();
        assert_eq!(decoded.flags, 0);
        assert!(decoded.extensions.is_none());
    }
}
