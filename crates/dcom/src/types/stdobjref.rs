//! STDOBJREF structure (MS-DCOM 2.2.18.1)
//!
//! Standard Object Reference - the core structure that identifies
//! a marshaled interface pointer.

use super::identifiers::{Ipid, Oid, Oxid};
use bytes::{Buf, BufMut};

/// STDOBJREF flags (SORF_*)
pub mod flags {
    /// Standard reference
    pub const SORF_NULL: u32 = 0x00000000;
    /// OID is not significant (used with NULL OXID)
    pub const SORF_OXRES1: u32 = 0x00000001;
    /// Reserved for OXID resolution
    pub const SORF_OXRES2: u32 = 0x00000020;
    /// Reserved for OXID resolution
    pub const SORF_OXRES3: u32 = 0x00000040;
    /// Reserved for OXID resolution
    pub const SORF_OXRES4: u32 = 0x00000080;
    /// Reserved for OXID resolution
    pub const SORF_OXRES5: u32 = 0x00000100;
    /// Reserved for OXID resolution
    pub const SORF_OXRES6: u32 = 0x00000200;
    /// Reserved for OXID resolution
    pub const SORF_OXRES7: u32 = 0x00000400;
    /// Reserved for OXID resolution
    pub const SORF_OXRES8: u32 = 0x00000800;
    /// The IPID is part of a machine-local interface
    pub const SORF_NOPING: u32 = 0x00001000;
}

/// Standard Object Reference (40 bytes)
///
/// This is the core structure used to marshal COM interface pointers
/// across process or machine boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdObjRef {
    /// SORF_* flags
    pub flags: u32,
    /// Number of public references held
    pub public_refs: u32,
    /// Object Exporter ID (identifies the apartment/process)
    pub oxid: Oxid,
    /// Object ID (identifies the object within the exporter)
    pub oid: Oid,
    /// Interface Pointer ID (identifies the interface on the object)
    pub ipid: Ipid,
}

impl StdObjRef {
    /// Size in bytes (4 + 4 + 8 + 8 + 16 = 40)
    pub const SIZE: usize = 40;

    /// Create a new STDOBJREF
    pub fn new(oxid: Oxid, oid: Oid, ipid: Ipid, public_refs: u32) -> Self {
        Self {
            flags: flags::SORF_NULL,
            public_refs,
            oxid,
            oid,
            ipid,
        }
    }

    /// Create a STDOBJREF that doesn't require pinging
    pub fn new_noping(oxid: Oxid, oid: Oid, ipid: Ipid, public_refs: u32) -> Self {
        Self {
            flags: flags::SORF_NOPING,
            public_refs,
            oxid,
            oid,
            ipid,
        }
    }

    /// Check if this reference requires pinging for GC
    pub fn requires_pinging(&self) -> bool {
        (self.flags & flags::SORF_NOPING) == 0
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u32_le(self.flags);
            buf.put_u32_le(self.public_refs);
        } else {
            buf.put_u32(self.flags);
            buf.put_u32(self.public_refs);
        }
        self.oxid.encode(buf, little_endian);
        self.oid.encode(buf, little_endian);
        self.ipid.encode(buf, little_endian);
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::SIZE {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::SIZE,
                have: buf.remaining(),
            });
        }

        let flags = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let public_refs = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let oxid = Oxid::decode(buf, little_endian);
        let oid = Oid::decode(buf, little_endian);
        let ipid = Ipid::decode(buf, little_endian);

        Ok(Self {
            flags,
            public_refs,
            oxid,
            oid,
            ipid,
        })
    }
}

impl Default for StdObjRef {
    fn default() -> Self {
        Self {
            flags: flags::SORF_NULL,
            public_refs: 0,
            oxid: Oxid::default(),
            oid: Oid::default(),
            ipid: Ipid::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_stdobjref_size() {
        let objref = StdObjRef::default();
        let mut buf = BytesMut::new();
        objref.encode(&mut buf, true);
        assert_eq!(buf.len(), StdObjRef::SIZE);
    }

    #[test]
    fn test_stdobjref_encode_decode() {
        let oxid = Oxid::new(0x123456789ABCDEF0);
        let oid = Oid::new(0xFEDCBA9876543210);
        let ipid = Ipid::generate();

        let objref = StdObjRef::new(oxid, oid, ipid, 5);
        let mut buf = BytesMut::new();
        objref.encode(&mut buf, true);

        let decoded = StdObjRef::decode(&mut buf.freeze(), true).unwrap();
        assert_eq!(objref, decoded);
    }

    #[test]
    fn test_stdobjref_noping() {
        let objref = StdObjRef::new_noping(
            Oxid::new(1),
            Oid::new(2),
            Ipid::generate(),
            1,
        );
        assert!(!objref.requires_pinging());

        let normal_ref = StdObjRef::new(
            Oxid::new(1),
            Oid::new(2),
            Ipid::generate(),
            1,
        );
        assert!(normal_ref.requires_pinging());
    }
}
