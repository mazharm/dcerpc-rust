//! OBJREF structure (MS-DCOM 2.2.18)
//!
//! OBJREF is the primary marshaling format for COM interface pointers.
//! It contains all the information needed to remarshal a reference
//! to a COM object across process or machine boundaries.

use super::identifiers::{Ipid, Oid, Oxid, decode_uuid, encode_uuid};
use super::stdobjref::StdObjRef;
use super::stringbinding::DualStringArray;
use bytes::{Buf, BufMut, Bytes};

/// OBJREF signature (must be "MEOW" in ASCII)
pub const OBJREF_SIGNATURE: u32 = 0x574F454D; // "MEOW" in little-endian

/// OBJREF flags indicating the variant type
pub mod objref_flags {
    /// Standard reference (STDOBJREF + DUALSTRINGARRAY)
    pub const OBJREF_STANDARD: u32 = 0x00000001;
    /// Handler reference (STDOBJREF + CLSID + DUALSTRINGARRAY)
    pub const OBJREF_HANDLER: u32 = 0x00000002;
    /// Custom marshaling (CLSID + extension + data)
    pub const OBJREF_CUSTOM: u32 = 0x00000004;
    /// Extended reference (COMVERSION 5.6+)
    pub const OBJREF_EXTENDED: u32 = 0x00000008;
}

/// OBJREF_STANDARD (MS-DCOM 2.2.18.4)
///
/// The most common OBJREF variant, containing a STDOBJREF
/// and resolver string bindings.
#[derive(Clone, Debug)]
pub struct ObjRefStandard {
    /// Standard object reference
    pub std: StdObjRef,
    /// Resolver string bindings
    pub resolver_addr: DualStringArray,
}

impl ObjRefStandard {
    /// Create a new standard OBJREF
    pub fn new(std: StdObjRef, resolver_addr: DualStringArray) -> Self {
        Self { std, resolver_addr }
    }

    /// Create a minimal reference for local use
    pub fn local(oxid: Oxid, oid: Oid, ipid: Ipid) -> Self {
        Self {
            std: StdObjRef::new_noping(oxid, oid, ipid, 1),
            resolver_addr: DualStringArray::new(),
        }
    }

    /// Encode to buffer (without header)
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        self.std.encode(buf, little_endian);
        self.resolver_addr.encode(buf, little_endian);
    }

    /// Decode from buffer (after header has been read)
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        let std = StdObjRef::decode(buf, little_endian)?;
        let resolver_addr = DualStringArray::decode(buf, little_endian)?;
        Ok(Self { std, resolver_addr })
    }
}

/// OBJREF_HANDLER (MS-DCOM 2.2.18.5)
///
/// Contains a handler CLSID for in-process optimization.
#[derive(Clone, Debug)]
pub struct ObjRefHandler {
    /// Standard object reference
    pub std: StdObjRef,
    /// Handler CLSID (to load a local handler instead of proxy)
    pub handler_clsid: dcerpc::Uuid,
    /// Resolver string bindings
    pub resolver_addr: DualStringArray,
}

impl ObjRefHandler {
    /// Create a new handler OBJREF
    pub fn new(std: StdObjRef, handler_clsid: dcerpc::Uuid, resolver_addr: DualStringArray) -> Self {
        Self {
            std,
            handler_clsid,
            resolver_addr,
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        self.std.encode(buf, little_endian);
        encode_uuid(&self.handler_clsid, buf, little_endian);
        self.resolver_addr.encode(buf, little_endian);
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        let std = StdObjRef::decode(buf, little_endian)?;
        let handler_clsid = decode_uuid(buf, little_endian);
        let resolver_addr = DualStringArray::decode(buf, little_endian)?;
        Ok(Self {
            std,
            handler_clsid,
            resolver_addr,
        })
    }
}

/// OBJREF_CUSTOM (MS-DCOM 2.2.18.6)
///
/// Used for custom marshaling where the object provides its own
/// marshaling implementation.
#[derive(Clone, Debug)]
pub struct ObjRefCustom {
    /// CLSID of the unmarshaler
    pub clsid: dcerpc::Uuid,
    /// Size of extension data
    pub cb_extension: u32,
    /// Reserved
    pub reserved: u32,
    /// Custom marshaled data
    pub data: Bytes,
}

impl ObjRefCustom {
    /// Create a new custom OBJREF
    pub fn new(clsid: dcerpc::Uuid, data: Bytes) -> Self {
        Self {
            clsid,
            cb_extension: 0,
            reserved: 0,
            data,
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        encode_uuid(&self.clsid, buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.cb_extension);
            buf.put_u32_le(self.data.len() as u32);
        } else {
            buf.put_u32(self.cb_extension);
            buf.put_u32(self.data.len() as u32);
        }
        buf.put_slice(&self.data);
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < 16 + 4 + 4 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: 24,
                have: buf.remaining(),
            });
        }

        let clsid = decode_uuid(buf, little_endian);
        let cb_extension = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let size = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        } as usize;

        if buf.remaining() < size {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: size,
                have: buf.remaining(),
            });
        }

        let data = buf.copy_to_bytes(size);

        Ok(Self {
            clsid,
            cb_extension,
            reserved: 0,
            data,
        })
    }
}

/// OBJREF_EXTENDED (MS-DCOM 2.2.18.7)
///
/// Extended format introduced in COMVERSION 5.6.
#[derive(Clone, Debug)]
pub struct ObjRefExtended {
    /// Standard object reference
    pub std: StdObjRef,
    /// Signature 1 (must match expected value)
    pub signature1: u32,
    /// Resolver string bindings
    pub resolver_addr: DualStringArray,
    /// Number of extension entries
    pub n_elms: u32,
    /// Signature 2 (must match expected value)
    pub signature2: u32,
    /// Extension data
    pub elms: Vec<ObjRefExtendedEntry>,
}

/// Extended OBJREF entry
#[derive(Clone, Debug)]
pub struct ObjRefExtendedEntry {
    /// Entry size
    pub size: u32,
    /// Entry data
    pub data: Bytes,
}

impl ObjRefExtended {
    /// Expected signature values
    pub const SIGNATURE1: u32 = 0x4E535854; // "TXSN"
    pub const SIGNATURE2: u32 = 0x4E535854; // "TXSN"

    /// Create a new extended OBJREF
    pub fn new(std: StdObjRef, resolver_addr: DualStringArray) -> Self {
        Self {
            std,
            signature1: Self::SIGNATURE1,
            resolver_addr,
            n_elms: 0,
            signature2: Self::SIGNATURE2,
            elms: Vec::new(),
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        self.std.encode(buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.signature1);
        } else {
            buf.put_u32(self.signature1);
        }
        self.resolver_addr.encode(buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.elms.len() as u32);
            buf.put_u32_le(self.signature2);
        } else {
            buf.put_u32(self.elms.len() as u32);
            buf.put_u32(self.signature2);
        }
        for elm in &self.elms {
            if little_endian {
                buf.put_u32_le(elm.size);
            } else {
                buf.put_u32(elm.size);
            }
            buf.put_slice(&elm.data);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        let std = StdObjRef::decode(buf, little_endian)?;

        if buf.remaining() < 4 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let signature1 = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let resolver_addr = DualStringArray::decode(buf, little_endian)?;

        if buf.remaining() < 8 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }

        let n_elms = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let signature2 = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let mut elms = Vec::with_capacity(n_elms as usize);
        for _ in 0..n_elms {
            if buf.remaining() < 4 {
                break;
            }
            let size = if little_endian {
                buf.get_u32_le()
            } else {
                buf.get_u32()
            };
            if buf.remaining() < size as usize {
                break;
            }
            let data = buf.copy_to_bytes(size as usize);
            elms.push(ObjRefExtendedEntry { size, data });
        }

        Ok(Self {
            std,
            signature1,
            resolver_addr,
            n_elms,
            signature2,
            elms,
        })
    }
}

/// OBJREF union (MS-DCOM 2.2.18)
///
/// The main marshaled object reference type.
#[derive(Clone, Debug)]
pub enum ObjRef {
    /// Standard object reference
    Standard(ObjRefStandard),
    /// Handler object reference
    Handler(ObjRefHandler),
    /// Custom marshaled reference
    Custom(ObjRefCustom),
    /// Extended reference
    Extended(ObjRefExtended),
}

impl ObjRef {
    /// Header size (signature + flags)
    pub const HEADER_SIZE: usize = 8;

    /// Create a standard OBJREF
    pub fn standard(std: StdObjRef, resolver_addr: DualStringArray) -> Self {
        Self::Standard(ObjRefStandard::new(std, resolver_addr))
    }

    /// Get the interface IID from this OBJREF
    pub fn iid(&self) -> Option<&dcerpc::Uuid> {
        match self {
            Self::Standard(s) => Some(s.std.ipid.uuid()),
            Self::Handler(h) => Some(h.std.ipid.uuid()),
            Self::Extended(e) => Some(e.std.ipid.uuid()),
            Self::Custom(_) => None,
        }
    }

    /// Get the STDOBJREF if this is a standard-like variant
    pub fn std_obj_ref(&self) -> Option<&StdObjRef> {
        match self {
            Self::Standard(s) => Some(&s.std),
            Self::Handler(h) => Some(&h.std),
            Self::Extended(e) => Some(&e.std),
            Self::Custom(_) => None,
        }
    }

    /// Get the flags for this variant
    pub fn flags(&self) -> u32 {
        match self {
            Self::Standard(_) => objref_flags::OBJREF_STANDARD,
            Self::Handler(_) => objref_flags::OBJREF_HANDLER,
            Self::Custom(_) => objref_flags::OBJREF_CUSTOM,
            Self::Extended(_) => objref_flags::OBJREF_EXTENDED,
        }
    }

    /// Encode to buffer with header
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        // Write signature
        if little_endian {
            buf.put_u32_le(OBJREF_SIGNATURE);
            buf.put_u32_le(self.flags());
        } else {
            buf.put_u32(OBJREF_SIGNATURE);
            buf.put_u32(self.flags());
        }

        // Write IID (for standard, handler, extended variants)
        match self {
            Self::Standard(s) => {
                encode_uuid(s.std.ipid.uuid(), buf, little_endian);
                s.encode(buf, little_endian);
            }
            Self::Handler(h) => {
                encode_uuid(h.std.ipid.uuid(), buf, little_endian);
                h.encode(buf, little_endian);
            }
            Self::Extended(e) => {
                encode_uuid(e.std.ipid.uuid(), buf, little_endian);
                e.encode(buf, little_endian);
            }
            Self::Custom(c) => {
                c.encode(buf, little_endian);
            }
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::HEADER_SIZE {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::HEADER_SIZE,
                have: buf.remaining(),
            });
        }

        let signature = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        if signature != OBJREF_SIGNATURE {
            return Err(crate::types::DcomError::InvalidObjRef(format!(
                "invalid signature: expected 0x{:08x}, got 0x{:08x}",
                OBJREF_SIGNATURE, signature
            )));
        }

        let flags = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        match flags {
            objref_flags::OBJREF_STANDARD => {
                // Skip IID (already in STDOBJREF.ipid)
                if buf.remaining() < 16 {
                    return Err(crate::types::DcomError::BufferUnderflow {
                        needed: 16,
                        have: buf.remaining(),
                    });
                }
                let _iid = decode_uuid(buf, little_endian);
                Ok(Self::Standard(ObjRefStandard::decode(buf, little_endian)?))
            }
            objref_flags::OBJREF_HANDLER => {
                if buf.remaining() < 16 {
                    return Err(crate::types::DcomError::BufferUnderflow {
                        needed: 16,
                        have: buf.remaining(),
                    });
                }
                let _iid = decode_uuid(buf, little_endian);
                Ok(Self::Handler(ObjRefHandler::decode(buf, little_endian)?))
            }
            objref_flags::OBJREF_CUSTOM => {
                Ok(Self::Custom(ObjRefCustom::decode(buf, little_endian)?))
            }
            objref_flags::OBJREF_EXTENDED => {
                if buf.remaining() < 16 {
                    return Err(crate::types::DcomError::BufferUnderflow {
                        needed: 16,
                        have: buf.remaining(),
                    });
                }
                let _iid = decode_uuid(buf, little_endian);
                Ok(Self::Extended(ObjRefExtended::decode(buf, little_endian)?))
            }
            _ => Err(crate::types::DcomError::InvalidObjRef(format!(
                "unknown OBJREF flags: 0x{:08x}",
                flags
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::identifiers::generate_uuid;
    use bytes::BytesMut;

    #[test]
    fn test_objref_signature() {
        // "MEOW" in little-endian
        assert_eq!(OBJREF_SIGNATURE, 0x574F454D);
        let bytes = OBJREF_SIGNATURE.to_le_bytes();
        assert_eq!(&bytes, b"MEOW");
    }

    #[test]
    fn test_objref_standard_encode_decode() {
        let oxid = Oxid::new(0x123456789ABCDEF0);
        let oid = Oid::new(0xFEDCBA9876543210);
        let ipid = Ipid::generate();
        let std = StdObjRef::new(oxid, oid, ipid, 5);
        let dsa = DualStringArray::with_tcp_binding("127.0.0.1");

        let objref = ObjRef::standard(std, dsa);

        let mut buf = BytesMut::new();
        objref.encode(&mut buf, true);

        let decoded = ObjRef::decode(&mut buf.freeze(), true).unwrap();
        assert!(matches!(decoded, ObjRef::Standard(_)));

        if let ObjRef::Standard(s) = decoded {
            assert_eq!(s.std.oxid, oxid);
            assert_eq!(s.std.oid, oid);
        }
    }

    #[test]
    fn test_objref_custom() {
        let clsid = generate_uuid();
        let data = Bytes::from_static(b"custom marshal data");
        let objref = ObjRef::Custom(ObjRefCustom::new(clsid, data.clone()));

        let mut buf = BytesMut::new();
        objref.encode(&mut buf, true);

        let decoded = ObjRef::decode(&mut buf.freeze(), true).unwrap();
        assert!(matches!(decoded, ObjRef::Custom(_)));

        if let ObjRef::Custom(c) = decoded {
            assert_eq!(c.clsid, clsid);
            assert_eq!(c.data, data);
        }
    }
}
