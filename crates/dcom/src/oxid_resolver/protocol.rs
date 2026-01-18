//! IObjectExporter wire protocol (MS-DCOM 3.1.2.5.2)
//!
//! Defines the NDR-encoded structures for OXID resolver operations.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::types::{
    DcomError, Result, Oxid, Oid, SetId, Ipid,
    DualStringArray, ComVersion,
};

/// IObjectExporter interface UUID
pub const OBJECT_EXPORTER_UUID: &str = "99fcfec4-5260-101b-bbcb-00aa0021347a";

/// IObjectExporter interface version
pub const OBJECT_EXPORTER_VERSION: (u16, u16) = (0, 0);

/// Operation numbers for IObjectExporter
pub mod opnum {
    /// ResolveOxid operation
    pub const RESOLVE_OXID: u16 = 0;
    /// SimplePing operation
    pub const SIMPLE_PING: u16 = 1;
    /// ComplexPing operation
    pub const COMPLEX_PING: u16 = 2;
    /// ServerAlive operation
    pub const SERVER_ALIVE: u16 = 3;
    /// ResolveOxid2 operation
    pub const RESOLVE_OXID2: u16 = 4;
    /// ServerAlive2 operation
    pub const SERVER_ALIVE2: u16 = 5;
}

/// ResolveOxid request (MS-DCOM 3.1.2.5.2.1)
#[derive(Clone, Debug)]
pub struct ResolveOxidRequest {
    /// OXID to resolve
    pub oxid: Oxid,
    /// Number of requested protocol sequences
    pub requested_protseqs_count: u16,
    /// Requested protocol sequences
    pub requested_protseqs: Vec<u16>,
}

impl ResolveOxidRequest {
    /// Create a new ResolveOxid request
    pub fn new(oxid: Oxid, protseqs: Vec<u16>) -> Self {
        Self {
            oxid,
            requested_protseqs_count: protseqs.len() as u16,
            requested_protseqs: protseqs,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.oxid.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.requested_protseqs_count);
        } else {
            buf.put_u16(self.requested_protseqs_count);
        }
        for ps in &self.requested_protseqs {
            if little_endian {
                buf.put_u16_le(*ps);
            } else {
                buf.put_u16(*ps);
            }
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 10 {
            return Err(DcomError::BufferUnderflow {
                needed: 10,
                have: buf.remaining(),
            });
        }
        let oxid = Oxid::decode(buf, little_endian);
        let count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let mut protseqs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if buf.remaining() < 2 {
                break;
            }
            let ps = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            protseqs.push(ps);
        }
        Ok(Self {
            oxid,
            requested_protseqs_count: count,
            requested_protseqs: protseqs,
        })
    }
}

/// ResolveOxid response
#[derive(Clone, Debug)]
pub struct ResolveOxidResponse {
    /// Binding strings for the OXID
    pub oxid_bindings: DualStringArray,
    /// IPID for IRemUnknown
    pub ipid_rem_unknown: Ipid,
    /// Authentication hint
    pub authn_hint: u32,
    /// Result status
    pub status: u32,
}

impl ResolveOxidResponse {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.oxid_bindings.encode(&mut buf, little_endian);
        self.ipid_rem_unknown.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.authn_hint);
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.authn_hint);
            buf.put_u32(self.status);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let oxid_bindings = DualStringArray::decode(buf, little_endian)?;
        let ipid_rem_unknown = Ipid::decode(buf, little_endian);
        if buf.remaining() < 8 {
            return Err(DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }
        let authn_hint = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let status = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        Ok(Self {
            oxid_bindings,
            ipid_rem_unknown,
            authn_hint,
            status,
        })
    }
}

/// ResolveOxid2 request (MS-DCOM 3.1.2.5.2.3.1)
#[derive(Clone, Debug)]
pub struct ResolveOxid2Request {
    /// OXID to resolve
    pub oxid: Oxid,
    /// Number of requested protocol sequences
    pub requested_protseqs_count: u16,
    /// Requested protocol sequences
    pub requested_protseqs: Vec<u16>,
}

impl ResolveOxid2Request {
    /// Create a new ResolveOxid2 request
    pub fn new(oxid: Oxid, protseqs: Vec<u16>) -> Self {
        Self {
            oxid,
            requested_protseqs_count: protseqs.len() as u16,
            requested_protseqs: protseqs,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.oxid.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.requested_protseqs_count);
        } else {
            buf.put_u16(self.requested_protseqs_count);
        }
        for ps in &self.requested_protseqs {
            if little_endian {
                buf.put_u16_le(*ps);
            } else {
                buf.put_u16(*ps);
            }
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 10 {
            return Err(DcomError::BufferUnderflow {
                needed: 10,
                have: buf.remaining(),
            });
        }
        let oxid = Oxid::decode(buf, little_endian);
        let count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let mut protseqs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if buf.remaining() < 2 {
                break;
            }
            let ps = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            protseqs.push(ps);
        }
        Ok(Self {
            oxid,
            requested_protseqs_count: count,
            requested_protseqs: protseqs,
        })
    }
}

/// ResolveOxid2 response
#[derive(Clone, Debug)]
pub struct ResolveOxid2Response {
    /// Binding strings for the OXID
    pub oxid_bindings: DualStringArray,
    /// IPID for IRemUnknown
    pub ipid_rem_unknown: Ipid,
    /// Authentication hint
    pub authn_hint: u32,
    /// COM version
    pub com_version: ComVersion,
    /// Result status
    pub status: u32,
}

impl ResolveOxid2Response {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.oxid_bindings.encode(&mut buf, little_endian);
        self.ipid_rem_unknown.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.authn_hint);
        } else {
            buf.put_u32(self.authn_hint);
        }
        self.com_version.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let oxid_bindings = DualStringArray::decode(buf, little_endian)?;
        let ipid_rem_unknown = Ipid::decode(buf, little_endian);
        if buf.remaining() < 12 {
            return Err(DcomError::BufferUnderflow {
                needed: 12,
                have: buf.remaining(),
            });
        }
        let authn_hint = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let com_version = ComVersion::decode(buf, little_endian);
        let status = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        Ok(Self {
            oxid_bindings,
            ipid_rem_unknown,
            authn_hint,
            com_version,
            status,
        })
    }
}

/// SimplePing request (MS-DCOM 3.1.2.5.2.1.2)
#[derive(Clone, Debug)]
pub struct SimplePingRequest {
    /// Set ID to ping
    pub set_id: SetId,
}

impl SimplePingRequest {
    /// Create a new SimplePing request
    pub fn new(set_id: SetId) -> Self {
        Self { set_id }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.set_id.encode(&mut buf, little_endian);
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }
        Ok(Self {
            set_id: SetId::decode(buf, little_endian),
        })
    }
}

/// SimplePing response
#[derive(Clone, Debug)]
pub struct SimplePingResponse {
    /// Result status
    pub status: u32,
}

impl SimplePingResponse {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        if little_endian {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }
        let status = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        Ok(Self { status })
    }
}

/// ComplexPing request (MS-DCOM 3.1.2.5.2.2)
#[derive(Clone, Debug)]
pub struct ComplexPingRequest {
    /// Set ID (0 to create new set)
    pub set_id: SetId,
    /// Sequence number
    pub sequence_num: u16,
    /// Number of OIDs to add
    pub add_count: u16,
    /// Number of OIDs to delete
    pub del_count: u16,
    /// OIDs to add to the set
    pub add_oids: Vec<Oid>,
    /// OIDs to delete from the set
    pub del_oids: Vec<Oid>,
}

impl ComplexPingRequest {
    /// Create a new ComplexPing request
    pub fn new(set_id: SetId, sequence_num: u16, add_oids: Vec<Oid>, del_oids: Vec<Oid>) -> Self {
        Self {
            set_id,
            sequence_num,
            add_count: add_oids.len() as u16,
            del_count: del_oids.len() as u16,
            add_oids,
            del_oids,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.set_id.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.sequence_num);
            buf.put_u16_le(self.add_count);
            buf.put_u16_le(self.del_count);
        } else {
            buf.put_u16(self.sequence_num);
            buf.put_u16(self.add_count);
            buf.put_u16(self.del_count);
        }
        for oid in &self.add_oids {
            oid.encode(&mut buf, little_endian);
        }
        for oid in &self.del_oids {
            oid.encode(&mut buf, little_endian);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 14 {
            return Err(DcomError::BufferUnderflow {
                needed: 14,
                have: buf.remaining(),
            });
        }
        let set_id = SetId::decode(buf, little_endian);
        let sequence_num = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let add_count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let del_count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };

        let mut add_oids = Vec::with_capacity(add_count as usize);
        for _ in 0..add_count {
            if buf.remaining() < 8 {
                break;
            }
            add_oids.push(Oid::decode(buf, little_endian));
        }

        let mut del_oids = Vec::with_capacity(del_count as usize);
        for _ in 0..del_count {
            if buf.remaining() < 8 {
                break;
            }
            del_oids.push(Oid::decode(buf, little_endian));
        }

        Ok(Self {
            set_id,
            sequence_num,
            add_count,
            del_count,
            add_oids,
            del_oids,
        })
    }
}

/// ComplexPing response
#[derive(Clone, Debug)]
pub struct ComplexPingResponse {
    /// Assigned or confirmed set ID
    pub set_id: SetId,
    /// Ping backoff factor
    pub ping_backoff_factor: u16,
    /// Result status
    pub status: u32,
}

impl ComplexPingResponse {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.set_id.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.ping_backoff_factor);
            buf.put_u16_le(0); // padding
            buf.put_u32_le(self.status);
        } else {
            buf.put_u16(self.ping_backoff_factor);
            buf.put_u16(0);
            buf.put_u32(self.status);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 14 {
            return Err(DcomError::BufferUnderflow {
                needed: 14,
                have: buf.remaining(),
            });
        }
        let set_id = SetId::decode(buf, little_endian);
        let ping_backoff_factor = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let _padding = buf.get_u16_le();
        let status = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        Ok(Self {
            set_id,
            ping_backoff_factor,
            status,
        })
    }
}

/// ServerAlive response
#[derive(Clone, Debug)]
pub struct ServerAliveResponse {
    /// Result status
    pub status: u32,
}

impl ServerAliveResponse {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        if little_endian {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }
        buf.freeze()
    }
}

/// ServerAlive2 response
#[derive(Clone, Debug)]
pub struct ServerAlive2Response {
    /// COM version
    pub com_version: ComVersion,
    /// Server bindings
    pub bindings: DualStringArray,
    /// Reserved
    pub reserved: u64,
    /// Result status
    pub status: u32,
}

impl ServerAlive2Response {
    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.com_version.encode(&mut buf, little_endian);
        self.bindings.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u64_le(self.reserved);
            buf.put_u32_le(self.status);
        } else {
            buf.put_u64(self.reserved);
            buf.put_u32(self.status);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let com_version = ComVersion::decode(buf, little_endian);
        let bindings = DualStringArray::decode(buf, little_endian)?;
        if buf.remaining() < 12 {
            return Err(DcomError::BufferUnderflow {
                needed: 12,
                have: buf.remaining(),
            });
        }
        let reserved = if little_endian {
            buf.get_u64_le()
        } else {
            buf.get_u64()
        };
        let status = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        Ok(Self {
            com_version,
            bindings,
            reserved,
            status,
        })
    }
}
