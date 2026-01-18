//! IRemUnknown wire protocol (MS-DCOM 3.1.1.5)
//!
//! Defines the NDR-encoded structures for remote IUnknown operations.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::types::{
    DcomError, Result, Ipid, OrpcThis, OrpcThat,
    decode_uuid, encode_uuid,
};

/// IRemUnknown interface UUID
pub const REMUNKNOWN_UUID: &str = "00000131-0000-0000-c000-000000000046";

/// IRemUnknown2 interface UUID
pub const REMUNKNOWN2_UUID: &str = "00000143-0000-0000-c000-000000000046";

/// IRemUnknown interface version
pub const REMUNKNOWN_VERSION: (u16, u16) = (0, 0);

/// Operation numbers for IRemUnknown
pub mod opnum {
    /// QueryInterface - Query additional interfaces
    pub const QUERY_INTERFACE: u16 = 3;
    /// AddRef - Increment reference counts
    pub const ADD_REF: u16 = 4;
    /// Release - Decrement reference counts
    pub const RELEASE: u16 = 5;
}

/// Operation numbers for IRemUnknown2 (extends IRemUnknown)
pub mod opnum2 {
    /// RemQueryInterface2 - Query interfaces with extended info
    pub const QUERY_INTERFACE2: u16 = 6;
}

/// REMQIRESULT structure (MS-DCOM 2.2.23)
#[derive(Clone, Debug)]
pub struct RemQiResult {
    /// HRESULT for this query
    pub hresult: u32,
    /// Standard object reference (if successful)
    pub std: Option<crate::types::StdObjRef>,
}

impl RemQiResult {
    /// Create a successful result
    pub fn success(std: crate::types::StdObjRef) -> Self {
        Self {
            hresult: 0,
            std: Some(std),
        }
    }

    /// Create a failure result
    pub fn failure(hresult: u32) -> Self {
        Self { hresult, std: None }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u32_le(self.hresult);
        } else {
            buf.put_u32(self.hresult);
        }
        if let Some(ref std) = self.std {
            std.encode(buf, little_endian);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let hresult = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let std = if hresult == 0 && buf.remaining() >= crate::types::StdObjRef::SIZE {
            Some(crate::types::StdObjRef::decode(buf, little_endian)?)
        } else {
            None
        };

        Ok(Self { hresult, std })
    }
}

/// REMINTERFACEREF structure (MS-DCOM 2.2.24)
#[derive(Clone, Debug)]
pub struct RemInterfaceRef {
    /// IPID of the interface
    pub ipid: Ipid,
    /// Number of public references to add/release
    pub public_refs: u32,
    /// Number of private references to add/release
    pub private_refs: u32,
}

impl RemInterfaceRef {
    /// Size in bytes
    pub const SIZE: usize = 16 + 4 + 4; // IPID + public + private

    /// Create a new reference operation
    pub fn new(ipid: Ipid, public_refs: u32, private_refs: u32) -> Self {
        Self {
            ipid,
            public_refs,
            private_refs,
        }
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        self.ipid.encode(buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.public_refs);
            buf.put_u32_le(self.private_refs);
        } else {
            buf.put_u32(self.public_refs);
            buf.put_u32(self.private_refs);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        if buf.remaining() < Self::SIZE {
            return Err(DcomError::BufferUnderflow {
                needed: Self::SIZE,
                have: buf.remaining(),
            });
        }

        let ipid = Ipid::decode(buf, little_endian);
        let public_refs = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let private_refs = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        Ok(Self {
            ipid,
            public_refs,
            private_refs,
        })
    }
}

/// RemQueryInterface request (MS-DCOM 3.1.1.5.1.1)
#[derive(Clone, Debug)]
pub struct RemQueryInterfaceRequest {
    /// ORPC header
    pub orpc_this: OrpcThis,
    /// IPID of the object
    pub ipid: Ipid,
    /// Number of public references requested
    pub refs: u32,
    /// Number of IIDs to query
    pub iids_count: u16,
    /// IIDs to query
    pub iids: Vec<dcerpc::Uuid>,
}

impl RemQueryInterfaceRequest {
    /// Create a new QueryInterface request
    pub fn new(ipid: Ipid, iids: Vec<dcerpc::Uuid>, refs: u32) -> Self {
        Self {
            orpc_this: OrpcThis::new(),
            ipid,
            refs,
            iids_count: iids.len() as u16,
            iids,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_this.encode(&mut buf, little_endian);
        self.ipid.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.refs);
            buf.put_u16_le(self.iids_count);
            buf.put_u16_le(0); // padding
        } else {
            buf.put_u32(self.refs);
            buf.put_u16(self.iids_count);
            buf.put_u16(0);
        }
        for iid in &self.iids {
            encode_uuid(iid, &mut buf, little_endian);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let orpc_this = OrpcThis::decode(buf, little_endian)?;
        let ipid = Ipid::decode(buf, little_endian);

        if buf.remaining() < 8 {
            return Err(DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }

        let refs = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let iids_count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let _padding = buf.get_u16();

        let mut iids = Vec::with_capacity(iids_count as usize);
        for _ in 0..iids_count {
            if buf.remaining() < 16 {
                break;
            }
            iids.push(decode_uuid(buf, little_endian));
        }

        Ok(Self {
            orpc_this,
            ipid,
            refs,
            iids_count,
            iids,
        })
    }
}

/// RemQueryInterface response
#[derive(Clone, Debug)]
pub struct RemQueryInterfaceResponse {
    /// ORPC response header
    pub orpc_that: OrpcThat,
    /// Results for each queried interface
    pub results: Vec<RemQiResult>,
    /// HRESULT
    pub hresult: u32,
}

impl RemQueryInterfaceResponse {
    /// Create a successful response
    pub fn success(results: Vec<RemQiResult>) -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            results,
            hresult: 0,
        }
    }

    /// Create a failure response
    pub fn failure(hresult: u32) -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            results: vec![],
            hresult,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_that.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.results.len() as u32);
        } else {
            buf.put_u32(self.results.len() as u32);
        }
        for result in &self.results {
            result.encode(&mut buf, little_endian);
        }
        if little_endian {
            buf.put_u32_le(self.hresult);
        } else {
            buf.put_u32(self.hresult);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let orpc_that = OrpcThat::decode(buf, little_endian)?;

        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let count = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let mut results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            results.push(RemQiResult::decode(buf, little_endian)?);
        }

        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let hresult = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        Ok(Self {
            orpc_that,
            results,
            hresult,
        })
    }
}

/// RemAddRef request (MS-DCOM 3.1.1.5.2.1)
#[derive(Clone, Debug)]
pub struct RemAddRefRequest {
    /// ORPC header
    pub orpc_this: OrpcThis,
    /// Number of interface references
    pub count: u16,
    /// Interface references to add
    pub refs: Vec<RemInterfaceRef>,
}

impl RemAddRefRequest {
    /// Create a new AddRef request
    pub fn new(refs: Vec<RemInterfaceRef>) -> Self {
        Self {
            orpc_this: OrpcThis::new(),
            count: refs.len() as u16,
            refs,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_this.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.count);
            buf.put_u16_le(0); // padding
        } else {
            buf.put_u16(self.count);
            buf.put_u16(0);
        }
        for r in &self.refs {
            r.encode(&mut buf, little_endian);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let orpc_this = OrpcThis::decode(buf, little_endian)?;

        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let _padding = buf.get_u16();

        let mut refs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            refs.push(RemInterfaceRef::decode(buf, little_endian)?);
        }

        Ok(Self {
            orpc_this,
            count,
            refs,
        })
    }
}

/// RemAddRef response
#[derive(Clone, Debug)]
pub struct RemAddRefResponse {
    /// ORPC response header
    pub orpc_that: OrpcThat,
    /// Results for each interface
    pub results: Vec<u32>,
    /// Overall HRESULT
    pub hresult: u32,
}

impl RemAddRefResponse {
    /// Create a successful response
    pub fn success(results: Vec<u32>) -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            results,
            hresult: 0,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_that.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.results.len() as u32);
        } else {
            buf.put_u32(self.results.len() as u32);
        }
        for &result in &self.results {
            if little_endian {
                buf.put_u32_le(result);
            } else {
                buf.put_u32(result);
            }
        }
        if little_endian {
            buf.put_u32_le(self.hresult);
        } else {
            buf.put_u32(self.hresult);
        }
        buf.freeze()
    }
}

/// RemRelease request (MS-DCOM 3.1.1.5.3.1)
#[derive(Clone, Debug)]
pub struct RemReleaseRequest {
    /// ORPC header
    pub orpc_this: OrpcThis,
    /// Number of interface references
    pub count: u16,
    /// Interface references to release
    pub refs: Vec<RemInterfaceRef>,
}

impl RemReleaseRequest {
    /// Create a new Release request
    pub fn new(refs: Vec<RemInterfaceRef>) -> Self {
        Self {
            orpc_this: OrpcThis::new(),
            count: refs.len() as u16,
            refs,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_this.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u16_le(self.count);
            buf.put_u16_le(0); // padding
        } else {
            buf.put_u16(self.count);
            buf.put_u16(0);
        }
        for r in &self.refs {
            r.encode(&mut buf, little_endian);
        }
        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let orpc_this = OrpcThis::decode(buf, little_endian)?;

        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let count = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let _padding = buf.get_u16();

        let mut refs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            refs.push(RemInterfaceRef::decode(buf, little_endian)?);
        }

        Ok(Self {
            orpc_this,
            count,
            refs,
        })
    }
}

/// RemRelease response
#[derive(Clone, Debug)]
pub struct RemReleaseResponse {
    /// ORPC response header
    pub orpc_that: OrpcThat,
    /// Overall HRESULT
    pub hresult: u32,
}

impl RemReleaseResponse {
    /// Create a successful response
    pub fn success() -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            hresult: 0,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_that.encode(&mut buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.hresult);
        } else {
            buf.put_u32(self.hresult);
        }
        buf.freeze()
    }
}
