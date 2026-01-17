//! DCE RPC Connectionless (Datagram) Protocol
//!
//! This module implements the DCE RPC connectionless (CL) wire format
//! as defined in DCE 1.1 RPC specification Chapter 12.
//!
//! The connectionless protocol uses UDP transport and has a completely
//! different PDU format from the connection-oriented (CO) protocol.
//!
//! Key differences from connection-oriented:
//! - Fixed 80-byte header (vs 16-byte CO header)
//! - RPC version 4 (vs version 5 for CO)
//! - No bind/bind_ack - uses request/response directly
//! - Activity ID instead of call ID
//! - Sequence numbers for ordering
//! - Fragment numbers for reassembly

use crate::dcerpc::{DataRepresentation, Uuid};
use crate::error::{Result, RpcError};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

/// DCE RPC connectionless protocol version
pub const DCE_RPC_CL_VERSION: u8 = 4;

/// Connectionless PDU header size (fixed at 80 bytes)
pub const CL_HEADER_SIZE: usize = 80;

/// Connectionless packet types (5 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClPacketType {
    /// Request PDU
    Request = 0,
    /// Ping PDU (client keepalive)
    Ping = 1,
    /// Response PDU
    Response = 2,
    /// Fault PDU
    Fault = 3,
    /// Working PDU (server is processing)
    Working = 4,
    /// Nocall PDU (no call in progress)
    Nocall = 5,
    /// Reject PDU
    Reject = 6,
    /// Ack PDU (acknowledge receipt)
    Ack = 7,
    /// Cancel PDU (cancel call)
    Quit = 8,
    /// Fack PDU (fragment acknowledge)
    Fack = 9,
    /// Quack PDU (quit acknowledge)
    Quack = 10,
}

impl ClPacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x1F {
            0 => Some(Self::Request),
            1 => Some(Self::Ping),
            2 => Some(Self::Response),
            3 => Some(Self::Fault),
            4 => Some(Self::Working),
            5 => Some(Self::Nocall),
            6 => Some(Self::Reject),
            7 => Some(Self::Ack),
            8 => Some(Self::Quit),
            9 => Some(Self::Fack),
            10 => Some(Self::Quack),
            _ => None,
        }
    }
}

/// Connectionless packet flags (flags1)
#[derive(Debug, Clone, Copy, Default)]
pub struct ClFlags1(u8);

impl ClFlags1 {
    /// Reserved (bit 0)
    pub const RESERVED: u8 = 0x01;
    /// Last fragment
    pub const LASTFRAG: u8 = 0x02;
    /// First fragment
    pub const FRAG: u8 = 0x04;
    /// No fragment acknowledge requested
    pub const NOFACK: u8 = 0x08;
    /// Maybe call semantics
    pub const MAYBE: u8 = 0x10;
    /// Idempotent call
    pub const IDEMPOTENT: u8 = 0x20;
    /// Broadcast call
    pub const BROADCAST: u8 = 0x40;
    /// Reserved (bit 7)
    pub const RESERVED2: u8 = 0x80;

    pub fn new() -> Self {
        Self(0)
    }

    /// Create flags for a non-fragmented request
    pub fn request() -> Self {
        Self(Self::LASTFRAG)
    }

    pub fn set_frag(&mut self) -> &mut Self {
        self.0 |= Self::FRAG;
        self
    }

    pub fn set_lastfrag(&mut self) -> &mut Self {
        self.0 |= Self::LASTFRAG;
        self
    }

    pub fn set_idempotent(&mut self) -> &mut Self {
        self.0 |= Self::IDEMPOTENT;
        self
    }

    pub fn is_frag(&self) -> bool {
        (self.0 & Self::FRAG) != 0
    }

    pub fn is_lastfrag(&self) -> bool {
        (self.0 & Self::LASTFRAG) != 0
    }

    pub fn is_idempotent(&self) -> bool {
        (self.0 & Self::IDEMPOTENT) != 0
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

/// Connectionless packet flags (flags2)
#[derive(Debug, Clone, Copy, Default)]
pub struct ClFlags2(u8);

impl ClFlags2 {
    /// Reserved (bit 0)
    pub const RESERVED: u8 = 0x01;
    /// Cancel pending
    pub const CANCEL_PENDING: u8 = 0x02;
    /// Reserved bits 2-7
    pub const RESERVED2: u8 = 0xFC;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

/// Connectionless PDU header (80 bytes)
///
/// Wire format:
/// ```text
/// Offset  Size  Field
/// 0       1     rpc_vers (4)
/// 1       1     ptype
/// 2       1     flags1
/// 3       1     flags2
/// 4       3     drep (data representation, only 3 bytes in CL)
/// 7       1     serial_hi
/// 8       16    object UUID
/// 24      16    interface UUID
/// 40      16    activity UUID
/// 56      4     server_boot
/// 60      4     if_vers (interface version)
/// 64      4     seqnum (sequence number)
/// 68      2     opnum (operation number)
/// 70      2     ihint (interface hint)
/// 72      2     ahint (activity hint)
/// 74      2     len (body length)
/// 76      2     fragnum (fragment number)
/// 78      1     auth_proto
/// 79      1     serial_lo
/// ```
#[derive(Debug, Clone)]
pub struct ClPduHeader {
    /// RPC version (should be 4)
    pub rpc_vers: u8,
    /// Packet type
    pub ptype: ClPacketType,
    /// Packet flags 1
    pub flags1: ClFlags1,
    /// Packet flags 2
    pub flags2: ClFlags2,
    /// Data representation (only 3 bytes used in CL)
    pub drep: DataRepresentation,
    /// Serial number high byte
    pub serial_hi: u8,
    /// Object UUID
    pub object: Uuid,
    /// Interface UUID
    pub if_id: Uuid,
    /// Activity UUID (identifies the call)
    pub act_id: Uuid,
    /// Server boot time
    pub server_boot: u32,
    /// Interface version
    pub if_vers: u32,
    /// Sequence number
    pub seqnum: u32,
    /// Operation number
    pub opnum: u16,
    /// Interface hint
    pub ihint: u16,
    /// Activity hint
    pub ahint: u16,
    /// Body length
    pub len: u16,
    /// Fragment number
    pub fragnum: u16,
    /// Authentication protocol identifier
    pub auth_proto: u8,
    /// Serial number low byte
    pub serial_lo: u8,
}

impl ClPduHeader {
    /// Create a new request header
    pub fn new_request(
        if_id: Uuid,
        if_vers: u32,
        act_id: Uuid,
        seqnum: u32,
        opnum: u16,
    ) -> Self {
        Self {
            rpc_vers: DCE_RPC_CL_VERSION,
            ptype: ClPacketType::Request,
            flags1: ClFlags1::request(),
            flags2: ClFlags2::new(),
            drep: DataRepresentation::ndr(),
            serial_hi: 0,
            object: Uuid::NIL,
            if_id,
            act_id,
            server_boot: 0,
            if_vers,
            seqnum,
            opnum,
            ihint: 0xFFFF, // No hint
            ahint: 0xFFFF, // No hint
            len: 0,        // Set when encoding
            fragnum: 0,
            auth_proto: 0,
            serial_lo: 0,
        }
    }

    /// Create a new response header
    pub fn new_response(request: &ClPduHeader) -> Self {
        Self {
            rpc_vers: DCE_RPC_CL_VERSION,
            ptype: ClPacketType::Response,
            flags1: ClFlags1::request(), // LASTFRAG set
            flags2: ClFlags2::new(),
            drep: DataRepresentation::ndr(),
            serial_hi: 0,
            object: request.object,
            if_id: request.if_id,
            act_id: request.act_id,
            server_boot: 0, // Set by server
            if_vers: request.if_vers,
            seqnum: request.seqnum,
            opnum: request.opnum,
            ihint: request.ihint,
            ahint: request.ahint,
            len: 0, // Set when encoding
            fragnum: 0,
            auth_proto: 0,
            serial_lo: 0,
        }
    }

    /// Get the serial number (combined from hi and lo bytes)
    pub fn serial(&self) -> u16 {
        ((self.serial_hi as u16) << 8) | (self.serial_lo as u16)
    }

    /// Set the serial number
    pub fn set_serial(&mut self, serial: u16) {
        self.serial_hi = (serial >> 8) as u8;
        self.serial_lo = serial as u8;
    }

    /// Encode the header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let le = self.drep.is_little_endian();

        buf.put_u8(self.rpc_vers);
        buf.put_u8(self.ptype as u8);
        buf.put_u8(self.flags1.as_u8());
        buf.put_u8(self.flags2.as_u8());

        // Data representation (only 3 bytes in CL)
        let drep_bytes = self.drep.encode();
        buf.put_slice(&drep_bytes[0..3]);

        buf.put_u8(self.serial_hi);

        // Object UUID
        self.object.encode(buf, le);

        // Interface UUID
        self.if_id.encode(buf, le);

        // Activity UUID
        self.act_id.encode(buf, le);

        // Multi-byte fields respect endianness
        if le {
            buf.put_u32_le(self.server_boot);
            buf.put_u32_le(self.if_vers);
            buf.put_u32_le(self.seqnum);
            buf.put_u16_le(self.opnum);
            buf.put_u16_le(self.ihint);
            buf.put_u16_le(self.ahint);
            buf.put_u16_le(self.len);
            buf.put_u16_le(self.fragnum);
        } else {
            buf.put_u32(self.server_boot);
            buf.put_u32(self.if_vers);
            buf.put_u32(self.seqnum);
            buf.put_u16(self.opnum);
            buf.put_u16(self.ihint);
            buf.put_u16(self.ahint);
            buf.put_u16(self.len);
            buf.put_u16(self.fragnum);
        }

        buf.put_u8(self.auth_proto);
        buf.put_u8(self.serial_lo);
    }

    /// Decode a header from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < CL_HEADER_SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("CL PDU header too short: {} bytes, need {}", data.len(), CL_HEADER_SIZE),
            )));
        }

        let rpc_vers = data[0];
        if rpc_vers != DCE_RPC_CL_VERSION {
            return Err(RpcError::RpcVersionMismatch(rpc_vers as u32));
        }

        let ptype = ClPacketType::from_u8(data[1])
            .ok_or_else(|| RpcError::InvalidMessageType(data[1] as i32))?;
        let flags1 = ClFlags1::from_u8(data[2]);
        let flags2 = ClFlags2::from_u8(data[3]);

        // Data representation (3 bytes, pad with 0 for decode)
        let drep = DataRepresentation::decode([data[4], data[5], data[6], 0]);
        let le = drep.is_little_endian();

        let serial_hi = data[7];

        let mut cursor = Cursor::new(&data[8..]);

        let object = Uuid::decode(&mut cursor, le)?;
        let if_id = Uuid::decode(&mut cursor, le)?;
        let act_id = Uuid::decode(&mut cursor, le)?;

        let server_boot = if le { cursor.get_u32_le() } else { cursor.get_u32() };
        let if_vers = if le { cursor.get_u32_le() } else { cursor.get_u32() };
        let seqnum = if le { cursor.get_u32_le() } else { cursor.get_u32() };
        let opnum = if le { cursor.get_u16_le() } else { cursor.get_u16() };
        let ihint = if le { cursor.get_u16_le() } else { cursor.get_u16() };
        let ahint = if le { cursor.get_u16_le() } else { cursor.get_u16() };
        let len = if le { cursor.get_u16_le() } else { cursor.get_u16() };
        let fragnum = if le { cursor.get_u16_le() } else { cursor.get_u16() };
        let auth_proto = cursor.get_u8();
        let serial_lo = cursor.get_u8();

        Ok(Self {
            rpc_vers,
            ptype,
            flags1,
            flags2,
            drep,
            serial_hi,
            object,
            if_id,
            act_id,
            server_boot,
            if_vers,
            seqnum,
            opnum,
            ihint,
            ahint,
            len,
            fragnum,
            auth_proto,
            serial_lo,
        })
    }
}

/// Connectionless Request PDU
#[derive(Debug, Clone)]
pub struct ClRequestPdu {
    pub header: ClPduHeader,
    pub body: Bytes,
}

impl ClRequestPdu {
    pub fn new(
        if_id: Uuid,
        if_vers: u32,
        act_id: Uuid,
        seqnum: u32,
        opnum: u16,
        body: Bytes,
    ) -> Self {
        let mut header = ClPduHeader::new_request(if_id, if_vers, act_id, seqnum, opnum);
        header.len = body.len() as u16;
        Self { header, body }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + self.body.len());

        // Encode header with correct body length
        let mut header = self.header.clone();
        header.len = self.body.len() as u16;
        header.encode(&mut buf);

        // Append body
        buf.put_slice(&self.body);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Request {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }

        let body_start = CL_HEADER_SIZE;
        let body_end = body_start + header.len as usize;

        if data.len() < body_end {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("CL request body too short: have {}, need {}", data.len() - body_start, header.len),
            )));
        }

        let body = Bytes::copy_from_slice(&data[body_start..body_end]);

        Ok(Self { header, body })
    }
}

/// Connectionless Response PDU
#[derive(Debug, Clone)]
pub struct ClResponsePdu {
    pub header: ClPduHeader,
    pub body: Bytes,
}

impl ClResponsePdu {
    pub fn new(request: &ClPduHeader, body: Bytes) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.len = body.len() as u16;
        Self { header, body }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + self.body.len());

        let mut header = self.header.clone();
        header.len = self.body.len() as u16;
        header.encode(&mut buf);

        buf.put_slice(&self.body);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Response {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }

        let body_start = CL_HEADER_SIZE;
        let body_end = body_start + header.len as usize;

        if data.len() < body_end {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("CL response body too short: have {}, need {}", data.len() - body_start, header.len),
            )));
        }

        let body = Bytes::copy_from_slice(&data[body_start..body_end]);

        Ok(Self { header, body })
    }
}

/// Connectionless Fault PDU
#[derive(Debug, Clone)]
pub struct ClFaultPdu {
    pub header: ClPduHeader,
    pub status: u32,
}

impl ClFaultPdu {
    pub fn new(request: &ClPduHeader, status: u32) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.ptype = ClPacketType::Fault;
        header.len = 4; // Status is 4 bytes
        Self { header, status }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + 4);
        let le = self.header.drep.is_little_endian();

        let mut header = self.header.clone();
        header.len = 4;
        header.encode(&mut buf);

        if le {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Fault {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }

        if data.len() < CL_HEADER_SIZE + 4 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CL fault body too short",
            )));
        }

        let le = header.drep.is_little_endian();
        let status = if le {
            u32::from_le_bytes([data[80], data[81], data[82], data[83]])
        } else {
            u32::from_be_bytes([data[80], data[81], data[82], data[83]])
        };

        Ok(Self { header, status })
    }
}

/// Connectionless Working PDU (server is still processing)
#[derive(Debug, Clone)]
pub struct ClWorkingPdu {
    pub header: ClPduHeader,
}

impl ClWorkingPdu {
    pub fn new(request: &ClPduHeader) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.ptype = ClPacketType::Working;
        header.len = 0;
        Self { header }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE);
        self.header.encode(&mut buf);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Working {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }
        Ok(Self { header })
    }
}

/// Connectionless Nocall PDU (no call with given activity ID)
#[derive(Debug, Clone)]
pub struct ClNocallPdu {
    pub header: ClPduHeader,
}

impl ClNocallPdu {
    pub fn new(request: &ClPduHeader) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.ptype = ClPacketType::Nocall;
        header.len = 0;
        Self { header }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE);
        self.header.encode(&mut buf);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Nocall {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }
        Ok(Self { header })
    }
}

/// Connectionless Reject PDU
#[derive(Debug, Clone)]
pub struct ClRejectPdu {
    pub header: ClPduHeader,
    pub status: u32,
}

impl ClRejectPdu {
    pub fn new(request: &ClPduHeader, status: u32) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.ptype = ClPacketType::Reject;
        header.len = 4;
        Self { header, status }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + 4);
        let le = self.header.drep.is_little_endian();

        let mut header = self.header.clone();
        header.len = 4;
        header.encode(&mut buf);

        if le {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Reject {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }

        if data.len() < CL_HEADER_SIZE + 4 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "CL reject body too short",
            )));
        }

        let le = header.drep.is_little_endian();
        let status = if le {
            u32::from_le_bytes([data[80], data[81], data[82], data[83]])
        } else {
            u32::from_be_bytes([data[80], data[81], data[82], data[83]])
        };

        Ok(Self { header, status })
    }
}

/// Connectionless Ping PDU (client keepalive/query)
#[derive(Debug, Clone)]
pub struct ClPingPdu {
    pub header: ClPduHeader,
}

impl ClPingPdu {
    pub fn new(request: &ClPduHeader) -> Self {
        let mut header = request.clone();
        header.ptype = ClPacketType::Ping;
        header.len = 0;
        Self { header }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE);
        self.header.encode(&mut buf);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Ping {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }
        Ok(Self { header })
    }
}

/// Connectionless Ack PDU
#[derive(Debug, Clone)]
pub struct ClAckPdu {
    pub header: ClPduHeader,
}

impl ClAckPdu {
    pub fn new(request: &ClPduHeader) -> Self {
        let mut header = ClPduHeader::new_response(request);
        header.ptype = ClPacketType::Ack;
        header.len = 0;
        Self { header }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE);
        self.header.encode(&mut buf);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = ClPduHeader::decode(data)?;
        if header.ptype != ClPacketType::Ack {
            return Err(RpcError::InvalidMessageType(header.ptype as u8 as i32));
        }
        Ok(Self { header })
    }
}

/// Parsed connectionless PDU
#[derive(Debug, Clone)]
pub enum ClPdu {
    Request(ClRequestPdu),
    Response(ClResponsePdu),
    Fault(ClFaultPdu),
    Working(ClWorkingPdu),
    Nocall(ClNocallPdu),
    Reject(ClRejectPdu),
    Ping(ClPingPdu),
    Ack(ClAckPdu),
}

impl ClPdu {
    /// Decode a connectionless PDU from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < CL_HEADER_SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("CL PDU too short: {} bytes", data.len()),
            )));
        }

        let ptype = ClPacketType::from_u8(data[1])
            .ok_or_else(|| RpcError::InvalidMessageType(data[1] as i32))?;

        match ptype {
            ClPacketType::Request => Ok(ClPdu::Request(ClRequestPdu::decode(data)?)),
            ClPacketType::Response => Ok(ClPdu::Response(ClResponsePdu::decode(data)?)),
            ClPacketType::Fault => Ok(ClPdu::Fault(ClFaultPdu::decode(data)?)),
            ClPacketType::Working => Ok(ClPdu::Working(ClWorkingPdu::decode(data)?)),
            ClPacketType::Nocall => Ok(ClPdu::Nocall(ClNocallPdu::decode(data)?)),
            ClPacketType::Reject => Ok(ClPdu::Reject(ClRejectPdu::decode(data)?)),
            ClPacketType::Ping => Ok(ClPdu::Ping(ClPingPdu::decode(data)?)),
            ClPacketType::Ack => Ok(ClPdu::Ack(ClAckPdu::decode(data)?)),
            _ => Err(RpcError::InvalidMessageType(ptype as u8 as i32)),
        }
    }

    /// Get the header from any PDU type
    pub fn header(&self) -> &ClPduHeader {
        match self {
            ClPdu::Request(p) => &p.header,
            ClPdu::Response(p) => &p.header,
            ClPdu::Fault(p) => &p.header,
            ClPdu::Working(p) => &p.header,
            ClPdu::Nocall(p) => &p.header,
            ClPdu::Reject(p) => &p.header,
            ClPdu::Ping(p) => &p.header,
            ClPdu::Ack(p) => &p.header,
        }
    }

    /// Encode the PDU to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            ClPdu::Request(p) => p.encode(),
            ClPdu::Response(p) => p.encode(),
            ClPdu::Fault(p) => p.encode(),
            ClPdu::Working(p) => p.encode(),
            ClPdu::Nocall(p) => p.encode(),
            ClPdu::Reject(p) => p.encode(),
            ClPdu::Ping(p) => p.encode(),
            ClPdu::Ack(p) => p.encode(),
        }
    }
}

/// Generate a new random activity ID
pub fn new_activity_id() -> Uuid {
    // Generate random UUID for activity ID
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    Uuid {
        time_low: now.as_secs() as u32,
        time_mid: now.subsec_millis() as u16,
        time_hi_and_version: (std::process::id() as u16) | 0x4000, // Version 4
        clock_seq_hi_and_reserved: 0x80 | (rand_u8() & 0x3F),
        clock_seq_low: rand_u8(),
        node: [rand_u8(), rand_u8(), rand_u8(), rand_u8(), rand_u8(), rand_u8()],
    }
}

fn rand_u8() -> u8 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(std::time::Instant::now().elapsed().as_nanos() as u64);
    h.finish() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cl_header_size() {
        let header = ClPduHeader::new_request(
            Uuid::NIL,
            1,
            Uuid::NIL,
            0,
            0,
        );
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), CL_HEADER_SIZE);
    }

    #[test]
    fn test_cl_request_roundtrip() {
        let act_id = new_activity_id();
        let if_id = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();

        let request = ClRequestPdu::new(
            if_id,
            1,
            act_id,
            0,
            5,
            Bytes::from_static(b"test data"),
        );

        let encoded = request.encode();
        assert_eq!(encoded.len(), CL_HEADER_SIZE + 9);

        let decoded = ClRequestPdu::decode(&encoded).unwrap();
        assert_eq!(decoded.header.ptype, ClPacketType::Request);
        assert_eq!(decoded.header.opnum, 5);
        assert_eq!(decoded.header.seqnum, 0);
        assert_eq!(decoded.body.as_ref(), b"test data");
    }

    #[test]
    fn test_cl_response_roundtrip() {
        let act_id = new_activity_id();
        let if_id = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();

        let request_header = ClPduHeader::new_request(if_id, 1, act_id, 0, 5);
        let response = ClResponsePdu::new(&request_header, Bytes::from_static(b"response"));

        let encoded = response.encode();
        let decoded = ClResponsePdu::decode(&encoded).unwrap();

        assert_eq!(decoded.header.ptype, ClPacketType::Response);
        assert_eq!(decoded.header.act_id, act_id);
        assert_eq!(decoded.body.as_ref(), b"response");
    }

    #[test]
    fn test_cl_fault_roundtrip() {
        let act_id = new_activity_id();
        let if_id = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();

        let request_header = ClPduHeader::new_request(if_id, 1, act_id, 0, 5);
        let fault = ClFaultPdu::new(&request_header, 0x1c010003);

        let encoded = fault.encode();
        let decoded = ClFaultPdu::decode(&encoded).unwrap();

        assert_eq!(decoded.header.ptype, ClPacketType::Fault);
        assert_eq!(decoded.status, 0x1c010003);
    }
}
