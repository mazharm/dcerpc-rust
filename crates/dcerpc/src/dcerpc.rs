//! DCE RPC PDU (Protocol Data Unit) types
//!
//! This module implements the DCE RPC wire format as defined in:
//! - DCE 1.1: Remote Procedure Call (C706)
//! - MS-RPCE: Remote Procedure Call Protocol Extensions
//!
//! DCE RPC PDU Header Format:
//! ```text
//! +--------+--------+--------+--------+
//! |  vers  |vers_min| ptype  | pflags |
//! +--------+--------+--------+--------+
//! |        data representation        |
//! +--------+--------+--------+--------+
//! |   frag_len      |   auth_len      |
//! +--------+--------+--------+--------+
//! |             call_id               |
//! +--------+--------+--------+--------+
//! ```

use crate::error::{Result, RpcError};
use crate::security::{AuthLevel, AuthType, AuthVerifier, calculate_auth_padding};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

/// DCE RPC protocol version
pub const DCE_RPC_VERSION: u8 = 5;
/// DCE RPC protocol minor version
pub const DCE_RPC_VERSION_MINOR: u8 = 0;

/// DCE RPC packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Request PDU
    Request = 0,
    /// Ping PDU (connectionless only)
    Ping = 1,
    /// Response PDU
    Response = 2,
    /// Fault PDU
    Fault = 3,
    /// Working PDU (connectionless only)
    Working = 4,
    /// No-call PDU (connectionless only)
    Nocall = 5,
    /// Reject PDU (connectionless only)
    Reject = 6,
    /// Ack PDU (connectionless only)
    Ack = 7,
    /// Cancel PDU (connectionless only)
    ClCancel = 8,
    /// Fack PDU (connectionless only)
    Fack = 9,
    /// Cancel-ack PDU (connectionless only)
    CancelAck = 10,
    /// Bind PDU
    Bind = 11,
    /// Bind-ack PDU
    BindAck = 12,
    /// Bind-nak PDU
    BindNak = 13,
    /// Alter-context PDU
    AlterContext = 14,
    /// Alter-context-response PDU
    AlterContextResp = 15,
    /// Auth3 PDU (MS-RPCE extension for NTLM/Kerberos auth continuation)
    Auth3 = 16,
    /// Shutdown PDU
    Shutdown = 17,
    /// Co-cancel PDU
    CoCancel = 18,
    /// Orphaned PDU
    Orphaned = 19,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Request),
            1 => Some(Self::Ping),
            2 => Some(Self::Response),
            3 => Some(Self::Fault),
            4 => Some(Self::Working),
            5 => Some(Self::Nocall),
            6 => Some(Self::Reject),
            7 => Some(Self::Ack),
            8 => Some(Self::ClCancel),
            9 => Some(Self::Fack),
            10 => Some(Self::CancelAck),
            11 => Some(Self::Bind),
            12 => Some(Self::BindAck),
            13 => Some(Self::BindNak),
            14 => Some(Self::AlterContext),
            15 => Some(Self::AlterContextResp),
            16 => Some(Self::Auth3),
            17 => Some(Self::Shutdown),
            18 => Some(Self::CoCancel),
            19 => Some(Self::Orphaned),
            _ => None,
        }
    }
}

/// Packet flags
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// First fragment
    pub const FIRST_FRAG: u8 = 0x01;
    /// Last fragment
    pub const LAST_FRAG: u8 = 0x02;
    /// Cancel pending
    pub const PENDING_CANCEL: u8 = 0x04;
    /// Reserved (must be zero)
    pub const RESERVED: u8 = 0x08;
    /// Supports concurrent multiplexing
    pub const CONC_MPX: u8 = 0x10;
    /// Did not execute
    pub const DID_NOT_EXECUTE: u8 = 0x20;
    /// Maybe semantics requested
    pub const MAYBE: u8 = 0x40;
    /// Object UUID present (connectionless only)
    pub const OBJECT_UUID: u8 = 0x80;

    pub fn new() -> Self {
        Self(0)
    }

    /// Create flags for a complete (non-fragmented) PDU
    pub fn complete() -> Self {
        Self(Self::FIRST_FRAG | Self::LAST_FRAG)
    }

    pub fn set_first_frag(&mut self) -> &mut Self {
        self.0 |= Self::FIRST_FRAG;
        self
    }

    pub fn set_last_frag(&mut self) -> &mut Self {
        self.0 |= Self::LAST_FRAG;
        self
    }

    pub fn is_first_frag(&self) -> bool {
        (self.0 & Self::FIRST_FRAG) != 0
    }

    pub fn is_last_frag(&self) -> bool {
        (self.0 & Self::LAST_FRAG) != 0
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }

    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

/// Data Representation Format Label
///
/// Format:
/// - Byte 0: Integer representation (bits 0-3) and character set (bits 4-7)
/// - Byte 1: Floating point representation
/// - Bytes 2-3: Reserved (must be zero)
#[derive(Debug, Clone, Copy)]
pub struct DataRepresentation {
    /// Integer representation: 0 = big-endian, 1 = little-endian
    pub int_rep: IntRep,
    /// Character representation: 0 = ASCII, 1 = EBCDIC
    pub char_rep: CharRep,
    /// Floating point representation: 0 = IEEE, 1 = VAX, 2 = Cray, 3 = IBM
    pub float_rep: FloatRep,
}

/// Integer representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntRep {
    BigEndian = 0,
    LittleEndian = 1,
}

/// Character representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharRep {
    Ascii = 0,
    Ebcdic = 1,
}

/// Floating point representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatRep {
    Ieee = 0,
    Vax = 1,
    Cray = 2,
    Ibm = 3,
}

impl DataRepresentation {
    /// Create NDR (Network Data Representation) format: little-endian, ASCII, IEEE
    pub fn ndr() -> Self {
        Self {
            int_rep: IntRep::LittleEndian,
            char_rep: CharRep::Ascii,
            float_rep: FloatRep::Ieee,
        }
    }

    /// Create big-endian representation
    pub fn big_endian() -> Self {
        Self {
            int_rep: IntRep::BigEndian,
            char_rep: CharRep::Ascii,
            float_rep: FloatRep::Ieee,
        }
    }

    /// Encode to 4-byte format
    ///
    /// Wire format (per MS-RPCE 2.2.2.3):
    /// - Byte 0: bits 0-3 = character rep, bits 4-7 = integer rep (endianness)
    /// - Byte 1: floating point representation
    /// - Bytes 2-3: reserved (zero)
    ///
    /// For little-endian ASCII IEEE: [0x10, 0x00, 0x00, 0x00]
    pub fn encode(&self) -> [u8; 4] {
        let byte0 = (self.char_rep as u8) | ((self.int_rep as u8) << 4);
        let byte1 = self.float_rep as u8;
        [byte0, byte1, 0, 0]
    }

    /// Decode from 4-byte format
    ///
    /// Wire format (per MS-RPCE 2.2.2.3):
    /// - Byte 0: bits 0-3 = character rep, bits 4-7 = integer rep (endianness)
    /// - Byte 1: floating point representation
    /// - Bytes 2-3: reserved
    pub fn decode(data: [u8; 4]) -> Self {
        // Upper nibble (bits 4-7) is integer representation (endianness)
        let int_rep = if (data[0] & 0xF0) == 0 {
            IntRep::BigEndian
        } else {
            IntRep::LittleEndian
        };
        // Lower nibble (bits 0-3) is character representation
        let char_rep = if (data[0] & 0x0F) == 0 {
            CharRep::Ascii
        } else {
            CharRep::Ebcdic
        };
        let float_rep = match data[1] {
            0 => FloatRep::Ieee,
            1 => FloatRep::Vax,
            2 => FloatRep::Cray,
            _ => FloatRep::Ibm,
        };
        Self {
            int_rep,
            char_rep,
            float_rep,
        }
    }

    /// Returns true if using little-endian byte order
    pub fn is_little_endian(&self) -> bool {
        self.int_rep == IntRep::LittleEndian
    }
}

impl Default for DataRepresentation {
    fn default() -> Self {
        Self::ndr()
    }
}

/// UUID structure (128 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Uuid {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq_hi_and_reserved: u8,
    pub clock_seq_low: u8,
    pub node: [u8; 6],
}

impl Uuid {
    /// Nil UUID (all zeros)
    pub const NIL: Self = Self {
        time_low: 0,
        time_mid: 0,
        time_hi_and_version: 0,
        clock_seq_hi_and_reserved: 0,
        clock_seq_low: 0,
        node: [0; 6],
    };

    /// Parse from string format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 36 {
            return None;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }

        let time_low = u32::from_str_radix(parts[0], 16).ok()?;
        let time_mid = u16::from_str_radix(parts[1], 16).ok()?;
        let time_hi_and_version = u16::from_str_radix(parts[2], 16).ok()?;
        let clock = u16::from_str_radix(parts[3], 16).ok()?;
        let node_str = parts[4];
        if node_str.len() != 12 {
            return None;
        }

        let mut node = [0u8; 6];
        for i in 0..6 {
            node[i] = u8::from_str_radix(&node_str[i * 2..i * 2 + 2], 16).ok()?;
        }

        Some(Self {
            time_low,
            time_mid,
            time_hi_and_version,
            clock_seq_hi_and_reserved: (clock >> 8) as u8,
            clock_seq_low: clock as u8,
            node,
        })
    }

    /// Encode UUID in wire format (respecting byte order)
    pub fn encode(&self, buf: &mut BytesMut, little_endian: bool) {
        if little_endian {
            buf.put_u32_le(self.time_low);
            buf.put_u16_le(self.time_mid);
            buf.put_u16_le(self.time_hi_and_version);
        } else {
            buf.put_u32(self.time_low);
            buf.put_u16(self.time_mid);
            buf.put_u16(self.time_hi_and_version);
        }
        buf.put_u8(self.clock_seq_hi_and_reserved);
        buf.put_u8(self.clock_seq_low);
        buf.put_slice(&self.node);
    }

    /// Encode UUID to 16 bytes in little-endian format
    pub fn to_bytes_le(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.time_low.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.time_mid.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.time_hi_and_version.to_le_bytes());
        bytes[8] = self.clock_seq_hi_and_reserved;
        bytes[9] = self.clock_seq_low;
        bytes[10..16].copy_from_slice(&self.node);
        bytes
    }

    /// Decode UUID from 16 bytes in little-endian format
    pub fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        Some(Self {
            time_low: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            time_mid: u16::from_le_bytes([bytes[4], bytes[5]]),
            time_hi_and_version: u16::from_le_bytes([bytes[6], bytes[7]]),
            clock_seq_hi_and_reserved: bytes[8],
            clock_seq_low: bytes[9],
            node: [
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ],
        })
    }

    /// Decode UUID from wire format
    pub fn decode(cursor: &mut Cursor<&[u8]>, little_endian: bool) -> Result<Self> {
        if cursor.remaining() < 16 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "not enough data for UUID",
            )));
        }

        let time_low = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };
        let time_mid = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let time_hi_and_version = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let clock_seq_hi_and_reserved = cursor.get_u8();
        let clock_seq_low = cursor.get_u8();
        let mut node = [0u8; 6];
        cursor.copy_to_slice(&mut node);

        Ok(Self {
            time_low,
            time_mid,
            time_hi_and_version,
            clock_seq_hi_and_reserved,
            clock_seq_low,
            node,
        })
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.time_low,
            self.time_mid,
            self.time_hi_and_version,
            self.clock_seq_hi_and_reserved,
            self.clock_seq_low,
            self.node[0],
            self.node[1],
            self.node[2],
            self.node[3],
            self.node[4],
            self.node[5]
        )
    }
}

/// Syntax ID - interface UUID with version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxId {
    pub uuid: Uuid,
    pub version: u32, // major in lower 16 bits, minor in upper 16 bits
}

impl SyntaxId {
    pub fn new(uuid: Uuid, major: u16, minor: u16) -> Self {
        Self {
            uuid,
            version: (major as u32) | ((minor as u32) << 16),
        }
    }

    pub fn major_version(&self) -> u16 {
        self.version as u16
    }

    pub fn minor_version(&self) -> u16 {
        (self.version >> 16) as u16
    }

    pub fn encode(&self, buf: &mut BytesMut, little_endian: bool) {
        self.uuid.encode(buf, little_endian);
        if little_endian {
            buf.put_u32_le(self.version);
        } else {
            buf.put_u32(self.version);
        }
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>, little_endian: bool) -> Result<Self> {
        let uuid = Uuid::decode(cursor, little_endian)?;
        if cursor.remaining() < 4 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "not enough data for syntax version",
            )));
        }
        let version = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };
        Ok(Self { uuid, version })
    }
}

/// NDR Transfer Syntax UUID
pub const NDR_SYNTAX_UUID: &str = "8a885d04-1ceb-11c9-9fe8-08002b104860";
pub const NDR_SYNTAX_VERSION: u32 = 2;

/// Common PDU header (16 bytes)
#[derive(Debug, Clone)]
pub struct PduHeader {
    /// RPC version (should be 5)
    pub version: u8,
    /// RPC minor version (0 or 1)
    pub version_minor: u8,
    /// Packet type
    pub packet_type: PacketType,
    /// Packet flags
    pub packet_flags: PacketFlags,
    /// Data representation
    pub data_rep: DataRepresentation,
    /// Total length of the PDU fragment
    pub frag_length: u16,
    /// Length of authentication data
    pub auth_length: u16,
    /// Call identifier
    pub call_id: u32,
}

impl PduHeader {
    /// PDU header size in bytes
    pub const SIZE: usize = 16;

    pub fn new(packet_type: PacketType, call_id: u32) -> Self {
        Self {
            version: DCE_RPC_VERSION,
            version_minor: DCE_RPC_VERSION_MINOR,
            packet_type,
            packet_flags: PacketFlags::complete(),
            data_rep: DataRepresentation::ndr(),
            frag_length: 0, // Will be set when encoding
            auth_length: 0,
            call_id,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.version_minor);
        buf.put_u8(self.packet_type as u8);
        buf.put_u8(self.packet_flags.as_u8());
        buf.put_slice(&self.data_rep.encode());
        // frag_length and auth_length use endianness from data_rep
        if self.data_rep.is_little_endian() {
            buf.put_u16_le(self.frag_length);
            buf.put_u16_le(self.auth_length);
            buf.put_u32_le(self.call_id);
        } else {
            buf.put_u16(self.frag_length);
            buf.put_u16(self.auth_length);
            buf.put_u32(self.call_id);
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("PDU header too short: {} bytes", data.len()),
            )));
        }

        let version = data[0];
        if version != DCE_RPC_VERSION {
            return Err(RpcError::RpcVersionMismatch(version as u32));
        }

        let version_minor = data[1];
        let packet_type = PacketType::from_u8(data[2])
            .ok_or_else(|| RpcError::InvalidMessageType(data[2] as i32))?;
        let packet_flags = PacketFlags::from_u8(data[3]);
        let data_rep = DataRepresentation::decode([data[4], data[5], data[6], data[7]]);

        let little_endian = data_rep.is_little_endian();
        let frag_length = if little_endian {
            u16::from_le_bytes([data[8], data[9]])
        } else {
            u16::from_be_bytes([data[8], data[9]])
        };
        let auth_length = if little_endian {
            u16::from_le_bytes([data[10], data[11]])
        } else {
            u16::from_be_bytes([data[10], data[11]])
        };
        let call_id = if little_endian {
            u32::from_le_bytes([data[12], data[13], data[14], data[15]])
        } else {
            u32::from_be_bytes([data[12], data[13], data[14], data[15]])
        };

        Ok(Self {
            version,
            version_minor,
            packet_type,
            packet_flags,
            data_rep,
            frag_length,
            auth_length,
            call_id,
        })
    }
}

/// Context element for bind request
#[derive(Debug, Clone)]
pub struct ContextElement {
    pub context_id: u16,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

impl ContextElement {
    pub fn new(context_id: u16, abstract_syntax: SyntaxId, transfer_syntax: SyntaxId) -> Self {
        Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes: vec![transfer_syntax],
        }
    }

    pub fn encode(&self, buf: &mut BytesMut, little_endian: bool) {
        if little_endian {
            buf.put_u16_le(self.context_id);
        } else {
            buf.put_u16(self.context_id);
        }
        buf.put_u8(self.transfer_syntaxes.len() as u8);
        buf.put_u8(0); // reserved

        self.abstract_syntax.encode(buf, little_endian);
        for ts in &self.transfer_syntaxes {
            ts.encode(buf, little_endian);
        }
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>, little_endian: bool) -> Result<Self> {
        if cursor.remaining() < 4 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "not enough data for context element",
            )));
        }

        let context_id = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let num_transfer_syntaxes = cursor.get_u8();
        let _reserved = cursor.get_u8();

        let abstract_syntax = SyntaxId::decode(cursor, little_endian)?;
        let mut transfer_syntaxes = Vec::with_capacity(num_transfer_syntaxes as usize);
        for _ in 0..num_transfer_syntaxes {
            transfer_syntaxes.push(SyntaxId::decode(cursor, little_endian)?);
        }

        Ok(Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes,
        })
    }
}

/// Bind PDU
#[derive(Debug, Clone)]
pub struct BindPdu {
    pub header: PduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub context_list: Vec<ContextElement>,
    /// Optional authentication verifier
    pub auth_verifier: Option<AuthVerifier>,
}

impl BindPdu {
    pub fn new(call_id: u32, interface: SyntaxId) -> Self {
        let ndr_syntax = SyntaxId::new(
            Uuid::parse(NDR_SYNTAX_UUID).expect("NDR_SYNTAX_UUID is a valid UUID constant"),
            NDR_SYNTAX_VERSION as u16,
            0,
        );
        Self {
            header: PduHeader::new(PacketType::Bind, call_id),
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            context_list: vec![ContextElement::new(0, interface, ndr_syntax)],
            auth_verifier: None,
        }
    }

    /// Create an authenticated bind PDU
    pub fn new_authenticated(
        call_id: u32,
        interface: SyntaxId,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        let mut pdu = Self::new(call_id, interface);
        pdu.auth_verifier = Some(AuthVerifier::new(
            auth_type,
            auth_level,
            auth_context_id,
            auth_token,
        ));
        pdu
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(128);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Bind body
        if little_endian {
            buf.put_u16_le(self.max_xmit_frag);
            buf.put_u16_le(self.max_recv_frag);
            buf.put_u32_le(self.assoc_group_id);
        } else {
            buf.put_u16(self.max_xmit_frag);
            buf.put_u16(self.max_recv_frag);
            buf.put_u32(self.assoc_group_id);
        }

        // Context list (p_cont_list_t)
        buf.put_u8(self.context_list.len() as u8); // n_context_elem
        buf.put_u8(0); // reserved
        if little_endian {
            buf.put_u16_le(0); // reserved2
        } else {
            buf.put_u16(0); // reserved2
        }

        for ctx in &self.context_list {
            ctx.encode(&mut buf, little_endian);
        }

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            // Calculate padding to align auth verifier
            let body_len = buf.len() - PduHeader::SIZE;
            let auth_pad = calculate_auth_padding(body_len, auth.auth_type);

            // Add padding
            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            // Update auth_pad_length and encode
            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header with correct fragment length and auth length
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        // Write header at the beginning
        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::Bind {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        if cursor.remaining() < 8 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "bind PDU too short",
            )));
        }

        let max_xmit_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let max_recv_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let assoc_group_id = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };

        let num_contexts = cursor.get_u8();
        let _reserved = cursor.get_u8();
        let _reserved2 = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        let mut context_list = Vec::with_capacity(num_contexts as usize);
        for _ in 0..num_contexts {
            context_list.push(ContextElement::decode(&mut cursor, little_endian)?);
        }

        // Decode auth verifier if present
        let auth_verifier = if header.auth_length > 0 {
            // Auth verifier is at the end of the PDU
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian)
        } else {
            None
        };

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            context_list,
            auth_verifier,
        })
    }
}

/// Context result for bind acknowledgment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ContextResult {
    Acceptance = 0,
    UserRejection = 1,
    ProviderRejection = 2,
}

/// Bind acknowledgment PDU
#[derive(Debug, Clone)]
pub struct BindAckPdu {
    pub header: PduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub secondary_addr: String,
    pub results: Vec<(ContextResult, SyntaxId)>,
    /// Optional authentication verifier
    pub auth_verifier: Option<AuthVerifier>,
}

impl BindAckPdu {
    pub fn new(call_id: u32, assoc_group_id: u32, accepted_syntax: SyntaxId) -> Self {
        Self {
            header: PduHeader::new(PacketType::BindAck, call_id),
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id,
            secondary_addr: String::new(),
            results: vec![(ContextResult::Acceptance, accepted_syntax)],
            auth_verifier: None,
        }
    }

    /// Create an authenticated bind ack PDU
    pub fn new_authenticated(
        call_id: u32,
        assoc_group_id: u32,
        accepted_syntax: SyntaxId,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        let mut pdu = Self::new(call_id, assoc_group_id, accepted_syntax);
        pdu.auth_verifier = Some(AuthVerifier::new(
            auth_type,
            auth_level,
            auth_context_id,
            auth_token,
        ));
        pdu
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(128);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Bind ack body
        if little_endian {
            buf.put_u16_le(self.max_xmit_frag);
            buf.put_u16_le(self.max_recv_frag);
            buf.put_u32_le(self.assoc_group_id);
        } else {
            buf.put_u16(self.max_xmit_frag);
            buf.put_u16(self.max_recv_frag);
            buf.put_u32(self.assoc_group_id);
        }

        // Secondary address (port as string)
        let sec_addr_bytes = self.secondary_addr.as_bytes();
        if little_endian {
            buf.put_u16_le(sec_addr_bytes.len() as u16 + 1); // +1 for null terminator
        } else {
            buf.put_u16(sec_addr_bytes.len() as u16 + 1);
        }
        buf.put_slice(sec_addr_bytes);
        buf.put_u8(0); // null terminator

        // Align to 4-byte boundary
        let padding = (4 - (buf.len() % 4)) % 4;
        for _ in 0..padding {
            buf.put_u8(0);
        }

        // Results (p_result_list_t)
        buf.put_u8(self.results.len() as u8); // n_results
        buf.put_u8(0); // reserved
        if little_endian {
            buf.put_u16_le(0); // reserved2
        } else {
            buf.put_u16(0); // reserved2
        }

        for (result, syntax) in &self.results {
            if little_endian {
                buf.put_u16_le(*result as u16);
                buf.put_u16_le(0); // reason (only if rejected)
            } else {
                buf.put_u16(*result as u16);
                buf.put_u16(0);
            }
            syntax.encode(&mut buf, little_endian);
        }

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            // Calculate padding to align auth verifier
            let body_len = buf.len() - PduHeader::SIZE;
            let auth_pad = calculate_auth_padding(body_len, auth.auth_type);

            // Add padding
            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            // Update auth_pad_length and encode
            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header with correct fragment length and auth length
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        // Write header at the beginning
        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::BindAck {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        let max_xmit_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let max_recv_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let assoc_group_id = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };

        // Secondary address
        let sec_addr_len = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        } as usize;

        let mut sec_addr_bytes = vec![0u8; sec_addr_len];
        cursor.copy_to_slice(&mut sec_addr_bytes);
        // Remove null terminator if present
        if sec_addr_bytes.last() == Some(&0) {
            sec_addr_bytes.pop();
        }
        let secondary_addr = String::from_utf8_lossy(&sec_addr_bytes).to_string();

        // Skip alignment padding
        let current_pos = PduHeader::SIZE + 10 + sec_addr_len;
        let padding = (4 - (current_pos % 4)) % 4;
        for _ in 0..padding {
            cursor.get_u8();
        }

        let num_results = cursor.get_u8();
        let _reserved = cursor.get_u8();
        let _reserved2 = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        let mut results = Vec::with_capacity(num_results as usize);
        for _ in 0..num_results {
            let result_code = if little_endian {
                cursor.get_u16_le()
            } else {
                cursor.get_u16()
            };
            let result = match result_code {
                0 => ContextResult::Acceptance,
                1 => ContextResult::UserRejection,
                _ => ContextResult::ProviderRejection,
            };
            let _reason = if little_endian {
                cursor.get_u16_le()
            } else {
                cursor.get_u16()
            };
            let syntax = SyntaxId::decode(&mut cursor, little_endian)?;
            results.push((result, syntax));
        }

        // Decode auth verifier if present
        let auth_verifier = if header.auth_length > 0 {
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian)
        } else {
            None
        };

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            secondary_addr,
            results,
            auth_verifier,
        })
    }
}

/// Request PDU
#[derive(Debug, Clone)]
pub struct RequestPdu {
    pub header: PduHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub object_uuid: Option<Uuid>,
    pub stub_data: Bytes,
    /// Optional authentication verifier
    pub auth_verifier: Option<AuthVerifier>,
}

impl RequestPdu {
    /// Request header size (after common header): alloc_hint(4) + context_id(2) + opnum(2) = 8 bytes
    pub const BODY_HEADER_SIZE: usize = 8;

    pub fn new(call_id: u32, opnum: u16, stub_data: Bytes) -> Self {
        Self {
            header: PduHeader::new(PacketType::Request, call_id),
            alloc_hint: stub_data.len() as u32,
            context_id: 0,
            opnum,
            object_uuid: None,
            stub_data,
            auth_verifier: None,
        }
    }

    /// Create an authenticated request PDU
    pub fn new_authenticated(
        call_id: u32,
        opnum: u16,
        stub_data: Bytes,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        let mut pdu = Self::new(call_id, opnum, stub_data);
        pdu.auth_verifier = Some(AuthVerifier::new(
            auth_type,
            auth_level,
            auth_context_id,
            auth_token,
        ));
        pdu
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            PduHeader::SIZE + Self::BODY_HEADER_SIZE + self.stub_data.len() + 64,
        );
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Request body header
        if little_endian {
            buf.put_u32_le(self.alloc_hint);
            buf.put_u16_le(self.context_id);
            buf.put_u16_le(self.opnum);
        } else {
            buf.put_u32(self.alloc_hint);
            buf.put_u16(self.context_id);
            buf.put_u16(self.opnum);
        }

        // Object UUID (if present - indicated by flag)
        if let Some(ref uuid) = self.object_uuid {
            uuid.encode(&mut buf, little_endian);
        }

        // Stub data
        buf.put_slice(&self.stub_data);

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            // Calculate padding to align auth verifier
            let stub_len = self.stub_data.len();
            let auth_pad = calculate_auth_padding(stub_len, auth.auth_type);

            // Add padding
            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            // Update auth_pad_length and encode
            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header with correct fragment length
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;
        if self.object_uuid.is_some() {
            header.packet_flags =
                PacketFlags::from_u8(header.packet_flags.as_u8() | PacketFlags::OBJECT_UUID);
        }

        // Write header at the beginning
        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::Request {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        if cursor.remaining() < Self::BODY_HEADER_SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request PDU too short",
            )));
        }

        let alloc_hint = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };
        let context_id = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let opnum = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        // Check for object UUID
        let has_object = (header.packet_flags.as_u8() & PacketFlags::OBJECT_UUID) != 0;
        let object_uuid = if has_object {
            Some(Uuid::decode(&mut cursor, little_endian)?)
        } else {
            None
        };

        // Decode auth verifier if present
        let (auth_verifier, auth_pad_len) = if header.auth_length > 0 {
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            let auth = AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian);
            let pad_len = auth.as_ref().map(|a| a.auth_pad_length as usize).unwrap_or(0);
            (auth, pad_len)
        } else {
            (None, 0)
        };

        // Remaining data is stub (minus auth data and padding at end if present)
        let auth_section_len = if header.auth_length > 0 {
            AuthVerifier::HEADER_SIZE + header.auth_length as usize + auth_pad_len
        } else {
            0
        };
        let stub_len = cursor.remaining().saturating_sub(auth_section_len);
        let mut stub_data = vec![0u8; stub_len];
        cursor.copy_to_slice(&mut stub_data);

        Ok(Self {
            header,
            alloc_hint,
            context_id,
            opnum,
            object_uuid,
            stub_data: Bytes::from(stub_data),
            auth_verifier,
        })
    }
}

/// Response PDU
#[derive(Debug, Clone)]
pub struct ResponsePdu {
    pub header: PduHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub stub_data: Bytes,
    /// Optional authentication verifier
    pub auth_verifier: Option<AuthVerifier>,
}

impl ResponsePdu {
    /// Response header size (after common header): alloc_hint(4) + context_id(2) + cancel_count(1) + reserved(1) = 8 bytes
    pub const BODY_HEADER_SIZE: usize = 8;

    pub fn new(call_id: u32, stub_data: Bytes) -> Self {
        Self {
            header: PduHeader::new(PacketType::Response, call_id),
            alloc_hint: stub_data.len() as u32,
            context_id: 0,
            cancel_count: 0,
            stub_data,
            auth_verifier: None,
        }
    }

    /// Create an authenticated response PDU
    pub fn new_authenticated(
        call_id: u32,
        stub_data: Bytes,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        let mut pdu = Self::new(call_id, stub_data);
        pdu.auth_verifier = Some(AuthVerifier::new(
            auth_type,
            auth_level,
            auth_context_id,
            auth_token,
        ));
        pdu
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            PduHeader::SIZE + Self::BODY_HEADER_SIZE + self.stub_data.len() + 64,
        );
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Response body header
        if little_endian {
            buf.put_u32_le(self.alloc_hint);
            buf.put_u16_le(self.context_id);
        } else {
            buf.put_u32(self.alloc_hint);
            buf.put_u16(self.context_id);
        }
        buf.put_u8(self.cancel_count);
        buf.put_u8(0); // reserved

        // Stub data
        buf.put_slice(&self.stub_data);

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            // Calculate padding to align auth verifier
            let stub_len = self.stub_data.len();
            let auth_pad = calculate_auth_padding(stub_len, auth.auth_type);

            // Add padding
            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            // Update auth_pad_length and encode
            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header with correct fragment length
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        // Write header at the beginning
        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::Response {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        if cursor.remaining() < Self::BODY_HEADER_SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "response PDU too short",
            )));
        }

        let alloc_hint = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };
        let context_id = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let cancel_count = cursor.get_u8();
        let _reserved = cursor.get_u8();

        // Decode auth verifier if present
        let (auth_verifier, auth_pad_len) = if header.auth_length > 0 {
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            let auth = AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian);
            let pad_len = auth.as_ref().map(|a| a.auth_pad_length as usize).unwrap_or(0);
            (auth, pad_len)
        } else {
            (None, 0)
        };

        // Remaining data is stub (minus auth data and padding at end if present)
        let auth_section_len = if header.auth_length > 0 {
            AuthVerifier::HEADER_SIZE + header.auth_length as usize + auth_pad_len
        } else {
            0
        };
        let stub_len = cursor.remaining().saturating_sub(auth_section_len);
        let mut stub_data = vec![0u8; stub_len];
        cursor.copy_to_slice(&mut stub_data);

        Ok(Self {
            header,
            alloc_hint,
            context_id,
            cancel_count,
            stub_data: Bytes::from(stub_data),
            auth_verifier,
        })
    }
}

/// Fault status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FaultStatus {
    /// No error
    None = 0,
    /// Operation not implemented
    OpRngError = 0x1c010002,
    /// Unknown interface
    UnkIf = 0x1c010003,
    /// Protocol version not supported
    NdrVersion = 0x1c000008,
    /// General RPC error
    RpcError = 0x1c000000,
    /// Access denied
    AccessDenied = 0x00000005,
    /// Context mismatch
    ContextMismatch = 0x1c00001a,
}

/// Fault PDU
#[derive(Debug, Clone)]
pub struct FaultPdu {
    pub header: PduHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub status: u32,
}

impl FaultPdu {
    pub fn new(call_id: u32, status: FaultStatus) -> Self {
        Self {
            header: PduHeader::new(PacketType::Fault, call_id),
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            status: status as u32,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Fault body
        if little_endian {
            buf.put_u32_le(self.alloc_hint);
            buf.put_u16_le(self.context_id);
        } else {
            buf.put_u32(self.alloc_hint);
            buf.put_u16(self.context_id);
        }
        buf.put_u8(self.cancel_count);
        buf.put_u8(0); // reserved

        // Status
        if little_endian {
            buf.put_u32_le(self.status);
        } else {
            buf.put_u32(self.status);
        }

        // Reserved (4 bytes)
        buf.put_u32(0);

        // Update header
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;

        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::Fault {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        let alloc_hint = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };
        let context_id = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let cancel_count = cursor.get_u8();
        let _reserved = cursor.get_u8();
        let status = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };

        Ok(Self {
            header,
            alloc_hint,
            context_id,
            cancel_count,
            status,
        })
    }
}

/// Auth3 PDU (MS-RPCE extension)
///
/// This PDU is used to complete authentication after bind_ack when using
/// NTLM or other multi-leg authentication protocols. The client sends this
/// after receiving the bind_ack with the server's challenge.
///
/// Wire format:
/// - Common header (16 bytes)
/// - max_xmit_frag (2 bytes)
/// - max_recv_frag (2 bytes)
/// - padding (to 4-byte boundary)
/// - auth_verifier
#[derive(Debug, Clone)]
pub struct Auth3Pdu {
    pub header: PduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub auth_verifier: AuthVerifier,
}

impl Auth3Pdu {
    pub fn new(
        call_id: u32,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        Self {
            header: PduHeader::new(PacketType::Auth3, call_id),
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            auth_verifier: AuthVerifier::new(auth_type, auth_level, auth_context_id, auth_token),
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(64);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Auth3 body
        if little_endian {
            buf.put_u16_le(self.max_xmit_frag);
            buf.put_u16_le(self.max_recv_frag);
        } else {
            buf.put_u16(self.max_xmit_frag);
            buf.put_u16(self.max_recv_frag);
        }

        // Auth verifier (no padding needed - already 4-byte aligned after frag sizes)
        self.auth_verifier.encode(&mut buf, little_endian);

        // Update header
        let frag_length = buf.len() as u16;
        let auth_length = self.auth_verifier.auth_value.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::Auth3 {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        if cursor.remaining() < 4 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "auth3 PDU too short",
            )));
        }

        let max_xmit_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let max_recv_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        // Decode auth verifier
        let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
        let auth_start = data.len() - auth_total_len;
        let auth_verifier = AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian)
            .ok_or_else(|| {
                RpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "failed to decode auth verifier",
                ))
            })?;

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            auth_verifier,
        })
    }
}

/// Alter Context PDU
///
/// Used to add a new presentation context to an existing association or
/// to renegotiate security context.
#[derive(Debug, Clone)]
pub struct AlterContextPdu {
    pub header: PduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub context_list: Vec<ContextElement>,
    pub auth_verifier: Option<AuthVerifier>,
}

impl AlterContextPdu {
    pub fn new(call_id: u32) -> Self {
        Self {
            header: PduHeader::new(PacketType::AlterContext, call_id),
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            context_list: Vec::new(),
            auth_verifier: None,
        }
    }

    /// Create for security context renegotiation
    pub fn new_for_auth(
        call_id: u32,
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_token: Bytes,
    ) -> Self {
        let mut pdu = Self::new(call_id);
        pdu.auth_verifier = Some(AuthVerifier::new(
            auth_type,
            auth_level,
            auth_context_id,
            auth_token,
        ));
        pdu
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(128);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Body (same as bind)
        if little_endian {
            buf.put_u16_le(self.max_xmit_frag);
            buf.put_u16_le(self.max_recv_frag);
            buf.put_u32_le(self.assoc_group_id);
        } else {
            buf.put_u16(self.max_xmit_frag);
            buf.put_u16(self.max_recv_frag);
            buf.put_u32(self.assoc_group_id);
        }

        // Context list (p_cont_list_t)
        buf.put_u8(self.context_list.len() as u8); // n_context_elem
        buf.put_u8(0); // reserved
        if little_endian {
            buf.put_u16_le(0); // reserved2
        } else {
            buf.put_u16(0); // reserved2
        }

        for ctx in &self.context_list {
            ctx.encode(&mut buf, little_endian);
        }

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            let body_len = buf.len() - PduHeader::SIZE;
            let auth_pad = calculate_auth_padding(body_len, auth.auth_type);

            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::AlterContext {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        if cursor.remaining() < 8 {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "alter_context PDU too short",
            )));
        }

        let max_xmit_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let max_recv_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let assoc_group_id = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };

        let num_contexts = cursor.get_u8();
        let _reserved = cursor.get_u8();
        let _reserved2 = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        let mut context_list = Vec::with_capacity(num_contexts as usize);
        for _ in 0..num_contexts {
            context_list.push(ContextElement::decode(&mut cursor, little_endian)?);
        }

        let auth_verifier = if header.auth_length > 0 {
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian)
        } else {
            None
        };

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            context_list,
            auth_verifier,
        })
    }
}

/// Alter Context Response PDU
#[derive(Debug, Clone)]
pub struct AlterContextRespPdu {
    pub header: PduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub secondary_addr: String,
    pub results: Vec<(ContextResult, SyntaxId)>,
    pub auth_verifier: Option<AuthVerifier>,
}

impl AlterContextRespPdu {
    pub fn new(call_id: u32, assoc_group_id: u32) -> Self {
        Self {
            header: PduHeader::new(PacketType::AlterContextResp, call_id),
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id,
            secondary_addr: String::new(),
            results: Vec::new(),
            auth_verifier: None,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(128);
        let little_endian = self.header.data_rep.is_little_endian();

        // Reserve space for header
        buf.put_slice(&[0u8; PduHeader::SIZE]);

        // Body (same as bind_ack)
        if little_endian {
            buf.put_u16_le(self.max_xmit_frag);
            buf.put_u16_le(self.max_recv_frag);
            buf.put_u32_le(self.assoc_group_id);
        } else {
            buf.put_u16(self.max_xmit_frag);
            buf.put_u16(self.max_recv_frag);
            buf.put_u32(self.assoc_group_id);
        }

        // Secondary address
        let sec_addr_bytes = self.secondary_addr.as_bytes();
        if little_endian {
            buf.put_u16_le(sec_addr_bytes.len() as u16 + 1);
        } else {
            buf.put_u16(sec_addr_bytes.len() as u16 + 1);
        }
        buf.put_slice(sec_addr_bytes);
        buf.put_u8(0);

        // Align to 4-byte boundary
        let padding = (4 - (buf.len() % 4)) % 4;
        for _ in 0..padding {
            buf.put_u8(0);
        }

        // Results (p_result_list_t)
        buf.put_u8(self.results.len() as u8); // n_results
        buf.put_u8(0); // reserved
        if little_endian {
            buf.put_u16_le(0); // reserved2
        } else {
            buf.put_u16(0); // reserved2
        }

        for (result, syntax) in &self.results {
            if little_endian {
                buf.put_u16_le(*result as u16);
                buf.put_u16_le(0); // reason
            } else {
                buf.put_u16(*result as u16);
                buf.put_u16(0); // reason
            }
            syntax.encode(&mut buf, little_endian);
        }

        // Add auth verifier if present
        let auth_length = if let Some(ref auth) = self.auth_verifier {
            let body_len = buf.len() - PduHeader::SIZE;
            let auth_pad = calculate_auth_padding(body_len, auth.auth_type);

            for _ in 0..auth_pad {
                buf.put_u8(0);
            }

            let mut auth_with_padding = auth.clone();
            auth_with_padding.auth_pad_length = auth_pad as u8;
            auth_with_padding.encode(&mut buf, little_endian);

            auth.auth_value.len() as u16
        } else {
            0
        };

        // Update header
        let frag_length = buf.len() as u16;
        let mut header = self.header.clone();
        header.frag_length = frag_length;
        header.auth_length = auth_length;

        let mut header_buf = BytesMut::with_capacity(PduHeader::SIZE);
        header.encode(&mut header_buf);
        buf[..PduHeader::SIZE].copy_from_slice(&header_buf);

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(data)?;
        if header.packet_type != PacketType::AlterContextResp {
            return Err(RpcError::InvalidMessageType(header.packet_type as i32));
        }

        let little_endian = header.data_rep.is_little_endian();
        let mut cursor = Cursor::new(&data[PduHeader::SIZE..]);

        let max_xmit_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let max_recv_frag = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };
        let assoc_group_id = if little_endian {
            cursor.get_u32_le()
        } else {
            cursor.get_u32()
        };

        let sec_addr_len = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        } as usize;

        let mut sec_addr_bytes = vec![0u8; sec_addr_len];
        cursor.copy_to_slice(&mut sec_addr_bytes);
        if sec_addr_bytes.last() == Some(&0) {
            sec_addr_bytes.pop();
        }
        let secondary_addr = String::from_utf8_lossy(&sec_addr_bytes).to_string();

        let current_pos = PduHeader::SIZE + 10 + sec_addr_len;
        let padding = (4 - (current_pos % 4)) % 4;
        for _ in 0..padding {
            cursor.get_u8();
        }

        let num_results = cursor.get_u8();
        let _reserved = cursor.get_u8();
        let _reserved2 = if little_endian {
            cursor.get_u16_le()
        } else {
            cursor.get_u16()
        };

        let mut results = Vec::with_capacity(num_results as usize);
        for _ in 0..num_results {
            let result_code = if little_endian {
                cursor.get_u16_le()
            } else {
                cursor.get_u16()
            };
            let result = match result_code {
                0 => ContextResult::Acceptance,
                1 => ContextResult::UserRejection,
                _ => ContextResult::ProviderRejection,
            };
            let _reason = if little_endian {
                cursor.get_u16_le()
            } else {
                cursor.get_u16()
            };
            let syntax = SyntaxId::decode(&mut cursor, little_endian)?;
            results.push((result, syntax));
        }

        let auth_verifier = if header.auth_length > 0 {
            let auth_total_len = AuthVerifier::HEADER_SIZE + header.auth_length as usize;
            let auth_start = data.len() - auth_total_len;
            AuthVerifier::decode(&data[auth_start..], auth_total_len, little_endian)
        } else {
            None
        };

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            secondary_addr,
            results,
            auth_verifier,
        })
    }
}

/// Represents any DCE RPC PDU type
#[derive(Debug, Clone)]
pub enum Pdu {
    Bind(BindPdu),
    BindAck(BindAckPdu),
    Auth3(Auth3Pdu),
    AlterContext(AlterContextPdu),
    AlterContextResp(AlterContextRespPdu),
    Request(RequestPdu),
    Response(ResponsePdu),
    Fault(FaultPdu),
}

impl Pdu {
    /// Decode a PDU from raw bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < PduHeader::SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "PDU too short for header",
            )));
        }

        let header = PduHeader::decode(data)?;
        match header.packet_type {
            PacketType::Bind => Ok(Pdu::Bind(BindPdu::decode(data)?)),
            PacketType::BindAck => Ok(Pdu::BindAck(BindAckPdu::decode(data)?)),
            PacketType::Auth3 => Ok(Pdu::Auth3(Auth3Pdu::decode(data)?)),
            PacketType::AlterContext => Ok(Pdu::AlterContext(AlterContextPdu::decode(data)?)),
            PacketType::AlterContextResp => {
                Ok(Pdu::AlterContextResp(AlterContextRespPdu::decode(data)?))
            }
            PacketType::Request => Ok(Pdu::Request(RequestPdu::decode(data)?)),
            PacketType::Response => Ok(Pdu::Response(ResponsePdu::decode(data)?)),
            PacketType::Fault => Ok(Pdu::Fault(FaultPdu::decode(data)?)),
            _ => Err(RpcError::InvalidMessageType(header.packet_type as i32)),
        }
    }

    /// Encode the PDU to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            Pdu::Bind(pdu) => pdu.encode(),
            Pdu::BindAck(pdu) => pdu.encode(),
            Pdu::Auth3(pdu) => pdu.encode(),
            Pdu::AlterContext(pdu) => pdu.encode(),
            Pdu::AlterContextResp(pdu) => pdu.encode(),
            Pdu::Request(pdu) => pdu.encode(),
            Pdu::Response(pdu) => pdu.encode(),
            Pdu::Fault(pdu) => pdu.encode(),
        }
    }

    /// Get the call ID from the PDU header
    pub fn call_id(&self) -> u32 {
        match self {
            Pdu::Bind(pdu) => pdu.header.call_id,
            Pdu::BindAck(pdu) => pdu.header.call_id,
            Pdu::Auth3(pdu) => pdu.header.call_id,
            Pdu::AlterContext(pdu) => pdu.header.call_id,
            Pdu::AlterContextResp(pdu) => pdu.header.call_id,
            Pdu::Request(pdu) => pdu.header.call_id,
            Pdu::Response(pdu) => pdu.header.call_id,
            Pdu::Fault(pdu) => pdu.header.call_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_parse() {
        let uuid = Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b104860").unwrap();
        assert_eq!(uuid.time_low, 0x8a885d04);
        assert_eq!(uuid.time_mid, 0x1ceb);
        assert_eq!(uuid.time_hi_and_version, 0x11c9);
    }

    #[test]
    fn test_header_encode_decode() {
        let header = PduHeader::new(PacketType::Request, 12345);
        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        assert_eq!(buf.len(), PduHeader::SIZE);
        assert_eq!(buf[0], DCE_RPC_VERSION);
        assert_eq!(buf[2], PacketType::Request as u8);

        let decoded = PduHeader::decode(&buf).unwrap();
        assert_eq!(decoded.version, DCE_RPC_VERSION);
        assert_eq!(decoded.packet_type, PacketType::Request);
        assert_eq!(decoded.call_id, 12345);
    }

    #[test]
    fn test_request_roundtrip() {
        let request = RequestPdu::new(42, 5, Bytes::from_static(b"test data"));
        let encoded = request.encode();
        let decoded = RequestPdu::decode(&encoded).unwrap();

        assert_eq!(decoded.header.call_id, 42);
        assert_eq!(decoded.opnum, 5);
        assert_eq!(decoded.stub_data.as_ref(), b"test data");
    }

    #[test]
    fn test_response_roundtrip() {
        let response = ResponsePdu::new(42, Bytes::from_static(b"result"));
        let encoded = response.encode();
        let decoded = ResponsePdu::decode(&encoded).unwrap();

        assert_eq!(decoded.header.call_id, 42);
        assert_eq!(decoded.stub_data.as_ref(), b"result");
    }

    #[test]
    fn test_bind_roundtrip() {
        let interface = SyntaxId::new(
            Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap(),
            1,
            0,
        );
        let bind = BindPdu::new(1, interface);
        let encoded = bind.encode();
        let decoded = BindPdu::decode(&encoded).unwrap();

        assert_eq!(decoded.header.call_id, 1);
        assert_eq!(decoded.context_list.len(), 1);
        assert_eq!(decoded.context_list[0].abstract_syntax.uuid, interface.uuid);
    }

    #[test]
    fn test_data_representation() {
        let ndr = DataRepresentation::ndr();
        let encoded = ndr.encode();
        // Wire format per MS-RPCE: upper nibble = endianness, lower nibble = char rep
        // For little-endian ASCII IEEE: [0x10, 0x00, 0x00, 0x00]
        assert_eq!(encoded[0], 0x10); // little-endian (upper nibble=1), ASCII (lower nibble=0)
        assert_eq!(encoded[1], 0x00); // IEEE float
        assert_eq!(encoded[2], 0x00); // reserved
        assert_eq!(encoded[3], 0x00); // reserved

        let decoded = DataRepresentation::decode(encoded);
        assert!(decoded.is_little_endian());
        assert_eq!(decoded.char_rep, CharRep::Ascii);
        assert_eq!(decoded.float_rep, FloatRep::Ieee);

        // Test big-endian encoding
        let be = DataRepresentation::big_endian();
        let be_encoded = be.encode();
        assert_eq!(be_encoded[0], 0x00); // big-endian (upper nibble=0), ASCII (lower nibble=0)
        assert!(!DataRepresentation::decode(be_encoded).is_little_endian());
    }
}
