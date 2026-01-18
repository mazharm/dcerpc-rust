//! DCE RPC Endpoint Mapper (EPM) Protocol Types
//!
//! The Endpoint Mapper allows DCE RPC services to register their endpoints
//! and allows clients to look up where services are located.
//!
//! Well-known port: 135 (TCP and UDP)
//! Interface UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa

use crate::dcerpc::{SyntaxId, Uuid};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Well-known port for the Endpoint Mapper
pub const EPM_PORT: u16 = 135;

/// Endpoint Mapper interface UUID
pub const EPM_INTERFACE_UUID: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

/// Endpoint Mapper interface version
pub const EPM_INTERFACE_VERSION: u16 = 3;

/// Operation numbers for the Endpoint Mapper
pub mod epm_op {
    /// Insert entries into the endpoint map
    pub const EPT_INSERT: u16 = 0;
    /// Delete entries from the endpoint map
    pub const EPT_DELETE: u16 = 1;
    /// Lookup entries in the endpoint map
    pub const EPT_LOOKUP: u16 = 2;
    /// Map an interface to an endpoint (simplified lookup)
    pub const EPT_MAP: u16 = 3;
    /// Lookup handle free
    pub const EPT_LOOKUP_HANDLE_FREE: u16 = 4;
    /// Inquire object (get info about an entry)
    pub const EPT_INQ_OBJECT: u16 = 5;
    /// Management delete
    pub const EPT_MGMT_DELETE: u16 = 6;
}

/// Protocol tower floor identifiers
pub mod protocol_id {
    /// UUID (interface identifier)
    pub const UUID: u8 = 0x0d;
    /// RPC connectionless (UDP)
    pub const RPC_CL: u8 = 0x0a;
    /// RPC connection-oriented (TCP)
    pub const RPC_CO: u8 = 0x0b;
    /// TCP transport
    pub const TCP: u8 = 0x07;
    /// UDP transport
    pub const UDP: u8 = 0x08;
    /// IP address
    pub const IP: u8 = 0x09;
    /// Named pipe
    pub const NAMED_PIPE: u8 = 0x0f;
    /// NetBIOS
    pub const NETBIOS: u8 = 0x11;
}

/// A floor in a protocol tower
#[derive(Debug, Clone)]
pub struct TowerFloor {
    /// Protocol identifier
    pub protocol_id: u8,
    /// Left-hand side data (protocol-specific)
    pub lhs_data: Vec<u8>,
    /// Right-hand side data (address/port info)
    pub rhs_data: Vec<u8>,
}

impl TowerFloor {
    /// Create a new floor
    pub fn new(protocol_id: u8, lhs_data: Vec<u8>, rhs_data: Vec<u8>) -> Self {
        Self {
            protocol_id,
            lhs_data,
            rhs_data,
        }
    }

    /// Create a UUID floor (for interface or transfer syntax)
    pub fn uuid(uuid: &Uuid, major_version: u16, minor_version: u16) -> Self {
        let mut lhs = Vec::with_capacity(19);
        lhs.push(protocol_id::UUID);
        lhs.extend_from_slice(&uuid.to_bytes_le());
        lhs.extend_from_slice(&major_version.to_le_bytes());

        let mut rhs = Vec::with_capacity(2);
        rhs.extend_from_slice(&minor_version.to_le_bytes());

        Self {
            protocol_id: protocol_id::UUID,
            lhs_data: lhs,
            rhs_data: rhs,
        }
    }

    /// Create an RPC connection-oriented floor
    pub fn rpc_co() -> Self {
        Self {
            protocol_id: protocol_id::RPC_CO,
            lhs_data: vec![protocol_id::RPC_CO],
            rhs_data: vec![0, 0], // Minor version
        }
    }

    /// Create an RPC connectionless floor
    pub fn rpc_cl() -> Self {
        Self {
            protocol_id: protocol_id::RPC_CL,
            lhs_data: vec![protocol_id::RPC_CL],
            rhs_data: vec![0, 0], // Minor version
        }
    }

    /// Create a TCP floor with port
    pub fn tcp(port: u16) -> Self {
        Self {
            protocol_id: protocol_id::TCP,
            lhs_data: vec![protocol_id::TCP],
            rhs_data: port.to_be_bytes().to_vec(), // Network byte order
        }
    }

    /// Create a UDP floor with port
    pub fn udp(port: u16) -> Self {
        Self {
            protocol_id: protocol_id::UDP,
            lhs_data: vec![protocol_id::UDP],
            rhs_data: port.to_be_bytes().to_vec(), // Network byte order
        }
    }

    /// Create an IP floor with address
    pub fn ip(addr: [u8; 4]) -> Self {
        Self {
            protocol_id: protocol_id::IP,
            lhs_data: vec![protocol_id::IP],
            rhs_data: addr.to_vec(),
        }
    }

    /// Create a named pipe floor with pipe name
    ///
    /// The pipe name should be in the format `\pipe\name` (without server prefix).
    /// It will be encoded as a null-terminated ASCII string.
    pub fn named_pipe(pipe_name: &str) -> Self {
        // Normalize the pipe name - remove any leading backslashes or \pipe\ prefix
        let name = pipe_name
            .trim_start_matches('\\')
            .trim_start_matches("pipe\\")
            .trim_start_matches('\\');

        // Create the endpoint string with \pipe\ prefix
        let endpoint = format!("\\pipe\\{}", name);

        // Encode as null-terminated ASCII
        let mut rhs = endpoint.as_bytes().to_vec();
        rhs.push(0); // Null terminator

        Self {
            protocol_id: protocol_id::NAMED_PIPE,
            lhs_data: vec![protocol_id::NAMED_PIPE],
            rhs_data: rhs,
        }
    }

    /// Create a NetBIOS floor with server name
    pub fn netbios(server_name: &str) -> Self {
        // Encode as null-terminated ASCII
        let mut rhs = server_name.as_bytes().to_vec();
        rhs.push(0); // Null terminator

        Self {
            protocol_id: protocol_id::NETBIOS,
            lhs_data: vec![protocol_id::NETBIOS],
            rhs_data: rhs,
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // LHS length (2 bytes, little-endian)
        buf.extend_from_slice(&(self.lhs_data.len() as u16).to_le_bytes());
        // LHS data
        buf.extend_from_slice(&self.lhs_data);
        // RHS length (2 bytes, little-endian)
        buf.extend_from_slice(&(self.rhs_data.len() as u16).to_le_bytes());
        // RHS data
        buf.extend_from_slice(&self.rhs_data);
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &mut impl Buf) -> Option<Self> {
        if data.remaining() < 2 {
            return None;
        }
        let lhs_len = data.get_u16_le() as usize;
        if data.remaining() < lhs_len {
            return None;
        }
        let mut lhs_data = vec![0u8; lhs_len];
        data.copy_to_slice(&mut lhs_data);
        let protocol_id = *lhs_data.first().unwrap_or(&0);

        if data.remaining() < 2 {
            return None;
        }
        let rhs_len = data.get_u16_le() as usize;
        if data.remaining() < rhs_len {
            return None;
        }
        let mut rhs_data = vec![0u8; rhs_len];
        data.copy_to_slice(&mut rhs_data);

        Some(Self {
            protocol_id,
            lhs_data,
            rhs_data,
        })
    }
}

/// A protocol tower describing how to reach a service
#[derive(Debug, Clone)]
pub struct ProtocolTower {
    /// Floors in the tower (from top to bottom)
    pub floors: Vec<TowerFloor>,
}

impl ProtocolTower {
    /// Create a new empty tower
    pub fn new() -> Self {
        Self { floors: Vec::new() }
    }

    /// Create a tower for TCP endpoint
    pub fn tcp_tower(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        port: u16,
        ip_addr: [u8; 4],
    ) -> Self {
        let mut tower = Self::new();
        // Floor 1: Interface UUID
        tower
            .floors
            .push(TowerFloor::uuid(interface_uuid, interface_version, 0));
        // Floor 2: Transfer syntax (NDR)
        tower.floors.push(TowerFloor::uuid(
            &transfer_syntax.uuid,
            transfer_syntax.major_version(),
            transfer_syntax.minor_version(),
        ));
        // Floor 3: RPC connection-oriented
        tower.floors.push(TowerFloor::rpc_co());
        // Floor 4: TCP port
        tower.floors.push(TowerFloor::tcp(port));
        // Floor 5: IP address
        tower.floors.push(TowerFloor::ip(ip_addr));
        tower
    }

    /// Create a tower for UDP endpoint
    pub fn udp_tower(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        port: u16,
        ip_addr: [u8; 4],
    ) -> Self {
        let mut tower = Self::new();
        // Floor 1: Interface UUID
        tower
            .floors
            .push(TowerFloor::uuid(interface_uuid, interface_version, 0));
        // Floor 2: Transfer syntax (NDR)
        tower.floors.push(TowerFloor::uuid(
            &transfer_syntax.uuid,
            transfer_syntax.major_version(),
            transfer_syntax.minor_version(),
        ));
        // Floor 3: RPC connectionless
        tower.floors.push(TowerFloor::rpc_cl());
        // Floor 4: UDP port
        tower.floors.push(TowerFloor::udp(port));
        // Floor 5: IP address
        tower.floors.push(TowerFloor::ip(ip_addr));
        tower
    }

    /// Create a tower for named pipe endpoint (local)
    ///
    /// # Arguments
    /// * `interface_uuid` - Interface UUID
    /// * `interface_version` - Interface major version
    /// * `transfer_syntax` - Transfer syntax (usually NDR)
    /// * `pipe_name` - Pipe name (e.g., "mypipe" or r"\pipe\mypipe")
    pub fn named_pipe_tower(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        pipe_name: &str,
    ) -> Self {
        let mut tower = Self::new();
        // Floor 1: Interface UUID
        tower
            .floors
            .push(TowerFloor::uuid(interface_uuid, interface_version, 0));
        // Floor 2: Transfer syntax (NDR)
        tower.floors.push(TowerFloor::uuid(
            &transfer_syntax.uuid,
            transfer_syntax.major_version(),
            transfer_syntax.minor_version(),
        ));
        // Floor 3: RPC connection-oriented (named pipes use CO)
        tower.floors.push(TowerFloor::rpc_co());
        // Floor 4: Named pipe endpoint
        tower.floors.push(TowerFloor::named_pipe(pipe_name));
        tower
    }

    /// Create a tower for named pipe endpoint with NetBIOS server name (remote)
    ///
    /// # Arguments
    /// * `interface_uuid` - Interface UUID
    /// * `interface_version` - Interface major version
    /// * `transfer_syntax` - Transfer syntax (usually NDR)
    /// * `pipe_name` - Pipe name (e.g., "mypipe" or r"\pipe\mypipe")
    /// * `server_name` - NetBIOS or DNS server name
    pub fn named_pipe_tower_remote(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        pipe_name: &str,
        server_name: &str,
    ) -> Self {
        let mut tower = Self::new();
        // Floor 1: Interface UUID
        tower
            .floors
            .push(TowerFloor::uuid(interface_uuid, interface_version, 0));
        // Floor 2: Transfer syntax (NDR)
        tower.floors.push(TowerFloor::uuid(
            &transfer_syntax.uuid,
            transfer_syntax.major_version(),
            transfer_syntax.minor_version(),
        ));
        // Floor 3: RPC connection-oriented (named pipes use CO)
        tower.floors.push(TowerFloor::rpc_co());
        // Floor 4: Named pipe endpoint
        tower.floors.push(TowerFloor::named_pipe(pipe_name));
        // Floor 5: NetBIOS server name
        tower.floors.push(TowerFloor::netbios(server_name));
        tower
    }

    /// Add a floor to the tower
    pub fn add_floor(&mut self, floor: TowerFloor) {
        self.floors.push(floor);
    }

    /// Get the interface UUID from the tower (first floor)
    pub fn interface_uuid(&self) -> Option<Uuid> {
        self.floors.first().and_then(|floor| {
            if floor.protocol_id == protocol_id::UUID && floor.lhs_data.len() >= 17 {
                Uuid::from_bytes_le(&floor.lhs_data[1..17])
            } else {
                None
            }
        })
    }

    /// Get the TCP port from the tower
    pub fn tcp_port(&self) -> Option<u16> {
        self.floors.iter().find_map(|floor| {
            if floor.protocol_id == protocol_id::TCP && floor.rhs_data.len() >= 2 {
                Some(u16::from_be_bytes([floor.rhs_data[0], floor.rhs_data[1]]))
            } else {
                None
            }
        })
    }

    /// Get the UDP port from the tower
    pub fn udp_port(&self) -> Option<u16> {
        self.floors.iter().find_map(|floor| {
            if floor.protocol_id == protocol_id::UDP && floor.rhs_data.len() >= 2 {
                Some(u16::from_be_bytes([floor.rhs_data[0], floor.rhs_data[1]]))
            } else {
                None
            }
        })
    }

    /// Get the IP address from the tower
    pub fn ip_addr(&self) -> Option<[u8; 4]> {
        self.floors.iter().find_map(|floor| {
            if floor.protocol_id == protocol_id::IP && floor.rhs_data.len() >= 4 {
                Some([
                    floor.rhs_data[0],
                    floor.rhs_data[1],
                    floor.rhs_data[2],
                    floor.rhs_data[3],
                ])
            } else {
                None
            }
        })
    }

    /// Check if this is a TCP tower
    pub fn is_tcp(&self) -> bool {
        self.floors
            .iter()
            .any(|f| f.protocol_id == protocol_id::TCP)
    }

    /// Check if this is a UDP tower
    pub fn is_udp(&self) -> bool {
        self.floors
            .iter()
            .any(|f| f.protocol_id == protocol_id::UDP)
    }

    /// Check if this is a named pipe tower
    pub fn is_named_pipe(&self) -> bool {
        self.floors
            .iter()
            .any(|f| f.protocol_id == protocol_id::NAMED_PIPE)
    }

    /// Get the named pipe name from the tower
    pub fn named_pipe_name(&self) -> Option<String> {
        self.floors.iter().find_map(|floor| {
            if floor.protocol_id == protocol_id::NAMED_PIPE && !floor.rhs_data.is_empty() {
                // Decode null-terminated ASCII string
                let end = floor.rhs_data.iter().position(|&b| b == 0)
                    .unwrap_or(floor.rhs_data.len());
                String::from_utf8(floor.rhs_data[..end].to_vec()).ok()
            } else {
                None
            }
        })
    }

    /// Get the NetBIOS server name from the tower
    pub fn netbios_name(&self) -> Option<String> {
        self.floors.iter().find_map(|floor| {
            if floor.protocol_id == protocol_id::NETBIOS && !floor.rhs_data.is_empty() {
                // Decode null-terminated ASCII string
                let end = floor.rhs_data.iter().position(|&b| b == 0)
                    .unwrap_or(floor.rhs_data.len());
                String::from_utf8(floor.rhs_data[..end].to_vec()).ok()
            } else {
                None
            }
        })
    }

    /// Encode the tower to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        // Number of floors (2 bytes)
        buf.put_u16_le(self.floors.len() as u16);
        // Encode each floor
        for floor in &self.floors {
            buf.extend_from_slice(&floor.encode());
        }
        buf.freeze()
    }

    /// Decode a tower from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        if buf.remaining() < 2 {
            return None;
        }
        let num_floors = buf.get_u16_le() as usize;
        let mut floors = Vec::with_capacity(num_floors);
        for _ in 0..num_floors {
            floors.push(TowerFloor::decode(&mut buf)?);
        }
        Some(Self { floors })
    }
}

impl Default for ProtocolTower {
    fn default() -> Self {
        Self::new()
    }
}

/// An endpoint map entry
#[derive(Debug, Clone)]
pub struct EpmEntry {
    /// Object UUID (can be nil)
    pub object: Uuid,
    /// Protocol tower describing how to reach the service
    pub tower: ProtocolTower,
    /// Annotation string (human-readable description)
    pub annotation: String,
}

impl EpmEntry {
    /// Create a new entry
    pub fn new(object: Uuid, tower: ProtocolTower, annotation: &str) -> Self {
        Self {
            object,
            tower,
            annotation: annotation.to_string(),
        }
    }

    /// Create a TCP entry for an interface
    pub fn tcp(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        port: u16,
        ip_addr: [u8; 4],
        annotation: &str,
    ) -> Self {
        Self {
            object: Uuid::NIL,
            tower: ProtocolTower::tcp_tower(
                interface_uuid,
                interface_version,
                transfer_syntax,
                port,
                ip_addr,
            ),
            annotation: annotation.to_string(),
        }
    }

    /// Create a UDP entry for an interface
    pub fn udp(
        interface_uuid: &Uuid,
        interface_version: u16,
        transfer_syntax: &SyntaxId,
        port: u16,
        ip_addr: [u8; 4],
        annotation: &str,
    ) -> Self {
        Self {
            object: Uuid::NIL,
            tower: ProtocolTower::udp_tower(
                interface_uuid,
                interface_version,
                transfer_syntax,
                port,
                ip_addr,
            ),
            annotation: annotation.to_string(),
        }
    }

    /// Get the interface UUID from the entry
    pub fn interface_uuid(&self) -> Option<Uuid> {
        self.tower.interface_uuid()
    }

    /// Encode the entry to bytes (NDR format)
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        // Object UUID (16 bytes)
        buf.extend_from_slice(&self.object.to_bytes_le());
        // Tower (as a conformant array)
        let tower_bytes = self.tower.encode();
        buf.put_u32_le(tower_bytes.len() as u32); // Max count
        buf.put_u32_le(0); // Offset
        buf.put_u32_le(tower_bytes.len() as u32); // Actual count
        buf.extend_from_slice(&tower_bytes);
        // Annotation (as a string with length)
        let ann_bytes = self.annotation.as_bytes();
        buf.put_u32_le(ann_bytes.len() as u32 + 1); // Include null terminator
        buf.extend_from_slice(ann_bytes);
        buf.put_u8(0); // Null terminator
                       // Pad to 4-byte boundary
        while !buf.len().is_multiple_of(4) {
            buf.put_u8(0);
        }
        buf.freeze()
    }

    /// Decode an entry from bytes (NDR format)
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        if buf.remaining() < 16 {
            return None;
        }
        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let object = Uuid::from_bytes_le(&uuid_bytes)?;

        if buf.remaining() < 12 {
            return None;
        }
        let _max_count = buf.get_u32_le();
        let _offset = buf.get_u32_le();
        let actual_count = buf.get_u32_le() as usize;

        if buf.remaining() < actual_count {
            return None;
        }
        let mut tower_bytes = vec![0u8; actual_count];
        buf.copy_to_slice(&mut tower_bytes);
        let tower = ProtocolTower::decode(&tower_bytes)?;

        if buf.remaining() < 4 {
            return None;
        }
        let ann_len = buf.get_u32_le() as usize;
        if buf.remaining() < ann_len {
            return None;
        }
        let mut ann_bytes = vec![0u8; ann_len];
        buf.copy_to_slice(&mut ann_bytes);
        // Remove null terminator
        if ann_bytes.last() == Some(&0) {
            ann_bytes.pop();
        }
        let annotation = String::from_utf8_lossy(&ann_bytes).to_string();

        Some(Self {
            object,
            tower,
            annotation,
        })
    }
}

/// Lookup request inquiry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EpmInquiryType {
    /// All interfaces
    All = 0,
    /// Match interface UUID
    Interface = 1,
    /// Match object UUID
    Object = 2,
    /// Match both interface and object UUID
    InterfaceAndObject = 3,
}

impl From<u32> for EpmInquiryType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::All,
            1 => Self::Interface,
            2 => Self::Object,
            3 => Self::InterfaceAndObject,
            _ => Self::All,
        }
    }
}

/// Result code for EPM operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EpmStatus {
    /// Success
    Ok = 0,
    /// Can't perform requested operation
    CantPerformOp = 0x16c9a0d6,
    /// Invalid entry
    InvalidEntry = 0x16c9a0d7,
    /// Not registered
    NotRegistered = 0x16c9a0d9,
    /// Invalid object
    InvalidObject = 0x16c9a0da,
}

impl From<u32> for EpmStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            0x16c9a0d6 => Self::CantPerformOp,
            0x16c9a0d7 => Self::InvalidEntry,
            0x16c9a0d9 => Self::NotRegistered,
            0x16c9a0da => Self::InvalidObject,
            _ => Self::CantPerformOp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcerpc::NDR_SYNTAX_UUID;

    #[test]
    fn test_tower_floor_encode_decode() {
        let floor = TowerFloor::tcp(12345);
        let encoded = floor.encode();
        let mut buf = encoded.as_slice();
        let decoded = TowerFloor::decode(&mut buf).unwrap();
        assert_eq!(decoded.protocol_id, protocol_id::TCP);
        assert_eq!(
            u16::from_be_bytes([decoded.rhs_data[0], decoded.rhs_data[1]]),
            12345
        );
    }

    #[test]
    fn test_protocol_tower_tcp() {
        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let ndr = SyntaxId::new(Uuid::parse(NDR_SYNTAX_UUID).unwrap(), 2, 0);
        let tower = ProtocolTower::tcp_tower(&uuid, 1, &ndr, 12346, [127, 0, 0, 1]);

        assert_eq!(tower.floors.len(), 5);
        assert!(tower.is_tcp());
        assert!(!tower.is_udp());
        assert_eq!(tower.tcp_port(), Some(12346));
        assert_eq!(tower.ip_addr(), Some([127, 0, 0, 1]));
    }

    #[test]
    fn test_protocol_tower_encode_decode() {
        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let ndr = SyntaxId::new(Uuid::parse(NDR_SYNTAX_UUID).unwrap(), 2, 0);
        let tower = ProtocolTower::tcp_tower(&uuid, 1, &ndr, 8080, [192, 168, 1, 100]);

        let encoded = tower.encode();
        let decoded = ProtocolTower::decode(&encoded).unwrap();

        assert_eq!(decoded.floors.len(), 5);
        assert_eq!(decoded.tcp_port(), Some(8080));
        assert_eq!(decoded.ip_addr(), Some([192, 168, 1, 100]));
    }
}
