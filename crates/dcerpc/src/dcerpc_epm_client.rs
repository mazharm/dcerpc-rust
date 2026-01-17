//! DCE RPC Endpoint Mapper Client
//!
//! Client implementation for querying and registering with the
//! DCE RPC Endpoint Mapper service (port 135).

use crate::dcerpc::{SyntaxId, Uuid, NDR_SYNTAX_UUID, NDR_SYNTAX_VERSION};
use crate::dcerpc_epm::*;
use crate::error::{Result, RpcError};
use crate::{DceRpcClient, UdpDceRpcClient};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tracing::debug;

/// Endpoint Mapper client
pub struct EpmClient {
    transport: EpmTransport,
}

enum EpmTransport {
    Tcp(DceRpcClient),
    Udp(UdpDceRpcClient),
}

impl EpmClient {
    /// Connect to the Endpoint Mapper over TCP
    pub async fn connect_tcp(host: IpAddr) -> Result<Self> {
        let addr = SocketAddr::new(host, EPM_PORT);
        let epm_interface = SyntaxId::new(
            Uuid::parse(EPM_INTERFACE_UUID).expect("Invalid EPM UUID"),
            EPM_INTERFACE_VERSION,
            0,
        );
        let client = DceRpcClient::connect(addr, epm_interface).await?;
        Ok(Self {
            transport: EpmTransport::Tcp(client),
        })
    }

    /// Connect to the Endpoint Mapper over UDP
    pub async fn connect_udp(host: IpAddr) -> Result<Self> {
        let addr = SocketAddr::new(host, EPM_PORT);
        let epm_uuid = Uuid::parse(EPM_INTERFACE_UUID).expect("Invalid EPM UUID");
        // CL protocol version format: (minor << 16) | major
        let epm_version = EPM_INTERFACE_VERSION as u32; // Major version in low 16 bits
        let mut client = UdpDceRpcClient::connect(addr, epm_uuid, epm_version).await?;
        client.set_timeout(Duration::from_secs(5));
        Ok(Self {
            transport: EpmTransport::Udp(client),
        })
    }

    /// Register endpoints with the Endpoint Mapper
    pub async fn insert(&mut self, entries: &[EpmEntry]) -> Result<()> {
        let mut buf = BytesMut::new();

        // Number of entries
        buf.put_u32_le(entries.len() as u32);

        // Encode entries
        for entry in entries {
            buf.extend_from_slice(&entry.encode());
        }

        // Replace flag (1 = replace existing)
        buf.put_u32_le(1);

        let result = self.call(epm_op::EPT_INSERT, buf.freeze()).await?;

        // Parse status
        if result.len() >= 4 {
            let status = EpmStatus::from((&result[..4]).get_u32_le());
            if status != EpmStatus::Ok {
                return Err(RpcError::CallRejected(format!(
                    "ept_insert failed: {:?}",
                    status
                )));
            }
        }

        debug!("ept_insert: {} entries registered", entries.len());
        Ok(())
    }

    /// Register a single TCP endpoint
    pub async fn insert_tcp(
        &mut self,
        interface_uuid: &Uuid,
        interface_version: u16,
        port: u16,
        ip_addr: [u8; 4],
        annotation: &str,
    ) -> Result<()> {
        let ndr = SyntaxId::new(
            Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
            NDR_SYNTAX_VERSION as u16,
            0,
        );
        let entry = EpmEntry::tcp(
            interface_uuid,
            interface_version,
            &ndr,
            port,
            ip_addr,
            annotation,
        );
        self.insert(&[entry]).await
    }

    /// Register a single UDP endpoint
    pub async fn insert_udp(
        &mut self,
        interface_uuid: &Uuid,
        interface_version: u16,
        port: u16,
        ip_addr: [u8; 4],
        annotation: &str,
    ) -> Result<()> {
        let ndr = SyntaxId::new(
            Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
            NDR_SYNTAX_VERSION as u16,
            0,
        );
        let entry = EpmEntry::udp(
            interface_uuid,
            interface_version,
            &ndr,
            port,
            ip_addr,
            annotation,
        );
        self.insert(&[entry]).await
    }

    /// Unregister endpoints from the Endpoint Mapper
    pub async fn delete(&mut self, entries: &[EpmEntry]) -> Result<()> {
        let mut buf = BytesMut::new();

        // Number of entries
        buf.put_u32_le(entries.len() as u32);

        // Encode entries
        for entry in entries {
            buf.extend_from_slice(&entry.encode());
        }

        let result = self.call(epm_op::EPT_DELETE, buf.freeze()).await?;

        // Parse status
        if result.len() >= 4 {
            let status = EpmStatus::from((&result[..4]).get_u32_le());
            if status != EpmStatus::Ok {
                return Err(RpcError::CallRejected(format!(
                    "ept_delete failed: {:?}",
                    status
                )));
            }
        }

        debug!("ept_delete: {} entries removed", entries.len());
        Ok(())
    }

    /// Lookup endpoints by interface UUID
    pub async fn lookup(&mut self, interface_uuid: &Uuid) -> Result<Vec<EpmEntry>> {
        let mut buf = BytesMut::new();

        // Inquiry type (1 = by interface)
        buf.put_u32_le(EpmInquiryType::Interface as u32);

        // Object UUID (nil)
        buf.extend_from_slice(&Uuid::NIL.to_bytes_le());

        // Interface UUID
        buf.extend_from_slice(&interface_uuid.to_bytes_le());

        // Interface version (can be 0 for any version)
        buf.put_u16_le(0);
        buf.put_u16_le(0);

        // Vers option (0 = exact match, 1 = all versions)
        buf.put_u32_le(1);

        // Entry handle (nil for first call)
        buf.extend_from_slice(&[0u8; 20]);

        // Max entries to return
        buf.put_u32_le(100);

        let result = self.call(epm_op::EPT_LOOKUP, buf.freeze()).await?;
        let mut cursor = result.as_ref();

        // Skip context handle (20 bytes)
        if cursor.remaining() < 20 {
            return Ok(Vec::new());
        }
        cursor.advance(20);

        // Number of entries
        if cursor.remaining() < 4 {
            return Ok(Vec::new());
        }
        let num_entries = cursor.get_u32_le() as usize;

        debug!(
            "ept_lookup: {} entries found for {}",
            num_entries, interface_uuid
        );

        // Parse entries
        let mut entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            if let Some(entry) = EpmEntry::decode(cursor) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Lookup all registered endpoints
    pub async fn lookup_all(&mut self) -> Result<Vec<EpmEntry>> {
        let mut buf = BytesMut::new();

        // Inquiry type (0 = all)
        buf.put_u32_le(EpmInquiryType::All as u32);

        // Object UUID (nil)
        buf.extend_from_slice(&Uuid::NIL.to_bytes_le());

        // Interface UUID (nil for all)
        buf.extend_from_slice(&Uuid::NIL.to_bytes_le());

        // Interface version
        buf.put_u16_le(0);
        buf.put_u16_le(0);

        // Vers option
        buf.put_u32_le(0);

        // Entry handle (nil for first call)
        buf.extend_from_slice(&[0u8; 20]);

        // Max entries to return
        buf.put_u32_le(1000);

        let result = self.call(epm_op::EPT_LOOKUP, buf.freeze()).await?;
        let mut cursor = result.as_ref();

        // Skip context handle (20 bytes)
        if cursor.remaining() < 20 {
            return Ok(Vec::new());
        }
        cursor.advance(20);

        // Number of entries
        if cursor.remaining() < 4 {
            return Ok(Vec::new());
        }
        let num_entries = cursor.get_u32_le() as usize;

        debug!("ept_lookup_all: {} entries found", num_entries);

        // Parse entries
        let mut entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            if let Some(entry) = EpmEntry::decode(cursor) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Map an interface to an endpoint (get the best matching endpoint)
    pub async fn map(
        &mut self,
        interface_uuid: &Uuid,
        interface_version: u16,
    ) -> Result<Option<(Ipv4Addr, u16, bool)>> {
        let ndr = SyntaxId::new(
            Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
            NDR_SYNTAX_VERSION as u16,
            0,
        );

        // Build a tower for the query
        let tower = ProtocolTower::tcp_tower(
            interface_uuid,
            interface_version,
            &ndr,
            0,            // We don't know the port yet
            [0, 0, 0, 0], // We don't know the IP yet
        );

        let mut buf = BytesMut::new();

        // Object UUID (nil)
        buf.extend_from_slice(&Uuid::NIL.to_bytes_le());

        // Tower
        let tower_bytes = tower.encode();
        buf.put_u32_le(tower_bytes.len() as u32);
        buf.extend_from_slice(&tower_bytes);

        // Entry handle (nil)
        buf.extend_from_slice(&[0u8; 20]);

        // Max towers
        buf.put_u32_le(1);

        let result = self.call(epm_op::EPT_MAP, buf.freeze()).await?;
        let mut cursor = result.as_ref();

        // Parse the response
        if cursor.remaining() < 4 {
            return Ok(None);
        }
        let tower_len = cursor.get_u32_le() as usize;

        if tower_len == 0 {
            // No matching endpoint
            return Ok(None);
        }

        if cursor.remaining() < tower_len {
            return Ok(None);
        }

        let mut tower_data = vec![0u8; tower_len];
        cursor.copy_to_slice(&mut tower_data);

        let response_tower = match ProtocolTower::decode(&tower_data) {
            Some(t) => t,
            None => return Ok(None),
        };

        // Extract the endpoint information
        let ip_addr = response_tower.ip_addr().unwrap_or([127, 0, 0, 1]);
        let is_tcp = response_tower.is_tcp();
        let port = if is_tcp {
            response_tower.tcp_port()
        } else {
            response_tower.udp_port()
        };

        if let Some(port) = port {
            debug!(
                "ept_map: found {} endpoint at {:?}:{}",
                if is_tcp { "TCP" } else { "UDP" },
                ip_addr,
                port
            );
            Ok(Some((Ipv4Addr::from(ip_addr), port, is_tcp)))
        } else {
            Ok(None)
        }
    }

    /// Map an interface and return the TCP endpoint
    pub async fn map_tcp(
        &mut self,
        interface_uuid: &Uuid,
        interface_version: u16,
    ) -> Result<Option<(Ipv4Addr, u16)>> {
        if let Some((ip, port, is_tcp)) = self.map(interface_uuid, interface_version).await? {
            if is_tcp {
                return Ok(Some((ip, port)));
            }
        }
        Ok(None)
    }

    async fn call(&mut self, opnum: u16, args: Bytes) -> Result<Bytes> {
        match &mut self.transport {
            EpmTransport::Tcp(client) => client.call(opnum, args).await,
            EpmTransport::Udp(client) => client.call(opnum, args).await,
        }
    }
}

/// Helper to connect to a DCE RPC service via the Endpoint Mapper
pub async fn connect_via_epm_tcp(
    host: IpAddr,
    interface_uuid: &Uuid,
    interface_version: u16,
) -> Result<DceRpcClient> {
    // First query the EPM
    let mut epm = EpmClient::connect_tcp(host).await?;
    let result = epm.map(interface_uuid, interface_version).await?;

    match result {
        Some((ip, port, true)) => {
            // TCP endpoint found
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            let interface = SyntaxId::new(*interface_uuid, interface_version, 0);
            DceRpcClient::connect(addr, interface).await
        }
        Some((_, _, false)) => Err(RpcError::CallRejected(
            "Only UDP endpoint available".to_string(),
        )),
        None => Err(RpcError::ProgramUnavailable(0)),
    }
}

/// Helper to connect to a DCE RPC service via the Endpoint Mapper (UDP)
pub async fn connect_via_epm_udp(
    host: IpAddr,
    interface_uuid: &Uuid,
    interface_version: u16,
) -> Result<UdpDceRpcClient> {
    // First query the EPM
    let mut epm = EpmClient::connect_udp(host).await?;
    let result = epm.map(interface_uuid, interface_version).await?;

    match result {
        Some((ip, port, false)) => {
            // UDP endpoint found
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            // CL protocol version format: (minor << 16) | major
            let version = interface_version as u32; // Major version in low 16 bits
            UdpDceRpcClient::connect(addr, *interface_uuid, version).await
        }
        Some((ip, port, true)) => {
            // Fall back to TCP endpoint via UDP client isn't ideal
            // Return the TCP info but as UDP connection won't work
            Err(RpcError::CallRejected(format!(
                "Only TCP endpoint available at {}:{}",
                ip, port
            )))
        }
        None => Err(RpcError::ProgramUnavailable(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epm_entry_creation() {
        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let ndr = SyntaxId::new(Uuid::parse(NDR_SYNTAX_UUID).unwrap(), 2, 0);

        let entry = EpmEntry::tcp(&uuid, 1, &ndr, 12346, [127, 0, 0, 1], "Test");
        assert_eq!(entry.annotation, "Test");
        assert!(entry.tower.is_tcp());
        assert_eq!(entry.tower.tcp_port(), Some(12346));
    }
}
