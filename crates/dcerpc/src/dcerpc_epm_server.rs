//! DCE RPC Endpoint Mapper Server
//!
//! Server implementation for the DCE RPC Endpoint Mapper service.
//! This allows DCE RPC services to register their endpoints and
//! clients to look up where services are located.

use crate::dcerpc::{SyntaxId, Uuid, NDR_SYNTAX_UUID, NDR_SYNTAX_VERSION};
use crate::dcerpc_epm::*;
use crate::dcerpc_server::{Interface, InterfaceBuilder};
use crate::error::Result;
use crate::{DceRpcServer, UdpDceRpcServer};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Shared state for endpoint mapper registrations
#[derive(Debug, Default)]
pub struct EpmRegistry {
    /// Registered entries, keyed by interface UUID
    entries: HashMap<Uuid, Vec<EpmEntry>>,
}

impl EpmRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an entry
    pub fn insert(&mut self, entry: EpmEntry) -> bool {
        if let Some(uuid) = entry.interface_uuid() {
            debug!("EPM: Registering interface {} ({})", uuid, entry.annotation);
            let entries = self.entries.entry(uuid).or_default();

            // Check if we already have this exact entry (same tower)
            let tower_bytes = entry.tower.encode();
            let exists = entries.iter().any(|e| e.tower.encode() == tower_bytes);

            if !exists {
                entries.push(entry);
            }
            true
        } else {
            false
        }
    }

    /// Unregister entries matching the given interface UUID
    pub fn delete(&mut self, interface_uuid: &Uuid) -> bool {
        debug!("EPM: Unregistering interface {}", interface_uuid);
        self.entries.remove(interface_uuid).is_some()
    }

    /// Unregister a specific entry
    pub fn delete_entry(&mut self, entry: &EpmEntry) -> bool {
        if let Some(uuid) = entry.interface_uuid() {
            if let Some(entries) = self.entries.get_mut(&uuid) {
                let tower_bytes = entry.tower.encode();
                let len_before = entries.len();
                entries.retain(|e| e.tower.encode() != tower_bytes);
                return entries.len() < len_before;
            }
        }
        false
    }

    /// Lookup entries for an interface
    pub fn lookup(&self, interface_uuid: &Uuid) -> Vec<&EpmEntry> {
        self.entries
            .get(interface_uuid)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Lookup all entries
    pub fn lookup_all(&self) -> Vec<&EpmEntry> {
        self.entries.values().flatten().collect()
    }

    /// Map an interface to an endpoint (returns the first matching tower)
    pub fn map(&self, interface_uuid: &Uuid, prefer_tcp: bool) -> Option<&EpmEntry> {
        let entries = self.entries.get(interface_uuid)?;

        if prefer_tcp {
            // Try to find a TCP entry first
            entries
                .iter()
                .find(|e| e.tower.is_tcp())
                .or_else(|| entries.first())
        } else {
            // Try to find a UDP entry first
            entries
                .iter()
                .find(|e| e.tower.is_udp())
                .or_else(|| entries.first())
        }
    }

    /// Get the number of registered entries
    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Create the EPM interface
pub fn create_epm_interface(registry: Arc<RwLock<EpmRegistry>>) -> Interface {
    let reg_insert = Arc::clone(&registry);
    let reg_delete = Arc::clone(&registry);
    let reg_lookup = Arc::clone(&registry);
    let reg_map = Arc::clone(&registry);

    InterfaceBuilder::new(EPM_INTERFACE_UUID, EPM_INTERFACE_VERSION, 0)
        .expect("Invalid EPM UUID")
        // ept_insert - Register endpoints
        .operation(epm_op::EPT_INSERT, move |args: Bytes| {
            let reg = Arc::clone(&reg_insert);
            async move {
                let result = process_ept_insert(&reg, &args).await;
                Ok(result)
            }
        })
        // ept_delete - Unregister endpoints
        .operation(epm_op::EPT_DELETE, move |args: Bytes| {
            let reg = Arc::clone(&reg_delete);
            async move {
                let result = process_ept_delete(&reg, &args).await;
                Ok(result)
            }
        })
        // ept_lookup - Lookup endpoints
        .operation(epm_op::EPT_LOOKUP, move |args: Bytes| {
            let reg = Arc::clone(&reg_lookup);
            async move {
                let result = process_ept_lookup(&reg, &args).await;
                Ok(result)
            }
        })
        // ept_map - Map interface to endpoint
        .operation(epm_op::EPT_MAP, move |args: Bytes| {
            let reg = Arc::clone(&reg_map);
            async move {
                let result = process_ept_map(&reg, &args).await;
                Ok(result)
            }
        })
        .build()
}

/// Process ept_insert request
async fn process_ept_insert(registry: &Arc<RwLock<EpmRegistry>>, args: &[u8]) -> Bytes {
    let mut buf = args;

    // Parse the request
    // num_ents (u32)
    if buf.remaining() < 4 {
        return encode_status(EpmStatus::InvalidEntry as u32);
    }
    let num_ents = buf.get_u32_le();

    debug!("ept_insert: {} entries", num_ents);

    let mut reg = registry.write().await;

    for _ in 0..num_ents {
        if let Some(entry) = EpmEntry::decode(buf) {
            reg.insert(entry);
        }
    }

    // Return status
    encode_status(EpmStatus::Ok as u32)
}

/// Process ept_delete request
async fn process_ept_delete(registry: &Arc<RwLock<EpmRegistry>>, args: &[u8]) -> Bytes {
    let mut buf = args;

    // Parse the request
    if buf.remaining() < 4 {
        return encode_status(EpmStatus::InvalidEntry as u32);
    }
    let num_ents = buf.get_u32_le();

    debug!("ept_delete: {} entries", num_ents);

    let mut reg = registry.write().await;

    for _ in 0..num_ents {
        if let Some(entry) = EpmEntry::decode(buf) {
            reg.delete_entry(&entry);
        }
    }

    encode_status(EpmStatus::Ok as u32)
}

/// Process ept_lookup request
async fn process_ept_lookup(registry: &Arc<RwLock<EpmRegistry>>, args: &[u8]) -> Bytes {
    let mut buf = args;

    // Parse inquiry type
    if buf.remaining() < 4 {
        return encode_lookup_response(&[], EpmStatus::InvalidEntry);
    }
    let inquiry_type = EpmInquiryType::from(buf.get_u32_le());

    // Parse object UUID (16 bytes)
    if buf.remaining() < 16 {
        return encode_lookup_response(&[], EpmStatus::InvalidEntry);
    }
    let mut object_bytes = [0u8; 16];
    buf.copy_to_slice(&mut object_bytes);
    let _object = Uuid::from_bytes_le(&object_bytes);

    // Parse interface UUID (if present in the tower)
    let interface_uuid = if buf.remaining() >= 16 {
        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        Uuid::from_bytes_le(&uuid_bytes)
    } else {
        None
    };

    debug!(
        "ept_lookup: type={:?}, interface={:?}",
        inquiry_type, interface_uuid
    );

    let reg = registry.read().await;

    let entries: Vec<&EpmEntry> = match (inquiry_type, interface_uuid) {
        (EpmInquiryType::Interface, Some(uuid))
        | (EpmInquiryType::InterfaceAndObject, Some(uuid)) => reg.lookup(&uuid),
        _ => reg.lookup_all(),
    };

    encode_lookup_response(&entries, EpmStatus::Ok)
}

/// Process ept_map request
async fn process_ept_map(registry: &Arc<RwLock<EpmRegistry>>, args: &[u8]) -> Bytes {
    let mut buf = args;

    // Parse object UUID
    if buf.remaining() < 16 {
        return encode_map_response(None, EpmStatus::InvalidEntry);
    }
    let mut object_bytes = [0u8; 16];
    buf.copy_to_slice(&mut object_bytes);
    let _object = Uuid::from_bytes_le(&object_bytes);

    // Parse the input tower to extract interface UUID
    if buf.remaining() < 4 {
        return encode_map_response(None, EpmStatus::InvalidEntry);
    }
    let tower_len = buf.get_u32_le() as usize;

    if buf.remaining() < tower_len {
        return encode_map_response(None, EpmStatus::InvalidEntry);
    }

    let mut tower_bytes = vec![0u8; tower_len];
    buf.copy_to_slice(&mut tower_bytes);

    let tower = match ProtocolTower::decode(&tower_bytes) {
        Some(t) => t,
        None => return encode_map_response(None, EpmStatus::InvalidEntry),
    };

    let interface_uuid = match tower.interface_uuid() {
        Some(u) => u,
        None => return encode_map_response(None, EpmStatus::InvalidEntry),
    };

    debug!("ept_map: interface={}", interface_uuid);

    let reg = registry.read().await;
    let entry = reg.map(&interface_uuid, true);

    if entry.is_some() {
        encode_map_response(entry, EpmStatus::Ok)
    } else {
        encode_map_response(None, EpmStatus::NotRegistered)
    }
}

/// Encode a simple status response
fn encode_status(status: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u32_le(status);
    buf.freeze()
}

/// Encode a lookup response
fn encode_lookup_response(entries: &[&EpmEntry], status: EpmStatus) -> Bytes {
    let mut buf = BytesMut::new();

    // Context handle (20 bytes, all zeros for now - we don't support continuation)
    buf.put_slice(&[0u8; 20]);

    // Number of entries
    buf.put_u32_le(entries.len() as u32);

    // Encode entries
    for entry in entries {
        buf.extend_from_slice(&entry.encode());
    }

    // Status
    buf.put_u32_le(status as u32);

    buf.freeze()
}

/// Encode a map response
fn encode_map_response(entry: Option<&EpmEntry>, status: EpmStatus) -> Bytes {
    let mut buf = BytesMut::new();

    if let Some(entry) = entry {
        // Tower present
        let tower_bytes = entry.tower.encode();
        buf.put_u32_le(tower_bytes.len() as u32);
        buf.extend_from_slice(&tower_bytes);
    } else {
        // No tower
        buf.put_u32_le(0);
    }

    // Status
    buf.put_u32_le(status as u32);

    buf.freeze()
}

/// Endpoint Mapper server
pub struct EpmServer {
    registry: Arc<RwLock<EpmRegistry>>,
}

impl EpmServer {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RwLock::new(EpmRegistry::new())),
        }
    }

    /// Get the registry for direct manipulation
    pub fn registry(&self) -> Arc<RwLock<EpmRegistry>> {
        Arc::clone(&self.registry)
    }

    /// Pre-register the EPM itself
    pub async fn register_self(&self, tcp_port: u16, udp_port: u16, ip_addr: [u8; 4]) {
        let ndr = SyntaxId::new(
            Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
            NDR_SYNTAX_VERSION as u16,
            0,
        );
        let epm_uuid = Uuid::parse(EPM_INTERFACE_UUID).unwrap();

        let mut reg = self.registry.write().await;

        // Register TCP endpoint
        reg.insert(EpmEntry::tcp(
            &epm_uuid,
            EPM_INTERFACE_VERSION,
            &ndr,
            tcp_port,
            ip_addr,
            "Endpoint Mapper (TCP)",
        ));

        // Register UDP endpoint
        reg.insert(EpmEntry::udp(
            &epm_uuid,
            EPM_INTERFACE_VERSION,
            &ndr,
            udp_port,
            ip_addr,
            "Endpoint Mapper (UDP)",
        ));

        info!(
            "EPM: Registered self on TCP:{} and UDP:{}",
            tcp_port, udp_port
        );
    }

    /// Run TCP server
    pub async fn run_tcp(&self, addr: SocketAddr) -> Result<()> {
        info!("Starting EPM TCP server on {}", addr);

        let server = DceRpcServer::new();
        server
            .register_interface(create_epm_interface(Arc::clone(&self.registry)))
            .await;

        server.run(addr).await
    }

    /// Run UDP server
    pub async fn run_udp(&self, addr: SocketAddr) -> Result<()> {
        info!("Starting EPM UDP server on {}", addr);

        let server = UdpDceRpcServer::new();
        server
            .register_interface(create_epm_interface(Arc::clone(&self.registry)))
            .await;

        server.run(addr).await
    }

    /// Run both TCP and UDP servers
    pub async fn run(self, tcp_addr: SocketAddr, udp_addr: SocketAddr) -> Result<()> {
        // Extract IP address from the address
        let ip_addr = match tcp_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => [0, 0, 0, 0], // Not supported yet
        };

        // Register self
        self.register_self(tcp_addr.port(), udp_addr.port(), ip_addr)
            .await;

        let tcp_registry = Arc::clone(&self.registry);
        let udp_registry = Arc::clone(&self.registry);

        // Run both servers concurrently
        let tcp_handle = tokio::spawn(async move {
            let server = DceRpcServer::new();
            server
                .register_interface(create_epm_interface(tcp_registry))
                .await;
            server.run(tcp_addr).await
        });

        let udp_handle = tokio::spawn(async move {
            let server = UdpDceRpcServer::new();
            server
                .register_interface(create_epm_interface(udp_registry))
                .await;
            server.run(udp_addr).await
        });

        tokio::select! {
            result = tcp_handle => result??,
            result = udp_handle => result??,
        }

        Ok(())
    }
}

impl Default for EpmServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_insert_lookup() {
        let mut registry = EpmRegistry::new();

        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let ndr = SyntaxId::new(Uuid::parse(NDR_SYNTAX_UUID).unwrap(), 2, 0);

        let entry = EpmEntry::tcp(&uuid, 1, &ndr, 12346, [127, 0, 0, 1], "Test Service");
        registry.insert(entry);

        let entries = registry.lookup(&uuid);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].annotation, "Test Service");
    }

    #[test]
    fn test_registry_map() {
        let mut registry = EpmRegistry::new();

        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let ndr = SyntaxId::new(Uuid::parse(NDR_SYNTAX_UUID).unwrap(), 2, 0);

        // Add both TCP and UDP entries
        registry.insert(EpmEntry::tcp(&uuid, 1, &ndr, 12346, [127, 0, 0, 1], "TCP"));
        registry.insert(EpmEntry::udp(&uuid, 1, &ndr, 12346, [127, 0, 0, 1], "UDP"));

        // Prefer TCP
        let entry = registry.map(&uuid, true).unwrap();
        assert!(entry.tower.is_tcp());

        // Prefer UDP
        let entry = registry.map(&uuid, false).unwrap();
        assert!(entry.tower.is_udp());
    }
}
