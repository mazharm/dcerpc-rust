//! DCE RPC UDP Server (Connectionless Protocol)
//!
//! A server implementation for the DCE RPC connectionless protocol over UDP.
//! Uses the 80-byte connectionless PDU header format (RPC version 4).
//!
//! Key differences from connection-oriented (TCP) server:
//! - No bind/bind_ack handshake - requests handled directly
//! - Activity ID identifies clients instead of connections
//! - Sequence numbers track call ordering
//! - Server boot time helps clients detect server restarts

use crate::dcerpc::Uuid;
use crate::dcerpc_cl::{
    ClFaultPdu, ClPdu, ClRejectPdu, ClRequestPdu, ClResponsePdu,
};
use crate::dcerpc_server::Interface;
use crate::error::Result;
use crate::udp_transport::UdpTransport;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

/// UDP DCE RPC Server Configuration
#[derive(Debug, Clone)]
pub struct UdpDceRpcServerConfig {
    /// Maximum message size
    pub max_message_size: usize,
}

impl Default for UdpDceRpcServerConfig {
    fn default() -> Self {
        Self {
            max_message_size: 4096,
        }
    }
}

/// UDP DCE RPC Server (Connectionless)
///
/// This server uses the DCE RPC connectionless (datagram) protocol,
/// which has an 80-byte header and uses RPC version 4.
pub struct UdpDceRpcServer {
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: UdpDceRpcServerConfig,
    /// Server boot time (seconds since epoch)
    server_boot: u32,
}

impl UdpDceRpcServer {
    /// Create a new UDP DCE RPC server
    pub fn new() -> Self {
        let server_boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            config: UdpDceRpcServerConfig::default(),
            server_boot,
        }
    }

    /// Create a new server with custom configuration
    pub fn with_config(config: UdpDceRpcServerConfig) -> Self {
        let server_boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            config,
            server_boot,
        }
    }

    /// Register an interface with the server
    pub async fn register_interface(&self, interface: Interface) {
        let mut interfaces = self.interfaces.write().await;
        // SyntaxId stores version as (minor << 16) | major
        info!(
            "Registering CL interface: {} version {}.{}",
            interface.syntax.uuid,
            interface.syntax.version & 0xFFFF,        // major in lower 16 bits
            (interface.syntax.version >> 16) & 0xFFFF // minor in upper 16 bits
        );
        interfaces.insert(interface.syntax.uuid, interface);
    }

    /// Unregister an interface
    pub async fn unregister_interface(&self, uuid: &Uuid) {
        let mut interfaces = self.interfaces.write().await;
        interfaces.remove(uuid);
    }

    /// Run the server on the specified address
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let mut transport = UdpTransport::bind(addr).await?;
        info!("CL DCE RPC server listening on {}", addr);

        loop {
            match transport.recv_from().await {
                Ok((data, peer_addr)) => {
                    trace!("Received {} bytes from {}", data.len(), peer_addr);

                    if let Some(response) = self.process_packet(&data, peer_addr).await {
                        if let Err(e) = transport.send_to(&response, peer_addr).await {
                            error!("Failed to send response to {}: {}", peer_addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }

    /// Process a single packet and return the response (if any)
    async fn process_packet(&self, data: &[u8], peer_addr: SocketAddr) -> Option<Bytes> {
        // Decode the PDU
        let pdu = match ClPdu::decode(data) {
            Ok(pdu) => pdu,
            Err(e) => {
                error!("Failed to decode CL PDU from {}: {}", peer_addr, e);
                return None;
            }
        };

        match pdu {
            ClPdu::Request(request) => {
                debug!(
                    "Received CL request from {}: seqnum={}, opnum={}, if={}, body_len={}",
                    peer_addr,
                    request.header.seqnum,
                    request.header.opnum,
                    request.header.if_id,
                    request.body.len()
                );

                let response = self.process_request(&request, peer_addr).await;
                Some(response.encode())
            }

            ClPdu::Ping(ping) => {
                // Client is checking if call is still being processed
                // For now, respond with nocall (we don't track pending calls)
                debug!(
                    "Received CL ping from {}: seqnum={}",
                    peer_addr, ping.header.seqnum
                );
                let nocall = crate::dcerpc_cl::ClNocallPdu::new(&ping.header);
                Some(nocall.encode())
            }

            ClPdu::Ack(_) => {
                // Client acknowledging our response, nothing to do
                trace!("Received CL ack from {}", peer_addr);
                None
            }

            _ => {
                warn!(
                    "Received unexpected CL packet type from {}: {:?}",
                    peer_addr,
                    pdu.header().ptype
                );
                None
            }
        }
    }

    /// Process a request PDU
    async fn process_request(&self, request: &ClRequestPdu, peer_addr: SocketAddr) -> ClPdu {
        let interfaces = self.interfaces.read().await;

        // Look up the interface
        let interface = match interfaces.get(&request.header.if_id) {
            Some(iface) => iface,
            None => {
                debug!(
                    "Unknown interface {} from {}",
                    request.header.if_id, peer_addr
                );
                let reject = ClRejectPdu::new(&request.header, 0x1c010003); // nca_s_unk_if
                return ClPdu::Reject(reject);
            }
        };

        // Check interface version
        // Both SyntaxId and CL protocol use (minor << 16) | major format
        // (major in lower 16 bits, minor in upper 16 bits)
        if interface.syntax.version != request.header.if_vers {
            let syntax_major = interface.syntax.version & 0xFFFF;
            let syntax_minor = (interface.syntax.version >> 16) & 0xFFFF;
            let req_major = request.header.if_vers & 0xFFFF;
            let req_minor = (request.header.if_vers >> 16) & 0xFFFF;
            debug!(
                "Interface version mismatch: expected v{}.{} (0x{:08x}), got v{}.{} (0x{:08x})",
                syntax_major, syntax_minor, interface.syntax.version,
                req_major, req_minor, request.header.if_vers
            );
            let reject = ClRejectPdu::new(&request.header, 0x1c000008); // nca_s_wrong_boot_time (reusing for version)
            return ClPdu::Reject(reject);
        }

        // Look up the operation
        let handler = match interface.get_operation(request.header.opnum) {
            Some(h) => h,
            None => {
                debug!(
                    "Unknown operation {} on interface {}",
                    request.header.opnum, request.header.if_id
                );
                let fault = ClFaultPdu::new(&request.header, 0x1c010002); // nca_s_op_rng_error
                return ClPdu::Fault(fault);
            }
        };

        // Call the handler
        match handler(request.body.clone()).await {
            Ok(result) => {
                let mut response = ClResponsePdu::new(&request.header, result);
                response.header.server_boot = self.server_boot;
                ClPdu::Response(response)
            }
            Err(e) => {
                error!("Handler error for opnum {}: {}", request.header.opnum, e);
                let fault = ClFaultPdu::new(&request.header, 0x1c000000); // Generic fault
                ClPdu::Fault(fault)
            }
        }
    }
}

impl Default for UdpDceRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_server_creation() {
        let server = UdpDceRpcServer::new();
        assert!(server.server_boot > 0);
    }

    #[test]
    fn test_udp_server_config() {
        let config = UdpDceRpcServerConfig {
            max_message_size: 8192,
        };
        let server = UdpDceRpcServer::with_config(config);
        assert_eq!(server.config.max_message_size, 8192);
    }
}
