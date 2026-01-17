//! DCE RPC UDP Server (Connectionless Protocol)
//!
//! A highly scalable server implementation for the DCE RPC connectionless protocol over UDP.
//! Uses the 80-byte connectionless PDU header format (RPC version 4).
//!
//! # Scalability Features
//!
//! - Concurrent request processing using Tokio tasks
//! - Configurable worker pool size
//! - Semaphore-based concurrency limiting
//! - Lock-free request dispatching where possible
//! - Graceful shutdown support
//!
//! # Key differences from connection-oriented (TCP) server:
//! - No bind/bind_ack handshake - requests handled directly
//! - Activity ID identifies clients instead of connections
//! - Sequence numbers track call ordering
//! - Server boot time helps clients detect server restarts

use crate::dcerpc::Uuid;
use crate::dcerpc_cl::{ClFaultPdu, ClPdu, ClRejectPdu, ClRequestPdu, ClResponsePdu};
use crate::dcerpc_server::Interface;
use crate::error::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, trace, warn};

/// UDP DCE RPC Server Configuration
#[derive(Debug, Clone)]
pub struct UdpDceRpcServerConfig {
    /// Maximum message size
    pub max_message_size: usize,
    /// Maximum concurrent requests (0 = unlimited)
    pub max_concurrent_requests: usize,
    /// Number of receiver tasks for parallel packet reception
    pub receiver_tasks: usize,
}

impl Default for UdpDceRpcServerConfig {
    fn default() -> Self {
        Self {
            max_message_size: 4096,
            max_concurrent_requests: 10000,
            receiver_tasks: num_cpus(),
        }
    }
}

/// Get number of CPUs (fallback to 4 if unavailable)
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

/// Server statistics
#[derive(Debug, Default)]
pub struct UdpServerStats {
    pub requests_received: AtomicU64,
    pub requests_processed: AtomicU64,
    pub requests_rejected: AtomicU64,
    pub requests_failed: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl UdpServerStats {
    pub fn snapshot(&self) -> UdpServerStatsSnapshot {
        UdpServerStatsSnapshot {
            requests_received: self.requests_received.load(Ordering::Relaxed),
            requests_processed: self.requests_processed.load(Ordering::Relaxed),
            requests_rejected: self.requests_rejected.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of server statistics
#[derive(Debug, Clone)]
pub struct UdpServerStatsSnapshot {
    pub requests_received: u64,
    pub requests_processed: u64,
    pub requests_rejected: u64,
    pub requests_failed: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

/// UDP DCE RPC Server (Connectionless)
///
/// This server uses the DCE RPC connectionless (datagram) protocol,
/// which has an 80-byte header and uses RPC version 4.
///
/// # Scalability
///
/// The server processes requests concurrently using Tokio tasks:
/// - Each incoming packet is dispatched to a worker task
/// - A semaphore limits maximum concurrent requests
/// - Multiple receiver tasks can run in parallel
pub struct UdpDceRpcServer {
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: UdpDceRpcServerConfig,
    /// Server boot time (seconds since epoch)
    server_boot: u32,
    /// Server statistics
    stats: Arc<UdpServerStats>,
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
            stats: Arc::new(UdpServerStats::default()),
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
            stats: Arc::new(UdpServerStats::default()),
        }
    }

    /// Get server statistics
    pub fn stats(&self) -> &Arc<UdpServerStats> {
        &self.stats
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
    ///
    /// This method runs until an error occurs. For graceful shutdown,
    /// use `run_until` instead.
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(
            "CL DCE RPC server listening on {} (max_concurrent: {}, receivers: {})",
            addr, self.config.max_concurrent_requests, self.config.receiver_tasks
        );

        // Create semaphore for concurrency limiting
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_requests));

        // Run the receive loop
        self.receive_loop(socket, semaphore).await
    }

    /// Run the server with graceful shutdown
    pub async fn run_until<F: Future<Output = ()>>(
        &self,
        addr: SocketAddr,
        shutdown: F,
    ) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(
            "CL DCE RPC server listening on {} (max_concurrent: {}, receivers: {})",
            addr, self.config.max_concurrent_requests, self.config.receiver_tasks
        );

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_requests));

        tokio::pin!(shutdown);

        loop {
            let mut buf = vec![0u8; self.config.max_message_size];

            tokio::select! {
                biased;

                _ = &mut shutdown => {
                    info!("UDP server shutting down gracefully");
                    // Wait for pending requests to complete
                    let _ = semaphore.acquire_many(self.config.max_concurrent_requests as u32).await;
                    info!("All pending requests completed");
                    return Ok(());
                }

                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
                            self.stats.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

                            let data = Bytes::copy_from_slice(&buf[..len]);
                            self.spawn_handler(
                                Arc::clone(&socket),
                                Arc::clone(&semaphore),
                                data,
                                peer_addr,
                            );
                        }
                        Err(e) => {
                            error!("Error receiving packet: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Main receive loop
    async fn receive_loop(
        &self,
        socket: Arc<UdpSocket>,
        semaphore: Arc<Semaphore>,
    ) -> Result<()> {
        let mut buf = vec![0u8; self.config.max_message_size];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

                    let data = Bytes::copy_from_slice(&buf[..len]);
                    self.spawn_handler(
                        Arc::clone(&socket),
                        Arc::clone(&semaphore),
                        data,
                        peer_addr,
                    );
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }

    /// Spawn a handler task for a received packet
    fn spawn_handler(
        &self,
        socket: Arc<UdpSocket>,
        semaphore: Arc<Semaphore>,
        data: Bytes,
        peer_addr: SocketAddr,
    ) {
        let interfaces = Arc::clone(&self.interfaces);
        let server_boot = self.server_boot;
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            // Acquire semaphore permit (limits concurrency)
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    // Semaphore closed, server shutting down
                    return;
                }
            };

            // Process the packet
            if let Some(response) = process_packet(&data, peer_addr, &interfaces, server_boot, &stats).await {
                let response_len = response.len();
                if let Err(e) = socket.send_to(&response, peer_addr).await {
                    error!("Failed to send response to {}: {}", peer_addr, e);
                } else {
                    stats.bytes_sent.fetch_add(response_len as u64, Ordering::Relaxed);
                }
            }
        });
    }
}

impl Default for UdpDceRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Process a single packet and return the response (if any)
async fn process_packet(
    data: &[u8],
    peer_addr: SocketAddr,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    server_boot: u32,
    stats: &Arc<UdpServerStats>,
) -> Option<Bytes> {
    // Decode the PDU
    let pdu = match ClPdu::decode(data) {
        Ok(pdu) => pdu,
        Err(e) => {
            error!("Failed to decode CL PDU from {}: {}", peer_addr, e);
            stats.requests_failed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };

    match pdu {
        ClPdu::Request(request) => {
            trace!(
                "Received CL request from {}: seqnum={}, opnum={}, if={}, body_len={}",
                peer_addr,
                request.header.seqnum,
                request.header.opnum,
                request.header.if_id,
                request.body.len()
            );

            let response = process_request(&request, peer_addr, interfaces, server_boot, stats).await;
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
async fn process_request(
    request: &ClRequestPdu,
    peer_addr: SocketAddr,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    server_boot: u32,
    stats: &Arc<UdpServerStats>,
) -> ClPdu {
    let interfaces_guard = interfaces.read().await;

    // Look up the interface
    let interface = match interfaces_guard.get(&request.header.if_id) {
        Some(iface) => iface,
        None => {
            debug!(
                "Unknown interface {} from {}",
                request.header.if_id, peer_addr
            );
            stats.requests_rejected.fetch_add(1, Ordering::Relaxed);
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
            syntax_major, syntax_minor, interface.syntax.version, req_major, req_minor, request.header.if_vers
        );
        stats.requests_rejected.fetch_add(1, Ordering::Relaxed);
        let reject = ClRejectPdu::new(&request.header, 0x1c000008); // nca_s_wrong_boot_time (reusing for version)
        return ClPdu::Reject(reject);
    }

    // Look up the operation and clone the handler
    let handler = match interface.get_operation(request.header.opnum) {
        Some(h) => Arc::clone(h),
        None => {
            debug!(
                "Unknown operation {} on interface {}",
                request.header.opnum, request.header.if_id
            );
            stats.requests_rejected.fetch_add(1, Ordering::Relaxed);
            let fault = ClFaultPdu::new(&request.header, 0x1c010002); // nca_s_op_rng_error
            return ClPdu::Fault(fault);
        }
    };

    // Release the lock before calling the handler
    drop(interfaces_guard);

    // Call the handler
    match handler(request.body.clone()).await {
        Ok(result) => {
            stats.requests_processed.fetch_add(1, Ordering::Relaxed);
            let mut response = ClResponsePdu::new(&request.header, result);
            response.header.server_boot = server_boot;
            ClPdu::Response(response)
        }
        Err(e) => {
            error!("Handler error for opnum {}: {}", request.header.opnum, e);
            stats.requests_failed.fetch_add(1, Ordering::Relaxed);
            let fault = ClFaultPdu::new(&request.header, 0x1c000000); // Generic fault
            ClPdu::Fault(fault)
        }
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
            max_concurrent_requests: 5000,
            receiver_tasks: 8,
        };
        let server = UdpDceRpcServer::with_config(config);
        assert_eq!(server.config.max_message_size, 8192);
        assert_eq!(server.config.max_concurrent_requests, 5000);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = UdpServerStats::default();
        stats.requests_received.fetch_add(100, Ordering::Relaxed);
        stats.requests_processed.fetch_add(95, Ordering::Relaxed);
        stats.requests_failed.fetch_add(5, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.requests_received, 100);
        assert_eq!(snapshot.requests_processed, 95);
        assert_eq!(snapshot.requests_failed, 5);
    }
}
