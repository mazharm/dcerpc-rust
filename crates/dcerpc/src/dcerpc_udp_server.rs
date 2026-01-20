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
//! - TTL-based fragment cache cleanup to prevent memory exhaustion
//!
//! # Key differences from connection-oriented (TCP) server:
//! - No bind/bind_ack handshake - requests handled directly
//! - Activity ID identifies clients instead of connections
//! - Sequence numbers track call ordering
//! - Server boot time helps clients detect server restarts

use crate::dcerpc::Uuid;
use crate::dcerpc_cl::{ClFaultPdu, ClPdu, ClPduHeader, ClRejectPdu, ClRequestPdu, ClResponsePdu, CL_HEADER_SIZE};
use crate::dcerpc_server::Interface;
use crate::error::Result;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    /// Maximum number of pending fragment assemblies (prevents memory exhaustion)
    pub max_fragment_assemblies: usize,
    /// Fragment assembly timeout (seconds) - assemblies older than this are cleaned up
    pub fragment_ttl_secs: u64,
}

impl Default for UdpDceRpcServerConfig {
    fn default() -> Self {
        Self {
            max_message_size: 4096,
            max_concurrent_requests: 10000,
            receiver_tasks: num_cpus(),
            max_fragment_assemblies: 10000,
            fragment_ttl_secs: 60,
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
    /// Number of fragment assemblies evicted due to cache limit
    pub fragments_evicted_limit: AtomicU64,
    /// Number of fragment assemblies evicted due to TTL expiry
    pub fragments_evicted_ttl: AtomicU64,
}

impl UdpServerStats {
    pub fn snapshot(&self) -> UdpServerStatsSnapshot {
        // Use Acquire ordering for consistent reads across all stats
        UdpServerStatsSnapshot {
            requests_received: self.requests_received.load(Ordering::Acquire),
            requests_processed: self.requests_processed.load(Ordering::Acquire),
            requests_rejected: self.requests_rejected.load(Ordering::Acquire),
            requests_failed: self.requests_failed.load(Ordering::Acquire),
            bytes_received: self.bytes_received.load(Ordering::Acquire),
            bytes_sent: self.bytes_sent.load(Ordering::Acquire),
            fragments_evicted_limit: self.fragments_evicted_limit.load(Ordering::Acquire),
            fragments_evicted_ttl: self.fragments_evicted_ttl.load(Ordering::Acquire),
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
    pub fragments_evicted_limit: u64,
    pub fragments_evicted_ttl: u64,
}

/// Key for identifying a fragmented request assembly
#[derive(Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    peer_addr: SocketAddr,
    activity_id: Uuid,
    seqnum: u32,
}

/// In-progress fragment assembly
struct FragmentAssembly {
    fragments: HashMap<u16, Bytes>,
    #[allow(dead_code)]
    opnum: u16,
    #[allow(dead_code)]
    if_id: Uuid,
    #[allow(dead_code)]
    if_vers: u32,
    header_template: ClPduHeader,
    received_last: bool,
    last_fragnum: u16,
    /// Timestamp when this assembly was created (for TTL cleanup)
    created_at: Instant,
}

impl FragmentAssembly {
    fn new(header: &ClPduHeader) -> Self {
        Self {
            fragments: HashMap::new(),
            opnum: header.opnum,
            if_id: header.if_id,
            if_vers: header.if_vers,
            header_template: header.clone(),
            received_last: false,
            last_fragnum: 0,
            created_at: Instant::now(),
        }
    }

    fn add_fragment(&mut self, fragnum: u16, body: Bytes, is_last: bool) {
        self.fragments.insert(fragnum, body);
        if is_last {
            self.received_last = true;
            self.last_fragnum = fragnum;
        }
    }

    fn is_complete(&self) -> bool {
        if !self.received_last {
            return false;
        }
        // Check we have all fragments from 0 to last_fragnum
        for i in 0..=self.last_fragnum {
            if !self.fragments.contains_key(&i) {
                return false;
            }
        }
        true
    }

    fn reassemble(&mut self) -> Bytes {
        let mut result = BytesMut::new();
        for i in 0..=self.last_fragnum {
            if let Some(body) = self.fragments.remove(&i) {
                result.extend_from_slice(&body);
            }
        }
        result.freeze()
    }
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
///
/// # Fragmentation
///
/// Large requests and responses are automatically fragmented and
/// reassembled using the CL fragmentation protocol.
pub struct UdpDceRpcServer {
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: UdpDceRpcServerConfig,
    /// Server boot time (seconds since epoch)
    server_boot: u32,
    /// Server statistics
    stats: Arc<UdpServerStats>,
    /// Fragment assembly cache for incoming fragmented requests
    fragment_cache: Arc<RwLock<HashMap<FragmentKey, FragmentAssembly>>>,
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
            fragment_cache: Arc::new(RwLock::new(HashMap::new())),
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
            fragment_cache: Arc::new(RwLock::new(HashMap::new())),
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

        // Spawn fragment cache cleanup task
        let cleanup_handle = self.spawn_fragment_cleanup_task();

        let result = self.receive_loop(socket, semaphore).await;

        // Abort cleanup task when server stops
        cleanup_handle.abort();

        result
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

        // Spawn fragment cache cleanup task
        let cleanup_handle = self.spawn_fragment_cleanup_task();

        tokio::pin!(shutdown);

        loop {
            let mut buf = vec![0u8; self.config.max_message_size];

            tokio::select! {
                biased;

                _ = &mut shutdown => {
                    info!("UDP server shutting down gracefully");
                    cleanup_handle.abort();
                    // Wait for pending requests to complete
                    let _ = semaphore.acquire_many(self.config.max_concurrent_requests as u32).await;
                    info!("All pending requests completed");
                    return Ok(());
                }

                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            self.stats.requests_received.fetch_add(1, Ordering::Release);
                            self.stats.bytes_received.fetch_add(len as u64, Ordering::Release);

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

    /// Spawn background task to cleanup expired fragment assemblies
    fn spawn_fragment_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let fragment_cache = Arc::clone(&self.fragment_cache);
        let stats = Arc::clone(&self.stats);
        let ttl = Duration::from_secs(self.config.fragment_ttl_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;

                let mut cache = fragment_cache.write().await;
                let now = Instant::now();
                let before_len = cache.len();

                cache.retain(|_key, assembly| {
                    now.duration_since(assembly.created_at) < ttl
                });

                let evicted = before_len - cache.len();
                if evicted > 0 {
                    stats.fragments_evicted_ttl.fetch_add(evicted as u64, Ordering::Release);
                    debug!("Cleaned up {} expired fragment assemblies", evicted);
                }
            }
        })
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
                    self.stats.requests_received.fetch_add(1, Ordering::Release);
                    self.stats.bytes_received.fetch_add(len as u64, Ordering::Release);

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
        let fragment_cache = Arc::clone(&self.fragment_cache);
        let max_message_size = self.config.max_message_size;
        let max_fragment_assemblies = self.config.max_fragment_assemblies;

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
            let responses = process_packet(
                &data,
                peer_addr,
                &interfaces,
                server_boot,
                &stats,
                &fragment_cache,
                max_message_size,
                max_fragment_assemblies,
            ).await;

            for response in responses {
                let response_len = response.len();
                if let Err(e) = socket.send_to(&response, peer_addr).await {
                    error!("Failed to send response to {}: {}", peer_addr, e);
                } else {
                    stats.bytes_sent.fetch_add(response_len as u64, Ordering::Release);
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

/// Process a single packet and return the response(s)
///
/// Returns a Vec of response packets. For fragmented responses,
/// multiple packets are returned.
async fn process_packet(
    data: &[u8],
    peer_addr: SocketAddr,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    server_boot: u32,
    stats: &Arc<UdpServerStats>,
    fragment_cache: &Arc<RwLock<HashMap<FragmentKey, FragmentAssembly>>>,
    max_message_size: usize,
    max_fragment_assemblies: usize,
) -> Vec<Bytes> {
    // Decode the PDU
    let pdu = match ClPdu::decode(data) {
        Ok(pdu) => pdu,
        Err(e) => {
            error!("Failed to decode CL PDU from {}: {}", peer_addr, e);
            stats.requests_failed.fetch_add(1, Ordering::Release);
            return vec![];
        }
    };

    match pdu {
        ClPdu::Request(request) => {
            let is_frag = request.header.flags1.is_frag();
            let is_lastfrag = request.header.flags1.is_lastfrag();
            let fragnum = request.header.fragnum;

            trace!(
                "Received CL request from {}: seqnum={}, opnum={}, if={}, body_len={}, fragnum={}, frag={}, lastfrag={}",
                peer_addr,
                request.header.seqnum,
                request.header.opnum,
                request.header.if_id,
                request.body.len(),
                fragnum,
                is_frag,
                is_lastfrag
            );

            // Check if this is a non-fragmented request
            if !is_frag && is_lastfrag && fragnum == 0 {
                // Single request - process immediately
                let response = process_request(&request, peer_addr, interfaces, server_boot, stats).await;
                return fragment_response(response, max_message_size);
            }

            // Handle fragmented request
            let key = FragmentKey {
                peer_addr,
                activity_id: request.header.act_id,
                seqnum: request.header.seqnum,
            };

            let complete_body = {
                let mut cache = fragment_cache.write().await;

                // Check if we're at the cache limit and this is a new assembly
                if !cache.contains_key(&key) && cache.len() >= max_fragment_assemblies {
                    // Evict oldest entry to make room
                    if let Some(oldest_key) = cache
                        .iter()
                        .min_by_key(|(_, v)| v.created_at)
                        .map(|(k, _)| k.clone())
                    {
                        cache.remove(&oldest_key);
                        stats.fragments_evicted_limit.fetch_add(1, Ordering::Release);
                        warn!(
                            "Fragment cache limit reached ({}), evicted oldest assembly",
                            max_fragment_assemblies
                        );
                    }
                }

                // Get or create assembly
                let assembly = cache.entry(key.clone()).or_insert_with(|| {
                    FragmentAssembly::new(&request.header)
                });

                assembly.add_fragment(fragnum, request.body.clone(), is_lastfrag);

                if assembly.is_complete() {
                    let body = assembly.reassemble();
                    let header = assembly.header_template.clone();
                    cache.remove(&key);
                    Some((body, header))
                } else {
                    None
                }
            };

            if let Some((body, header)) = complete_body {
                debug!(
                    "Reassembled CL request from {}: seqnum={}, total_body_len={}",
                    peer_addr, header.seqnum, body.len()
                );

                // Create a complete request from reassembled data
                let complete_request = ClRequestPdu {
                    header,
                    body,
                };

                let response = process_request(&complete_request, peer_addr, interfaces, server_boot, stats).await;
                return fragment_response(response, max_message_size);
            }

            // Still waiting for more fragments
            vec![]
        }

        ClPdu::Ping(ping) => {
            // Check if we have a pending fragment assembly for this call
            let key = FragmentKey {
                peer_addr,
                activity_id: ping.header.act_id,
                seqnum: ping.header.seqnum,
            };

            let has_pending = {
                let cache = fragment_cache.read().await;
                cache.contains_key(&key)
            };

            if has_pending {
                // We're still assembling fragments, send working
                debug!(
                    "Received CL ping from {} for pending assembly: seqnum={}",
                    peer_addr, ping.header.seqnum
                );
                let working = crate::dcerpc_cl::ClWorkingPdu::new(&ping.header);
                vec![working.encode()]
            } else {
                // No pending call
                debug!(
                    "Received CL ping from {}: seqnum={}",
                    peer_addr, ping.header.seqnum
                );
                let nocall = crate::dcerpc_cl::ClNocallPdu::new(&ping.header);
                vec![nocall.encode()]
            }
        }

        ClPdu::Ack(_) => {
            // Client acknowledging our response, nothing to do
            trace!("Received CL ack from {}", peer_addr);
            vec![]
        }

        _ => {
            warn!(
                "Received unexpected CL packet type from {}: {:?}",
                peer_addr,
                pdu.header().ptype
            );
            vec![]
        }
    }
}

/// Fragment a response PDU if it exceeds the max message size
fn fragment_response(response: ClPdu, max_message_size: usize) -> Vec<Bytes> {
    let max_body = max_message_size.saturating_sub(CL_HEADER_SIZE);

    match response {
        ClPdu::Response(resp) => {
            if resp.body.len() <= max_body {
                // Single response
                vec![resp.encode()]
            } else {
                // Fragment the response
                let total_len = resp.body.len();
                let num_fragments = (total_len + max_body - 1) / max_body;

                debug!(
                    "Fragmenting CL response: seqnum={}, total_body_len={}, num_fragments={}",
                    resp.header.seqnum, total_len, num_fragments
                );

                let mut responses = Vec::with_capacity(num_fragments);

                for fragnum in 0..num_fragments {
                    let offset = fragnum * max_body;
                    let end = (offset + max_body).min(total_len);
                    let chunk = resp.body.slice(offset..end);
                    let is_last = fragnum == num_fragments - 1;

                    let mut header = resp.header.clone();
                    header.fragnum = fragnum as u16;
                    header.len = chunk.len() as u16;

                    // Set fragment flags
                    if fragnum > 0 {
                        header.flags1.set_frag();
                    }
                    if is_last {
                        header.flags1.set_lastfrag();
                    }

                    let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + chunk.len());
                    header.encode(&mut buf);
                    buf.extend_from_slice(&chunk);

                    responses.push(buf.freeze());
                }

                responses
            }
        }
        // Faults and rejects are never fragmented
        other => vec![other.encode()],
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
            stats.requests_rejected.fetch_add(1, Ordering::Release);
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
        stats.requests_rejected.fetch_add(1, Ordering::Release);
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
            stats.requests_rejected.fetch_add(1, Ordering::Release);
            let fault = ClFaultPdu::new(&request.header, 0x1c010002); // nca_s_op_rng_error
            return ClPdu::Fault(fault);
        }
    };

    // Release the lock before calling the handler
    drop(interfaces_guard);

    // Call the handler
    match handler(request.body.clone()).await {
        Ok(result) => {
            stats.requests_processed.fetch_add(1, Ordering::Release);
            let mut response = ClResponsePdu::new(&request.header, result);
            response.header.server_boot = server_boot;
            ClPdu::Response(response)
        }
        Err(e) => {
            error!("Handler error for opnum {}: {}", request.header.opnum, e);
            stats.requests_failed.fetch_add(1, Ordering::Release);
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
            max_fragment_assemblies: 5000,
            fragment_ttl_secs: 30,
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
