//! DCE RPC UDP Client (Connectionless Protocol)
//!
//! A client implementation for the DCE RPC connectionless protocol over UDP.
//! Uses the 80-byte connectionless PDU header format (RPC version 4).
//!
//! Key differences from connection-oriented (TCP) client:
//! - No bind/bind_ack handshake - requests sent directly
//! - Activity ID identifies the call instead of call ID
//! - Sequence numbers track call ordering
//! - Automatic retransmission on timeout

use crate::dcerpc::Uuid;
use crate::dcerpc_cl::{
    new_activity_id, ClPdu, ClPduHeader, ClRequestPdu, CL_HEADER_SIZE,
};
use crate::error::{Result, RpcError};
use crate::udp_transport::UdpTransport;
use bytes::BytesMut;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Default timeout for UDP DCE RPC calls
pub const DEFAULT_DCE_UDP_TIMEOUT: Duration = Duration::from_secs(5);

/// Default number of retries for UDP DCE RPC calls
pub const DEFAULT_DCE_UDP_RETRIES: u32 = 3;

/// UDP DCE RPC Client (Connectionless)
///
/// This client uses the DCE RPC connectionless (datagram) protocol,
/// which has an 80-byte header and uses RPC version 4.
pub struct UdpDceRpcClient {
    transport: UdpTransport,
    server_addr: SocketAddr,
    /// Interface UUID
    interface_id: Uuid,
    /// Interface version (major in lower 16 bits, minor in upper 16 bits)
    interface_version: u32,
    /// Activity ID for this client session
    activity_id: Uuid,
    /// Sequence number counter
    seqnum_counter: AtomicU32,
    /// Serial number counter (for retransmissions)
    /// Reserved for future retransmission tracking
    #[allow(dead_code)]
    serial_counter: AtomicU32,
    /// Server boot time (learned from responses)
    /// Reserved for future server restart detection
    #[allow(dead_code)]
    server_boot: u32,
    /// Call timeout
    timeout: Duration,
    /// Number of retries
    retries: u32,
}

impl UdpDceRpcClient {
    /// Connect to a DCE RPC server over UDP
    ///
    /// Note: In the connectionless protocol, there is no bind handshake.
    /// The client simply sends requests and the server responds.
    pub async fn connect(server_addr: SocketAddr, interface_id: Uuid, version: u32) -> Result<Self> {
        // Bind to any available port
        let transport = UdpTransport::bind("0.0.0.0:0".parse().unwrap()).await?;

        Ok(Self {
            transport,
            server_addr,
            interface_id,
            interface_version: version,
            activity_id: new_activity_id(),
            seqnum_counter: AtomicU32::new(0),
            serial_counter: AtomicU32::new(0),
            server_boot: 0,
            timeout: DEFAULT_DCE_UDP_TIMEOUT,
            retries: DEFAULT_DCE_UDP_RETRIES,
        })
    }

    /// Create a client from an existing transport
    pub fn from_transport(
        transport: UdpTransport,
        server_addr: SocketAddr,
        interface_id: Uuid,
        version: u32,
    ) -> Self {
        Self {
            transport,
            server_addr,
            interface_id,
            interface_version: version,
            activity_id: new_activity_id(),
            seqnum_counter: AtomicU32::new(0),
            serial_counter: AtomicU32::new(0),
            server_boot: 0,
            timeout: DEFAULT_DCE_UDP_TIMEOUT,
            retries: DEFAULT_DCE_UDP_RETRIES,
        }
    }

    /// Set the timeout for RPC calls
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set the number of retries for RPC calls
    pub fn set_retries(&mut self, retries: u32) {
        self.retries = retries;
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.transport.local_addr()
    }

    /// Get the interface UUID
    pub fn interface_id(&self) -> Uuid {
        self.interface_id
    }

    /// Get the activity ID
    pub fn activity_id(&self) -> Uuid {
        self.activity_id
    }

    /// Calculate maximum body size per fragment
    fn max_body_size(&self) -> usize {
        self.transport.max_message_size().saturating_sub(CL_HEADER_SIZE)
    }

    /// Make an RPC call
    ///
    /// # Arguments
    /// * `opnum` - Operation number to call
    /// * `stub_data` - Marshalled arguments
    ///
    /// # Returns
    /// The response stub data on success
    ///
    /// # Fragmentation
    /// If the stub data exceeds the maximum UDP message size,
    /// the request is automatically split into multiple fragments
    /// using the CL fragmentation protocol.
    pub async fn call(&mut self, opnum: u16, stub_data: Bytes) -> Result<Bytes> {
        let seqnum = self.seqnum_counter.fetch_add(1, Ordering::SeqCst);
        let max_body = self.max_body_size();

        // Check if we need to fragment
        if stub_data.len() > max_body {
            debug!(
                "Fragmenting CL request: seqnum={}, opnum={}, body_len={}, max_body={}",
                seqnum, opnum, stub_data.len(), max_body
            );
            self.send_fragmented_request(seqnum, opnum, stub_data).await
        } else {
            self.send_single_request(seqnum, opnum, stub_data).await
        }
    }

    /// Send a single (non-fragmented) request
    async fn send_single_request(
        &mut self,
        seqnum: u32,
        opnum: u16,
        stub_data: Bytes,
    ) -> Result<Bytes> {
        // Create the request PDU
        let request = ClRequestPdu::new(
            self.interface_id,
            self.interface_version,
            self.activity_id,
            seqnum,
            opnum,
            stub_data,
        );

        let encoded = request.encode();

        // Check message size
        if encoded.len() > self.transport.max_message_size() {
            return Err(RpcError::RecordTooLarge {
                size: encoded.len(),
                max: self.transport.max_message_size(),
            });
        }

        debug!(
            "Sending CL request: seqnum={}, opnum={}, body_len={}",
            seqnum, opnum, request.body.len()
        );

        // Try with retransmissions
        let mut last_error = RpcError::Timeout;

        for attempt in 0..=self.retries {
            if attempt > 0 {
                debug!(
                    "Retransmitting request seqnum={}, attempt {}",
                    seqnum, attempt
                );
            }

            // Send the request
            self.transport.send_to(&encoded, self.server_addr).await?;

            // Wait for response with timeout
            match timeout(self.timeout, self.receive_response(seqnum)).await {
                Ok(Ok(response)) => {
                    trace!("CL call succeeded: {} bytes response", response.len());
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    // Got a response but it was an error (fault/reject)
                    return Err(e);
                }
                Err(_) => {
                    // Timeout
                    warn!("Timeout waiting for response seqnum={}", seqnum);
                    last_error = RpcError::Timeout;
                }
            }
        }

        Err(last_error)
    }

    /// Send a fragmented request
    async fn send_fragmented_request(
        &mut self,
        seqnum: u32,
        opnum: u16,
        stub_data: Bytes,
    ) -> Result<Bytes> {
        let max_body = self.max_body_size();
        let total_len = stub_data.len();
        let num_fragments = (total_len + max_body - 1) / max_body;

        debug!(
            "Sending {} CL fragments: seqnum={}, opnum={}, total_len={}",
            num_fragments, seqnum, opnum, total_len
        );

        // Send all fragments
        for fragnum in 0..num_fragments {
            let offset = fragnum * max_body;
            let end = (offset + max_body).min(total_len);
            let chunk = stub_data.slice(offset..end);
            let is_last = fragnum == num_fragments - 1;

            // Create fragment header
            let mut header = ClPduHeader::new_request(
                self.interface_id,
                self.interface_version,
                self.activity_id,
                seqnum,
                opnum,
            );
            header.fragnum = fragnum as u16;
            header.len = chunk.len() as u16;

            // Set fragment flags
            // FRAG flag: set on fragments after the first
            // LASTFRAG flag: set on the last fragment
            if fragnum > 0 {
                header.flags1.set_frag();
            }
            if is_last {
                header.flags1.set_lastfrag();
            }

            // Encode and send
            let mut buf = BytesMut::with_capacity(CL_HEADER_SIZE + chunk.len());
            header.encode(&mut buf);
            buf.extend_from_slice(&chunk);

            trace!(
                "Sending CL fragment {}/{}: fragnum={}, body_len={}, frag={}, lastfrag={}",
                fragnum + 1,
                num_fragments,
                header.fragnum,
                chunk.len(),
                header.flags1.is_frag(),
                header.flags1.is_lastfrag()
            );

            self.transport.send_to(&buf.freeze(), self.server_addr).await?;
        }

        // Receive fragmented response
        self.receive_fragmented_response(seqnum).await
    }

    /// Receive a potentially fragmented response
    async fn receive_fragmented_response(&mut self, expected_seqnum: u32) -> Result<Bytes> {
        let mut fragments: Vec<(u16, Bytes)> = Vec::new();
        let mut last_error = RpcError::Timeout;

        for attempt in 0..=self.retries {
            if attempt > 0 {
                debug!(
                    "Retrying fragmented response seqnum={}, attempt {}",
                    expected_seqnum, attempt
                );
            }

            match timeout(self.timeout, self.receive_fragment_loop(expected_seqnum, &mut fragments)).await {
                Ok(Ok(complete)) => {
                    return Ok(complete);
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Err(_) => {
                    warn!(
                        "Timeout waiting for response fragments seqnum={}, received {}",
                        expected_seqnum,
                        fragments.len()
                    );
                    last_error = RpcError::FragmentTimeout { received: fragments.len() };
                }
            }
        }

        Err(last_error)
    }

    /// Internal loop to receive response fragments
    async fn receive_fragment_loop(
        &mut self,
        expected_seqnum: u32,
        fragments: &mut Vec<(u16, Bytes)>,
    ) -> Result<Bytes> {
        loop {
            let (data, from_addr) = self.transport.recv_from().await?;

            // Verify it's from the server
            if from_addr != self.server_addr {
                trace!("Ignoring packet from unexpected source: {}", from_addr);
                continue;
            }

            // Decode the PDU
            let pdu = match ClPdu::decode(&data) {
                Ok(pdu) => pdu,
                Err(e) => {
                    warn!("Failed to decode CL PDU: {}", e);
                    continue;
                }
            };

            let header = pdu.header();
            let act_id = header.act_id;
            let seqnum = header.seqnum;

            // Verify activity ID matches
            if act_id != self.activity_id {
                trace!("Ignoring packet with wrong activity ID");
                continue;
            }

            // Verify sequence number matches
            if seqnum != expected_seqnum {
                trace!(
                    "Ignoring packet with wrong seqnum: expected {}, got {}",
                    expected_seqnum, seqnum
                );
                continue;
            }

            // Process by type
            match pdu {
                ClPdu::Response(response) => {
                    let fragnum = response.header.fragnum;
                    let is_frag = response.header.flags1.is_frag();
                    let is_lastfrag = response.header.flags1.is_lastfrag();

                    debug!(
                        "Received CL response fragment: seqnum={}, fragnum={}, body_len={}, frag={}, lastfrag={}",
                        seqnum, fragnum, response.body.len(), is_frag, is_lastfrag
                    );

                    // Check if this is a single (non-fragmented) response
                    if !is_frag && is_lastfrag && fragnum == 0 {
                        return Ok(response.body);
                    }

                    // Store fragment
                    fragments.push((fragnum, response.body));

                    // Check if we have all fragments
                    if is_lastfrag {
                        // Sort by fragnum and reassemble
                        fragments.sort_by_key(|(num, _)| *num);

                        let mut complete = BytesMut::new();
                        for (_, body) in fragments.drain(..) {
                            complete.extend_from_slice(&body);
                        }

                        trace!(
                            "Reassembled CL response: {} bytes from {} fragments",
                            complete.len(),
                            fragments.len() + 1
                        );

                        return Ok(complete.freeze());
                    }
                }
                ClPdu::Fault(fault) => {
                    debug!(
                        "Received CL fault: seqnum={}, status=0x{:08x}",
                        seqnum, fault.status
                    );
                    return Err(RpcError::CallRejected(format!(
                        "fault: status=0x{:08x}",
                        fault.status
                    )));
                }
                ClPdu::Reject(reject) => {
                    debug!(
                        "Received CL reject: seqnum={}, status=0x{:08x}",
                        seqnum, reject.status
                    );
                    return Err(RpcError::CallRejected(format!(
                        "reject: status=0x{:08x}",
                        reject.status
                    )));
                }
                ClPdu::Working(_) => {
                    debug!("Received CL working: seqnum={}", seqnum);
                    continue;
                }
                ClPdu::Nocall(_) => {
                    debug!("Received CL nocall: seqnum={}", seqnum);
                    return Err(RpcError::CallRejected("nocall: server has no record of call".to_string()));
                }
                _ => {
                    trace!("Ignoring unexpected packet type");
                    continue;
                }
            }
        }
    }

    /// Receive and process a response
    async fn receive_response(&mut self, expected_seqnum: u32) -> Result<Bytes> {
        loop {
            let (data, from_addr) = self.transport.recv_from().await?;

            // Verify it's from the server
            if from_addr != self.server_addr {
                trace!("Ignoring packet from unexpected source: {}", from_addr);
                continue;
            }

            // Decode the PDU
            let pdu = match ClPdu::decode(&data) {
                Ok(pdu) => pdu,
                Err(e) => {
                    warn!("Failed to decode CL PDU: {}", e);
                    continue;
                }
            };

            // Get header info before consuming pdu
            let header = pdu.header();
            let act_id = header.act_id;
            let seqnum = header.seqnum;
            let ptype = header.ptype;

            // Verify activity ID matches
            if act_id != self.activity_id {
                trace!("Ignoring packet with wrong activity ID");
                continue;
            }

            // Verify sequence number matches
            if seqnum != expected_seqnum {
                trace!(
                    "Ignoring packet with wrong seqnum: expected {}, got {}",
                    expected_seqnum, seqnum
                );
                continue;
            }

            // Process by type
            match pdu {
                ClPdu::Response(response) => {
                    debug!(
                        "Received CL response: seqnum={}, body_len={}",
                        seqnum, response.body.len()
                    );
                    return Ok(response.body);
                }
                ClPdu::Fault(fault) => {
                    debug!(
                        "Received CL fault: seqnum={}, status=0x{:08x}",
                        seqnum, fault.status
                    );
                    return Err(RpcError::CallRejected(format!(
                        "fault: status=0x{:08x}",
                        fault.status
                    )));
                }
                ClPdu::Reject(reject) => {
                    debug!(
                        "Received CL reject: seqnum={}, status=0x{:08x}",
                        seqnum, reject.status
                    );
                    return Err(RpcError::CallRejected(format!(
                        "reject: status=0x{:08x}",
                        reject.status
                    )));
                }
                ClPdu::Working(_) => {
                    // Server is still processing, continue waiting
                    debug!("Received CL working: seqnum={}", seqnum);
                    continue;
                }
                ClPdu::Nocall(_) => {
                    // Server doesn't know about this call
                    debug!("Received CL nocall: seqnum={}", seqnum);
                    return Err(RpcError::CallRejected("nocall: server has no record of call".to_string()));
                }
                _ => {
                    trace!("Ignoring unexpected packet type: {:?}", ptype);
                    continue;
                }
            }
        }
    }

    /// Call operation 0 (typically a null/ping operation)
    pub async fn null_call(&mut self) -> Result<()> {
        self.call(0, Bytes::new()).await?;
        Ok(())
    }
}

/// Builder for UdpDceRpcClient
pub struct UdpDceRpcClientBuilder {
    server_addr: SocketAddr,
    interface_id: Uuid,
    interface_version: u32,
    timeout: Duration,
    retries: u32,
}

impl UdpDceRpcClientBuilder {
    pub fn new(server_addr: SocketAddr, interface_id: Uuid, version: u32) -> Self {
        Self {
            server_addr,
            interface_id,
            interface_version: version,
            timeout: DEFAULT_DCE_UDP_TIMEOUT,
            retries: DEFAULT_DCE_UDP_RETRIES,
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub async fn build(self) -> Result<UdpDceRpcClient> {
        let mut client = UdpDceRpcClient::connect(
            self.server_addr,
            self.interface_id,
            self.interface_version,
        ).await?;
        client.set_timeout(self.timeout);
        client.set_retries(self.retries);
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let builder = UdpDceRpcClientBuilder::new(
            "127.0.0.1:135".parse().unwrap(),
            Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap(),
            1,
        )
        .timeout(Duration::from_secs(10))
        .retries(5);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert_eq!(builder.retries, 5);
    }
}
