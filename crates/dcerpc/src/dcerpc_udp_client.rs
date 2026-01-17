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
    new_activity_id, ClPdu, ClRequestPdu,
};
use crate::error::{Result, RpcError};
use crate::udp_transport::UdpTransport;
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

    /// Make an RPC call
    ///
    /// # Arguments
    /// * `opnum` - Operation number to call
    /// * `stub_data` - Marshalled arguments
    ///
    /// # Returns
    /// The response stub data on success
    pub async fn call(&mut self, opnum: u16, stub_data: Bytes) -> Result<Bytes> {
        let seqnum = self.seqnum_counter.fetch_add(1, Ordering::SeqCst);

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
