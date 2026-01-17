//! DCE RPC Client
//!
//! A client implementation for the DCE RPC protocol.

use crate::dcerpc::{BindPdu, ContextResult, Pdu, RequestPdu, SyntaxId, Uuid};
use crate::dcerpc_transport::DceRpcTransport;
use crate::error::{Result, RpcError};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace};

/// DCE RPC Client for making calls to a DCE RPC server
pub struct DceRpcClient {
    read_transport: Mutex<DceRpcTransport<ReadHalf<TcpStream>>>,
    write_transport: Mutex<DceRpcTransport<WriteHalf<TcpStream>>>,
    call_id_counter: AtomicU32,
    interface: SyntaxId,
    context_id: u16,
    max_xmit_frag: u16,
    max_recv_frag: u16,
    is_bound: bool,
}

impl DceRpcClient {
    /// Connect to a DCE RPC server and bind to the specified interface
    pub async fn connect(addr: SocketAddr, interface: SyntaxId) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut client = Self::from_stream(stream, interface);
        client.bind().await?;
        Ok(client)
    }

    /// Create a client from an existing TCP stream (unbound)
    pub fn from_stream(stream: TcpStream, interface: SyntaxId) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            read_transport: Mutex::new(DceRpcTransport::new(reader)),
            write_transport: Mutex::new(DceRpcTransport::new(writer)),
            call_id_counter: AtomicU32::new(1),
            interface,
            context_id: 0,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            is_bound: false,
        }
    }

    /// Perform the bind handshake with the server
    pub async fn bind(&mut self) -> Result<()> {
        let call_id = self.call_id_counter.fetch_add(1, Ordering::SeqCst);
        let bind = BindPdu::new(call_id, self.interface);

        debug!(
            "Sending bind request: call_id={}, interface={}",
            call_id, self.interface.uuid
        );

        // Send bind request
        {
            let mut write = self.write_transport.lock().await;
            write.write_pdu(&bind.encode()).await?;
        }

        // Read bind ack/nak
        let pdu = {
            let mut read = self.read_transport.lock().await;
            read.read_pdu_decoded().await?
        };

        match pdu {
            Pdu::BindAck(ack) => {
                if ack.header.call_id != call_id {
                    return Err(RpcError::XidMismatch {
                        expected: call_id,
                        got: ack.header.call_id,
                    });
                }

                // Check if binding was accepted
                if let Some((result, _syntax)) = ack.results.first() {
                    if *result != ContextResult::Acceptance {
                        return Err(RpcError::CallRejected("bind rejected".to_string()));
                    }
                } else {
                    return Err(RpcError::CallRejected("no bind result".to_string()));
                }

                self.max_xmit_frag = ack.max_xmit_frag;
                self.max_recv_frag = ack.max_recv_frag;
                self.is_bound = true;

                debug!(
                    "Bind successful: max_xmit={}, max_recv={}",
                    self.max_xmit_frag, self.max_recv_frag
                );

                Ok(())
            }
            Pdu::Fault(fault) => Err(RpcError::CallRejected(format!(
                "bind fault: status=0x{:08x}",
                fault.status
            ))),
            _ => Err(RpcError::InvalidMessageType(0)),
        }
    }

    /// Make an RPC call
    ///
    /// # Arguments
    /// * `opnum` - The operation number to call
    /// * `stub_data` - The marshalled arguments (in NDR format)
    ///
    /// # Returns
    /// The stub data from the response (in NDR format)
    pub async fn call(&self, opnum: u16, stub_data: Bytes) -> Result<Bytes> {
        if !self.is_bound {
            return Err(RpcError::CallRejected("not bound".to_string()));
        }

        let call_id = self.call_id_counter.fetch_add(1, Ordering::SeqCst);
        let mut request = RequestPdu::new(call_id, opnum, stub_data);
        request.context_id = self.context_id;

        debug!(
            "Sending request: call_id={}, opnum={}, stub_len={}",
            call_id,
            opnum,
            request.stub_data.len()
        );

        // Send request
        {
            let mut write = self.write_transport.lock().await;
            write.write_pdu(&request.encode()).await?;
        }

        // Read response
        let pdu = {
            let mut read = self.read_transport.lock().await;
            read.read_pdu_decoded().await?
        };

        match pdu {
            Pdu::Response(response) => {
                if response.header.call_id != call_id {
                    return Err(RpcError::XidMismatch {
                        expected: call_id,
                        got: response.header.call_id,
                    });
                }

                trace!("Call succeeded: {} bytes result", response.stub_data.len());

                Ok(response.stub_data)
            }
            Pdu::Fault(fault) => {
                if fault.header.call_id != call_id {
                    return Err(RpcError::XidMismatch {
                        expected: call_id,
                        got: fault.header.call_id,
                    });
                }

                Err(RpcError::CallRejected(format!(
                    "fault: status=0x{:08x}",
                    fault.status
                )))
            }
            _ => Err(RpcError::InvalidMessageType(0)),
        }
    }

    /// Call operation 0 (typically a null/ping operation)
    pub async fn null_call(&self) -> Result<()> {
        self.call(0, Bytes::new()).await?;
        Ok(())
    }

    /// Get the interface UUID this client is bound to
    pub fn interface(&self) -> &SyntaxId {
        &self.interface
    }

    /// Check if the client is bound to the server
    pub fn is_bound(&self) -> bool {
        self.is_bound
    }
}

/// Builder for DCE RPC clients
pub struct DceRpcClientBuilder {
    interface: SyntaxId,
    timeout: Option<Duration>,
    max_pdu_size: usize,
}

impl DceRpcClientBuilder {
    /// Create a builder for the specified interface
    pub fn new(interface_uuid: Uuid, major_version: u16, minor_version: u16) -> Self {
        Self {
            interface: SyntaxId::new(interface_uuid, major_version, minor_version),
            timeout: None,
            max_pdu_size: 65536,
        }
    }

    /// Create a builder from a SyntaxId
    pub fn from_syntax(interface: SyntaxId) -> Self {
        Self {
            interface,
            timeout: None,
            max_pdu_size: 65536,
        }
    }

    /// Set connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set maximum PDU size
    pub fn max_pdu_size(mut self, size: usize) -> Self {
        self.max_pdu_size = size;
        self
    }

    /// Connect to the server and perform bind
    pub async fn connect(self, addr: SocketAddr) -> Result<DceRpcClient> {
        let stream = match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| RpcError::Timeout)??,
            None => TcpStream::connect(addr).await?,
        };

        let (reader, writer) = tokio::io::split(stream);
        let mut client = DceRpcClient {
            read_transport: Mutex::new(
                DceRpcTransport::new(reader).with_max_pdu_size(self.max_pdu_size),
            ),
            write_transport: Mutex::new(DceRpcTransport::new(writer)),
            call_id_counter: AtomicU32::new(1),
            interface: self.interface,
            context_id: 0,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            is_bound: false,
        };

        client.bind().await?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
        let builder = DceRpcClientBuilder::new(uuid, 1, 0)
            .timeout(Duration::from_secs(30))
            .max_pdu_size(1024 * 1024);

        assert_eq!(builder.interface.major_version(), 1);
        assert_eq!(builder.interface.minor_version(), 0);
        assert_eq!(builder.timeout, Some(Duration::from_secs(30)));
    }
}
