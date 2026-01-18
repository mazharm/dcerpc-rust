//! UDP transport for DCE RPC connectionless protocol
//!
//! UDP transports do not use Record Marking.
//! Each UDP datagram contains exactly one complete RPC message.
//! The maximum message size is limited by UDP datagram size.

use crate::error::{Result, RpcError};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Default maximum UDP message size (8KB is common for RPC)
pub const DEFAULT_MAX_UDP_SIZE: usize = 8 * 1024;

/// Maximum theoretical UDP payload size
pub const MAX_UDP_PAYLOAD: usize = 65507;

/// UDP transport for sending/receiving RPC messages
pub struct UdpTransport {
    socket: UdpSocket,
    max_message_size: usize,
    recv_buf: BytesMut,
}

impl UdpTransport {
    /// Create a new UDP transport from an existing socket
    pub fn new(socket: UdpSocket) -> Self {
        Self::with_max_size(socket, DEFAULT_MAX_UDP_SIZE)
    }

    /// Create a new UDP transport with custom max message size
    pub fn with_max_size(socket: UdpSocket, max_message_size: usize) -> Self {
        let max_size = max_message_size.min(MAX_UDP_PAYLOAD);
        Self {
            socket,
            max_message_size: max_size,
            recv_buf: BytesMut::with_capacity(max_size),
        }
    }

    /// Bind to a local address and create transport
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::new(socket))
    }

    /// Connect to a remote address (for client use)
    pub async fn connect(&self, addr: SocketAddr) -> Result<()> {
        self.socket.connect(addr).await?;
        Ok(())
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Get reference to the underlying socket
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Send a message to a specific address
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        if data.len() > self.max_message_size {
            return Err(RpcError::RecordTooLarge {
                size: data.len(),
                max: self.max_message_size,
            });
        }
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    /// Send a message on a connected socket
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > self.max_message_size {
            return Err(RpcError::RecordTooLarge {
                size: data.len(),
                max: self.max_message_size,
            });
        }
        self.socket.send(data).await?;
        Ok(())
    }

    /// Receive a message and return (data, sender address)
    pub async fn recv_from(&mut self) -> Result<(Bytes, SocketAddr)> {
        self.recv_buf.clear();
        self.recv_buf.resize(self.max_message_size, 0);

        let (len, addr) = self.socket.recv_from(&mut self.recv_buf).await?;
        self.recv_buf.truncate(len);

        Ok((self.recv_buf.clone().freeze(), addr))
    }

    /// Receive a message on a connected socket
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.recv_buf.clear();
        self.recv_buf.resize(self.max_message_size, 0);

        let len = self.socket.recv(&mut self.recv_buf).await?;
        self.recv_buf.truncate(len);

        Ok(self.recv_buf.clone().freeze())
    }

    /// Get the maximum message size
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Set the maximum message size
    pub fn set_max_message_size(&mut self, size: usize) {
        self.max_message_size = size.min(MAX_UDP_PAYLOAD);
        if self.recv_buf.capacity() < self.max_message_size {
            self.recv_buf
                .reserve(self.max_message_size - self.recv_buf.capacity());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_roundtrip() {
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let data = b"hello UDP";

        // Send from client to server
        client.send_to(data, server_addr).await.unwrap();

        // Receive on server
        let mut server = server;
        let (received, from_addr) = server.recv_from().await.unwrap();
        assert_eq!(received.as_ref(), data);
        assert_eq!(from_addr, client.local_addr().unwrap());
    }

    #[tokio::test]
    async fn test_udp_transport_connected() {
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        client.connect(server_addr).await.unwrap();

        let data = b"connected UDP";

        // Send using connected socket
        client.send(data).await.unwrap();

        // Receive on server
        let mut server = server;
        let (received, _) = server.recv_from().await.unwrap();
        assert_eq!(received.as_ref(), data);
    }

    #[tokio::test]
    async fn test_udp_max_size_enforcement() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Try to send oversized message
        let large_data = vec![0u8; DEFAULT_MAX_UDP_SIZE + 1000];
        let result = transport
            .send_to(&large_data, "127.0.0.1:12345".parse().unwrap())
            .await;

        assert!(matches!(result, Err(RpcError::RecordTooLarge { .. })));
    }
}
