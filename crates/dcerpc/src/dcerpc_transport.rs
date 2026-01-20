//! DCE RPC transport layer
//!
//! DCE RPC uses connection-oriented or connectionless transport.
//! For connection-oriented (TCP), PDUs are self-delimiting via the
//! frag_length field in the header.

use crate::dcerpc::{Pdu, PduHeader};
use crate::error::{Result, RpcError};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum PDU size (64 KB default, typical DCE RPC limit)
pub const DEFAULT_MAX_PDU_SIZE: usize = 65536;

/// DCE RPC transport for reading/writing PDUs over TCP
pub struct DceRpcTransport<T> {
    inner: T,
    max_pdu_size: usize,
    read_buf: BytesMut,
}

impl<T> DceRpcTransport<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            max_pdu_size: DEFAULT_MAX_PDU_SIZE,
            read_buf: BytesMut::with_capacity(8192),
        }
    }

    pub fn with_max_pdu_size(mut self, max_size: usize) -> Self {
        self.max_pdu_size = max_size;
        self
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + Unpin> DceRpcTransport<T> {
    /// Read a complete DCE RPC PDU
    pub async fn read_pdu(&mut self) -> Result<Bytes> {
        // First, read enough for the header (16 bytes)
        while self.read_buf.len() < PduHeader::SIZE {
            let n = self.fill_buf().await?;
            if n == 0 {
                if self.read_buf.is_empty() {
                    return Err(RpcError::ConnectionClosed);
                } else {
                    return Err(RpcError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "incomplete PDU header",
                    )));
                }
            }
        }

        // Parse header to get fragment length
        let header = PduHeader::decode(&self.read_buf)?;
        let frag_length = header.frag_length as usize;

        // Validate fragment length
        if frag_length < PduHeader::SIZE {
            return Err(RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid fragment length: {} < header size", frag_length),
            )));
        }

        if frag_length > self.max_pdu_size {
            return Err(RpcError::RecordTooLarge {
                size: frag_length,
                max: self.max_pdu_size,
            });
        }

        // Read the rest of the PDU
        while self.read_buf.len() < frag_length {
            let n = self.fill_buf().await?;
            if n == 0 {
                return Err(RpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "incomplete PDU: expected {} bytes, got {}",
                        frag_length,
                        self.read_buf.len()
                    ),
                )));
            }
        }

        // Extract the complete PDU
        let pdu_data = self.read_buf.split_to(frag_length);
        Ok(pdu_data.freeze())
    }

    /// Read and decode a complete PDU
    pub async fn read_pdu_decoded(&mut self) -> Result<Pdu> {
        let data = self.read_pdu().await?;
        Pdu::decode(&data)
    }

    async fn fill_buf(&mut self) -> Result<usize> {
        // Ensure buffer has capacity
        if self.read_buf.capacity() - self.read_buf.len() < 4096 {
            self.read_buf.reserve(8192);
        }

        let start_len = self.read_buf.len();
        let spare = self.read_buf.spare_capacity_mut();
        
        // Safety: spare_capacity_mut() returns uninitialized memory that is safe to write to.
        // We must ensure that:
        // 1. We only write up to spare.len() bytes
        // 2. We only mark as initialized the actual bytes written (n)
        // 3. n <= spare.len() is guaranteed by AsyncRead contract
        let buf =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        let n = self.inner.read(buf).await?;
        
        // Verify AsyncRead contract: n must not exceed buffer size
        debug_assert!(n <= spare.len(), "AsyncRead implementation returned more bytes than buffer size");
        
        if n > 0 {
            // Safety: We've verified n <= spare.len() above, and the bytes [start_len..start_len+n]
            // have been initialized by the read operation
            unsafe {
                self.read_buf.set_len(start_len + n);
            }
        }
        Ok(n)
    }
}

impl<T: AsyncWrite + Unpin> DceRpcTransport<T> {
    /// Write a complete DCE RPC PDU (already encoded)
    pub async fn write_pdu(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_all(data).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// Encode and write a PDU
    pub async fn write_pdu_encoded(&mut self, pdu: &Pdu) -> Result<()> {
        let data = pdu.encode();
        self.write_pdu(&data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcerpc::RequestPdu;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_pdu_roundtrip() {
        let (client, server) = duplex(1024);
        let mut client_transport = DceRpcTransport::new(client);
        let mut server_transport = DceRpcTransport::new(server);

        // Spawn writer task
        let write_handle = tokio::spawn(async move {
            let request = RequestPdu::new(1, 0, Bytes::from_static(b"hello"));
            client_transport.write_pdu(&request.encode()).await.unwrap();
        });

        // Read on server side
        let pdu_data = server_transport.read_pdu().await.unwrap();
        let pdu = Pdu::decode(&pdu_data).unwrap();

        match pdu {
            Pdu::Request(req) => {
                assert_eq!(req.header.call_id, 1);
                assert_eq!(req.opnum, 0);
                assert_eq!(req.stub_data.as_ref(), b"hello");
            }
            other => panic!("expected request PDU, got {:?}", other),
        }

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_pdus() {
        let (client, server) = duplex(4096);
        let mut client_transport = DceRpcTransport::new(client);
        let mut server_transport = DceRpcTransport::new(server);

        // Write multiple PDUs
        let write_handle = tokio::spawn(async move {
            for i in 0..3 {
                let request = RequestPdu::new(i, i as u16, Bytes::from(format!("msg{}", i)));
                client_transport.write_pdu(&request.encode()).await.unwrap();
            }
        });

        // Read multiple PDUs
        for i in 0..3 {
            let pdu = server_transport.read_pdu_decoded().await.unwrap();
            match pdu {
                Pdu::Request(req) => {
                    assert_eq!(req.header.call_id, i);
                    assert_eq!(req.opnum, i as u16);
                }
                other => panic!("expected request PDU, got {:?}", other),
            }
        }

        write_handle.await.unwrap();
    }
}
