//! IRemUnknown client implementation

use std::net::SocketAddr;
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use crate::types::{Result, DcomError, Ipid, StdObjRef};
use super::protocol::*;

/// IRemUnknown client
///
/// Client for the IRemUnknown interface for remote reference counting.
pub struct RemUnknownClient {
    client: DceRpcClient,
}

impl RemUnknownClient {
    /// Connect to a remote IRemUnknown endpoint
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let interface = SyntaxId::new(
            Uuid::parse(REMUNKNOWN_UUID).ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?,
            REMUNKNOWN_VERSION.0,
            REMUNKNOWN_VERSION.1,
        );

        let client = DceRpcClient::connect(addr, interface)
            .await
            .map_err(DcomError::Rpc)?;

        Ok(Self { client })
    }

    /// Query for additional interfaces on an object
    pub async fn query_interface(
        &self,
        ipid: Ipid,
        iids: Vec<dcerpc::Uuid>,
        refs: u32,
    ) -> Result<Vec<RemQiResult>> {
        let request = RemQueryInterfaceRequest::new(ipid, iids, refs);
        let response_bytes = self
            .client
            .call(opnum::QUERY_INTERFACE, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        let response = RemQueryInterfaceResponse::decode(&mut buf, true)?;

        if response.hresult != 0 {
            return Err(DcomError::RefCountError(format!(
                "QueryInterface failed: 0x{:08x}",
                response.hresult
            )));
        }

        Ok(response.results)
    }

    /// Add references to interfaces
    pub async fn add_ref(&self, refs: Vec<RemInterfaceRef>) -> Result<Vec<u32>> {
        let request = RemAddRefRequest::new(refs);
        let response_bytes = self
            .client
            .call(opnum::ADD_REF, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        // Parse minimal response
        let _ = crate::types::OrpcThat::decode(&mut buf, true)?;

        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let count = buf.get_u32_le();
        let mut results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if buf.remaining() < 4 {
                break;
            }
            results.push(buf.get_u32_le());
        }

        Ok(results)
    }

    /// Release references from interfaces
    pub async fn release(&self, refs: Vec<RemInterfaceRef>) -> Result<()> {
        let request = RemReleaseRequest::new(refs);
        let response_bytes = self
            .client
            .call(opnum::RELEASE, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        let _ = crate::types::OrpcThat::decode(&mut buf, true)?;

        if buf.remaining() >= 4 {
            let hresult = buf.get_u32_le();
            if hresult != 0 {
                return Err(DcomError::RefCountError(format!(
                    "Release failed: 0x{:08x}",
                    hresult
                )));
            }
        }

        Ok(())
    }

    /// Convenience method: query single interface
    pub async fn query_single_interface(
        &self,
        ipid: Ipid,
        iid: dcerpc::Uuid,
        refs: u32,
    ) -> Result<Option<StdObjRef>> {
        let results = self.query_interface(ipid, vec![iid], refs).await?;
        if let Some(result) = results.into_iter().next() {
            if result.hresult == 0 {
                Ok(result.std)
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Convenience method: add reference to single interface
    pub async fn add_single_ref(&self, ipid: Ipid, public_refs: u32) -> Result<u32> {
        let refs = vec![RemInterfaceRef::new(ipid, public_refs, 0)];
        let results = self.add_ref(refs).await?;
        Ok(results.into_iter().next().unwrap_or(0x80004005))
    }

    /// Convenience method: release reference from single interface
    pub async fn release_single_ref(&self, ipid: Ipid, public_refs: u32) -> Result<()> {
        let refs = vec![RemInterfaceRef::new(ipid, public_refs, 0)];
        self.release(refs).await
    }
}

use bytes::Buf;
