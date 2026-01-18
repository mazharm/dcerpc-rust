//! OXID resolver client implementation

use std::net::SocketAddr;
use bytes::Bytes;
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use crate::types::{Result, DcomError, Oxid, SetId, Oid};
use super::protocol::*;

/// OXID Resolver client
///
/// Client for the IObjectExporter interface on port 135.
pub struct OxidResolverClient {
    client: DceRpcClient,
}

impl OxidResolverClient {
    /// Connect to an OXID resolver
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let interface = SyntaxId::new(
            Uuid::parse(OBJECT_EXPORTER_UUID).ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?,
            OBJECT_EXPORTER_VERSION.0,
            OBJECT_EXPORTER_VERSION.1,
        );

        let client = DceRpcClient::connect(addr, interface)
            .await
            .map_err(DcomError::Rpc)?;

        Ok(Self { client })
    }

    /// Resolve an OXID to get binding information
    pub async fn resolve_oxid(&self, oxid: Oxid, protseqs: Vec<u16>) -> Result<ResolveOxidResponse> {
        let request = ResolveOxidRequest::new(oxid, protseqs);
        let response_bytes = self
            .client
            .call(opnum::RESOLVE_OXID, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        ResolveOxidResponse::decode(&mut buf, true)
    }

    /// Resolve an OXID with version 2 (includes COM version)
    pub async fn resolve_oxid2(
        &self,
        oxid: Oxid,
        protseqs: Vec<u16>,
    ) -> Result<ResolveOxid2Response> {
        let request = ResolveOxid2Request::new(oxid, protseqs);
        let response_bytes = self
            .client
            .call(opnum::RESOLVE_OXID2, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        ResolveOxid2Response::decode(&mut buf, true)
    }

    /// Send a simple ping to keep a ping set alive
    pub async fn simple_ping(&self, set_id: SetId) -> Result<u32> {
        let request = SimplePingRequest::new(set_id);
        let response_bytes = self
            .client
            .call(opnum::SIMPLE_PING, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        let response = SimplePingResponse::decode(&mut buf, true)?;
        Ok(response.status)
    }

    /// Send a complex ping to modify a ping set
    pub async fn complex_ping(
        &self,
        set_id: SetId,
        sequence_num: u16,
        add_oids: Vec<Oid>,
        del_oids: Vec<Oid>,
    ) -> Result<ComplexPingResponse> {
        let request = ComplexPingRequest::new(set_id, sequence_num, add_oids, del_oids);
        let response_bytes = self
            .client
            .call(opnum::COMPLEX_PING, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        ComplexPingResponse::decode(&mut buf, true)
    }

    /// Check if the server is alive
    pub async fn server_alive(&self) -> Result<bool> {
        let response_bytes = self
            .client
            .call(opnum::SERVER_ALIVE, Bytes::new())
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        let response = SimplePingResponse::decode(&mut buf, true)?;
        Ok(response.status == 0)
    }

    /// Check if the server is alive (version 2, includes bindings)
    pub async fn server_alive2(&self) -> Result<ServerAlive2Response> {
        let response_bytes = self
            .client
            .call(opnum::SERVER_ALIVE2, Bytes::new())
            .await
            .map_err(DcomError::Rpc)?;

        let mut buf = response_bytes;
        ServerAlive2Response::decode(&mut buf, true)
    }
}

/// Ping set manager for keeping remote objects alive
pub struct PingSetManager {
    /// Client for sending pings
    client: OxidResolverClient,
    /// Current set ID
    set_id: SetId,
    /// Sequence number for complex pings
    sequence_num: u16,
}

impl PingSetManager {
    /// Create a new ping set manager
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let client = OxidResolverClient::connect(addr).await?;
        Ok(Self {
            client,
            set_id: SetId::default(),
            sequence_num: 0,
        })
    }

    /// Add OIDs to the ping set
    pub async fn add_oids(&mut self, oids: Vec<Oid>) -> Result<()> {
        self.sequence_num = self.sequence_num.wrapping_add(1);
        let response = self
            .client
            .complex_ping(self.set_id, self.sequence_num, oids, vec![])
            .await?;

        if response.status == 0 {
            self.set_id = response.set_id;
            Ok(())
        } else {
            Err(DcomError::RefCountError(format!(
                "ComplexPing failed with status 0x{:08x}",
                response.status
            )))
        }
    }

    /// Remove OIDs from the ping set
    pub async fn remove_oids(&mut self, oids: Vec<Oid>) -> Result<()> {
        self.sequence_num = self.sequence_num.wrapping_add(1);
        let response = self
            .client
            .complex_ping(self.set_id, self.sequence_num, vec![], oids)
            .await?;

        if response.status == 0 {
            Ok(())
        } else {
            Err(DcomError::RefCountError(format!(
                "ComplexPing failed with status 0x{:08x}",
                response.status
            )))
        }
    }

    /// Send a simple ping to keep the set alive
    pub async fn ping(&self) -> Result<()> {
        let status = self.client.simple_ping(self.set_id).await?;
        if status == 0 {
            Ok(())
        } else {
            Err(DcomError::PingTimeout(self.set_id.0))
        }
    }

    /// Get the current set ID
    pub fn set_id(&self) -> SetId {
        self.set_id
    }
}
