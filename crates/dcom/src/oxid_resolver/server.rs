//! OXID resolver server implementation

use std::sync::Arc;
use bytes::Bytes;
use dcerpc::{DceRpcServer, InterfaceBuilder};
use crate::types::{Result, DcomError, SetId, DualStringArray, ComVersion, Ipid};
use crate::exporter::ObjectExporter;
use super::protocol::*;

/// OXID Resolver server
///
/// Implements the IObjectExporter interface on port 135.
pub struct OxidResolverServer {
    /// Reference to the object exporter
    exporter: Arc<ObjectExporter>,
    /// Server bindings (addresses clients can use to connect)
    bindings: DualStringArray,
}

impl OxidResolverServer {
    /// Create a new OXID resolver server
    pub fn new(exporter: Arc<ObjectExporter>, bindings: DualStringArray) -> Self {
        Self { exporter, bindings }
    }

    /// Build the DCE RPC interface for the OXID resolver
    pub fn build_interface(&self) -> Result<dcerpc::Interface> {
        let exporter = self.exporter.clone();
        let bindings = self.bindings.clone();
        let bindings2 = self.bindings.clone();
        let exporter2 = self.exporter.clone();
        let exporter3 = self.exporter.clone();
        let exporter4 = self.exporter.clone();
        let bindings3 = self.bindings.clone();

        let interface = InterfaceBuilder::new(
            OBJECT_EXPORTER_UUID,
            OBJECT_EXPORTER_VERSION.0,
            OBJECT_EXPORTER_VERSION.1,
        )
        .ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?
        .operation(opnum::RESOLVE_OXID, move |args: Bytes| {
            let exporter = exporter.clone();
            let bindings = bindings.clone();
            async move {
                Self::handle_resolve_oxid(&exporter, &bindings, args)
            }
        })
        .operation(opnum::SIMPLE_PING, move |args: Bytes| {
            let exporter = exporter2.clone();
            async move {
                Self::handle_simple_ping(&exporter, args)
            }
        })
        .operation(opnum::COMPLEX_PING, move |args: Bytes| {
            let exporter = exporter3.clone();
            async move {
                Self::handle_complex_ping(&exporter, args)
            }
        })
        .operation(opnum::SERVER_ALIVE, move |_args: Bytes| {
            async move {
                Self::handle_server_alive()
            }
        })
        .operation(opnum::RESOLVE_OXID2, move |args: Bytes| {
            let exporter = exporter4.clone();
            let bindings = bindings2.clone();
            async move {
                Self::handle_resolve_oxid2(&exporter, &bindings, args)
            }
        })
        .operation(opnum::SERVER_ALIVE2, move |_args: Bytes| {
            let bindings = bindings3.clone();
            async move {
                Self::handle_server_alive2(&bindings)
            }
        })
        .build();

        Ok(interface)
    }

    /// Handle ResolveOxid request
    fn handle_resolve_oxid(
        exporter: &ObjectExporter,
        bindings: &DualStringArray,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = ResolveOxidRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        // Look up the OXID in our exporter
        let ipid = exporter.get_remunknown_ipid(&request.oxid);

        let response = ResolveOxidResponse {
            oxid_bindings: bindings.clone(),
            ipid_rem_unknown: ipid.unwrap_or_else(Ipid::nil),
            authn_hint: 0,
            status: if ipid.is_some() { 0 } else { 0x80070057 }, // E_INVALIDARG
        };

        Ok(response.encode(true))
    }

    /// Handle SimplePing request
    fn handle_simple_ping(exporter: &ObjectExporter, args: Bytes) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = SimplePingRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        let status = match exporter.simple_ping(request.set_id) {
            Ok(()) => 0,
            Err(_) => 0x80070057, // E_INVALIDARG
        };

        let response = SimplePingResponse { status };
        Ok(response.encode(true))
    }

    /// Handle ComplexPing request
    fn handle_complex_ping(exporter: &ObjectExporter, args: Bytes) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = ComplexPingRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        let (set_id, status) = match exporter.complex_ping(
            request.set_id,
            request.sequence_num,
            &request.add_oids,
            &request.del_oids,
        ) {
            Ok(set_id) => (set_id, 0),
            Err(_) => (SetId::default(), 0x80070057),
        };

        let response = ComplexPingResponse {
            set_id,
            ping_backoff_factor: 1,
            status,
        };
        Ok(response.encode(true))
    }

    /// Handle ServerAlive request
    fn handle_server_alive() -> dcerpc::Result<Bytes> {
        let response = ServerAliveResponse { status: 0 };
        Ok(response.encode(true))
    }

    /// Handle ResolveOxid2 request
    fn handle_resolve_oxid2(
        exporter: &ObjectExporter,
        bindings: &DualStringArray,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = ResolveOxid2Request::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        let ipid = exporter.get_remunknown_ipid(&request.oxid);

        let response = ResolveOxid2Response {
            oxid_bindings: bindings.clone(),
            ipid_rem_unknown: ipid.unwrap_or_else(Ipid::nil),
            authn_hint: 0,
            com_version: ComVersion::DCOM_5_7,
            status: if ipid.is_some() { 0 } else { 0x80070057 },
        };

        Ok(response.encode(true))
    }

    /// Handle ServerAlive2 request
    fn handle_server_alive2(bindings: &DualStringArray) -> dcerpc::Result<Bytes> {
        let response = ServerAlive2Response {
            com_version: ComVersion::DCOM_5_7,
            bindings: bindings.clone(),
            reserved: 0,
            status: 0,
        };
        Ok(response.encode(true))
    }

    /// Register the OXID resolver with a DCE RPC server
    pub async fn register(&self, server: &DceRpcServer) -> Result<()> {
        let interface = self.build_interface()?;
        server.register_interface(interface).await;
        Ok(())
    }
}
