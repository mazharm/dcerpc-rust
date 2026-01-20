//! IRemUnknown server implementation

use std::sync::Arc;
use bytes::Bytes;
use dcerpc::InterfaceBuilder;
use crate::types::{Result, DcomError, StdObjRef};
use crate::exporter::ObjectExporter;
use super::protocol::*;

/// IRemUnknown server
///
/// Implements the IRemUnknown interface for remote reference counting.
pub struct RemUnknownServer {
    /// Reference to the object exporter
    exporter: Arc<ObjectExporter>,
}

impl RemUnknownServer {
    /// Create a new IRemUnknown server
    pub fn new(exporter: Arc<ObjectExporter>) -> Self {
        Self { exporter }
    }

    /// Build the DCE RPC interface
    pub fn build_interface(&self) -> Result<dcerpc::Interface> {
        let exporter = self.exporter.clone();
        let exporter2 = self.exporter.clone();
        let exporter3 = self.exporter.clone();

        let interface = InterfaceBuilder::new(
            REMUNKNOWN_UUID,
            REMUNKNOWN_VERSION.0,
            REMUNKNOWN_VERSION.1,
        )
        .ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?
        .operation(opnum::QUERY_INTERFACE, move |args: Bytes| {
            let exporter = exporter.clone();
            async move {
                Self::handle_query_interface(&exporter, args)
            }
        })
        .operation(opnum::ADD_REF, move |args: Bytes| {
            let exporter = exporter2.clone();
            async move {
                Self::handle_add_ref(&exporter, args)
            }
        })
        .operation(opnum::RELEASE, move |args: Bytes| {
            let exporter = exporter3.clone();
            async move {
                Self::handle_release(&exporter, args)
            }
        })
        .build();

        Ok(interface)
    }

    /// Handle RemQueryInterface
    fn handle_query_interface(
        exporter: &ObjectExporter,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = RemQueryInterfaceRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        let mut results = Vec::with_capacity(request.iids.len());

        for iid in &request.iids {
            match exporter.query_interface(&request.ipid, iid) {
                Ok(new_ipid) => {
                    // Get the OID for this IPID
                    if let Some(entry) = exporter.lookup_ipid(&new_ipid) {
                        // Add the requested number of public references
                        if request.refs > 0 {
                            if let Err(e) = exporter.add_refs(&new_ipid, request.refs, None) {
                                tracing::warn!(
                                    "Failed to add {} refs to IPID {:?}: {:?}",
                                    request.refs, new_ipid, e
                                );
                            }
                        }

                        let std = StdObjRef::new(
                            exporter.oxid(),
                            entry.oid,
                            new_ipid,
                            request.refs,
                        );
                        results.push(RemQiResult::success(std));
                    } else {
                        results.push(RemQiResult::failure(0x80004002)); // E_NOINTERFACE
                    }
                }
                Err(_) => {
                    results.push(RemQiResult::failure(0x80004002)); // E_NOINTERFACE
                }
            }
        }

        let response = RemQueryInterfaceResponse::success(results);
        Ok(response.encode(true))
    }

    /// Handle RemAddRef
    fn handle_add_ref(
        exporter: &ObjectExporter,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = RemAddRefRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        let mut results = Vec::with_capacity(request.refs.len());

        for r in &request.refs {
            match exporter.add_refs(&r.ipid, r.public_refs, None) {
                Ok(_) => results.push(0), // S_OK
                Err(_) => results.push(0x80004005), // E_FAIL
            }
        }

        let response = RemAddRefResponse::success(results);
        Ok(response.encode(true))
    }

    /// Handle RemRelease
    fn handle_release(
        exporter: &ObjectExporter,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = RemReleaseRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        for r in &request.refs {
            if let Err(e) = exporter.release_refs(&r.ipid, r.public_refs, None) {
                tracing::warn!(
                    "Failed to release {} refs from IPID {:?}: {:?}",
                    r.public_refs, r.ipid, e
                );
            }
        }

        let response = RemReleaseResponse::success();
        Ok(response.encode(true))
    }

    /// Register with a DCE RPC server
    pub async fn register(&self, server: &dcerpc::DceRpcServer) -> Result<()> {
        let interface = self.build_interface()?;
        server.register_interface(interface).await;
        Ok(())
    }
}
