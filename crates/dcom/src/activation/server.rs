//! IActivation server implementation

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use bytes::Bytes;
use dcerpc::InterfaceBuilder;
use crate::types::{Result, DcomError, StdObjRef};
use crate::exporter::ObjectExporter;
use crate::apartment::{ComObject, CallDispatcher};
use super::protocol::*;

/// Factory function type for creating COM objects
pub type ClassFactory = Arc<dyn Fn(&dcerpc::Uuid) -> Option<Arc<dyn ComObject>> + Send + Sync>;

/// IActivation server
///
/// Implements the IActivation interface for remote object creation.
pub struct ActivationServer {
    /// Reference to the object exporter
    exporter: Arc<ObjectExporter>,
    /// Call dispatcher
    dispatcher: Arc<CallDispatcher>,
    /// Registered class factories by CLSID
    factories: RwLock<HashMap<dcerpc::Uuid, ClassFactory>>,
}

impl ActivationServer {
    /// Create a new activation server
    pub fn new(exporter: Arc<ObjectExporter>, dispatcher: Arc<CallDispatcher>) -> Self {
        Self {
            exporter,
            dispatcher,
            factories: RwLock::new(HashMap::new()),
        }
    }

    /// Register a class factory
    pub fn register_class(&self, clsid: dcerpc::Uuid, factory: ClassFactory) {
        let mut factories = self.factories.write().unwrap();
        factories.insert(clsid, factory);
    }

    /// Unregister a class factory
    pub fn unregister_class(&self, clsid: &dcerpc::Uuid) {
        let mut factories = self.factories.write().unwrap();
        factories.remove(clsid);
    }

    /// Build the DCE RPC interface
    pub fn build_interface(&self) -> Result<dcerpc::Interface> {
        let exporter = self.exporter.clone();
        let dispatcher = self.dispatcher.clone();
        let factories = Arc::new(RwLock::new(HashMap::<dcerpc::Uuid, ClassFactory>::new()));

        // Copy our factories into the Arc'd version
        {
            let src = self.factories.read().unwrap();
            let mut dst = factories.write().unwrap();
            for (k, v) in src.iter() {
                dst.insert(*k, v.clone());
            }
        }

        let interface = InterfaceBuilder::new(
            ACTIVATION_UUID,
            ACTIVATION_VERSION.0,
            ACTIVATION_VERSION.1,
        )
        .ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?
        .operation(opnum::REMOTE_ACTIVATION, move |args: Bytes| {
            let exporter = exporter.clone();
            let dispatcher = dispatcher.clone();
            let factories = factories.clone();
            async move {
                Self::handle_remote_activation(&exporter, &dispatcher, &factories, args)
            }
        })
        .build();

        Ok(interface)
    }

    /// Handle RemoteActivation
    fn handle_remote_activation(
        exporter: &ObjectExporter,
        dispatcher: &CallDispatcher,
        factories: &RwLock<HashMap<dcerpc::Uuid, ClassFactory>>,
        args: Bytes,
    ) -> dcerpc::Result<Bytes> {
        let mut buf = args;
        let request = RemoteActivationRequest::decode(&mut buf, true)
            .map_err(|e| dcerpc::RpcError::InvalidPduData(e.to_string()))?;

        // Look up the class factory
        let factory = {
            let factories = factories.read().unwrap();
            factories.get(&request.clsid).cloned()
        };

        let factory = match factory {
            Some(f) => f,
            None => {
                // Class not registered
                let response = RemoteActivationResponse::failure(0x80040154); // REGDB_E_CLASSNOTREG
                return Ok(response.encode(true));
            }
        };

        // Create the object
        let object = match factory(&request.clsid) {
            Some(obj) => obj,
            None => {
                let response = RemoteActivationResponse::failure(0x80004005); // E_FAIL
                return Ok(response.encode(true));
            }
        };

        // Register the object in the exporter
        let oid = exporter.register_object();
        dispatcher.default_mta().register_object(object.clone());
        dispatcher.associate_oid(oid, dispatcher.default_mta().id());

        // Create interface references for requested interfaces
        let mut interface_results = Vec::with_capacity(request.interfaces.len());
        let supported = object.supported_interfaces();

        for iid in &request.interfaces {
            if supported.contains(iid) || iid == &dcerpc::Uuid::NIL {
                // Register the interface
                match exporter.register_interface(oid, *iid) {
                    Ok(ipid) => {
                        let std = StdObjRef::new(exporter.oxid(), oid, ipid, 1);
                        interface_results.push(InterfaceResult::success(std));
                        dispatcher.associate_ipid(ipid, dispatcher.default_mta().id());
                    }
                    Err(_) => {
                        interface_results.push(InterfaceResult::failure(0x80004002)); // E_NOINTERFACE
                    }
                }
            } else {
                interface_results.push(InterfaceResult::failure(0x80004002)); // E_NOINTERFACE
            }
        }

        let response = RemoteActivationResponse::success(
            exporter.oxid(),
            exporter.bindings().clone(),
            exporter.remunknown_ipid(),
            interface_results,
        );

        Ok(response.encode(true))
    }

    /// Register with a DCE RPC server
    pub async fn register(&self, server: &dcerpc::DceRpcServer) -> Result<()> {
        let interface = self.build_interface()?;
        server.register_interface(interface).await;
        Ok(())
    }
}

use crate::apartment::Apartment;
