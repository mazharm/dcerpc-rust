//! High-level DCOM server API
//!
//! Provides a simple interface for hosting COM objects.

use std::net::SocketAddr;
use std::sync::Arc;
use crate::types::{Result, DcomError, DualStringArray};
use crate::exporter::ObjectExporter;
use crate::remunknown::RemUnknownServer;
use crate::activation::{ActivationServer, ClassFactory};
use crate::apartment::{CallDispatcher, ComObject, Apartment};

/// DCOM Server configuration
#[derive(Clone, Debug)]
pub struct DcomServerConfig {
    /// Address to listen on for RPC connections
    pub rpc_addr: SocketAddr,
    /// Whether to register with the endpoint mapper
    pub register_with_epm: bool,
    /// Whether to start the OXID resolver on port 135
    pub start_oxid_resolver: bool,
}

impl Default for DcomServerConfig {
    fn default() -> Self {
        Self {
            rpc_addr: "0.0.0.0:0".parse().unwrap(),
            register_with_epm: false,
            start_oxid_resolver: false,
        }
    }
}

impl DcomServerConfig {
    /// Create a new configuration
    pub fn new(rpc_addr: SocketAddr) -> Self {
        Self {
            rpc_addr,
            register_with_epm: false,
            start_oxid_resolver: false,
        }
    }
}

/// High-level DCOM server
///
/// Manages the DCOM runtime including:
/// - Object exporter
/// - IRemUnknown endpoint
/// - IActivation endpoint
/// - OXID resolver (optional)
pub struct DcomServer {
    /// Configuration
    config: DcomServerConfig,
    /// Object exporter
    exporter: Arc<ObjectExporter>,
    /// Call dispatcher
    dispatcher: Arc<CallDispatcher>,
    /// Activation server
    activation: Arc<ActivationServer>,
    /// DCE RPC server
    rpc_server: dcerpc::DceRpcServer,
    /// Running state
    running: std::sync::atomic::AtomicBool,
}

impl DcomServer {
    /// Create a new DCOM server
    pub fn new(config: DcomServerConfig) -> Self {
        let bindings = DualStringArray::with_tcp_binding(&config.rpc_addr.to_string());
        let exporter = Arc::new(ObjectExporter::new(bindings));
        let dispatcher = Arc::new(CallDispatcher::new());
        let activation = Arc::new(ActivationServer::new(exporter.clone(), dispatcher.clone()));

        Self {
            config,
            exporter,
            dispatcher,
            activation,
            rpc_server: dcerpc::DceRpcServer::new(),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create with default configuration
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self::new(DcomServerConfig::new(addr))
    }

    /// Get the object exporter
    pub fn exporter(&self) -> &Arc<ObjectExporter> {
        &self.exporter
    }

    /// Get the call dispatcher
    pub fn dispatcher(&self) -> &Arc<CallDispatcher> {
        &self.dispatcher
    }

    /// Register a class factory
    pub fn register_class(&self, clsid: dcerpc::Uuid, factory: ClassFactory) {
        self.activation.register_class(clsid, factory);
    }

    /// Register a COM object
    pub fn register_object(&self, object: Arc<dyn ComObject>) -> crate::types::Oid {
        let oid = self.exporter.register_object();
        self.dispatcher.default_mta().register_object(object);
        self.dispatcher.associate_oid(oid, self.dispatcher.default_mta().id());
        oid
    }

    /// Register a COM object in a specific apartment
    pub fn register_object_in_apartment(
        &self,
        object: Arc<dyn ComObject>,
        apartment: Arc<dyn Apartment>,
    ) -> crate::types::Oid {
        let oid = self.exporter.register_object();
        apartment.register_object(object);
        self.dispatcher.register_apartment(apartment.clone());
        self.dispatcher.associate_oid(oid, apartment.id());
        oid
    }

    /// Start the server
    pub async fn start(&self) -> Result<()> {
        use std::sync::atomic::Ordering;

        if self.running.load(Ordering::SeqCst) {
            return Err(DcomError::InvalidData("server already running".to_string()));
        }

        // Register IRemUnknown interface
        let remunknown = RemUnknownServer::new(self.exporter.clone());
        remunknown.register(&self.rpc_server).await?;

        // Register IActivation interface
        self.activation.register(&self.rpc_server).await?;

        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Run the server (blocking)
    pub async fn run(&self) -> Result<()> {
        self.start().await?;
        self.rpc_server
            .run(self.config.rpc_addr)
            .await
            .map_err(DcomError::Rpc)
    }

    /// Run until a shutdown signal
    pub async fn run_until<F>(&self, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send,
    {
        self.start().await?;
        self.rpc_server
            .run_until(self.config.rpc_addr, shutdown)
            .await
            .map_err(DcomError::Rpc)
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        self.dispatcher.shutdown();
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.running.load(Ordering::SeqCst)
    }

    /// Get the server's OXID
    pub fn oxid(&self) -> crate::types::Oxid {
        self.exporter.oxid()
    }

    /// Get the server's bindings
    pub fn bindings(&self) -> &DualStringArray {
        self.exporter.bindings()
    }

    /// Run garbage collection
    pub fn run_gc(&self) -> Vec<crate::types::Oid> {
        self.exporter.run_gc()
    }
}

/// Builder for DCOM server
#[allow(dead_code)]
pub struct DcomServerBuilder {
    config: DcomServerConfig,
    classes: Vec<(dcerpc::Uuid, ClassFactory)>,
}

#[allow(dead_code)]
impl DcomServerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: DcomServerConfig::default(),
            classes: Vec::new(),
        }
    }

    /// Set the RPC address
    pub fn rpc_addr(mut self, addr: SocketAddr) -> Self {
        self.config.rpc_addr = addr;
        self
    }

    /// Enable endpoint mapper registration
    pub fn register_with_epm(mut self, enable: bool) -> Self {
        self.config.register_with_epm = enable;
        self
    }

    /// Enable OXID resolver
    pub fn start_oxid_resolver(mut self, enable: bool) -> Self {
        self.config.start_oxid_resolver = enable;
        self
    }

    /// Register a class factory
    pub fn class(mut self, clsid: dcerpc::Uuid, factory: ClassFactory) -> Self {
        self.classes.push((clsid, factory));
        self
    }

    /// Build the server
    pub fn build(self) -> DcomServer {
        let server = DcomServer::new(self.config);
        for (clsid, factory) in self.classes {
            server.register_class(clsid, factory);
        }
        server
    }
}

impl Default for DcomServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
