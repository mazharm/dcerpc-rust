//! High-level DCOM client API
//!
//! Provides a simple interface for consuming remote COM objects.

use std::net::SocketAddr;
use bytes::Bytes;
use crate::types::{
    Result, DcomError, Oxid, Oid, Ipid,
    DualStringArray, StdObjRef,
};
use crate::oxid_resolver::{OxidResolverClient, PingSetManager};
use crate::remunknown::{RemUnknownClient, RemInterfaceRef};
use crate::activation::ActivationClient;

/// Configuration for DCOM client
#[derive(Clone, Debug)]
pub struct DcomClientConfig {
    /// Whether to automatically ping for garbage collection
    pub auto_ping: bool,
    /// Ping interval in seconds
    pub ping_interval_secs: u64,
    /// Default number of references to request
    pub default_refs: u32,
}

impl Default for DcomClientConfig {
    fn default() -> Self {
        Self {
            auto_ping: true,
            ping_interval_secs: 60,
            default_refs: 5,
        }
    }
}

/// Proxy for a remote COM interface
pub struct InterfaceProxy {
    /// Standard object reference
    std: StdObjRef,
    /// Server bindings
    bindings: DualStringArray,
    /// RPC client (lazy initialized)
    rpc_client: Option<dcerpc::DceRpcClient>,
    /// Server address
    server_addr: SocketAddr,
}

impl InterfaceProxy {
    /// Create a new interface proxy
    pub fn new(std: StdObjRef, bindings: DualStringArray, server_addr: SocketAddr) -> Self {
        Self {
            std,
            bindings,
            rpc_client: None,
            server_addr,
        }
    }

    /// Get the IPID
    pub fn ipid(&self) -> Ipid {
        self.std.ipid
    }

    /// Get the OID
    pub fn oid(&self) -> Oid {
        self.std.oid
    }

    /// Get the OXID
    pub fn oxid(&self) -> Oxid {
        self.std.oxid
    }

    /// Get the public reference count
    pub fn public_refs(&self) -> u32 {
        self.std.public_refs
    }

    /// Invoke a method on the remote interface
    pub async fn invoke(
        &mut self,
        opnum: u16,
        args: Bytes,
        interface_uuid: &str,
    ) -> Result<Bytes> {
        // Ensure we have a connection
        if self.rpc_client.is_none() {
            let interface = dcerpc::SyntaxId::new(
                dcerpc::Uuid::parse(interface_uuid).ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?,
                0,
                0,
            );
            let client = dcerpc::DceRpcClient::connect(self.server_addr, interface)
                .await
                .map_err(DcomError::Rpc)?;
            self.rpc_client = Some(client);
        }

        let client = self.rpc_client.as_ref().unwrap();
        client.call(opnum, args).await.map_err(DcomError::Rpc)
    }
}

/// High-level DCOM client
///
/// Manages connections to remote DCOM servers and provides
/// a simple interface for activating and invoking COM objects.
pub struct DcomClient {
    /// Configuration
    config: DcomClientConfig,
    /// Server address
    server_addr: SocketAddr,
    /// OXID resolver client
    oxid_client: Option<OxidResolverClient>,
    /// IRemUnknown client
    remunknown_client: Option<RemUnknownClient>,
    /// Activation client
    activation_client: Option<ActivationClient>,
    /// Ping set manager
    ping_manager: Option<PingSetManager>,
    /// Active interface proxies
    proxies: Vec<InterfaceProxy>,
}

impl DcomClient {
    /// Create a new DCOM client
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            config: DcomClientConfig::default(),
            server_addr,
            oxid_client: None,
            remunknown_client: None,
            activation_client: None,
            ping_manager: None,
            proxies: Vec::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(server_addr: SocketAddr, config: DcomClientConfig) -> Self {
        Self {
            config,
            server_addr,
            oxid_client: None,
            remunknown_client: None,
            activation_client: None,
            ping_manager: None,
            proxies: Vec::new(),
        }
    }

    /// Connect to the server
    pub async fn connect(&mut self) -> Result<()> {
        // Connect to activation endpoint
        self.activation_client = Some(ActivationClient::connect(self.server_addr).await?);
        Ok(())
    }

    /// Check if the server is alive
    pub async fn server_alive(&mut self) -> Result<bool> {
        if self.oxid_client.is_none() {
            self.oxid_client = Some(OxidResolverClient::connect(self.server_addr).await?);
        }
        self.oxid_client.as_ref().unwrap().server_alive().await
    }

    /// Activate a remote object by CLSID
    pub async fn activate(
        &mut self,
        clsid: dcerpc::Uuid,
        interfaces: Vec<dcerpc::Uuid>,
    ) -> Result<Vec<InterfaceProxy>> {
        // Ensure activation client is connected
        if self.activation_client.is_none() {
            self.connect().await?;
        }

        let result = self
            .activation_client
            .as_ref()
            .unwrap()
            .remote_activation(clsid, interfaces)
            .await?;

        // Create proxies for successful interfaces
        let mut proxies = Vec::new();
        for interface_result in result.interface_results {
            if interface_result.hresult == 0 {
                if let Some(std) = interface_result.std {
                    let proxy = InterfaceProxy::new(
                        std,
                        result.bindings.clone(),
                        self.server_addr,
                    );
                    proxies.push(proxy);
                }
            }
        }

        // Register OIDs for pinging if auto_ping is enabled
        if self.config.auto_ping && !proxies.is_empty() {
            let oids: Vec<Oid> = proxies.iter().map(|p| p.oid()).collect();
            if let Err(e) = self.register_for_ping(oids).await {
                tracing::warn!("Failed to register for ping: {}", e);
            }
        }

        self.proxies.extend(proxies.iter().map(|p| InterfaceProxy::new(
            p.std.clone(),
            p.bindings.clone(),
            p.server_addr,
        )));

        Ok(proxies)
    }

    /// Query for an additional interface on an existing object
    pub async fn query_interface(
        &mut self,
        proxy: &InterfaceProxy,
        iid: dcerpc::Uuid,
    ) -> Result<Option<InterfaceProxy>> {
        // Ensure IRemUnknown client is connected
        if self.remunknown_client.is_none() {
            self.remunknown_client = Some(RemUnknownClient::connect(self.server_addr).await?);
        }

        let result = self
            .remunknown_client
            .as_ref()
            .unwrap()
            .query_single_interface(proxy.ipid(), iid, self.config.default_refs)
            .await?;

        if let Some(std) = result {
            Ok(Some(InterfaceProxy::new(
                std,
                proxy.bindings.clone(),
                self.server_addr,
            )))
        } else {
            Ok(None)
        }
    }

    /// Add references to an interface
    pub async fn add_ref(&mut self, proxy: &InterfaceProxy, count: u32) -> Result<u32> {
        if self.remunknown_client.is_none() {
            self.remunknown_client = Some(RemUnknownClient::connect(self.server_addr).await?);
        }

        self.remunknown_client
            .as_ref()
            .unwrap()
            .add_single_ref(proxy.ipid(), count)
            .await
    }

    /// Release references from an interface
    pub async fn release(&mut self, proxy: &InterfaceProxy, count: u32) -> Result<()> {
        if self.remunknown_client.is_none() {
            self.remunknown_client = Some(RemUnknownClient::connect(self.server_addr).await?);
        }

        self.remunknown_client
            .as_ref()
            .unwrap()
            .release_single_ref(proxy.ipid(), count)
            .await
    }

    /// Register OIDs for ping-based garbage collection
    async fn register_for_ping(&mut self, oids: Vec<Oid>) -> Result<()> {
        if self.ping_manager.is_none() {
            self.ping_manager = Some(PingSetManager::new(self.server_addr).await?);
        }

        self.ping_manager.as_mut().unwrap().add_oids(oids).await
    }

    /// Send a ping to keep references alive
    pub async fn ping(&self) -> Result<()> {
        if let Some(ref manager) = self.ping_manager {
            manager.ping().await
        } else {
            Ok(())
        }
    }

    /// Release all references and disconnect
    pub async fn disconnect(&mut self) -> Result<()> {
        // Release all proxies
        if self.remunknown_client.is_some() {
            let refs: Vec<RemInterfaceRef> = self
                .proxies
                .iter()
                .map(|p| RemInterfaceRef::new(p.ipid(), p.public_refs(), 0))
                .collect();

            if !refs.is_empty() {
                let _ = self.remunknown_client.as_ref().unwrap().release(refs).await;
            }
        }

        self.proxies.clear();
        self.oxid_client = None;
        self.remunknown_client = None;
        self.activation_client = None;
        self.ping_manager = None;

        Ok(())
    }

    /// Get the server address
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

impl Drop for DcomClient {
    fn drop(&mut self) {
        // Note: Can't await in drop, so we just clear state
        // A proper cleanup should call disconnect() before dropping
        self.proxies.clear();
    }
}

/// Builder for DCOM client
#[allow(dead_code)]
pub struct DcomClientBuilder {
    server_addr: SocketAddr,
    config: DcomClientConfig,
}

#[allow(dead_code)]
impl DcomClientBuilder {
    /// Create a new builder
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            config: DcomClientConfig::default(),
        }
    }

    /// Enable or disable auto-ping
    pub fn auto_ping(mut self, enable: bool) -> Self {
        self.config.auto_ping = enable;
        self
    }

    /// Set ping interval
    pub fn ping_interval(mut self, secs: u64) -> Self {
        self.config.ping_interval_secs = secs;
        self
    }

    /// Set default reference count
    pub fn default_refs(mut self, refs: u32) -> Self {
        self.config.default_refs = refs;
        self
    }

    /// Build the client
    pub fn build(self) -> DcomClient {
        DcomClient::with_config(self.server_addr, self.config)
    }
}
