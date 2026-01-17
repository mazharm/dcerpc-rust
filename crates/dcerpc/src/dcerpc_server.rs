//! DCE RPC Server
//!
//! A server implementation for the DCE RPC protocol.

use crate::dcerpc::{
    BindAckPdu, BindPdu, ContextResult, FaultPdu, FaultStatus, Pdu, RequestPdu, ResponsePdu,
    SyntaxId, Uuid, NDR_SYNTAX_UUID, NDR_SYNTAX_VERSION,
};
use crate::dcerpc_transport::DceRpcTransport;
use crate::error::{Result, RpcError};
use bytes::Bytes;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Operation handler function type
pub type OperationHandler =
    Arc<dyn Fn(Bytes) -> Pin<Box<dyn Future<Output = Result<Bytes>> + Send>> + Send + Sync>;

/// Interface definition - contains operations for a specific interface version
pub struct Interface {
    pub syntax: SyntaxId,
    operations: HashMap<u16, OperationHandler>,
}

impl Interface {
    pub fn new(uuid: Uuid, major_version: u16, minor_version: u16) -> Self {
        Self {
            syntax: SyntaxId::new(uuid, major_version, minor_version),
            operations: HashMap::new(),
        }
    }

    pub fn from_syntax(syntax: SyntaxId) -> Self {
        Self {
            syntax,
            operations: HashMap::new(),
        }
    }

    /// Register an operation handler
    pub fn register_operation<F, Fut>(&mut self, opnum: u16, handler: F)
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Bytes>> + Send + 'static,
    {
        self.operations
            .insert(opnum, Arc::new(move |args| Box::pin(handler(args))));
    }

    /// Get an operation handler
    pub fn get_operation(&self, opnum: u16) -> Option<&OperationHandler> {
        self.operations.get(&opnum)
    }
}

/// DCE RPC Server configuration
pub struct DceRpcServerConfig {
    pub max_pdu_size: usize,
    pub max_connections: usize,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
}

impl Default for DceRpcServerConfig {
    fn default() -> Self {
        Self {
            max_pdu_size: 65536,
            max_connections: 1024,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
        }
    }
}

/// DCE RPC Server
pub struct DceRpcServer {
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: DceRpcServerConfig,
    assoc_group_counter: AtomicU32,
}

impl DceRpcServer {
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            config: DceRpcServerConfig::default(),
            assoc_group_counter: AtomicU32::new(1),
        }
    }

    pub fn with_config(config: DceRpcServerConfig) -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            config,
            assoc_group_counter: AtomicU32::new(1),
        }
    }

    /// Register an interface with the server
    pub async fn register_interface(&self, interface: Interface) {
        let mut interfaces = self.interfaces.write().await;
        interfaces.insert(interface.syntax.uuid, interface);
    }

    /// Run the server on the given address
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("DCE RPC server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("Accepted connection from {}", peer_addr);

            let interfaces = Arc::clone(&self.interfaces);
            let max_pdu_size = self.config.max_pdu_size;
            let max_xmit_frag = self.config.max_xmit_frag;
            let max_recv_frag = self.config.max_recv_frag;
            let assoc_group_id = self.assoc_group_counter.fetch_add(1, Ordering::SeqCst);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    interfaces,
                    max_pdu_size,
                    max_xmit_frag,
                    max_recv_frag,
                    assoc_group_id,
                )
                .await
                {
                    match &e {
                        RpcError::ConnectionClosed => {
                            debug!("Connection closed from {}", peer_addr);
                        }
                        _ => {
                            warn!("Connection error from {}: {}", peer_addr, e);
                        }
                    }
                }
            });
        }
    }

    /// Run the server with graceful shutdown
    pub async fn run_until<F: Future<Output = ()>>(
        &self,
        addr: SocketAddr,
        shutdown: F,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("DCE RPC server listening on {}", addr);

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = result?;
                    debug!("Accepted connection from {}", peer_addr);

                    let interfaces = Arc::clone(&self.interfaces);
                    let max_pdu_size = self.config.max_pdu_size;
                    let max_xmit_frag = self.config.max_xmit_frag;
                    let max_recv_frag = self.config.max_recv_frag;
                    let assoc_group_id = self.assoc_group_counter.fetch_add(1, Ordering::SeqCst);

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            interfaces,
                            max_pdu_size,
                            max_xmit_frag,
                            max_recv_frag,
                            assoc_group_id,
                        ).await {
                            match &e {
                                RpcError::ConnectionClosed => {
                                    debug!("Connection closed from {}", peer_addr);
                                }
                                _ => {
                                    warn!("Connection error from {}: {}", peer_addr, e);
                                }
                            }
                        }
                    });
                }
                _ = &mut shutdown => {
                    info!("Server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Default for DceRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-connection context
struct ConnectionContext {
    bound_context: Option<BoundContext>,
}

struct BoundContext {
    context_id: u16,
    interface_uuid: Uuid,
    #[allow(dead_code)]
    transfer_syntax: SyntaxId,
}

/// Handle a single connection
async fn handle_connection(
    stream: TcpStream,
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    max_pdu_size: usize,
    max_xmit_frag: u16,
    max_recv_frag: u16,
    assoc_group_id: u32,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut read_transport = DceRpcTransport::new(reader).with_max_pdu_size(max_pdu_size);
    let mut write_transport = DceRpcTransport::new(writer);

    let mut ctx = ConnectionContext {
        bound_context: None,
    };

    let ndr_syntax = SyntaxId::new(
        Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
        NDR_SYNTAX_VERSION as u16,
        0,
    );

    loop {
        // Read a PDU
        let pdu = read_transport.read_pdu_decoded().await?;

        match pdu {
            Pdu::Bind(bind) => {
                debug!(
                    "Received bind: call_id={}, contexts={}",
                    bind.header.call_id,
                    bind.context_list.len()
                );

                // Process bind request
                let response = process_bind(
                    &bind,
                    &interfaces,
                    max_xmit_frag,
                    max_recv_frag,
                    assoc_group_id,
                    &mut ctx,
                    &ndr_syntax,
                )
                .await;

                write_transport.write_pdu(&response.encode()).await?;
            }

            Pdu::Request(request) => {
                debug!(
                    "Received request: call_id={}, opnum={}, stub_len={}",
                    request.header.call_id,
                    request.opnum,
                    request.stub_data.len()
                );

                let response = process_request(&request, &interfaces, &ctx).await;

                write_transport.write_pdu(&response.encode()).await?;
            }

            Pdu::BindAck(_) | Pdu::Response(_) => {
                // These are client-side PDUs, ignore
                warn!("Received unexpected client PDU");
            }

            Pdu::Fault(fault) => {
                // Client sent a fault?
                warn!("Received fault from client: 0x{:08x}", fault.status);
            }

            Pdu::Auth3(_) | Pdu::AlterContext(_) | Pdu::AlterContextResp(_) => {
                // These PDUs are for authenticated connections
                // Use AuthenticatedDceRpcServer for auth support
                warn!("Received authentication PDU on non-authenticated connection");
            }
        }
    }
}

async fn process_bind(
    bind: &BindPdu,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    max_xmit_frag: u16,
    max_recv_frag: u16,
    assoc_group_id: u32,
    ctx: &mut ConnectionContext,
    ndr_syntax: &SyntaxId,
) -> BindAckPdu {
    let interfaces = interfaces.read().await;

    let mut results = Vec::new();

    for context in &bind.context_list {
        let interface_uuid = context.abstract_syntax.uuid;

        // Check if we support this interface
        if interfaces.contains_key(&interface_uuid) {
            // Check for NDR transfer syntax
            let has_ndr = context
                .transfer_syntaxes
                .iter()
                .any(|ts| ts.uuid == ndr_syntax.uuid);

            if has_ndr {
                // Accept the context
                ctx.bound_context = Some(BoundContext {
                    context_id: context.context_id,
                    interface_uuid,
                    transfer_syntax: *ndr_syntax,
                });
                results.push((ContextResult::Acceptance, *ndr_syntax));
            } else {
                results.push((
                    ContextResult::ProviderRejection,
                    SyntaxId::new(Uuid::NIL, 0, 0),
                ));
            }
        } else {
            results.push((
                ContextResult::ProviderRejection,
                SyntaxId::new(Uuid::NIL, 0, 0),
            ));
        }
    }

    // If no results, reject everything
    if results.is_empty() {
        results.push((
            ContextResult::ProviderRejection,
            SyntaxId::new(Uuid::NIL, 0, 0),
        ));
    }

    let mut ack = BindAckPdu::new(bind.header.call_id, assoc_group_id, *ndr_syntax);
    ack.max_xmit_frag = max_xmit_frag.min(bind.max_xmit_frag);
    ack.max_recv_frag = max_recv_frag.min(bind.max_recv_frag);
    ack.results = results;

    ack
}

async fn process_request(
    request: &RequestPdu,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    ctx: &ConnectionContext,
) -> Pdu {
    let call_id = request.header.call_id;

    // Check if we have a bound context
    let bound = match &ctx.bound_context {
        Some(b) => b,
        None => {
            return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::ContextMismatch));
        }
    };

    // Verify context ID matches
    if request.context_id != bound.context_id {
        return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::ContextMismatch));
    }

    // Look up the interface and operation
    let interfaces = interfaces.read().await;
    let interface = match interfaces.get(&bound.interface_uuid) {
        Some(iface) => iface,
        None => {
            return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::UnkIf));
        }
    };

    let handler = match interface.get_operation(request.opnum) {
        Some(h) => Arc::clone(h),
        None => {
            return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::OpRngError));
        }
    };

    // Release lock before calling handler
    drop(interfaces);

    // Call the handler
    match handler(request.stub_data.clone()).await {
        Ok(result) => {
            let mut response = ResponsePdu::new(call_id, result);
            response.context_id = request.context_id;
            Pdu::Response(response)
        }
        Err(e) => {
            error!("Operation error: {}", e);
            Pdu::Fault(FaultPdu::new(call_id, FaultStatus::RpcError))
        }
    }
}

/// Builder for creating DCE RPC interfaces with a fluent API
pub struct InterfaceBuilder {
    interface: Interface,
}

impl InterfaceBuilder {
    pub fn new(uuid: &str, major_version: u16, minor_version: u16) -> Option<Self> {
        let uuid = Uuid::parse(uuid)?;
        Some(Self {
            interface: Interface::new(uuid, major_version, minor_version),
        })
    }

    pub fn from_syntax(syntax: SyntaxId) -> Self {
        Self {
            interface: Interface::from_syntax(syntax),
        }
    }

    pub fn operation<F, Fut>(mut self, opnum: u16, handler: F) -> Self
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Bytes>> + Send + 'static,
    {
        self.interface.register_operation(opnum, handler);
        self
    }

    pub fn build(self) -> Interface {
        self.interface
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_builder() {
        let interface = InterfaceBuilder::new("12345678-1234-1234-1234-123456789012", 1, 0)
            .unwrap()
            .operation(0, |_args| async { Ok(Bytes::new()) })
            .operation(1, |_args| async { Ok(Bytes::from_static(b"hello")) })
            .build();

        assert!(interface.get_operation(0).is_some());
        assert!(interface.get_operation(1).is_some());
        assert!(interface.get_operation(2).is_none());
    }
}
