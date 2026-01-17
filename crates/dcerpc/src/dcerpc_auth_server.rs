//! Authenticated DCE RPC Server
//!
//! A server implementation for DCE RPC with SSPI-based authentication.
//! Supports NTLM, Kerberos, and Negotiate authentication.

use crate::dcerpc::{
    AlterContextPdu, AlterContextRespPdu, Auth3Pdu, BindAckPdu, BindPdu, ContextResult,
    FaultPdu, FaultStatus, Pdu, RequestPdu, ResponsePdu, SyntaxId, Uuid,
    NDR_SYNTAX_UUID, NDR_SYNTAX_VERSION,
};
use crate::dcerpc_server::Interface;
use crate::dcerpc_transport::DceRpcTransport;
use crate::error::{Result, RpcError};
use crate::security::{AuthLevel, AuthType, AuthVerifier};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use crate::sspi::SspiContext;

/// Authenticated DCE RPC Server configuration
#[derive(Clone)]
pub struct AuthServerConfig {
    pub max_pdu_size: usize,
    pub max_connections: usize,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    /// Minimum acceptable auth level
    pub min_auth_level: AuthLevel,
    /// Whether to allow unauthenticated connections
    pub allow_unauthenticated: bool,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            max_pdu_size: 65536,
            max_connections: 1024,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            min_auth_level: AuthLevel::None,
            allow_unauthenticated: true,
        }
    }
}

impl AuthServerConfig {
    /// Require at least Connect-level authentication
    pub fn require_auth(mut self) -> Self {
        self.min_auth_level = AuthLevel::Connect;
        self.allow_unauthenticated = false;
        self
    }

    /// Require message integrity (signing)
    pub fn require_integrity(mut self) -> Self {
        self.min_auth_level = AuthLevel::PktIntegrity;
        self.allow_unauthenticated = false;
        self
    }

    /// Require message privacy (encryption)
    pub fn require_privacy(mut self) -> Self {
        self.min_auth_level = AuthLevel::PktPrivacy;
        self.allow_unauthenticated = false;
        self
    }
}

/// Authenticated DCE RPC Server
#[cfg(windows)]
pub struct AuthenticatedDceRpcServer {
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: AuthServerConfig,
    assoc_group_counter: AtomicU32,
}

#[cfg(windows)]
impl AuthenticatedDceRpcServer {
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            config: AuthServerConfig::default(),
            assoc_group_counter: AtomicU32::new(1),
        }
    }

    pub fn with_config(config: AuthServerConfig) -> Self {
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
        info!("Authenticated DCE RPC server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("Accepted connection from {}", peer_addr);

            let interfaces = Arc::clone(&self.interfaces);
            let config = self.config.clone();
            let assoc_group_id = self.assoc_group_counter.fetch_add(1, Ordering::SeqCst);

            tokio::spawn(async move {
                if let Err(e) =
                    handle_authenticated_connection(stream, interfaces, config, assoc_group_id)
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
        info!("Authenticated DCE RPC server listening on {}", addr);

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer_addr) = result?;
                    debug!("Accepted connection from {}", peer_addr);

                    let interfaces = Arc::clone(&self.interfaces);
                    let config = self.config.clone();
                    let assoc_group_id = self.assoc_group_counter.fetch_add(1, Ordering::SeqCst);

                    tokio::spawn(async move {
                        if let Err(e) = handle_authenticated_connection(
                            stream, interfaces, config, assoc_group_id
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

#[cfg(windows)]
impl Default for AuthenticatedDceRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-connection authentication context
#[cfg(windows)]
struct AuthConnectionContext {
    bound_context: Option<BoundContext>,
    security_context: Option<SspiContext>,
    auth_type: Option<AuthType>,
    auth_level: Option<AuthLevel>,
    auth_context_id: u32,
}

#[cfg(windows)]
struct BoundContext {
    context_id: u16,
    interface_uuid: Uuid,
    #[allow(dead_code)]
    transfer_syntax: SyntaxId,
}

/// Handle a single authenticated connection
#[cfg(windows)]
async fn handle_authenticated_connection(
    stream: TcpStream,
    interfaces: Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: AuthServerConfig,
    assoc_group_id: u32,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut read_transport = DceRpcTransport::new(reader).with_max_pdu_size(config.max_pdu_size);
    let mut write_transport = DceRpcTransport::new(writer);

    let mut ctx = AuthConnectionContext {
        bound_context: None,
        security_context: None,
        auth_type: None,
        auth_level: None,
        auth_context_id: 0,
    };

    let ndr_syntax = SyntaxId::new(
        Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
        NDR_SYNTAX_VERSION as u16,
        0,
    );

    loop {
        let pdu = read_transport.read_pdu_decoded().await?;

        match pdu {
            Pdu::Bind(bind) => {
                debug!(
                    "Received bind: call_id={}, contexts={}, auth={}",
                    bind.header.call_id,
                    bind.context_list.len(),
                    bind.auth_verifier.is_some()
                );

                let response = process_authenticated_bind(
                    &bind,
                    &interfaces,
                    &config,
                    assoc_group_id,
                    &mut ctx,
                    &ndr_syntax,
                )
                .await?;

                write_transport.write_pdu(&response.encode()).await?;
            }

            Pdu::Auth3(auth3) => {
                debug!("Received Auth3: call_id={}", auth3.header.call_id);

                // Process Auth3 to complete authentication
                process_auth3(&auth3, &mut ctx)?;
                // Auth3 has no response
            }

            Pdu::AlterContext(alter) => {
                debug!(
                    "Received AlterContext: call_id={}, auth={}",
                    alter.header.call_id,
                    alter.auth_verifier.is_some()
                );

                let response = process_alter_context(&alter, &config, assoc_group_id, &mut ctx)?;

                write_transport.write_pdu(&response.encode()).await?;
            }

            Pdu::Request(request) => {
                debug!(
                    "Received request: call_id={}, opnum={}, auth={}",
                    request.header.call_id,
                    request.opnum,
                    request.auth_verifier.is_some()
                );

                // Check authentication requirements
                if !config.allow_unauthenticated && ctx.security_context.is_none() {
                    let fault = FaultPdu::new(request.header.call_id, FaultStatus::AccessDenied);
                    write_transport.write_pdu(&fault.encode()).await?;
                    continue;
                }

                let response =
                    process_authenticated_request(&request, &interfaces, &mut ctx).await;

                write_transport.write_pdu(&response.encode()).await?;
            }

            Pdu::BindAck(_) | Pdu::Response(_) | Pdu::AlterContextResp(_) => {
                warn!("Received unexpected client PDU");
            }

            Pdu::Fault(fault) => {
                warn!("Received fault from client: 0x{:08x}", fault.status);
            }
        }
    }
}

/// Process an authenticated bind request
#[cfg(windows)]
async fn process_authenticated_bind(
    bind: &BindPdu,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    config: &AuthServerConfig,
    assoc_group_id: u32,
    ctx: &mut AuthConnectionContext,
    ndr_syntax: &SyntaxId,
) -> Result<BindAckPdu> {
    let interfaces_read = interfaces.read().await;

    let mut results = Vec::new();

    for context in &bind.context_list {
        let interface_uuid = context.abstract_syntax.uuid;

        if interfaces_read.contains_key(&interface_uuid) {
            let has_ndr = context
                .transfer_syntaxes
                .iter()
                .any(|ts| ts.uuid == ndr_syntax.uuid);

            if has_ndr {
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

    if results.is_empty() {
        results.push((
            ContextResult::ProviderRejection,
            SyntaxId::new(Uuid::NIL, 0, 0),
        ));
    }

    drop(interfaces_read);

    // Process authentication if present
    let auth_response = if let Some(ref auth_verifier) = bind.auth_verifier {
        // Check minimum auth level
        if auth_verifier.auth_level < config.min_auth_level {
            return Err(RpcError::CallRejected(format!(
                "Auth level {:?} below minimum {:?}",
                auth_verifier.auth_level, config.min_auth_level
            )));
        }

        ctx.auth_type = Some(auth_verifier.auth_type);
        ctx.auth_level = Some(auth_verifier.auth_level);
        ctx.auth_context_id = auth_verifier.auth_context_id;

        // Create server-side SSPI context
        let mut sspi_context =
            SspiContext::new_server(auth_verifier.auth_type, auth_verifier.auth_level)
                .map_err(|e| RpcError::CallRejected(format!("SSPI init failed: {}", e)))?;

        // Accept the client's token
        let response_token = sspi_context
            .accept(&auth_verifier.auth_value)
            .map_err(|e| RpcError::CallRejected(format!("SSPI accept failed: {}", e)))?;

        ctx.security_context = Some(sspi_context);

        response_token.map(|token| {
            AuthVerifier::new(
                auth_verifier.auth_type,
                auth_verifier.auth_level,
                auth_verifier.auth_context_id,
                token,
            )
        })
    } else if !config.allow_unauthenticated {
        return Err(RpcError::CallRejected(
            "Authentication required".to_string(),
        ));
    } else {
        None
    };

    let mut ack = BindAckPdu::new(bind.header.call_id, assoc_group_id, *ndr_syntax);
    ack.max_xmit_frag = config.max_xmit_frag.min(bind.max_xmit_frag);
    ack.max_recv_frag = config.max_recv_frag.min(bind.max_recv_frag);
    ack.results = results;
    ack.auth_verifier = auth_response;

    Ok(ack)
}

/// Process Auth3 PDU to complete authentication
#[cfg(windows)]
fn process_auth3(auth3: &Auth3Pdu, ctx: &mut AuthConnectionContext) -> Result<()> {
    if let Some(ref mut sspi_context) = ctx.security_context {
        // Continue the authentication with the client's final token
        let _ = sspi_context
            .accept(&auth3.auth_verifier.auth_value)
            .map_err(|e| RpcError::CallRejected(format!("Auth3 SSPI accept failed: {}", e)))?;

        debug!("Auth3 processed, security context established");
    } else {
        return Err(RpcError::CallRejected("No security context".to_string()));
    }

    Ok(())
}

/// Process AlterContext PDU for security renegotiation
#[cfg(windows)]
fn process_alter_context(
    alter: &AlterContextPdu,
    config: &AuthServerConfig,
    assoc_group_id: u32,
    ctx: &mut AuthConnectionContext,
) -> Result<AlterContextRespPdu> {
    let mut resp = AlterContextRespPdu::new(alter.header.call_id, assoc_group_id);
    resp.max_xmit_frag = config.max_xmit_frag.min(alter.max_xmit_frag);
    resp.max_recv_frag = config.max_recv_frag.min(alter.max_recv_frag);

    // Process authentication if present
    if let Some(ref auth_verifier) = alter.auth_verifier {
        if let Some(ref mut sspi_context) = ctx.security_context {
            let response_token = sspi_context
                .accept(&auth_verifier.auth_value)
                .map_err(|e| {
                    RpcError::CallRejected(format!("AlterContext SSPI accept failed: {}", e))
                })?;

            resp.auth_verifier = response_token.map(|token| {
                AuthVerifier::new(
                    auth_verifier.auth_type,
                    auth_verifier.auth_level,
                    auth_verifier.auth_context_id,
                    token,
                )
            });
        }
    }

    Ok(resp)
}

/// Process an authenticated request
#[cfg(windows)]
async fn process_authenticated_request(
    request: &RequestPdu,
    interfaces: &Arc<RwLock<HashMap<Uuid, Interface>>>,
    ctx: &mut AuthConnectionContext,
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

    // Verify/decrypt stub data if needed
    let stub_data = if let Some(ref mut sspi_context) = ctx.security_context {
        let auth_level = ctx.auth_level.unwrap_or(AuthLevel::None);

        if auth_level.requires_encryption() {
            // Decrypt the stub data
            if let Some(ref auth_verifier) = request.auth_verifier {
                match sspi_context.decrypt(&request.stub_data, &auth_verifier.auth_value) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        error!("Decryption failed: {}", e);
                        return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::AccessDenied));
                    }
                }
            } else {
                return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::AccessDenied));
            }
        } else if auth_level.requires_signing() {
            // Verify the signature
            if let Some(ref auth_verifier) = request.auth_verifier {
                if let Err(e) = sspi_context.verify(&request.stub_data, &auth_verifier.auth_value) {
                    error!("Signature verification failed: {}", e);
                    return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::AccessDenied));
                }
            } else {
                return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::AccessDenied));
            }
            request.stub_data.clone()
        } else {
            request.stub_data.clone()
        }
    } else {
        request.stub_data.clone()
    };

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

    drop(interfaces);

    // Call the handler
    match handler(stub_data).await {
        Ok(result) => {
            // Sign/encrypt response if needed
            let (response_stub, auth_verifier) = if let Some(ref mut sspi_context) =
                ctx.security_context
            {
                let auth_level = ctx.auth_level.unwrap_or(AuthLevel::None);
                let auth_type = ctx.auth_type.unwrap_or(AuthType::None);

                if auth_level.requires_encryption() {
                    match sspi_context.encrypt(&result) {
                        Ok((encrypted, signature)) => (
                            encrypted,
                            Some(AuthVerifier::new(
                                auth_type,
                                auth_level,
                                ctx.auth_context_id,
                                signature,
                            )),
                        ),
                        Err(e) => {
                            error!("Encryption failed: {}", e);
                            return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::RpcError));
                        }
                    }
                } else if auth_level.requires_signing() {
                    match sspi_context.sign(&result) {
                        Ok(signature) => (
                            result,
                            Some(AuthVerifier::new(
                                auth_type,
                                auth_level,
                                ctx.auth_context_id,
                                signature,
                            )),
                        ),
                        Err(e) => {
                            error!("Signing failed: {}", e);
                            return Pdu::Fault(FaultPdu::new(call_id, FaultStatus::RpcError));
                        }
                    }
                } else {
                    (result, None)
                }
            } else {
                (result, None)
            };

            let mut response = ResponsePdu::new(call_id, response_stub);
            response.context_id = request.context_id;
            response.auth_verifier = auth_verifier;
            Pdu::Response(response)
        }
        Err(e) => {
            error!("Operation error: {}", e);
            Pdu::Fault(FaultPdu::new(call_id, FaultStatus::RpcError))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_server_config() {
        let config = AuthServerConfig::default();
        assert!(config.allow_unauthenticated);
        assert_eq!(config.min_auth_level, AuthLevel::None);

        let config = AuthServerConfig::default().require_integrity();
        assert!(!config.allow_unauthenticated);
        assert_eq!(config.min_auth_level, AuthLevel::PktIntegrity);

        let config = AuthServerConfig::default().require_privacy();
        assert!(!config.allow_unauthenticated);
        assert_eq!(config.min_auth_level, AuthLevel::PktPrivacy);
    }
}
