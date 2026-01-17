//! Authenticated DCE RPC Client
//!
//! A client implementation for DCE RPC with SSPI-based authentication.
//! Supports NTLM, Kerberos, and Negotiate authentication.

use crate::dcerpc::{Auth3Pdu, BindAckPdu, BindPdu, ContextResult, Pdu, RequestPdu, ResponsePdu, SyntaxId};
use crate::dcerpc_transport::DceRpcTransport;
use crate::error::{Result, RpcError};
use crate::security::{AuthLevel, AuthType};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace};

#[cfg(windows)]
use crate::sspi::SspiContext;

/// Authenticated DCE RPC Client
///
/// This client extends the basic DCE RPC client with SSPI-based authentication.
/// It supports:
/// - NTLM authentication
/// - Kerberos authentication
/// - Negotiate (SPNEGO) authentication
/// - Message integrity (signing)
/// - Message privacy (encryption)
#[cfg(windows)]
pub struct AuthenticatedDceRpcClient {
    read_transport: Mutex<DceRpcTransport<ReadHalf<TcpStream>>>,
    write_transport: Mutex<DceRpcTransport<WriteHalf<TcpStream>>>,
    call_id_counter: AtomicU32,
    interface: SyntaxId,
    context_id: u16,
    max_xmit_frag: u16,
    max_recv_frag: u16,
    is_bound: bool,
    /// Security context for signing/sealing
    security_context: Option<Mutex<SspiContext>>,
    /// Authentication type
    auth_type: AuthType,
    /// Authentication level
    auth_level: AuthLevel,
    /// Authentication context ID
    auth_context_id: u32,
}

#[cfg(windows)]
impl AuthenticatedDceRpcClient {
    /// Connect to a DCE RPC server with authentication
    ///
    /// # Arguments
    /// * `addr` - Server address
    /// * `interface` - Interface to bind to
    /// * `auth_type` - Authentication type (NTLM, Negotiate, or Kerberos)
    /// * `auth_level` - Authentication level (Connect, Integrity, or Privacy)
    /// * `target_spn` - Target service principal name (for Kerberos)
    pub async fn connect(
        addr: SocketAddr,
        interface: SyntaxId,
        auth_type: AuthType,
        auth_level: AuthLevel,
        target_spn: Option<&str>,
    ) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut client = Self::from_stream(stream, interface, auth_type, auth_level);
        client.authenticated_bind(target_spn).await?;
        Ok(client)
    }

    /// Create a client from an existing TCP stream (unbound)
    fn from_stream(
        stream: TcpStream,
        interface: SyntaxId,
        auth_type: AuthType,
        auth_level: AuthLevel,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            read_transport: Mutex::new(DceRpcTransport::new(reader)),
            write_transport: Mutex::new(DceRpcTransport::new(writer)),
            call_id_counter: AtomicU32::new(1),
            interface,
            context_id: 0,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            is_bound: false,
            security_context: None,
            auth_type,
            auth_level,
            auth_context_id: 0,
        }
    }

    /// Perform authenticated bind handshake
    async fn authenticated_bind(&mut self, target_spn: Option<&str>) -> Result<()> {
        // Create SSPI context
        let mut sspi_context = SspiContext::new_client(self.auth_type, self.auth_level, target_spn)
            .map_err(|e| RpcError::CallRejected(format!("SSPI initialization failed: {}", e)))?;

        // Get initial authentication token
        let initial_token = sspi_context
            .initialize(target_spn)
            .map_err(|e| RpcError::CallRejected(format!("SSPI initialize failed: {}", e)))?;

        let call_id = self.call_id_counter.fetch_add(1, Ordering::SeqCst);

        // Create authenticated bind PDU
        let bind = BindPdu::new_authenticated(
            call_id,
            self.interface,
            self.auth_type,
            self.auth_level,
            self.auth_context_id,
            initial_token,
        );

        debug!(
            "Sending authenticated bind request: call_id={}, interface={}, auth_type={:?}",
            call_id, self.interface.uuid, self.auth_type
        );

        // Send bind request
        {
            let mut write = self.write_transport.lock().await;
            write.write_pdu(&bind.encode()).await?;
        }

        // Read bind ack
        let pdu = {
            let mut read = self.read_transport.lock().await;
            read.read_pdu_decoded().await?
        };

        match pdu {
            Pdu::BindAck(ack) => {
                self.process_bind_ack(ack, call_id, &mut sspi_context).await?;
            }
            Pdu::Fault(fault) => {
                return Err(RpcError::CallRejected(format!(
                    "authenticated bind fault: status=0x{:08x}",
                    fault.status
                )));
            }
            _ => {
                return Err(RpcError::InvalidMessageType(0));
            }
        }

        // Store the security context
        self.security_context = Some(Mutex::new(sspi_context));
        self.is_bound = true;

        debug!(
            "Authenticated bind successful: auth_type={:?}, auth_level={:?}",
            self.auth_type, self.auth_level
        );

        Ok(())
    }

    /// Process bind ack and continue authentication if needed
    async fn process_bind_ack(
        &mut self,
        ack: BindAckPdu,
        original_call_id: u32,
        sspi_context: &mut SspiContext,
    ) -> Result<()> {
        if ack.header.call_id != original_call_id {
            return Err(RpcError::XidMismatch {
                expected: original_call_id,
                got: ack.header.call_id,
            });
        }

        // Check if binding was accepted
        if let Some((result, _syntax)) = ack.results.first() {
            if *result != ContextResult::Acceptance {
                return Err(RpcError::CallRejected("bind rejected".to_string()));
            }
        } else {
            return Err(RpcError::CallRejected("no bind result".to_string()));
        }

        self.max_xmit_frag = ack.max_xmit_frag;
        self.max_recv_frag = ack.max_recv_frag;

        // Check if server sent auth token for multi-leg auth
        if let Some(ref auth_verifier) = ack.auth_verifier {
            if !sspi_context.is_established() {
                // Continue authentication with server's challenge
                let continue_token = sspi_context
                    .continue_client(&auth_verifier.auth_value)
                    .map_err(|e| RpcError::CallRejected(format!("SSPI continue failed: {}", e)))?;

                if let Some(token) = continue_token {
                    // Send Auth3 PDU to complete authentication
                    let auth3_call_id = self.call_id_counter.fetch_add(1, Ordering::SeqCst);
                    let auth3 = Auth3Pdu::new(
                        auth3_call_id,
                        self.auth_type,
                        self.auth_level,
                        self.auth_context_id,
                        token,
                    );

                    debug!("Sending Auth3: call_id={}", auth3_call_id);

                    let mut write = self.write_transport.lock().await;
                    write.write_pdu(&auth3.encode()).await?;
                    // Note: Auth3 has no response
                }
            }
        }

        Ok(())
    }

    /// Make an authenticated RPC call
    ///
    /// For AuthLevel::PktIntegrity, the stub data is signed.
    /// For AuthLevel::PktPrivacy, the stub data is encrypted.
    pub async fn call(&self, opnum: u16, stub_data: Bytes) -> Result<Bytes> {
        if !self.is_bound {
            return Err(RpcError::CallRejected("not bound".to_string()));
        }

        let call_id = self.call_id_counter.fetch_add(1, Ordering::SeqCst);

        // Process stub data based on auth level
        let (processed_stub, auth_token) = if self.auth_level.requires_signing() {
            self.sign_or_seal_stub(&stub_data).await?
        } else {
            (stub_data.clone(), Bytes::new())
        };

        let mut request = if !auth_token.is_empty() {
            RequestPdu::new_authenticated(
                call_id,
                opnum,
                processed_stub,
                self.auth_type,
                self.auth_level,
                self.auth_context_id,
                auth_token,
            )
        } else {
            RequestPdu::new(call_id, opnum, processed_stub)
        };
        request.context_id = self.context_id;

        debug!(
            "Sending authenticated request: call_id={}, opnum={}, stub_len={}",
            call_id,
            opnum,
            request.stub_data.len()
        );

        // Send request
        {
            let mut write = self.write_transport.lock().await;
            write.write_pdu(&request.encode()).await?;
        }

        // Read response
        let pdu = {
            let mut read = self.read_transport.lock().await;
            read.read_pdu_decoded().await?
        };

        match pdu {
            Pdu::Response(response) => {
                if response.header.call_id != call_id {
                    return Err(RpcError::XidMismatch {
                        expected: call_id,
                        got: response.header.call_id,
                    });
                }

                // Verify/decrypt stub data if auth level requires it
                let result_stub = if self.auth_level.requires_signing() {
                    self.verify_or_unseal_stub(&response).await?
                } else {
                    response.stub_data
                };

                trace!("Authenticated call succeeded: {} bytes result", result_stub.len());

                Ok(result_stub)
            }
            Pdu::Fault(fault) => {
                if fault.header.call_id != call_id {
                    return Err(RpcError::XidMismatch {
                        expected: call_id,
                        got: fault.header.call_id,
                    });
                }

                Err(RpcError::CallRejected(format!(
                    "fault: status=0x{:08x}",
                    fault.status
                )))
            }
            _ => Err(RpcError::InvalidMessageType(0)),
        }
    }

    /// Sign or seal stub data based on auth level
    async fn sign_or_seal_stub(&self, stub_data: &Bytes) -> Result<(Bytes, Bytes)> {
        let security_ctx = self
            .security_context
            .as_ref()
            .ok_or_else(|| RpcError::CallRejected("no security context".to_string()))?;

        let mut ctx = security_ctx.lock().await;

        if self.auth_level.requires_encryption() {
            // Encrypt the stub data
            let (encrypted, signature) = ctx
                .encrypt(stub_data)
                .map_err(|e| RpcError::CallRejected(format!("encryption failed: {}", e)))?;
            Ok((encrypted, signature))
        } else if self.auth_level.requires_signing() {
            // Sign the stub data (data stays plaintext, signature appended)
            let signature = ctx
                .sign(stub_data)
                .map_err(|e| RpcError::CallRejected(format!("signing failed: {}", e)))?;
            Ok((stub_data.clone(), signature))
        } else {
            Ok((stub_data.clone(), Bytes::new()))
        }
    }

    /// Verify or unseal response stub data
    async fn verify_or_unseal_stub(&self, response: &ResponsePdu) -> Result<Bytes> {
        let security_ctx = self
            .security_context
            .as_ref()
            .ok_or_else(|| RpcError::CallRejected("no security context".to_string()))?;

        let mut ctx = security_ctx.lock().await;

        let auth_verifier = response
            .auth_verifier
            .as_ref()
            .ok_or_else(|| RpcError::CallRejected("missing auth verifier in response".to_string()))?;

        if self.auth_level.requires_encryption() {
            // Decrypt the stub data
            let plaintext = ctx
                .decrypt(&response.stub_data, &auth_verifier.auth_value)
                .map_err(|e| RpcError::CallRejected(format!("decryption failed: {}", e)))?;
            Ok(plaintext)
        } else if self.auth_level.requires_signing() {
            // Verify the signature
            ctx.verify(&response.stub_data, &auth_verifier.auth_value)
                .map_err(|e| RpcError::CallRejected(format!("signature verification failed: {}", e)))?;
            Ok(response.stub_data.clone())
        } else {
            Ok(response.stub_data.clone())
        }
    }

    /// Call operation 0 (typically a null/ping operation)
    pub async fn null_call(&self) -> Result<()> {
        self.call(0, Bytes::new()).await?;
        Ok(())
    }

    /// Get the interface UUID this client is bound to
    pub fn interface(&self) -> &SyntaxId {
        &self.interface
    }

    /// Check if the client is bound to the server
    pub fn is_bound(&self) -> bool {
        self.is_bound
    }

    /// Get the authentication type
    pub fn auth_type(&self) -> AuthType {
        self.auth_type
    }

    /// Get the authentication level
    pub fn auth_level(&self) -> AuthLevel {
        self.auth_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_levels() {
        assert!(!AuthLevel::None.requires_signing());
        assert!(!AuthLevel::None.requires_encryption());

        assert!(!AuthLevel::Connect.requires_signing());
        assert!(!AuthLevel::Connect.requires_encryption());

        assert!(AuthLevel::PktIntegrity.requires_signing());
        assert!(!AuthLevel::PktIntegrity.requires_encryption());

        assert!(AuthLevel::PktPrivacy.requires_signing());
        assert!(AuthLevel::PktPrivacy.requires_encryption());
    }
}
