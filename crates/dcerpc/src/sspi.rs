//! Windows SSPI (Security Support Provider Interface) Integration
//!
//! This module provides wrappers around the Windows SSPI APIs for DCE RPC authentication.
//! It supports NTLM, Kerberos, and Negotiate (SPNEGO) authentication mechanisms.
//!
//! # Wire Compatibility
//!
//! This implementation is designed to be 100% wire compatible with native Windows
//! RPC servers and clients, following the MS-RPCE specification.

use crate::security::{AuthLevel, AuthType, SecurityContextState};
use bytes::Bytes;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use thiserror::Error;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED,
    SEC_I_CONTINUE_NEEDED,
};
use windows::Win32::Security::Authentication::Identity::{
    AcceptSecurityContext, AcquireCredentialsHandleW, CompleteAuthToken, DecryptMessage,
    DeleteSecurityContext, EncryptMessage, FreeContextBuffer, FreeCredentialsHandle,
    InitializeSecurityContextW, MakeSignature, QueryContextAttributesW, VerifySignature,
    SecBuffer, SecBufferDesc, SecPkgContext_Sizes,
    ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONFIDENTIALITY,
    ASC_REQ_INTEGRITY, ASC_REQ_REPLAY_DETECT, ASC_REQ_SEQUENCE_DETECT,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_INTEGRITY,
    ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT,
    SECBUFFER_DATA, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND,
};
use windows::Win32::Security::Credentials::SecHandle;

/// SSPI-related errors
#[derive(Debug, Error)]
pub enum SspiError {
    /// Failed to acquire credentials
    #[error("Failed to acquire credentials: {0}")]
    AcquireCredentials(String),

    /// Failed to initialize security context
    #[error("Failed to initialize security context: {0}")]
    InitializeContext(String),

    /// Failed to accept security context
    #[error("Failed to accept security context: {0}")]
    AcceptContext(String),

    /// Failed to complete authentication token
    #[error("Failed to complete auth token: {0}")]
    CompleteAuthToken(String),

    /// Failed to make signature
    #[error("Failed to make signature: {0}")]
    MakeSignature(String),

    /// Failed to verify signature
    #[error("Failed to verify signature: {0}")]
    VerifySignature(String),

    /// Failed to encrypt message
    #[error("Failed to encrypt message: {0}")]
    EncryptMessage(String),

    /// Failed to decrypt message
    #[error("Failed to decrypt message: {0}")]
    DecryptMessage(String),

    /// Failed to query context attributes
    #[error("Failed to query context: {0}")]
    QueryContext(String),

    /// Invalid state for operation
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Buffer too small
    #[error("Buffer too small: need {needed}, have {have}")]
    BufferTooSmall { needed: usize, have: usize },

    /// Unsupported auth type
    #[error("Unsupported auth type: {0:?}")]
    UnsupportedAuthType(AuthType),
}

/// Result type for SSPI operations
pub type SspiResult<T> = std::result::Result<T, SspiError>;

/// Security context sizes for buffer allocation
#[derive(Debug, Clone, Copy)]
pub struct ContextSizes {
    /// Maximum token size
    pub max_token: u32,
    /// Maximum signature size
    pub max_signature: u32,
    /// Block size for encryption
    pub block_size: u32,
    /// Security trailer size
    pub security_trailer: u32,
}

/// SSPI security context wrapper
///
/// This provides a safe Rust wrapper around Windows SSPI security contexts
/// for use with DCE RPC authentication.
pub struct SspiContext {
    /// Credentials handle
    cred_handle: SecHandle,
    /// Security context handle
    ctx_handle: Option<SecHandle>,
    /// Current state
    state: SecurityContextState,
    /// Authentication type
    auth_type: AuthType,
    /// Authentication level
    auth_level: AuthLevel,
    /// Whether this is a client context
    is_client: bool,
    /// Context sizes (populated after context is established)
    sizes: Option<ContextSizes>,
    /// Sequence number for signing/sealing
    sequence_number: u32,
}

impl SspiContext {
    /// Create a new client security context
    ///
    /// # Arguments
    /// * `auth_type` - Type of authentication (NTLM, Negotiate, Kerberos)
    /// * `auth_level` - Level of authentication (Connect, Integrity, Privacy)
    /// * `target_spn` - Target service principal name (required for Kerberos)
    pub fn new_client(
        auth_type: AuthType,
        auth_level: AuthLevel,
        _target_spn: Option<&str>,
    ) -> SspiResult<Self> {
        let package_name = auth_type
            .sspi_package_name()
            .ok_or_else(|| SspiError::UnsupportedAuthType(auth_type))?;

        let cred_handle = acquire_credentials(package_name, true)?;

        Ok(Self {
            cred_handle,
            ctx_handle: None,
            state: SecurityContextState::Initial,
            auth_type,
            auth_level,
            is_client: true,
            sizes: None,
            sequence_number: 0,
        })
    }

    /// Create a new server security context
    ///
    /// # Arguments
    /// * `auth_type` - Type of authentication (NTLM, Negotiate, Kerberos)
    /// * `auth_level` - Level of authentication (Connect, Integrity, Privacy)
    pub fn new_server(auth_type: AuthType, auth_level: AuthLevel) -> SspiResult<Self> {
        let package_name = auth_type
            .sspi_package_name()
            .ok_or_else(|| SspiError::UnsupportedAuthType(auth_type))?;

        let cred_handle = acquire_credentials(package_name, false)?;

        Ok(Self {
            cred_handle,
            ctx_handle: None,
            state: SecurityContextState::Initial,
            auth_type,
            auth_level,
            is_client: false,
            sizes: None,
            sequence_number: 0,
        })
    }

    /// Get the current state of the security context
    pub fn state(&self) -> SecurityContextState {
        self.state
    }

    /// Check if the security context is fully established
    pub fn is_established(&self) -> bool {
        self.state == SecurityContextState::Established
    }

    /// Get the authentication type
    pub fn auth_type(&self) -> AuthType {
        self.auth_type
    }

    /// Initialize the client security context (first leg)
    ///
    /// Returns the output token to send to the server
    pub fn initialize(&mut self, target_spn: Option<&str>) -> SspiResult<Bytes> {
        if !self.is_client {
            return Err(SspiError::InvalidState(
                "Cannot initialize on server context".into(),
            ));
        }

        if self.state != SecurityContextState::Initial {
            return Err(SspiError::InvalidState(format!(
                "Context in wrong state: {:?}",
                self.state
            )));
        }

        let (token, new_ctx, continue_needed) =
            initialize_security_context(&self.cred_handle, None, target_spn, self.auth_level)?;

        self.ctx_handle = Some(new_ctx);

        if continue_needed {
            self.state = SecurityContextState::InProgress;
        } else {
            self.state = SecurityContextState::Established;
            self.query_sizes()?;
        }

        Ok(token)
    }

    /// Continue client authentication with server's response
    ///
    /// Returns the output token to send to the server (if any)
    pub fn continue_client(&mut self, input_token: &[u8]) -> SspiResult<Option<Bytes>> {
        if !self.is_client {
            return Err(SspiError::InvalidState(
                "Cannot call continue_client on server context".into(),
            ));
        }

        if self.state != SecurityContextState::InProgress {
            return Err(SspiError::InvalidState(format!(
                "Context in wrong state: {:?}",
                self.state
            )));
        }

        let (token, new_ctx, continue_needed) = continue_security_context(
            &self.cred_handle,
            self.ctx_handle.as_ref(),
            input_token,
            self.auth_level,
        )?;

        self.ctx_handle = Some(new_ctx);

        if continue_needed {
            Ok(Some(token))
        } else {
            self.state = SecurityContextState::Established;
            self.query_sizes()?;
            if token.is_empty() {
                Ok(None)
            } else {
                Ok(Some(token))
            }
        }
    }

    /// Accept an incoming security context (server side)
    ///
    /// Returns the output token to send to the client (if any)
    pub fn accept(&mut self, input_token: &[u8]) -> SspiResult<Option<Bytes>> {
        if self.is_client {
            return Err(SspiError::InvalidState(
                "Cannot accept on client context".into(),
            ));
        }

        let (token, new_ctx, continue_needed) = accept_security_context(
            &self.cred_handle,
            self.ctx_handle.as_ref(),
            input_token,
            self.auth_level,
        )?;

        self.ctx_handle = Some(new_ctx);

        if continue_needed {
            self.state = SecurityContextState::InProgress;
            Ok(Some(token))
        } else {
            self.state = SecurityContextState::Established;
            self.query_sizes()?;
            if token.is_empty() {
                Ok(None)
            } else {
                Ok(Some(token))
            }
        }
    }

    /// Sign a message (make signature)
    ///
    /// Returns the signature to append to the message
    pub fn sign(&mut self, message: &[u8]) -> SspiResult<Bytes> {
        if !self.is_established() {
            return Err(SspiError::InvalidState("Context not established".into()));
        }

        if !self.auth_level.requires_signing() {
            return Err(SspiError::InvalidState(
                "Auth level does not require signing".into(),
            ));
        }

        let ctx = self
            .ctx_handle
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("No context handle".into()))?;
        let sizes = self
            .sizes
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("Sizes not queried".into()))?;

        let signature = make_signature(ctx, message, sizes.max_signature as usize)?;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok(signature)
    }

    /// Verify a message signature
    pub fn verify(&mut self, message: &[u8], signature: &[u8]) -> SspiResult<()> {
        if !self.is_established() {
            return Err(SspiError::InvalidState("Context not established".into()));
        }

        let ctx = self
            .ctx_handle
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("No context handle".into()))?;

        verify_signature(ctx, message, signature)?;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok(())
    }

    /// Encrypt a message (seal)
    ///
    /// Returns (encrypted_data, signature) pair
    pub fn encrypt(&mut self, message: &[u8]) -> SspiResult<(Bytes, Bytes)> {
        if !self.is_established() {
            return Err(SspiError::InvalidState("Context not established".into()));
        }

        if !self.auth_level.requires_encryption() {
            return Err(SspiError::InvalidState(
                "Auth level does not require encryption".into(),
            ));
        }

        let ctx = self
            .ctx_handle
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("No context handle".into()))?;
        let sizes = self
            .sizes
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("Sizes not queried".into()))?;

        let (encrypted, signature) = encrypt_message(
            ctx,
            message,
            sizes.max_signature as usize,
            sizes.security_trailer as usize,
        )?;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok((encrypted, signature))
    }

    /// Decrypt a message (unseal)
    ///
    /// Returns the decrypted plaintext
    pub fn decrypt(&mut self, encrypted: &[u8], signature: &[u8]) -> SspiResult<Bytes> {
        if !self.is_established() {
            return Err(SspiError::InvalidState("Context not established".into()));
        }

        let ctx = self
            .ctx_handle
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("No context handle".into()))?;

        let plaintext = decrypt_message(ctx, encrypted, signature)?;
        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok(plaintext)
    }

    /// Get context sizes for buffer allocation
    pub fn sizes(&self) -> Option<&ContextSizes> {
        self.sizes.as_ref()
    }

    /// Query and cache the context sizes
    fn query_sizes(&mut self) -> SspiResult<()> {
        let ctx = self
            .ctx_handle
            .as_ref()
            .ok_or_else(|| SspiError::InvalidState("No context handle".into()))?;

        self.sizes = Some(query_context_sizes(ctx)?);
        Ok(())
    }
}

impl Drop for SspiContext {
    fn drop(&mut self) {
        // Clean up security context
        if let Some(ref mut ctx) = self.ctx_handle {
            unsafe {
                let _ = DeleteSecurityContext(ctx);
            }
        }

        // Clean up credentials handle
        unsafe {
            let _ = FreeCredentialsHandle(&mut self.cred_handle);
        }
    }
}

// Helper function to convert a string to a null-terminated wide string
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Acquire credentials for the specified security package
fn acquire_credentials(package_name: &str, is_client: bool) -> SspiResult<SecHandle> {
    let package_wide = to_wide_string(package_name);
    let mut cred_handle = SecHandle::default();
    let mut expiry: i64 = 0;

    let cred_use = if is_client {
        SECPKG_CRED_OUTBOUND
    } else {
        SECPKG_CRED_INBOUND
    };

    let status = unsafe {
        AcquireCredentialsHandleW(
            PCWSTR::null(),                     // Principal (use current user)
            PCWSTR(package_wide.as_ptr()),      // Package name
            cred_use,                           // Usage
            None,                               // LogonId
            None,                               // AuthData
            None,                               // GetKeyFn
            None,                               // GetKeyArgument
            &mut cred_handle,                   // Credential handle
            Some(&mut expiry),                  // Expiry
        )
    };

    if status.is_err() {
        return Err(SspiError::AcquireCredentials(format!(
            "AcquireCredentialsHandle failed: {:?}",
            status
        )));
    }

    Ok(cred_handle)
}

/// Initialize a client security context
fn initialize_security_context(
    cred_handle: &SecHandle,
    ctx_handle: Option<&SecHandle>,
    target_spn: Option<&str>,
    auth_level: AuthLevel,
) -> SspiResult<(Bytes, SecHandle, bool)> {
    let target_wide = target_spn.map(to_wide_string);
    let target_ptr = target_wide
        .as_ref()
        .map(|w| w.as_ptr())
        .unwrap_or(std::ptr::null());

    // Build context requirements based on auth level
    let mut context_req = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;

    if auth_level.requires_signing() {
        context_req |= ISC_REQ_INTEGRITY;
    }
    if auth_level.requires_encryption() {
        context_req |= ISC_REQ_CONFIDENTIALITY;
    }

    // Output buffer
    let mut out_buffer = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut out_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buffer,
    };

    let mut new_ctx = SecHandle::default();
    let mut context_attr: u32 = 0;
    let mut expiry: i64 = 0;

    // Convert Option<&SecHandle> to Option<*const SecHandle>
    let ctx_ptr = ctx_handle.map(|h| h as *const SecHandle);

    let status = unsafe {
        InitializeSecurityContextW(
            Some(cred_handle as *const SecHandle),
            ctx_ptr,
            Some(target_ptr),
            context_req,
            0,
            0, // Native endian
            None,
            0,
            Some(&mut new_ctx as *mut SecHandle),
            Some(&mut out_desc),
            &mut context_attr as *mut u32,
            Some(&mut expiry),
        )
    };

    // Get output token
    let token = if !out_buffer.pvBuffer.is_null() && out_buffer.cbBuffer > 0 {
        let slice = unsafe {
            std::slice::from_raw_parts(out_buffer.pvBuffer as *const u8, out_buffer.cbBuffer as usize)
        };
        let bytes = Bytes::copy_from_slice(slice);
        unsafe {
            let _ = FreeContextBuffer(out_buffer.pvBuffer);
        }
        bytes
    } else {
        Bytes::new()
    };

    match status {
        SEC_E_OK => Ok((token, new_ctx, false)),
        SEC_I_CONTINUE_NEEDED => Ok((token, new_ctx, true)),
        SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
            // Need to call CompleteAuthToken
            let mut complete_buffer = SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_ptr() as *mut _,
            };
            let mut complete_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut complete_buffer,
            };

            let complete_status = unsafe { CompleteAuthToken(&mut new_ctx, &mut complete_desc) };

            if complete_status.is_err() {
                return Err(SspiError::CompleteAuthToken(format!(
                    "CompleteAuthToken failed: {:?}",
                    complete_status
                )));
            }

            Ok((token, new_ctx, status == SEC_I_COMPLETE_AND_CONTINUE))
        }
        _ => Err(SspiError::InitializeContext(format!(
            "InitializeSecurityContext failed: {:?}",
            status
        ))),
    }
}

/// Continue a client security context with input token
fn continue_security_context(
    cred_handle: &SecHandle,
    ctx_handle: Option<&SecHandle>,
    input_token: &[u8],
    auth_level: AuthLevel,
) -> SspiResult<(Bytes, SecHandle, bool)> {
    // Build context requirements based on auth level
    let mut context_req = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;

    if auth_level.requires_signing() {
        context_req |= ISC_REQ_INTEGRITY;
    }
    if auth_level.requires_encryption() {
        context_req |= ISC_REQ_CONFIDENTIALITY;
    }

    // Input buffer
    let mut in_buffer = SecBuffer {
        cbBuffer: input_token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: input_token.as_ptr() as *mut _,
    };
    let in_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut in_buffer,
    };

    // Output buffer
    let mut out_buffer = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut out_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buffer,
    };

    let mut new_ctx = SecHandle::default();
    let mut context_attr: u32 = 0;
    let mut expiry: i64 = 0;

    // Convert Option<&SecHandle> to Option<*const SecHandle>
    let ctx_ptr = ctx_handle.map(|h| h as *const SecHandle);

    let status = unsafe {
        InitializeSecurityContextW(
            Some(cred_handle as *const SecHandle),
            ctx_ptr,
            None,
            context_req,
            0,
            0,
            Some(&in_desc),
            0,
            Some(&mut new_ctx as *mut SecHandle),
            Some(&mut out_desc),
            &mut context_attr as *mut u32,
            Some(&mut expiry),
        )
    };

    // Get output token
    let token = if !out_buffer.pvBuffer.is_null() && out_buffer.cbBuffer > 0 {
        let slice = unsafe {
            std::slice::from_raw_parts(out_buffer.pvBuffer as *const u8, out_buffer.cbBuffer as usize)
        };
        let bytes = Bytes::copy_from_slice(slice);
        unsafe {
            let _ = FreeContextBuffer(out_buffer.pvBuffer);
        }
        bytes
    } else {
        Bytes::new()
    };

    match status {
        SEC_E_OK => Ok((token, new_ctx, false)),
        SEC_I_CONTINUE_NEEDED => Ok((token, new_ctx, true)),
        _ => Err(SspiError::InitializeContext(format!(
            "InitializeSecurityContext (continue) failed: {:?}",
            status
        ))),
    }
}

/// Accept a server security context
fn accept_security_context(
    cred_handle: &SecHandle,
    ctx_handle: Option<&SecHandle>,
    input_token: &[u8],
    auth_level: AuthLevel,
) -> SspiResult<(Bytes, SecHandle, bool)> {
    // Input buffer
    let mut in_buffer = SecBuffer {
        cbBuffer: input_token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: input_token.as_ptr() as *mut _,
    };
    let in_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut in_buffer,
    };

    // Build context requirements
    let mut context_req = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT;

    if auth_level.requires_signing() {
        context_req |= ASC_REQ_INTEGRITY;
    }
    if auth_level.requires_encryption() {
        context_req |= ASC_REQ_CONFIDENTIALITY;
    }

    // Output buffer
    let mut out_buffer = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut out_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buffer,
    };

    let mut new_ctx = SecHandle::default();
    let mut context_attr: u32 = 0;
    let mut expiry: i64 = 0;

    // Convert Option<&SecHandle> to Option<*const SecHandle>
    let ctx_ptr = ctx_handle.map(|h| h as *const SecHandle);

    let status = unsafe {
        AcceptSecurityContext(
            Some(cred_handle as *const SecHandle),
            ctx_ptr,
            Some(&in_desc),
            context_req,
            0,
            Some(&mut new_ctx as *mut SecHandle),
            Some(&mut out_desc),
            &mut context_attr as *mut u32,
            Some(&mut expiry),
        )
    };

    // Get output token
    let token = if !out_buffer.pvBuffer.is_null() && out_buffer.cbBuffer > 0 {
        let slice = unsafe {
            std::slice::from_raw_parts(out_buffer.pvBuffer as *const u8, out_buffer.cbBuffer as usize)
        };
        let bytes = Bytes::copy_from_slice(slice);
        unsafe {
            let _ = FreeContextBuffer(out_buffer.pvBuffer);
        }
        bytes
    } else {
        Bytes::new()
    };

    match status {
        SEC_E_OK => Ok((token, new_ctx, false)),
        SEC_I_CONTINUE_NEEDED => Ok((token, new_ctx, true)),
        SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
            // Need to call CompleteAuthToken
            let mut complete_buffer = SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_ptr() as *mut _,
            };
            let mut complete_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut complete_buffer,
            };

            let complete_status = unsafe { CompleteAuthToken(&mut new_ctx, &mut complete_desc) };

            if complete_status.is_err() {
                return Err(SspiError::CompleteAuthToken(format!(
                    "CompleteAuthToken failed: {:?}",
                    complete_status
                )));
            }

            Ok((token, new_ctx, status == SEC_I_COMPLETE_AND_CONTINUE))
        }
        _ => Err(SspiError::AcceptContext(format!(
            "AcceptSecurityContext failed: {:?}",
            status
        ))),
    }
}

/// Query context sizes
fn query_context_sizes(ctx: &SecHandle) -> SspiResult<ContextSizes> {
    let mut sizes = SecPkgContext_Sizes::default();

    let status = unsafe {
        QueryContextAttributesW(
            ctx,
            windows::Win32::Security::Authentication::Identity::SECPKG_ATTR_SIZES,
            &mut sizes as *mut _ as *mut _,
        )
    };

    if status.is_err() {
        return Err(SspiError::QueryContext(format!(
            "QueryContextAttributes(SIZES) failed: {:?}",
            status
        )));
    }

    Ok(ContextSizes {
        max_token: sizes.cbMaxToken,
        max_signature: sizes.cbMaxSignature,
        block_size: sizes.cbBlockSize,
        security_trailer: sizes.cbSecurityTrailer,
    })
}

/// Sign a message
fn make_signature(ctx: &SecHandle, message: &[u8], signature_size: usize) -> SspiResult<Bytes> {
    let mut signature_buffer = vec![0u8; signature_size];

    let mut buffers = [
        SecBuffer {
            cbBuffer: signature_buffer.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: signature_buffer.as_mut_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: message.len() as u32,
            BufferType: SECBUFFER_DATA,
            pvBuffer: message.as_ptr() as *mut _,
        },
    ];

    let mut desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 2,
        pBuffers: buffers.as_mut_ptr(),
    };

    let status = unsafe { MakeSignature(ctx, 0, &mut desc, 0) };

    if status.is_err() {
        return Err(SspiError::MakeSignature(format!(
            "MakeSignature failed: {:?}",
            status
        )));
    }

    // Get actual signature size
    let actual_size = buffers[0].cbBuffer as usize;
    signature_buffer.truncate(actual_size);

    Ok(Bytes::from(signature_buffer))
}

/// Verify a message signature
fn verify_signature(ctx: &SecHandle, message: &[u8], signature: &[u8]) -> SspiResult<()> {
    let mut buffers = [
        SecBuffer {
            cbBuffer: signature.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: signature.as_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: message.len() as u32,
            BufferType: SECBUFFER_DATA,
            pvBuffer: message.as_ptr() as *mut _,
        },
    ];

    let mut desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 2,
        pBuffers: buffers.as_mut_ptr(),
    };

    let status = unsafe { VerifySignature(ctx, &mut desc, 0) };

    if status.is_err() {
        return Err(SspiError::VerifySignature(format!(
            "VerifySignature failed: {:?}",
            status
        )));
    }

    Ok(())
}

/// Encrypt a message
fn encrypt_message(
    ctx: &SecHandle,
    message: &[u8],
    signature_size: usize,
    trailer_size: usize,
) -> SspiResult<(Bytes, Bytes)> {
    let mut signature_buffer = vec![0u8; signature_size];
    let mut data_buffer = message.to_vec();
    let mut trailer_buffer = vec![0u8; trailer_size];

    let mut buffers = [
        SecBuffer {
            cbBuffer: signature_buffer.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: signature_buffer.as_mut_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: data_buffer.len() as u32,
            BufferType: SECBUFFER_DATA,
            pvBuffer: data_buffer.as_mut_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: trailer_buffer.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: trailer_buffer.as_mut_ptr() as *mut _,
        },
    ];

    let mut desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 3,
        pBuffers: buffers.as_mut_ptr(),
    };

    let status = unsafe { EncryptMessage(ctx, 0, &mut desc, 0) };

    if status.is_err() {
        return Err(SspiError::EncryptMessage(format!(
            "EncryptMessage failed: {:?}",
            status
        )));
    }

    // Combine signature and trailer into signature output
    let actual_sig_size = buffers[0].cbBuffer as usize;
    let actual_trailer_size = buffers[2].cbBuffer as usize;
    signature_buffer.truncate(actual_sig_size);
    trailer_buffer.truncate(actual_trailer_size);

    // For DCE RPC, the auth_value contains the signature
    let mut combined_signature = Vec::with_capacity(actual_sig_size + actual_trailer_size);
    combined_signature.extend_from_slice(&signature_buffer);
    combined_signature.extend_from_slice(&trailer_buffer);

    Ok((Bytes::from(data_buffer), Bytes::from(combined_signature)))
}

/// Decrypt a message
fn decrypt_message(ctx: &SecHandle, encrypted: &[u8], signature: &[u8]) -> SspiResult<Bytes> {
    let mut data_buffer = encrypted.to_vec();

    let mut buffers = [
        SecBuffer {
            cbBuffer: signature.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: signature.as_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: data_buffer.len() as u32,
            BufferType: SECBUFFER_DATA,
            pvBuffer: data_buffer.as_mut_ptr() as *mut _,
        },
    ];

    let mut desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 2,
        pBuffers: buffers.as_mut_ptr(),
    };

    let status = unsafe { DecryptMessage(ctx, &mut desc, 0, None) };

    if status.is_err() {
        return Err(SspiError::DecryptMessage(format!(
            "DecryptMessage failed: {:?}",
            status
        )));
    }

    let actual_size = buffers[1].cbBuffer as usize;
    data_buffer.truncate(actual_size);

    Ok(Bytes::from(data_buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sspi_context_creation() {
        // Test creating a client context with NTLM
        let result = SspiContext::new_client(AuthType::Ntlm, AuthLevel::Connect, None);
        assert!(result.is_ok(), "Failed to create NTLM client context");

        let ctx = result.unwrap();
        assert_eq!(ctx.state(), SecurityContextState::Initial);
        assert!(!ctx.is_established());
    }

    #[test]
    fn test_sspi_negotiate_context() {
        // Test creating a client context with Negotiate
        let result = SspiContext::new_client(AuthType::GssNegotiate, AuthLevel::PktIntegrity, None);
        assert!(result.is_ok(), "Failed to create Negotiate client context");
    }

    #[test]
    fn test_unsupported_auth_type() {
        // Test that unsupported auth types return an error
        let result = SspiContext::new_client(AuthType::None, AuthLevel::Connect, None);
        assert!(result.is_err());
    }
}
