//! DCE RPC Security Support (SSPI Integration)
//!
//! This module provides authentication and encryption support for DCE RPC
//! using the Windows Security Support Provider Interface (SSPI).
//!
//! Supports:
//! - NTLM authentication
//! - Kerberos authentication
//! - Negotiate (SPNEGO) authentication
//! - Message integrity (signing)
//! - Message privacy (encryption)
//!
//! Wire format follows MS-RPCE specification for auth_verifier.

use bytes::{BufMut, Bytes, BytesMut};

/// Authentication types (MS-RPCE Section 2.2.1.1.7)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    /// No authentication
    None = 0,
    /// OSF DCE private key authentication (deprecated)
    DcePrivate = 1,
    /// OSF DCE public key authentication (deprecated)
    DcePublic = 2,
    /// GSS Negotiate (SPNEGO)
    GssNegotiate = 9,
    /// Windows NT LAN Manager (NTLM)
    Ntlm = 10,
    /// GSS Kerberos (also known as DCE Kerberos, auth type 16)
    GssKerberos = 16,
    /// Netlogon secure channel
    Netlogon = 68,
}

impl AuthType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::DcePrivate),
            2 => Some(Self::DcePublic),
            9 => Some(Self::GssNegotiate),
            10 => Some(Self::Ntlm),
            16 => Some(Self::GssKerberos),
            68 => Some(Self::Netlogon),
            _ => None,
        }
    }

    /// Get the SSPI package name for this auth type
    pub fn sspi_package_name(&self) -> Option<&'static str> {
        match self {
            Self::GssNegotiate => Some("Negotiate"),
            Self::Ntlm => Some("NTLM"),
            Self::GssKerberos => Some("Kerberos"),
            _ => None,
        }
    }
}

/// Authentication levels (MS-RPCE Section 2.2.1.1.8)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuthLevel {
    /// No authentication
    None = 1,
    /// Connect-level authentication (authenticate at connection)
    Connect = 2,
    /// Call-level authentication (authenticate each call)
    Call = 3,
    /// Packet-level authentication (authenticate each packet)
    Pkt = 4,
    /// Packet integrity (sign each packet)
    PktIntegrity = 5,
    /// Packet privacy (encrypt each packet)
    PktPrivacy = 6,
}

impl AuthLevel {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::None),
            2 => Some(Self::Connect),
            3 => Some(Self::Call),
            4 => Some(Self::Pkt),
            5 => Some(Self::PktIntegrity),
            6 => Some(Self::PktPrivacy),
            _ => None,
        }
    }

    /// Returns true if this level requires message signing
    pub fn requires_signing(&self) -> bool {
        matches!(self, Self::PktIntegrity | Self::PktPrivacy)
    }

    /// Returns true if this level requires message encryption
    pub fn requires_encryption(&self) -> bool {
        matches!(self, Self::PktPrivacy)
    }
}

impl Default for AuthLevel {
    fn default() -> Self {
        Self::None
    }
}

/// Authentication verifier (appended to authenticated PDUs)
///
/// Wire format (MS-RPCE 2.2.2.11):
/// ```text
/// +------------------+
/// | auth_type (1)    |
/// +------------------+
/// | auth_level (1)   |
/// +------------------+
/// | auth_pad_len (1) |
/// +------------------+
/// | reserved (1)     |
/// +------------------+
/// | auth_context_id  |
/// | (4 bytes)        |
/// +------------------+
/// | auth_value       |
/// | (variable)       |
/// +------------------+
/// ```
#[derive(Debug, Clone)]
pub struct AuthVerifier {
    /// Authentication type
    pub auth_type: AuthType,
    /// Authentication level
    pub auth_level: AuthLevel,
    /// Number of padding bytes before this verifier
    pub auth_pad_length: u8,
    /// Reserved (must be zero)
    pub reserved: u8,
    /// Authentication context identifier
    pub auth_context_id: u32,
    /// Authentication token/credentials
    pub auth_value: Bytes,
}

impl AuthVerifier {
    /// Size of the fixed header portion (8 bytes)
    pub const HEADER_SIZE: usize = 8;

    pub fn new(
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_value: Bytes,
    ) -> Self {
        Self {
            auth_type,
            auth_level,
            auth_pad_length: 0,
            reserved: 0,
            auth_context_id,
            auth_value,
        }
    }

    /// Total size including header and auth value
    pub fn size(&self) -> usize {
        Self::HEADER_SIZE + self.auth_value.len()
    }

    /// Encode the auth verifier
    pub fn encode(&self, buf: &mut BytesMut, little_endian: bool) {
        buf.put_u8(self.auth_type as u8);
        buf.put_u8(self.auth_level as u8);
        buf.put_u8(self.auth_pad_length);
        buf.put_u8(self.reserved);
        if little_endian {
            buf.put_u32_le(self.auth_context_id);
        } else {
            buf.put_u32(self.auth_context_id);
        }
        buf.put_slice(&self.auth_value);
    }

    /// Decode an auth verifier from the end of a PDU
    pub fn decode(data: &[u8], auth_length: usize, little_endian: bool) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }

        let auth_type = AuthType::from_u8(data[0])?;
        let auth_level = AuthLevel::from_u8(data[1])?;
        let auth_pad_length = data[2];
        let reserved = data[3];
        let auth_context_id = if little_endian {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]])
        } else {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]])
        };

        let auth_value_len = auth_length.saturating_sub(Self::HEADER_SIZE);
        if data.len() < Self::HEADER_SIZE + auth_value_len {
            return None;
        }

        let auth_value = Bytes::copy_from_slice(&data[Self::HEADER_SIZE..Self::HEADER_SIZE + auth_value_len]);

        Some(Self {
            auth_type,
            auth_level,
            auth_pad_length,
            reserved,
            auth_context_id,
            auth_value,
        })
    }
}

/// Security context state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityContextState {
    /// Initial state, no security context established
    Initial,
    /// Authentication in progress (multi-leg)
    InProgress,
    /// Security context fully established
    Established,
    /// Security context has been invalidated
    Invalid,
}

/// Security context configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Authentication type to use
    pub auth_type: AuthType,
    /// Authentication level
    pub auth_level: AuthLevel,
    /// Target service principal name (for Kerberos)
    pub target_spn: Option<String>,
    /// Whether this is a client or server context
    pub is_client: bool,
}

impl SecurityConfig {
    /// Create a new client security configuration
    pub fn client(auth_type: AuthType, auth_level: AuthLevel) -> Self {
        Self {
            auth_type,
            auth_level,
            target_spn: None,
            is_client: true,
        }
    }

    /// Create a new server security configuration
    pub fn server(auth_type: AuthType, auth_level: AuthLevel) -> Self {
        Self {
            auth_type,
            auth_level,
            target_spn: None,
            is_client: false,
        }
    }

    /// Set the target SPN for Kerberos authentication
    pub fn with_spn(mut self, spn: impl Into<String>) -> Self {
        self.target_spn = Some(spn.into());
        self
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth_type: AuthType::None,
            auth_level: AuthLevel::None,
            target_spn: None,
            is_client: true,
        }
    }
}

/// Calculate the number of padding bytes needed to align stub data
/// before the auth verifier (must be aligned to 4 or 8 bytes depending on auth type)
pub fn calculate_auth_padding(stub_len: usize, auth_type: AuthType) -> usize {
    let alignment = match auth_type {
        // Most auth types require 4-byte alignment
        AuthType::Ntlm | AuthType::GssNegotiate | AuthType::GssKerberos => 4,
        // Some may require 8-byte alignment
        _ => 4,
    };
    let remainder = stub_len % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}

/// Maximum signature size for common auth types
pub fn max_signature_size(auth_type: AuthType) -> usize {
    match auth_type {
        AuthType::Ntlm => 16,          // NTLM signature is 16 bytes
        AuthType::GssNegotiate => 28,  // Negotiate can be larger
        AuthType::GssKerberos => 28,   // Kerberos signatures
        _ => 0,
    }
}

/// Maximum token size for initial auth negotiation
pub fn max_token_size(auth_type: AuthType) -> usize {
    match auth_type {
        AuthType::Ntlm => 2048,        // NTLM tokens are relatively small
        AuthType::GssNegotiate => 12288, // Negotiate tokens can be large (includes Kerberos tickets)
        AuthType::GssKerberos => 12288,  // Kerberos tickets can be large
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_type_from_u8() {
        assert_eq!(AuthType::from_u8(0), Some(AuthType::None));
        assert_eq!(AuthType::from_u8(9), Some(AuthType::GssNegotiate));
        assert_eq!(AuthType::from_u8(10), Some(AuthType::Ntlm));
        assert_eq!(AuthType::from_u8(16), Some(AuthType::GssKerberos));
        assert_eq!(AuthType::from_u8(255), None);
    }

    #[test]
    fn test_auth_level_ordering() {
        assert!(AuthLevel::None < AuthLevel::Connect);
        assert!(AuthLevel::Connect < AuthLevel::PktIntegrity);
        assert!(AuthLevel::PktIntegrity < AuthLevel::PktPrivacy);
    }

    #[test]
    fn test_auth_verifier_encode_decode() {
        let verifier = AuthVerifier::new(
            AuthType::Ntlm,
            AuthLevel::PktIntegrity,
            1,
            Bytes::from_static(b"test_token"),
        );

        let mut buf = BytesMut::new();
        verifier.encode(&mut buf, true);

        let decoded = AuthVerifier::decode(&buf, buf.len(), true).unwrap();
        assert_eq!(decoded.auth_type, AuthType::Ntlm);
        assert_eq!(decoded.auth_level, AuthLevel::PktIntegrity);
        assert_eq!(decoded.auth_context_id, 1);
        assert_eq!(decoded.auth_value.as_ref(), b"test_token");
    }

    #[test]
    fn test_calculate_auth_padding() {
        assert_eq!(calculate_auth_padding(0, AuthType::Ntlm), 0);
        assert_eq!(calculate_auth_padding(4, AuthType::Ntlm), 0);
        assert_eq!(calculate_auth_padding(1, AuthType::Ntlm), 3);
        assert_eq!(calculate_auth_padding(2, AuthType::Ntlm), 2);
        assert_eq!(calculate_auth_padding(3, AuthType::Ntlm), 1);
        assert_eq!(calculate_auth_padding(5, AuthType::Ntlm), 3);
    }
}
