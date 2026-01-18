//! String binding and dual string array types (MS-DCOM 2.2.19, 2.2.20)
//!
//! These structures represent RPC binding information for DCOM objects.

use bytes::{Buf, BufMut};
use std::fmt;

/// Protocol tower identifiers (from dcerpc EPM)
pub mod protocol_id {
    /// TCP/IP protocol
    pub const NCACN_IP_TCP: u16 = 0x07;
    /// Named pipes protocol
    pub const NCACN_NP: u16 = 0x0F;
    /// HTTP protocol
    pub const NCACN_HTTP: u16 = 0x1F;
    /// Local RPC
    pub const NCALRPC: u16 = 0x10;
}

/// String binding (MS-DCOM 2.2.19.2)
///
/// Represents a single RPC binding string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringBinding {
    /// Tower ID (protocol sequence)
    pub tower_id: u16,
    /// Network address string (null-terminated wide string)
    pub network_addr: String,
}

impl StringBinding {
    /// Create a new string binding
    pub fn new(tower_id: u16, network_addr: String) -> Self {
        Self {
            tower_id,
            network_addr,
        }
    }

    /// Create a TCP/IP binding
    pub fn tcp(addr: &str) -> Self {
        Self {
            tower_id: protocol_id::NCACN_IP_TCP,
            network_addr: addr.to_string(),
        }
    }

    /// Create a named pipe binding
    pub fn named_pipe(pipe_name: &str) -> Self {
        Self {
            tower_id: protocol_id::NCACN_NP,
            network_addr: pipe_name.to_string(),
        }
    }

    /// Encoded size in bytes
    pub fn encoded_size(&self) -> usize {
        // tower_id (2) + wstring (chars * 2 + null terminator * 2)
        2 + (self.network_addr.len() + 1) * 2
    }

    /// Encode to buffer as wide string
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u16_le(self.tower_id);
        } else {
            buf.put_u16(self.tower_id);
        }
        // Encode as null-terminated UTF-16LE string
        for ch in self.network_addr.encode_utf16() {
            if little_endian {
                buf.put_u16_le(ch);
            } else {
                buf.put_u16(ch);
            }
        }
        // Null terminator
        if little_endian {
            buf.put_u16_le(0);
        } else {
            buf.put_u16(0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < 4 {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let tower_id = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };

        // Read null-terminated UTF-16 string
        let mut chars = Vec::new();
        loop {
            if buf.remaining() < 2 {
                return Err(crate::types::DcomError::BufferUnderflow {
                    needed: 2,
                    have: buf.remaining(),
                });
            }
            let ch = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            if ch == 0 {
                break;
            }
            chars.push(ch);
        }

        let network_addr = String::from_utf16(&chars).map_err(|_| {
            crate::types::DcomError::InvalidStringBinding("invalid UTF-16 string".to_string())
        })?;

        Ok(Self {
            tower_id,
            network_addr,
        })
    }
}

impl fmt::Display for StringBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.tower_id {
            protocol_id::NCACN_IP_TCP => "ncacn_ip_tcp",
            protocol_id::NCACN_NP => "ncacn_np",
            protocol_id::NCACN_HTTP => "ncacn_http",
            protocol_id::NCALRPC => "ncalrpc",
            _ => "unknown",
        };
        write!(f, "{}:{}", proto, self.network_addr)
    }
}

/// Security binding (MS-DCOM 2.2.19.3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityBinding {
    /// Authentication service (NTLM, Kerberos, etc.)
    pub authn_svc: u16,
    /// Authorization service
    pub authz_svc: u16,
    /// Principal name
    pub principal_name: String,
}

impl SecurityBinding {
    /// Size of fixed fields
    pub const FIXED_SIZE: usize = 4;

    /// Create a new security binding
    pub fn new(authn_svc: u16, authz_svc: u16, principal_name: String) -> Self {
        Self {
            authn_svc,
            authz_svc,
            principal_name,
        }
    }

    /// Create with no authentication
    pub fn none() -> Self {
        Self {
            authn_svc: 0,
            authz_svc: 0,
            principal_name: String::new(),
        }
    }

    /// Encoded size in bytes
    pub fn encoded_size(&self) -> usize {
        Self::FIXED_SIZE + (self.principal_name.len() + 1) * 2
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        if little_endian {
            buf.put_u16_le(self.authn_svc);
            buf.put_u16_le(self.authz_svc);
        } else {
            buf.put_u16(self.authn_svc);
            buf.put_u16(self.authz_svc);
        }
        // Principal name as null-terminated UTF-16
        for ch in self.principal_name.encode_utf16() {
            if little_endian {
                buf.put_u16_le(ch);
            } else {
                buf.put_u16(ch);
            }
        }
        if little_endian {
            buf.put_u16_le(0);
        } else {
            buf.put_u16(0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::FIXED_SIZE {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::FIXED_SIZE,
                have: buf.remaining(),
            });
        }

        let authn_svc = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let authz_svc = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };

        // Read null-terminated UTF-16 string
        let mut chars = Vec::new();
        loop {
            if buf.remaining() < 2 {
                break;
            }
            let ch = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            if ch == 0 {
                break;
            }
            chars.push(ch);
        }

        let principal_name = String::from_utf16(&chars).map_err(|_| {
            crate::types::DcomError::InvalidStringBinding("invalid UTF-16 string".to_string())
        })?;

        Ok(Self {
            authn_svc,
            authz_svc,
            principal_name,
        })
    }
}

/// Dual String Array (MS-DCOM 2.2.19.1)
///
/// Contains both string bindings (network addresses) and security bindings.
/// This is the primary structure used to convey RPC binding information.
#[derive(Clone, Debug, Default)]
pub struct DualStringArray {
    /// Number of entries in string bindings (in u16 units)
    pub num_entries: u16,
    /// Offset to security bindings (in u16 units from start of aStringArray)
    pub security_offset: u16,
    /// String bindings (network addresses)
    pub string_bindings: Vec<StringBinding>,
    /// Security bindings
    pub security_bindings: Vec<SecurityBinding>,
}

impl DualStringArray {
    /// Fixed header size
    pub const HEADER_SIZE: usize = 4;

    /// Create a new empty dual string array
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a single TCP binding
    pub fn with_tcp_binding(addr: &str) -> Self {
        Self {
            num_entries: 0, // Will be calculated on encode
            security_offset: 0,
            string_bindings: vec![StringBinding::tcp(addr)],
            security_bindings: vec![],
        }
    }

    /// Add a string binding
    pub fn add_string_binding(&mut self, binding: StringBinding) {
        self.string_bindings.push(binding);
    }

    /// Add a security binding
    pub fn add_security_binding(&mut self, binding: SecurityBinding) {
        self.security_bindings.push(binding);
    }

    /// Calculate the encoded size
    pub fn encoded_size(&self) -> usize {
        let mut size = Self::HEADER_SIZE;
        for sb in &self.string_bindings {
            size += sb.encoded_size();
        }
        size += 2; // Null terminator between string and security bindings
        for sec in &self.security_bindings {
            size += sec.encoded_size();
        }
        size += 2; // Final null terminator
        size
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B, little_endian: bool) {
        // Calculate offsets
        let mut string_size = 0usize;
        for sb in &self.string_bindings {
            string_size += sb.encoded_size();
        }
        string_size += 2; // Null terminator

        let security_offset = string_size / 2;
        let mut total_size = string_size;
        for sec in &self.security_bindings {
            total_size += sec.encoded_size();
        }
        total_size += 2; // Final null terminator

        let num_entries = total_size / 2;

        // Write header
        if little_endian {
            buf.put_u16_le(num_entries as u16);
            buf.put_u16_le(security_offset as u16);
        } else {
            buf.put_u16(num_entries as u16);
            buf.put_u16(security_offset as u16);
        }

        // Write string bindings
        for sb in &self.string_bindings {
            sb.encode(buf, little_endian);
        }
        // Null terminator
        if little_endian {
            buf.put_u16_le(0);
        } else {
            buf.put_u16(0);
        }

        // Write security bindings
        for sec in &self.security_bindings {
            sec.encode(buf, little_endian);
        }
        // Final null terminator
        if little_endian {
            buf.put_u16_le(0);
        } else {
            buf.put_u16(0);
        }
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> crate::types::Result<Self> {
        if buf.remaining() < Self::HEADER_SIZE {
            return Err(crate::types::DcomError::BufferUnderflow {
                needed: Self::HEADER_SIZE,
                have: buf.remaining(),
            });
        }

        let num_entries = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };
        let security_offset = if little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        };

        let mut string_bindings = Vec::new();
        let mut security_bindings = Vec::new();

        // Read string bindings until we hit null terminator or security offset
        let mut current_offset = 0u16;
        while current_offset < security_offset.saturating_sub(1) && buf.remaining() >= 2 {
            let tower_id = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            current_offset += 1;

            if tower_id == 0 {
                // End of string bindings
                break;
            }

            // Read the network address
            let mut chars = Vec::new();
            loop {
                if buf.remaining() < 2 {
                    break;
                }
                let ch = if little_endian {
                    buf.get_u16_le()
                } else {
                    buf.get_u16()
                };
                current_offset += 1;
                if ch == 0 {
                    break;
                }
                chars.push(ch);
            }

            let network_addr = String::from_utf16(&chars).unwrap_or_default();
            string_bindings.push(StringBinding {
                tower_id,
                network_addr,
            });
        }

        // Skip to security offset if needed
        while current_offset < security_offset && buf.remaining() >= 2 {
            let _ = buf.get_u16_le();
            current_offset += 1;
        }

        // Read security bindings
        while current_offset < num_entries && buf.remaining() >= 4 {
            let authn_svc = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            current_offset += 1;

            if authn_svc == 0 {
                // End of security bindings
                break;
            }

            let authz_svc = if little_endian {
                buf.get_u16_le()
            } else {
                buf.get_u16()
            };
            current_offset += 1;

            // Read principal name
            let mut chars = Vec::new();
            loop {
                if buf.remaining() < 2 {
                    break;
                }
                let ch = if little_endian {
                    buf.get_u16_le()
                } else {
                    buf.get_u16()
                };
                current_offset += 1;
                if ch == 0 {
                    break;
                }
                chars.push(ch);
            }

            let principal_name = String::from_utf16(&chars).unwrap_or_default();
            security_bindings.push(SecurityBinding {
                authn_svc,
                authz_svc,
                principal_name,
            });
        }

        Ok(Self {
            num_entries,
            security_offset,
            string_bindings,
            security_bindings,
        })
    }
}

/// Authentication services
pub mod authn_svc {
    /// No authentication
    pub const NONE: u16 = 0;
    /// DCE private key authentication
    pub const DCE_PRIVATE: u16 = 1;
    /// DCE public key authentication
    pub const DCE_PUBLIC: u16 = 2;
    /// SPNEGO negotiation
    pub const GSS_NEGOTIATE: u16 = 9;
    /// NTLM authentication
    pub const WINNT: u16 = 10;
    /// Kerberos authentication
    pub const GSS_KERBEROS: u16 = 16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_string_binding_tcp() {
        let binding = StringBinding::tcp("192.168.1.1[1234]");
        assert_eq!(binding.tower_id, protocol_id::NCACN_IP_TCP);

        let mut buf = BytesMut::new();
        binding.encode(&mut buf, true);

        let decoded = StringBinding::decode(&mut buf.freeze(), true).unwrap();
        assert_eq!(binding, decoded);
    }

    #[test]
    fn test_dual_string_array() {
        let mut dsa = DualStringArray::new();
        dsa.add_string_binding(StringBinding::tcp("127.0.0.1"));
        dsa.add_security_binding(SecurityBinding::none());

        let mut buf = BytesMut::new();
        dsa.encode(&mut buf, true);

        let decoded = DualStringArray::decode(&mut buf.freeze(), true).unwrap();
        assert_eq!(decoded.string_bindings.len(), 1);
    }
}
