//! IActivation wire protocol (MS-DCOM 3.1.2.5.2.3)
//!
//! Defines the NDR-encoded structures for object activation.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::types::{
    DcomError, Result, Ipid, Oxid,
    DualStringArray, ComVersion, OrpcThis, OrpcThat, StdObjRef,
    decode_uuid, encode_uuid,
};

/// IActivation interface UUID
pub const ACTIVATION_UUID: &str = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57";

/// IRemoteSCMActivator interface UUID
pub const REMOTE_SCM_ACTIVATOR_UUID: &str = "000001a0-0000-0000-c000-000000000046";

/// IActivation interface version
pub const ACTIVATION_VERSION: (u16, u16) = (0, 0);

/// Operation numbers for IActivation
pub mod opnum {
    /// RemoteActivation
    pub const REMOTE_ACTIVATION: u16 = 0;
}

/// Activation mode flags
pub mod mode {
    /// Create new instance
    pub const CLSCTX_LOCAL_SERVER: u32 = 0x00000004;
    /// Create remote instance
    pub const CLSCTX_REMOTE_SERVER: u32 = 0x00000010;
    /// No failure log
    pub const CLSCTX_NO_FAILURE_LOG: u32 = 0x04000000;
}

/// Activation property structure
#[derive(Clone, Debug)]
pub struct ActivationProperty {
    /// Property ID
    pub property_id: u32,
    /// Property data
    pub data: Bytes,
}

impl ActivationProperty {
    /// Create a new activation property
    pub fn new(property_id: u32, data: Bytes) -> Self {
        Self { property_id, data }
    }
}

/// COSERVERINFO structure (MS-DCOM 2.2.22)
#[derive(Clone, Debug, Default)]
pub struct CoServerInfo {
    /// Reserved
    pub reserved1: u32,
    /// Server name
    pub server_name: String,
    /// Authentication info (optional)
    pub auth_info: Option<AuthInfo>,
    /// Reserved
    pub reserved2: u32,
}

impl CoServerInfo {
    /// Create with server name
    pub fn with_server(server_name: String) -> Self {
        Self {
            reserved1: 0,
            server_name,
            auth_info: None,
            reserved2: 0,
        }
    }
}

/// COAUTHINFO structure
#[derive(Clone, Debug)]
pub struct AuthInfo {
    /// Authentication service
    pub authn_svc: u32,
    /// Authorization service
    pub authz_svc: u32,
    /// Server principal name
    pub server_principal: String,
    /// Authentication level
    pub authn_level: u32,
    /// Impersonation level
    pub impersonation_level: u32,
    /// Authentication identity (optional)
    pub auth_identity: Option<Vec<u8>>,
    /// Capabilities
    pub capabilities: u32,
}

/// RemoteActivation request (MS-DCOM 3.1.2.5.2.3.1)
#[derive(Clone, Debug)]
pub struct RemoteActivationRequest {
    /// ORPC header
    pub orpc_this: OrpcThis,
    /// CLSID to activate
    pub clsid: dcerpc::Uuid,
    /// Object name (for activation by name)
    pub object_name: Option<String>,
    /// Storage object (for file activation)
    pub object_storage: Option<Bytes>,
    /// Client impersonation level
    pub client_imp_level: u32,
    /// Activation mode
    pub mode: u32,
    /// Number of interfaces requested
    pub interfaces_count: u32,
    /// Requested interface IIDs
    pub interfaces: Vec<dcerpc::Uuid>,
    /// Client COM version
    pub client_version: ComVersion,
}

impl RemoteActivationRequest {
    /// Create a basic activation request
    pub fn new(clsid: dcerpc::Uuid, interfaces: Vec<dcerpc::Uuid>) -> Self {
        Self {
            orpc_this: OrpcThis::new(),
            clsid,
            object_name: None,
            object_storage: None,
            client_imp_level: 2, // RPC_C_IMP_LEVEL_IDENTIFY
            mode: mode::CLSCTX_REMOTE_SERVER,
            interfaces_count: interfaces.len() as u32,
            interfaces,
            client_version: ComVersion::DCOM_5_7,
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_this.encode(&mut buf, little_endian);
        encode_uuid(&self.clsid, &mut buf, little_endian);

        // Object name (null pointer for now)
        if little_endian {
            buf.put_u32_le(0); // null pointer
        } else {
            buf.put_u32(0);
        }

        // Object storage (null pointer for now)
        if little_endian {
            buf.put_u32_le(0); // null pointer
        } else {
            buf.put_u32(0);
        }

        // Client imp level
        if little_endian {
            buf.put_u32_le(self.client_imp_level);
        } else {
            buf.put_u32(self.client_imp_level);
        }

        // Mode
        if little_endian {
            buf.put_u32_le(self.mode);
        } else {
            buf.put_u32(self.mode);
        }

        // Interfaces count and array
        if little_endian {
            buf.put_u32_le(self.interfaces_count);
        } else {
            buf.put_u32(self.interfaces_count);
        }

        for iid in &self.interfaces {
            encode_uuid(iid, &mut buf, little_endian);
        }

        // Client version
        self.client_version.encode(&mut buf, little_endian);

        buf.freeze()
    }

    /// Decode from buffer
    pub fn decode<B: Buf>(buf: &mut B, little_endian: bool) -> Result<Self> {
        let orpc_this = OrpcThis::decode(buf, little_endian)?;
        let clsid = decode_uuid(buf, little_endian);

        // Skip object name pointer
        if buf.remaining() < 8 {
            return Err(DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }
        let _obj_name_ptr = buf.get_u32_le();
        let _obj_storage_ptr = buf.get_u32_le();

        if buf.remaining() < 12 {
            return Err(DcomError::BufferUnderflow {
                needed: 12,
                have: buf.remaining(),
            });
        }

        let client_imp_level = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let mode = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };
        let interfaces_count = if little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        };

        let mut interfaces = Vec::with_capacity(interfaces_count as usize);
        for _ in 0..interfaces_count {
            if buf.remaining() < 16 {
                break;
            }
            interfaces.push(decode_uuid(buf, little_endian));
        }

        let client_version = if buf.remaining() >= 4 {
            ComVersion::decode(buf, little_endian)
        } else {
            ComVersion::DCOM_5_7
        };

        Ok(Self {
            orpc_this,
            clsid,
            object_name: None,
            object_storage: None,
            client_imp_level,
            mode,
            interfaces_count,
            interfaces,
            client_version,
        })
    }
}

/// Interface result for activation
#[derive(Clone, Debug)]
pub struct InterfaceResult {
    /// HRESULT for this interface
    pub hresult: u32,
    /// Standard object reference (if successful)
    pub std: Option<StdObjRef>,
}

impl InterfaceResult {
    /// Create a successful result
    pub fn success(std: StdObjRef) -> Self {
        Self {
            hresult: 0,
            std: Some(std),
        }
    }

    /// Create a failure result
    pub fn failure(hresult: u32) -> Self {
        Self { hresult, std: None }
    }
}

/// RemoteActivation response
#[derive(Clone, Debug)]
pub struct RemoteActivationResponse {
    /// ORPC response header
    pub orpc_that: OrpcThat,
    /// Object exporter ID
    pub oxid: Oxid,
    /// Dual string array with bindings
    pub dsa: DualStringArray,
    /// IPID for IRemUnknown
    pub ipid_rem_unknown: Ipid,
    /// Authentication hint
    pub authn_hint: u32,
    /// Server COM version
    pub server_version: ComVersion,
    /// Overall HRESULT
    pub hresult: u32,
    /// Interface results
    pub interface_results: Vec<InterfaceResult>,
}

impl RemoteActivationResponse {
    /// Create a successful response
    pub fn success(
        oxid: Oxid,
        dsa: DualStringArray,
        ipid_rem_unknown: Ipid,
        interface_results: Vec<InterfaceResult>,
    ) -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            oxid,
            dsa,
            ipid_rem_unknown,
            authn_hint: 0,
            server_version: ComVersion::DCOM_5_7,
            hresult: 0,
            interface_results,
        }
    }

    /// Create a failure response
    pub fn failure(hresult: u32) -> Self {
        Self {
            orpc_that: OrpcThat::new(),
            oxid: Oxid::default(),
            dsa: DualStringArray::new(),
            ipid_rem_unknown: Ipid::nil(),
            authn_hint: 0,
            server_version: ComVersion::DCOM_5_7,
            hresult,
            interface_results: vec![],
        }
    }

    /// Encode to buffer
    pub fn encode(&self, little_endian: bool) -> Bytes {
        let mut buf = BytesMut::new();
        self.orpc_that.encode(&mut buf, little_endian);
        self.oxid.encode(&mut buf, little_endian);
        self.dsa.encode(&mut buf, little_endian);
        self.ipid_rem_unknown.encode(&mut buf, little_endian);

        if little_endian {
            buf.put_u32_le(self.authn_hint);
        } else {
            buf.put_u32(self.authn_hint);
        }

        self.server_version.encode(&mut buf, little_endian);

        if little_endian {
            buf.put_u32_le(self.hresult);
            buf.put_u32_le(self.interface_results.len() as u32);
        } else {
            buf.put_u32(self.hresult);
            buf.put_u32(self.interface_results.len() as u32);
        }

        for result in &self.interface_results {
            if little_endian {
                buf.put_u32_le(result.hresult);
            } else {
                buf.put_u32(result.hresult);
            }
            if let Some(ref std) = result.std {
                std.encode(&mut buf, little_endian);
            }
        }

        buf.freeze()
    }
}
