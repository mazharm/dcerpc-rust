//! IActivation client implementation

use std::net::SocketAddr;
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use crate::types::{Result, DcomError, Oxid, Ipid, DualStringArray, StdObjRef, ComVersion};
use super::protocol::*;

/// IActivation client
///
/// Client for remote object activation.
pub struct ActivationClient {
    client: DceRpcClient,
}

impl ActivationClient {
    /// Connect to a remote activation endpoint
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let interface = SyntaxId::new(
            Uuid::parse(ACTIVATION_UUID).ok_or_else(|| DcomError::InvalidData("invalid UUID".to_string()))?,
            ACTIVATION_VERSION.0,
            ACTIVATION_VERSION.1,
        );

        let client = DceRpcClient::connect(addr, interface)
            .await
            .map_err(DcomError::Rpc)?;

        Ok(Self { client })
    }

    /// Activate a remote object
    pub async fn remote_activation(
        &self,
        clsid: dcerpc::Uuid,
        interfaces: Vec<dcerpc::Uuid>,
    ) -> Result<ActivationResult> {
        let request = RemoteActivationRequest::new(clsid, interfaces);
        let response_bytes = self
            .client
            .call(opnum::REMOTE_ACTIVATION, request.encode(true))
            .await
            .map_err(DcomError::Rpc)?;

        // Parse response
        let mut buf = response_bytes;

        // Skip ORPCTHAT
        let _ = crate::types::OrpcThat::decode(&mut buf, true)?;

        use bytes::Buf;

        // Read OXID
        if buf.remaining() < 8 {
            return Err(DcomError::BufferUnderflow {
                needed: 8,
                have: buf.remaining(),
            });
        }
        let oxid = crate::types::Oxid::decode(&mut buf, true);

        // Read DSA
        let dsa = DualStringArray::decode(&mut buf, true)?;

        // Read IPID
        let ipid_rem_unknown = Ipid::decode(&mut buf, true);

        // Read authn_hint and version
        if buf.remaining() < 12 {
            return Err(DcomError::BufferUnderflow {
                needed: 12,
                have: buf.remaining(),
            });
        }
        let authn_hint = buf.get_u32_le();
        let server_version = ComVersion::decode(&mut buf, true);
        let hresult = buf.get_u32_le();

        if hresult != 0 {
            return Err(DcomError::ActivationError(format!(
                "activation failed: 0x{:08x}",
                hresult
            )));
        }

        // Read interface results
        if buf.remaining() < 4 {
            return Err(DcomError::BufferUnderflow {
                needed: 4,
                have: buf.remaining(),
            });
        }
        let count = buf.get_u32_le();

        let mut interface_results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if buf.remaining() < 4 {
                break;
            }
            let hr = buf.get_u32_le();
            let std = if hr == 0 && buf.remaining() >= StdObjRef::SIZE {
                Some(StdObjRef::decode(&mut buf, true)?)
            } else {
                None
            };
            interface_results.push(InterfaceResult { hresult: hr, std });
        }

        Ok(ActivationResult {
            oxid,
            bindings: dsa,
            ipid_rem_unknown,
            authn_hint,
            server_version,
            interface_results,
        })
    }

    /// Convenience method: activate and get single interface
    pub async fn activate_single(
        &self,
        clsid: dcerpc::Uuid,
        iid: dcerpc::Uuid,
    ) -> Result<(StdObjRef, DualStringArray, Ipid)> {
        let result = self.remote_activation(clsid, vec![iid]).await?;

        if let Some(first) = result.interface_results.into_iter().next() {
            if first.hresult == 0 {
                if let Some(std) = first.std {
                    return Ok((std, result.bindings, result.ipid_rem_unknown));
                }
            }
            return Err(DcomError::ActivationError(format!(
                "interface request failed: 0x{:08x}",
                first.hresult
            )));
        }

        Err(DcomError::ActivationError("no interface returned".to_string()))
    }
}

/// Result of a remote activation
#[derive(Clone, Debug)]
pub struct ActivationResult {
    /// Object exporter ID
    pub oxid: Oxid,
    /// Server bindings
    pub bindings: DualStringArray,
    /// IPID for IRemUnknown
    pub ipid_rem_unknown: Ipid,
    /// Authentication hint
    pub authn_hint: u32,
    /// Server COM version
    pub server_version: ComVersion,
    /// Interface results
    pub interface_results: Vec<InterfaceResult>,
}

impl ActivationResult {
    /// Get successful interface references
    pub fn successful_interfaces(&self) -> Vec<&StdObjRef> {
        self.interface_results
            .iter()
            .filter_map(|r| {
                if r.hresult == 0 {
                    r.std.as_ref()
                } else {
                    None
                }
            })
            .collect()
    }
}
