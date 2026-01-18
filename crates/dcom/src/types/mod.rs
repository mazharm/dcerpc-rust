//! Core DCOM types (MS-DCOM 2.2)
//!
//! This module contains the fundamental data structures used throughout DCOM:
//! - Identifiers: OXID, OID, IPID, SETID
//! - Object references: OBJREF and its variants
//! - String bindings: DUALSTRINGARRAY
//! - ORPC headers: ORPCTHIS, ORPCTHAT

mod error;
mod identifiers;
mod objref;
mod orpc;
mod stdobjref;
mod stringbinding;

// Re-export all types
pub use error::*;
pub use identifiers::{
    Oxid, Oid, Ipid, SetId,
    decode_uuid, encode_uuid, generate_uuid,
};
pub use objref::*;
pub use orpc::*;
pub use stdobjref::*;
pub use stringbinding::*;

/// Well-known interface UUIDs
pub mod iid {
    /// IUnknown interface UUID
    pub const IUNKNOWN: &str = "00000000-0000-0000-c000-000000000046";
    /// IClassFactory interface UUID
    pub const ICLASSFACTORY: &str = "00000001-0000-0000-c000-000000000046";
    /// IRemUnknown interface UUID
    pub const IREMUNKNOWN: &str = "00000131-0000-0000-c000-000000000046";
    /// IRemUnknown2 interface UUID
    pub const IREMUNKNOWN2: &str = "00000143-0000-0000-c000-000000000046";
    /// IObjectExporter interface UUID (for OXID resolution)
    pub const IOBJECTEXPORTER: &str = "99fcfec4-5260-101b-bbcb-00aa0021347a";
    /// IActivation interface UUID
    pub const IACTIVATION: &str = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57";
    /// IRemoteSCMActivator interface UUID
    pub const IREMOTESCMACTIVATOR: &str = "000001a0-0000-0000-c000-000000000046";
}

/// Well-known CLSID values
pub mod clsid {
    /// Standard marshaler CLSID
    pub const STD_MARSHAL: &str = "00000017-0000-0000-c000-000000000046";
}
