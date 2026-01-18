//! DCOM Hello World Example
//!
//! This example demonstrates a DCOM-style interface using MIDL-generated stubs.
//! While the stubs themselves are standard DCE RPC stubs, this example shows
//! how you would integrate ORPC headers for true DCOM communication.

// Re-export the generated stubs
#[allow(dead_code)]
#[allow(non_snake_case)]
mod hello_rpc;

pub use hello_rpc::*;

/// DCOM interface IIDs (Interface Identifiers)
pub mod iid {
    /// IUnknown IID - base interface for all COM objects
    pub const IUNKNOWN: &str = "00000000-0000-0000-C000-000000000046";

    /// IHello IID - our custom interface
    pub const IHELLO: &str = super::IHELLO_UUID;
}

/// HRESULT codes for DCOM
#[allow(dead_code)]
pub mod hresult {
    pub const S_OK: i32 = 0;
    pub const E_FAIL: i32 = -2147467259; // 0x80004005
    pub const E_INVALIDARG: i32 = -2147024809; // 0x80070057
    pub const E_NOTIMPL: i32 = -2147467263; // 0x80004001
}
