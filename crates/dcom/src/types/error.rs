//! DCOM error types

use thiserror::Error;

/// Result type for DCOM operations
pub type Result<T> = std::result::Result<T, DcomError>;

/// DCOM-specific errors
#[derive(Error, Debug)]
pub enum DcomError {
    /// Underlying DCE RPC error
    #[error("DCE RPC error: {0}")]
    Rpc(#[from] dcerpc::RpcError),

    /// Invalid OBJREF format
    #[error("invalid OBJREF: {0}")]
    InvalidObjRef(String),

    /// Invalid string binding format
    #[error("invalid string binding: {0}")]
    InvalidStringBinding(String),

    /// Object not found
    #[error("object not found: OID {0:016x}")]
    ObjectNotFound(u64),

    /// Interface not found
    #[error("interface not found: IPID {0}")]
    InterfaceNotFound(String),

    /// OXID not found
    #[error("OXID not found: {0:016x}")]
    OxidNotFound(u64),

    /// Reference counting error
    #[error("reference counting error: {0}")]
    RefCountError(String),

    /// Apartment threading error
    #[error("apartment error: {0}")]
    ApartmentError(String),

    /// Activation error
    #[error("activation error: {0}")]
    ActivationError(String),

    /// Marshaling error
    #[error("marshaling error: {0}")]
    MarshalingError(String),

    /// Buffer underflow (not enough data)
    #[error("buffer underflow: need {needed} bytes, have {have}")]
    BufferUnderflow { needed: usize, have: usize },

    /// Invalid data
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Ping timeout (garbage collection)
    #[error("ping timeout: set {0:016x}")]
    PingTimeout(u64),

    /// Access denied
    #[error("access denied")]
    AccessDenied,

    /// Server unavailable
    #[error("server unavailable")]
    ServerUnavailable,
}

/// HRESULT codes commonly used in DCOM
pub mod hresult {
    /// Operation successful
    pub const S_OK: u32 = 0x00000000;
    /// Operation successful, returning false
    pub const S_FALSE: u32 = 0x00000001;
    /// Unspecified error
    pub const E_FAIL: u32 = 0x80004005;
    /// Invalid pointer
    pub const E_POINTER: u32 = 0x80004003;
    /// No such interface supported
    pub const E_NOINTERFACE: u32 = 0x80004002;
    /// Out of memory
    pub const E_OUTOFMEMORY: u32 = 0x8007000E;
    /// Invalid argument
    pub const E_INVALIDARG: u32 = 0x80070057;
    /// Class not registered
    pub const REGDB_E_CLASSNOTREG: u32 = 0x80040154;
    /// Access denied
    pub const E_ACCESSDENIED: u32 = 0x80070005;
    /// Object or server not available
    pub const CO_E_OBJNOTCONNECTED: u32 = 0x800401FD;
    /// RPC server unavailable
    pub const RPC_E_SERVER_DIED: u32 = 0x80010007;
    /// Server is too busy
    pub const RPC_E_TOO_LATE: u32 = 0x80010119;
}
