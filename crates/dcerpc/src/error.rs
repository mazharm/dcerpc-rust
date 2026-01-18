//! Error types for DCE RPC

use thiserror::Error;

/// RPC error types
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DCE RPC version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("RPC version mismatch: {0}")]
    RpcVersionMismatch(u32),

    #[error("program unavailable: {0}")]
    ProgramUnavailable(u32),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("operation unavailable: {0}")]
    OperationUnavailable(u16),

    #[error("invalid PDU")]
    InvalidPdu,

    #[error("invalid PDU: {0}")]
    InvalidPduData(String),

    #[error("invalid message type: {0}")]
    InvalidMessageType(i32),

    #[error("call rejected: {0}")]
    CallRejected(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("timeout")]
    Timeout,

    #[error("bind failed: {0}")]
    BindFailed(String),

    #[error("fault: status 0x{0:08x}")]
    Fault(u32),

    #[error("context mismatch")]
    ContextMismatch,

    #[error("call ID mismatch: expected {expected}, got {got}")]
    CallIdMismatch { expected: u32, got: u32 },

    #[error("XID mismatch: expected {expected}, got {got}")]
    XidMismatch { expected: u32, got: u32 },

    #[error("PDU too large: {size} bytes exceeds maximum {max}")]
    PduTooLarge { size: usize, max: usize },

    #[error("record too large: {size} bytes exceeds maximum {max}")]
    RecordTooLarge { size: usize, max: usize },

    #[error("task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("NDR encoding/decoding error: {0}")]
    Ndr(String),
}

impl From<midl_ndr::NdrError> for RpcError {
    fn from(err: midl_ndr::NdrError) -> Self {
        RpcError::Ndr(err.to_string())
    }
}

impl RpcError {
    /// Check if this error represents a normal connection close
    /// (EOF, connection reset, etc.)
    pub fn is_connection_closed(&self) -> bool {
        match self {
            RpcError::ConnectionClosed => true,
            RpcError::Io(e) => {
                // Check by error kind
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) {
                    return true;
                }
                // Also check error message for EOF indicators
                // (some platforms/libraries report EOF differently)
                let msg = e.to_string().to_lowercase();
                msg.contains("eof") || msg.contains("end of file")
            }
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, RpcError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_is_connection_closed() {
        // Test ConnectionClosed variant
        assert!(RpcError::ConnectionClosed.is_connection_closed());

        // Test "early eof" message (Windows named pipe)
        let err = RpcError::Io(Error::new(ErrorKind::Other, "early eof"));
        assert!(err.is_connection_closed(), "Should detect 'early eof' as connection closed");

        // Test UnexpectedEof kind
        let err = RpcError::Io(Error::new(ErrorKind::UnexpectedEof, "unexpected eof"));
        assert!(err.is_connection_closed(), "Should detect UnexpectedEof as connection closed");

        // Test ConnectionReset kind
        let err = RpcError::Io(Error::new(ErrorKind::ConnectionReset, "reset"));
        assert!(err.is_connection_closed(), "Should detect ConnectionReset as connection closed");

        // Test other errors are not connection closed
        let err = RpcError::Io(Error::new(ErrorKind::PermissionDenied, "denied"));
        assert!(!err.is_connection_closed(), "PermissionDenied should not be connection closed");

        let err = RpcError::InvalidPdu;
        assert!(!err.is_connection_closed(), "InvalidPdu should not be connection closed");
    }
}
