//! NDR error types

use thiserror::Error;

/// Maximum allocation size in bytes (64 MB default)
/// This prevents memory exhaustion attacks from malformed input.
pub const MAX_NDR_ALLOCATION_SIZE: usize = 64 * 1024 * 1024;

/// Maximum array element count
/// Based on MAX_NDR_ALLOCATION_SIZE / minimum element size (1 byte)
pub const MAX_NDR_ARRAY_ELEMENTS: usize = MAX_NDR_ALLOCATION_SIZE;

/// NDR encoding/decoding errors
#[derive(Debug, Error)]
pub enum NdrError {
    /// Buffer underflow - not enough data
    #[error("buffer underflow: needed {needed} bytes, have {have}")]
    BufferUnderflow { needed: usize, have: usize },

    /// Buffer overflow - not enough space
    #[error("buffer overflow: needed {needed} bytes, have {have}")]
    BufferOverflow { needed: usize, have: usize },

    /// Invalid string - not null terminated or invalid encoding
    #[error("invalid string: {0}")]
    InvalidString(String),

    /// Invalid pointer - unexpected referent ID
    #[error("invalid pointer: referent ID {0}")]
    InvalidPointer(u32),

    /// Array size mismatch
    #[error("array size mismatch: expected {expected}, got {got}")]
    ArraySizeMismatch { expected: usize, got: usize },

    /// Invalid discriminant for union
    #[error("invalid union discriminant: {0}")]
    InvalidDiscriminant(i32),

    /// Invalid enum value
    #[error("invalid enum value: {0}")]
    InvalidEnumValue(i32),

    /// Conformance mismatch
    #[error("conformance mismatch: max_count={max_count}, actual_count={actual_count}")]
    ConformanceMismatch { max_count: u32, actual_count: u32 },

    /// Allocation limit exceeded - prevents memory exhaustion attacks
    #[error("allocation limit exceeded: requested {requested} elements, limit {limit}")]
    AllocationLimitExceeded { requested: usize, limit: usize },

    /// Integer overflow during size calculation
    #[error("integer overflow during size calculation")]
    IntegerOverflow,

    /// UTF-8 decoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// UTF-16 decoding error
    #[error("UTF-16 error: {0}")]
    Utf16Error(#[from] std::char::DecodeUtf16Error),
}

/// Result type for NDR operations
pub type Result<T> = std::result::Result<T, NdrError>;
