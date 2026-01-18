//! NDR error types

use thiserror::Error;

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

    /// UTF-8 decoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// UTF-16 decoding error
    #[error("UTF-16 error: {0}")]
    Utf16Error(#[from] std::char::DecodeUtf16Error),
}

/// Result type for NDR operations
pub type Result<T> = std::result::Result<T, NdrError>;
