//! NDR (Network Data Representation) runtime library
//!
//! This crate provides the runtime support for MIDL-generated code, implementing
//! the NDR wire format as specified in DCE RPC and MS-RPCE.
//!
//! # NDR Wire Format
//!
//! NDR is the standard encoding for DCE RPC data. Key characteristics:
//! - Primitives align to their natural size (1, 2, 4, or 8 bytes)
//! - Structures align to their largest member
//! - Conformant data (arrays with runtime-determined size) comes at the end
//! - Strings are conformant varying arrays with null terminator

mod context;
mod decode;
mod encode;
mod primitives;
mod strings;
mod arrays;
mod pointers;
mod error;

pub use context::NdrContext;
pub use decode::NdrDecode;
pub use encode::NdrEncode;
pub use error::{NdrError, Result};
pub use strings::{NdrString, NdrWString, BString};
pub use arrays::{FixedArray, ConformantArray, VaryingArray, ConformantVaryingArray};
pub use pointers::{NdrPtr, RefPtr, UniquePtr, FullPtr};

/// Re-export bytes for convenience
pub use bytes::{Buf, BufMut, Bytes, BytesMut};
