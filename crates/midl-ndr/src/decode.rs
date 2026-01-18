//! NDR decoding trait

use crate::{NdrContext, Result};
use bytes::Buf;

/// Trait for types that can be decoded from NDR format
pub trait NdrDecode: Sized {
    /// Decode a value from the buffer at the current position.
    ///
    /// The `position` parameter tracks the current byte offset from the start
    /// of the stub data, which is needed for alignment calculations.
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self>;

    /// Get the NDR alignment requirement for this type
    fn ndr_align() -> usize {
        1
    }
}
