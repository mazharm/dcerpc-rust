//! NDR encoding trait

use crate::{NdrContext, Result};
use bytes::BufMut;

/// Trait for types that can be encoded to NDR format
pub trait NdrEncode {
    /// Encode this value to the buffer at the current position.
    ///
    /// The `position` parameter tracks the current byte offset from the start
    /// of the stub data, which is needed for alignment calculations.
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()>;

    /// Get the NDR alignment requirement for this type
    fn ndr_align() -> usize where Self: Sized {
        1
    }

    /// Compute the encoded size (not including alignment padding from previous fields)
    fn ndr_size(&self) -> usize;
}
