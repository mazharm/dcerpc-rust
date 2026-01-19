//! NDR array types
//!
//! NDR supports several array types:
//!
//! - Fixed arrays: size known at compile time
//! - Conformant arrays: size determined at runtime, transmitted as prefix
//! - Varying arrays: subset of elements transmitted
//! - Conformant varying arrays: both conformant and varying

use crate::{NdrContext, NdrDecode, NdrEncode, NdrError, Result};
use bytes::{Buf, BufMut};
use std::marker::PhantomData;

/// Fixed-size array
///
/// Wire format: just the elements (no size prefix)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedArray<T, const N: usize> {
    pub elements: [T; N],
}

impl<T: Default + Copy, const N: usize> Default for FixedArray<T, N> {
    fn default() -> Self {
        Self {
            elements: [T::default(); N],
        }
    }
}

impl<T, const N: usize> FixedArray<T, N> {
    pub fn new(elements: [T; N]) -> Self {
        Self { elements }
    }
}

impl<T: NdrEncode, const N: usize> NdrEncode for FixedArray<T, N> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        for elem in &self.elements {
            elem.ndr_encode(buf, ctx, position)?;
        }
        Ok(())
    }

    fn ndr_align() -> usize {
        T::ndr_align()
    }

    fn ndr_size(&self) -> usize {
        self.elements.iter().map(|e| e.ndr_size()).sum()
    }
}

impl<T: NdrDecode + Default + Copy, const N: usize> NdrDecode for FixedArray<T, N> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        let mut elements = [T::default(); N];
        for elem in &mut elements {
            *elem = T::ndr_decode(buf, ctx, position)?;
        }
        Ok(Self { elements })
    }

    fn ndr_align() -> usize {
        T::ndr_align()
    }
}

/// Conformant array - size determined at runtime
///
/// Wire format:
/// ```text
/// max_count: u32      # Maximum elements
/// elements[max_count] # Element data
/// ```
///
/// Note: In struct context, max_count may be at struct start while
/// elements are at end (conformant data comes last).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConformantArray<T> {
    pub elements: Vec<T>,
}

impl<T> ConformantArray<T> {
    pub fn new(elements: Vec<T>) -> Self {
        Self { elements }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

impl<T> From<Vec<T>> for ConformantArray<T> {
    fn from(elements: Vec<T>) -> Self {
        Self { elements }
    }
}

impl<T: NdrEncode> NdrEncode for ConformantArray<T> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Align for max_count
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        // Write max_count
        ctx.put_u32(buf, self.elements.len() as u32);
        *position += 4;

        // Write elements
        for elem in &self.elements {
            elem.ndr_encode(buf, ctx, position)?;
        }

        Ok(())
    }

    fn ndr_align() -> usize {
        4 // For max_count
    }

    fn ndr_size(&self) -> usize {
        4 + self.elements.iter().map(|e| e.ndr_size()).sum::<usize>()
    }
}

impl<T: NdrDecode> NdrDecode for ConformantArray<T> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        use crate::error::MAX_NDR_ARRAY_ELEMENTS;

        // Align for max_count
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 4 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 4,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        // Read max_count
        let max_count = ctx.get_u32(buf) as usize;
        *position += 4;

        // Validate allocation size to prevent memory exhaustion
        if max_count > MAX_NDR_ARRAY_ELEMENTS {
            return Err(NdrError::AllocationLimitExceeded {
                requested: max_count,
                limit: MAX_NDR_ARRAY_ELEMENTS,
            });
        }

        // Read elements
        let mut elements = Vec::with_capacity(max_count);
        for _ in 0..max_count {
            elements.push(T::ndr_decode(buf, ctx, position)?);
        }

        Ok(Self { elements })
    }

    fn ndr_align() -> usize {
        4
    }
}

/// Varying array - subset of fixed array transmitted
///
/// Wire format:
/// ```text
/// offset: u32       # First transmitted element (always 0 in practice)
/// actual_count: u32 # Number of transmitted elements
/// elements[actual_count]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaryingArray<T, const N: usize> {
    pub offset: usize,
    pub elements: Vec<T>,
    _marker: PhantomData<[T; N]>,
}

impl<T, const N: usize> Default for VaryingArray<T, N> {
    fn default() -> Self {
        Self {
            offset: 0,
            elements: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<T, const N: usize> VaryingArray<T, N> {
    pub fn new(elements: Vec<T>) -> Self {
        Self {
            offset: 0,
            elements,
            _marker: PhantomData,
        }
    }

    pub fn with_offset(offset: usize, elements: Vec<T>) -> Self {
        Self {
            offset,
            elements,
            _marker: PhantomData,
        }
    }
}

impl<T: NdrEncode, const N: usize> NdrEncode for VaryingArray<T, N> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Align for offset
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        // Write offset
        ctx.put_u32(buf, self.offset as u32);
        *position += 4;

        // Write actual_count
        ctx.put_u32(buf, self.elements.len() as u32);
        *position += 4;

        // Write elements
        for elem in &self.elements {
            elem.ndr_encode(buf, ctx, position)?;
        }

        Ok(())
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        8 + self.elements.iter().map(|e| e.ndr_size()).sum::<usize>()
    }
}

impl<T: NdrDecode, const N: usize> NdrDecode for VaryingArray<T, N> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        // Align for offset
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 8 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 8,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        let offset = ctx.get_u32(buf) as usize;
        let actual_count = ctx.get_u32(buf) as usize;
        *position += 8;

        if offset + actual_count > N {
            return Err(NdrError::ArraySizeMismatch {
                expected: N,
                got: offset + actual_count,
            });
        }

        let mut elements = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            elements.push(T::ndr_decode(buf, ctx, position)?);
        }

        Ok(Self {
            offset,
            elements,
            _marker: PhantomData,
        })
    }

    fn ndr_align() -> usize {
        4
    }
}

/// Conformant varying array - size and subset determined at runtime
///
/// Wire format:
/// ```text
/// max_count: u32    # Maximum elements (conformance)
/// offset: u32       # First transmitted element
/// actual_count: u32 # Number of transmitted elements
/// elements[actual_count]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConformantVaryingArray<T> {
    pub max_count: usize,
    pub offset: usize,
    pub elements: Vec<T>,
}

impl<T> ConformantVaryingArray<T> {
    pub fn new(elements: Vec<T>) -> Self {
        let len = elements.len();
        Self {
            max_count: len,
            offset: 0,
            elements,
        }
    }

    pub fn with_max(max_count: usize, elements: Vec<T>) -> Self {
        Self {
            max_count,
            offset: 0,
            elements,
        }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

impl<T: NdrEncode> NdrEncode for ConformantVaryingArray<T> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Align for max_count
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        // Write max_count
        ctx.put_u32(buf, self.max_count as u32);
        *position += 4;

        // Write offset
        ctx.put_u32(buf, self.offset as u32);
        *position += 4;

        // Write actual_count
        ctx.put_u32(buf, self.elements.len() as u32);
        *position += 4;

        // Write elements
        for elem in &self.elements {
            elem.ndr_encode(buf, ctx, position)?;
        }

        Ok(())
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        12 + self.elements.iter().map(|e| e.ndr_size()).sum::<usize>()
    }
}

impl<T: NdrDecode> NdrDecode for ConformantVaryingArray<T> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        use crate::error::MAX_NDR_ARRAY_ELEMENTS;

        // Align for max_count
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 12 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 12,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        let max_count = ctx.get_u32(buf) as usize;
        let offset = ctx.get_u32(buf) as usize;
        let actual_count = ctx.get_u32(buf) as usize;
        *position += 12;

        // Validate allocation size to prevent memory exhaustion
        if actual_count > MAX_NDR_ARRAY_ELEMENTS {
            return Err(NdrError::AllocationLimitExceeded {
                requested: actual_count,
                limit: MAX_NDR_ARRAY_ELEMENTS,
            });
        }

        // Check for integer overflow in offset + actual_count
        let total_count = offset.checked_add(actual_count).ok_or(NdrError::IntegerOverflow)?;
        if total_count > max_count {
            return Err(NdrError::ConformanceMismatch {
                max_count: max_count as u32,
                actual_count: total_count as u32,
            });
        }

        let mut elements = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            elements.push(T::ndr_decode(buf, ctx, position)?);
        }

        Ok(Self {
            max_count,
            offset,
            elements,
        })
    }

    fn ndr_align() -> usize {
        4
    }
}

/// Encode conformance (max_count) separately for embedded conformant arrays
#[allow(dead_code)]
pub fn encode_conformance<B: BufMut>(buf: &mut B, ctx: &NdrContext, max_count: u32, position: &mut usize) -> Result<()> {
    let padding = NdrContext::align_padding(*position, 4);
    for _ in 0..padding {
        buf.put_u8(0);
    }
    *position += padding;
    ctx.put_u32(buf, max_count);
    *position += 4;
    Ok(())
}

/// Decode conformance (max_count) separately for embedded conformant arrays
#[allow(dead_code)]
pub fn decode_conformance<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<u32> {
    let padding = NdrContext::align_padding(*position, 4);
    if buf.remaining() < padding + 4 {
        return Err(NdrError::BufferUnderflow {
            needed: padding + 4,
            have: buf.remaining(),
        });
    }
    buf.advance(padding);
    *position += padding;
    let max_count = ctx.get_u32(buf);
    *position += 4;
    Ok(max_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_fixed_array() {
        let ctx = NdrContext::new();
        let arr = FixedArray::new([1u32, 2, 3, 4]);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        arr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: FixedArray<u32, 4> = FixedArray::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(arr.elements, decoded.elements);
    }

    #[test]
    fn test_conformant_array() {
        let ctx = NdrContext::new();
        let arr = ConformantArray::new(vec![10i32, 20, 30]);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        arr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: ConformantArray<i32> = ConformantArray::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(arr.elements, decoded.elements);
    }

    #[test]
    fn test_conformant_varying_array() {
        let ctx = NdrContext::new();
        let arr = ConformantVaryingArray::with_max(100, vec![1u16, 2, 3, 4, 5]);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        arr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: ConformantVaryingArray<u16> =
            ConformantVaryingArray::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(decoded.max_count, 100);
        assert_eq!(decoded.elements, arr.elements);
    }

    #[test]
    fn test_empty_conformant_array() {
        let ctx = NdrContext::new();
        let arr: ConformantArray<u32> = ConformantArray::new(vec![]);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        arr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        assert_eq!(buf.len(), 4); // Just max_count

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: ConformantArray<u32> = ConformantArray::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert!(decoded.is_empty());
    }
}
