//! NDR pointer types
//!
//! NDR supports three pointer semantics:
//!
//! - Reference (`[ref]`): Non-null, data follows inline, no wire representation
//! - Unique (`[unique]`): Nullable, 4-byte referent ID, no aliasing
//! - Full (`[ptr]`): Nullable, 4-byte referent ID, aliasing allowed

use crate::{NdrContext, NdrDecode, NdrEncode, NdrError, Result};
use bytes::{Buf, BufMut};
use std::ops::{Deref, DerefMut};

/// Trait for NDR pointer types
pub trait NdrPtr {
    type Target;

    /// Check if the pointer is null
    fn is_null(&self) -> bool;

    /// Get the inner value, if any
    fn get(&self) -> Option<&Self::Target>;

    /// Get a mutable reference to the inner value, if any
    fn get_mut(&mut self) -> Option<&mut Self::Target>;
}

/// Reference pointer - non-null, data follows inline
///
/// The `[ref]` attribute in MIDL. The pointer itself is not transmitted;
/// the pointee data is always present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPtr<T>(pub T);

impl<T> RefPtr<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Default> Default for RefPtr<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T> Deref for RefPtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for RefPtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> NdrPtr for RefPtr<T> {
    type Target = T;

    fn is_null(&self) -> bool {
        false
    }

    fn get(&self) -> Option<&T> {
        Some(&self.0)
    }

    fn get_mut(&mut self) -> Option<&mut T> {
        Some(&mut self.0)
    }
}

impl<T: NdrEncode> NdrEncode for RefPtr<T> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Reference pointers have no wire representation - just encode the data
        self.0.ndr_encode(buf, ctx, position)
    }

    fn ndr_align() -> usize {
        T::ndr_align()
    }

    fn ndr_size(&self) -> usize {
        self.0.ndr_size()
    }
}

impl<T: NdrDecode> NdrDecode for RefPtr<T> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        // Reference pointers have no wire representation - just decode the data
        let value = T::ndr_decode(buf, ctx, position)?;
        Ok(Self(value))
    }

    fn ndr_align() -> usize {
        T::ndr_align()
    }
}

/// Unique pointer - nullable, no aliasing
///
/// The `[unique]` attribute in MIDL. Encoded as:
/// - 4-byte referent ID (0 = null, non-zero = valid)
/// - If non-null, pointee data follows
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniquePtr<T>(pub Option<Box<T>>);

impl<T> UniquePtr<T> {
    pub fn new(value: T) -> Self {
        Self(Some(Box::new(value)))
    }

    pub fn null() -> Self {
        Self(None)
    }

    pub fn from_option(opt: Option<T>) -> Self {
        Self(opt.map(Box::new))
    }

    pub fn into_option(self) -> Option<T> {
        self.0.map(|b| *b)
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.0.as_ref().map(|b| b.as_ref())
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut().map(|b| b.as_mut())
    }
}

impl<T> Default for UniquePtr<T> {
    fn default() -> Self {
        Self::null()
    }
}

impl<T> From<Option<T>> for UniquePtr<T> {
    fn from(opt: Option<T>) -> Self {
        Self::from_option(opt)
    }
}

impl<T> NdrPtr for UniquePtr<T> {
    type Target = T;

    fn is_null(&self) -> bool {
        self.0.is_none()
    }

    fn get(&self) -> Option<&T> {
        self.0.as_ref().map(|b| b.as_ref())
    }

    fn get_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut().map(|b| b.as_mut())
    }
}

impl<T: NdrEncode> NdrEncode for UniquePtr<T> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Align for referent ID
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        match &self.0 {
            None => {
                // Null pointer
                ctx.put_u32(buf, 0);
                *position += 4;
            }
            Some(value) => {
                // Non-null: write referent ID then data
                ctx.put_u32(buf, 1); // Any non-zero value works
                *position += 4;
                value.ndr_encode(buf, ctx, position)?;
            }
        }
        Ok(())
    }

    fn ndr_align() -> usize {
        4 // For referent ID
    }

    fn ndr_size(&self) -> usize {
        match &self.0 {
            None => 4,
            Some(value) => 4 + value.ndr_size(),
        }
    }
}

impl<T: NdrDecode> NdrDecode for UniquePtr<T> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        // Align for referent ID
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 4 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 4,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        let referent_id = ctx.get_u32(buf);
        *position += 4;

        if referent_id == 0 {
            Ok(Self::null())
        } else {
            let value = T::ndr_decode(buf, ctx, position)?;
            Ok(Self::new(value))
        }
    }

    fn ndr_align() -> usize {
        4
    }
}

/// Full pointer - nullable, aliasing allowed
///
/// The `[ptr]` attribute in MIDL. Similar to unique but allows multiple
/// pointers to reference the same data. In practice, the wire format
/// is the same as unique for simple cases.
///
/// For complex cases with actual aliasing, a referent table would be
/// needed to track already-transmitted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullPtr<T>(pub Option<Box<T>>);

impl<T> FullPtr<T> {
    pub fn new(value: T) -> Self {
        Self(Some(Box::new(value)))
    }

    pub fn null() -> Self {
        Self(None)
    }

    pub fn from_option(opt: Option<T>) -> Self {
        Self(opt.map(Box::new))
    }

    pub fn into_option(self) -> Option<T> {
        self.0.map(|b| *b)
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.0.as_ref().map(|b| b.as_ref())
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut().map(|b| b.as_mut())
    }
}

impl<T> Default for FullPtr<T> {
    fn default() -> Self {
        Self::null()
    }
}

impl<T> From<Option<T>> for FullPtr<T> {
    fn from(opt: Option<T>) -> Self {
        Self::from_option(opt)
    }
}

impl<T> NdrPtr for FullPtr<T> {
    type Target = T;

    fn is_null(&self) -> bool {
        self.0.is_none()
    }

    fn get(&self) -> Option<&T> {
        self.0.as_ref().map(|b| b.as_ref())
    }

    fn get_mut(&mut self) -> Option<&mut T> {
        self.0.as_mut().map(|b| b.as_mut())
    }
}

// FullPtr uses same wire format as UniquePtr for non-aliasing cases
impl<T: NdrEncode> NdrEncode for FullPtr<T> {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Align for referent ID
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        match &self.0 {
            None => {
                ctx.put_u32(buf, 0);
                *position += 4;
            }
            Some(value) => {
                ctx.put_u32(buf, 1);
                *position += 4;
                value.ndr_encode(buf, ctx, position)?;
            }
        }
        Ok(())
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        match &self.0 {
            None => 4,
            Some(value) => 4 + value.ndr_size(),
        }
    }
}

impl<T: NdrDecode> NdrDecode for FullPtr<T> {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 4 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 4,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        let referent_id = ctx.get_u32(buf);
        *position += 4;

        if referent_id == 0 {
            Ok(Self::null())
        } else {
            let value = T::ndr_decode(buf, ctx, position)?;
            Ok(Self::new(value))
        }
    }

    fn ndr_align() -> usize {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_ref_ptr() {
        let ctx = NdrContext::new();
        let ptr = RefPtr::new(42u32);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        ptr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        // No referent ID for ref pointers
        assert_eq!(buf.len(), 4);

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: RefPtr<u32> = RefPtr::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(*decoded, 42);
    }

    #[test]
    fn test_unique_ptr_non_null() {
        let ctx = NdrContext::new();
        let ptr = UniquePtr::new(0xDEADBEEFu32);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        ptr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        // Referent ID + data
        assert_eq!(buf.len(), 8);

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: UniquePtr<u32> = UniquePtr::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert!(!decoded.is_null());
        assert_eq!(*decoded.get().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_unique_ptr_null() {
        let ctx = NdrContext::new();
        let ptr: UniquePtr<u32> = UniquePtr::null();

        let mut buf = BytesMut::new();
        let mut pos = 0;
        ptr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        // Just referent ID = 0
        assert_eq!(buf.len(), 4);
        assert_eq!(&buf[..], &[0, 0, 0, 0]);

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: UniquePtr<u32> = UniquePtr::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert!(decoded.is_null());
    }

    #[test]
    fn test_full_ptr_roundtrip() {
        let ctx = NdrContext::new();
        let ptr = FullPtr::new(12345i64);

        let mut buf = BytesMut::new();
        let mut pos = 0;
        ptr.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded: FullPtr<i64> = FullPtr::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(*decoded.get().unwrap(), 12345);
    }
}
