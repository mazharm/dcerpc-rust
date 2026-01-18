//! NDR encoding/decoding context
//!
//! The context tracks byte order and provides helpers for alignment and
//! primitive encoding/decoding.

use bytes::{Buf, BufMut};

/// NDR encoding/decoding context
///
/// Tracks the current byte order and provides methods for encoding/decoding
/// primitives with proper alignment.
#[derive(Debug, Clone, Copy)]
pub struct NdrContext {
    /// Whether to use little-endian byte order
    pub little_endian: bool,
}

impl NdrContext {
    /// Create a new NDR context with little-endian byte order (default)
    pub fn new() -> Self {
        Self { little_endian: true }
    }

    /// Create a context with big-endian byte order
    pub fn big_endian() -> Self {
        Self { little_endian: false }
    }

    /// Create a context with specified byte order
    pub fn with_byte_order(little_endian: bool) -> Self {
        Self { little_endian }
    }

    /// Calculate padding needed to align to the given boundary
    #[inline]
    pub fn align_padding(position: usize, alignment: usize) -> usize {
        if alignment == 0 || alignment == 1 {
            return 0;
        }
        let remainder = position % alignment;
        if remainder == 0 {
            0
        } else {
            alignment - remainder
        }
    }

    /// Write padding bytes to align to the given boundary
    pub fn write_align<B: BufMut>(&self, buf: &mut B, position: usize, alignment: usize) -> usize {
        let padding = Self::align_padding(position, alignment);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        padding
    }

    /// Skip padding bytes to align to the given boundary
    pub fn read_align<B: Buf>(&self, buf: &mut B, position: usize, alignment: usize) -> usize {
        let padding = Self::align_padding(position, alignment);
        if buf.remaining() >= padding {
            buf.advance(padding);
        }
        padding
    }

    // Primitive encoding methods

    /// Put a u8
    #[inline]
    pub fn put_u8<B: BufMut>(&self, buf: &mut B, value: u8) {
        buf.put_u8(value);
    }

    /// Put an i8
    #[inline]
    pub fn put_i8<B: BufMut>(&self, buf: &mut B, value: i8) {
        buf.put_i8(value);
    }

    /// Put a u16
    #[inline]
    pub fn put_u16<B: BufMut>(&self, buf: &mut B, value: u16) {
        if self.little_endian {
            buf.put_u16_le(value);
        } else {
            buf.put_u16(value);
        }
    }

    /// Put an i16
    #[inline]
    pub fn put_i16<B: BufMut>(&self, buf: &mut B, value: i16) {
        if self.little_endian {
            buf.put_i16_le(value);
        } else {
            buf.put_i16(value);
        }
    }

    /// Put a u32
    #[inline]
    pub fn put_u32<B: BufMut>(&self, buf: &mut B, value: u32) {
        if self.little_endian {
            buf.put_u32_le(value);
        } else {
            buf.put_u32(value);
        }
    }

    /// Put an i32
    #[inline]
    pub fn put_i32<B: BufMut>(&self, buf: &mut B, value: i32) {
        if self.little_endian {
            buf.put_i32_le(value);
        } else {
            buf.put_i32(value);
        }
    }

    /// Put a u64
    #[inline]
    pub fn put_u64<B: BufMut>(&self, buf: &mut B, value: u64) {
        if self.little_endian {
            buf.put_u64_le(value);
        } else {
            buf.put_u64(value);
        }
    }

    /// Put an i64
    #[inline]
    pub fn put_i64<B: BufMut>(&self, buf: &mut B, value: i64) {
        if self.little_endian {
            buf.put_i64_le(value);
        } else {
            buf.put_i64(value);
        }
    }

    /// Put an f32
    #[inline]
    pub fn put_f32<B: BufMut>(&self, buf: &mut B, value: f32) {
        if self.little_endian {
            buf.put_f32_le(value);
        } else {
            buf.put_f32(value);
        }
    }

    /// Put an f64
    #[inline]
    pub fn put_f64<B: BufMut>(&self, buf: &mut B, value: f64) {
        if self.little_endian {
            buf.put_f64_le(value);
        } else {
            buf.put_f64(value);
        }
    }

    // Primitive decoding methods

    /// Get a u8
    #[inline]
    pub fn get_u8<B: Buf>(&self, buf: &mut B) -> u8 {
        buf.get_u8()
    }

    /// Get an i8
    #[inline]
    pub fn get_i8<B: Buf>(&self, buf: &mut B) -> i8 {
        buf.get_i8()
    }

    /// Get a u16
    #[inline]
    pub fn get_u16<B: Buf>(&self, buf: &mut B) -> u16 {
        if self.little_endian {
            buf.get_u16_le()
        } else {
            buf.get_u16()
        }
    }

    /// Get an i16
    #[inline]
    pub fn get_i16<B: Buf>(&self, buf: &mut B) -> i16 {
        if self.little_endian {
            buf.get_i16_le()
        } else {
            buf.get_i16()
        }
    }

    /// Get a u32
    #[inline]
    pub fn get_u32<B: Buf>(&self, buf: &mut B) -> u32 {
        if self.little_endian {
            buf.get_u32_le()
        } else {
            buf.get_u32()
        }
    }

    /// Get an i32
    #[inline]
    pub fn get_i32<B: Buf>(&self, buf: &mut B) -> i32 {
        if self.little_endian {
            buf.get_i32_le()
        } else {
            buf.get_i32()
        }
    }

    /// Get a u64
    #[inline]
    pub fn get_u64<B: Buf>(&self, buf: &mut B) -> u64 {
        if self.little_endian {
            buf.get_u64_le()
        } else {
            buf.get_u64()
        }
    }

    /// Get an i64
    #[inline]
    pub fn get_i64<B: Buf>(&self, buf: &mut B) -> i64 {
        if self.little_endian {
            buf.get_i64_le()
        } else {
            buf.get_i64()
        }
    }

    /// Get an f32
    #[inline]
    pub fn get_f32<B: Buf>(&self, buf: &mut B) -> f32 {
        if self.little_endian {
            buf.get_f32_le()
        } else {
            buf.get_f32()
        }
    }

    /// Get an f64
    #[inline]
    pub fn get_f64<B: Buf>(&self, buf: &mut B) -> f64 {
        if self.little_endian {
            buf.get_f64_le()
        } else {
            buf.get_f64()
        }
    }
}

impl Default for NdrContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_alignment_padding() {
        assert_eq!(NdrContext::align_padding(0, 4), 0);
        assert_eq!(NdrContext::align_padding(1, 4), 3);
        assert_eq!(NdrContext::align_padding(2, 4), 2);
        assert_eq!(NdrContext::align_padding(3, 4), 1);
        assert_eq!(NdrContext::align_padding(4, 4), 0);
        assert_eq!(NdrContext::align_padding(5, 8), 3);
        assert_eq!(NdrContext::align_padding(0, 1), 0);
        assert_eq!(NdrContext::align_padding(5, 1), 0);
    }

    #[test]
    fn test_primitive_roundtrip_le() {
        let ctx = NdrContext::new();
        let mut buf = BytesMut::new();

        ctx.put_u16(&mut buf, 0x1234);
        ctx.put_i32(&mut buf, -42);
        ctx.put_u64(&mut buf, 0xDEADBEEF12345678);
        ctx.put_f32(&mut buf, 3.14);
        ctx.put_f64(&mut buf, 2.71828);

        let mut reader = buf.freeze();
        assert_eq!(ctx.get_u16(&mut reader), 0x1234);
        assert_eq!(ctx.get_i32(&mut reader), -42);
        assert_eq!(ctx.get_u64(&mut reader), 0xDEADBEEF12345678);
        assert!((ctx.get_f32(&mut reader) - 3.14).abs() < 0.001);
        assert!((ctx.get_f64(&mut reader) - 2.71828).abs() < 0.00001);
    }

    #[test]
    fn test_primitive_roundtrip_be() {
        let ctx = NdrContext::big_endian();
        let mut buf = BytesMut::new();

        ctx.put_u32(&mut buf, 0x12345678);

        let mut reader = buf.freeze();
        assert_eq!(ctx.get_u32(&mut reader), 0x12345678);
    }
}
