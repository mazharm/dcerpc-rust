//! NDR primitive type implementations
//!
//! NDR primitive types and their encodings:
//!
//! | MIDL Type     | Rust Type | Size | Alignment |
//! |---------------|-----------|------|-----------|
//! | boolean       | bool      | 1    | 1         |
//! | byte/char     | u8        | 1    | 1         |
//! | small         | i8        | 1    | 1         |
//! | short         | i16       | 2    | 2         |
//! | long/int      | i32       | 4    | 4         |
//! | hyper         | i64       | 8    | 8         |
//! | unsigned short| u16       | 2    | 2         |
//! | unsigned long | u32       | 4    | 4         |
//! | unsigned hyper| u64       | 8    | 8         |
//! | float         | f32       | 4    | 4         |
//! | double        | f64       | 8    | 8         |
//! | wchar_t       | u16       | 2    | 2         |
//! | error_status_t| u32       | 4    | 4         |

use crate::{NdrContext, NdrDecode, NdrEncode, Result};
use bytes::{Buf, BufMut};

// Macro to implement NdrEncode/NdrDecode for primitive types
macro_rules! impl_ndr_primitive {
    ($ty:ty, $size:expr, $align:expr, $put:ident, $get:ident) => {
        impl NdrEncode for $ty {
            fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
                // Apply alignment padding
                let padding = NdrContext::align_padding(*position, $align);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
                *position += padding;

                // Encode value
                ctx.$put(buf, *self);
                *position += $size;
                Ok(())
            }

            fn ndr_align() -> usize {
                $align
            }

            fn ndr_size(&self) -> usize {
                $size
            }
        }

        impl NdrDecode for $ty {
            fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
                // Apply alignment
                let padding = NdrContext::align_padding(*position, $align);
                if buf.remaining() < padding + $size {
                    return Err(crate::error::NdrError::BufferUnderflow {
                        needed: padding + $size,
                        have: buf.remaining(),
                    });
                }
                buf.advance(padding);
                *position += padding;

                // Decode value
                let value = ctx.$get(buf);
                *position += $size;
                Ok(value)
            }

            fn ndr_align() -> usize {
                $align
            }
        }
    };
}

// Implement for u8 (byte, char)
impl NdrEncode for u8 {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        ctx.put_u8(buf, *self);
        *position += 1;
        Ok(())
    }

    fn ndr_align() -> usize { 1 }
    fn ndr_size(&self) -> usize { 1 }
}

impl NdrDecode for u8 {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(crate::error::NdrError::BufferUnderflow { needed: 1, have: buf.remaining() });
        }
        let value = ctx.get_u8(buf);
        *position += 1;
        Ok(value)
    }

    fn ndr_align() -> usize { 1 }
}

// Implement for i8 (small)
impl NdrEncode for i8 {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        ctx.put_i8(buf, *self);
        *position += 1;
        Ok(())
    }

    fn ndr_align() -> usize { 1 }
    fn ndr_size(&self) -> usize { 1 }
}

impl NdrDecode for i8 {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(crate::error::NdrError::BufferUnderflow { needed: 1, have: buf.remaining() });
        }
        let value = ctx.get_i8(buf);
        *position += 1;
        Ok(value)
    }

    fn ndr_align() -> usize { 1 }
}

// Use macro for types with alignment > 1
impl_ndr_primitive!(u16, 2, 2, put_u16, get_u16);
impl_ndr_primitive!(i16, 2, 2, put_i16, get_i16);
impl_ndr_primitive!(u32, 4, 4, put_u32, get_u32);
impl_ndr_primitive!(i32, 4, 4, put_i32, get_i32);
impl_ndr_primitive!(u64, 8, 8, put_u64, get_u64);
impl_ndr_primitive!(i64, 8, 8, put_i64, get_i64);
impl_ndr_primitive!(f32, 4, 4, put_f32, get_f32);
impl_ndr_primitive!(f64, 8, 8, put_f64, get_f64);

/// NDR boolean - encoded as a single byte (0x00 = false, 0x01 = true)
impl NdrEncode for bool {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, _ctx: &NdrContext, position: &mut usize) -> Result<()> {
        buf.put_u8(if *self { 1 } else { 0 });
        *position += 1;
        Ok(())
    }

    fn ndr_align() -> usize { 1 }
    fn ndr_size(&self) -> usize { 1 }
}

impl NdrDecode for bool {
    fn ndr_decode<B: Buf>(buf: &mut B, _ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(crate::error::NdrError::BufferUnderflow { needed: 1, have: buf.remaining() });
        }
        let value = buf.get_u8();
        *position += 1;
        Ok(value != 0)
    }

    fn ndr_align() -> usize { 1 }
}

/// GUID/UUID type for NDR encoding
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NdrUuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[allow(dead_code)]
impl NdrUuid {
    /// Nil UUID
    pub const NIL: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    /// Parse from string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 36 {
            return None;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }

        let data1 = u32::from_str_radix(parts[0], 16).ok()?;
        let data2 = u16::from_str_radix(parts[1], 16).ok()?;
        let data3 = u16::from_str_radix(parts[2], 16).ok()?;
        let clock = u16::from_str_radix(parts[3], 16).ok()?;
        let node_str = parts[4];
        if node_str.len() != 12 {
            return None;
        }

        let mut data4 = [0u8; 8];
        data4[0] = (clock >> 8) as u8;
        data4[1] = clock as u8;
        for i in 0..6 {
            data4[2 + i] = u8::from_str_radix(&node_str[i * 2..i * 2 + 2], 16).ok()?;
        }

        Some(Self { data1, data2, data3, data4 })
    }
}

impl std::fmt::Display for NdrUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl NdrEncode for NdrUuid {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // UUID aligns to 4 bytes (same as first field)
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        ctx.put_u32(buf, self.data1);
        ctx.put_u16(buf, self.data2);
        ctx.put_u16(buf, self.data3);
        buf.put_slice(&self.data4);
        *position += 16;
        Ok(())
    }

    fn ndr_align() -> usize { 4 }
    fn ndr_size(&self) -> usize { 16 }
}

impl NdrDecode for NdrUuid {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 16 {
            return Err(crate::error::NdrError::BufferUnderflow {
                needed: padding + 16,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        let data1 = ctx.get_u32(buf);
        let data2 = ctx.get_u16(buf);
        let data3 = ctx.get_u16(buf);
        let mut data4 = [0u8; 8];
        buf.copy_to_slice(&mut data4);
        *position += 16;

        Ok(Self { data1, data2, data3, data4 })
    }

    fn ndr_align() -> usize { 4 }
}

/// NDR handle_t (opaque handle) - represented as a 32-bit context ID
#[allow(dead_code)]
pub type HandleT = u32;

/// NDR error_status_t - HRESULT-like error code
#[allow(dead_code)]
pub type ErrorStatusT = u32;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_bool_encode_decode() {
        let ctx = NdrContext::new();
        let mut buf = BytesMut::new();
        let mut pos = 0;

        true.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();
        false.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        assert!(bool::ndr_decode(&mut reader, &ctx, &mut pos).unwrap());
        assert!(!bool::ndr_decode(&mut reader, &ctx, &mut pos).unwrap());
    }

    #[test]
    fn test_alignment() {
        let ctx = NdrContext::new();
        let mut buf = BytesMut::new();
        let mut pos = 0;

        // Write a byte then a u32 (should add 3 bytes padding)
        42u8.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();
        0xDEADBEEFu32.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        assert_eq!(buf.len(), 8); // 1 + 3 padding + 4
        assert_eq!(pos, 8);

        let mut reader = buf.freeze();
        let mut pos = 0;
        assert_eq!(u8::ndr_decode(&mut reader, &ctx, &mut pos).unwrap(), 42);
        assert_eq!(u32::ndr_decode(&mut reader, &ctx, &mut pos).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_uuid_roundtrip() {
        let ctx = NdrContext::new();
        let uuid = NdrUuid::parse("12345678-1234-5678-9ABC-DEF012345678").unwrap();

        let mut buf = BytesMut::new();
        let mut pos = 0;
        uuid.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded = NdrUuid::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(uuid, decoded);
    }

    #[test]
    fn test_uuid_parse_display() {
        let uuid_str = "12345678-abcd-ef01-2345-6789abcdef01";
        let uuid = NdrUuid::parse(uuid_str).unwrap();
        let displayed = format!("{}", uuid);
        assert_eq!(displayed, uuid_str);
    }
}
