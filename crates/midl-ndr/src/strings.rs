//! NDR string types
//!
//! NDR strings are conformant varying arrays with a null terminator.
//!
//! Wire format:
//! ```text
//! max_count: u32    # Maximum elements including null
//! offset: u32       # Always 0
//! actual_count: u32 # Actual elements including null
//! chars[actual_count]
//! padding to 4-byte alignment
//! ```

use crate::{NdrContext, NdrDecode, NdrEncode, NdrError, Result};
use bytes::{Buf, BufMut};

/// ANSI string type (null-terminated char*)
///
/// Used for [string] annotated char* parameters in MIDL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdrString(pub String);

impl NdrString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for NdrString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for NdrString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for NdrString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl NdrEncode for NdrString {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        let bytes = self.0.as_bytes();
        let len_with_null = bytes.len() + 1;

        // Align to 4 bytes for the max_count field
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        // max_count (including null terminator)
        ctx.put_u32(buf, len_with_null as u32);
        *position += 4;

        // offset (always 0)
        ctx.put_u32(buf, 0);
        *position += 4;

        // actual_count (including null terminator)
        ctx.put_u32(buf, len_with_null as u32);
        *position += 4;

        // String data
        buf.put_slice(bytes);
        buf.put_u8(0); // Null terminator
        *position += len_with_null;

        // Pad to 4-byte alignment
        let str_padding = NdrContext::align_padding(*position, 4);
        for _ in 0..str_padding {
            buf.put_u8(0);
        }
        *position += str_padding;

        Ok(())
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        let len_with_null = self.0.len() + 1;
        let str_padding = NdrContext::align_padding(len_with_null, 4);
        12 + len_with_null + str_padding // 3 u32s + string + padding
    }
}

impl NdrDecode for NdrString {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        use crate::error::MAX_NDR_ALLOCATION_SIZE;

        // Align to 4 bytes
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 12 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 12,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        // Read conformance
        let max_count = ctx.get_u32(buf) as usize;
        let offset = ctx.get_u32(buf) as usize;
        let actual_count = ctx.get_u32(buf) as usize;
        *position += 12;

        if offset != 0 {
            return Err(NdrError::InvalidString("non-zero offset".to_string()));
        }
        if actual_count > max_count {
            return Err(NdrError::ConformanceMismatch {
                max_count: max_count as u32,
                actual_count: actual_count as u32,
            });
        }

        // Validate allocation size to prevent memory exhaustion
        if actual_count > MAX_NDR_ALLOCATION_SIZE {
            return Err(NdrError::AllocationLimitExceeded {
                requested: actual_count,
                limit: MAX_NDR_ALLOCATION_SIZE,
            });
        }

        // Read string bytes
        if buf.remaining() < actual_count {
            return Err(NdrError::BufferUnderflow {
                needed: actual_count,
                have: buf.remaining(),
            });
        }
        let mut bytes = vec![0u8; actual_count];
        buf.copy_to_slice(&mut bytes);
        *position += actual_count;

        // Remove null terminator if present
        if bytes.last() == Some(&0) {
            bytes.pop();
        }

        // Skip alignment padding
        let str_padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() >= str_padding {
            buf.advance(str_padding);
            *position += str_padding;
        }

        let s = String::from_utf8(bytes)?;
        Ok(Self(s))
    }

    fn ndr_align() -> usize {
        4
    }
}

/// Unicode string type (null-terminated wchar_t*)
///
/// Used for [string] annotated wchar_t* parameters in MIDL.
/// Encoded as UTF-16LE on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdrWString(pub String);

impl NdrWString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for NdrWString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for NdrWString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for NdrWString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl NdrEncode for NdrWString {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        // Convert to UTF-16
        let utf16: Vec<u16> = self.0.encode_utf16().collect();
        let len_with_null = utf16.len() + 1;

        // Align to 4 bytes for the max_count field
        let padding = NdrContext::align_padding(*position, 4);
        for _ in 0..padding {
            buf.put_u8(0);
        }
        *position += padding;

        // max_count (in wchar_t units, including null)
        ctx.put_u32(buf, len_with_null as u32);
        *position += 4;

        // offset (always 0)
        ctx.put_u32(buf, 0);
        *position += 4;

        // actual_count (in wchar_t units, including null)
        ctx.put_u32(buf, len_with_null as u32);
        *position += 4;

        // String data as UTF-16
        for ch in &utf16 {
            ctx.put_u16(buf, *ch);
        }
        ctx.put_u16(buf, 0); // Null terminator
        *position += len_with_null * 2;

        // Pad to 4-byte alignment (already aligned since we wrote 2-byte values)
        let str_padding = NdrContext::align_padding(*position, 4);
        for _ in 0..str_padding {
            buf.put_u8(0);
        }
        *position += str_padding;

        Ok(())
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        let utf16_len = self.0.encode_utf16().count();
        let len_with_null = utf16_len + 1;
        let byte_len = len_with_null * 2;
        let str_padding = NdrContext::align_padding(byte_len, 4);
        12 + byte_len + str_padding
    }
}

impl NdrDecode for NdrWString {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        use crate::error::MAX_NDR_ALLOCATION_SIZE;

        // Align to 4 bytes
        let padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() < padding + 12 {
            return Err(NdrError::BufferUnderflow {
                needed: padding + 12,
                have: buf.remaining(),
            });
        }
        buf.advance(padding);
        *position += padding;

        // Read conformance
        let max_count = ctx.get_u32(buf) as usize;
        let offset = ctx.get_u32(buf) as usize;
        let actual_count = ctx.get_u32(buf) as usize;
        *position += 12;

        if offset != 0 {
            return Err(NdrError::InvalidString("non-zero offset".to_string()));
        }
        if actual_count > max_count {
            return Err(NdrError::ConformanceMismatch {
                max_count: max_count as u32,
                actual_count: actual_count as u32,
            });
        }

        // Validate allocation size to prevent memory exhaustion
        // Each UTF-16 code unit is 2 bytes
        if actual_count > MAX_NDR_ALLOCATION_SIZE / 2 {
            return Err(NdrError::AllocationLimitExceeded {
                requested: actual_count,
                limit: MAX_NDR_ALLOCATION_SIZE / 2,
            });
        }

        // Read UTF-16 code units (use checked_mul for safety)
        let byte_count = actual_count.checked_mul(2).ok_or(NdrError::IntegerOverflow)?;
        if buf.remaining() < byte_count {
            return Err(NdrError::BufferUnderflow {
                needed: byte_count,
                have: buf.remaining(),
            });
        }

        let mut utf16 = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            utf16.push(ctx.get_u16(buf));
        }
        *position += byte_count;

        // Remove null terminator if present
        if utf16.last() == Some(&0) {
            utf16.pop();
        }

        // Skip alignment padding
        let str_padding = NdrContext::align_padding(*position, 4);
        if buf.remaining() >= str_padding {
            buf.advance(str_padding);
            *position += str_padding;
        }

        // Convert from UTF-16
        let s: std::result::Result<String, _> = char::decode_utf16(utf16)
            .collect();
        match s {
            Ok(s) => Ok(Self(s)),
            Err(e) => Err(NdrError::Utf16Error(e)),
        }
    }

    fn ndr_align() -> usize {
        4
    }
}

/// BSTR - COM-style string with length prefix
///
/// Note: In NDR, BSTR is encoded differently than in-memory COM BSTRs.
/// The wire format includes max_count, offset, actual_count like other strings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BString(pub String);

impl BString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for BString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for BString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// BString uses same encoding as NdrWString for wire format
impl NdrEncode for BString {
    fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<()> {
        NdrWString(self.0.clone()).ndr_encode(buf, ctx, position)
    }

    fn ndr_align() -> usize {
        4
    }

    fn ndr_size(&self) -> usize {
        NdrWString(self.0.clone()).ndr_size()
    }
}

impl NdrDecode for BString {
    fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> Result<Self> {
        let wstr = NdrWString::ndr_decode(buf, ctx, position)?;
        Ok(Self(wstr.0))
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
    fn test_ndr_string_roundtrip() {
        let ctx = NdrContext::new();
        let s = NdrString::new("Hello, World!");

        let mut buf = BytesMut::new();
        let mut pos = 0;
        s.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded = NdrString::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(s, decoded);
    }

    #[test]
    fn test_ndr_wstring_roundtrip() {
        let ctx = NdrContext::new();
        let s = NdrWString::new("Hello, World!");

        let mut buf = BytesMut::new();
        let mut pos = 0;
        s.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded = NdrWString::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(s, decoded);
    }

    #[test]
    fn test_ndr_wstring_unicode() {
        let ctx = NdrContext::new();
        let s = NdrWString::new("Hello\u{00e9}"); // e with acute accent

        let mut buf = BytesMut::new();
        let mut pos = 0;
        s.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded = NdrWString::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(s.0, decoded.0);
    }

    #[test]
    fn test_empty_string() {
        let ctx = NdrContext::new();
        let s = NdrString::new("");

        let mut buf = BytesMut::new();
        let mut pos = 0;
        s.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();

        // Should still have max_count=1, offset=0, actual_count=1 for null terminator
        assert!(buf.len() >= 12 + 1);

        let mut reader = buf.freeze();
        let mut pos = 0;
        let decoded = NdrString::ndr_decode(&mut reader, &ctx, &mut pos).unwrap();

        assert_eq!(decoded.0, "");
    }
}
