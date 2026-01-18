//! RPC Pipe Data Structures for Streaming
//!
//! This module implements RPC pipes as defined in DCE 1.1 and MS-RPCE.
//! Pipes allow streaming data within an RPC call using chunked transfer.
//!
//! # Overview
//!
//! A pipe is represented as a sequence of chunks, where each chunk contains:
//! - An element count (u32 for NDR, u64 for NDR64)
//! - The actual elements
//! - For NDR64: the arithmetic negation of the count (for validation)
//!
//! The stream is terminated by an empty chunk (count = 0).
//!
//! # NDR Format (32-bit)
//!
//! ```text
//! +------------------+
//! | count (u32)      |  Number of elements in this chunk
//! +------------------+
//! | element[0]       |
//! | element[1]       |
//! | ...              |
//! | element[count-1] |
//! +------------------+
//! | ... more chunks  |
//! +------------------+
//! | 0 (u32)          |  Terminator - empty chunk
//! +------------------+
//! ```
//!
//! # NDR64 Format (64-bit)
//!
//! ```text
//! +------------------+
//! | count (u64)      |  Number of elements in this chunk
//! +------------------+
//! | element[0]       |
//! | element[1]       |
//! | ...              |
//! | element[count-1] |
//! +------------------+
//! | -count (i64)     |  Negated count for validation
//! +------------------+
//! | ... more chunks  |
//! +------------------+
//! | 0 (u64)          |  Terminator
//! | 0 (u64)          |
//! +------------------+
//! ```
//!
//! # Restrictions
//!
//! Pipe elements cannot be:
//! - Nested pipes
//! - Pointers
//! - Conformant arrays
//! - Varying arrays
//! - Structures containing conformant or varying arrays
//!
//! # Usage
//!
//! ```
//! use dcerpc::{PipeWriter, PipeReader, PipeFormat};
//!
//! // Writing pipe data
//! let mut writer = PipeWriter::new(PipeFormat::Ndr);
//! writer.write_chunk(&[1u32, 2, 3, 4, 5]);
//! writer.write_chunk(&[6u32, 7, 8]);
//! let data = writer.finish();
//!
//! // Reading pipe data
//! let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
//! while let Some(chunk) = reader.read_chunk::<u32>().unwrap() {
//!     println!("Got {} elements", chunk.len());
//! }
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;
use std::marker::PhantomData;

use crate::error::{Result, RpcError};

/// Maximum elements per chunk (2^31 - 1 for NDR64 compatibility)
pub const MAX_CHUNK_ELEMENTS: u32 = i32::MAX as u32;

/// Pipe format (NDR vs NDR64)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeFormat {
    /// NDR format: 32-bit counts
    Ndr,
    /// NDR64 format: 64-bit counts with validation
    Ndr64,
}

impl Default for PipeFormat {
    fn default() -> Self {
        PipeFormat::Ndr
    }
}

/// Trait for types that can be pipe elements
///
/// Pipe elements must have a fixed size and be encodable/decodable
/// without pointers or conformant arrays.
pub trait PipeElement: Sized {
    /// Size of the element in bytes
    fn element_size() -> usize;

    /// Encode the element to bytes (little-endian)
    fn encode(&self, buf: &mut BytesMut);

    /// Decode the element from bytes (little-endian)
    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self>;
}

// Implement PipeElement for primitive types

impl PipeElement for u8 {
    fn element_size() -> usize {
        1
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(RpcError::InvalidPduData("insufficient data for u8".into()));
        }
        Ok(buf.get_u8())
    }
}

impl PipeElement for i8 {
    fn element_size() -> usize {
        1
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i8(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(RpcError::InvalidPduData("insufficient data for i8".into()));
        }
        Ok(buf.get_i8())
    }
}

impl PipeElement for u16 {
    fn element_size() -> usize {
        2
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(RpcError::InvalidPduData("insufficient data for u16".into()));
        }
        Ok(buf.get_u16_le())
    }
}

impl PipeElement for i16 {
    fn element_size() -> usize {
        2
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i16_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(RpcError::InvalidPduData("insufficient data for i16".into()));
        }
        Ok(buf.get_i16_le())
    }
}

impl PipeElement for u32 {
    fn element_size() -> usize {
        4
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(RpcError::InvalidPduData("insufficient data for u32".into()));
        }
        Ok(buf.get_u32_le())
    }
}

impl PipeElement for i32 {
    fn element_size() -> usize {
        4
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i32_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(RpcError::InvalidPduData("insufficient data for i32".into()));
        }
        Ok(buf.get_i32_le())
    }
}

impl PipeElement for u64 {
    fn element_size() -> usize {
        8
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(RpcError::InvalidPduData("insufficient data for u64".into()));
        }
        Ok(buf.get_u64_le())
    }
}

impl PipeElement for i64 {
    fn element_size() -> usize {
        8
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_i64_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(RpcError::InvalidPduData("insufficient data for i64".into()));
        }
        Ok(buf.get_i64_le())
    }
}

impl PipeElement for f32 {
    fn element_size() -> usize {
        4
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_f32_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(RpcError::InvalidPduData("insufficient data for f32".into()));
        }
        Ok(buf.get_f32_le())
    }
}

impl PipeElement for f64 {
    fn element_size() -> usize {
        8
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_f64_le(*self);
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(RpcError::InvalidPduData("insufficient data for f64".into()));
        }
        Ok(buf.get_f64_le())
    }
}

/// A chunk of pipe data
#[derive(Debug, Clone)]
pub struct PipeChunk<T> {
    /// The elements in this chunk
    pub elements: Vec<T>,
}

impl<T: PipeElement> PipeChunk<T> {
    /// Create a new chunk with the given elements
    pub fn new(elements: Vec<T>) -> Self {
        Self { elements }
    }

    /// Create an empty chunk (used for termination)
    pub fn empty() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Check if this is an empty/terminator chunk
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Encode this chunk in NDR format
    pub fn encode_ndr(&self, buf: &mut BytesMut) {
        // Write element count (u32)
        buf.put_u32_le(self.elements.len() as u32);

        // Write elements
        for element in &self.elements {
            element.encode(buf);
        }
    }

    /// Encode this chunk in NDR64 format
    pub fn encode_ndr64(&self, buf: &mut BytesMut) {
        let count = self.elements.len() as u64;

        // Write element count (u64)
        buf.put_u64_le(count);

        // Write elements
        for element in &self.elements {
            element.encode(buf);
        }

        // Write negated count (i64) - two's complement negation
        buf.put_i64_le(-(count as i64));
    }

    /// Decode a chunk from NDR format
    pub fn decode_ndr(buf: &mut Cursor<&[u8]>) -> Result<Option<Self>> {
        if buf.remaining() < 4 {
            return Err(RpcError::InvalidPduData(
                "insufficient data for pipe chunk count".into(),
            ));
        }

        let count = buf.get_u32_le() as usize;

        // Empty chunk signals end of pipe
        if count == 0 {
            return Ok(None);
        }

        // Validate count
        if count > MAX_CHUNK_ELEMENTS as usize {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk count {} exceeds maximum {}",
                count, MAX_CHUNK_ELEMENTS
            )));
        }

        // Check we have enough data
        let element_size = T::element_size();
        let required = count * element_size;
        if buf.remaining() < required {
            return Err(RpcError::InvalidPduData(format!(
                "insufficient data for {} pipe elements ({} bytes needed, {} available)",
                count,
                required,
                buf.remaining()
            )));
        }

        // Decode elements
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(T::decode(buf)?);
        }

        Ok(Some(Self { elements }))
    }

    /// Decode a chunk from NDR64 format
    pub fn decode_ndr64(buf: &mut Cursor<&[u8]>) -> Result<Option<Self>> {
        if buf.remaining() < 8 {
            return Err(RpcError::InvalidPduData(
                "insufficient data for pipe chunk count (NDR64)".into(),
            ));
        }

        let count = buf.get_u64_le();

        // Empty chunk signals end of pipe (two zeros)
        if count == 0 {
            // Read the second zero
            if buf.remaining() < 8 {
                return Err(RpcError::InvalidPduData(
                    "insufficient data for pipe terminator (NDR64)".into(),
                ));
            }
            let second = buf.get_u64_le();
            if second != 0 {
                return Err(RpcError::InvalidPduData(format!(
                    "invalid pipe terminator: expected 0, got {}",
                    second
                )));
            }
            return Ok(None);
        }

        // Validate count
        if count > MAX_CHUNK_ELEMENTS as u64 {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk count {} exceeds maximum {}",
                count, MAX_CHUNK_ELEMENTS
            )));
        }

        let count = count as usize;

        // Check we have enough data for elements + negated count
        let element_size = T::element_size();
        let required = count * element_size + 8; // +8 for negated count
        if buf.remaining() < required {
            return Err(RpcError::InvalidPduData(format!(
                "insufficient data for {} pipe elements + validation ({} bytes needed, {} available)",
                count,
                required,
                buf.remaining()
            )));
        }

        // Decode elements
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(T::decode(buf)?);
        }

        // Read and validate negated count
        let negated = buf.get_i64_le();
        let expected = -(count as i64);
        if negated != expected {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk validation failed: expected {}, got {}",
                expected, negated
            )));
        }

        Ok(Some(Self { elements }))
    }
}

/// Writer for encoding pipe data
pub struct PipeWriter {
    format: PipeFormat,
    buffer: BytesMut,
    finished: bool,
}

impl PipeWriter {
    /// Create a new pipe writer
    pub fn new(format: PipeFormat) -> Self {
        Self {
            format,
            buffer: BytesMut::new(),
            finished: false,
        }
    }

    /// Write a chunk of elements
    pub fn write_chunk<T: PipeElement + Clone>(&mut self, elements: &[T]) {
        if self.finished {
            panic!("cannot write to finished pipe");
        }

        let chunk = PipeChunk {
            elements: elements.to_vec(),
        };

        match self.format {
            PipeFormat::Ndr => chunk.encode_ndr(&mut self.buffer),
            PipeFormat::Ndr64 => chunk.encode_ndr64(&mut self.buffer),
        }
    }

    /// Write raw bytes as a single chunk (for u8 elements)
    pub fn write_bytes(&mut self, data: &[u8]) {
        if self.finished {
            panic!("cannot write to finished pipe");
        }

        match self.format {
            PipeFormat::Ndr => {
                self.buffer.put_u32_le(data.len() as u32);
                self.buffer.extend_from_slice(data);
            }
            PipeFormat::Ndr64 => {
                let count = data.len() as u64;
                self.buffer.put_u64_le(count);
                self.buffer.extend_from_slice(data);
                self.buffer.put_i64_le(-(count as i64));
            }
        }
    }

    /// Finish the pipe and get the encoded data
    pub fn finish(mut self) -> Bytes {
        if !self.finished {
            // Write terminator
            match self.format {
                PipeFormat::Ndr => {
                    self.buffer.put_u32_le(0);
                }
                PipeFormat::Ndr64 => {
                    self.buffer.put_u64_le(0);
                    self.buffer.put_u64_le(0);
                }
            }
            self.finished = true;
        }
        self.buffer.freeze()
    }

    /// Get the current buffer without finishing
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

/// Reader for decoding pipe data
pub struct PipeReader<'a> {
    format: PipeFormat,
    cursor: Cursor<&'a [u8]>,
    finished: bool,
}

impl<'a> PipeReader<'a> {
    /// Create a new pipe reader
    pub fn new(data: &'a [u8], format: PipeFormat) -> Self {
        Self {
            format,
            cursor: Cursor::new(data),
            finished: false,
        }
    }

    /// Read the next chunk, returns None when pipe is finished
    pub fn read_chunk<T: PipeElement>(&mut self) -> Result<Option<PipeChunk<T>>> {
        if self.finished {
            return Ok(None);
        }

        let chunk = match self.format {
            PipeFormat::Ndr => PipeChunk::decode_ndr(&mut self.cursor)?,
            PipeFormat::Ndr64 => PipeChunk::decode_ndr64(&mut self.cursor)?,
        };

        if chunk.is_none() {
            self.finished = true;
        }

        Ok(chunk)
    }

    /// Read all remaining chunks into a single vector
    pub fn read_all<T: PipeElement>(&mut self) -> Result<Vec<T>> {
        let mut all = Vec::new();
        while let Some(chunk) = self.read_chunk()? {
            all.extend(chunk.elements);
        }
        Ok(all)
    }

    /// Read all bytes (for u8 pipe elements)
    pub fn read_all_bytes(&mut self) -> Result<Vec<u8>> {
        self.read_all()
    }

    /// Check if the pipe is finished
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Get remaining unread data
    pub fn remaining(&self) -> usize {
        self.cursor.remaining()
    }
}

/// Iterator adapter for reading pipe chunks
pub struct PipeChunkIterator<'a, T> {
    reader: PipeReader<'a>,
    _marker: PhantomData<T>,
}

impl<'a, T: PipeElement> PipeChunkIterator<'a, T> {
    pub fn new(data: &'a [u8], format: PipeFormat) -> Self {
        Self {
            reader: PipeReader::new(data, format),
            _marker: PhantomData,
        }
    }
}

impl<'a, T: PipeElement> Iterator for PipeChunkIterator<'a, T> {
    type Item = Result<Vec<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_finished() {
            return None;
        }

        match self.reader.read_chunk() {
            Ok(Some(chunk)) => Some(Ok(chunk.elements)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Create a pipe iterator from raw bytes
pub fn pipe_iter<T: PipeElement>(data: &[u8], format: PipeFormat) -> PipeChunkIterator<'_, T> {
    PipeChunkIterator::new(data, format)
}

// ============================================================================
// Async Streaming Support
// ============================================================================

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Async pipe writer for streaming data over async transports
pub struct AsyncPipeWriter<W> {
    writer: W,
    format: PipeFormat,
}

impl<W: AsyncWrite + Unpin> AsyncPipeWriter<W> {
    /// Create a new async pipe writer
    pub fn new(writer: W, format: PipeFormat) -> Self {
        Self { writer, format }
    }

    /// Write a chunk of elements
    pub async fn write_chunk<T: PipeElement + Clone>(&mut self, elements: &[T]) -> Result<()> {
        let mut buf = BytesMut::new();
        let chunk = PipeChunk {
            elements: elements.to_vec(),
        };

        match self.format {
            PipeFormat::Ndr => chunk.encode_ndr(&mut buf),
            PipeFormat::Ndr64 => chunk.encode_ndr64(&mut buf),
        }

        self.writer.write_all(&buf).await?;
        Ok(())
    }

    /// Write raw bytes as a chunk (for u8 elements)
    pub async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        let mut buf = BytesMut::new();

        match self.format {
            PipeFormat::Ndr => {
                buf.put_u32_le(data.len() as u32);
                buf.extend_from_slice(data);
            }
            PipeFormat::Ndr64 => {
                let count = data.len() as u64;
                buf.put_u64_le(count);
                buf.extend_from_slice(data);
                buf.put_i64_le(-(count as i64));
            }
        }

        self.writer.write_all(&buf).await?;
        Ok(())
    }

    /// Write the terminator and finish the pipe
    pub async fn finish(mut self) -> Result<W> {
        let mut buf = BytesMut::new();

        match self.format {
            PipeFormat::Ndr => {
                buf.put_u32_le(0);
            }
            PipeFormat::Ndr64 => {
                buf.put_u64_le(0);
                buf.put_u64_le(0);
            }
        }

        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;
        Ok(self.writer)
    }

    /// Get a reference to the underlying writer
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Get a mutable reference to the underlying writer
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

/// Async pipe reader for streaming data from async transports
pub struct AsyncPipeReader<R> {
    reader: R,
    format: PipeFormat,
    finished: bool,
}

impl<R: AsyncRead + Unpin> AsyncPipeReader<R> {
    /// Create a new async pipe reader
    pub fn new(reader: R, format: PipeFormat) -> Self {
        Self {
            reader,
            format,
            finished: false,
        }
    }

    /// Read the next chunk, returns None when pipe is finished
    pub async fn read_chunk<T: PipeElement>(&mut self) -> Result<Option<PipeChunk<T>>> {
        if self.finished {
            return Ok(None);
        }

        match self.format {
            PipeFormat::Ndr => self.read_chunk_ndr().await,
            PipeFormat::Ndr64 => self.read_chunk_ndr64().await,
        }
    }

    async fn read_chunk_ndr<T: PipeElement>(&mut self) -> Result<Option<PipeChunk<T>>> {
        // Read count (u32)
        let mut count_buf = [0u8; 4];
        self.reader.read_exact(&mut count_buf).await?;
        let count = u32::from_le_bytes(count_buf) as usize;

        // Empty chunk = end of pipe
        if count == 0 {
            self.finished = true;
            return Ok(None);
        }

        // Validate count
        if count > MAX_CHUNK_ELEMENTS as usize {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk count {} exceeds maximum {}",
                count, MAX_CHUNK_ELEMENTS
            )));
        }

        // Read elements
        let element_size = T::element_size();
        let mut data = vec![0u8; count * element_size];
        self.reader.read_exact(&mut data).await?;

        // Decode elements
        let mut cursor = Cursor::new(data.as_slice());
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(T::decode(&mut cursor)?);
        }

        Ok(Some(PipeChunk { elements }))
    }

    async fn read_chunk_ndr64<T: PipeElement>(&mut self) -> Result<Option<PipeChunk<T>>> {
        // Read count (u64)
        let mut count_buf = [0u8; 8];
        self.reader.read_exact(&mut count_buf).await?;
        let count = u64::from_le_bytes(count_buf);

        // Empty chunk = end of pipe (two zeros)
        if count == 0 {
            // Read second zero
            let mut second_buf = [0u8; 8];
            self.reader.read_exact(&mut second_buf).await?;
            let second = u64::from_le_bytes(second_buf);
            if second != 0 {
                return Err(RpcError::InvalidPduData(format!(
                    "invalid pipe terminator: expected 0, got {}",
                    second
                )));
            }
            self.finished = true;
            return Ok(None);
        }

        // Validate count
        if count > MAX_CHUNK_ELEMENTS as u64 {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk count {} exceeds maximum {}",
                count, MAX_CHUNK_ELEMENTS
            )));
        }

        let count = count as usize;

        // Read elements
        let element_size = T::element_size();
        let mut data = vec![0u8; count * element_size];
        self.reader.read_exact(&mut data).await?;

        // Decode elements
        let mut cursor = Cursor::new(data.as_slice());
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(T::decode(&mut cursor)?);
        }

        // Read and validate negated count
        let mut neg_buf = [0u8; 8];
        self.reader.read_exact(&mut neg_buf).await?;
        let negated = i64::from_le_bytes(neg_buf);
        let expected = -(count as i64);
        if negated != expected {
            return Err(RpcError::InvalidPduData(format!(
                "pipe chunk validation failed: expected {}, got {}",
                expected, negated
            )));
        }

        Ok(Some(PipeChunk { elements }))
    }

    /// Read all remaining chunks into a single vector
    pub async fn read_all<T: PipeElement>(&mut self) -> Result<Vec<T>> {
        let mut all = Vec::new();
        while let Some(chunk) = self.read_chunk().await? {
            all.extend(chunk.elements);
        }
        Ok(all)
    }

    /// Read all bytes (for u8 pipe elements)
    pub async fn read_all_bytes(&mut self) -> Result<Vec<u8>> {
        self.read_all().await
    }

    /// Check if the pipe is finished
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Get a reference to the underlying reader
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Get a mutable reference to the underlying reader
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

/// Helper function to encode pipe data from a slice of chunks
pub fn encode_pipe_data<T: PipeElement + Clone>(
    chunks: &[Vec<T>],
    format: PipeFormat,
) -> Bytes {
    let mut writer = PipeWriter::new(format);
    for chunk in chunks {
        writer.write_chunk(chunk);
    }
    writer.finish()
}

/// Helper function to decode all pipe data into chunks
pub fn decode_pipe_data<T: PipeElement>(
    data: &[u8],
    format: PipeFormat,
) -> Result<Vec<Vec<T>>> {
    let mut reader = PipeReader::new(data, format);
    let mut chunks = Vec::new();
    while let Some(chunk) = reader.read_chunk()? {
        chunks.push(chunk.elements);
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_ndr_u32() {
        // Write some chunks
        let mut writer = PipeWriter::new(PipeFormat::Ndr);
        writer.write_chunk(&[1u32, 2, 3]);
        writer.write_chunk(&[4u32, 5]);
        let data = writer.finish();

        // Read them back
        let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
        let chunk1: PipeChunk<u32> = reader.read_chunk().unwrap().unwrap();
        assert_eq!(chunk1.elements, vec![1, 2, 3]);

        let chunk2: PipeChunk<u32> = reader.read_chunk().unwrap().unwrap();
        assert_eq!(chunk2.elements, vec![4, 5]);

        // Should be finished
        let chunk3: Option<PipeChunk<u32>> = reader.read_chunk().unwrap();
        assert!(chunk3.is_none());
    }

    #[test]
    fn test_pipe_ndr64_u32() {
        // Write some chunks
        let mut writer = PipeWriter::new(PipeFormat::Ndr64);
        writer.write_chunk(&[100u32, 200, 300]);
        writer.write_chunk(&[400u32]);
        let data = writer.finish();

        // Read them back
        let mut reader = PipeReader::new(&data, PipeFormat::Ndr64);
        let chunk1: PipeChunk<u32> = reader.read_chunk().unwrap().unwrap();
        assert_eq!(chunk1.elements, vec![100, 200, 300]);

        let chunk2: PipeChunk<u32> = reader.read_chunk().unwrap().unwrap();
        assert_eq!(chunk2.elements, vec![400]);

        // Should be finished
        assert!(reader.read_chunk::<u32>().unwrap().is_none());
    }

    #[test]
    fn test_pipe_bytes() {
        let mut writer = PipeWriter::new(PipeFormat::Ndr);
        writer.write_bytes(b"Hello, ");
        writer.write_bytes(b"World!");
        let data = writer.finish();

        let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
        let all = reader.read_all_bytes().unwrap();
        assert_eq!(all, b"Hello, World!");
    }

    #[test]
    fn test_pipe_read_all() {
        let mut writer = PipeWriter::new(PipeFormat::Ndr);
        writer.write_chunk(&[1i32, 2, 3]);
        writer.write_chunk(&[4i32, 5, 6]);
        writer.write_chunk(&[7i32, 8, 9, 10]);
        let data = writer.finish();

        let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
        let all: Vec<i32> = reader.read_all().unwrap();
        assert_eq!(all, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_pipe_iterator() {
        let mut writer = PipeWriter::new(PipeFormat::Ndr);
        writer.write_chunk(&[10u64, 20]);
        writer.write_chunk(&[30u64, 40, 50]);
        let data = writer.finish();

        let chunks: Vec<_> = pipe_iter::<u64>(&data, PipeFormat::Ndr)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec![10, 20]);
        assert_eq!(chunks[1], vec![30, 40, 50]);
    }

    #[test]
    fn test_pipe_empty() {
        let writer = PipeWriter::new(PipeFormat::Ndr);
        let data = writer.finish();

        // Should just be the terminator (0)
        assert_eq!(data.len(), 4);

        let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
        assert!(reader.read_chunk::<u32>().unwrap().is_none());
    }

    #[test]
    fn test_pipe_ndr64_validation() {
        // Manually create invalid NDR64 data with wrong negated count
        let mut bad_data = BytesMut::new();
        bad_data.put_u64_le(2); // count = 2
        bad_data.put_u32_le(100); // element 0
        bad_data.put_u32_le(200); // element 1
        bad_data.put_i64_le(-999); // wrong negated count (should be -2)

        let mut reader = PipeReader::new(&bad_data, PipeFormat::Ndr64);
        let result = reader.read_chunk::<u32>();
        assert!(result.is_err());
    }

    #[test]
    fn test_pipe_f64() {
        let mut writer = PipeWriter::new(PipeFormat::Ndr);
        writer.write_chunk(&[1.5f64, 2.5, 3.5]);
        let data = writer.finish();

        let mut reader = PipeReader::new(&data, PipeFormat::Ndr);
        let chunk: PipeChunk<f64> = reader.read_chunk().unwrap().unwrap();
        assert_eq!(chunk.elements, vec![1.5, 2.5, 3.5]);
    }

    #[test]
    fn test_encode_decode_helpers() {
        let chunks = vec![vec![1u32, 2, 3], vec![4u32, 5, 6]];
        let data = encode_pipe_data(&chunks, PipeFormat::Ndr);

        let decoded: Vec<Vec<u32>> = decode_pipe_data(&data, PipeFormat::Ndr).unwrap();
        assert_eq!(decoded, chunks);
    }

    #[tokio::test]
    async fn test_async_pipe_ndr() {
        use std::io::Cursor;

        // Create a buffer to write to
        let mut buffer = Vec::new();

        // Write chunks asynchronously
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = AsyncPipeWriter::new(cursor, PipeFormat::Ndr);
            writer.write_chunk(&[1u32, 2, 3]).await.unwrap();
            writer.write_chunk(&[4u32, 5]).await.unwrap();
            writer.finish().await.unwrap();
        }

        // Read chunks asynchronously
        let cursor = Cursor::new(&buffer);
        let mut reader = AsyncPipeReader::new(cursor, PipeFormat::Ndr);

        let chunk1: PipeChunk<u32> = reader.read_chunk().await.unwrap().unwrap();
        assert_eq!(chunk1.elements, vec![1, 2, 3]);

        let chunk2: PipeChunk<u32> = reader.read_chunk().await.unwrap().unwrap();
        assert_eq!(chunk2.elements, vec![4, 5]);

        // Should be finished
        assert!(reader.read_chunk::<u32>().await.unwrap().is_none());
        assert!(reader.is_finished());
    }

    #[tokio::test]
    async fn test_async_pipe_ndr64() {
        use std::io::Cursor;

        let mut buffer = Vec::new();

        // Write
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = AsyncPipeWriter::new(cursor, PipeFormat::Ndr64);
            writer.write_chunk(&[100i64, 200]).await.unwrap();
            writer.write_bytes(b"hello").await.unwrap();
            writer.finish().await.unwrap();
        }

        // Read
        let cursor = Cursor::new(&buffer);
        let mut reader = AsyncPipeReader::new(cursor, PipeFormat::Ndr64);

        let chunk1: PipeChunk<i64> = reader.read_chunk().await.unwrap().unwrap();
        assert_eq!(chunk1.elements, vec![100, 200]);

        let chunk2: PipeChunk<u8> = reader.read_chunk().await.unwrap().unwrap();
        assert_eq!(chunk2.elements, b"hello".to_vec());

        assert!(reader.read_chunk::<u8>().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_async_read_all() {
        use std::io::Cursor;

        let mut buffer = Vec::new();

        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = AsyncPipeWriter::new(cursor, PipeFormat::Ndr);
            writer.write_chunk(&[1u32, 2]).await.unwrap();
            writer.write_chunk(&[3u32, 4, 5]).await.unwrap();
            writer.finish().await.unwrap();
        }

        let cursor = Cursor::new(&buffer);
        let mut reader = AsyncPipeReader::new(cursor, PipeFormat::Ndr);

        let all: Vec<u32> = reader.read_all().await.unwrap();
        assert_eq!(all, vec![1, 2, 3, 4, 5]);
    }
}
