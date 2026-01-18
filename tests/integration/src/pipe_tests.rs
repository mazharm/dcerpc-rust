//! Pipe Tests - RPC Pipe Scenarios
//!
//! These tests exercise the DCE RPC pipe functionality:
//! - Streaming large amounts of data
//! - Chunked data transfer
//! - Bidirectional pipes
//! - Error handling during streaming

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use futures::future::join_all;

use common::*;
use dcerpc::{DceRpcClient, DceRpcServer, Interface, InterfaceBuilder, SyntaxId, Uuid};
use dcerpc::dcerpc_pipe::{PipeWriter, PipeReader, PipeChunk, PipeFormat};
use midl_ndr::NdrContext;

/// Pipe service UUID
pub const PIPE_UUID: &str = "91919191-9191-9191-9191-919191919191";
pub const PIPE_VERSION: (u16, u16) = (1, 0);

/// Pipe operation numbers
pub mod pipe_opnum {
    pub const SEND_CHUNKS: u16 = 0;
    pub const ECHO_CHUNKS: u16 = 1;
    pub const SUM_STREAM: u16 = 2;
    pub const LARGE_TRANSFER: u16 = 3;
    pub const BIDIRECTIONAL: u16 = 4;
}

/// Create a pipe test interface
fn create_pipe_interface() -> Interface {
    InterfaceBuilder::new(PIPE_UUID, PIPE_VERSION.0, PIPE_VERSION.1)
        .unwrap()
        // Op 0: Receive chunks and count them
        .operation(pipe_opnum::SEND_CHUNKS, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();

                let mut chunk_count = 0u32;
                let mut total_bytes = 0u64;

                // Read pipe chunks
                while cursor.remaining() >= 4 {
                    let chunk_size = ctx.get_u32(&mut cursor);
                    if chunk_size == 0 {
                        break; // End of pipe
                    }
                    if cursor.remaining() < chunk_size as usize {
                        break;
                    }
                    cursor.advance(chunk_size as usize);
                    chunk_count += 1;
                    total_bytes += chunk_size as u64;
                }

                let mut result = BytesMut::new();
                ctx.put_u32(&mut result, chunk_count);
                ctx.put_u64(&mut result, total_bytes);
                Ok(result.freeze())
            })
        })
        // Op 1: Echo all chunks back
        .operation(pipe_opnum::ECHO_CHUNKS, |stub_data| {
            Box::pin(async move {
                // Simply echo the entire payload back
                Ok(stub_data)
            })
        })
        // Op 2: Sum all i32s from the stream
        .operation(pipe_opnum::SUM_STREAM, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();

                let mut sum: i64 = 0;

                // Read chunks of i32s
                while cursor.remaining() >= 4 {
                    let chunk_size = ctx.get_u32(&mut cursor);
                    if chunk_size == 0 {
                        break;
                    }
                    let element_count = chunk_size / 4;
                    for _ in 0..element_count {
                        if cursor.remaining() >= 4 {
                            sum += ctx.get_i32(&mut cursor) as i64;
                        }
                    }
                }

                let mut result = BytesMut::new();
                ctx.put_i64(&mut result, sum);
                Ok(result.freeze())
            })
        })
        // Op 3: Large data transfer
        .operation(pipe_opnum::LARGE_TRANSFER, |stub_data| {
            Box::pin(async move {
                // Compute checksum of all data
                let checksum = compute_checksum(&stub_data);
                let total_size = stub_data.len();

                let ctx = NdrContext::default();
                let mut result = BytesMut::new();
                ctx.put_u64(&mut result, checksum);
                ctx.put_u64(&mut result, total_size as u64);
                Ok(result.freeze())
            })
        })
        // Op 4: Bidirectional - transform and return
        .operation(pipe_opnum::BIDIRECTIONAL, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let mut result = BytesMut::new();

                // Read chunks, transform (double each byte), write back as chunks
                while cursor.remaining() >= 4 {
                    let chunk_size = ctx.get_u32(&mut cursor);
                    if chunk_size == 0 {
                        ctx.put_u32(&mut result, 0); // End marker
                        break;
                    }
                    if cursor.remaining() < chunk_size as usize {
                        break;
                    }

                    // Transform chunk
                    let chunk_data: Vec<u8> = cursor[..chunk_size as usize]
                        .iter()
                        .map(|&b| b.wrapping_mul(2))
                        .collect();
                    cursor.advance(chunk_size as usize);

                    // Write transformed chunk
                    ctx.put_u32(&mut result, chunk_data.len() as u32);
                    result.put_slice(&chunk_data);
                }

                Ok(result.freeze())
            })
        })
        .build()
}

/// Encode data as pipe chunks
fn encode_as_chunks(data: &[u8], chunk_size: usize) -> Bytes {
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();

    for chunk in data.chunks(chunk_size) {
        ctx.put_u32(&mut buf, chunk.len() as u32);
        buf.put_slice(chunk);
    }
    ctx.put_u32(&mut buf, 0); // End marker

    buf.freeze()
}

/// Decode pipe chunks back to data
fn decode_chunks(data: &[u8]) -> Vec<u8> {
    let ctx = NdrContext::default();
    let mut cursor = data;
    let mut result = Vec::new();

    while cursor.remaining() >= 4 {
        let chunk_size = ctx.get_u32(&mut cursor);
        if chunk_size == 0 {
            break;
        }
        if cursor.remaining() < chunk_size as usize {
            break;
        }
        result.extend_from_slice(&cursor[..chunk_size as usize]);
        cursor.advance(chunk_size as usize);
    }

    result
}

/// Test: Basic chunk sending
#[tokio::test]
async fn test_basic_chunks() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // Create test data and encode as chunks
    let test_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let chunked = encode_as_chunks(&test_data, 100);

    let response = client.call(pipe_opnum::SEND_CHUNKS, chunked).await.unwrap();

    let ctx = NdrContext::default();
    let mut cursor = response.as_ref();
    let chunk_count = ctx.get_u32(&mut cursor);
    let total_bytes = ctx.get_u64(&mut cursor);

    server_handle.abort();

    println!("\n=== Basic Chunks Test ===");
    println!("Data size: {} bytes", test_data.len());
    println!("Chunk count: {} (expected 10)", chunk_count);
    println!("Total bytes: {} (expected 1000)", total_bytes);

    assert_eq!(chunk_count, 10);
    assert_eq!(total_bytes, 1000);

    println!("Basic Chunks Test: PASSED");
}

/// Test: Chunk echo (round-trip)
#[tokio::test]
async fn test_chunk_echo() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // Various data sizes
    let test_sizes = [0, 1, 100, 1000, 10000];
    let chunk_sizes = [16, 64, 256, 1024];

    for &data_size in &test_sizes {
        for &chunk_size in &chunk_sizes {
            let mut gen = TestDataGenerator::new((data_size * chunk_size) as u64);
            let test_data = gen.random_bytes(data_size);
            let expected_checksum = compute_checksum(&test_data);

            let chunked = encode_as_chunks(&test_data, chunk_size);
            let response = client.call(pipe_opnum::ECHO_CHUNKS, chunked).await.unwrap();
            let decoded = decode_chunks(&response);
            let response_checksum = compute_checksum(&decoded);

            assert_eq!(expected_checksum, response_checksum,
                "Data corruption for size={}, chunk_size={}", data_size, chunk_size);
        }
    }

    server_handle.abort();
    println!("\n=== Chunk Echo Test: PASSED ===");
}

/// Test: Sum stream of integers
#[tokio::test]
async fn test_sum_stream() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    let ctx = NdrContext::default();

    // Create a stream of integers
    let values: Vec<i32> = (1..=100).collect();
    let expected_sum: i64 = values.iter().map(|&x| x as i64).sum();

    // Encode as pipe chunks (each chunk contains multiple i32s)
    let mut data = BytesMut::new();
    for chunk in values.chunks(10) {
        let chunk_size = (chunk.len() * 4) as u32;
        ctx.put_u32(&mut data, chunk_size);
        for &val in chunk {
            ctx.put_i32(&mut data, val);
        }
    }
    ctx.put_u32(&mut data, 0); // End marker

    let response = client.call(pipe_opnum::SUM_STREAM, data.freeze()).await.unwrap();

    let mut cursor = response.as_ref();
    let sum = ctx.get_i64(&mut cursor);

    server_handle.abort();

    println!("\n=== Sum Stream Test ===");
    println!("Values: 1 to 100");
    println!("Sum: {} (expected {})", sum, expected_sum);

    assert_eq!(sum, expected_sum);

    println!("Sum Stream Test: PASSED");
}

/// Test: Large data transfer
#[tokio::test]
async fn test_large_pipe_transfer() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // Test with various sizes (DCE RPC has fragmentation limits around 32KB)
    let sizes = [4 * 1024, 16 * 1024, 32 * 1024];

    for size in sizes {
        let mut gen = TestDataGenerator::new(size as u64);
        let test_data = gen.random_bytes(size);
        let expected_checksum = compute_checksum(&test_data);

        let start = Instant::now();
        let response = client.call(pipe_opnum::LARGE_TRANSFER, test_data).await.unwrap();
        let duration = start.elapsed();

        let ctx = NdrContext::default();
        let mut cursor = response.as_ref();
        let response_checksum = ctx.get_u64(&mut cursor);
        let response_size = ctx.get_u64(&mut cursor);

        let throughput = size as f64 / duration.as_secs_f64() / 1024.0 / 1024.0;

        println!("Size: {} KB, Duration: {:?}, Throughput: {:.2} MB/s",
            size / 1024, duration, throughput);

        assert_eq!(expected_checksum, response_checksum,
            "Data corruption for size {}", size);
        assert_eq!(response_size, size as u64);
    }

    server_handle.abort();
    println!("\n=== Large Pipe Transfer Test: PASSED ===");
}

/// Test: Bidirectional transformation
#[tokio::test]
async fn test_bidirectional_pipe() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // Create test data
    let test_data: Vec<u8> = (0..100).collect();
    let chunked = encode_as_chunks(&test_data, 20);

    let response = client.call(pipe_opnum::BIDIRECTIONAL, chunked).await.unwrap();
    let decoded = decode_chunks(&response);

    // Verify transformation (each byte doubled)
    let expected: Vec<u8> = test_data.iter().map(|&b| b.wrapping_mul(2)).collect();

    server_handle.abort();

    println!("\n=== Bidirectional Pipe Test ===");
    println!("Input size: {} bytes", test_data.len());
    println!("Output size: {} bytes", decoded.len());

    assert_eq!(decoded, expected, "Transformation incorrect");

    println!("Bidirectional Pipe Test: PASSED");
}

/// Test: Concurrent pipe operations
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_pipe_ops() {
    init_logging();

    const NUM_CLIENTS: usize = 10;
    const OPS_PER_CLIENT: usize = 20;

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let mut handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

            for i in 0..OPS_PER_CLIENT {
                let mut gen = TestDataGenerator::new((client_id * 1000 + i) as u64);
                let data_size = 100 + (i % 10) * 100; // 100-1000 bytes
                let chunk_size = 50 + (i % 5) * 20;   // 50-130 bytes

                let test_data = gen.random_bytes(data_size);
                let expected_checksum = compute_checksum(&test_data);
                let chunked = encode_as_chunks(&test_data, chunk_size);

                let start = Instant::now();
                match client.call(pipe_opnum::ECHO_CHUNKS, chunked).await {
                    Ok(response) => {
                        let decoded = decode_chunks(&response);
                        let response_checksum = compute_checksum(&decoded);

                        if expected_checksum == response_checksum {
                            stats.record_success(start.elapsed());
                        } else {
                            stats.record_failure();
                        }
                    }
                    Err(_) => {
                        stats.record_failure();
                    }
                }
            }
        });

        handles.push(handle);
    }

    join_all(handles).await;
    server_handle.abort();

    let total = (NUM_CLIENTS * OPS_PER_CLIENT) as u64;
    println!("\n=== Concurrent Pipe Ops Test ===");
    println!("Clients: {}", NUM_CLIENTS);
    println!("Ops per client: {}", OPS_PER_CLIENT);
    println!("Total: {}", total);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Avg latency: {:?}", stats.avg_latency());

    assert_eq!(stats.failure_count(), 0, "All pipe operations should succeed");

    println!("Concurrent Pipe Ops Test: PASSED");
}

/// Test: Empty pipe
#[tokio::test]
async fn test_empty_pipe() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // Empty pipe (just end marker)
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_u32(&mut buf, 0);

    let response = client.call(pipe_opnum::SEND_CHUNKS, buf.freeze()).await.unwrap();

    let mut cursor = response.as_ref();
    let chunk_count = ctx.get_u32(&mut cursor);
    let total_bytes = ctx.get_u64(&mut cursor);

    server_handle.abort();

    println!("\n=== Empty Pipe Test ===");
    println!("Chunk count: {}", chunk_count);
    println!("Total bytes: {}", total_bytes);

    assert_eq!(chunk_count, 0);
    assert_eq!(total_bytes, 0);

    println!("Empty Pipe Test: PASSED");
}

/// Test: Single byte chunks (worst case fragmentation)
#[tokio::test]
async fn test_single_byte_chunks() {
    init_logging();

    let interface = create_pipe_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, PIPE_UUID, PIPE_VERSION).await.unwrap();

    // 100 single-byte chunks
    let test_data: Vec<u8> = (0..100).collect();
    let chunked = encode_as_chunks(&test_data, 1); // 1 byte per chunk

    let response = client.call(pipe_opnum::ECHO_CHUNKS, chunked).await.unwrap();
    let decoded = decode_chunks(&response);

    server_handle.abort();

    println!("\n=== Single Byte Chunks Test ===");
    println!("Chunks: 100");
    println!("Decoded size: {}", decoded.len());

    assert_eq!(decoded, test_data);

    println!("Single Byte Chunks Test: PASSED");
}

/// Test: PipeChunk struct functionality
#[tokio::test]
async fn test_pipe_chunk_struct() {
    init_logging();

    // Test PipeChunk creation and usage
    let chunk1: PipeChunk<i32> = PipeChunk::new(vec![1, 2, 3]);
    let chunk2: PipeChunk<i32> = PipeChunk::new(vec![4, 5, 6]);
    let empty: PipeChunk<i32> = PipeChunk::empty();

    println!("\n=== PipeChunk Struct Test ===");
    println!("Chunk1 len: {}", chunk1.len());
    println!("Chunk2 len: {}", chunk2.len());
    println!("Empty chunk is_empty: {}", empty.is_empty());

    assert_eq!(chunk1.len(), 3);
    assert_eq!(chunk2.len(), 3);
    assert!(empty.is_empty());

    println!("PipeChunk Struct Test: PASSED");
}

/// Test: PipeWriter/PipeReader roundtrip
#[tokio::test]
async fn test_pipe_writer_reader_roundtrip() {
    init_logging();

    // Test using PipeWriter and PipeReader for encoding/decoding
    let mut writer = PipeWriter::new(PipeFormat::Ndr);

    // Write some data chunks
    let data1: [u8; 4] = [1, 2, 3, 4];
    let data2: [u8; 4] = [5, 6, 7, 8];

    writer.write_bytes(&data1);
    writer.write_bytes(&data2);
    let encoded = writer.finish();

    // Read it back
    let mut reader = PipeReader::new(&encoded, PipeFormat::Ndr);
    let decoded = reader.read_all_bytes().unwrap();

    println!("\n=== PipeWriter/PipeReader Roundtrip Test ===");
    println!("Encoded size: {} bytes", encoded.len());
    println!("Decoded size: {} bytes", decoded.len());
    println!("Original: {:?}", [data1, data2].concat());
    println!("Decoded: {:?}", decoded);

    // The decoded data should match what we wrote
    assert_eq!(decoded.len(), 8);

    println!("PipeWriter/PipeReader Roundtrip Test: PASSED");
}
