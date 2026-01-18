//! Complex Types Tests - MIDL NDR Encoding Scenarios
//!
//! These tests exercise complex data type handling:
//! - Nested structures
//! - Conformant and varying arrays
//! - Pointers (ref, unique, full)
//! - Strings (ANSI and Unicode)
//! - Unions with discriminants
//! - Large data transfers

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use futures::future::join_all;

use common::*;
use dcerpc::{DceRpcClient, DceRpcServer, Interface, InterfaceBuilder, SyntaxId, Uuid};
use midl_ndr::{NdrContext, NdrEncode, NdrDecode, NdrString, NdrWString, UniquePtr};

/// Interface for complex type testing
pub const COMPLEX_UUID: &str = "c3d4e5f6-a7b8-9012-cdef-234567890123";
pub const COMPLEX_VERSION: (u16, u16) = (1, 0);

/// Operation numbers
pub mod complex_opnum {
    pub const ECHO_STRUCT: u16 = 0;
    pub const ECHO_ARRAY: u16 = 1;
    pub const ECHO_STRING: u16 = 2;
    pub const ECHO_WSTRING: u16 = 3;
    pub const ECHO_NESTED: u16 = 4;
    pub const ECHO_UNIQUE_PTR: u16 = 5;
    pub const ECHO_LARGE_DATA: u16 = 6;
    pub const SUM_ARRAY: u16 = 7;
    pub const CONCAT_STRINGS: u16 = 8;
    pub const TRANSFORM_STRUCT: u16 = 9;
}

/// Simple struct for testing
#[derive(Debug, Clone, PartialEq)]
struct Point {
    x: i32,
    y: i32,
}

impl Point {
    fn encode(&self, buf: &mut BytesMut, ctx: &NdrContext) {
        ctx.put_i32(buf, self.x);
        ctx.put_i32(buf, self.y);
    }

    fn decode(cursor: &mut &[u8], ctx: &NdrContext) -> Option<Self> {
        if cursor.remaining() < 8 {
            return None;
        }
        Some(Self {
            x: ctx.get_i32(cursor),
            y: ctx.get_i32(cursor),
        })
    }
}

/// Rectangle struct with nested Points
#[derive(Debug, Clone, PartialEq)]
struct Rectangle {
    top_left: Point,
    bottom_right: Point,
    color: u32,
}

impl Rectangle {
    fn encode(&self, buf: &mut BytesMut, ctx: &NdrContext) {
        self.top_left.encode(buf, ctx);
        self.bottom_right.encode(buf, ctx);
        ctx.put_u32(buf, self.color);
    }

    fn decode(cursor: &mut &[u8], ctx: &NdrContext) -> Option<Self> {
        let top_left = Point::decode(cursor, ctx)?;
        let bottom_right = Point::decode(cursor, ctx)?;
        if cursor.remaining() < 4 {
            return None;
        }
        let color = ctx.get_u32(cursor);
        Some(Self { top_left, bottom_right, color })
    }
}

/// Complex nested structure
#[derive(Debug, Clone, PartialEq)]
struct ComplexNested {
    id: u64,
    name_len: u32,
    name: Vec<u8>,
    points_count: u32,
    points: Vec<Point>,
    optional_rect: Option<Rectangle>,
}

impl ComplexNested {
    fn encode(&self, buf: &mut BytesMut, ctx: &NdrContext) {
        ctx.put_u64(buf, self.id);

        // Conformant string
        ctx.put_u32(buf, self.name_len);
        buf.put_slice(&self.name);
        // Pad to alignment
        while buf.len() % 4 != 0 {
            buf.put_u8(0);
        }

        // Conformant array of points
        ctx.put_u32(buf, self.points_count);
        for p in &self.points {
            p.encode(buf, ctx);
        }

        // Unique pointer to rectangle
        if let Some(ref rect) = self.optional_rect {
            ctx.put_u32(buf, 1); // non-null
            rect.encode(buf, ctx);
        } else {
            ctx.put_u32(buf, 0); // null
        }
    }

    fn decode(cursor: &mut &[u8], ctx: &NdrContext) -> Option<Self> {
        if cursor.remaining() < 8 {
            return None;
        }
        let id = ctx.get_u64(cursor);

        if cursor.remaining() < 4 {
            return None;
        }
        let name_len = ctx.get_u32(cursor);

        if cursor.remaining() < name_len as usize {
            return None;
        }
        let name: Vec<u8> = cursor[..name_len as usize].to_vec();
        cursor.advance(name_len as usize);
        // Skip padding
        while cursor.len() % 4 != 0 && !cursor.is_empty() {
            cursor.advance(1);
        }

        if cursor.remaining() < 4 {
            return None;
        }
        let points_count = ctx.get_u32(cursor);

        let mut points = Vec::with_capacity(points_count as usize);
        for _ in 0..points_count {
            points.push(Point::decode(cursor, ctx)?);
        }

        if cursor.remaining() < 4 {
            return None;
        }
        let has_rect = ctx.get_u32(cursor) != 0;
        let optional_rect = if has_rect {
            Some(Rectangle::decode(cursor, ctx)?)
        } else {
            None
        };

        Some(Self {
            id,
            name_len,
            name,
            points_count,
            points,
            optional_rect,
        })
    }
}

/// Create the complex types test interface
fn create_complex_interface() -> Interface {
    InterfaceBuilder::new(COMPLEX_UUID, COMPLEX_VERSION.0, COMPLEX_VERSION.1)
        .unwrap()
        // Echo struct (Point)
        .operation(complex_opnum::ECHO_STRUCT, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo array
        .operation(complex_opnum::ECHO_ARRAY, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo string
        .operation(complex_opnum::ECHO_STRING, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo wide string
        .operation(complex_opnum::ECHO_WSTRING, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo nested structure
        .operation(complex_opnum::ECHO_NESTED, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo unique pointer
        .operation(complex_opnum::ECHO_UNIQUE_PTR, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Echo large data
        .operation(complex_opnum::ECHO_LARGE_DATA, |stub_data| {
            Box::pin(async move { Ok(stub_data) })
        })
        // Sum array of integers
        .operation(complex_opnum::SUM_ARRAY, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();

                if cursor.remaining() < 4 {
                    return Ok(Bytes::new());
                }
                let count = ctx.get_u32(&mut cursor) as usize;

                let mut sum: i64 = 0;
                for _ in 0..count {
                    if cursor.remaining() < 4 {
                        break;
                    }
                    sum += ctx.get_i32(&mut cursor) as i64;
                }

                let mut buf = BytesMut::new();
                ctx.put_i64(&mut buf, sum);
                Ok(buf.freeze())
            })
        })
        // Concatenate strings
        .operation(complex_opnum::CONCAT_STRINGS, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let mut position = 0usize;

                // Decode two strings and concatenate
                let s1 = match NdrString::ndr_decode(&mut cursor, &ctx, &mut position) {
                    Ok(s) => s,
                    Err(_) => return Ok(Bytes::new()),
                };
                let s2 = match NdrString::ndr_decode(&mut cursor, &ctx, &mut position) {
                    Ok(s) => s,
                    Err(_) => return Ok(Bytes::new()),
                };

                let concatenated = format!("{}{}", s1.as_str(), s2.as_str());
                let result = NdrString::from(concatenated);

                let mut buf = BytesMut::new();
                let mut pos = 0usize;
                result.ndr_encode(&mut buf, &ctx, &mut pos).ok();

                Ok(buf.freeze())
            })
        })
        // Transform struct (double coordinates)
        .operation(complex_opnum::TRANSFORM_STRUCT, |stub_data| {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();

                let point = match Point::decode(&mut cursor, &ctx) {
                    Some(p) => p,
                    None => return Ok(Bytes::new()),
                };

                let transformed = Point {
                    x: point.x * 2,
                    y: point.y * 2,
                };

                let mut buf = BytesMut::new();
                transformed.encode(&mut buf, &ctx);
                Ok(buf.freeze())
            })
        })
        .build()
}

/// Test: Simple struct encoding/decoding
#[tokio::test]
async fn test_simple_struct() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    let point = Point { x: 100, y: -50 };
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    point.encode(&mut buf, &ctx);

    let response = client.call(complex_opnum::ECHO_STRUCT, buf.freeze()).await.unwrap();
    let mut cursor = response.as_ref();
    let decoded = Point::decode(&mut cursor, &ctx).unwrap();

    server_handle.abort();

    println!("\n=== Simple Struct Test ===");
    println!("Original: {:?}", point);
    println!("Decoded: {:?}", decoded);

    assert_eq!(point, decoded);
}

/// Test: Conformant array
#[tokio::test]
async fn test_conformant_array() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    // Test various array sizes
    let sizes = [0, 1, 10, 100, 1000];

    for size in sizes {
        let ctx = NdrContext::default();
        let mut buf = BytesMut::new();

        // Encode conformant array
        ctx.put_u32(&mut buf, size);
        let mut expected_sum: i64 = 0;
        for i in 0..size {
            let val = (i as i32) * 2 - (size as i32);
            ctx.put_i32(&mut buf, val);
            expected_sum += val as i64;
        }

        let response = client.call(complex_opnum::SUM_ARRAY, buf.freeze()).await.unwrap();

        let mut cursor = response.as_ref();
        let sum = ctx.get_i64(&mut cursor);

        println!("Array size {}: sum = {}, expected = {}", size, sum, expected_sum);
        assert_eq!(sum, expected_sum, "Sum mismatch for size {}", size);
    }

    server_handle.abort();
    println!("\n=== Conformant Array Test: PASSED ===");
}

/// Test: NDR strings (ANSI)
#[tokio::test]
async fn test_ndr_string() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    let test_strings = [
        "",
        "Hello",
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        &"x".repeat(1000),
    ];

    for s in test_strings {
        let ctx = NdrContext::default();
        let mut buf = BytesMut::new();
        let mut position = 0usize;

        let ndr_str = NdrString::from(s);
        ndr_str.ndr_encode(&mut buf, &ctx, &mut position).unwrap();

        let response = client.call(complex_opnum::ECHO_STRING, buf.freeze()).await.unwrap();

        let mut cursor = response.as_ref();
        position = 0;
        let decoded = NdrString::ndr_decode(&mut cursor, &ctx, &mut position).unwrap();

        assert_eq!(s, decoded.as_str(),
            "String mismatch for length {}", s.len());
    }

    server_handle.abort();
    println!("\n=== NDR String Test: PASSED ===");
}

/// Test: NDR wide strings (Unicode)
#[tokio::test]
async fn test_ndr_wstring() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    let test_strings = [
        "",
        "Hello",
        "Unicode: \u{00E9}\u{00E8}\u{00EA}", // French accents
        "\u{4E2D}\u{6587}", // Chinese characters
        "\u{1F600}\u{1F601}", // Emojis (may need surrogate pairs)
    ];

    for s in test_strings {
        let ctx = NdrContext::default();
        let mut buf = BytesMut::new();
        let mut position = 0usize;

        let ndr_str = NdrWString::from(s);
        ndr_str.ndr_encode(&mut buf, &ctx, &mut position).unwrap();

        let response = client.call(complex_opnum::ECHO_WSTRING, buf.freeze()).await.unwrap();

        let mut cursor = response.as_ref();
        position = 0;
        let decoded = NdrWString::ndr_decode(&mut cursor, &ctx, &mut position).unwrap();

        println!("WString test: '{}' -> '{}'", s, decoded.as_str());
        assert_eq!(s, decoded.as_str(),
            "WString mismatch for: {}", s);
    }

    server_handle.abort();
    println!("\n=== NDR WString Test: PASSED ===");
}

/// Test: Nested structures
#[tokio::test]
async fn test_nested_structures() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    // Test with optional rect
    let nested = ComplexNested {
        id: 0x123456789ABCDEF0,
        name_len: 5,
        name: b"Hello".to_vec(),
        points_count: 3,
        points: vec![
            Point { x: 1, y: 2 },
            Point { x: 3, y: 4 },
            Point { x: 5, y: 6 },
        ],
        optional_rect: Some(Rectangle {
            top_left: Point { x: 0, y: 0 },
            bottom_right: Point { x: 100, y: 100 },
            color: 0xFF0000,
        }),
    };

    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    nested.encode(&mut buf, &ctx);

    let response = client.call(complex_opnum::ECHO_NESTED, buf.freeze()).await.unwrap();
    let mut cursor = response.as_ref();
    let decoded = ComplexNested::decode(&mut cursor, &ctx).unwrap();

    assert_eq!(nested.id, decoded.id);
    assert_eq!(nested.name, decoded.name);
    assert_eq!(nested.points, decoded.points);
    assert_eq!(nested.optional_rect, decoded.optional_rect);

    // Test without optional rect
    let nested_no_rect = ComplexNested {
        id: 42,
        name_len: 4,
        name: b"Test".to_vec(),
        points_count: 0,
        points: vec![],
        optional_rect: None,
    };

    let mut buf = BytesMut::new();
    nested_no_rect.encode(&mut buf, &ctx);

    let response = client.call(complex_opnum::ECHO_NESTED, buf.freeze()).await.unwrap();
    let mut cursor = response.as_ref();
    let decoded = ComplexNested::decode(&mut cursor, &ctx).unwrap();

    assert_eq!(nested_no_rect.optional_rect, decoded.optional_rect);

    server_handle.abort();
    println!("\n=== Nested Structures Test: PASSED ===");
}

/// Test: Unique pointer
#[tokio::test]
async fn test_unique_pointer() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    // Test non-null pointer
    let ctx = NdrContext::default();
    let ptr: UniquePtr<i32> = UniquePtr::new(42);

    let mut buf = BytesMut::new();
    let mut position = 0usize;
    ptr.ndr_encode(&mut buf, &ctx, &mut position).unwrap();

    let response = client.call(complex_opnum::ECHO_UNIQUE_PTR, buf.freeze()).await.unwrap();
    let mut cursor = response.as_ref();
    position = 0;
    let decoded: UniquePtr<i32> = UniquePtr::ndr_decode(&mut cursor, &ctx, &mut position).unwrap();

    assert_eq!(ptr.as_ref(), decoded.as_ref());

    // Test null pointer
    let null_ptr: UniquePtr<i32> = UniquePtr::default();

    let mut buf = BytesMut::new();
    position = 0;
    null_ptr.ndr_encode(&mut buf, &ctx, &mut position).unwrap();

    let response = client.call(complex_opnum::ECHO_UNIQUE_PTR, buf.freeze()).await.unwrap();
    let mut cursor = response.as_ref();
    position = 0;
    let decoded: UniquePtr<i32> = UniquePtr::ndr_decode(&mut cursor, &ctx, &mut position).unwrap();

    assert!(decoded.as_ref().is_none());

    server_handle.abort();
    println!("\n=== Unique Pointer Test: PASSED ===");
}

/// Test: Large data transfer
#[tokio::test]
async fn test_large_data_transfer() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    // Test various sizes up to 32KB (DCE RPC has fragmentation limits)
    // Note: Larger transfers require proper PDU fragmentation support
    let sizes = [1024, 4 * 1024, 16 * 1024, 32 * 1024];

    for size in sizes {
        let mut gen = TestDataGenerator::new(size as u64);
        let data = gen.random_bytes(size);
        let expected_checksum = compute_checksum(&data);

        let start = Instant::now();
        let response = client.call(complex_opnum::ECHO_LARGE_DATA, data).await.unwrap();
        let duration = start.elapsed();

        let response_checksum = compute_checksum(&response);

        let throughput = size as f64 / duration.as_secs_f64() / 1024.0 / 1024.0;

        println!("Size: {} KB, Duration: {:?}, Throughput: {:.2} MB/s",
            size / 1024, duration, throughput);

        assert_eq!(expected_checksum, response_checksum,
            "Data corruption for size {}", size);
    }

    server_handle.abort();
    println!("\n=== Large Data Transfer Test: PASSED ===");
}

/// Test: String concatenation (processing complex types)
#[tokio::test]
async fn test_string_processing() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    let long_string = "Long string ".repeat(10);
    let test_cases = [
        ("Hello", " World"),
        ("", "Empty first"),
        ("Empty second", ""),
        ("", ""),
        (long_string.as_str(), "end"),
    ];

    for (s1, s2) in test_cases.iter().map(|(a, b)| (a.to_string(), b.to_string())) {
        let ctx = NdrContext::default();
        let mut buf = BytesMut::new();
        let mut position = 0usize;

        let ndr_s1 = NdrString::from(s1.as_str());
        let ndr_s2 = NdrString::from(s2.as_str());

        ndr_s1.ndr_encode(&mut buf, &ctx, &mut position).unwrap();
        ndr_s2.ndr_encode(&mut buf, &ctx, &mut position).unwrap();

        let response = client.call(complex_opnum::CONCAT_STRINGS, buf.freeze()).await.unwrap();

        let mut cursor = response.as_ref();
        position = 0;
        let result = NdrString::ndr_decode(&mut cursor, &ctx, &mut position).unwrap();

        let expected = format!("{}{}", s1, s2);
        assert_eq!(expected, result.as_str(),
            "Concat mismatch for '{}' + '{}'", s1, s2);
    }

    server_handle.abort();
    println!("\n=== String Processing Test: PASSED ===");
}

/// Test: Struct transformation
#[tokio::test]
async fn test_struct_transformation() {
    init_logging();

    let interface = create_complex_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();

    let test_points = [
        Point { x: 0, y: 0 },
        Point { x: 1, y: 1 },
        Point { x: -5, y: 10 },
        Point { x: i32::MAX / 2, y: i32::MIN / 2 },
    ];

    for point in test_points {
        let ctx = NdrContext::default();
        let mut buf = BytesMut::new();
        point.encode(&mut buf, &ctx);

        let response = client.call(complex_opnum::TRANSFORM_STRUCT, buf.freeze()).await.unwrap();
        let mut cursor = response.as_ref();
        let transformed = Point::decode(&mut cursor, &ctx).unwrap();

        let expected = Point { x: point.x * 2, y: point.y * 2 };
        assert_eq!(expected, transformed,
            "Transform mismatch for {:?}", point);
    }

    server_handle.abort();
    println!("\n=== Struct Transformation Test: PASSED ===");
}

/// Test: Concurrent complex operations
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_complex_operations() {
    init_logging();

    const NUM_CLIENTS: usize = 10;
    const OPS_PER_CLIENT: usize = 50;

    let interface = create_complex_interface();
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
            let client = connect_client(addr, COMPLEX_UUID, COMPLEX_VERSION).await.unwrap();
            let ctx = NdrContext::default();

            for i in 0..OPS_PER_CLIENT {
                let op = i % 4;
                let start = Instant::now();

                let result = match op {
                    0 => {
                        // Simple struct
                        let point = Point { x: client_id as i32, y: i as i32 };
                        let mut buf = BytesMut::new();
                        point.encode(&mut buf, &ctx);
                        client.call(complex_opnum::ECHO_STRUCT, buf.freeze()).await
                    }
                    1 => {
                        // String
                        let mut buf = BytesMut::new();
                        let mut pos = 0;
                        let s = NdrString::from(format!("client_{}_op_{}", client_id, i));
                        s.ndr_encode(&mut buf, &ctx, &mut pos).unwrap();
                        client.call(complex_opnum::ECHO_STRING, buf.freeze()).await
                    }
                    2 => {
                        // Array sum
                        let mut buf = BytesMut::new();
                        ctx.put_u32(&mut buf, 10);
                        for j in 0..10 {
                            ctx.put_i32(&mut buf, j);
                        }
                        client.call(complex_opnum::SUM_ARRAY, buf.freeze()).await
                    }
                    _ => {
                        // Transform
                        let point = Point { x: i as i32, y: -(i as i32) };
                        let mut buf = BytesMut::new();
                        point.encode(&mut buf, &ctx);
                        client.call(complex_opnum::TRANSFORM_STRUCT, buf.freeze()).await
                    }
                };

                match result {
                    Ok(_) => stats.record_success(start.elapsed()),
                    Err(_) => stats.record_failure(),
                }
            }
        });

        handles.push(handle);
    }

    join_all(handles).await;
    server_handle.abort();

    let total = (NUM_CLIENTS * OPS_PER_CLIENT) as u64;
    println!("\n=== Concurrent Complex Operations Test ===");
    println!("Total operations: {}", total);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Avg latency: {:?}", stats.avg_latency());

    assert_eq!(stats.failure_count(), 0, "All operations should succeed");
}
