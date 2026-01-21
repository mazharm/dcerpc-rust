//! Fragmentation Tests - Large PDU Transfer Tests
//!
//! These tests exercise the multi-PDU fragmentation support for large data transfers:
//! - Requests exceeding max_xmit_frag (default 4280 bytes)
//! - Responses exceeding max_recv_frag
//! - Bidirectional large transfers
//! - Fragmentation under concurrent load

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::{BufMut, BytesMut};
use futures::future::join_all;

use common::*;
use dcerpc::{
    DceRpcClient, DceRpcServer, DceRpcServerConfig, Interface, InterfaceBuilder, SyntaxId, Uuid,
};

const FRAG_TEST_UUID: &str = "f1a2b3c4-d5e6-7890-abcd-ef1234567890";
const FRAG_TEST_VERSION: (u16, u16) = (1, 0);

/// Create a test interface that echoes data (for large payload testing)
fn create_large_echo_interface() -> Interface {
    let uuid = Uuid::parse(FRAG_TEST_UUID).unwrap();
    InterfaceBuilder::from_syntax(SyntaxId::new(uuid, FRAG_TEST_VERSION.0, FRAG_TEST_VERSION.1))
        // opnum 0: Echo - returns the input data unchanged
        .operation(0, |args| async move {
            Ok(args)
        })
        // opnum 1: GenerateLarge - returns N bytes of pattern data
        // Input: 4 bytes (u32 LE) specifying size
        .operation(1, |args| async move {
            if args.len() < 4 {
                return Err(dcerpc::RpcError::CallRejected("invalid input".to_string()));
            }
            let size = u32::from_le_bytes([args[0], args[1], args[2], args[3]]) as usize;
            // Generate pattern data
            let mut data = BytesMut::with_capacity(size);
            for i in 0..size {
                data.put_u8((i % 256) as u8);
            }
            Ok(data.freeze())
        })
        // opnum 2: Checksum - returns a simple checksum of the input
        // Output: 8 bytes (u64 LE) checksum
        .operation(2, |args| async move {
            let checksum = compute_checksum(&args);
            let mut result = BytesMut::with_capacity(8);
            result.put_u64_le(checksum);
            Ok(result.freeze())
        })
        .build()
}

/// Start a test server with specific fragment size configuration
async fn start_frag_test_server(
    interface: Interface,
    max_frag: u16,
) -> dcerpc::Result<(std::net::SocketAddr, Arc<DceRpcServer>)> {
    use tokio::net::TcpListener;

    let config = DceRpcServerConfig {
        max_pdu_size: 1024 * 1024, // 1MB max PDU
        max_connections: 100,
        max_xmit_frag: max_frag,
        max_recv_frag: max_frag,
        max_concurrent_fragments: 100,
        max_connection_memory_budget: 16 * 1024 * 1024,
    };

    let server = Arc::new(DceRpcServer::with_config(config));
    server.register_interface(interface).await;

    // Find available port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    Ok((addr, server))
}

/// Connect a client to the fragmentation test server
async fn connect_frag_client(addr: std::net::SocketAddr) -> dcerpc::Result<DceRpcClient> {
    let uuid = Uuid::parse(FRAG_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, FRAG_TEST_VERSION.0, FRAG_TEST_VERSION.1);
    DceRpcClient::connect(addr, syntax).await
}

/// Test: Large request fragmentation
/// Sends a request that exceeds max_xmit_frag and verifies it's correctly received
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_request_fragmentation() {
    init_logging();

    const REQUEST_SIZE: usize = 100_000; // 100KB - will require ~25 fragments at 4KB max

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, 4096).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_frag_client(addr).await.unwrap();

    // Generate large test data with pattern
    let mut payload = BytesMut::with_capacity(REQUEST_SIZE);
    for i in 0..REQUEST_SIZE {
        payload.put_u8((i % 256) as u8);
    }
    let payload = payload.freeze();
    let expected_checksum = compute_checksum(&payload);

    println!("Sending {} byte request (should fragment into ~25 PDUs)", REQUEST_SIZE);
    let start = Instant::now();

    match client.call(0, payload.clone()).await {
        Ok(response) => {
            let duration = start.elapsed();
            let response_checksum = compute_checksum(&response);

            println!("Response received in {:?}", duration);
            println!("Request size: {} bytes", REQUEST_SIZE);
            println!("Response size: {} bytes", response.len());

            assert_eq!(response.len(), REQUEST_SIZE, "Response size mismatch");
            assert_eq!(response_checksum, expected_checksum, "Data corruption detected!");
            println!("✓ Large request fragmentation test passed");
        }
        Err(e) => {
            panic!("Large request failed: {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Large response fragmentation
/// Requests the server to generate a large response
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_large_response_fragmentation() {
    init_logging();

    const RESPONSE_SIZE: usize = 150_000; // 150KB response

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, 4096).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_frag_client(addr).await.unwrap();

    // Request server to generate large response
    let mut request = BytesMut::with_capacity(4);
    request.put_u32_le(RESPONSE_SIZE as u32);

    println!("Requesting {} byte response (should fragment into ~37 PDUs)", RESPONSE_SIZE);
    let start = Instant::now();

    match client.call(1, request.freeze()).await {
        Ok(response) => {
            let duration = start.elapsed();

            println!("Response received in {:?}", duration);
            println!("Response size: {} bytes", response.len());

            assert_eq!(response.len(), RESPONSE_SIZE, "Response size mismatch");

            // Verify pattern
            for (i, byte) in response.iter().enumerate() {
                assert_eq!(*byte, (i % 256) as u8, "Pattern mismatch at byte {}", i);
            }

            println!("✓ Large response fragmentation test passed");
        }
        Err(e) => {
            panic!("Large response request failed: {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Bidirectional large transfer
/// Both request and response are large
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_bidirectional_large_transfer() {
    init_logging();

    const DATA_SIZE: usize = 75_000; // 75KB each way

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, 4096).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_frag_client(addr).await.unwrap();

    // Generate random test data
    let mut gen = TestDataGenerator::new(12345);
    let payload = gen.random_bytes(DATA_SIZE);
    let expected_checksum = compute_checksum(&payload);

    println!("Sending {} byte request, expecting {} byte response", DATA_SIZE, DATA_SIZE);
    let start = Instant::now();

    match client.call(0, payload).await {
        Ok(response) => {
            let duration = start.elapsed();
            let response_checksum = compute_checksum(&response);

            println!("Bidirectional transfer completed in {:?}", duration);
            println!("Throughput: {:.2} MB/s", (DATA_SIZE * 2) as f64 / duration.as_secs_f64() / 1_000_000.0);

            assert_eq!(response.len(), DATA_SIZE, "Response size mismatch");
            assert_eq!(response_checksum, expected_checksum, "Data corruption detected!");

            println!("✓ Bidirectional large transfer test passed");
        }
        Err(e) => {
            panic!("Bidirectional transfer failed: {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Multiple concurrent large requests
/// Tests fragmentation under concurrent load
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_fragmentation_under_load() {
    init_logging();

    const NUM_CLIENTS: usize = 10;
    const REQUESTS_PER_CLIENT: usize = 5;
    const DATA_SIZE: usize = 50_000; // 50KB per request

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, 4096).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let mut handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            let client = match connect_frag_client(addr).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Client {} failed to connect: {}", client_id, e);
                    stats.record_failure();
                    return;
                }
            };

            let mut gen = TestDataGenerator::new(client_id as u64 * 12345);

            for req_id in 0..REQUESTS_PER_CLIENT {
                let payload = gen.random_bytes(DATA_SIZE);
                let expected_checksum = compute_checksum(&payload);

                let start = Instant::now();
                match client.call(0, payload).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        let response_checksum = compute_checksum(&response);

                        if response.len() == DATA_SIZE && response_checksum == expected_checksum {
                            stats.record_success(latency);
                        } else {
                            eprintln!(
                                "Client {} request {} data mismatch: expected {}B, got {}B",
                                client_id, req_id, DATA_SIZE, response.len()
                            );
                            stats.record_failure();
                        }
                    }
                    Err(e) => {
                        eprintln!("Client {} request {} failed: {}", client_id, req_id, e);
                        stats.record_failure();
                    }
                }
            }
        });

        handles.push(handle);
    }

    join_all(handles).await;
    server_handle.abort();

    let total = (NUM_CLIENTS * REQUESTS_PER_CLIENT) as u64;
    let success = stats.success_count();
    let failure = stats.failure_count();

    println!("\n=== Fragmentation Under Load Test Results ===");
    println!("Total requests: {} ({} KB each)", total, DATA_SIZE / 1024);
    println!("Successful: {} ({:.1}%)", success, (success as f64 / total as f64) * 100.0);
    println!("Failed: {}", failure);
    println!("Avg latency: {:?}", stats.avg_latency());
    println!("Max latency: {:?}", stats.max_latency());

    assert!(success >= total * 95 / 100, "Too many failures: {} out of {}", failure, total);
    println!("✓ Fragmentation under load test passed");
}

/// Test: Very large payload (stress test)
/// Tests with 1MB payload
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_very_large_payload() {
    init_logging();

    const DATA_SIZE: usize = 1_000_000; // 1MB

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, 4096).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_frag_client(addr).await.unwrap();

    // Generate 1MB of test data
    let mut gen = TestDataGenerator::new(999);
    let payload = gen.random_bytes(DATA_SIZE);
    let expected_checksum = compute_checksum(&payload);

    println!("Sending 1MB request (should fragment into ~250 PDUs)");
    let start = Instant::now();

    match client.call(0, payload).await {
        Ok(response) => {
            let duration = start.elapsed();
            let response_checksum = compute_checksum(&response);

            println!("1MB transfer completed in {:?}", duration);
            println!("Throughput: {:.2} MB/s", (DATA_SIZE * 2) as f64 / duration.as_secs_f64() / 1_000_000.0);

            assert_eq!(response.len(), DATA_SIZE, "Response size mismatch");
            assert_eq!(response_checksum, expected_checksum, "Data corruption in 1MB transfer!");

            println!("✓ Very large payload test passed");
        }
        Err(e) => {
            panic!("1MB transfer failed: {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Small fragment size
/// Tests fragmentation with a very small max_frag to ensure many fragments work
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_small_fragment_size() {
    init_logging();

    const DATA_SIZE: usize = 10_000; // 10KB
    const MAX_FRAG: u16 = 512; // Very small fragments

    let interface = create_large_echo_interface();
    let (addr, server) = start_frag_test_server(interface, MAX_FRAG).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_frag_client(addr).await.unwrap();

    let mut gen = TestDataGenerator::new(42);
    let payload = gen.random_bytes(DATA_SIZE);
    let expected_checksum = compute_checksum(&payload);

    // Calculate expected fragments
    let max_stub_per_frag = MAX_FRAG as usize - 24; // header + body header
    let expected_fragments = (DATA_SIZE + max_stub_per_frag - 1) / max_stub_per_frag;

    println!(
        "Sending {}B with {}B max_frag (expecting ~{} fragments)",
        DATA_SIZE, MAX_FRAG, expected_fragments
    );
    let start = Instant::now();

    match client.call(0, payload).await {
        Ok(response) => {
            let duration = start.elapsed();
            let response_checksum = compute_checksum(&response);

            println!("Transfer with small fragments completed in {:?}", duration);

            assert_eq!(response.len(), DATA_SIZE, "Response size mismatch");
            assert_eq!(response_checksum, expected_checksum, "Data corruption!");

            println!("✓ Small fragment size test passed");
        }
        Err(e) => {
            panic!("Small fragment transfer failed: {}", e);
        }
    }

    server_handle.abort();
}
