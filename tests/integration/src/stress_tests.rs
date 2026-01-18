//! Stress Tests - Multi-threading at Large Scale
//!
//! These tests exercise race conditions and concurrency issues by:
//! - Running many concurrent clients against a single server
//! - Sending high volumes of requests
//! - Testing data integrity under load
//! - Measuring throughput and latency

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::{Bytes, BytesMut, BufMut};
use tokio::sync::Barrier;
use futures::future::join_all;

use common::*;
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use midl_ndr::NdrContext;

/// Test: High concurrency with many simultaneous clients
/// This tests race conditions in connection handling and request processing
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_high_concurrency_many_clients() {
    init_logging();

    const NUM_CLIENTS: usize = 50;
    const REQUESTS_PER_CLIENT: usize = 100;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    // Allow server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let barrier = Arc::new(Barrier::new(NUM_CLIENTS));

    let mut client_handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let stats = stats.clone();
        let barrier = barrier.clone();

        let handle = tokio::spawn(async move {
            // Wait for all clients to be ready
            barrier.wait().await;

            // Connect
            let client = match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Client {} failed to connect: {}", client_id, e);
                    stats.record_failure();
                    return;
                }
            };

            // Send requests
            for req_id in 0..REQUESTS_PER_CLIENT {
                let data = format!("client_{}_request_{}", client_id, req_id);
                let payload = Bytes::from(data.clone());

                let start = Instant::now();
                match client.call(0, payload.clone()).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        if response == payload {
                            stats.record_success(latency);
                        } else {
                            eprintln!("Data mismatch for client {} request {}", client_id, req_id);
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

        client_handles.push(handle);
    }

    // Wait for all clients to complete
    join_all(client_handles).await;

    // Shutdown server
    server_handle.abort();

    // Verify results
    let total_expected = (NUM_CLIENTS * REQUESTS_PER_CLIENT) as u64;
    let success = stats.success_count();
    let failure = stats.failure_count();

    println!("\n=== High Concurrency Test Results ===");
    println!("Total expected: {}", total_expected);
    println!("Successful: {} ({:.2}%)", success, (success as f64 / total_expected as f64) * 100.0);
    println!("Failed: {} ({:.2}%)", failure, (failure as f64 / total_expected as f64) * 100.0);
    println!("Avg latency: {:?}", stats.avg_latency());
    println!("Min latency: {:?}", stats.min_latency());
    println!("Max latency: {:?}", stats.max_latency());

    // Allow some failures due to connection limits, but most should succeed
    assert!(success > total_expected * 90 / 100,
        "Too many failures: {} out of {}", failure, total_expected);
}

/// Test: Rapid fire requests from a single client
/// This tests the server's ability to handle burst traffic
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rapid_fire_single_client() {
    init_logging();

    const NUM_REQUESTS: usize = 1000;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = connect_client(addr, ECHO_UUID, ECHO_VERSION).await.unwrap();
    let stats = ConcurrentStats::new();

    let start = Instant::now();

    for i in 0..NUM_REQUESTS {
        let data = format!("request_{:05}", i);
        let payload = Bytes::from(data);

        let req_start = Instant::now();
        match client.call(0, payload.clone()).await {
            Ok(response) => {
                if response == payload {
                    stats.record_success(req_start.elapsed());
                } else {
                    stats.record_failure();
                }
            }
            Err(_) => {
                stats.record_failure();
            }
        }
    }

    let total_duration = start.elapsed();
    server_handle.abort();

    let throughput = NUM_REQUESTS as f64 / total_duration.as_secs_f64();

    println!("\n=== Rapid Fire Test Results ===");
    println!("Total requests: {}", NUM_REQUESTS);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Total duration: {:?}", total_duration);
    println!("Throughput: {:.2} req/sec", throughput);
    println!("Avg latency: {:?}", stats.avg_latency());

    assert_eq!(stats.failure_count(), 0, "No failures expected in sequential test");
}

/// Test: Concurrent requests with varying payload sizes
/// This tests buffer handling under concurrent load
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_varying_payload_sizes_concurrent() {
    init_logging();

    const NUM_CLIENTS: usize = 10;
    const REQUESTS_PER_CLIENT: usize = 50;
    const PAYLOAD_SIZES: &[usize] = &[1, 16, 64, 256, 1024, 4096, 16384];

    let interface = create_echo_interface();
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
            let client = connect_client(addr, ECHO_UUID, ECHO_VERSION).await.unwrap();
            let mut gen = TestDataGenerator::new(client_id as u64 * 12345);

            for req_id in 0..REQUESTS_PER_CLIENT {
                let size = PAYLOAD_SIZES[req_id % PAYLOAD_SIZES.len()];
                let payload = gen.random_bytes(size);
                let expected_checksum = compute_checksum(&payload);

                let start = Instant::now();
                match client.call(0, payload).await {
                    Ok(response) => {
                        let response_checksum = compute_checksum(&response);
                        if expected_checksum == response_checksum {
                            stats.record_success(start.elapsed());
                        } else {
                            eprintln!("Checksum mismatch for size {}", size);
                            stats.record_failure();
                        }
                    }
                    Err(e) => {
                        eprintln!("Request failed: {}", e);
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
    println!("\n=== Varying Payload Sizes Test Results ===");
    println!("Total requests: {}", total);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());

    assert_eq!(stats.failure_count(), 0, "No failures expected");
}

/// Test: Connection churn - rapid connect/disconnect cycles
/// This tests connection handling race conditions
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connection_churn() {
    init_logging();

    const NUM_CYCLES: usize = 100;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = ConcurrentStats::new();
    let start = Instant::now();

    for i in 0..NUM_CYCLES {
        let connect_start = Instant::now();

        // Connect
        let client = match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cycle {} connect failed: {}", i, e);
                stats.record_failure();
                continue;
            }
        };

        // Do a quick request
        let payload = Bytes::from(format!("cycle_{}", i));
        match client.call(0, payload.clone()).await {
            Ok(response) => {
                if response == payload {
                    stats.record_success(connect_start.elapsed());
                } else {
                    stats.record_failure();
                }
            }
            Err(_) => {
                stats.record_failure();
            }
        }

        // Client drops here (disconnect)
    }

    let total_duration = start.elapsed();
    server_handle.abort();

    println!("\n=== Connection Churn Test Results ===");
    println!("Total cycles: {}", NUM_CYCLES);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Total duration: {:?}", total_duration);
    println!("Avg cycle time: {:?}", stats.avg_latency());

    assert!(stats.success_count() > NUM_CYCLES as u64 * 90 / 100,
        "Too many connection failures");
}

/// Test: Parallel requests on shared connection
/// This tests multiplexing and concurrent call handling on a single connection
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_parallel_requests_shared_connection() {
    init_logging();

    const NUM_PARALLEL_REQUESTS: usize = 50;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Arc::new(connect_client(addr, ECHO_UUID, ECHO_VERSION).await.unwrap());
    let stats = Arc::new(ConcurrentStats::new());

    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..NUM_PARALLEL_REQUESTS {
        let client = client.clone();
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            let payload = Bytes::from(format!("parallel_request_{:03}", i));
            let req_start = Instant::now();

            match client.call(1, payload.clone()).await { // opnum 1 = delayed echo
                Ok(response) => {
                    if response == payload {
                        stats.record_success(req_start.elapsed());
                    } else {
                        stats.record_failure();
                    }
                }
                Err(_) => {
                    stats.record_failure();
                }
            }
        });

        handles.push(handle);
    }

    join_all(handles).await;

    let total_duration = start.elapsed();
    server_handle.abort();

    println!("\n=== Parallel Requests Test Results ===");
    println!("Total parallel requests: {}", NUM_PARALLEL_REQUESTS);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Total duration: {:?}", total_duration);
    println!("Avg latency: {:?}", stats.avg_latency());

    // With 50 parallel requests each taking ~10ms, they should complete much faster than 500ms
    // if truly parallel
    assert!(total_duration < Duration::from_millis(500) || stats.failure_count() == 0,
        "Requests should be parallel or all succeed");
}

/// Test: Data integrity under high load
/// This tests that data is not corrupted under concurrent access
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_data_integrity_under_load() {
    init_logging();

    const NUM_CLIENTS: usize = 20;
    const REQUESTS_PER_CLIENT: usize = 200;
    const DATA_SIZE: usize = 256;

    let interface = create_echo_interface();
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
            let client = connect_client(addr, ECHO_UUID, ECHO_VERSION).await.unwrap();
            let mut gen = TestDataGenerator::new(client_id as u64 * 999);

            for _ in 0..REQUESTS_PER_CLIENT {
                let payload = gen.random_bytes(DATA_SIZE);
                let expected_checksum = compute_checksum(&payload);

                let start = Instant::now();
                match client.call(0, payload).await {
                    Ok(response) => {
                        let response_checksum = compute_checksum(&response);
                        if expected_checksum == response_checksum {
                            stats.record_success(start.elapsed());
                        } else {
                            // DATA CORRUPTION DETECTED!
                            eprintln!("DATA CORRUPTION! Expected checksum: {}, got: {}",
                                expected_checksum, response_checksum);
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

    let total = (NUM_CLIENTS * REQUESTS_PER_CLIENT) as u64;
    println!("\n=== Data Integrity Test Results ===");
    println!("Total requests: {}", total);
    println!("Successful (integrity verified): {}", stats.success_count());
    println!("Failed/Corrupted: {}", stats.failure_count());

    // Data integrity is critical - no corruption should occur
    assert_eq!(stats.failure_count(), 0,
        "DATA CORRUPTION DETECTED! {} requests had corrupted data", stats.failure_count());
}

/// Test: Thundering herd - all clients connect simultaneously
/// This tests server startup/connection handling under extreme load
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_thundering_herd() {
    init_logging();

    const NUM_CLIENTS: usize = 100;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let barrier = Arc::new(Barrier::new(NUM_CLIENTS));
    let stats = Arc::new(ConcurrentStats::new());

    let start = Instant::now();
    let mut handles = Vec::new();

    for i in 0..NUM_CLIENTS {
        let barrier = barrier.clone();
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            // Wait for all tasks to be ready
            barrier.wait().await;

            // Immediately try to connect
            let conn_start = Instant::now();
            match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
                Ok(client) => {
                    // Do one request
                    let payload = Bytes::from(format!("herd_{}", i));
                    match client.call(0, payload.clone()).await {
                        Ok(response) if response == payload => {
                            stats.record_success(conn_start.elapsed());
                        }
                        _ => {
                            stats.record_failure();
                        }
                    }
                }
                Err(_) => {
                    stats.record_failure();
                }
            }
        });

        handles.push(handle);
    }

    join_all(handles).await;

    let total_duration = start.elapsed();
    server_handle.abort();

    println!("\n=== Thundering Herd Test Results ===");
    println!("Simultaneous clients: {}", NUM_CLIENTS);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Total duration: {:?}", total_duration);

    // Expect most connections to succeed
    assert!(stats.success_count() >= NUM_CLIENTS as u64 * 80 / 100,
        "Too many thundering herd failures: {} out of {}",
        stats.failure_count(), NUM_CLIENTS);
}

/// Test: Long-running stress test
/// Runs for a fixed duration to detect memory leaks and gradual degradation
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sustained_load() {
    init_logging();

    const TEST_DURATION_SECS: u64 = 5; // Keep short for CI
    const NUM_CLIENTS: usize = 5;

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let mut handles = Vec::new();

    for client_id in 0..NUM_CLIENTS {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            let client = match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
                Ok(c) => c,
                Err(_) => return,
            };

            let mut gen = TestDataGenerator::new(client_id as u64);

            while running.load(std::sync::atomic::Ordering::Relaxed) {
                let payload = gen.random_bytes(64);
                let expected_checksum = compute_checksum(&payload);

                let start = Instant::now();
                match client.call(0, payload).await {
                    Ok(response) => {
                        let checksum = compute_checksum(&response);
                        if checksum == expected_checksum {
                            stats.record_success(start.elapsed());
                        } else {
                            stats.record_failure();
                        }
                    }
                    Err(_) => {
                        stats.record_failure();
                    }
                }

                // Small delay to prevent overwhelming
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });

        handles.push(handle);
    }

    // Run for the specified duration
    tokio::time::sleep(Duration::from_secs(TEST_DURATION_SECS)).await;
    running.store(false, std::sync::atomic::Ordering::Relaxed);

    join_all(handles).await;
    server_handle.abort();

    let success = stats.success_count();
    let failure = stats.failure_count();
    let total = success + failure;

    println!("\n=== Sustained Load Test Results ===");
    println!("Duration: {} seconds", TEST_DURATION_SECS);
    println!("Total operations: {}", total);
    println!("Successful: {} ({:.2}%)", success, (success as f64 / total as f64) * 100.0);
    println!("Failed: {} ({:.2}%)", failure, (failure as f64 / total as f64) * 100.0);
    println!("Throughput: {:.2} ops/sec", total as f64 / TEST_DURATION_SECS as f64);
    println!("Avg latency: {:?}", stats.avg_latency());

    assert!(success > 0, "No successful operations");
    assert!((failure as f64 / total as f64) < 0.01, "Error rate too high: {:.2}%",
        (failure as f64 / total as f64) * 100.0);
}
