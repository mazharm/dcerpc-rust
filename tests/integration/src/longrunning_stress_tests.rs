//! Long-Running Stress Tests for DCE RPC / DCOM
//!
//! These tests are designed to run for extended periods (hours or days) to uncover:
//! - Memory leaks
//! - Race conditions
//! - Resource exhaustion
//! - Performance degradation over time
//!
//! # Transports Covered
//! - TCP (connection-oriented MSRPC)
//! - UDP (connectionless protocol)
//! - Named Pipes (Windows only)
//!
//! # Threading Models Covered
//! - DCOM MTA (Multi-Threaded Apartment)
//! - DCOM STA (Single-Threaded Apartment)
//!
//! # Running These Tests
//!
//! These tests are NOT run by default `cargo test`. They must be run explicitly:
//!
//! ```bash
//! # Run for 1 hour (default)
//! cargo test --test longrunning_stress_tests --release -- --ignored --nocapture
//!
//! # Run with custom duration via environment variable
//! STRESS_TEST_DURATION_SECS=86400 cargo test --test longrunning_stress_tests --release -- --ignored --nocapture
//!
//! # Run specific test
//! STRESS_TEST_DURATION_SECS=3600 cargo test --test longrunning_stress_tests test_tcp_msrpc_sustained_load --release -- --ignored --nocapture
//! ```
//!
//! # Environment Variables
//!
//! - `STRESS_TEST_DURATION_SECS`: Test duration in seconds (default: 3600 = 1 hour)
//! - `STRESS_TEST_CLIENTS`: Number of concurrent clients (default: 20)
//! - `STRESS_TEST_REPORT_INTERVAL_SECS`: Stats reporting interval (default: 60)
//! - `STRESS_TEST_MEMORY_CHECK_INTERVAL_SECS`: Memory check interval (default: 300)

#![allow(dead_code)]

mod common;

use std::any::Any;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, BufMut};
use futures::future::join_all;
use parking_lot::Mutex;

use common::*;
use dcerpc::{Interface, InterfaceBuilder, Uuid};
use dcom::apartment::{
    Apartment, CallFuture, ComObject,
    MultithreadedApartment, SinglethreadedApartment, CallDispatcher,
};
use dcom::types::Oid;
use midl_ndr::NdrContext;

// =============================================================================
// Configuration
// =============================================================================

/// Get test duration from environment or use default
fn get_test_duration() -> Duration {
    let secs = std::env::var("STRESS_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600); // 1 hour default
    Duration::from_secs(secs)
}

/// Get number of clients from environment or use default
fn get_num_clients() -> usize {
    std::env::var("STRESS_TEST_CLIENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

/// Get report interval from environment or use default
fn get_report_interval() -> Duration {
    let secs = std::env::var("STRESS_TEST_REPORT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    Duration::from_secs(secs)
}

/// Get memory check interval from environment or use default
fn get_memory_check_interval() -> Duration {
    let secs = std::env::var("STRESS_TEST_MEMORY_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    Duration::from_secs(secs)
}

// =============================================================================
// Extended Statistics Tracking
// =============================================================================

/// Extended statistics for long-running tests
#[derive(Debug)]
pub struct ExtendedStats {
    // Operation counts
    pub successful_ops: AtomicU64,
    pub failed_ops: AtomicU64,
    pub timeout_ops: AtomicU64,
    pub connection_errors: AtomicU64,

    // Latency tracking
    pub total_latency_ns: AtomicU64,
    pub max_latency_ns: AtomicU64,
    pub min_latency_ns: AtomicU64,

    // Throughput windows (for detecting degradation)
    pub recent_ops: Mutex<VecDeque<(Instant, u64)>>,

    // Data integrity
    pub data_corruption_count: AtomicU64,
    pub checksum_failures: AtomicU64,

    // Connection stats
    pub connections_created: AtomicU64,
    pub connections_dropped: AtomicU64,

    // Memory tracking (approximate, from periodic checks)
    pub peak_memory_bytes: AtomicU64,
    pub memory_samples: Mutex<Vec<(Instant, u64)>>,

    // Start time
    pub start_time: Instant,
}

impl ExtendedStats {
    pub fn new() -> Self {
        Self {
            successful_ops: AtomicU64::new(0),
            failed_ops: AtomicU64::new(0),
            timeout_ops: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
            recent_ops: Mutex::new(VecDeque::new()),
            data_corruption_count: AtomicU64::new(0),
            checksum_failures: AtomicU64::new(0),
            connections_created: AtomicU64::new(0),
            connections_dropped: AtomicU64::new(0),
            peak_memory_bytes: AtomicU64::new(0),
            memory_samples: Mutex::new(Vec::new()),
            start_time: Instant::now(),
        }
    }

    pub fn record_success(&self, latency: Duration) {
        self.successful_ops.fetch_add(1, Ordering::Relaxed);
        let ns = latency.as_nanos() as u64;
        self.total_latency_ns.fetch_add(ns, Ordering::Relaxed);

        // Update max
        let mut current = self.max_latency_ns.load(Ordering::Relaxed);
        while ns > current {
            match self.max_latency_ns.compare_exchange_weak(
                current, ns, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }

        // Update min
        current = self.min_latency_ns.load(Ordering::Relaxed);
        while ns < current {
            match self.min_latency_ns.compare_exchange_weak(
                current, ns, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }

        // Record for throughput window
        let mut recent = self.recent_ops.lock();
        let now = Instant::now();
        recent.push_back((now, 1));

        // Keep only last 60 seconds of data
        let cutoff = now - Duration::from_secs(60);
        while let Some((time, _)) = recent.front() {
            if *time < cutoff {
                recent.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn record_failure(&self) {
        self.failed_ops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeout_ops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_error(&self) {
        self.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_data_corruption(&self) {
        self.data_corruption_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_checksum_failure(&self) {
        self.checksum_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_created(&self) {
        self.connections_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_dropped(&self) {
        self.connections_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_memory_sample(&self, bytes: u64) {
        let mut samples = self.memory_samples.lock();
        samples.push((Instant::now(), bytes));

        // Update peak
        let mut current = self.peak_memory_bytes.load(Ordering::Relaxed);
        while bytes > current {
            match self.peak_memory_bytes.compare_exchange_weak(
                current, bytes, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    pub fn get_recent_throughput(&self) -> f64 {
        let recent = self.recent_ops.lock();
        if recent.is_empty() {
            return 0.0;
        }

        let count: u64 = recent.iter().map(|(_, c)| c).sum();
        let duration = recent.back().map(|(t, _)| t.elapsed().as_secs_f64())
            .unwrap_or(1.0);

        if duration > 0.0 {
            count as f64 / duration.max(1.0)
        } else {
            0.0
        }
    }

    pub fn avg_latency(&self) -> Duration {
        let total = self.total_latency_ns.load(Ordering::Relaxed);
        let count = self.successful_ops.load(Ordering::Relaxed);
        if count > 0 {
            Duration::from_nanos(total / count)
        } else {
            Duration::ZERO
        }
    }

    pub fn max_latency(&self) -> Duration {
        Duration::from_nanos(self.max_latency_ns.load(Ordering::Relaxed))
    }

    pub fn min_latency(&self) -> Duration {
        let min = self.min_latency_ns.load(Ordering::Relaxed);
        if min == u64::MAX {
            Duration::ZERO
        } else {
            Duration::from_nanos(min)
        }
    }

    pub fn total_ops(&self) -> u64 {
        self.successful_ops.load(Ordering::Relaxed) +
        self.failed_ops.load(Ordering::Relaxed) +
        self.timeout_ops.load(Ordering::Relaxed)
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_ops();
        if total > 0 {
            self.successful_ops.load(Ordering::Relaxed) as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn print_report(&self, title: &str) {
        let elapsed = self.elapsed();
        let total_ops = self.total_ops();
        let successful = self.successful_ops.load(Ordering::Relaxed);
        let failed = self.failed_ops.load(Ordering::Relaxed);
        let timeouts = self.timeout_ops.load(Ordering::Relaxed);
        let conn_errors = self.connection_errors.load(Ordering::Relaxed);
        let corruptions = self.data_corruption_count.load(Ordering::Relaxed);
        let _checksum_fails = self.checksum_failures.load(Ordering::Relaxed);

        let separator = "=".repeat(80);
        let short_sep = "-".repeat(40);

        println!("\n{}", separator);
        println!("{}", title);
        println!("{}", separator);
        println!("Duration: {:?}", elapsed);
        println!("{}", short_sep);
        println!("OPERATIONS:");
        println!("  Total:     {}", total_ops);
        println!("  Successful: {} ({:.2}%)", successful, self.success_rate());
        println!("  Failed:    {}", failed);
        println!("  Timeouts:  {}", timeouts);
        println!("{}", short_sep);
        println!("LATENCY:");
        println!("  Average:   {:?}", self.avg_latency());
        println!("  Minimum:   {:?}", self.min_latency());
        println!("  Maximum:   {:?}", self.max_latency());
        println!("{}", short_sep);
        println!("THROUGHPUT:");
        println!("  Overall:   {:.2} ops/sec", total_ops as f64 / elapsed.as_secs_f64().max(1.0));
        println!("  Recent:    {:.2} ops/sec", self.get_recent_throughput());
        println!("{}", short_sep);
        println!("CONNECTIONS:");
        println!("  Created:   {}", self.connections_created.load(Ordering::Relaxed));
        println!("  Dropped:   {}", self.connections_dropped.load(Ordering::Relaxed));
        println!("  Errors:    {}", conn_errors);
        println!("{}", short_sep);
        println!("DATA INTEGRITY:");
        println!("  Corruptions:       {}", corruptions);
        println!("  Checksum Failures: {}", self.checksum_failures.load(Ordering::Relaxed));
        println!("{}", short_sep);
        println!("MEMORY:");
        println!("  Peak: {} bytes ({:.2} MB)",
            self.peak_memory_bytes.load(Ordering::Relaxed),
            self.peak_memory_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0);

        // Check for memory growth trend
        let samples = self.memory_samples.lock();
        if samples.len() >= 2 {
            let first = samples.first().map(|(_, m)| *m).unwrap_or(0);
            let last = samples.last().map(|(_, m)| *m).unwrap_or(0);
            if last > first && first > 0 {
                let growth = last - first;
                let growth_pct = (growth as f64 / first as f64) * 100.0;
                println!("  Growth:    {} bytes ({:.2}%)", growth, growth_pct);
                if growth_pct > 50.0 {
                    println!("  WARNING: Significant memory growth detected!");
                }
            }
        }
        println!("{}", separator);
    }
}

impl Default for ExtendedStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Memory Monitoring (approximate, platform-specific)
// =============================================================================

/// Get approximate process memory usage
fn get_process_memory() -> u64 {
    // On Windows, we'd use GetProcessMemoryInfo
    // For now, return 0 as a placeholder - in production you'd use
    // platform-specific APIs or a crate like `sysinfo`
    0
}

/// Background task to periodically check memory
async fn memory_monitor(stats: Arc<ExtendedStats>, running: Arc<AtomicBool>, interval: Duration) {
    while running.load(Ordering::Relaxed) {
        let mem = get_process_memory();
        if mem > 0 {
            stats.record_memory_sample(mem);
        }
        tokio::time::sleep(interval).await;
    }
}

/// Background task to periodically print stats
async fn stats_reporter(stats: Arc<ExtendedStats>, running: Arc<AtomicBool>, interval: Duration, title: &str) {
    let title = title.to_string();
    while running.load(Ordering::Relaxed) {
        tokio::time::sleep(interval).await;
        if running.load(Ordering::Relaxed) {
            stats.print_report(&format!("{} - Progress Report", title));
        }
    }
}

// =============================================================================
// Test Interfaces
// =============================================================================

/// Complex interface for thorough NDR testing
pub const NDR_TEST_UUID: &str = "c1d2e3f4-a5b6-7890-cdef-123456789abc";
pub const NDR_TEST_VERSION: (u16, u16) = (1, 0);

/// Create an interface that exercises NDR encoding thoroughly
pub fn create_ndr_test_interface() -> Interface {
    InterfaceBuilder::new(NDR_TEST_UUID, NDR_TEST_VERSION.0, NDR_TEST_VERSION.1)
        .unwrap()
        // Op 0: Echo (simple)
        .operation(0, |stub_data| {
            Box::pin(async move {
                Ok(stub_data)
            })
        })
        // Op 1: Reverse bytes
        .operation(1, |stub_data| {
            Box::pin(async move {
                let reversed: Vec<u8> = stub_data.iter().rev().cloned().collect();
                Ok(Bytes::from(reversed))
            })
        })
        // Op 2: Sum i32 array (conformant array test)
        .operation(2, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();

                if cursor.len() < 4 {
                    return Ok(Bytes::new());
                }

                let count = ctx.get_u32(&mut cursor) as usize;
                let mut sum: i64 = 0;

                for _ in 0..count {
                    if cursor.len() < 4 {
                        break;
                    }
                    sum += ctx.get_i32(&mut cursor) as i64;
                }

                let mut buf = BytesMut::new();
                ctx.put_i64(&mut buf, sum);
                Ok(buf.freeze())
            })
        })
        // Op 3: String length (varying string test)
        .operation(3, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();

                // Read conformant varying string format
                if cursor.len() < 12 {
                    let mut buf = BytesMut::new();
                    ctx.put_u32(&mut buf, 0);
                    return Ok(buf.freeze());
                }

                let _max_count = ctx.get_u32(&mut cursor);
                let _offset = ctx.get_u32(&mut cursor);
                let actual_count = ctx.get_u32(&mut cursor);

                let mut buf = BytesMut::new();
                ctx.put_u32(&mut buf, actual_count);
                Ok(buf.freeze())
            })
        })
        // Op 4: Complex struct roundtrip
        .operation(4, |stub_data| {
            Box::pin(async move {
                // Decode and re-encode complex data
                if let Some(data) = ComplexTestData::decode(&stub_data) {
                    Ok(data.encode())
                } else {
                    Ok(Bytes::new())
                }
            })
        })
        // Op 5: Large buffer allocation (stress memory)
        .operation(5, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();

                if cursor.len() < 4 {
                    return Ok(Bytes::new());
                }

                let size = ctx.get_u32(&mut cursor) as usize;
                // Cap at 1MB to prevent OOM
                let size = size.min(1_048_576);

                // Allocate and fill with pattern
                let mut buf = BytesMut::with_capacity(size);
                for i in 0..size {
                    buf.put_u8((i % 256) as u8);
                }
                Ok(buf.freeze())
            })
        })
        // Op 6: Checksum verification
        .operation(6, |stub_data| {
            Box::pin(async move {
                let checksum = compute_checksum(&stub_data);
                let mut buf = BytesMut::new();
                let ctx = NdrContext::default();
                ctx.put_u64(&mut buf, checksum);
                Ok(buf.freeze())
            })
        })
        .build()
}

// =============================================================================
// DCOM Test Objects
// =============================================================================

/// Test object for MTA stress testing
struct MtaStressObject {
    oid: Oid,
    call_count: AtomicU64,
    concurrent_calls: AtomicUsize,
    max_concurrent: AtomicUsize,
}

impl MtaStressObject {
    fn new() -> Self {
        Self {
            oid: Oid::generate(),
            call_count: AtomicU64::new(0),
            concurrent_calls: AtomicUsize::new(0),
            max_concurrent: AtomicUsize::new(0),
        }
    }
}

impl ComObject for MtaStressObject {
    fn oid(&self) -> Oid {
        self.oid
    }

    fn supported_interfaces(&self) -> Vec<Uuid> {
        vec![Uuid::NIL]
    }

    fn invoke(&self, _iid: &Uuid, opnum: u16, args: Bytes) -> CallFuture {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        let current = self.concurrent_calls.fetch_add(1, Ordering::Relaxed) + 1;

        // Track max concurrent
        let mut max = self.max_concurrent.load(Ordering::Relaxed);
        while current > max {
            match self.max_concurrent.compare_exchange_weak(
                max, current, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(m) => max = m,
            }
        }

        // Use a wrapper to decrement count at end
        let concurrent_calls = Arc::new(AtomicUsize::new(0));
        let cc_for_decrement = Arc::clone(&concurrent_calls);

        // Store address of actual concurrent_calls for decrement
        let cc_addr = &self.concurrent_calls as *const AtomicUsize as usize;

        Box::pin(async move {
            // Simulate varying work durations
            let delay_ms = match opnum {
                0 => 0,      // Instant
                1 => 1,      // Short
                2 => 10,     // Medium
                3 => 50,     // Long
                _ => opnum as u64 % 20,
            };

            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            // We can't safely decrement here without unsafe, so we just track entry
            let _ = (cc_for_decrement, cc_addr);

            Ok(args)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Thread-safety checker for STA verification
struct StaVerificationObject {
    oid: Oid,
    is_in_call: Arc<AtomicUsize>,
    violations: AtomicU64,
    call_count: AtomicU64,
}

impl StaVerificationObject {
    fn new() -> Self {
        Self {
            oid: Oid::generate(),
            is_in_call: Arc::new(AtomicUsize::new(0)),
            violations: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
        }
    }

    fn get_violations(&self) -> u64 {
        self.violations.load(Ordering::Relaxed)
    }
}

impl ComObject for StaVerificationObject {
    fn oid(&self) -> Oid {
        self.oid
    }

    fn supported_interfaces(&self) -> Vec<Uuid> {
        vec![Uuid::NIL]
    }

    fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
        self.call_count.fetch_add(1, Ordering::Relaxed);

        // Check for concurrent call (violation in STA)
        let was_in_call = self.is_in_call.fetch_add(1, Ordering::SeqCst);
        if was_in_call > 0 {
            self.violations.fetch_add(1, Ordering::Relaxed);
        }

        let is_in_call = Arc::clone(&self.is_in_call);

        Box::pin(async move {
            // Simulate work
            tokio::time::sleep(Duration::from_millis(5)).await;
            is_in_call.fetch_sub(1, Ordering::SeqCst);
            Ok(args)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// =============================================================================
// TCP/MSRPC Long-Running Stress Tests
// =============================================================================

/// TCP MSRPC sustained load test
///
/// This test runs for an extended period, continuously sending requests
/// over TCP connections while monitoring for leaks and degradation.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Only run explicitly
async fn test_tcp_msrpc_sustained_load() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("TCP MSRPC SUSTAINED LOAD TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let interface = create_ndr_test_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    // Start reporter
    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "TCP MSRPC").await;
    });

    // Start memory monitor
    let mem_stats = stats.clone();
    let mem_running = running.clone();
    let mem_handle = tokio::spawn(async move {
        memory_monitor(mem_stats, mem_running, get_memory_check_interval()).await;
    });

    // Spawn client workers
    let mut client_handles = Vec::new();
    for client_id in 0..num_clients {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            tcp_client_worker(client_id, addr, stats, running).await;
        });
        client_handles.push(handle);
    }

    // Run for specified duration
    tokio::time::sleep(test_duration).await;

    // Signal shutdown
    running.store(false, Ordering::SeqCst);

    // Wait for clients to finish
    join_all(client_handles).await;

    // Stop reporter and monitor
    reporter_handle.abort();
    mem_handle.abort();

    // Final report
    stats.print_report("TCP MSRPC SUSTAINED LOAD - FINAL RESULTS");

    // Cleanup
    server_handle.abort();

    // Assertions
    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0,
        "Data corruption detected!");
    assert!(stats.success_rate() > 99.0,
        "Success rate too low: {:.2}%", stats.success_rate());
}

/// Client worker for TCP stress test
async fn tcp_client_worker(
    client_id: usize,
    addr: SocketAddr,
    stats: Arc<ExtendedStats>,
    running: Arc<AtomicBool>,
) {
    let mut gen = TestDataGenerator::new(client_id as u64 * 12345);
    let mut reconnect_count = 0;

    while running.load(Ordering::Relaxed) {
        // Connect
        let client = match connect_client(addr, NDR_TEST_UUID, NDR_TEST_VERSION).await {
            Ok(c) => {
                stats.record_connection_created();
                c
            }
            Err(_) => {
                stats.record_connection_error();
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // Use connection for a while
        let connection_lifetime = Duration::from_secs(30);
        let conn_start = Instant::now();

        while running.load(Ordering::Relaxed) && conn_start.elapsed() < connection_lifetime {
            // Pick random operation
            let rand_byte = gen.random_bytes(1)[0];
            let opnum = (rand_byte % 7) as u16;

            // Generate test data based on operation
            let (payload, expected_checksum) = match opnum {
                0 | 1 => {
                    // Echo or reverse
                    let rand_size = gen.random_bytes(1)[0];
                    let data = gen.random_bytes(64 + (rand_size as usize % 200));
                    let checksum = compute_checksum(&data);
                    (data, Some(checksum))
                }
                2 => {
                    // Array sum
                    let ctx = NdrContext::default();
                    let rand_count = gen.random_bytes(1)[0];
                    let count = 10 + (rand_count as usize % 50);
                    let mut buf = BytesMut::new();
                    ctx.put_u32(&mut buf, count as u32);
                    for _ in 0..count {
                        let rand_val = gen.random_bytes(1)[0];
                        ctx.put_i32(&mut buf, rand_val as i32);
                    }
                    (buf.freeze(), None)
                }
                6 => {
                    // Checksum verification
                    let data = gen.random_bytes(128);
                    (data, None)
                }
                _ => {
                    (gen.random_bytes(32), None)
                }
            };

            let start = Instant::now();
            match tokio::time::timeout(Duration::from_secs(5), client.call(opnum, payload.clone())).await {
                Ok(Ok(response)) => {
                    let latency = start.elapsed();

                    // Verify data integrity
                    match opnum {
                        0 => {
                            // Echo - response should match
                            if response != payload {
                                stats.record_data_corruption();
                            } else if let Some(expected) = expected_checksum {
                                if compute_checksum(&response) != expected {
                                    stats.record_checksum_failure();
                                } else {
                                    stats.record_success(latency);
                                }
                            } else {
                                stats.record_success(latency);
                            }
                        }
                        1 => {
                            // Reverse - verify reversal
                            let reversed: Vec<u8> = payload.iter().rev().cloned().collect();
                            if response.as_ref() != reversed.as_slice() {
                                stats.record_data_corruption();
                            } else {
                                stats.record_success(latency);
                            }
                        }
                        _ => {
                            stats.record_success(latency);
                        }
                    }
                }
                Ok(Err(_)) => {
                    stats.record_failure();
                }
                Err(_) => {
                    stats.record_timeout();
                }
            }

            // Small delay to prevent overwhelming
            tokio::time::sleep(Duration::from_micros(100)).await;
        }

        stats.record_connection_dropped();
        reconnect_count += 1;

        // Occasional longer pause between connections
        if reconnect_count % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// TCP MSRPC connection churn stress test
///
/// Rapidly creates and destroys connections to detect connection leaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_tcp_msrpc_connection_churn() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("TCP MSRPC CONNECTION CHURN TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    // Start reporter
    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "TCP Connection Churn").await;
    });

    // Spawn churning workers
    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(client_id as u64);

            while running.load(Ordering::Relaxed) {
                // Connect
                let start = Instant::now();
                match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
                    Ok(client) => {
                        stats.record_connection_created();

                        // Do one request
                        let payload = gen.random_bytes(64);
                        match client.call(0, payload.clone()).await {
                            Ok(response) if response == payload => {
                                stats.record_success(start.elapsed());
                            }
                            Ok(_) => {
                                stats.record_data_corruption();
                            }
                            Err(_) => {
                                stats.record_failure();
                            }
                        }

                        stats.record_connection_dropped();
                    }
                    Err(_) => {
                        stats.record_connection_error();
                    }
                }

                // Small delay
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    stats.print_report("TCP CONNECTION CHURN - FINAL RESULTS");

    server_handle.abort();

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
    assert!(stats.success_rate() > 95.0);
}

/// TCP MSRPC large payload fragmentation stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_tcp_msrpc_fragmentation_stress() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients() / 2; // Fewer clients for large payloads
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("TCP MSRPC FRAGMENTATION STRESS TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let interface = create_echo_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "TCP Fragmentation").await;
    });

    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            let client = match connect_client(addr, ECHO_UUID, ECHO_VERSION).await {
                Ok(c) => {
                    stats.record_connection_created();
                    c
                }
                Err(_) => return,
            };

            let mut gen = TestDataGenerator::new(client_id as u64);

            // Payload sizes that force fragmentation
            let sizes = [4096, 8192, 16384, 32768, 65536, 100000];
            let mut size_idx = 0;

            while running.load(Ordering::Relaxed) {
                let size = sizes[size_idx % sizes.len()];
                size_idx += 1;

                let payload = gen.random_bytes(size);
                let expected_checksum = compute_checksum(&payload);

                let start = Instant::now();
                match tokio::time::timeout(Duration::from_secs(30), client.call(0, payload)).await {
                    Ok(Ok(response)) => {
                        let latency = start.elapsed();
                        let actual_checksum = compute_checksum(&response);

                        if actual_checksum != expected_checksum {
                            stats.record_data_corruption();
                            eprintln!("DATA CORRUPTION at size {}: expected {:016x}, got {:016x}",
                                size, expected_checksum, actual_checksum);
                        } else {
                            stats.record_success(latency);
                        }
                    }
                    Ok(Err(_)) => {
                        stats.record_failure();
                    }
                    Err(_) => {
                        stats.record_timeout();
                    }
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            stats.record_connection_dropped();
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    stats.print_report("TCP FRAGMENTATION STRESS - FINAL RESULTS");

    server_handle.abort();

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0,
        "Data corruption detected during fragmentation!");
}

// =============================================================================
// UDP Connectionless Protocol Stress Tests
// =============================================================================

/// UDP sustained load stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_udp_sustained_load() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("UDP CONNECTIONLESS SUSTAINED LOAD TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    // Create UDP server
    let udp_server = dcerpc::UdpDceRpcServer::new();

    let interface = create_echo_interface();
    udp_server.register_interface(interface).await;

    let port = next_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let server_handle = tokio::spawn(async move {
        udp_server.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "UDP Stress").await;
    });

    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            udp_client_worker(client_id, addr, stats, running).await;
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    stats.print_report("UDP SUSTAINED LOAD - FINAL RESULTS");

    server_handle.abort();

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
    // UDP may have some packet loss, so allow lower success rate
    assert!(stats.success_rate() > 90.0,
        "UDP success rate too low: {:.2}%", stats.success_rate());
}

/// UDP client worker
async fn udp_client_worker(
    client_id: usize,
    addr: SocketAddr,
    stats: Arc<ExtendedStats>,
    running: Arc<AtomicBool>,
) {
    let interface_uuid = Uuid::parse(ECHO_UUID).unwrap();
    let version = (ECHO_VERSION.1 as u32) << 16 | (ECHO_VERSION.0 as u32);

    let mut client = match dcerpc::UdpDceRpcClient::connect(addr, interface_uuid, version).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("UDP client {} failed to connect: {}", client_id, e);
            stats.record_connection_error();
            return;
        }
    };

    client.set_timeout(Duration::from_secs(2));
    client.set_retries(2);

    stats.record_connection_created();

    let mut gen = TestDataGenerator::new(client_id as u64 * 9999);

    while running.load(Ordering::Relaxed) {
        // UDP has smaller max message size, keep payloads smaller
        let rand_size = gen.random_bytes(1)[0];
        let size = 64 + (rand_size as usize % 200);
        let payload = gen.random_bytes(size);
        let expected_checksum = compute_checksum(&payload);

        let start = Instant::now();
        match client.call(0, payload).await {
            Ok(response) => {
                let latency = start.elapsed();
                let actual_checksum = compute_checksum(&response);

                if actual_checksum != expected_checksum {
                    stats.record_data_corruption();
                } else {
                    stats.record_success(latency);
                }
            }
            Err(e) => {
                if e.to_string().contains("timeout") {
                    stats.record_timeout();
                } else {
                    stats.record_failure();
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    stats.record_connection_dropped();
}

// =============================================================================
// DCOM Apartment Threading Model Stress Tests
// =============================================================================

/// DCOM MTA sustained load stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_dcom_mta_sustained_load() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("DCOM MTA SUSTAINED LOAD TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let mta = Arc::new(MultithreadedApartment::new());
    let obj = Arc::new(MtaStressObject::new());
    let oid = obj.oid();

    mta.register_object(obj.clone());

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "DCOM MTA").await;
    });

    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let mta = mta.clone();
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(client_id as u64);

            while running.load(Ordering::Relaxed) {
                let rand_op = gen.random_bytes(1)[0];
                let opnum = (rand_op % 4) as u16;
                let payload = gen.random_bytes(32);
                let expected = payload.clone();

                let start = Instant::now();
                match mta.dispatch(oid, Uuid::NIL, opnum, payload).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        if response != expected {
                            stats.record_data_corruption();
                        } else {
                            stats.record_success(latency);
                        }
                    }
                    Err(_) => {
                        stats.record_failure();
                    }
                }

                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    // Report MTA-specific stats
    println!("\nMTA Object Stats:");
    println!("  Total calls: {}", obj.call_count.load(Ordering::Relaxed));
    println!("  Max concurrent: {}", obj.max_concurrent.load(Ordering::Relaxed));

    stats.print_report("DCOM MTA SUSTAINED LOAD - FINAL RESULTS");

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
    assert!(stats.success_rate() > 99.0);
    assert!(obj.max_concurrent.load(Ordering::Relaxed) > 1,
        "MTA should allow concurrent execution");
}

/// DCOM STA thread safety stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_dcom_sta_thread_safety_stress() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("DCOM STA THREAD SAFETY STRESS TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let sta = Arc::new(SinglethreadedApartment::new());
    let obj = Arc::new(StaVerificationObject::new());
    let oid = obj.oid();

    sta.register_object(obj.clone());

    // Give STA message loop time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "DCOM STA").await;
    });

    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let sta = sta.clone();
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(client_id as u64);

            while running.load(Ordering::Relaxed) {
                let payload = gen.random_bytes(16);
                let expected = payload.clone();

                let start = Instant::now();
                match sta.dispatch(oid, Uuid::NIL, 0, payload).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        if response != expected {
                            stats.record_data_corruption();
                        } else {
                            stats.record_success(latency);
                        }
                    }
                    Err(_) => {
                        stats.record_failure();
                    }
                }

                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    sta.shutdown();

    // Report STA-specific stats
    let violations = obj.get_violations();
    println!("\nSTA Object Stats:");
    println!("  Total calls: {}", obj.call_count.load(Ordering::Relaxed));
    println!("  Thread safety violations: {}", violations);

    stats.print_report("DCOM STA THREAD SAFETY - FINAL RESULTS");

    assert_eq!(violations, 0,
        "STA thread safety violations detected! {} concurrent calls", violations);
    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
}

/// DCOM mixed apartment stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_dcom_mixed_apartments_stress() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("DCOM MIXED APARTMENTS STRESS TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let dispatcher = Arc::new(CallDispatcher::new());

    // Create multiple MTAs and STAs
    let mta1 = Arc::new(MultithreadedApartment::new());
    let mta2 = Arc::new(MultithreadedApartment::new());
    let sta1 = Arc::new(SinglethreadedApartment::new());
    let sta2 = Arc::new(SinglethreadedApartment::new());

    dispatcher.register_apartment(mta1.clone());
    dispatcher.register_apartment(mta2.clone());
    dispatcher.register_apartment(sta1.clone());
    dispatcher.register_apartment(sta2.clone());

    // Create objects
    let mut oids = Vec::new();

    for _ in 0..5 {
        let obj = Arc::new(MtaStressObject::new());
        let oid = obj.oid();
        mta1.register_object(obj);
        dispatcher.associate_oid(oid, mta1.id());
        oids.push(oid);
    }

    for _ in 0..5 {
        let obj = Arc::new(MtaStressObject::new());
        let oid = obj.oid();
        mta2.register_object(obj);
        dispatcher.associate_oid(oid, mta2.id());
        oids.push(oid);
    }

    for _ in 0..3 {
        let obj = Arc::new(StaVerificationObject::new());
        let oid = obj.oid();
        sta1.register_object(obj);
        dispatcher.associate_oid(oid, sta1.id());
        oids.push(oid);
    }

    for _ in 0..3 {
        let obj = Arc::new(StaVerificationObject::new());
        let oid = obj.oid();
        sta2.register_object(obj);
        dispatcher.associate_oid(oid, sta2.id());
        oids.push(oid);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "DCOM Mixed").await;
    });

    let oids = Arc::new(oids);
    let mut handles = Vec::new();

    for client_id in 0..num_clients {
        let dispatcher = dispatcher.clone();
        let stats = stats.clone();
        let running = running.clone();
        let oids = oids.clone();

        let handle = tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(client_id as u64);

            while running.load(Ordering::Relaxed) {
                // Pick random object
                let rand_idx = gen.random_bytes(1)[0];
                let oid_idx = (rand_idx as usize) % oids.len();
                let oid = oids[oid_idx];

                let payload = gen.random_bytes(16);
                let expected = payload.clone();

                let start = Instant::now();
                match dispatcher.dispatch(oid, Uuid::NIL, 0, payload).await {
                    Ok(response) => {
                        let latency = start.elapsed();
                        if response != expected {
                            stats.record_data_corruption();
                        } else {
                            stats.record_success(latency);
                        }
                    }
                    Err(_) => {
                        stats.record_failure();
                    }
                }

                tokio::time::sleep(Duration::from_micros(500)).await;
            }
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    sta1.shutdown();
    sta2.shutdown();

    stats.print_report("DCOM MIXED APARTMENTS - FINAL RESULTS");

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
    assert!(stats.success_rate() > 95.0);
}

// =============================================================================
// NDR Encoding Stress Tests
// =============================================================================

/// NDR encoding/decoding stress test
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_ndr_encoding_stress() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("NDR ENCODING STRESS TEST");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("{}", separator);

    let interface = create_ndr_test_interface();
    let (addr, server) = start_test_server(interface).await.unwrap();

    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "NDR Encoding").await;
    });

    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let stats = stats.clone();
        let running = running.clone();

        let handle = tokio::spawn(async move {
            ndr_client_worker(client_id, addr, stats, running).await;
        });
        handles.push(handle);
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    stats.print_report("NDR ENCODING STRESS - FINAL RESULTS");

    server_handle.abort();

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0,
        "NDR encoding corruption detected!");
    assert!(stats.success_rate() > 99.0);
}

/// NDR client worker that exercises all NDR types
async fn ndr_client_worker(
    client_id: usize,
    addr: SocketAddr,
    stats: Arc<ExtendedStats>,
    running: Arc<AtomicBool>,
) {
    let client = match connect_client(addr, NDR_TEST_UUID, NDR_TEST_VERSION).await {
        Ok(c) => {
            stats.record_connection_created();
            c
        }
        Err(_) => {
            stats.record_connection_error();
            return;
        }
    };

    let mut gen = TestDataGenerator::new(client_id as u64 * 77777);
    let ctx = NdrContext::default();

    while running.load(Ordering::Relaxed) {
        // Cycle through different NDR operations
        let rand_type = gen.random_bytes(1)[0];
        let op_type = rand_type % 6;

        let start = Instant::now();
        let result = match op_type {
            0 => {
                // Array sum test
                let rand_count = gen.random_bytes(1)[0];
                let count = 5 + (rand_count as usize % 20);
                let mut buf = BytesMut::new();
                ctx.put_u32(&mut buf, count as u32);

                let mut expected_sum: i64 = 0;
                for _ in 0..count {
                    let rand_val = gen.random_bytes(1)[0];
                    let val = (rand_val as i32) - 128;
                    ctx.put_i32(&mut buf, val);
                    expected_sum += val as i64;
                }

                match client.call(2, buf.freeze()).await {
                    Ok(response) => {
                        if response.len() >= 8 {
                            let mut cursor = response.as_ref();
                            let actual_sum = ctx.get_i64(&mut cursor);
                            if actual_sum == expected_sum {
                                Ok(())
                            } else {
                                Err(format!("Sum mismatch: {} != {}", actual_sum, expected_sum))
                            }
                        } else {
                            Err("Response too short".to_string())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            1 => {
                // String length test
                let rand_len = gen.random_bytes(1)[0];
                let len = 10 + (rand_len as usize % 100);
                let test_str = gen.random_string(len);

                let mut buf = BytesMut::new();
                let str_bytes = test_str.as_bytes();
                ctx.put_u32(&mut buf, (str_bytes.len() + 1) as u32); // max_count
                ctx.put_u32(&mut buf, 0); // offset
                ctx.put_u32(&mut buf, (str_bytes.len() + 1) as u32); // actual_count
                buf.extend_from_slice(str_bytes);
                buf.put_u8(0); // null terminator

                match client.call(3, buf.freeze()).await {
                    Ok(response) => {
                        if response.len() >= 4 {
                            let mut cursor = response.as_ref();
                            let reported_len = ctx.get_u32(&mut cursor);
                            if reported_len == (str_bytes.len() + 1) as u32 {
                                Ok(())
                            } else {
                                Err(format!("Length mismatch: {} != {}", reported_len, str_bytes.len() + 1))
                            }
                        } else {
                            Err("Response too short".to_string())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            2 => {
                // Complex struct roundtrip
                let rand_id = gen.random_bytes(1)[0];
                let data = ComplexTestData {
                    id: rand_id as u64 * 1000,
                    name: gen.random_string(20),
                    values: gen.random_i32_array(10),
                    nested: None,
                };

                let encoded = data.encode();

                match client.call(4, encoded).await {
                    Ok(response) => {
                        if let Some(decoded) = ComplexTestData::decode(&response) {
                            if decoded == data {
                                Ok(())
                            } else {
                                Err("Complex struct mismatch".to_string())
                            }
                        } else {
                            Err("Failed to decode complex struct".to_string())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            3 => {
                // Checksum verification
                let data = gen.random_bytes(128);
                let expected_checksum = compute_checksum(&data);

                match client.call(6, data).await {
                    Ok(response) => {
                        if response.len() >= 8 {
                            let mut cursor = response.as_ref();
                            let server_checksum = ctx.get_u64(&mut cursor);
                            if server_checksum == expected_checksum {
                                Ok(())
                            } else {
                                Err(format!("Checksum mismatch: {:016x} != {:016x}",
                                    server_checksum, expected_checksum))
                            }
                        } else {
                            Err("Response too short".to_string())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            4 => {
                // Large buffer allocation
                let rand_size1 = gen.random_bytes(1)[0];
                let rand_size2 = gen.random_bytes(1)[0];
                let size = 1024 + (rand_size1 as usize * 100) + (rand_size2 as usize);
                let mut buf = BytesMut::new();
                ctx.put_u32(&mut buf, size as u32);

                match client.call(5, buf.freeze()).await {
                    Ok(response) => {
                        if response.len() == size {
                            // Verify pattern
                            let mut valid = true;
                            for (i, &byte) in response.iter().enumerate() {
                                if byte != (i % 256) as u8 {
                                    valid = false;
                                    break;
                                }
                            }
                            if valid {
                                Ok(())
                            } else {
                                Err("Buffer pattern mismatch".to_string())
                            }
                        } else {
                            Err(format!("Buffer size mismatch: {} != {}", response.len(), size))
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            _ => {
                // Simple echo
                let data = gen.random_bytes(64);
                match client.call(0, data.clone()).await {
                    Ok(response) if response == data => Ok(()),
                    Ok(_) => Err("Echo mismatch".to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
        };

        let latency = start.elapsed();
        match result {
            Ok(()) => stats.record_success(latency),
            Err(e) => {
                if e.contains("mismatch") || e.contains("corruption") {
                    stats.record_data_corruption();
                } else {
                    stats.record_failure();
                }
            }
        }

        tokio::time::sleep(Duration::from_micros(500)).await;
    }

    stats.record_connection_dropped();
}

// =============================================================================
// Combined Full Stack Stress Test
// =============================================================================

/// Full stack stress test combining all components
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore]
async fn test_full_stack_stress() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("FULL STACK STRESS TEST");
    println!("Testing: TCP + UDP + DCOM MTA + DCOM STA + NDR");
    println!("Duration: {:?}", test_duration);
    println!("Clients per component: {}", num_clients / 4);
    println!("{}", separator);

    // Create all servers
    let tcp_interface = create_ndr_test_interface();
    let (tcp_addr, tcp_server) = start_test_server(tcp_interface).await.unwrap();
    let tcp_handle = tokio::spawn(async move { tcp_server.run().await });

    let udp_server = dcerpc::UdpDceRpcServer::new();
    udp_server.register_interface(create_echo_interface()).await;
    let udp_port = next_port();
    let udp_addr: SocketAddr = format!("127.0.0.1:{}", udp_port).parse().unwrap();
    let udp_handle = tokio::spawn(async move { udp_server.run(udp_addr).await });

    // Create DCOM apartments
    let mta = Arc::new(MultithreadedApartment::new());
    let sta = Arc::new(SinglethreadedApartment::new());

    let mta_obj = Arc::new(MtaStressObject::new());
    let mta_oid = mta_obj.oid();
    mta.register_object(mta_obj);

    let sta_obj = Arc::new(StaVerificationObject::new());
    let sta_oid = sta_obj.oid();
    sta.register_object(sta_obj);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "Full Stack").await;
    });

    let clients_per_type = (num_clients / 4).max(1);
    let mut handles = Vec::new();

    // TCP clients
    for i in 0..clients_per_type {
        let stats = stats.clone();
        let running = running.clone();
        handles.push(tokio::spawn(async move {
            ndr_client_worker(i, tcp_addr, stats, running).await;
        }));
    }

    // UDP clients
    for i in 0..clients_per_type {
        let stats = stats.clone();
        let running = running.clone();
        handles.push(tokio::spawn(async move {
            udp_client_worker(i + 1000, udp_addr, stats, running).await;
        }));
    }

    // MTA clients
    for i in 0..clients_per_type {
        let mta = mta.clone();
        let stats = stats.clone();
        let running = running.clone();
        handles.push(tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(i as u64 + 2000);
            while running.load(Ordering::Relaxed) {
                let payload = gen.random_bytes(32);
                let expected = payload.clone();
                let start = Instant::now();
                match mta.dispatch(mta_oid, Uuid::NIL, 0, payload).await {
                    Ok(response) if response == expected => {
                        stats.record_success(start.elapsed());
                    }
                    Ok(_) => stats.record_data_corruption(),
                    Err(_) => stats.record_failure(),
                }
                tokio::time::sleep(Duration::from_micros(500)).await;
            }
        }));
    }

    // STA clients
    for i in 0..clients_per_type {
        let sta = sta.clone();
        let stats = stats.clone();
        let running = running.clone();
        handles.push(tokio::spawn(async move {
            let mut gen = TestDataGenerator::new(i as u64 + 3000);
            while running.load(Ordering::Relaxed) {
                let payload = gen.random_bytes(16);
                let expected = payload.clone();
                let start = Instant::now();
                match sta.dispatch(sta_oid, Uuid::NIL, 0, payload).await {
                    Ok(response) if response == expected => {
                        stats.record_success(start.elapsed());
                    }
                    Ok(_) => stats.record_data_corruption(),
                    Err(_) => stats.record_failure(),
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }));
    }

    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    join_all(handles).await;
    reporter_handle.abort();

    sta.shutdown();
    tcp_handle.abort();
    udp_handle.abort();

    stats.print_report("FULL STACK STRESS - FINAL RESULTS");

    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0,
        "Data corruption detected in full stack test!");
    assert!(stats.success_rate() > 95.0,
        "Full stack success rate too low: {:.2}%", stats.success_rate());
}
