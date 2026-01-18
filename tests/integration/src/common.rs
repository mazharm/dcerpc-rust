//! Common test utilities and infrastructure
//!
//! Provides shared functionality for all integration tests including:
//! - Test server/client setup
//! - Port allocation
//! - Logging initialization
//! - Test result collection

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tracing::{info, warn, Level};

use dcerpc::{DceRpcClient, DceRpcServer, Interface, InterfaceBuilder, SyntaxId, Uuid};
use midl_ndr::{NdrContext, NdrEncode, NdrDecode};

/// Base port for test servers (incremented for each test)
static NEXT_PORT: AtomicU16 = AtomicU16::new(10000);

/// Global test counter for unique IDs
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Get the next available port for a test server
pub fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// Get a unique test ID
pub fn next_test_id() -> u64 {
    TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Initialize logging for tests
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// Test result with timing information
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    pub error: Option<String>,
    pub operations: u64,
    pub throughput: Option<f64>, // ops/sec
}

impl TestResult {
    pub fn success(name: &str, duration: Duration, operations: u64) -> Self {
        let throughput = if duration.as_secs_f64() > 0.0 {
            Some(operations as f64 / duration.as_secs_f64())
        } else {
            None
        };

        Self {
            name: name.to_string(),
            passed: true,
            duration,
            error: None,
            operations,
            throughput,
        }
    }

    pub fn failure(name: &str, duration: Duration, error: String) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            duration,
            error: Some(error),
            operations: 0,
            throughput: None,
        }
    }
}

/// Test suite results collector
#[derive(Debug, Default)]
pub struct TestSuiteResults {
    pub results: Vec<TestResult>,
    pub total_duration: Duration,
}

impl TestSuiteResults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, result: TestResult) {
        self.results.push(result);
    }

    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    pub fn print_summary(&self) {
        println!("\n{}", "=".repeat(80));
        println!("TEST SUITE SUMMARY");
        println!("{}", "=".repeat(80));
        println!("Total: {} | Passed: {} | Failed: {}",
            self.results.len(), self.passed(), self.failed());
        println!("Total Duration: {:?}", self.total_duration);
        println!("{}", "-".repeat(80));

        for result in &self.results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            let throughput = result.throughput
                .map(|t| format!(" ({:.2} ops/sec)", t))
                .unwrap_or_default();

            println!("[{}] {} - {:?}{}",
                status,
                result.name,
                result.duration,
                throughput
            );

            if let Some(ref err) = result.error {
                println!("       Error: {}", err);
            }
        }

        println!("{}", "=".repeat(80));
    }
}

/// Simple echo interface for testing
pub const ECHO_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
pub const ECHO_VERSION: (u16, u16) = (1, 0);

/// Create an echo interface for testing
pub fn create_echo_interface() -> Interface {
    InterfaceBuilder::new(ECHO_UUID, ECHO_VERSION.0, ECHO_VERSION.1)
        .unwrap()
        .operation(0, |stub_data| {
            Box::pin(async move {
                // Echo back the input
                Ok(stub_data)
            })
        })
        .operation(1, |stub_data| {
            // Delayed echo - simulate work
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(stub_data)
            })
        })
        .operation(2, |stub_data| {
            // Transform echo - reverse bytes
            Box::pin(async move {
                let reversed: Vec<u8> = stub_data.iter().rev().cloned().collect();
                Ok(Bytes::from(reversed))
            })
        })
        .build()
}

/// Calculator interface for complex type testing
pub const CALC_UUID: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
pub const CALC_VERSION: (u16, u16) = (1, 0);

/// Operation numbers for calculator
pub mod calc_opnum {
    pub const ADD: u16 = 0;
    pub const SUBTRACT: u16 = 1;
    pub const MULTIPLY: u16 = 2;
    pub const DIVIDE: u16 = 3;
    pub const COMPLEX_OP: u16 = 4;
    pub const ARRAY_SUM: u16 = 5;
    pub const STRING_CONCAT: u16 = 6;
}

/// Create a calculator interface for testing
pub fn create_calculator_interface() -> Interface {
    InterfaceBuilder::new(CALC_UUID, CALC_VERSION.0, CALC_VERSION.1)
        .unwrap()
        .operation(calc_opnum::ADD, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();
                let a = ctx.get_i32(&mut cursor);
                let b = ctx.get_i32(&mut cursor);

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, a + b);
                Ok(buf.freeze())
            })
        })
        .operation(calc_opnum::SUBTRACT, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();
                let a = ctx.get_i32(&mut cursor);
                let b = ctx.get_i32(&mut cursor);

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, a - b);
                Ok(buf.freeze())
            })
        })
        .operation(calc_opnum::MULTIPLY, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();
                let a = ctx.get_i32(&mut cursor);
                let b = ctx.get_i32(&mut cursor);

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, a * b);
                Ok(buf.freeze())
            })
        })
        .operation(calc_opnum::DIVIDE, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();
                let a = ctx.get_i32(&mut cursor);
                let b = ctx.get_i32(&mut cursor);

                let mut buf = BytesMut::new();
                if b == 0 {
                    ctx.put_i32(&mut buf, 0);
                    ctx.put_i32(&mut buf, -1); // Error flag
                } else {
                    ctx.put_i32(&mut buf, a / b);
                    ctx.put_i32(&mut buf, a % b);
                }
                Ok(buf.freeze())
            })
        })
        .operation(calc_opnum::ARRAY_SUM, |stub_data| {
            Box::pin(async move {
                let mut cursor = stub_data.as_ref();
                let ctx = NdrContext::default();

                // Read array count
                let count = ctx.get_u32(&mut cursor) as usize;

                // Sum all elements
                let mut sum: i64 = 0;
                for _ in 0..count {
                    sum += ctx.get_i32(&mut cursor) as i64;
                }

                let mut buf = BytesMut::new();
                ctx.put_i64(&mut buf, sum);
                Ok(buf.freeze())
            })
        })
        .build()
}

/// A test server wrapper that knows its address
pub struct TestServer {
    pub addr: SocketAddr,
    pub server: DceRpcServer,
}

impl TestServer {
    pub async fn run(&self) -> dcerpc::Result<()> {
        self.server.run(self.addr).await
    }
}

/// Start a test server and return its address
pub async fn start_test_server(interface: Interface) -> dcerpc::Result<(SocketAddr, TestServer)> {
    let port = next_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let server = DceRpcServer::new();
    server.register_interface(interface).await;

    Ok((addr, TestServer { addr, server }))
}

/// Connect a client to a test server
pub async fn connect_client(addr: SocketAddr, uuid: &str, version: (u16, u16)) -> dcerpc::Result<DceRpcClient> {
    let interface = SyntaxId::new(
        Uuid::parse(uuid).unwrap(),
        version.0,
        version.1,
    );
    DceRpcClient::connect(addr, interface).await
}

/// Statistics tracker for concurrent tests
#[derive(Debug, Default)]
pub struct ConcurrentStats {
    pub successful_ops: AtomicU64,
    pub failed_ops: AtomicU64,
    pub total_latency_ns: AtomicU64,
    pub max_latency_ns: AtomicU64,
    pub min_latency_ns: AtomicU64,
}

impl ConcurrentStats {
    pub fn new() -> Self {
        Self {
            successful_ops: AtomicU64::new(0),
            failed_ops: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
        }
    }

    pub fn record_success(&self, latency: Duration) {
        self.successful_ops.fetch_add(1, Ordering::SeqCst);
        let ns = latency.as_nanos() as u64;
        self.total_latency_ns.fetch_add(ns, Ordering::SeqCst);

        // Update max
        let mut current = self.max_latency_ns.load(Ordering::SeqCst);
        while ns > current {
            match self.max_latency_ns.compare_exchange_weak(
                current, ns, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }

        // Update min
        current = self.min_latency_ns.load(Ordering::SeqCst);
        while ns < current {
            match self.min_latency_ns.compare_exchange_weak(
                current, ns, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    pub fn record_failure(&self) {
        self.failed_ops.fetch_add(1, Ordering::SeqCst);
    }

    pub fn success_count(&self) -> u64 {
        self.successful_ops.load(Ordering::SeqCst)
    }

    pub fn failure_count(&self) -> u64 {
        self.failed_ops.load(Ordering::SeqCst)
    }

    pub fn avg_latency(&self) -> Duration {
        let total = self.total_latency_ns.load(Ordering::SeqCst);
        let count = self.successful_ops.load(Ordering::SeqCst);
        if count > 0 {
            Duration::from_nanos(total / count)
        } else {
            Duration::ZERO
        }
    }

    pub fn max_latency(&self) -> Duration {
        Duration::from_nanos(self.max_latency_ns.load(Ordering::SeqCst))
    }

    pub fn min_latency(&self) -> Duration {
        let min = self.min_latency_ns.load(Ordering::SeqCst);
        if min == u64::MAX {
            Duration::ZERO
        } else {
            Duration::from_nanos(min)
        }
    }
}

/// Rate limiter for controlled concurrency testing
pub struct RateLimiter {
    semaphore: Semaphore,
    max_concurrent: usize,
}

impl RateLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Semaphore::new(max_concurrent),
            max_concurrent,
        }
    }

    pub async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.semaphore.acquire().await.unwrap()
    }
}

/// Test data generator for various scenarios
pub struct TestDataGenerator {
    rng_seed: u64,
}

impl TestDataGenerator {
    pub fn new(seed: u64) -> Self {
        Self { rng_seed: seed }
    }

    /// Generate random bytes of given length
    pub fn random_bytes(&mut self, len: usize) -> Bytes {
        let mut data = Vec::with_capacity(len);
        for i in 0..len {
            self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            data.push((self.rng_seed >> 33) as u8);
        }
        Bytes::from(data)
    }

    /// Generate a random i32 array
    pub fn random_i32_array(&mut self, len: usize) -> Vec<i32> {
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            data.push((self.rng_seed >> 32) as i32);
        }
        data
    }

    /// Generate a random string
    pub fn random_string(&mut self, len: usize) -> String {
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            self.rng_seed = self.rng_seed.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = ((self.rng_seed >> 33) as usize) % CHARS.len();
            s.push(CHARS[idx] as char);
        }
        s
    }
}

/// Verify data integrity by checking a simple checksum
pub fn compute_checksum(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }
    hash
}

/// Complex test structure for NDR encoding tests
#[derive(Debug, Clone, PartialEq)]
pub struct ComplexTestData {
    pub id: u64,
    pub name: String,
    pub values: Vec<i32>,
    pub nested: Option<Box<ComplexTestData>>,
}

impl ComplexTestData {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let ctx = NdrContext::default();

        // Encode id
        ctx.put_u64(&mut buf, self.id);

        // Encode name as conformant varying string
        let name_bytes = self.name.as_bytes();
        ctx.put_u32(&mut buf, name_bytes.len() as u32 + 1); // max_count
        ctx.put_u32(&mut buf, 0); // offset
        ctx.put_u32(&mut buf, name_bytes.len() as u32 + 1); // actual_count
        buf.put_slice(name_bytes);
        buf.put_u8(0); // null terminator
        // Pad to 4-byte alignment
        while buf.len() % 4 != 0 {
            buf.put_u8(0);
        }

        // Encode values array
        ctx.put_u32(&mut buf, self.values.len() as u32);
        for &v in &self.values {
            ctx.put_i32(&mut buf, v);
        }

        // Encode nested (as unique pointer)
        if let Some(ref nested) = self.nested {
            ctx.put_u32(&mut buf, 1); // non-null
            let nested_data = nested.encode();
            buf.put_slice(&nested_data);
        } else {
            ctx.put_u32(&mut buf, 0); // null
        }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let ctx = NdrContext::default();
        let mut cursor = data;

        if cursor.remaining() < 8 {
            return None;
        }
        let id = ctx.get_u64(&mut cursor);

        if cursor.remaining() < 12 {
            return None;
        }
        let max_count = ctx.get_u32(&mut cursor) as usize;
        let _offset = ctx.get_u32(&mut cursor);
        let actual_count = ctx.get_u32(&mut cursor) as usize;

        if cursor.remaining() < actual_count {
            return None;
        }
        let name_bytes: Vec<u8> = cursor[..actual_count - 1].to_vec();
        cursor.advance(actual_count);
        // Skip padding
        while cursor.len() % 4 != 0 && !cursor.is_empty() {
            cursor.advance(1);
        }
        let name = String::from_utf8(name_bytes).ok()?;

        if cursor.remaining() < 4 {
            return None;
        }
        let array_count = ctx.get_u32(&mut cursor) as usize;

        if cursor.remaining() < array_count * 4 {
            return None;
        }
        let mut values = Vec::with_capacity(array_count);
        for _ in 0..array_count {
            values.push(ctx.get_i32(&mut cursor));
        }

        if cursor.remaining() < 4 {
            return None;
        }
        let has_nested = ctx.get_u32(&mut cursor) != 0;
        let nested = if has_nested {
            ComplexTestData::decode(cursor).map(Box::new)
        } else {
            None
        };

        Some(Self { id, name, values, nested })
    }
}
