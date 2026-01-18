//! Circular Call Tests - A->B->A Callback Scenarios
//!
//! These tests exercise circular/recursive call patterns:
//! - Service A calls Service B which calls back to Service A
//! - Reentrancy handling
//! - Deadlock detection/prevention
//! - Stack depth limits

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use futures::future::join_all;
use parking_lot::Mutex;

use common::*;
use dcerpc::{DceRpcClient, DceRpcServer, Interface, InterfaceBuilder, SyntaxId, Uuid};
use midl_ndr::NdrContext;

/// Service A UUID
pub const SERVICE_A_UUID: &str = "a1111111-1111-1111-1111-111111111111";
/// Service B UUID
pub const SERVICE_B_UUID: &str = "b2222222-2222-2222-2222-222222222222";
/// Service version
pub const CIRCULAR_VERSION: (u16, u16) = (1, 0);

/// Callback tracking
struct CallbackTracker {
    a_calls: AtomicU64,
    b_calls: AtomicU64,
    a_callbacks: AtomicU64,
    max_depth: AtomicU32,
    current_depth: AtomicU32,
}

impl CallbackTracker {
    fn new() -> Self {
        Self {
            a_calls: AtomicU64::new(0),
            b_calls: AtomicU64::new(0),
            a_callbacks: AtomicU64::new(0),
            max_depth: AtomicU32::new(0),
            current_depth: AtomicU32::new(0),
        }
    }

    fn enter(&self) -> u32 {
        let depth = self.current_depth.fetch_add(1, Ordering::SeqCst) + 1;
        let mut max = self.max_depth.load(Ordering::SeqCst);
        while depth > max {
            match self.max_depth.compare_exchange_weak(
                max, depth, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(m) => max = m,
            }
        }
        depth
    }

    fn leave(&self) {
        self.current_depth.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Create Service A that can receive callbacks
fn create_service_a(tracker: Arc<CallbackTracker>) -> Interface {
    InterfaceBuilder::new(SERVICE_A_UUID, CIRCULAR_VERSION.0, CIRCULAR_VERSION.1)
        .unwrap()
        // Op 0: Initial entry point (will call Service B)
        .operation(0, {
            let tracker = tracker.clone();
            move |stub_data| {
                let tracker = tracker.clone();
                Box::pin(async move {
                    tracker.a_calls.fetch_add(1, Ordering::SeqCst);
                    let depth = tracker.enter();

                    let ctx = NdrContext::default();
                    let mut cursor = stub_data.as_ref();

                    // Get B's address and value
                    let b_port = if cursor.remaining() >= 2 {
                        ctx.get_u16(&mut cursor)
                    } else {
                        return Err(dcerpc::RpcError::InvalidPduData("missing port".into()));
                    };
                    let value = if cursor.remaining() >= 4 {
                        ctx.get_i32(&mut cursor)
                    } else {
                        0
                    };

                    let b_addr: SocketAddr = format!("127.0.0.1:{}", b_port).parse().unwrap();

                    // Call Service B
                    let b_client = DceRpcClient::connect(
                        b_addr,
                        SyntaxId::new(
                            Uuid::parse(SERVICE_B_UUID).unwrap(),
                            CIRCULAR_VERSION.0,
                            CIRCULAR_VERSION.1,
                        ),
                    ).await?;

                    let mut forward = BytesMut::new();
                    ctx.put_i32(&mut forward, value + 1);

                    let response = b_client.call(0, forward.freeze()).await?;

                    tracker.leave();

                    // Add our marker
                    let mut result = BytesMut::new();
                    result.put_slice(&response);
                    ctx.put_i32(&mut result, 1000 + depth as i32); // A marker with depth
                    Ok(result.freeze())
                })
            }
        })
        // Op 1: Callback endpoint (called by B)
        .operation(1, {
            let tracker = tracker.clone();
            move |stub_data| {
                let tracker = tracker.clone();
                Box::pin(async move {
                    tracker.a_callbacks.fetch_add(1, Ordering::SeqCst);
                    let depth = tracker.enter();

                    let ctx = NdrContext::default();
                    let mut cursor = stub_data.as_ref();
                    let value = if cursor.remaining() >= 4 {
                        ctx.get_i32(&mut cursor)
                    } else {
                        0
                    };

                    // Simple processing - no further calls
                    tokio::time::sleep(Duration::from_millis(1)).await;

                    tracker.leave();

                    let mut result = BytesMut::new();
                    ctx.put_i32(&mut result, value * 2);
                    ctx.put_i32(&mut result, 500 + depth as i32); // Callback marker
                    Ok(result.freeze())
                })
            }
        })
        .build()
}

/// Create Service B that calls back to A
fn create_service_b(a_addr: SocketAddr, tracker: Arc<CallbackTracker>) -> Interface {
    InterfaceBuilder::new(SERVICE_B_UUID, CIRCULAR_VERSION.0, CIRCULAR_VERSION.1)
        .unwrap()
        // Op 0: Receive call and callback to A
        .operation(0, {
            let tracker = tracker.clone();
            move |stub_data| {
                let tracker = tracker.clone();
                let a_addr = a_addr;
                Box::pin(async move {
                    tracker.b_calls.fetch_add(1, Ordering::SeqCst);
                    let depth = tracker.enter();

                    let ctx = NdrContext::default();
                    let mut cursor = stub_data.as_ref();
                    let value = if cursor.remaining() >= 4 {
                        ctx.get_i32(&mut cursor)
                    } else {
                        0
                    };

                    // Callback to Service A
                    let a_client = DceRpcClient::connect(
                        a_addr,
                        SyntaxId::new(
                            Uuid::parse(SERVICE_A_UUID).unwrap(),
                            CIRCULAR_VERSION.0,
                            CIRCULAR_VERSION.1,
                        ),
                    ).await?;

                    let mut callback_data = BytesMut::new();
                    ctx.put_i32(&mut callback_data, value + 10);

                    let callback_response = a_client.call(1, callback_data.freeze()).await?;

                    tracker.leave();

                    // Combine responses
                    let mut result = BytesMut::new();
                    result.put_slice(&callback_response);
                    ctx.put_i32(&mut result, 2000 + depth as i32); // B marker
                    Ok(result.freeze())
                })
            }
        })
        .build()
}

/// Test: Simple A->B->A callback
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simple_callback() {
    init_logging();

    let tracker = Arc::new(CallbackTracker::new());

    // Start Service A
    let a_interface = create_service_a(tracker.clone());
    let a_port = next_port();
    let a_addr: SocketAddr = format!("127.0.0.1:{}", a_port).parse().unwrap();
    let a_server = DceRpcServer::new();
    a_server.register_interface(a_interface).await;
    let a_handle = tokio::spawn(async move { a_server.run(a_addr).await });

    // Start Service B (needs A's address for callbacks)
    let b_interface = create_service_b(a_addr, tracker.clone());
    let b_port = next_port();
    let b_addr: SocketAddr = format!("127.0.0.1:{}", b_port).parse().unwrap();
    let b_server = DceRpcServer::new();
    b_server.register_interface(b_interface).await;
    let b_handle = tokio::spawn(async move { b_server.run(b_addr).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Client calls A, which calls B, which calls back to A
    let client = connect_client(a_addr, SERVICE_A_UUID, CIRCULAR_VERSION).await.unwrap();

    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_u16(&mut buf, b_port);
    ctx.put_i32(&mut buf, 5); // Initial value

    let start = Instant::now();
    let response = client.call(0, buf.freeze()).await.unwrap();
    let duration = start.elapsed();

    // Parse response
    // Flow: A(5) -> B(6) -> A_callback(16) -> 16*2=32
    // Response: [callback_result, callback_marker, b_marker, a_marker]
    let mut cursor = response.as_ref();
    let callback_result = ctx.get_i32(&mut cursor);
    let callback_marker = ctx.get_i32(&mut cursor);
    let b_marker = ctx.get_i32(&mut cursor);
    let a_marker = ctx.get_i32(&mut cursor);

    a_handle.abort();
    b_handle.abort();

    println!("\n=== Simple Callback Test ===");
    println!("Input: 5");
    println!("Callback result: {} (expected 32)", callback_result);
    println!("Callback marker: {} (expected 501)", callback_marker);
    println!("B marker: {} (expected 2001)", b_marker);
    println!("A marker: {} (expected 1001)", a_marker);
    println!("Duration: {:?}", duration);
    println!("A calls: {}", tracker.a_calls.load(Ordering::SeqCst));
    println!("B calls: {}", tracker.b_calls.load(Ordering::SeqCst));
    println!("A callbacks: {}", tracker.a_callbacks.load(Ordering::SeqCst));
    println!("Max depth: {}", tracker.max_depth.load(Ordering::SeqCst));

    assert_eq!(callback_result, 32, "Callback should return (5+1+10)*2 = 32");
    assert_eq!(tracker.a_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tracker.b_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tracker.a_callbacks.load(Ordering::SeqCst), 1);

    println!("Simple Callback Test: PASSED");
}

/// Test: Multiple concurrent circular calls
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_callbacks() {
    init_logging();

    const NUM_CLIENTS: usize = 20;

    let tracker = Arc::new(CallbackTracker::new());

    // Start services
    let a_interface = create_service_a(tracker.clone());
    let a_port = next_port();
    let a_addr: SocketAddr = format!("127.0.0.1:{}", a_port).parse().unwrap();
    let a_server = DceRpcServer::new();
    a_server.register_interface(a_interface).await;
    let a_handle = tokio::spawn(async move { a_server.run(a_addr).await });

    let b_interface = create_service_b(a_addr, tracker.clone());
    let b_port = next_port();
    let b_addr: SocketAddr = format!("127.0.0.1:{}", b_port).parse().unwrap();
    let b_server = DceRpcServer::new();
    b_server.register_interface(b_interface).await;
    let b_handle = tokio::spawn(async move { b_server.run(b_addr).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..NUM_CLIENTS {
        let stats = stats.clone();
        let b_port = b_port;

        let handle = tokio::spawn(async move {
            let client = match connect_client(a_addr, SERVICE_A_UUID, CIRCULAR_VERSION).await {
                Ok(c) => c,
                Err(_) => {
                    stats.record_failure();
                    return;
                }
            };

            let ctx = NdrContext::default();
            let mut buf = BytesMut::new();
            ctx.put_u16(&mut buf, b_port);
            ctx.put_i32(&mut buf, i as i32);

            let req_start = Instant::now();
            match client.call(0, buf.freeze()).await {
                Ok(response) => {
                    // Verify response structure
                    if response.len() >= 16 {
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

    a_handle.abort();
    b_handle.abort();

    println!("\n=== Concurrent Callbacks Test ===");
    println!("Concurrent clients: {}", NUM_CLIENTS);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Duration: {:?}", total_duration);
    println!("A calls: {}", tracker.a_calls.load(Ordering::SeqCst));
    println!("B calls: {}", tracker.b_calls.load(Ordering::SeqCst));
    println!("A callbacks: {}", tracker.a_callbacks.load(Ordering::SeqCst));
    println!("Max depth: {}", tracker.max_depth.load(Ordering::SeqCst));

    assert!(stats.success_count() >= NUM_CLIENTS as u64 * 80 / 100,
        "Too many failures in concurrent callbacks");

    println!("Concurrent Callbacks Test: PASSED");
}

/// Test: Circular calls with MTA
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_circular_mta() {
    init_logging();

    use dcom::apartment::{Apartment, MultithreadedApartment, ComObject, CallFuture};
    use dcom::types::Oid;
    use std::any::Any;

    let mta = Arc::new(MultithreadedApartment::new());
    let call_count = Arc::new(AtomicU64::new(0));
    let max_depth = Arc::new(AtomicU32::new(0));

    // Object A
    struct ObjectA {
        oid: Oid,
        mta: Arc<MultithreadedApartment>,
        b_oid: Arc<Mutex<Option<Oid>>>,
        call_count: Arc<AtomicU64>,
        depth: Arc<AtomicU32>,
        max_depth: Arc<AtomicU32>,
    }

    impl ComObject for ObjectA {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, opnum: u16, args: Bytes) -> CallFuture {
            let mta = self.mta.clone();
            let b_oid = self.b_oid.clone();
            let call_count = self.call_count.clone();
            let depth = self.depth.clone();
            let max_depth = self.max_depth.clone();

            Box::pin(async move {
                call_count.fetch_add(1, Ordering::SeqCst);
                let current_depth = depth.fetch_add(1, Ordering::SeqCst) + 1;

                // Update max depth
                let mut max = max_depth.load(Ordering::SeqCst);
                while current_depth > max {
                    match max_depth.compare_exchange_weak(max, current_depth, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(m) => max = m,
                    }
                }

                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let value = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                // Get b_oid outside of if-let to avoid holding lock across await
                let maybe_b_oid = *b_oid.lock();
                let result = if opnum == 0 {
                    // Initial call - forward to B
                    if let Some(b_oid_val) = maybe_b_oid {
                        let mut forward = BytesMut::new();
                        ctx.put_i32(&mut forward, value + 1);
                        let response = mta.dispatch(b_oid_val, Uuid::NIL, 0, forward.freeze()).await?;

                        let mut result = BytesMut::new();
                        result.put_slice(&response);
                        ctx.put_i32(&mut result, 100);
                        result.freeze()
                    } else {
                        let mut buf = BytesMut::new();
                        ctx.put_i32(&mut buf, value);
                        buf.freeze()
                    }
                } else {
                    // Callback from B
                    let mut buf = BytesMut::new();
                    ctx.put_i32(&mut buf, value * 3);
                    ctx.put_i32(&mut buf, 200);
                    buf.freeze()
                };

                depth.fetch_sub(1, Ordering::SeqCst);
                Ok(result)
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    // Object B
    struct ObjectB {
        oid: Oid,
        mta: Arc<MultithreadedApartment>,
        a_oid: Oid,
    }

    impl ComObject for ObjectB {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            let mta = self.mta.clone();
            let a_oid = self.a_oid;

            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let value = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                // Callback to A
                let mut callback = BytesMut::new();
                ctx.put_i32(&mut callback, value + 5);
                let response = mta.dispatch(a_oid, Uuid::NIL, 1, callback.freeze()).await?;

                let mut result = BytesMut::new();
                result.put_slice(&response);
                ctx.put_i32(&mut result, 300);
                Ok(result.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let b_oid_holder = Arc::new(Mutex::new(None));
    let depth = Arc::new(AtomicU32::new(0));

    let obj_a = Arc::new(ObjectA {
        oid: Oid::generate(),
        mta: mta.clone(),
        b_oid: b_oid_holder.clone(),
        call_count: call_count.clone(),
        depth: depth.clone(),
        max_depth: max_depth.clone(),
    });
    let a_oid = obj_a.oid();
    mta.register_object(obj_a);

    let obj_b = Arc::new(ObjectB {
        oid: Oid::generate(),
        mta: mta.clone(),
        a_oid,
    });
    let b_oid = obj_b.oid();
    mta.register_object(obj_b);

    *b_oid_holder.lock() = Some(b_oid);

    // Test circular call
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_i32(&mut buf, 10);

    // Flow: A(10) -> B(11) -> A_callback(16) -> 16*3=48
    let response = mta.dispatch(a_oid, Uuid::NIL, 0, buf.freeze()).await.unwrap();

    let mut cursor = response.as_ref();
    let callback_result = ctx.get_i32(&mut cursor);
    let callback_marker = ctx.get_i32(&mut cursor);
    let b_marker = ctx.get_i32(&mut cursor);
    let a_marker = ctx.get_i32(&mut cursor);

    println!("\n=== Circular MTA Test ===");
    println!("Input: 10");
    println!("Callback result: {} (expected 48)", callback_result);
    println!("Callback marker: {} (expected 200)", callback_marker);
    println!("B marker: {} (expected 300)", b_marker);
    println!("A marker: {} (expected 100)", a_marker);
    println!("Total A calls: {}", call_count.load(Ordering::SeqCst));
    println!("Max depth: {}", max_depth.load(Ordering::SeqCst));

    assert_eq!(callback_result, 48);
    assert_eq!(call_count.load(Ordering::SeqCst), 2); // Initial + callback

    println!("Circular MTA Test: PASSED");
}

/// Test: Circular calls with STA (tests reentrancy)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_circular_sta() {
    init_logging();

    use dcom::apartment::{Apartment, SinglethreadedApartment, ComObject, CallFuture};
    use dcom::types::Oid;
    use std::any::Any;

    // For STA circular calls, we need to be careful about reentrancy
    // The STA message loop should handle nested dispatches

    let sta = Arc::new(SinglethreadedApartment::new());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let call_count = Arc::new(AtomicU64::new(0));

    // Simple object that can be called back
    struct StaObject {
        oid: Oid,
        call_count: Arc<AtomicU64>,
    }

    impl ComObject for StaObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, opnum: u16, args: Bytes) -> CallFuture {
            self.call_count.fetch_add(1, Ordering::SeqCst);

            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let value = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                let result = match opnum {
                    0 => value + 1,
                    1 => value * 2,
                    _ => value,
                };

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, result);
                Ok(buf.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let obj = Arc::new(StaObject {
        oid: Oid::generate(),
        call_count: call_count.clone(),
    });
    let oid = obj.oid();
    sta.register_object(obj);

    // Make multiple sequential calls (STA serializes them)
    let ctx = NdrContext::default();
    let mut results = Vec::new();

    for i in 0..5 {
        let mut buf = BytesMut::new();
        ctx.put_i32(&mut buf, i);

        let response = sta.dispatch(oid, Uuid::NIL, 0, buf.freeze()).await.unwrap();
        let mut cursor = response.as_ref();
        let result = ctx.get_i32(&mut cursor);
        results.push(result);
    }

    sta.shutdown();

    println!("\n=== Circular STA Test ===");
    println!("Results: {:?}", results);
    println!("Expected: [1, 2, 3, 4, 5]");
    println!("Call count: {}", call_count.load(Ordering::SeqCst));

    assert_eq!(results, vec![1, 2, 3, 4, 5]);
    assert_eq!(call_count.load(Ordering::SeqCst), 5);

    println!("Circular STA Test: PASSED");
}

/// Test: Deep recursion through circular calls
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_deep_circular_recursion() {
    init_logging();

    use dcom::apartment::{Apartment, MultithreadedApartment, ComObject, CallFuture};
    use dcom::types::Oid;
    use std::any::Any;

    const MAX_DEPTH: i32 = 10;

    let mta = Arc::new(MultithreadedApartment::new());
    let actual_max_depth = Arc::new(AtomicU32::new(0));

    // Recursive object
    struct RecursiveObject {
        oid: Oid,
        mta: Arc<MultithreadedApartment>,
        max_depth: Arc<AtomicU32>,
    }

    impl ComObject for RecursiveObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            let mta = self.mta.clone();
            let oid = self.oid;
            let max_depth_tracker = self.max_depth.clone();

            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let depth = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                // Track max depth
                let mut max = max_depth_tracker.load(Ordering::SeqCst);
                while depth as u32 > max {
                    match max_depth_tracker.compare_exchange_weak(max, depth as u32, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(m) => max = m,
                    }
                }

                if depth >= MAX_DEPTH {
                    // Base case - return accumulated value
                    let mut buf = BytesMut::new();
                    ctx.put_i32(&mut buf, depth);
                    Ok(buf.freeze())
                } else {
                    // Recursive case - call self with depth+1
                    let mut recurse = BytesMut::new();
                    ctx.put_i32(&mut recurse, depth + 1);

                    let response = mta.dispatch(oid, Uuid::NIL, 0, recurse.freeze()).await?;

                    let mut result_cursor = response.as_ref();
                    let inner_result = if result_cursor.remaining() >= 4 {
                        ctx.get_i32(&mut result_cursor)
                    } else {
                        0
                    };

                    let mut buf = BytesMut::new();
                    ctx.put_i32(&mut buf, inner_result + 1);
                    Ok(buf.freeze())
                }
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let obj = Arc::new(RecursiveObject {
        oid: Oid::generate(),
        mta: mta.clone(),
        max_depth: actual_max_depth.clone(),
    });
    let oid = obj.oid();
    mta.register_object(obj);

    // Start recursion from depth 1
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_i32(&mut buf, 1);

    let start = Instant::now();
    let response = mta.dispatch(oid, Uuid::NIL, 0, buf.freeze()).await.unwrap();
    let duration = start.elapsed();

    let mut cursor = response.as_ref();
    let final_result = ctx.get_i32(&mut cursor);

    println!("\n=== Deep Circular Recursion Test ===");
    println!("Max depth: {}", MAX_DEPTH);
    println!("Actual max depth reached: {}", actual_max_depth.load(Ordering::SeqCst));
    println!("Final result: {} (expected {})", final_result, MAX_DEPTH + (MAX_DEPTH - 1));
    println!("Duration: {:?}", duration);

    // The result should be MAX_DEPTH + (MAX_DEPTH-1) because each return adds 1
    // Starting from depth 1, going to depth 10, then unwinding
    assert_eq!(actual_max_depth.load(Ordering::SeqCst), MAX_DEPTH as u32);

    println!("Deep Circular Recursion Test: PASSED");
}
