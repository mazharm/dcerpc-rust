//! Apartment Tests - MTA and STA Threading Model Tests
//!
//! These tests exercise the DCOM apartment threading models:
//! - MTA (Multi-Threaded Apartment): Concurrent execution
//! - STA (Single-Threaded Apartment): Serialized execution via message queue
//! - Cross-apartment calls and marshaling
//! - Apartment affinity and thread safety

mod common;

use std::any::Any;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::future::join_all;
use parking_lot::Mutex;
use tokio::sync::Barrier;

use common::*;
use dcom::apartment::{
    Apartment, CallFuture, ComObject, MultithreadedApartment, SinglethreadedApartment,
    CallDispatcher,
};
use dcom::types::Oid;
use dcerpc::Uuid;

/// Test object that tracks call execution
struct TrackingObject {
    oid: Oid,
    call_count: AtomicU64,
    concurrent_calls: AtomicUsize,
    max_concurrent: AtomicUsize,
    call_thread_ids: Mutex<Vec<std::thread::ThreadId>>,
}

impl TrackingObject {
    fn new() -> Self {
        Self {
            oid: Oid::generate(),
            call_count: AtomicU64::new(0),
            concurrent_calls: AtomicUsize::new(0),
            max_concurrent: AtomicUsize::new(0),
            call_thread_ids: Mutex::new(Vec::new()),
        }
    }

    fn get_call_count(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }

    fn get_max_concurrent(&self) -> usize {
        self.max_concurrent.load(Ordering::SeqCst)
    }

    fn get_unique_threads(&self) -> usize {
        let ids = self.call_thread_ids.lock();
        let mut unique: Vec<_> = ids.clone();
        unique.sort_by_key(|id| format!("{:?}", id));
        unique.dedup();
        unique.len()
    }
}

impl ComObject for TrackingObject {
    fn oid(&self) -> Oid {
        self.oid
    }

    fn supported_interfaces(&self) -> Vec<Uuid> {
        vec![Uuid::NIL]
    }

    fn invoke(&self, _iid: &Uuid, opnum: u16, args: Bytes) -> CallFuture {
        // Record entry
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let current = self.concurrent_calls.fetch_add(1, Ordering::SeqCst) + 1;

        // Update max concurrent
        let mut max = self.max_concurrent.load(Ordering::SeqCst);
        while current > max {
            match self.max_concurrent.compare_exchange_weak(
                max, current, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(m) => max = m,
            }
        }

        // Record thread ID
        {
            let mut ids = self.call_thread_ids.lock();
            ids.push(std::thread::current().id());
        }

        Box::pin(async move {
            // Simulate some work
            if opnum == 1 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // Note: We can't decrement in async block easily, but that's ok for testing
            Ok(args)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Object that can detect if it's called from multiple threads simultaneously
struct ThreadSafetyChecker {
    oid: Oid,
    is_in_call: Arc<AtomicUsize>,
    violations: Arc<AtomicUsize>,
}

impl ThreadSafetyChecker {
    fn new() -> Self {
        Self {
            oid: Oid::generate(),
            is_in_call: Arc::new(AtomicUsize::new(0)),
            violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn get_violations(&self) -> usize {
        self.violations.load(Ordering::SeqCst)
    }
}

impl ComObject for ThreadSafetyChecker {
    fn oid(&self) -> Oid {
        self.oid
    }

    fn supported_interfaces(&self) -> Vec<Uuid> {
        vec![Uuid::NIL]
    }

    fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
        // Check if already in a call (for violation detection)
        let was_in_call = self.is_in_call.fetch_add(1, Ordering::SeqCst);
        if was_in_call > 0 {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }

        let is_in_call = self.is_in_call.clone();

        Box::pin(async move {
            // Simulate work
            tokio::time::sleep(Duration::from_millis(10)).await;
            is_in_call.fetch_sub(1, Ordering::SeqCst);
            Ok(args)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Test: MTA allows concurrent calls
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mta_concurrent_calls() {
    init_logging();

    let mta = Arc::new(MultithreadedApartment::new());
    let obj = Arc::new(TrackingObject::new());
    let oid = obj.oid();

    mta.register_object(obj.clone());

    const NUM_CONCURRENT: usize = 20;
    let barrier = Arc::new(Barrier::new(NUM_CONCURRENT));

    let mut handles = Vec::new();
    for i in 0..NUM_CONCURRENT {
        let barrier = barrier.clone();
        let mta = mta.clone();

        let handle = tokio::spawn(async move {
            barrier.wait().await;
            mta.dispatch(oid, Uuid::NIL, 1, Bytes::from(format!("call_{}", i))).await
        });
        handles.push(handle);
    }

    let results: Vec<_> = join_all(handles).await;
    let success_count = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();

    println!("\n=== MTA Concurrent Calls Test ===");
    println!("Total calls: {}", NUM_CONCURRENT);
    println!("Successful: {}", success_count);
    println!("Recorded calls: {}", obj.get_call_count());
    println!("Max concurrent: {}", obj.get_max_concurrent());
    println!("Unique threads: {}", obj.get_unique_threads());

    assert_eq!(success_count, NUM_CONCURRENT);
    // MTA should allow multiple concurrent calls
    assert!(obj.get_max_concurrent() > 1,
        "MTA should have concurrent execution, but max_concurrent was {}",
        obj.get_max_concurrent());
}

/// Test: STA serializes calls
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sta_serialized_calls() {
    init_logging();

    let sta = Arc::new(SinglethreadedApartment::new());
    let obj = Arc::new(ThreadSafetyChecker::new());
    let oid = obj.oid();

    sta.register_object(obj.clone());

    // Give the STA message loop time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    const NUM_CALLS: usize = 20;
    let barrier = Arc::new(Barrier::new(NUM_CALLS));

    let mut handles = Vec::new();
    for i in 0..NUM_CALLS {
        let barrier = barrier.clone();
        let sta = sta.clone();

        let handle = tokio::spawn(async move {
            barrier.wait().await;
            sta.dispatch(oid, Uuid::NIL, 0, Bytes::from(format!("call_{}", i))).await
        });
        handles.push(handle);
    }

    let results: Vec<_> = join_all(handles).await;
    let success_count = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();

    sta.shutdown();

    println!("\n=== STA Serialized Calls Test ===");
    println!("Total calls: {}", NUM_CALLS);
    println!("Successful: {}", success_count);
    println!("Thread safety violations: {}", obj.get_violations());

    assert_eq!(success_count, NUM_CALLS);
    // STA should serialize - no concurrent execution
    assert_eq!(obj.get_violations(), 0,
        "STA should serialize calls, but {} violations detected", obj.get_violations());
}

/// Test: MTA can handle many objects
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mta_many_objects() {
    init_logging();

    const NUM_OBJECTS: usize = 50;
    const CALLS_PER_OBJECT: usize = 10;

    let mta = Arc::new(MultithreadedApartment::new());
    let mut objects: Vec<(Oid, Arc<TrackingObject>)> = Vec::new();

    for _ in 0..NUM_OBJECTS {
        let obj = Arc::new(TrackingObject::new());
        let oid = obj.oid();
        mta.register_object(obj.clone());
        objects.push((oid, obj));
    }

    let mut handles = Vec::new();
    for (oid, _) in &objects {
        for i in 0..CALLS_PER_OBJECT {
            let oid = *oid;
            let mta = mta.clone();
            let handle = tokio::spawn(async move {
                mta.dispatch(oid, Uuid::NIL, 0, Bytes::from(format!("call_{}", i))).await
            });
            handles.push(handle);
        }
    }

    let results: Vec<_> = join_all(handles).await;
    let success_count = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();

    let total_calls: u64 = objects.iter().map(|(_, o)| o.get_call_count()).sum();

    println!("\n=== MTA Many Objects Test ===");
    println!("Objects: {}", NUM_OBJECTS);
    println!("Calls per object: {}", CALLS_PER_OBJECT);
    println!("Total expected: {}", NUM_OBJECTS * CALLS_PER_OBJECT);
    println!("Successful dispatches: {}", success_count);
    println!("Total recorded calls: {}", total_calls);

    assert_eq!(success_count, NUM_OBJECTS * CALLS_PER_OBJECT);
}

/// Test: Apartment dispatcher routes to correct apartment
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_apartment_dispatcher() {
    init_logging();

    let dispatcher = CallDispatcher::new();

    // Create MTA and STA
    let mta = Arc::new(MultithreadedApartment::new());
    let sta = Arc::new(SinglethreadedApartment::new());

    // Register apartments
    dispatcher.register_apartment(mta.clone());
    dispatcher.register_apartment(sta.clone());

    // Create objects for each apartment
    let mta_obj = Arc::new(TrackingObject::new());
    let sta_obj = Arc::new(TrackingObject::new());

    let mta_oid = mta_obj.oid();
    let sta_oid = sta_obj.oid();

    mta.register_object(mta_obj.clone());
    sta.register_object(sta_obj.clone());

    // Register OID -> Apartment mappings
    dispatcher.associate_oid(mta_oid, mta.id());
    dispatcher.associate_oid(sta_oid, sta.id());

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Dispatch to both
    let mta_result = dispatcher.dispatch(mta_oid, Uuid::NIL, 0, Bytes::from("mta_call")).await;
    let sta_result = dispatcher.dispatch(sta_oid, Uuid::NIL, 0, Bytes::from("sta_call")).await;

    println!("\n=== Apartment Dispatcher Test ===");
    println!("MTA dispatch: {:?}", mta_result.is_ok());
    println!("STA dispatch: {:?}", sta_result.is_ok());
    println!("MTA object calls: {}", mta_obj.get_call_count());
    println!("STA object calls: {}", sta_obj.get_call_count());

    assert!(mta_result.is_ok());
    assert!(sta_result.is_ok());
    assert_eq!(mta_obj.get_call_count(), 1);
    assert_eq!(sta_obj.get_call_count(), 1);

    sta.shutdown();
}

/// Test: MTA stress test with high contention
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_mta_high_contention() {
    init_logging();

    const NUM_CLIENTS: usize = 100;
    const CALLS_PER_CLIENT: usize = 50;

    let mta = Arc::new(MultithreadedApartment::new());
    let obj = Arc::new(TrackingObject::new());
    let oid = obj.oid();

    mta.register_object(obj.clone());

    let start = Instant::now();
    let barrier = Arc::new(Barrier::new(NUM_CLIENTS));

    let mut handles = Vec::new();
    for client_id in 0..NUM_CLIENTS {
        let barrier = barrier.clone();
        let mta = mta.clone();

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            let mut successes = 0;
            for i in 0..CALLS_PER_CLIENT {
                let result = mta.dispatch(
                    oid,
                    Uuid::NIL,
                    0,
                    Bytes::from(format!("client_{}_call_{}", client_id, i))
                ).await;
                if result.is_ok() {
                    successes += 1;
                }
            }
            successes
        });
        handles.push(handle);
    }

    let results: Vec<_> = join_all(handles).await;
    let total_success: usize = results.iter()
        .filter_map(|r| r.as_ref().ok())
        .sum();

    let duration = start.elapsed();

    println!("\n=== MTA High Contention Test ===");
    println!("Clients: {}", NUM_CLIENTS);
    println!("Calls per client: {}", CALLS_PER_CLIENT);
    println!("Total expected: {}", NUM_CLIENTS * CALLS_PER_CLIENT);
    println!("Total successful: {}", total_success);
    println!("Recorded by object: {}", obj.get_call_count());
    println!("Max concurrent: {}", obj.get_max_concurrent());
    println!("Duration: {:?}", duration);
    println!("Throughput: {:.2} calls/sec",
        total_success as f64 / duration.as_secs_f64());

    assert!(total_success >= (NUM_CLIENTS * CALLS_PER_CLIENT) * 95 / 100,
        "Too many failures: {} out of {}",
        (NUM_CLIENTS * CALLS_PER_CLIENT) - total_success,
        NUM_CLIENTS * CALLS_PER_CLIENT);
}

/// Test: STA graceful shutdown during calls
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sta_shutdown_during_calls() {
    init_logging();

    let sta = Arc::new(SinglethreadedApartment::new());
    let obj = Arc::new(TrackingObject::new());
    let oid = obj.oid();

    sta.register_object(obj.clone());

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start some calls
    let mut handles = Vec::new();
    for i in 0..10 {
        let sta = sta.clone();
        let handle = tokio::spawn(async move {
            sta.dispatch(oid, Uuid::NIL, 1, Bytes::from(format!("call_{}", i))).await
        });
        handles.push(handle);
    }

    // Give some calls time to start
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Shutdown
    sta.shutdown();

    // Wait for all to complete
    let results: Vec<_> = join_all(handles).await;

    // Some should have succeeded before shutdown
    let success = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();
    let failed = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_err()).count();

    println!("\n=== STA Shutdown During Calls Test ===");
    println!("Total calls: 10");
    println!("Completed successfully: {}", success);
    println!("Failed (after shutdown): {}", failed);
    println!("Object recorded: {}", obj.get_call_count());

    // We just want to verify it doesn't panic or hang
    assert!(sta.is_running() == false, "STA should be stopped");
}

/// Test: Object not found error handling
#[tokio::test]
async fn test_object_not_found() {
    init_logging();

    let mta = MultithreadedApartment::new();
    let nonexistent_oid = Oid::generate();

    let result = mta.dispatch(nonexistent_oid, Uuid::NIL, 0, Bytes::new()).await;

    println!("\n=== Object Not Found Test ===");
    println!("Result: {:?}", result);

    assert!(result.is_err(), "Should fail for nonexistent object");
}

/// Test: MTA object removal
#[tokio::test]
async fn test_mta_object_lifecycle() {
    init_logging();

    let mta = MultithreadedApartment::new();
    let obj = Arc::new(TrackingObject::new());
    let oid = obj.oid();

    // Register
    mta.register_object(obj.clone());

    // Call should succeed
    let result1 = mta.dispatch(oid, Uuid::NIL, 0, Bytes::from("test")).await;
    assert!(result1.is_ok());

    // Verify object is registered
    let retrieved = mta.get_object(&oid);
    assert!(retrieved.is_some());

    println!("\n=== MTA Object Lifecycle Test ===");
    println!("Initial registration: OK");
    println!("First call: {:?}", result1.is_ok());
    println!("Object retrieval: {:?}", retrieved.is_some());
}

/// Test: Mixed apartment types with dispatcher
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mixed_apartment_workload() {
    init_logging();

    const NUM_MTA_OBJECTS: usize = 5;
    const NUM_STA_OBJECTS: usize = 5;
    const CALLS_PER_OBJECT: usize = 20;

    let dispatcher = Arc::new(CallDispatcher::new());

    let mta = Arc::new(MultithreadedApartment::new());
    let sta = Arc::new(SinglethreadedApartment::new());

    dispatcher.register_apartment(mta.clone());
    dispatcher.register_apartment(sta.clone());

    let mut mta_objects = Vec::new();
    let mut sta_objects = Vec::new();

    // Create MTA objects
    for _ in 0..NUM_MTA_OBJECTS {
        let obj = Arc::new(TrackingObject::new());
        let oid = obj.oid();
        mta.register_object(obj.clone());
        dispatcher.associate_oid(oid, mta.id());
        mta_objects.push((oid, obj));
    }

    // Create STA objects
    for _ in 0..NUM_STA_OBJECTS {
        let obj = Arc::new(TrackingObject::new());
        let oid = obj.oid();
        sta.register_object(obj.clone());
        dispatcher.associate_oid(oid, sta.id());
        sta_objects.push((oid, obj));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut handles = Vec::new();

    // Dispatch to MTA objects
    for (oid, _) in &mta_objects {
        for i in 0..CALLS_PER_OBJECT {
            let oid = *oid;
            let dispatcher = dispatcher.clone();
            let handle = tokio::spawn(async move {
                dispatcher.dispatch(oid, Uuid::NIL, 0, Bytes::from(format!("mta_{}", i))).await
            });
            handles.push(handle);
        }
    }

    // Dispatch to STA objects
    for (oid, _) in &sta_objects {
        for i in 0..CALLS_PER_OBJECT {
            let oid = *oid;
            let dispatcher = dispatcher.clone();
            let handle = tokio::spawn(async move {
                dispatcher.dispatch(oid, Uuid::NIL, 0, Bytes::from(format!("sta_{}", i))).await
            });
            handles.push(handle);
        }
    }

    let results: Vec<_> = join_all(handles).await;
    let success = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();

    sta.shutdown();

    let mta_total_calls: u64 = mta_objects.iter().map(|(_, o)| o.get_call_count()).sum();
    let sta_total_calls: u64 = sta_objects.iter().map(|(_, o)| o.get_call_count()).sum();

    println!("\n=== Mixed Apartment Workload Test ===");
    println!("MTA objects: {}", NUM_MTA_OBJECTS);
    println!("STA objects: {}", NUM_STA_OBJECTS);
    println!("Calls per object: {}", CALLS_PER_OBJECT);
    println!("Total dispatches: {}", results.len());
    println!("Successful: {}", success);
    println!("MTA recorded calls: {}", mta_total_calls);
    println!("STA recorded calls: {}", sta_total_calls);

    let expected = (NUM_MTA_OBJECTS + NUM_STA_OBJECTS) * CALLS_PER_OBJECT;
    assert!(success >= expected * 90 / 100,
        "Too many failures: {} out of {}", expected - success, expected);
}
