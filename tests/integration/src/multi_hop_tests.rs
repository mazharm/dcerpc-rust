//! Multi-Hop Tests - Chain of RPC Calls
//!
//! These tests exercise scenarios where:
//! - Service A calls Service B which calls Service C
//! - Requests pass through multiple servers
//! - Data is transformed at each hop
//! - Errors propagate correctly through the chain

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut, Buf, BufMut};
use futures::future::join_all;

use common::*;
use dcerpc::{DceRpcClient, DceRpcServer, Interface, InterfaceBuilder, SyntaxId, Uuid};
use midl_ndr::NdrContext;

/// Frontend service UUID
pub const FRONTEND_UUID: &str = "f1e2d3c4-b5a6-9870-fedc-ba0987654321";
/// Backend service UUID
pub const BACKEND_UUID: &str = "b1a2c3d4-e5f6-0789-abcd-ef1234567890";
/// Database service UUID
pub const DATABASE_UUID: &str = "d1b2a3c4-5e6f-7890-bcde-f12345678901";

/// Service version
pub const SERVICE_VERSION: (u16, u16) = (1, 0);

/// Create a database service (end of chain)
fn create_database_service() -> Interface {
    InterfaceBuilder::new(DATABASE_UUID, SERVICE_VERSION.0, SERVICE_VERSION.1)
        .unwrap()
        // Op 0: Store value (returns success)
        .operation(0, |stub_data| {
            Box::pin(async move {
                // Simulate database write
                tokio::time::sleep(Duration::from_millis(5)).await;

                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let value = if cursor.remaining() >= 4 {
                    ctx.get_i32(&mut cursor)
                } else {
                    0
                };

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, value * 10); // Transform: multiply by 10
                ctx.put_i32(&mut buf, 0); // Success code
                Ok(buf.freeze())
            })
        })
        // Op 1: Read value
        .operation(1, |stub_data| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(3)).await;

                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let key = if cursor.remaining() >= 4 {
                    ctx.get_i32(&mut cursor)
                } else {
                    0
                };

                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, key + 100); // Return key + 100
                ctx.put_i32(&mut buf, 0); // Success
                Ok(buf.freeze())
            })
        })
        .build()
}

/// Create a backend service (middle of chain, calls database)
fn create_backend_service(db_addr: SocketAddr) -> Interface {
    InterfaceBuilder::new(BACKEND_UUID, SERVICE_VERSION.0, SERVICE_VERSION.1)
        .unwrap()
        // Op 0: Process and forward to database
        .operation(0, move |stub_data| {
            let db_addr = db_addr;
            Box::pin(async move {
                // Connect to database
                let db_client = DceRpcClient::connect(
                    db_addr,
                    SyntaxId::new(
                        Uuid::parse(DATABASE_UUID).unwrap(),
                        SERVICE_VERSION.0,
                        SERVICE_VERSION.1,
                    ),
                ).await?;

                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let value = if cursor.remaining() >= 4 {
                    ctx.get_i32(&mut cursor)
                } else {
                    0
                };

                // Transform: add 5
                let mut forward_buf = BytesMut::new();
                ctx.put_i32(&mut forward_buf, value + 5);

                // Forward to database
                let db_response = db_client.call(0, forward_buf.freeze()).await?;

                // Return database response with backend marker
                let mut result = BytesMut::new();
                result.put_slice(&db_response);
                ctx.put_i32(&mut result, 1); // Backend processed marker
                Ok(result.freeze())
            })
        })
        // Op 1: Aggregate query (calls database multiple times)
        .operation(1, move |stub_data| {
            let db_addr = db_addr;
            Box::pin(async move {
                let db_client = DceRpcClient::connect(
                    db_addr,
                    SyntaxId::new(
                        Uuid::parse(DATABASE_UUID).unwrap(),
                        SERVICE_VERSION.0,
                        SERVICE_VERSION.1,
                    ),
                ).await?;

                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let count = if cursor.remaining() >= 4 {
                    ctx.get_u32(&mut cursor).min(10) as usize
                } else {
                    1
                };

                // Call database multiple times
                let mut sum: i32 = 0;
                for i in 0..count {
                    let mut query_buf = BytesMut::new();
                    ctx.put_i32(&mut query_buf, i as i32);
                    let response = db_client.call(1, query_buf.freeze()).await?;

                    let mut resp_cursor = response.as_ref();
                    if resp_cursor.remaining() >= 4 {
                        sum += ctx.get_i32(&mut resp_cursor);
                    }
                }

                let mut result = BytesMut::new();
                ctx.put_i32(&mut result, sum);
                Ok(result.freeze())
            })
        })
        .build()
}

/// Create a frontend service (entry point, calls backend)
fn create_frontend_service(backend_addr: SocketAddr) -> Interface {
    InterfaceBuilder::new(FRONTEND_UUID, SERVICE_VERSION.0, SERVICE_VERSION.1)
        .unwrap()
        // Op 0: User request -> Backend -> Database
        .operation(0, move |stub_data| {
            let backend_addr = backend_addr;
            Box::pin(async move {
                // Connect to backend
                let backend_client = DceRpcClient::connect(
                    backend_addr,
                    SyntaxId::new(
                        Uuid::parse(BACKEND_UUID).unwrap(),
                        SERVICE_VERSION.0,
                        SERVICE_VERSION.1,
                    ),
                ).await?;

                let ctx = NdrContext::default();
                let mut cursor = stub_data.as_ref();
                let user_value = if cursor.remaining() >= 4 {
                    ctx.get_i32(&mut cursor)
                } else {
                    0
                };

                // Transform: multiply by 2
                let mut forward_buf = BytesMut::new();
                ctx.put_i32(&mut forward_buf, user_value * 2);

                // Forward to backend
                let backend_response = backend_client.call(0, forward_buf.freeze()).await?;

                // Return with frontend marker
                let mut result = BytesMut::new();
                result.put_slice(&backend_response);
                ctx.put_i32(&mut result, 2); // Frontend processed marker
                Ok(result.freeze())
            })
        })
        // Op 1: Aggregate through chain
        .operation(1, move |stub_data| {
            let backend_addr = backend_addr;
            Box::pin(async move {
                let backend_client = DceRpcClient::connect(
                    backend_addr,
                    SyntaxId::new(
                        Uuid::parse(BACKEND_UUID).unwrap(),
                        SERVICE_VERSION.0,
                        SERVICE_VERSION.1,
                    ),
                ).await?;

                // Forward directly to backend aggregate
                let response = backend_client.call(1, stub_data).await?;
                Ok(response)
            })
        })
        .build()
}

/// Test: Simple 3-hop chain (Frontend -> Backend -> Database)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_three_hop_chain() {
    init_logging();

    // Start database service
    let db_interface = create_database_service();
    let db_port = next_port();
    let db_addr: SocketAddr = format!("127.0.0.1:{}", db_port).parse().unwrap();
    let db_server = DceRpcServer::new();
    db_server.register_interface(db_interface).await;

    let db_handle = tokio::spawn(async move { db_server.run(db_addr).await });

    // Start backend service
    let backend_interface = create_backend_service(db_addr);
    let backend_port = next_port();
    let backend_addr: SocketAddr = format!("127.0.0.1:{}", backend_port).parse().unwrap();
    let backend_server = DceRpcServer::new();
    backend_server.register_interface(backend_interface).await;

    let backend_handle = tokio::spawn(async move { backend_server.run(backend_addr).await });

    // Start frontend service
    let frontend_interface = create_frontend_service(backend_addr);
    let frontend_port = next_port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{}", frontend_port).parse().unwrap();
    let frontend_server = DceRpcServer::new();
    frontend_server.register_interface(frontend_interface).await;

    let frontend_handle = tokio::spawn(async move { frontend_server.run(frontend_addr).await });

    // Wait for all services to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect client to frontend
    let client = connect_client(frontend_addr, FRONTEND_UUID, SERVICE_VERSION).await.unwrap();

    // Send request through chain
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    let input_value = 7;
    ctx.put_i32(&mut buf, input_value);

    let start = Instant::now();
    let response = client.call(0, buf.freeze()).await.unwrap();
    let duration = start.elapsed();

    // Parse response
    // Chain: 7 -> *2 (frontend) = 14 -> +5 (backend) = 19 -> *10 (database) = 190
    let mut cursor = response.as_ref();
    let db_result = ctx.get_i32(&mut cursor);
    let db_status = ctx.get_i32(&mut cursor);
    let backend_marker = ctx.get_i32(&mut cursor);
    let frontend_marker = ctx.get_i32(&mut cursor);

    println!("\n=== Three-Hop Chain Test ===");
    println!("Input: {}", input_value);
    println!("DB result: {} (expected 190)", db_result);
    println!("DB status: {} (expected 0)", db_status);
    println!("Backend marker: {} (expected 1)", backend_marker);
    println!("Frontend marker: {} (expected 2)", frontend_marker);
    println!("Chain duration: {:?}", duration);

    assert_eq!(db_result, 190, "Transformation chain should produce 190");
    assert_eq!(db_status, 0, "Database should return success");
    assert_eq!(backend_marker, 1, "Backend should mark response");
    assert_eq!(frontend_marker, 2, "Frontend should mark response");

    // Cleanup
    db_handle.abort();
    backend_handle.abort();
    frontend_handle.abort();

    println!("Three-Hop Chain Test: PASSED");
}

/// Test: Aggregate query through chain
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_aggregate_through_chain() {
    init_logging();

    // Start services
    let db_interface = create_database_service();
    let db_port = next_port();
    let db_addr: SocketAddr = format!("127.0.0.1:{}", db_port).parse().unwrap();
    let db_server = DceRpcServer::new();
    db_server.register_interface(db_interface).await;
    let db_handle = tokio::spawn(async move { db_server.run(db_addr).await });

    let backend_interface = create_backend_service(db_addr);
    let backend_port = next_port();
    let backend_addr: SocketAddr = format!("127.0.0.1:{}", backend_port).parse().unwrap();
    let backend_server = DceRpcServer::new();
    backend_server.register_interface(backend_interface).await;
    let backend_handle = tokio::spawn(async move { backend_server.run(backend_addr).await });

    let frontend_interface = create_frontend_service(backend_addr);
    let frontend_port = next_port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{}", frontend_port).parse().unwrap();
    let frontend_server = DceRpcServer::new();
    frontend_server.register_interface(frontend_interface).await;
    let frontend_handle = tokio::spawn(async move { frontend_server.run(frontend_addr).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = connect_client(frontend_addr, FRONTEND_UUID, SERVICE_VERSION).await.unwrap();

    // Request aggregate of 5 items
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_u32(&mut buf, 5);

    let start = Instant::now();
    let response = client.call(1, buf.freeze()).await.unwrap();
    let duration = start.elapsed();

    let mut cursor = response.as_ref();
    let sum = ctx.get_i32(&mut cursor);

    // Database returns key + 100 for each query
    // Sum of (0+100) + (1+100) + (2+100) + (3+100) + (4+100) = 510
    let expected_sum = (0..5).map(|i| i + 100).sum::<i32>();

    println!("\n=== Aggregate Through Chain Test ===");
    println!("Requested items: 5");
    println!("Sum: {} (expected {})", sum, expected_sum);
    println!("Duration: {:?}", duration);

    assert_eq!(sum, expected_sum);

    db_handle.abort();
    backend_handle.abort();
    frontend_handle.abort();

    println!("Aggregate Through Chain Test: PASSED");
}

/// Test: Concurrent multi-hop requests
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_multi_hop() {
    init_logging();

    const NUM_CLIENTS: usize = 20;
    const REQUESTS_PER_CLIENT: usize = 10;

    // Start services
    let db_interface = create_database_service();
    let db_port = next_port();
    let db_addr: SocketAddr = format!("127.0.0.1:{}", db_port).parse().unwrap();
    let db_server = DceRpcServer::new();
    db_server.register_interface(db_interface).await;
    let db_handle = tokio::spawn(async move { db_server.run(db_addr).await });

    let backend_interface = create_backend_service(db_addr);
    let backend_port = next_port();
    let backend_addr: SocketAddr = format!("127.0.0.1:{}", backend_port).parse().unwrap();
    let backend_server = DceRpcServer::new();
    backend_server.register_interface(backend_interface).await;
    let backend_handle = tokio::spawn(async move { backend_server.run(backend_addr).await });

    let frontend_interface = create_frontend_service(backend_addr);
    let frontend_port = next_port();
    let frontend_addr: SocketAddr = format!("127.0.0.1:{}", frontend_port).parse().unwrap();
    let frontend_server = DceRpcServer::new();
    frontend_server.register_interface(frontend_interface).await;
    let frontend_handle = tokio::spawn(async move { frontend_server.run(frontend_addr).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = Arc::new(ConcurrentStats::new());
    let start = Instant::now();

    let mut handles = Vec::new();
    for client_id in 0..NUM_CLIENTS {
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            let client = match connect_client(frontend_addr, FRONTEND_UUID, SERVICE_VERSION).await {
                Ok(c) => c,
                Err(_) => {
                    for _ in 0..REQUESTS_PER_CLIENT {
                        stats.record_failure();
                    }
                    return;
                }
            };

            let ctx = NdrContext::default();

            for i in 0..REQUESTS_PER_CLIENT {
                let mut buf = BytesMut::new();
                let value = (client_id * 100 + i) as i32;
                ctx.put_i32(&mut buf, value);

                let req_start = Instant::now();
                match client.call(0, buf.freeze()).await {
                    Ok(response) => {
                        // Verify the chain processed correctly
                        let expected = (value * 2 + 5) * 10;
                        let mut cursor = response.as_ref();
                        let result = ctx.get_i32(&mut cursor);

                        if result == expected {
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
        });

        handles.push(handle);
    }

    join_all(handles).await;

    let total_duration = start.elapsed();
    let total = (NUM_CLIENTS * REQUESTS_PER_CLIENT) as u64;

    db_handle.abort();
    backend_handle.abort();
    frontend_handle.abort();

    println!("\n=== Concurrent Multi-Hop Test ===");
    println!("Clients: {}", NUM_CLIENTS);
    println!("Requests per client: {}", REQUESTS_PER_CLIENT);
    println!("Total requests: {}", total);
    println!("Successful: {}", stats.success_count());
    println!("Failed: {}", stats.failure_count());
    println!("Total duration: {:?}", total_duration);
    println!("Throughput: {:.2} req/sec", total as f64 / total_duration.as_secs_f64());
    println!("Avg latency: {:?}", stats.avg_latency());

    assert!(stats.success_count() >= total * 90 / 100,
        "Too many failures in multi-hop chain");

    println!("Concurrent Multi-Hop Test: PASSED");
}

/// Test: Chain with MTA apartments
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multi_hop_mta() {
    init_logging();

    use dcom::apartment::{Apartment, MultithreadedApartment, ComObject, CallFuture};
    use dcom::types::Oid;
    use std::any::Any;

    // Create MTA apartments for each tier
    let db_mta = Arc::new(MultithreadedApartment::new());
    let backend_mta = Arc::new(MultithreadedApartment::new());
    let frontend_mta = Arc::new(MultithreadedApartment::new());

    // Database object
    struct DbObject { oid: Oid }
    impl ComObject for DbObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                // Echo with transformation
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let val = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };
                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, val + 1);
                Ok(buf.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let db_obj = Arc::new(DbObject { oid: Oid::generate() });
    let db_oid = db_obj.oid();
    db_mta.register_object(db_obj);

    // Backend object (calls database)
    struct BackendObject {
        oid: Oid,
        db_mta: Arc<MultithreadedApartment>,
        db_oid: Oid,
    }
    impl ComObject for BackendObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            let db_mta = self.db_mta.clone();
            let db_oid = self.db_oid;
            Box::pin(async move {
                // Process and forward to DB
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let val = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                let mut forward = BytesMut::new();
                ctx.put_i32(&mut forward, val + 10);

                let db_response = db_mta.dispatch(db_oid, Uuid::NIL, 0, forward.freeze()).await?;

                // Add backend marker
                let mut result = BytesMut::new();
                result.put_slice(&db_response);
                ctx.put_i32(&mut result, 100);
                Ok(result.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let backend_obj = Arc::new(BackendObject {
        oid: Oid::generate(),
        db_mta: db_mta.clone(),
        db_oid,
    });
    let backend_oid = backend_obj.oid();
    backend_mta.register_object(backend_obj);

    // Frontend object (calls backend)
    struct FrontendObject {
        oid: Oid,
        backend_mta: Arc<MultithreadedApartment>,
        backend_oid: Oid,
    }
    impl ComObject for FrontendObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            let backend_mta = self.backend_mta.clone();
            let backend_oid = self.backend_oid;
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let val = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                let mut forward = BytesMut::new();
                ctx.put_i32(&mut forward, val * 2);

                let backend_response = backend_mta.dispatch(backend_oid, Uuid::NIL, 0, forward.freeze()).await?;

                let mut result = BytesMut::new();
                result.put_slice(&backend_response);
                ctx.put_i32(&mut result, 200);
                Ok(result.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let frontend_obj = Arc::new(FrontendObject {
        oid: Oid::generate(),
        backend_mta: backend_mta.clone(),
        backend_oid,
    });
    let frontend_oid = frontend_obj.oid();
    frontend_mta.register_object(frontend_obj);

    // Test the chain
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_i32(&mut buf, 5); // input = 5

    // Chain: 5 -> *2=10 -> +10=20 -> +1=21
    // Response should be: 21, 100 (backend marker), 200 (frontend marker)
    let response = frontend_mta.dispatch(frontend_oid, Uuid::NIL, 0, buf.freeze()).await.unwrap();

    let mut cursor = response.as_ref();
    let db_result = ctx.get_i32(&mut cursor);
    let backend_marker = ctx.get_i32(&mut cursor);
    let frontend_marker = ctx.get_i32(&mut cursor);

    println!("\n=== Multi-Hop MTA Test ===");
    println!("Input: 5");
    println!("DB result: {} (expected 21)", db_result);
    println!("Backend marker: {} (expected 100)", backend_marker);
    println!("Frontend marker: {} (expected 200)", frontend_marker);

    assert_eq!(db_result, 21);
    assert_eq!(backend_marker, 100);
    assert_eq!(frontend_marker, 200);

    println!("Multi-Hop MTA Test: PASSED");
}

/// Test: Chain with STA apartments
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multi_hop_sta() {
    init_logging();

    use dcom::apartment::{Apartment, SinglethreadedApartment, ComObject, CallFuture};
    use dcom::types::Oid;
    use std::any::Any;

    // Create STA apartments
    let db_sta = Arc::new(SinglethreadedApartment::new());
    let backend_sta = Arc::new(SinglethreadedApartment::new());

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Simple database object
    struct SimpleDbObject { oid: Oid }
    impl ComObject for SimpleDbObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let val = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };
                let mut buf = BytesMut::new();
                ctx.put_i32(&mut buf, val + 1);
                Ok(buf.freeze())
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let db_obj = Arc::new(SimpleDbObject { oid: Oid::generate() });
    let db_oid = db_obj.oid();
    db_sta.register_object(db_obj);

    // Backend that calls database
    struct StaBackendObject {
        oid: Oid,
        db_sta: Arc<SinglethreadedApartment>,
        db_oid: Oid,
    }
    impl ComObject for StaBackendObject {
        fn oid(&self) -> Oid { self.oid }
        fn supported_interfaces(&self) -> Vec<Uuid> { vec![Uuid::NIL] }
        fn invoke(&self, _iid: &Uuid, _opnum: u16, args: Bytes) -> CallFuture {
            let db_sta = self.db_sta.clone();
            let db_oid = self.db_oid;
            Box::pin(async move {
                let ctx = NdrContext::default();
                let mut cursor = args.as_ref();
                let val = if cursor.remaining() >= 4 { ctx.get_i32(&mut cursor) } else { 0 };

                let mut forward = BytesMut::new();
                ctx.put_i32(&mut forward, val + 5);

                let response = db_sta.dispatch(db_oid, Uuid::NIL, 0, forward.freeze()).await?;
                Ok(response)
            })
        }
        fn as_any(&self) -> &dyn Any { self }
    }

    let backend_obj = Arc::new(StaBackendObject {
        oid: Oid::generate(),
        db_sta: db_sta.clone(),
        db_oid,
    });
    let backend_oid = backend_obj.oid();
    backend_sta.register_object(backend_obj);

    // Test
    let ctx = NdrContext::default();
    let mut buf = BytesMut::new();
    ctx.put_i32(&mut buf, 10); // input = 10

    // Chain: 10 -> +5=15 -> +1=16
    let response = backend_sta.dispatch(backend_oid, Uuid::NIL, 0, buf.freeze()).await.unwrap();

    let mut cursor = response.as_ref();
    let result = ctx.get_i32(&mut cursor);

    db_sta.shutdown();
    backend_sta.shutdown();

    println!("\n=== Multi-Hop STA Test ===");
    println!("Input: 10");
    println!("Result: {} (expected 16)", result);

    assert_eq!(result, 16);

    println!("Multi-Hop STA Test: PASSED");
}
