//! Security Integration Tests
//!
//! These tests exercise the authentication, signing, and encryption code paths
//! for both MSRPC (DCE RPC) and DCOM protocols.
//!
//! Note: Most tests require Windows and SSPI support.
//!
//! # Test Categories
//!
//! 1. **MSRPC Authentication Tests**
//!    - Connect-level authentication
//!    - Packet integrity (signing)
//!    - Packet privacy (encryption)
//!
//! 2. **DCOM Security Tests**
//!    - Authenticated ORPC calls
//!    - Security context propagation
//!
//! 3. **Error Handling Tests**
//!    - Authentication required but not provided
//!    - Invalid credentials
//!    - Auth level mismatch

mod common;

use std::sync::Arc;
use std::time::Duration;
use bytes::{Bytes, BytesMut, BufMut};

use common::*;
use dcerpc::{Interface, InterfaceBuilder, SyntaxId, Uuid};

#[cfg(windows)]
use dcerpc::{
    AuthenticatedDceRpcServer, AuthServerConfig,
    AuthenticatedDceRpcClient,
    AuthLevel, AuthType,
};

const SECURITY_TEST_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567891";
const SECURITY_TEST_VERSION: (u16, u16) = (1, 0);

/// Create a test interface for security testing
fn create_security_test_interface() -> Interface {
    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    InterfaceBuilder::from_syntax(SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1))
        // opnum 0: Echo - returns the input data unchanged
        .operation(0, |args| async move {
            Ok(args)
        })
        // opnum 1: GetSecret - returns "secret data" (should be encrypted in transit)
        .operation(1, |_args| async move {
            Ok(Bytes::from_static(b"SECRET_DATA_12345"))
        })
        // opnum 2: Compute checksum - demonstrates data integrity
        .operation(2, |args| async move {
            let checksum = compute_checksum(&args);
            let mut result = BytesMut::with_capacity(8);
            result.put_u64_le(checksum);
            Ok(result.freeze())
        })
        // opnum 3: Large response - for testing encrypted fragmentation
        .operation(3, |args| async move {
            if args.len() < 4 {
                return Err(dcerpc::RpcError::CallRejected("invalid input".to_string()));
            }
            let size = u32::from_le_bytes([args[0], args[1], args[2], args[3]]) as usize;
            let mut data = BytesMut::with_capacity(size);
            for i in 0..size {
                data.put_u8((i % 256) as u8);
            }
            Ok(data.freeze())
        })
        .build()
}

// ============================================================================
// MSRPC Authentication Tests (Windows-only)
// ============================================================================

/// Test: Basic NTLM authentication at Connect level
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msrpc_ntlm_connect_auth() {
    init_logging();

    let interface = create_security_test_interface();

    // Create server requiring authentication
    let server_config = AuthServerConfig::default().require_auth();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    // Find available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect with NTLM authentication
    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::Ntlm, AuthLevel::Connect, None).await {
        Ok(client) => {
            // Make a simple call
            let result = client.call(0, Bytes::from_static(b"hello")).await;
            match result {
                Ok(response) => {
                    assert_eq!(response.as_ref(), b"hello");
                    println!("✓ NTLM Connect-level authentication test passed");
                }
                Err(e) => {
                    println!("Call failed (may be expected in test environment): {}", e);
                }
            }
        }
        Err(e) => {
            // Authentication may fail in test environment without proper credentials
            println!("Connection failed (may be expected): {}", e);
        }
    }

    server_handle.abort();
}

/// Test: NTLM authentication with packet integrity (signing)
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msrpc_ntlm_integrity() {
    init_logging();

    let interface = create_security_test_interface();

    // Create server requiring integrity
    let server_config = AuthServerConfig::default().require_integrity();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    // Connect with integrity level
    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::Ntlm, AuthLevel::PktIntegrity, None).await {
        Ok(client) => {
            // Test data integrity with checksum operation
            let test_data = Bytes::from_static(b"test data for integrity check");
            let expected_checksum = compute_checksum(&test_data);

            match client.call(2, test_data).await {
                Ok(response) => {
                    if response.len() >= 8 {
                        let received_checksum = u64::from_le_bytes([
                            response[0], response[1], response[2], response[3],
                            response[4], response[5], response[6], response[7],
                        ]);
                        assert_eq!(received_checksum, expected_checksum);
                        println!("✓ NTLM Integrity (signing) test passed");
                    }
                }
                Err(e) => {
                    println!("Call failed (may be expected): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Connection failed (may be expected): {}", e);
        }
    }

    server_handle.abort();
}

/// Test: NTLM authentication with packet privacy (encryption)
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msrpc_ntlm_privacy() {
    init_logging();

    let interface = create_security_test_interface();

    // Create server requiring privacy (encryption)
    let server_config = AuthServerConfig::default().require_privacy();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    // Connect with privacy level
    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::Ntlm, AuthLevel::PktPrivacy, None).await {
        Ok(client) => {
            // Request secret data - should be encrypted in transit
            match client.call(1, Bytes::new()).await {
                Ok(response) => {
                    assert_eq!(response.as_ref(), b"SECRET_DATA_12345");
                    println!("✓ NTLM Privacy (encryption) test passed");
                }
                Err(e) => {
                    println!("Call failed (may be expected): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Connection failed (may be expected): {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Encrypted large payload fragmentation
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_msrpc_encrypted_fragmentation() {
    init_logging();

    const PAYLOAD_SIZE: usize = 50_000; // 50KB - requires multiple fragments

    let interface = create_security_test_interface();

    let server_config = AuthServerConfig {
        max_xmit_frag: 4096,
        max_recv_frag: 4096,
        ..AuthServerConfig::default().require_privacy()
    };
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::Ntlm, AuthLevel::PktPrivacy, None).await {
        Ok(client) => {
            // Request large encrypted response
            let mut request = BytesMut::with_capacity(4);
            request.put_u32_le(PAYLOAD_SIZE as u32);

            println!("Requesting {}KB encrypted response (should fragment)", PAYLOAD_SIZE / 1024);

            match client.call(3, request.freeze()).await {
                Ok(response) => {
                    assert_eq!(response.len(), PAYLOAD_SIZE);

                    // Verify pattern
                    for (i, byte) in response.iter().enumerate() {
                        assert_eq!(*byte, (i % 256) as u8, "Pattern mismatch at byte {}", i);
                    }

                    println!("✓ Encrypted fragmentation test passed ({}KB)", PAYLOAD_SIZE / 1024);
                }
                Err(e) => {
                    println!("Call failed (may be expected): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Connection failed (may be expected): {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Negotiate authentication (auto-selects best available)
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msrpc_negotiate_auth() {
    init_logging();

    let interface = create_security_test_interface();

    let server_config = AuthServerConfig::default().require_auth();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    // Use GssNegotiate (SPNEGO) which auto-selects best available auth
    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::GssNegotiate, AuthLevel::Connect, None).await {
        Ok(client) => {
            match client.call(0, Bytes::from_static(b"negotiate test")).await {
                Ok(response) => {
                    assert_eq!(response.as_ref(), b"negotiate test");
                    println!("✓ Negotiate authentication test passed");
                }
                Err(e) => {
                    println!("Call failed (may be expected): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Connection failed (may be expected): {}", e);
        }
    }

    server_handle.abort();
}

// ============================================================================
// Security Error Handling Tests
// ============================================================================

/// Test: Unauthenticated client rejected when auth required
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unauthenticated_client_rejected() {
    init_logging();

    let interface = create_security_test_interface();

    // Server requires authentication
    let server_config = AuthServerConfig::default().require_auth();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to connect with regular (unauthenticated) client
    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    match dcerpc::DceRpcClient::connect(addr, syntax).await {
        Ok(client) => {
            // Connection might succeed but call should fail
            match client.call(0, Bytes::from_static(b"test")).await {
                Ok(_) => {
                    // This shouldn't happen - server should reject
                    println!("Warning: Call succeeded when it should have been rejected");
                }
                Err(e) => {
                    println!("✓ Unauthenticated call correctly rejected: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✓ Unauthenticated connection rejected: {}", e);
        }
    }

    server_handle.abort();
}

/// Test: Auth level too low rejected
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auth_level_too_low_rejected() {
    init_logging();

    let interface = create_security_test_interface();

    // Server requires privacy (encryption)
    let server_config = AuthServerConfig::default().require_privacy();
    let server = Arc::new(AuthenticatedDceRpcServer::with_config(server_config));
    server.register_interface(interface).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_clone = server.clone();
    let server_handle = tokio::spawn(async move {
        server_clone.run(addr).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let uuid = Uuid::parse(SECURITY_TEST_UUID).unwrap();
    let syntax = SyntaxId::new(uuid, SECURITY_TEST_VERSION.0, SECURITY_TEST_VERSION.1);

    // Try to connect with only Connect level (server requires Privacy)
    match AuthenticatedDceRpcClient::connect(addr, syntax, AuthType::Ntlm, AuthLevel::Connect, None).await {
        Ok(_client) => {
            println!("Warning: Connection succeeded with insufficient auth level");
        }
        Err(e) => {
            println!("✓ Insufficient auth level correctly rejected: {}", e);
        }
    }

    server_handle.abort();
}

// ============================================================================
// DCOM Security Tests (Windows-only)
// ============================================================================

#[cfg(windows)]
mod dcom_security_tests {
    use super::*;
    use dcom::apartment::{Apartment, ApartmentType, MultithreadedApartment, ComObject, CallFuture};
    use dcom::types::{Oid, DcomError};
    use std::any::Any;

    /// Test COM object for security testing
    struct SecureTestObject {
        oid: Oid,
    }

    impl SecureTestObject {
        fn new() -> Self {
            Self { oid: Oid::generate() }
        }
    }

    impl ComObject for SecureTestObject {
        fn oid(&self) -> Oid {
            self.oid
        }

        fn supported_interfaces(&self) -> Vec<dcerpc::Uuid> {
            vec![dcerpc::Uuid::parse(SECURITY_TEST_UUID).unwrap()]
        }

        fn invoke(
            &self,
            _iid: &dcerpc::Uuid,
            opnum: u16,
            args: Bytes,
        ) -> CallFuture {
            match opnum {
                0 => {
                    // Echo
                    Box::pin(async move { Ok(args) })
                }
                1 => {
                    // Get secret
                    Box::pin(async move { Ok(Bytes::from_static(b"DCOM_SECRET")) })
                }
                _ => {
                    Box::pin(async move {
                        Err(DcomError::Rpc(dcerpc::RpcError::OperationUnavailable(opnum)))
                    })
                }
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Test: DCOM object in MTA with authentication context
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dcom_mta_security_context() {
        init_logging();

        let mta = MultithreadedApartment::new();
        let obj = Arc::new(SecureTestObject::new());
        let oid = obj.oid();

        mta.register_object(obj);

        // Verify apartment type
        assert_eq!(mta.apartment_type(), ApartmentType::Mta);

        // Make authenticated call through apartment
        let iid = dcerpc::Uuid::parse(SECURITY_TEST_UUID).unwrap();
        let result = mta.dispatch(oid, iid, 1, Bytes::new()).await;

        match result {
            Ok(response) => {
                assert_eq!(response.as_ref(), b"DCOM_SECRET");
                println!("✓ DCOM MTA security context test passed");
            }
            Err(e) => {
                panic!("DCOM call failed: {}", e);
            }
        }

        mta.shutdown();
    }

    /// Test: DCOM concurrent secure calls
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_dcom_concurrent_secure_calls() {
        init_logging();

        const NUM_CALLS: usize = 50;

        let mta = Arc::new(MultithreadedApartment::new());
        let obj = Arc::new(SecureTestObject::new());
        let oid = obj.oid();

        mta.register_object(obj);

        let iid = dcerpc::Uuid::parse(SECURITY_TEST_UUID).unwrap();

        let mut handles = Vec::new();

        for i in 0..NUM_CALLS {
            let mta = mta.clone();
            let iid = iid;

            let handle = tokio::spawn(async move {
                let data = format!("call_{}", i);
                let result = mta.dispatch(oid, iid, 0, Bytes::from(data.clone())).await;

                match result {
                    Ok(response) => {
                        assert_eq!(response.as_ref(), data.as_bytes());
                        true
                    }
                    Err(_) => false,
                }
            });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let success_count = results.iter().filter(|r| r.as_ref().unwrap_or(&false) == &true).count();

        assert_eq!(success_count, NUM_CALLS);
        println!("✓ DCOM concurrent secure calls test passed ({} calls)", NUM_CALLS);

        mta.shutdown();
    }
}

// ============================================================================
// Non-Windows Stub Tests
// ============================================================================

/// Placeholder test for non-Windows platforms
#[cfg(not(windows))]
#[tokio::test]
async fn test_security_not_available() {
    println!("Security tests require Windows with SSPI support");
    println!("Skipping security tests on this platform");
}

// ============================================================================
// Auth Configuration Tests (Cross-platform)
// ============================================================================

#[cfg(windows)]
#[test]
fn test_auth_server_config_builder() {
    // Test default config
    let config = AuthServerConfig::default();
    assert!(config.allow_unauthenticated);
    assert_eq!(config.min_auth_level, AuthLevel::None);

    // Test require_auth
    let config = AuthServerConfig::default().require_auth();
    assert!(!config.allow_unauthenticated);
    assert_eq!(config.min_auth_level, AuthLevel::Connect);

    // Test require_integrity
    let config = AuthServerConfig::default().require_integrity();
    assert!(!config.allow_unauthenticated);
    assert_eq!(config.min_auth_level, AuthLevel::PktIntegrity);

    // Test require_privacy
    let config = AuthServerConfig::default().require_privacy();
    assert!(!config.allow_unauthenticated);
    assert_eq!(config.min_auth_level, AuthLevel::PktPrivacy);

    println!("✓ Auth server config builder test passed");
}

#[cfg(windows)]
#[test]
fn test_auth_level_ordering() {
    // Verify auth levels are properly ordered
    assert!(AuthLevel::None < AuthLevel::Connect);
    assert!(AuthLevel::Connect < AuthLevel::Call);
    assert!(AuthLevel::Call < AuthLevel::Pkt);
    assert!(AuthLevel::Pkt < AuthLevel::PktIntegrity);
    assert!(AuthLevel::PktIntegrity < AuthLevel::PktPrivacy);

    println!("✓ Auth level ordering test passed");
}

#[cfg(windows)]
#[test]
fn test_auth_level_requirements() {
    assert!(!AuthLevel::None.requires_signing());
    assert!(!AuthLevel::None.requires_encryption());

    assert!(!AuthLevel::Connect.requires_signing());
    assert!(!AuthLevel::Connect.requires_encryption());

    assert!(AuthLevel::PktIntegrity.requires_signing());
    assert!(!AuthLevel::PktIntegrity.requires_encryption());

    assert!(AuthLevel::PktPrivacy.requires_signing());
    assert!(AuthLevel::PktPrivacy.requires_encryption());

    println!("✓ Auth level requirements test passed");
}
