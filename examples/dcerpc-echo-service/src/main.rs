//! DCE RPC Echo Service Example
//!
//! This example demonstrates a DCE RPC service using the proper DCE RPC wire format.
//!
//! ```text
//! DCE RPC PDU Header (16 bytes):
//! +--------+--------+--------+--------+
//! |  vers  |vers_min| ptype  | pflags |
//! +--------+--------+--------+--------+
//! |        data representation        |
//! +--------+--------+--------+--------+
//! |   frag_len      |   auth_len      |
//! +--------+--------+--------+--------+
//! |             call_id               |
//! +--------+--------+--------+--------+
//! ```
//!
//! Key features:
//! - Bind/BindAck handshake required before making calls
//! - Uses opnum for operation identification
//! - Interface identified by UUID
//!
//! Usage:
//!   cargo run --example dcerpc-echo-service

use bytes::Bytes;
use dcerpc::{DceRpcClient, DceRpcServer, InterfaceBuilder, SyntaxId, Uuid};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Interface UUID for our echo service
/// (In a real application, this would be a proper UUID)
const ECHO_INTERFACE_UUID: &str = "12345678-1234-5678-1234-567812345678";
const ECHO_INTERFACE_VERSION: u16 = 1;

/// Operation numbers
const OP_NULL: u16 = 0;
const OP_ECHO: u16 = 1;
const OP_REVERSE: u16 = 2;

fn create_interface() -> dcerpc::Interface {
    InterfaceBuilder::new(ECHO_INTERFACE_UUID, ECHO_INTERFACE_VERSION, 0)
        .expect("Invalid UUID")
        // Operation 0: Null - always succeeds, returns nothing
        .operation(OP_NULL, |_args: Bytes| async {
            info!("OP_NULL called");
            Ok(Bytes::new())
        })
        // Operation 1: Echo - returns input unchanged
        .operation(OP_ECHO, |args: Bytes| async move {
            info!("OP_ECHO called with {} bytes", args.len());
            Ok(args)
        })
        // Operation 2: Reverse - returns input bytes reversed
        .operation(OP_REVERSE, |args: Bytes| async move {
            info!("OP_REVERSE called with {} bytes", args.len());
            let mut reversed: Vec<u8> = args.to_vec();
            reversed.reverse();
            Ok(Bytes::from(reversed))
        })
        .build()
}

async fn run_server(addr: SocketAddr, shutdown: tokio::sync::oneshot::Receiver<()>) {
    info!("Starting DCE RPC echo service server on {}", addr);

    let server = DceRpcServer::new();
    server.register_interface(create_interface()).await;

    // Run until shutdown signal
    server
        .run_until(addr, async {
            let _ = shutdown.await;
        })
        .await
        .expect("Server error");

    info!("Server shut down");
}

async fn run_client(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to DCE RPC server at {}", addr);

    // Wait a bit for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create interface syntax ID
    let interface = SyntaxId::new(
        Uuid::parse(ECHO_INTERFACE_UUID).expect("Invalid UUID"),
        ECHO_INTERFACE_VERSION,
        0,
    );

    // Connect and bind to the interface
    let client = DceRpcClient::connect(addr, interface).await?;

    info!("Successfully connected and bound to interface");

    // Test 1: Null call
    info!("Test 1: Calling OP_NULL...");
    client.null_call().await?;
    info!("  OP_NULL succeeded");

    // Test 2: Echo call
    info!("Test 2: Calling OP_ECHO with 'Hello, DCE RPC!'...");
    let result = client.call(OP_ECHO, Bytes::from("Hello, DCE RPC!")).await?;
    assert_eq!(result.as_ref(), b"Hello, DCE RPC!");
    info!("  OP_ECHO returned: {:?}", String::from_utf8_lossy(&result));

    // Test 3: Reverse call
    info!("Test 3: Calling OP_REVERSE with 'hello'...");
    let result = client.call(OP_REVERSE, Bytes::from("hello")).await?;
    assert_eq!(result.as_ref(), b"olleh");
    info!(
        "  OP_REVERSE returned: {:?}",
        String::from_utf8_lossy(&result)
    );

    // Test 4: Echo with binary data
    info!("Test 4: Calling OP_ECHO with binary data...");
    let binary_data: Vec<u8> = (0..=255).collect();
    let result = client
        .call(OP_ECHO, Bytes::from(binary_data.clone()))
        .await?;
    assert_eq!(result.as_ref(), binary_data.as_slice());
    info!("  OP_ECHO successfully echoed 256 bytes of binary data");

    // Test 5: Larger echo (within fragment limits)
    info!("Test 5: Calling OP_ECHO with 4KB data...");
    let large_data = vec![0xABu8; 4 * 1024];
    let result = client
        .call(OP_ECHO, Bytes::from(large_data.clone()))
        .await?;
    assert_eq!(result.len(), large_data.len());
    assert_eq!(result.as_ref(), large_data.as_slice());
    info!("  OP_ECHO successfully echoed 4KB of data");

    info!("All tests passed!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let addr: SocketAddr = "127.0.0.1:12346".parse()?;

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    info!("Running DCE RPC echo service example");
    info!("This uses the proper DCE RPC wire format with bind/bind_ack handshake");

    // Start server in background
    let server_handle = tokio::spawn(run_server(addr, shutdown_rx));

    // Run client tests
    match run_client(addr).await {
        Ok(()) => info!("Client completed successfully"),
        Err(e) => {
            eprintln!("Client error: {}", e);
            let _ = shutdown_tx.send(());
            let _ = server_handle.await;
            return Err(e);
        }
    }

    // Shutdown server
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dcerpc_echo_service() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind to get actual port
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Start server
        let server_handle = tokio::spawn(run_server(actual_addr, shutdown_rx));

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create interface syntax ID
        let interface = SyntaxId::new(
            Uuid::parse(ECHO_INTERFACE_UUID).expect("Invalid UUID"),
            ECHO_INTERFACE_VERSION,
            0,
        );

        // Connect and test
        let client = DceRpcClient::connect(actual_addr, interface)
            .await
            .expect("Failed to connect");

        // Test null call
        client.null_call().await.expect("Null call failed");

        // Test echo
        let result = client
            .call(OP_ECHO, Bytes::from("test"))
            .await
            .expect("Echo call failed");
        assert_eq!(result.as_ref(), b"test");

        // Test reverse
        let result = client
            .call(OP_REVERSE, Bytes::from("abcd"))
            .await
            .expect("Reverse call failed");
        assert_eq!(result.as_ref(), b"dcba");

        // Shutdown
        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }
}
