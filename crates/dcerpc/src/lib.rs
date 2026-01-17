//! DCE RPC (MS-RPC) client and server implementation
//!
//! This crate provides a wire-compatible implementation of DCE RPC
//! as specified in the DCE 1.1 RPC specification and MS-RPCE.
//!
//! # Features
//!
//! - Full DCE RPC protocol support (connection-oriented and connectionless)
//! - TCP and UDP transport
//! - NDR (Network Data Representation) transfer syntax
//! - Endpoint Mapper (EPM) client and server (port 135)
//! - Async server and client using Tokio
//!
//! # Example
//!
//! ## TCP Server
//!
//! ```no_run
//! use dcerpc::{DceRpcServer, InterfaceBuilder};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Define an interface with UUID
//!     let interface = InterfaceBuilder::new(
//!         "12345678-1234-1234-1234-123456789012",
//!         1,
//!         0,
//!     )
//!     .unwrap()
//!     // Operation 0: null procedure
//!     .operation(0, |_args| async { Ok(Bytes::new()) })
//!     // Operation 1: echo
//!     .operation(1, |args: Bytes| async move { Ok(args) })
//!     .build();
//!
//!     let server = DceRpcServer::new();
//!     server.register_interface(interface).await;
//!
//!     // Run server on port 12345
//!     server.run("127.0.0.1:12345".parse().unwrap()).await.unwrap();
//! }
//! ```
//!
//! ## TCP Client
//!
//! ```no_run
//! use dcerpc::{DceRpcClient, SyntaxId, Uuid};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create interface syntax ID
//!     let interface = SyntaxId::new(
//!         Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap(),
//!         1,
//!         0,
//!     );
//!
//!     let client = DceRpcClient::connect(
//!         "127.0.0.1:12345".parse().unwrap(),
//!         interface,
//!     ).await.unwrap();
//!
//!     // Call null procedure
//!     client.null_call().await.unwrap();
//!
//!     // Call operation 1 with arguments
//!     let result = client.call(1, Bytes::from("hello")).await.unwrap();
//!     assert_eq!(result.as_ref(), b"hello");
//! }
//! ```
//!
//! ## UDP Server
//!
//! ```no_run
//! use dcerpc::{UdpDceRpcServer, InterfaceBuilder};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() {
//!     let interface = InterfaceBuilder::new(
//!         "12345678-1234-1234-1234-123456789012",
//!         1,
//!         0,
//!     )
//!     .unwrap()
//!     .operation(0, |_args| async { Ok(Bytes::new()) })
//!     .build();
//!
//!     let server = UdpDceRpcServer::new();
//!     server.register_interface(interface).await;
//!     server.run("127.0.0.1:12345".parse().unwrap()).await.unwrap();
//! }
//! ```
//!
//! ## UDP Client
//!
//! ```no_run
//! use dcerpc::{UdpDceRpcClient, Uuid};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() {
//!     let interface_uuid = Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap();
//!     // CL protocol version format: (minor << 16) | major
//!     let version = 1u32; // Major version 1, minor version 0
//!
//!     let mut client = UdpDceRpcClient::connect(
//!         "127.0.0.1:12345".parse().unwrap(),
//!         interface_uuid,
//!         version,
//!     ).await.unwrap();
//!
//!     // Call with automatic retransmission on timeout
//!     client.null_call().await.unwrap();
//! }
//! ```

pub mod error;
pub mod udp_transport;

// DCE RPC modules (connection-oriented)
pub mod dcerpc;
pub mod dcerpc_client;
pub mod dcerpc_server;
pub mod dcerpc_transport;

// DCE RPC connectionless (datagram) modules
pub mod dcerpc_cl;
pub mod dcerpc_udp_client;
pub mod dcerpc_udp_server;

// Security modules
pub mod security;
#[cfg(windows)]
pub mod sspi;
#[cfg(windows)]
pub mod dcerpc_auth_client;
#[cfg(windows)]
pub mod dcerpc_auth_server;

// DCE RPC Endpoint Mapper modules
pub mod dcerpc_epm;
pub mod dcerpc_epm_client;
pub mod dcerpc_epm_server;

// Re-export error types
pub use error::{Result, RpcError};

// UDP transport exports
pub use udp_transport::{UdpTransport, DEFAULT_MAX_UDP_SIZE, MAX_UDP_PAYLOAD};

// DCE RPC exports
pub use dcerpc::{
    // PDU structures
    AlterContextPdu,
    AlterContextRespPdu,
    Auth3Pdu,
    BindAckPdu,
    BindPdu,
    CharRep,
    ContextElement,
    ContextResult,
    DataRepresentation,
    FaultPdu,
    FaultStatus,
    FloatRep,
    // Data representation
    IntRep,
    PacketFlags,
    PacketType,
    // PDU types
    Pdu,
    PduHeader,
    RequestPdu,
    ResponsePdu,
    SyntaxId,
    // Supporting types
    Uuid,
    // Constants
    DCE_RPC_VERSION,
    DCE_RPC_VERSION_MINOR,
    NDR_SYNTAX_UUID,
    NDR_SYNTAX_VERSION,
};
pub use dcerpc_client::{DceRpcClient, DceRpcClientBuilder};
pub use dcerpc_server::{
    DceRpcServer, DceRpcServerConfig, Interface, InterfaceBuilder, OperationHandler,
};
pub use dcerpc_transport::{DceRpcTransport, DEFAULT_MAX_PDU_SIZE};
pub use dcerpc_udp_client::{
    UdpDceRpcClient, UdpDceRpcClientBuilder, DEFAULT_DCE_UDP_RETRIES, DEFAULT_DCE_UDP_TIMEOUT,
};
pub use dcerpc_udp_server::{UdpDceRpcServer, UdpDceRpcServerConfig};

// DCE RPC Connectionless (Datagram) exports
pub use dcerpc_cl::{
    ClAckPdu, ClFaultPdu, ClFlags1, ClFlags2, ClNocallPdu, ClPacketType, ClPdu, ClPduHeader,
    ClPingPdu, ClRejectPdu, ClRequestPdu, ClResponsePdu, ClWorkingPdu,
    new_activity_id, CL_HEADER_SIZE, DCE_RPC_CL_VERSION,
};

// DCE RPC Endpoint Mapper exports
pub use dcerpc_epm::{
    epm_op,
    protocol_id,
    EpmEntry,
    EpmInquiryType,
    // Enums and status types
    EpmStatus,
    // Data structures
    ProtocolTower,
    TowerFloor,
    EPM_INTERFACE_UUID,
    EPM_INTERFACE_VERSION,
    // Constants and modules
    EPM_PORT,
};
pub use dcerpc_epm_client::{connect_via_epm_tcp, connect_via_epm_udp, EpmClient};
pub use dcerpc_epm_server::{create_epm_interface, EpmRegistry, EpmServer};

// Security exports
pub use security::{
    AuthLevel, AuthType, AuthVerifier, SecurityConfig, SecurityContextState,
    calculate_auth_padding, max_signature_size, max_token_size,
};

// SSPI exports (Windows only)
#[cfg(windows)]
pub use sspi::{SspiContext, SspiError, SspiResult};

// Authenticated client/server exports (Windows only)
#[cfg(windows)]
pub use dcerpc_auth_client::AuthenticatedDceRpcClient;
#[cfg(windows)]
pub use dcerpc_auth_server::{AuthServerConfig, AuthenticatedDceRpcServer};
