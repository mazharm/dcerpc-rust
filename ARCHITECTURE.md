# DCE RPC Rust Architecture

This document describes the architecture of the `dcerpc-rust` project, a Rust implementation of the DCE RPC (Distributed Computing Environment Remote Procedure Call) protocol and DCOM (Distributed Component Object Model).

## Table of Contents

1. [Project Structure](#project-structure)
2. [DCE RPC Crate](#dce-rpc-crate)
3. [DCOM Crate](#dcom-crate)
4. [MIDL-NDR Crate](#midl-ndr-crate)
5. [Data Flow](#data-flow)
6. [Authentication Architecture](#authentication-architecture)
7. [Fragmentation Support](#fragmentation-support)
8. [Threading Model](#threading-model)

---

## Project Structure

The project is organized as a Cargo workspace with the following crates:

```
dcerpc-rust/
├── crates/
│   ├── dcerpc/          # Core DCE RPC protocol implementation
│   ├── dcom/            # DCOM layer on top of DCE RPC
│   ├── midl-ndr/        # NDR serialization runtime
│   └── midl/            # MIDL compiler
├── tools/
│   └── midlc/           # MIDL compiler CLI
├── examples/            # Example applications
└── tests/
    └── integration/     # Integration test suite
```

### Crate Dependencies

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│         (examples, integration tests, user code)            │
├─────────────────────────────────────────────────────────────┤
│                       DCOM Crate                            │
│   Apartments, Object Exporter, Activation, IRemUnknown      │
├─────────────────────────────────────────────────────────────┤
│                      DCE RPC Crate                          │
│   PDU encoding, clients, servers, transports, EPM, auth     │
├─────────────────────────────────────────────────────────────┤
│                     MIDL-NDR Crate                          │
│      NDR encoding/decoding, primitives, arrays, strings     │
├─────────────────────────────────────────────────────────────┤
│                    External Dependencies                     │
│           tokio, bytes, uuid, windows (on Windows)          │
└─────────────────────────────────────────────────────────────┘
```

---

## DCE RPC Crate

The `dcerpc` crate implements the DCE RPC protocol as specified in the Open Group's DCE 1.1 specification and Microsoft's MS-RPCE.

### Module Structure

| Module | Purpose |
|--------|---------|
| `dcerpc.rs` | PDU structures and wire format definitions |
| `dcerpc_client.rs` | Connection-oriented (TCP) client |
| `dcerpc_server.rs` | Connection-oriented (TCP) server |
| `dcerpc_cl.rs` | Connectionless (UDP) protocol definitions |
| `dcerpc_udp_client.rs` | Connectionless client |
| `dcerpc_udp_server.rs` | Connectionless server |
| `dcerpc_transport.rs` | Transport abstraction layer |
| `dcerpc_epm.rs` | Endpoint Mapper protocol (port 135) |
| `dcerpc_epm_client.rs` | EPM client for endpoint discovery |
| `dcerpc_epm_server.rs` | EPM server for endpoint registration |
| `fragmentation.rs` | Multi-PDU fragmentation support |
| `dcerpc_pipe.rs` | RPC pipe streaming |
| `security.rs` | Authentication types and levels |
| `sspi.rs` | Windows SSPI integration |
| `dcerpc_auth_client.rs` | Authenticated client (Windows) |
| `dcerpc_auth_server.rs` | Authenticated server (Windows) |
| `named_pipe_transport.rs` | Windows named pipe transport |
| `error.rs` | Error types |

### PDU Structure

All DCE RPC PDUs share a common 16-byte header:

```
┌─────────────────────────────────────────────────────────────┐
│  vers (1)  │ vers_min (1) │  ptype (1)  │  pflags (1)      │
├─────────────────────────────────────────────────────────────┤
│                  data_representation (4)                    │
├─────────────────────────────────────────────────────────────┤
│      frag_length (2)      │       auth_length (2)          │
├─────────────────────────────────────────────────────────────┤
│                      call_id (4)                            │
└─────────────────────────────────────────────────────────────┘
```

PDU types:
- **Bind/BindAck**: Connection establishment and capability negotiation
- **Request/Response**: RPC call and return
- **Fault**: Error response
- **AlterContext/AlterContextResp**: Add interfaces to existing connection
- **Auth3**: Third leg of authentication handshake

### Key Types

```rust
// Client for connection-oriented RPC
pub struct DceRpcClient {
    read_transport: Arc<Mutex<DceRpcTransport<ReadHalf<TcpStream>>>>,
    write_transport: Arc<Mutex<DceRpcTransport<WriteHalf<TcpStream>>>>,
    context_id: u16,
    call_id: AtomicU32,
    max_xmit_frag: u16,
    max_recv_frag: u16,
}

// Server for connection-oriented RPC
pub struct DceRpcServer {
    interfaces: RwLock<HashMap<Uuid, Interface>>,
    max_connections: usize,
    config: DceRpcServerConfig,
    stats: ServerStats,
}

// Interface definition with operation handlers
pub struct Interface {
    syntax: SyntaxId,
    operations: HashMap<u16, Box<dyn OperationHandler>>,
}

// Interface builder for fluent API
pub struct InterfaceBuilder {
    syntax: SyntaxId,
    operations: HashMap<u16, Box<dyn OperationHandler>>,
}
```

### Interface Registration

```rust
// Server-side: Define and register an interface
let interface = InterfaceBuilder::from_syntax(syntax_id)
    .operation(0, |args| async move {
        // Handle opnum 0
        Ok(process_echo(args))
    })
    .operation(1, |args| async move {
        // Handle opnum 1
        Ok(process_add(args))
    })
    .build();

server.register_interface(interface).await;

// Client-side: Connect and call
let client = DceRpcClient::connect(addr, syntax_id).await?;
let result = client.call(0, args).await?;
```

---

## DCOM Crate

The `dcom` crate implements the Distributed Component Object Model protocol on top of DCE RPC, following the MS-DCOM specification.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DCOM Application                         │
├─────────────────────────────────────────────────────────────┤
│  Apartment Runtime    │  Object Exporter  │  Marshaling     │
│  - MTA (concurrent)   │  - OXID/OID/IPID  │  - Proxy/Stub   │
│  - STA (serialized)   │  - Ref counting   │  - OBJREF       │
│  - Call dispatcher    │  - GC (pinging)   │                 │
├─────────────────────────────────────────────────────────────┤
│  IObjectExporter      │  IRemUnknown      │  IActivation    │
│  (port 135)           │  (per exporter)   │  (activation)   │
├─────────────────────────────────────────────────────────────┤
│                  DCE RPC Layer (dcerpc crate)               │
└─────────────────────────────────────────────────────────────┘
```

### Module Structure

| Module | Purpose |
|--------|---------|
| `types/` | Core DCOM types (OXID, OID, IPID, OBJREF, etc.) |
| `apartment/` | Threading model (MTA, STA) |
| `exporter/` | Object lifecycle and reference counting |
| `oxid_resolver/` | OXID resolution protocol (port 135) |
| `remunknown/` | IRemUnknown protocol |
| `activation/` | Object activation protocol |
| `client.rs` | High-level DCOM client |
| `server.rs` | High-level DCOM server |

### Core Identifiers

DCOM uses three key identifiers:

| Identifier | Size | Purpose |
|------------|------|---------|
| **OXID** | 8 bytes | Object Exporter ID - identifies an apartment/process |
| **OID** | 8 bytes | Object ID - identifies an object within an exporter |
| **IPID** | 16 bytes (UUID) | Interface Pointer ID - identifies an interface on an object |

### Apartment Threading Model

DCOM supports two threading models:

**Multi-Threaded Apartment (MTA)**:
- Concurrent call execution via Tokio tasks
- Objects must be thread-safe (`Send + Sync`)
- No serialization of calls

**Single-Threaded Apartment (STA)**:
- Message queue for serialized execution
- Objects don't need synchronization
- One call at a time per apartment

```rust
// MTA example
let mta = MultithreadedApartment::new();
let obj = Arc::new(MyComObject::new());
mta.register_object(obj);

// Concurrent calls are handled by Tokio
let result = mta.dispatch(oid, iid, opnum, args).await?;

// STA example
let sta = SingleThreadedApartment::new();
sta.register_object(obj);
sta.start_message_loop();

// Calls are serialized through the message queue
let result = sta.dispatch(oid, iid, opnum, args).await?;
```

### Object Exporter

The Object Exporter manages COM object lifecycle:

```rust
pub struct ObjectExporter {
    oxid: Oxid,
    oxid_table: Arc<RwLock<OxidTable>>,
    oid_table: Arc<RwLock<OidTable>>,
    ipid_table: Arc<RwLock<IpidTable>>,
    ref_count_manager: Arc<RefCountManager>,
    garbage_collector: Arc<GarbageCollector>,
}
```

### Reference Counting

DCOM uses distributed reference counting via IRemUnknown:

- **RemAddRef**: Increment reference count on remote object
- **RemRelease**: Decrement reference count
- **RemQueryInterface**: Query for additional interfaces

When reference count reaches zero and no pings are received, the garbage collector removes the object.

### Garbage Collection

Ping-based garbage collection:
- Clients must ping every 120 seconds (default)
- After 3 missed periods (360 seconds), objects are collected
- SimplePing: Keep objects alive
- ComplexPing: Manage ping sets

---

## MIDL-NDR Crate

The `midl-ndr` crate provides Network Data Representation (NDR) serialization, the wire format used by DCE RPC.

### Module Structure

| Module | Purpose |
|--------|---------|
| `context.rs` | Encoding context (byte order, alignment) |
| `encode.rs` | `NdrEncode` trait |
| `decode.rs` | `NdrDecode` trait |
| `primitives.rs` | Primitive types (u8, u16, u32, u64, f32, f64, bool) |
| `strings.rs` | String types (NdrString, NdrWString, BString) |
| `arrays.rs` | Array types (Fixed, Conformant, Varying) |
| `pointers.rs` | Pointer types (Ref, Unique, Full) |
| `error.rs` | NDR errors |

### NDR Encoding Traits

```rust
pub trait NdrEncode {
    fn ndr_encode<B: BufMut>(
        &self,
        buf: &mut B,
        ctx: &NdrContext,
        position: &mut usize
    ) -> Result<()>;

    fn ndr_align() -> usize;
    fn ndr_size(&self) -> usize;
}

pub trait NdrDecode: Sized {
    fn ndr_decode<B: Buf>(
        buf: &mut B,
        ctx: &NdrContext,
        position: &mut usize
    ) -> Result<Self>;

    fn ndr_align() -> usize;
}
```

### Wire Format Rules

1. **Alignment**: Primitives align to their natural size (1, 2, 4, or 8 bytes)
2. **Structures**: Align to largest member
3. **Conformant data**: Size information comes first, data at end
4. **Strings**: Conformant varying arrays with null terminator

### String Types

```rust
// ANSI string (char*)
pub struct NdrString(pub String);

// Unicode string (wchar_t*)
pub struct NdrWString(pub String);

// COM BSTR
pub struct BString(pub String);
```

Wire format for strings:
```
max_count: u32      # Maximum elements including null
offset: u32         # Always 0
actual_count: u32   # Actual elements including null
chars[actual_count] # String data
[padding]           # Align to 4 bytes
```

### Array Types

| Type | Description |
|------|-------------|
| `FixedArray<T, N>` | Fixed-size array, size known at compile time |
| `ConformantArray<T>` | Size determined at runtime (max_count) |
| `VaryingArray<T>` | Offset and count determined at runtime |
| `ConformantVaryingArray<T>` | Both size and range variable |

---

## Data Flow

### Client Call Flow (TCP)

```
1. DceRpcClient::connect(addr, interface)
   ├── Establish TCP connection
   ├── Split into reader/writer halves
   └── Initialize with max_xmit_frag=4280

2. Bind handshake
   ├── Send BindPdu with interface UUID
   ├── Receive BindAckPdu
   └── Extract negotiated fragment sizes

3. client.call(opnum, stub_data)
   ├── If stub_data > max_xmit_frag:
   │   └── Fragment into multiple RequestPdus
   ├── Send all fragments
   ├── Receive response fragments
   ├── Reassemble if fragmented
   └── Return stub_data
```

### Server Request Flow (TCP)

```
1. DceRpcServer::run(addr)
   ├── Bind TcpListener
   └── For each connection: spawn handle_connection()

2. handle_connection()
   └── Loop:
       ├── Read PDU
       ├── Match PDU type:
       │   ├── Bind → Send BindAck
       │   ├── Request:
       │   │   ├── Reassemble if fragmented
       │   │   ├── Dispatch to operation handler
       │   │   ├── Fragment response if needed
       │   │   └── Send ResponsePdu(s)
       │   └── Others → Handle accordingly
       └── Until connection closes
```

### DCOM Call Flow

```
Client:
1. Obtain OBJREF (contains OXID, OID, IPID, bindings)
2. ResolveOxid(OXID) → Get RPC bindings from port 135
3. Connect to server using bindings
4. RemQueryInterface(IPID, IID) → Get interface IPID
5. Call operation via RPC

Server:
1. Register object → Generate OID, IPID
2. Handle IRemUnknown calls (QueryInterface, AddRef, Release)
3. Handle IObjectExporter calls (ResolveOxid, Ping)
4. Garbage collect unused objects
```

---

## Authentication Architecture

### Supported Authentication Types

| Type | Value | Description |
|------|-------|-------------|
| None | 0 | No authentication |
| GssNegotiate | 9 | SPNEGO (auto-negotiation) |
| Ntlm | 10 | NT LAN Manager |
| GssKerberos | 16 | Kerberos v5 |

### Authentication Levels

| Level | Value | Description |
|-------|-------|-------------|
| None | 1 | No authentication |
| Connect | 2 | Authenticate at connection |
| Call | 3 | Authenticate each call |
| Pkt | 4 | Authenticate each packet |
| PktIntegrity | 5 | Sign each packet |
| PktPrivacy | 6 | Encrypt each packet |

### Security Flow

```
1. Client initiates bind with auth token
   └── BindPdu contains AuthVerifier with SSPI token

2. Server validates and responds
   └── BindAckPdu contains server's token

3. Client sends Auth3 (if needed)
   └── Auth3Pdu completes handshake

4. Subsequent calls are protected:
   └── PktIntegrity: Signature in AuthVerifier
   └── PktPrivacy: Stub data encrypted
```

### AuthVerifier Structure

```
┌─────────────────────────────────────────────────────────────┐
│  auth_type (1)  │ auth_level (1) │ auth_pad_len (1) │ (1)  │
├─────────────────────────────────────────────────────────────┤
│                   auth_context_id (4)                       │
├─────────────────────────────────────────────────────────────┤
│                   auth_value (variable)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Fragmentation Support

### Problem

PDUs are limited by negotiated `max_xmit_frag` (typically 4280 bytes). Large data must be split across multiple PDUs.

### Fragment Flags

| Flag | Value | Description |
|------|-------|-------------|
| FIRST_FRAG | 0x01 | First fragment in sequence |
| LAST_FRAG | 0x02 | Last fragment in sequence |

Complete (single PDU): `FIRST_FRAG | LAST_FRAG`

### Fragment Size Calculation

```
max_stub_size = max_frag
              - 16 (header)
              - 8 (request body)
              - [16 (object UUID, if present)]
              - [auth overhead, if authenticated]

Default: 4280 - 24 = 4256 bytes per fragment
```

### Multi-Fragment Example

Original: 10,000 bytes of stub data

```
Fragment 1: [FIRST_FRAG] stub_data[0:4256]     (4256 bytes)
Fragment 2: [         ] stub_data[4256:8512]   (4256 bytes)
Fragment 3: [LAST_FRAG] stub_data[8512:10000]  (1488 bytes)

Server assembles: 4256 + 4256 + 1488 = 10000 bytes
```

### Implementation

```rust
// Generator splits large PDUs
pub struct FragmentGenerator;

impl FragmentGenerator {
    pub fn max_stub_size(max_frag: u16, auth_len: u16) -> usize;
    pub fn fragment_request(request: &RequestPdu, max_frag: u16) -> Vec<RequestPdu>;
    pub fn fragment_response(response: &ResponsePdu, max_frag: u16) -> Vec<ResponsePdu>;
}

// Assembler reassembles fragments
pub struct FragmentAssembler {
    call_id: u32,
    stub_data: BytesMut,
    received_first: bool,
    received_last: bool,
}

impl FragmentAssembler {
    pub fn add_fragment(&mut self, header: &PduHeader, stub: &[u8])
        -> Result<Option<Bytes>>;
}
```

---

## Threading Model

### Async Runtime

All I/O is async using Tokio:

```rust
// Server accepts connections concurrently
let listener = TcpListener::bind(addr).await?;
loop {
    let (stream, _) = listener.accept().await?;
    tokio::spawn(handle_connection(stream));
}

// Client operations are async
let result = client.call(opnum, args).await?;
```

### Connection Limiting

Servers use semaphores to limit concurrent connections:

```rust
pub struct DceRpcServerConfig {
    pub max_connections: usize,  // Default: 1000
    pub max_xmit_frag: u16,      // Default: 4280
    pub max_recv_frag: u16,      // Default: 4280
}
```

### DCOM Apartments

```
MTA (Multi-Threaded):
├── tokio::spawn() for each call
├── Concurrent execution
└── Objects must be Send + Sync

STA (Single-Threaded):
├── mpsc channel for message queue
├── Serialized execution
└── Objects can be !Send
```

### Shared State

Thread-safe state using `Arc<RwLock<T>>`:

```rust
// Object tables use parking_lot for performance
pub struct ObjectExporter {
    oxid_table: Arc<RwLock<OxidTable>>,
    oid_table: Arc<RwLock<OidTable>>,
    ipid_table: Arc<RwLock<IpidTable>>,
}

// Atomic counters for IDs
static APARTMENT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static CALL_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
```

---

## Error Handling

### RpcError

```rust
pub enum RpcError {
    Io(std::io::Error),
    VersionMismatch { expected: u8, got: u8 },
    CallRejected(String),
    ConnectionClosed,
    Timeout,
    BindFailed(String),
    Fault(u32),
    InterfaceNotFound(String),
    OperationUnavailable(u16),
    PduTooLarge { size: usize, max: usize },
    FragmentAssemblyError(String),
    AuthenticationError(String),
    // ... more variants
}
```

### DcomError

```rust
pub enum DcomError {
    Rpc(dcerpc::RpcError),
    ObjectNotFound(u64),
    InterfaceNotFound(String),
    OxidNotFound(u64),
    ApartmentError(String),
    ActivationError(String),
    RefCountError(String),
    // ... more variants
}
```

### NdrError

```rust
pub enum NdrError {
    BufferUnderflow { needed: usize, have: usize },
    InvalidString(String),
    ConformanceMismatch { max_count: u32, actual_count: u32 },
    AllocationLimitExceeded { requested: usize, limit: usize },
    IntegerOverflow,
    Utf8Error(std::string::FromUtf8Error),
    Utf16Error(std::char::DecodeUtf16Error),
}
```

---

## Security Considerations

### Input Validation

- NDR arrays limited to 64MB total allocation
- Integer overflow checks in size calculations
- Conformance validation (actual_count <= max_count)

### Authentication

- SSPI integration on Windows for NTLM/Kerberos
- Per-fragment signing and encryption supported
- Configurable minimum auth level on servers

### Resource Limits

- Connection limits via semaphores
- Fragment timeout to prevent memory exhaustion
- Allocation limits in NDR decoding

---

## Testing

### Test Categories

| Test Suite | Purpose |
|------------|---------|
| `stress_tests` | Multi-threading, race conditions |
| `fragmentation_tests` | Large PDU transfers |
| `security_tests` | Authentication, signing, encryption |
| `apartment_tests` | MTA/STA threading models |
| `complex_types_tests` | NDR encoding edge cases |
| `multi_hop_tests` | Chain of RPC calls (A→B→C) |
| `circular_call_tests` | Callback scenarios (A→B→A) |
| `pipe_tests` | RPC pipe streaming |

### Running Tests

```bash
# All tests
cargo test

# Specific test suite
cargo test -p integration-tests --test security_tests

# With logging
RUST_LOG=debug cargo test -p integration-tests
```

---

## References

- [DCE 1.1: Remote Procedure Call](https://pubs.opengroup.org/onlinepubs/9629399/)
- [MS-RPCE: Remote Procedure Call Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)
- [MS-DCOM: Distributed Component Object Model Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/)
- [MS-NRPC: Netlogon Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/)
