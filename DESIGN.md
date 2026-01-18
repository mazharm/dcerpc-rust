# Design Overview

This document provides a high-level architectural overview of the three main components in this project: MS-RPC (DCE RPC), DCOM, and MIDL Compiler.

## Table of Contents

1. [MS-RPC (DCE RPC)](#ms-rpc-dce-rpc)
2. [DCOM](#dcom)
3. [MIDL Compiler](#midl-compiler)
4. [NDR Runtime](#ndr-runtime)

---

## MS-RPC (DCE RPC)

The `dcerpc` crate implements the Distributed Computing Environment Remote Procedure Call protocol, compatible with Microsoft's MS-RPCE extensions.

### Protocol Overview

DCE RPC provides two transport modes:

```
┌─────────────────────────────────────────────────────────────────┐
│                      DCE RPC Protocol                            │
├────────────────────────────┬────────────────────────────────────┤
│    Connection-Oriented     │        Connectionless              │
│         (CO/TCP)           │           (CL/UDP)                 │
├────────────────────────────┼────────────────────────────────────┤
│  - Reliable delivery       │  - Best-effort delivery            │
│  - Session binding         │  - Stateless requests              │
│  - Multi-call context      │  - Per-call addressing             │
│  - Fragmentation support   │  - Single-datagram messages        │
└────────────────────────────┴────────────────────────────────────┘
```

### PDU (Protocol Data Unit) Structure

All DCE RPC messages follow a common header format:

```
+--------+--------+--------+--------+
| version|vers_min| ptype  | pflags |
+--------+--------+--------+--------+
|      data representation          |
+--------+--------+--------+--------+
|    frag_len     |    auth_len     |
+--------+--------+--------+--------+
|             call_id               |
+--------+--------+--------+--------+
|           PDU body...             |
```

### Connection-Oriented Protocol Flow

```
    Client                              Server
      │                                   │
      │────── BIND ──────────────────────►│
      │       (interface UUID, version)   │
      │◄───── BIND_ACK ──────────────────│
      │       (context_id, syntax)        │
      │                                   │
      │────── REQUEST ───────────────────►│
      │       (opnum, call_id, data)      │
      │◄───── RESPONSE ──────────────────│
      │       (call_id, result)           │
      │                                   │
      │────── ALTER_CONTEXT ─────────────►│  (optional: add interface)
      │◄───── ALTER_CONTEXT_RESP ────────│
      │                                   │
```

### Key Components

| Module | Purpose |
|--------|---------|
| `dcerpc.rs` | PDU types and wire format encoding/decoding |
| `dcerpc_client.rs` | TCP client with connection management |
| `dcerpc_server.rs` | TCP server with interface registry |
| `dcerpc_transport.rs` | Record-marked stream transport |
| `dcerpc_udp_client.rs` | UDP client with retransmission |
| `dcerpc_udp_server.rs` | UDP server with concurrent request handling |
| `dcerpc_epm.rs` | Endpoint Mapper protocol (port 135) |
| `security.rs` | Authentication framework |
| `sspi.rs` | Windows SSPI integration |

### Server Architecture

The server uses a multi-layer design:

```
┌─────────────────────────────────────────────────────────────────┐
│                       DceRpcServer                               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                Interface Registry                            ││
│  │   HashMap<UUID, Interface>                                   ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              Connection Handler (per connection)             ││
│  │   - Bind context management                                  ││
│  │   - PDU fragmentation/reassembly                            ││
│  │   - Request dispatch to Interface                           ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Transport Layer                           ││
│  │   DceRpcTransport (TCP) / UdpTransport (UDP)                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Interface Registration

Interfaces are defined using a builder pattern:

```rust
let interface = InterfaceBuilder::new(uuid, major, minor)
    .operation(0, |args| async { /* handler */ })
    .operation(1, |args| async { /* handler */ })
    .build();

server.register_interface(interface).await;
```

### Endpoint Mapper

The Endpoint Mapper (EPM) runs on well-known port 135 and provides service discovery:

- **ept_map**: Look up endpoints for a given interface UUID
- **ept_insert**: Register a service endpoint
- **ept_delete**: Remove a service endpoint
- **ept_lookup**: Browse registered services

---

## DCOM

The `dcom` crate implements Microsoft's Distributed Component Object Model on top of DCE RPC.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         DCOM Layer                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐│
│  │   Apartments     │  │  Object Exporter │  │   Marshaling   ││
│  │                  │  │                  │  │                ││
│  │  - MTA (multi-   │  │  - OXID table    │  │  - OBJREF      ││
│  │    threaded)     │  │  - OID table     │  │  - STDOBJREF   ││
│  │  - STA (single-  │  │  - IPID table    │  │  - Interface   ││
│  │    threaded)     │  │  - Ref counting  │  │    pointers    ││
│  └──────────────────┘  └──────────────────┘  └────────────────┘│
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                     Well-Known Interfaces                        │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐│
│  │ IObjectExporter  │  │   IRemUnknown    │  │  IActivation   ││
│  │   (port 135)     │  │  (per exporter)  │  │  (activation)  ││
│  │                  │  │                  │  │                ││
│  │  - ResolveOxid   │  │  - RemQueryIface │  │  - RemoteActiv ││
│  │  - SimplePing    │  │  - RemAddRef     │  │    ation       ││
│  │  - ComplexPing   │  │  - RemRelease    │  │                ││
│  └──────────────────┘  └──────────────────┘  └────────────────┘│
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                       DCE RPC Layer                              │
└─────────────────────────────────────────────────────────────────┘
```

### Key Identifiers

DCOM uses a hierarchy of identifiers to locate objects:

```
OXID (Object Exporter ID)
  │
  ├── OID (Object ID)
  │     │
  │     └── IPID (Interface Pointer ID)
  │           Points to specific interface on object
  │
  └── OID (Object ID)
        │
        └── IPID (Interface Pointer ID)
```

| Identifier | Size | Purpose |
|------------|------|---------|
| OXID | 64 bits | Identifies an object exporter (apartment) |
| OID | 64 bits | Identifies an object within an exporter |
| IPID | 128 bits | Identifies an interface instance |
| SetId | 64 bits | Groups objects for ping-based GC |

### Apartment Threading Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-Threaded Apartment (MTA)                │
│                                                                  │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                        │
│   │Thread 1 │  │Thread 2 │  │Thread N │    Concurrent calls    │
│   └────┬────┘  └────┬────┘  └────┬────┘    Objects must be     │
│        │            │            │          thread-safe         │
│        └────────────┼────────────┘                              │
│                     ▼                                            │
│              ┌───────────┐                                       │
│              │  Objects  │                                       │
│              └───────────┘                                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   Single-Threaded Apartment (STA)                │
│                                                                  │
│   ┌─────────┐      ┌───────────────┐                            │
│   │ Thread  │◄────►│ Message Queue │   Serialized calls         │
│   └────┬────┘      └───────────────┘   Single thread access     │
│        │                                                         │
│        ▼                                                         │
│   ┌───────────┐                                                  │
│   │  Objects  │                                                  │
│   └───────────┘                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Reference Counting and Garbage Collection

DCOM uses distributed reference counting with ping-based keep-alive:

```
  Client                    Server
    │                         │
    │   RemAddRef(IPID)      │
    │────────────────────────►│ refs++
    │                         │
    │   SimplePing(SetId)    │
    │────────────────────────►│ reset GC timer
    │                         │
    │   SimplePing(SetId)    │
    │────────────────────────►│ reset GC timer
    │                         │
    │   RemRelease(IPID)     │
    │────────────────────────►│ refs--
    │                         │
    │   (no pings)           │
    │                         │ GC timer expires
    │                         │ → object collected
```

### OBJREF Marshaling

Interface pointers are marshaled as OBJREF structures:

```
┌────────────────────────────────────────┐
│              OBJREF                     │
├────────────────────────────────────────┤
│  signature: 0x574F454D ("MEOW")        │
│  flags: STANDARD | HANDLER | CUSTOM    │
├────────────────────────────────────────┤
│  IID: Interface identifier             │
├────────────────────────────────────────┤
│  STDOBJREF (if standard):              │
│    - flags                             │
│    - cPublicRefs                       │
│    - OXID                              │
│    - OID                               │
│    - IPID                              │
│  DualStringArray:                      │
│    - Network bindings                  │
│    - Security bindings                 │
└────────────────────────────────────────┘
```

---

## MIDL Compiler

The `midl` crate provides a compiler for Microsoft Interface Definition Language files.

### Compiler Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                     MIDL Compiler Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌───────────┐ │
│   │  Lexer  │───►│ Parser  │───►│ Semantic │───►│  Codegen  │ │
│   │         │    │         │    │ Analysis │    │           │ │
│   └─────────┘    └─────────┘    └──────────┘    └───────────┘ │
│        │              │              │               │         │
│        ▼              ▼              ▼               ▼         │
│    Tokens          AST         AnalyzedFile     Rust Code      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Stage 1: Lexer

Tokenizes IDL source into a stream of tokens:

```
Input: [uuid(12345678-...), version(1.0)] interface IFoo { ... }

Tokens:
  LBRACKET
  IDENT("uuid")
  LPAREN
  UUID("12345678-...")
  RPAREN
  COMMA
  IDENT("version")
  ...
```

### Stage 2: Parser

Constructs an Abstract Syntax Tree:

```
File
├── Attributes
│   ├── uuid("12345678-...")
│   └── version(1, 0)
└── Interface "IFoo"
    ├── Methods
    │   └── Method "Add"
    │       ├── ReturnType: long
    │       └── Parameters
    │           ├── [in] long a
    │           └── [in] long b
    └── Types
        └── (any defined structs, enums, etc.)
```

### Stage 3: Semantic Analysis

Performs type resolution and validation:

- Resolves type references
- Validates attribute combinations
- Computes NDR layout information
- Assigns operation numbers (opnums)
- Checks parameter directions

### Stage 4: Code Generation

Generates Rust code for:

**Type Definitions**
```rust
#[derive(Debug, Clone)]
pub struct MyStruct {
    pub field1: i32,
    pub field2: String,
}

impl NdrEncode for MyStruct { ... }
impl NdrDecode for MyStruct { ... }
```

**Client Stubs**
```rust
pub struct ICalculatorClient {
    client: DceRpcClient,
}

impl ICalculatorClient {
    pub async fn add(&self, a: i32, b: i32) -> Result<i32> {
        // Marshal arguments
        // Call remote procedure
        // Unmarshal result
    }
}
```

**Server Stubs**
```rust
pub trait ICalculatorServer {
    async fn add(&self, a: i32, b: i32) -> Result<i32>;
}

pub fn create_calculator_interface<T: ICalculatorServer>(
    impl_: Arc<T>
) -> Interface {
    // Dispatch table mapping opnums to handlers
}
```

### Supported IDL Features

| Feature | Support |
|---------|---------|
| Basic types (int, long, float, etc.) | Yes |
| Structs | Yes |
| Enums | Yes |
| Unions | Yes |
| Arrays (fixed, conformant, varying) | Yes |
| Pointers (ref, unique, ptr) | Yes |
| Strings (char*, wchar_t*) | Yes |
| Parameter directions ([in], [out], [in,out]) | Yes |
| Interface inheritance | Yes |
| Type definitions (typedef) | Yes |

---

## NDR Runtime

The `midl-ndr` crate provides the runtime library for NDR encoding/decoding.

### NDR Encoding Rules

NDR (Network Data Representation) defines the wire format:

```
┌─────────────────────────────────────────────────────────────────┐
│                     NDR Encoding Rules                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Alignment:                                                      │
│    - Primitives align to their natural size                     │
│    - Structs align to largest member                            │
│    - Position = start of marshaling buffer                      │
│                                                                  │
│  ┌──────────┬───────────┐                                       │
│  │   Type   │ Alignment │                                       │
│  ├──────────┼───────────┤                                       │
│  │  char    │     1     │                                       │
│  │  short   │     2     │                                       │
│  │  long    │     4     │                                       │
│  │  hyper   │     8     │                                       │
│  │  float   │     4     │                                       │
│  │  double  │     8     │                                       │
│  │  pointer │     4     │                                       │
│  └──────────┴───────────┘                                       │
│                                                                  │
│  Byte Order:                                                     │
│    - Indicated in data representation field                     │
│    - Little-endian (0x10) or Big-endian (0x00)                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Conformant Arrays

Arrays with runtime-determined size:

```
Conformant Array Wire Format:
┌─────────────────────────────────────┐
│  max_count (4 bytes, aligned)       │  ← Maximum elements
├─────────────────────────────────────┤
│  element[0]                         │
│  element[1]                         │
│  ...                                │
│  element[max_count-1]               │
└─────────────────────────────────────┘

Varying Array Wire Format:
┌─────────────────────────────────────┐
│  offset (4 bytes)                   │  ← First valid element
├─────────────────────────────────────┤
│  actual_count (4 bytes)             │  ← Number of valid elements
├─────────────────────────────────────┤
│  element[offset]                    │
│  ...                                │
│  element[offset+actual_count-1]     │
└─────────────────────────────────────┘

Conformant Varying Array:
┌─────────────────────────────────────┐
│  max_count                          │
├─────────────────────────────────────┤
│  offset                             │
├─────────────────────────────────────┤
│  actual_count                       │
├─────────────────────────────────────┤
│  elements...                        │
└─────────────────────────────────────┘
```

### Pointer Types

```
┌─────────────────────────────────────────────────────────────────┐
│                      Pointer Types                               │
├───────────────┬─────────────────────────────────────────────────┤
│  [ref]        │  Reference pointer                              │
│               │  - Cannot be null                               │
│               │  - No referent ID on wire                       │
│               │  - Data immediately follows                     │
├───────────────┼─────────────────────────────────────────────────┤
│  [unique]     │  Unique pointer                                 │
│               │  - Can be null                                  │
│               │  - Referent ID: 0 = null, non-zero = valid     │
│               │  - Single reference (no aliasing)              │
├───────────────┼─────────────────────────────────────────────────┤
│  [ptr]        │  Full pointer                                   │
│               │  - Can be null                                  │
│               │  - Supports aliasing                           │
│               │  - Uses referent ID for deduplication          │
└───────────────┴─────────────────────────────────────────────────┘
```

### String Encoding

```
NDR String (char*):
┌─────────────────────────────────────┐
│  max_count (conformant size)        │
├─────────────────────────────────────┤
│  offset (usually 0)                 │
├─────────────────────────────────────┤
│  actual_count (including null)      │
├─────────────────────────────────────┤
│  characters (1 byte each)           │
│  null terminator                    │
└─────────────────────────────────────┘

Wide String (wchar_t*):
┌─────────────────────────────────────┐
│  max_count                          │
├─────────────────────────────────────┤
│  offset                             │
├─────────────────────────────────────┤
│  actual_count                       │
├─────────────────────────────────────┤
│  characters (2 bytes each, LE)      │
│  null terminator (2 bytes)          │
└─────────────────────────────────────┘
```

### Traits

The NDR runtime uses traits for encoding/decoding:

```rust
/// Encode a value to NDR wire format
pub trait NdrEncode {
    fn ndr_encode(&self, ctx: &NdrContext, buf: &mut BytesMut, pos: &mut usize);
}

/// Decode a value from NDR wire format
pub trait NdrDecode: Sized {
    fn ndr_decode(ctx: &NdrContext, buf: &mut Bytes, pos: &mut usize) -> Result<Self>;
}
```

---

## Integration Example

Here's how the components work together:

```
1. Write IDL file:
   ┌─────────────────────────────────────────┐
   │  [uuid(...), version(1.0)]              │
   │  interface ICalculator {                │
   │      long Add([in] long a, [in] long b);│
   │  }                                      │
   └─────────────────────────────────────────┘
                    │
                    ▼
2. MIDL compiler generates Rust code:
   ┌─────────────────────────────────────────┐
   │  // Client stub                         │
   │  impl ICalculatorClient { ... }         │
   │                                         │
   │  // Server trait                        │
   │  trait ICalculatorServer { ... }        │
   │                                         │
   │  // NDR encode/decode                   │
   │  impl NdrEncode for AddArgs { ... }     │
   └─────────────────────────────────────────┘
                    │
                    ▼
3. Application uses generated code:
   ┌─────────────────────────────────────────┐
   │  // Server                              │
   │  struct MyCalculator;                   │
   │  impl ICalculatorServer for MyCalc {    │
   │      async fn add(&self, a, b) -> i32   │
   │  }                                      │
   │                                         │
   │  // Client                              │
   │  let client = ICalculatorClient::new(); │
   │  let result = client.add(1, 2).await;   │
   └─────────────────────────────────────────┘
                    │
                    ▼
4. At runtime (DCE RPC layer):
   ┌─────────────────────────────────────────┐
   │  Client              Server             │
   │    │                   │                │
   │    │─── BIND ─────────►│                │
   │    │◄── BIND_ACK ─────│                │
   │    │                   │                │
   │    │─── REQUEST ──────►│                │
   │    │   [NDR: a=1, b=2] │                │
   │    │◄── RESPONSE ─────│                │
   │    │   [NDR: result=3] │                │
   └─────────────────────────────────────────┘
```
