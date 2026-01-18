# dcerpc-rust

A pure Rust implementation of DCE RPC (MS-RPC), DCOM, and MIDL compiler with NDR runtime.

## Overview

This project provides a complete, wire-compatible implementation of DCE RPC as specified in the DCE 1.1 RPC specification and Microsoft's MS-RPCE extensions. It includes:

- **DCE RPC Protocol** - Full client and server support for both connection-oriented (TCP) and connectionless (UDP) protocols
- **DCOM Layer** - Distributed Component Object Model implementation for remote object invocation
- **MIDL Compiler** - Microsoft Interface Definition Language compiler generating Rust code
- **NDR Runtime** - Network Data Representation encoding/decoding library

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                      Applications                             │
└───────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────┐
│                   MIDL Compiler (midl)                        │
│        Parses .idl files → generates Rust client/server       │
└───────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────┐
│                    DCOM Layer (dcom)                          │
│    Apartment Model │ Object Exporter │ OXID/OID/IPID          │
└───────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────┐
│                  DCE RPC Layer (dcerpc)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │ Connection-  │  │ Connectionless│  │  Endpoint Mapper │   │
│  │ Oriented TCP │  │    UDP       │  │    (port 135)    │   │
│  └──────────────┘  └──────────────┘  └───────────────────┘   │
│  ┌──────────────┐  ┌──────────────────────────────────────┐   │
│  │  Security/   │  │          RPC Pipe Support            │   │
│  │    SSPI      │  │    (streaming within RPC calls)     │   │
│  └──────────────┘  └──────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────┐
│                  NDR Runtime (midl-ndr)                       │
│     Wire format encoding/decoding with proper alignment       │
└───────────────────────────────────────────────────────────────┘
```

## Features

### DCE RPC (`dcerpc` crate)
- Connection-oriented protocol over TCP
- Connectionless protocol over UDP
- Endpoint Mapper (EPM) client and server on port 135
- RPC pipe support for streaming data
- Windows named pipe transport
- SSPI authentication (Windows)
- Async/await with Tokio runtime

### DCOM (`dcom` crate)
- Full MS-DCOM specification support
- Apartment threading model (MTA and STA)
- Object exporter with reference counting
- OXID resolver for cross-machine communication
- IRemUnknown for remote reference management
- Object activation via IActivation

### MIDL Compiler (`midl` crate)
- Parses Microsoft IDL files
- Generates type-safe Rust code
- Client and server stub generation
- Automatic NDR encoding/decoding

### NDR Runtime (`midl-ndr` crate)
- Primitive types with proper alignment
- Conformant and varying arrays
- Fixed, unique, and full pointers
- String and wide-string handling
- Struct and union encoding

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Tokio runtime (included as dependency)

### Installation

Add the relevant crates to your `Cargo.toml`:

```toml
[dependencies]
dcerpc = { path = "crates/dcerpc" }
dcom = { path = "crates/dcom" }      # Optional: for DCOM support
midl = { path = "crates/midl" }      # Optional: for IDL compilation
midl-ndr = { path = "crates/midl-ndr" }
```

### Quick Example

#### TCP Server

```rust
use dcerpc::{DceRpcServer, InterfaceBuilder};
use bytes::Bytes;

#[tokio::main]
async fn main() {
    let interface = InterfaceBuilder::new(
        "12345678-1234-1234-1234-123456789012",
        1,
        0,
    )
    .unwrap()
    .operation(0, |_args| async { Ok(Bytes::new()) })
    .operation(1, |args: Bytes| async move { Ok(args) })
    .build();

    let server = DceRpcServer::new();
    server.register_interface(interface).await;
    server.run("127.0.0.1:12345".parse().unwrap()).await.unwrap();
}
```

#### TCP Client

```rust
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use bytes::Bytes;

#[tokio::main]
async fn main() {
    let interface = SyntaxId::new(
        Uuid::parse("12345678-1234-1234-1234-123456789012").unwrap(),
        1,
        0,
    );

    let client = DceRpcClient::connect(
        "127.0.0.1:12345".parse().unwrap(),
        interface,
    ).await.unwrap();

    let result = client.call(1, Bytes::from("hello")).await.unwrap();
    assert_eq!(result.as_ref(), b"hello");
}
```

## Project Structure

```
dcerpc-rust/
├── crates/
│   ├── dcerpc/       # DCE RPC protocol implementation
│   ├── dcom/         # DCOM layer
│   ├── midl/         # MIDL compiler
│   └── midl-ndr/     # NDR runtime library
├── examples/
│   ├── dcerpc-echo-service/   # Simple echo service
│   ├── msrpc-calculator/      # Calculator with MIDL
│   ├── dcom-hello/            # DCOM hello world
│   ├── dcom-service/          # DCOM service example
│   └── print-service/         # Print service example
└── tools/
    └── midlc/        # MIDL compiler CLI
```

## Examples

Run the echo service example:

```bash
# Terminal 1: Start server
cargo run --example dcerpc-echo-service -- server

# Terminal 2: Run client
cargo run --example dcerpc-echo-service -- client
```

Run the calculator example with MIDL-generated stubs:

```bash
# Terminal 1: Start server
cargo run --package msrpc-calculator --bin server

# Terminal 2: Run client
cargo run --package msrpc-calculator --bin client
```

## Documentation

- [DESIGN.md](DESIGN.md) - High-level architecture and design overview
- Individual crate documentation via `cargo doc`

## Specifications

This implementation follows these specifications:

- [DCE 1.1: Remote Procedure Call](https://pubs.opengroup.org/onlinepubs/9629399/) - Open Group Technical Standard
- [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/) - Microsoft RPC Protocol Extensions
- [MS-DCOM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/) - Distributed Component Object Model Protocol
- NDR (Network Data Representation) as defined in DCE RPC specification

## License

MIT License - see [LICENSE](LICENSE) for details.
