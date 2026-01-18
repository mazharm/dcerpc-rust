//! Print Service Server
//!
//! A simple DCE RPC service that receives strings and prints them to stdout.
//!
//! USAGE:
//!   print-server [OPTIONS]
//!
//! EXAMPLES:
//!   print-server                          # DCE RPC over TCP (default)
//!   print-server --protocol udp           # DCE RPC over UDP
//!   print-server --protocol pipe          # DCE RPC over named pipes (Windows)
//!   print-server --port 8000              # Custom port
//!   print-server --host 0.0.0.0           # Listen on all interfaces
//!   print-server --pipe mypipe            # Custom pipe name (Windows)

mod common;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use common::*;
use dcerpc::{DceRpcServer, InterfaceBuilder, RpcError, UdpDceRpcServer};
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[cfg(windows)]
use dcerpc::{
    DceRpcNamedPipeServer, NamedPipeServerConfig, NamedPipeTransport, local_pipe_name,
};
#[cfg(windows)]
use tokio::sync::Semaphore;
#[cfg(windows)]
use std::sync::Arc;

/// Transport protocol for RPC communication
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protocol {
    /// TCP - Reliable, connection-oriented (default)
    Tcp,
    /// UDP - Unreliable, connectionless
    Udp,
    /// Pipe - Named pipes (Windows only)
    Pipe,
}

#[derive(Parser, Debug)]
#[command(name = "print-server")]
#[command(version)]
#[command(about = "DCE RPC print service server - receives and prints strings")]
#[command(
    long_about = "A demonstration DCE RPC server that listens for string messages and prints them.\n\n\
Uses DCE RPC (MS-RPCE) with UUID-based interface identification.\n\n\
Run the corresponding print-client to send messages to this server.\n\n\
PROTOCOLS:\n\
  tcp   Connection-oriented RPC over TCP/IP (default)\n\
  udp   Connectionless RPC over UDP/IP\n\
  pipe  Connection-oriented RPC over named pipes (Windows only)"
)]
struct Args {
    /// Transport protocol (tcp, udp, or pipe)
    ///
    /// TCP provides reliable delivery with connection tracking.
    /// UDP is connectionless with automatic retransmission support.
    /// Pipe uses Windows named pipes for local/remote IPC.
    #[arg(short, long, value_enum, default_value = "tcp")]
    protocol: Protocol,

    /// Host address to bind to (TCP/UDP only)
    ///
    /// Use 127.0.0.1 for localhost only, 0.0.0.0 for all interfaces.
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to listen on (TCP/UDP only)
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Named pipe name (pipe protocol only)
    ///
    /// The pipe will be created as \\.\pipe\<name>
    #[arg(long, default_value = DEFAULT_PIPE_NAME)]
    pipe: String,
}

fn create_print_interface() -> dcerpc::Interface {
    InterfaceBuilder::new(PRINT_INTERFACE_UUID, PRINT_INTERFACE_VERSION, 0)
        .expect("Invalid UUID")
        // Operation 0: Null - always succeeds, returns nothing
        .operation(OP_NULL, |_args: Bytes| async {
            info!("OP_NULL called");
            Ok(Bytes::new())
        })
        // Operation 1: Print - receives a string and prints it
        .operation(OP_PRINT, |args: Bytes| async move {
            // Interpret bytes as UTF-8 string
            let message = match String::from_utf8(args.to_vec()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to decode string: {}", e);
                    return Err(RpcError::InvalidPdu);
                }
            };

            // Print the received message
            println!("[RECEIVED] {}", message);
            info!("Printed message: {} bytes", message.len());

            // Return empty success response
            Ok(Bytes::new())
        })
        .build()
}

async fn run_tcp_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           Print Service Server (DCE RPC / TCP)               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Protocol:  DCE RPC (MS-RPCE)                                ║");
    println!("║  Transport: TCP                                              ║");
    println!(
        "║  Interface: {} (v{})  ║",
        PRINT_INTERFACE_UUID, PRINT_INTERFACE_VERSION
    );
    println!("║  Listening: {:47} ║", addr);
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Press Ctrl+C to stop                                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let server = DceRpcServer::new();
    server.register_interface(create_print_interface()).await;

    server.run(addr).await?;
    Ok(())
}

async fn run_udp_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           Print Service Server (DCE RPC / UDP)               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Protocol:  DCE RPC (MS-RPCE)                                ║");
    println!("║  Transport: UDP                                              ║");
    println!(
        "║  Interface: {} (v{})  ║",
        PRINT_INTERFACE_UUID, PRINT_INTERFACE_VERSION
    );
    println!("║  Listening: {:47} ║", addr);
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Press Ctrl+C to stop                                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let server = UdpDceRpcServer::new();
    server.register_interface(create_print_interface()).await;

    server.run(addr).await?;
    Ok(())
}

#[cfg(windows)]
async fn run_pipe_server(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use dcerpc::dcerpc::{
        BindAckPdu, ContextResult, Pdu, SyntaxId, Uuid, NDR_SYNTAX_UUID, NDR_SYNTAX_VERSION,
    };

    let full_pipe_name = local_pipe_name(pipe_name);

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        Print Service Server (DCE RPC / Named Pipe)           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Protocol:  DCE RPC (MS-RPCE)                                ║");
    println!("║  Transport: Named Pipe                                       ║");
    println!(
        "║  Interface: {} (v{})  ║",
        PRINT_INTERFACE_UUID, PRINT_INTERFACE_VERSION
    );
    println!("║  Pipe:      {:47} ║", full_pipe_name);
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Press Ctrl+C to stop                                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let config = NamedPipeServerConfig::new(&full_pipe_name);
    let pipe_server = DceRpcNamedPipeServer::new(config);

    // Create interface for request handling
    let _interface = create_print_interface();
    let interface_uuid = Uuid::parse(PRINT_INTERFACE_UUID).unwrap();

    let ndr_syntax = SyntaxId::new(
        Uuid::parse(NDR_SYNTAX_UUID).unwrap(),
        NDR_SYNTAX_VERSION as u16,
        0,
    );

    // Semaphore for connection limiting
    let semaphore = Arc::new(Semaphore::new(100));

    // Create first pipe instance
    let mut is_first = true;

    loop {
        // Create pipe instance
        let pipe = if is_first {
            is_first = false;
            pipe_server.create_first_pipe_instance()?
        } else {
            pipe_server.create_pipe_instance()?
        };

        info!("Waiting for client connection on {}", full_pipe_name);

        // Wait for client to connect
        pipe.connect().await?;
        info!("Client connected");

        let permit = semaphore.clone().try_acquire_owned();
        if permit.is_err() {
            tracing::warn!("Connection limit reached");
            continue;
        }
        let _permit = permit.unwrap();

        let interface_uuid = interface_uuid;
        let ndr_syntax = ndr_syntax;

        // Handle connection in a separate task
        tokio::spawn(async move {
            let mut transport = NamedPipeTransport::new(pipe);
            let mut bound_context: Option<u16> = None;

            loop {
                // Read PDU
                let pdu = match transport.read_pdu_decoded().await {
                    Ok(pdu) => pdu,
                    Err(e) => {
                        if !matches!(e, RpcError::ConnectionClosed) {
                            tracing::error!("Error reading PDU: {}", e);
                        }
                        break;
                    }
                };

                match pdu {
                    Pdu::Bind(bind) => {
                        info!("Received bind request");

                        // Check for our interface
                        let mut results = Vec::new();
                        for context in &bind.context_list {
                            if context.abstract_syntax.uuid == interface_uuid {
                                bound_context = Some(context.context_id);
                                results.push((ContextResult::Acceptance, ndr_syntax));
                            } else {
                                results.push((
                                    ContextResult::ProviderRejection,
                                    SyntaxId::new(Uuid::NIL, 0, 0),
                                ));
                            }
                        }

                        let mut ack = BindAckPdu::new(bind.header.call_id, 1, ndr_syntax);
                        ack.results = results;
                        let response = ack.encode();

                        if let Err(e) = transport.write_pdu(&response).await {
                            tracing::error!("Error sending bind ack: {}", e);
                            break;
                        }
                    }

                    Pdu::Request(request) => {
                        info!("Received request: opnum={}", request.opnum);

                        let result = match request.opnum {
                            OP_NULL => {
                                info!("OP_NULL called");
                                Ok(Bytes::new())
                            }
                            OP_PRINT => {
                                match String::from_utf8(request.stub_data.to_vec()) {
                                    Ok(s) => {
                                        println!("[RECEIVED] {}", s);
                                        info!("Printed message: {} bytes", s.len());
                                        Ok(Bytes::new())
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to decode string: {}", e);
                                        Err(RpcError::InvalidPdu)
                                    }
                                }
                            }
                            _ => {
                                tracing::warn!("Unknown opnum: {}", request.opnum);
                                Err(RpcError::OperationUnavailable(request.opnum))
                            }
                        };

                        let response = match result {
                            Ok(data) => {
                                let mut resp =
                                    dcerpc::dcerpc::ResponsePdu::new(request.header.call_id, data);
                                resp.context_id = bound_context.unwrap_or(0);
                                Pdu::Response(resp)
                            }
                            Err(_) => Pdu::Fault(dcerpc::dcerpc::FaultPdu::new(
                                request.header.call_id,
                                dcerpc::dcerpc::FaultStatus::RpcError,
                            )),
                        };

                        if let Err(e) = transport.write_pdu(&response.encode()).await {
                            tracing::error!("Error sending response: {}", e);
                            break;
                        }
                    }

                    _ => {
                        tracing::warn!("Unexpected PDU type");
                    }
                }
            }

            info!("Client disconnected");
        });
    }
}

#[cfg(not(windows))]
async fn run_pipe_server(_pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Error: Named pipe transport is only available on Windows.");
    eprintln!("Please use --protocol tcp or --protocol udp on this platform.");
    std::process::exit(1);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    match args.protocol {
        Protocol::Tcp => {
            let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
            run_tcp_server(addr).await
        }
        Protocol::Udp => {
            let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
            run_udp_server(addr).await
        }
        Protocol::Pipe => run_pipe_server(&args.pipe).await,
    }
}
