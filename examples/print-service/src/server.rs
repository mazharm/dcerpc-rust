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
//!   print-server --port 8000              # Custom port
//!   print-server --host 0.0.0.0           # Listen on all interfaces

mod common;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use common::*;
use dcerpc::{DceRpcServer, InterfaceBuilder, RpcError, UdpDceRpcServer};
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Transport protocol for RPC communication
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Protocol {
    /// TCP - Reliable, connection-oriented (default)
    Tcp,
    /// UDP - Unreliable, connectionless
    Udp,
}

#[derive(Parser, Debug)]
#[command(name = "print-server")]
#[command(version)]
#[command(about = "DCE RPC print service server - receives and prints strings")]
#[command(
    long_about = "A demonstration DCE RPC server that listens for string messages and prints them.\n\n\
Uses DCE RPC (MS-RPCE) with UUID-based interface identification.\n\n\
Run the corresponding print-client to send messages to this server."
)]
struct Args {
    /// Transport protocol (tcp or udp)
    ///
    /// TCP provides reliable delivery with connection tracking.
    /// UDP is connectionless with automatic retransmission support.
    #[arg(short, long, value_enum, default_value = "tcp")]
    protocol: Protocol,

    /// Host address to bind to
    ///
    /// Use 127.0.0.1 for localhost only, 0.0.0.0 for all interfaces.
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to listen on
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    match args.protocol {
        Protocol::Tcp => run_tcp_server(addr).await,
        Protocol::Udp => run_udp_server(addr).await,
    }
}
