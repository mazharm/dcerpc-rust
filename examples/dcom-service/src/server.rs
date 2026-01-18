//! DCOM Calculator Service Server
//!
//! A simple DCOM service that hosts a Calculator COM object.
//!
//! USAGE:
//!   dcom-server [OPTIONS]
//!
//! EXAMPLES:
//!   dcom-server                          # Start with default settings
//!   dcom-server --port 8000              # Custom port
//!   dcom-server --host 0.0.0.0           # Listen on all interfaces

mod common;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::Parser;
use common::*;
use dcerpc::{DceRpcServer, InterfaceBuilder, RpcError};
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "dcom-server")]
#[command(version)]
#[command(about = "DCOM Calculator service server - hosts a Calculator COM object")]
struct Args {
    /// Host address to bind to
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to listen on
    #[arg(long, default_value_t = DEFAULT_RPC_PORT)]
    port: u16,
}

/// Handle Add operation
fn handle_add(a: i32, b: i32) -> i32 {
    let result = a + b;
    println!("[CALC] {} + {} = {}", a, b, result);
    result
}

/// Handle Subtract operation
fn handle_subtract(a: i32, b: i32) -> i32 {
    let result = a - b;
    println!("[CALC] {} - {} = {}", a, b, result);
    result
}

/// Handle Multiply operation
fn handle_multiply(a: i32, b: i32) -> i32 {
    let result = a * b;
    println!("[CALC] {} * {} = {}", a, b, result);
    result
}

/// Handle Divide operation
fn handle_divide(a: i32, b: i32) -> Result<i32, &'static str> {
    if b == 0 {
        println!("[CALC] {} / {} = ERROR (division by zero)", a, b);
        return Err("division by zero");
    }
    let result = a / b;
    println!("[CALC] {} / {} = {}", a, b, result);
    Ok(result)
}

/// Parse two i32 arguments from bytes
fn parse_args(args: Bytes) -> Result<(i32, i32), RpcError> {
    let mut buf = args;
    if buf.remaining() < 8 {
        return Err(RpcError::InvalidPdu);
    }
    let a = buf.get_i32_le();
    let b = buf.get_i32_le();
    Ok((a, b))
}

/// Encode i32 result to bytes
fn encode_result(value: i32) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_i32_le(value);
    buf.freeze()
}

fn create_calculator_interface() -> dcerpc::Interface {
    InterfaceBuilder::new(ICALCULATOR_IID, 1, 0)
        .expect("Invalid UUID")
        .operation(opnum::ADD, |args: Bytes| async move {
            let (a, b) = parse_args(args)?;
            info!("ADD: {} + {}", a, b);
            Ok(encode_result(handle_add(a, b)))
        })
        .operation(opnum::SUBTRACT, |args: Bytes| async move {
            let (a, b) = parse_args(args)?;
            info!("SUBTRACT: {} - {}", a, b);
            Ok(encode_result(handle_subtract(a, b)))
        })
        .operation(opnum::MULTIPLY, |args: Bytes| async move {
            let (a, b) = parse_args(args)?;
            info!("MULTIPLY: {} * {}", a, b);
            Ok(encode_result(handle_multiply(a, b)))
        })
        .operation(opnum::DIVIDE, |args: Bytes| async move {
            let (a, b) = parse_args(args)?;
            info!("DIVIDE: {} / {}", a, b);
            match handle_divide(a, b) {
                Ok(result) => Ok(encode_result(result)),
                Err(_) => Err(RpcError::InvalidPduData("division by zero".to_string())),
            }
        })
        .build()
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

    println!("========================================================");
    println!("         DCOM Calculator Service Server");
    println!("========================================================");
    println!("  Protocol:  DCE RPC / TCP");
    println!("  IID:       {}", ICALCULATOR_IID);
    println!("  Listening: {}", addr);
    println!("========================================================");
    println!("  Operations:");
    println!("    ADD (opnum 3)      - Add two i32 values");
    println!("    SUBTRACT (opnum 4) - Subtract two i32 values");
    println!("    MULTIPLY (opnum 5) - Multiply two i32 values");
    println!("    DIVIDE (opnum 6)   - Divide two i32 values");
    println!("========================================================");
    println!("  Press Ctrl+C to stop");
    println!("========================================================");
    println!();

    let server = DceRpcServer::new();
    server.register_interface(create_calculator_interface()).await;

    info!("Starting Calculator server on {}", addr);
    server.run(addr).await?;

    Ok(())
}
