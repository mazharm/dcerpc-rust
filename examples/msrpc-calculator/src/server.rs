//! Calculator RPC Server
//!
//! Run with: cargo run --bin calculator-server -- --port 5000

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use dcerpc::RpcError;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use msrpc_calculator::{
    create_i_calculator_interface, ICalculatorServer, ICALCULATOR_UUID, ICALCULATOR_VERSION,
};

/// Calculator server implementation
struct CalculatorImpl;

#[async_trait]
impl ICalculatorServer for CalculatorImpl {
    async fn add(&self, a: i32, b: i32) -> dcerpc::Result<i32> {
        info!("Add({}, {}) = {}", a, b, a + b);
        Ok(a + b)
    }

    async fn subtract(&self, a: i32, b: i32) -> dcerpc::Result<i32> {
        info!("Subtract({}, {}) = {}", a, b, a - b);
        Ok(a - b)
    }

    async fn multiply(&self, a: i32, b: i32) -> dcerpc::Result<i32> {
        info!("Multiply({}, {}) = {}", a, b, a * b);
        Ok(a * b)
    }

    async fn divide(
        &self,
        a: i32,
        b: i32,
    ) -> dcerpc::Result<(i32, midl_ndr::UniquePtr<i32>)> {
        if b == 0 {
            return Err(RpcError::Ndr("Division by zero".into()));
        }
        let quotient = a / b;
        let remainder = a % b;
        info!("Divide({}, {}) = {} remainder {}", a, b, quotient, remainder);
        Ok((quotient, midl_ndr::UniquePtr::new(remainder)))
    }
}

#[derive(Parser)]
#[command(name = "calculator-server")]
#[command(about = "MSRPC Calculator Server")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "5000")]
    port: u16,

    /// Host to bind to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    info!("Starting Calculator RPC Server");
    info!("Interface UUID: {}", ICALCULATOR_UUID);
    info!("Version: {}.{}", ICALCULATOR_VERSION.0, ICALCULATOR_VERSION.1);
    info!("Listening on {}", addr);

    // Create the calculator implementation
    let calc_impl = Arc::new(CalculatorImpl);

    // Create the RPC interface from the implementation
    let interface = create_i_calculator_interface(calc_impl);

    // Create and run the server
    let server = dcerpc::DceRpcServer::new();
    server.register_interface(interface).await;

    info!("Server ready, waiting for connections...");
    server.run(addr).await?;

    Ok(())
}
