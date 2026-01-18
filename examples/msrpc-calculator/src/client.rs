//! Calculator RPC Client
//!
//! Run with: cargo run --bin calculator-client -- --host 127.0.0.1 --port 5000

use std::net::SocketAddr;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use msrpc_calculator::ICalculatorClient;

#[derive(Parser)]
#[command(name = "calculator-client")]
#[command(about = "MSRPC Calculator Client")]
struct Args {
    /// Server host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(short, long, default_value = "5000")]
    port: u16,
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

    info!("Connecting to Calculator server at {}", addr);

    // Connect to the server using generated client stub
    let client = ICalculatorClient::connect(addr).await?;

    info!("Connected! Running calculator operations...");

    // Test Add
    let result = client.add(10, 5).await?;
    info!("Add(10, 5) = {}", result);
    assert_eq!(result, 15);

    // Test Subtract
    let result = client.subtract(10, 5).await?;
    info!("Subtract(10, 5) = {}", result);
    assert_eq!(result, 5);

    // Test Multiply
    let result = client.multiply(10, 5).await?;
    info!("Multiply(10, 5) = {}", result);
    assert_eq!(result, 50);

    // Test Divide
    let (quotient, remainder) = client.divide(17, 5).await?;
    info!("Divide(17, 5) = {} remainder {:?}", quotient, remainder);
    assert_eq!(quotient, 3);
    assert_eq!(remainder.as_ref(), Some(&2));

    info!("All tests passed!");

    Ok(())
}
