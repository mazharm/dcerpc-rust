//! DCOM Hello Client
//!
//! This example shows a DCOM-style client using MIDL-generated stubs.
//!
//! Run with: cargo run --bin hello-client -- --host 127.0.0.1 --port 5001

use std::net::SocketAddr;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use dcom_hello::{hresult, IHelloClient};

#[derive(Parser)]
#[command(name = "hello-client")]
#[command(about = "DCOM Hello Client")]
struct Args {
    /// Server host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(short, long, default_value = "5001")]
    port: u16,

    /// Name to greet
    #[arg(short, long, default_value = "World")]
    name: String,
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

    info!("Connecting to DCOM Hello server at {}", addr);

    // Connect to the server using generated client stub
    let client = IHelloClient::connect(addr).await?;

    info!("Connected! Running DCOM operations...");

    // Test SayHello
    let name = midl_ndr::NdrString::from(args.name.clone());
    let (hr, greeting) = client.say_hello(name).await?;
    if hr == hresult::S_OK {
        info!("SayHello result: {}", greeting.as_str());
    } else {
        info!("SayHello failed with HRESULT: 0x{:08x}", hr);
    }

    // Test Echo
    let message = midl_ndr::NdrString::from("This is a test message!");
    let (hr, response) = client.echo(message).await?;
    if hr == hresult::S_OK {
        info!("Echo result: {}", response.as_str());
    } else {
        info!("Echo failed with HRESULT: 0x{:08x}", hr);
    }

    info!("All operations completed successfully!");

    Ok(())
}
