//! DCOM Hello Server
//!
//! This example shows a DCOM-style server using MIDL-generated stubs.
//!
//! Run with: cargo run --bin hello-server -- --port 5001

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use dcom_hello::{
    create_i_hello_interface, hresult, IHelloServer, IHELLO_UUID, IHELLO_VERSION,
};

/// Hello server implementation
struct HelloImpl;

#[async_trait]
impl IHelloServer for HelloImpl {
    async fn say_hello(
        &self,
        name: midl_ndr::NdrString,
    ) -> dcerpc::Result<(i32, midl_ndr::NdrString)> {
        let name_str = name.as_str();
        info!("SayHello called with name: {}", name_str);

        let greeting = format!("Hello, {}! Welcome to DCOM!", name_str);
        Ok((hresult::S_OK, midl_ndr::NdrString::from(greeting)))
    }

    async fn echo(
        &self,
        message: midl_ndr::NdrString,
    ) -> dcerpc::Result<(i32, midl_ndr::NdrString)> {
        let msg_str = message.as_str();
        info!("Echo called with message: {}", msg_str);

        let response = format!("ECHO: {}", msg_str);
        Ok((hresult::S_OK, midl_ndr::NdrString::from(response)))
    }
}

#[derive(Parser)]
#[command(name = "hello-server")]
#[command(about = "DCOM Hello Server")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "5001")]
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

    info!("Starting DCOM Hello Server");
    info!("Interface UUID: {}", IHELLO_UUID);
    info!("Version: {}.{}", IHELLO_VERSION.0, IHELLO_VERSION.1);
    info!("Listening on {}", addr);

    // Create the implementation
    let hello_impl = Arc::new(HelloImpl);

    // Create the RPC interface from the implementation
    let interface = create_i_hello_interface(hello_impl);

    // Create and run the server
    let server = dcerpc::DceRpcServer::new();
    server.register_interface(interface).await;

    info!("Server ready, waiting for connections...");
    info!("NOTE: This is a DCE RPC server. For full DCOM support,");
    info!("      ORPC headers would need to be handled separately.");

    server.run(addr).await?;

    Ok(())
}
