//! Print Service Client
//!
//! An interactive client that sends strings to the print server using DCE RPC.
//!
//! USAGE:
//!   print-client [OPTIONS] [MESSAGE]
//!
//! EXAMPLES:
//!   print-client                                # Interactive mode (TCP)
//!   print-client "Hello, World!"                # Send single message
//!   print-client -m "msg1" -m "msg2"            # Send multiple messages
//!   print-client --protocol udp "Hello"         # Send via UDP
//!   print-client --host 192.168.1.1 --port 8000 # Connect to custom address

mod common;

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use common::*;
use dcerpc::{DceRpcClient, SyntaxId, UdpDceRpcClient, Uuid};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::time::Duration;
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
#[command(name = "print-client")]
#[command(version)]
#[command(about = "DCE RPC print client - sends strings to the print server")]
#[command(
    long_about = "A demonstration DCE RPC client that sends string messages to the print server.\n\n\
Uses DCE RPC (MS-RPCE) with UUID-based interface identification.\n\n\
If no message is provided, enters interactive mode where you can type messages.\n\n\
INTERACTIVE COMMANDS:\n\
  <message>  Send the message to the server\n\
  ping       Send a null RPC call (health check)\n\
  quit/exit  Disconnect and exit\n\
  Ctrl+D     Disconnect and exit"
)]
struct Args {
    /// Transport protocol (tcp or udp)
    ///
    /// TCP provides reliable delivery with connection tracking.
    /// UDP is connectionless with automatic retransmission support.
    #[arg(short, long, value_enum, default_value = "tcp")]
    protocol: Protocol,

    /// Host address to connect to
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to connect to
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Messages to send (repeatable)
    ///
    /// Use -m multiple times to send several messages in batch mode.
    #[arg(short, long = "message")]
    messages: Vec<String>,

    /// Single message to send (positional argument)
    ///
    /// If provided, sends this message and exits (batch mode).
    /// If not provided, enters interactive mode.
    #[arg(value_name = "MESSAGE")]
    message: Option<String>,

    /// Quiet mode - suppress informational output
    #[arg(short, long)]
    quiet: bool,
}

/// TCP client wrapper for DCE RPC
struct TcpPrintClient {
    client: DceRpcClient,
}

impl TcpPrintClient {
    async fn connect(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        // Create interface syntax ID
        let interface = SyntaxId::new(
            Uuid::parse(PRINT_INTERFACE_UUID).expect("Invalid UUID"),
            PRINT_INTERFACE_VERSION,
            0,
        );
        let client = DceRpcClient::connect(addr, interface).await?;
        Ok(Self { client })
    }

    async fn send_message(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Send raw UTF-8 bytes
        self.client
            .call(OP_PRINT, Bytes::from(message.to_string()))
            .await?;
        Ok(())
    }

    async fn null_call(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.client.null_call().await?;
        Ok(())
    }
}

/// UDP client wrapper for DCE RPC
struct UdpPrintClient {
    client: UdpDceRpcClient,
}

impl UdpPrintClient {
    async fn connect(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        // Create interface UUID and version
        // CL protocol version format: (minor << 16) | major
        let interface_uuid = Uuid::parse(PRINT_INTERFACE_UUID).expect("Invalid UUID");
        let version = PRINT_INTERFACE_VERSION as u32; // Major version in low 16 bits (CL format)
        let mut client = UdpDceRpcClient::connect(addr, interface_uuid, version).await?;
        client.set_timeout(Duration::from_secs(5));
        Ok(Self { client })
    }

    async fn send_message(&mut self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Send raw UTF-8 bytes
        self.client
            .call(OP_PRINT, Bytes::from(message.to_string()))
            .await?;
        Ok(())
    }

    async fn null_call(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.client.null_call().await?;
        Ok(())
    }
}

/// Client abstraction to handle all transport combinations
enum PrintClient {
    Tcp(TcpPrintClient),
    Udp(UdpPrintClient),
}

impl PrintClient {
    async fn send_message(&mut self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            PrintClient::Tcp(c) => c.send_message(message).await,
            PrintClient::Udp(c) => c.send_message(message).await,
        }
    }

    async fn null_call(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            PrintClient::Tcp(c) => c.null_call().await,
            PrintClient::Udp(c) => c.null_call().await,
        }
    }
}

fn get_protocol_display(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "DCE RPC / TCP",
        Protocol::Udp => "DCE RPC / UDP",
    }
}

async fn run_interactive(
    mut client: PrintClient,
    protocol: Protocol,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !quiet {
        let proto_name = get_protocol_display(protocol);
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║             Print Client - Interactive Mode                  ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Protocol: {:50} ║", proto_name);
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Commands:                                                   ║");
        println!("║    <message>   Send message to server                        ║");
        println!("║    ping        Health check (null RPC call)                  ║");
        println!("║    quit/exit   Disconnect                                    ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        // Print prompt
        print!("> ");
        stdout.flush()?;

        // Read line
        let mut line = String::new();
        let bytes_read = stdin.lock().read_line(&mut line)?;

        // Check for EOF (Ctrl+D)
        if bytes_read == 0 {
            println!();
            break;
        }

        let line = line.trim();

        // Check for empty line
        if line.is_empty() {
            continue;
        }

        // Check for quit commands
        if line.eq_ignore_ascii_case("quit") || line.eq_ignore_ascii_case("exit") {
            if !quiet {
                println!("Goodbye!");
            }
            break;
        }

        // Check for ping command
        if line.eq_ignore_ascii_case("ping") {
            match client.null_call().await {
                Ok(()) => println!("Pong! (server is alive)"),
                Err(e) => eprintln!("Ping failed: {}", e),
            }
            continue;
        }

        // Send the message
        match client.send_message(line).await {
            Ok(()) => {
                if !quiet {
                    println!("Sent: {}", line);
                }
            }
            Err(e) => {
                eprintln!("Failed to send: {}", e);
            }
        }
    }

    Ok(())
}

async fn send_messages(
    mut client: PrintClient,
    messages: Vec<String>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for message in messages {
        match client.send_message(&message).await {
            Ok(()) => {
                if !quiet {
                    println!("Sent: {}", message);
                }
            }
            Err(e) => {
                eprintln!("Failed to send '{}': {}", message, e);
                return Err(e);
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize tracing (unless quiet mode)
    if !args.quiet {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::WARN)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    info!("Connecting to {} using {:?}", addr, args.protocol);

    // Connect to server
    let client = match args.protocol {
        Protocol::Tcp => {
            let c = TcpPrintClient::connect(addr).await?;
            PrintClient::Tcp(c)
        }
        Protocol::Udp => {
            let c = UdpPrintClient::connect(addr).await?;
            PrintClient::Udp(c)
        }
    };

    if !args.quiet {
        let proto_name = get_protocol_display(args.protocol);
        println!("Connected to {} via {}", addr, proto_name);
    }

    // Collect all messages
    let mut messages: Vec<String> = args.messages;
    if let Some(msg) = args.message {
        messages.insert(0, msg);
    }

    // If we have messages, send them; otherwise enter interactive mode
    if messages.is_empty() {
        run_interactive(client, args.protocol, args.quiet).await
    } else {
        send_messages(client, messages, args.quiet).await
    }
}
