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
//!   print-client --protocol pipe "Hello"        # Send via named pipe (Windows)
//!   print-client --host 192.168.1.1 --port 8000 # Connect to custom address
//!   print-client --pipe mypipe "Hello"          # Custom pipe name (Windows)

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

#[cfg(windows)]
use dcerpc::{
    DceRpcNamedPipeClient, NamedPipeTransport, local_pipe_name,
    dcerpc::{BindPdu, ContextResult, Pdu, RequestPdu, SyntaxId as DceSyntaxId, Uuid as DceUuid},
};

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
#[command(name = "print-client")]
#[command(version)]
#[command(about = "DCE RPC print client - sends strings to the print server")]
#[command(
    long_about = "A demonstration DCE RPC client that sends string messages to the print server.\n\n\
Uses DCE RPC (MS-RPCE) with UUID-based interface identification.\n\n\
If no message is provided, enters interactive mode where you can type messages.\n\n\
PROTOCOLS:\n\
  tcp   Connection-oriented RPC over TCP/IP (default)\n\
  udp   Connectionless RPC over UDP/IP\n\
  pipe  Connection-oriented RPC over named pipes (Windows only)\n\n\
INTERACTIVE COMMANDS:\n\
  <message>  Send the message to the server\n\
  ping       Send a null RPC call (health check)\n\
  quit/exit  Disconnect and exit\n\
  Ctrl+D     Disconnect and exit"
)]
struct Args {
    /// Transport protocol (tcp, udp, or pipe)
    ///
    /// TCP provides reliable delivery with connection tracking.
    /// UDP is connectionless with automatic retransmission support.
    /// Pipe uses Windows named pipes for local/remote IPC.
    #[arg(short, long, value_enum, default_value = "tcp")]
    protocol: Protocol,

    /// Host address to connect to (TCP/UDP only)
    ///
    /// Use 127.0.0.1 for localhost, or a remote IP address.
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to connect to (TCP/UDP only)
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Named pipe name (pipe protocol only)
    ///
    /// Connects to \\.\\pipe\\<name>
    #[arg(long, default_value = DEFAULT_PIPE_NAME)]
    pipe: String,

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

/// Named pipe client wrapper for DCE RPC (Windows only)
#[cfg(windows)]
struct PipePrintClient {
    transport: NamedPipeTransport<tokio::net::windows::named_pipe::NamedPipeClient>,
    context_id: u16,
    call_id: u32,
}

#[cfg(windows)]
impl PipePrintClient {
    async fn connect(pipe_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let full_pipe_name = local_pipe_name(pipe_name);
        let pipe = DceRpcNamedPipeClient::connect(&full_pipe_name).await?;
        let mut transport = NamedPipeTransport::new(pipe);

        // Perform bind
        let interface_uuid = DceUuid::parse(PRINT_INTERFACE_UUID).expect("Invalid UUID");
        let interface = DceSyntaxId::new(interface_uuid, PRINT_INTERFACE_VERSION, 0);

        let bind = BindPdu::new(1, interface);
        transport.write_pdu(&bind.encode()).await?;

        // Read bind ack
        let response = transport.read_pdu_decoded().await?;
        match response {
            Pdu::BindAck(ack) => {
                if ack.results.is_empty() {
                    return Err("Bind rejected: no results".into());
                }
                // Check that the context was accepted
                let (result, _) = &ack.results[0];
                if *result != ContextResult::Acceptance {
                    return Err(format!("Bind rejected: {:?}", result).into());
                }
            }
            _ => {
                return Err("Bind rejected or unexpected response".into());
            }
        }

        Ok(Self {
            transport,
            context_id: 0,
            call_id: 2, // Start after bind
        })
    }

    async fn send_message(&mut self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let call_id = self.call_id;
        self.call_id += 1;

        let mut request = RequestPdu::new(call_id, OP_PRINT, Bytes::from(message.to_string()));
        request.context_id = self.context_id;
        self.transport.write_pdu(&Pdu::Request(request).encode()).await?;

        // Read response
        let response = self.transport.read_pdu_decoded().await?;
        match response {
            Pdu::Response(_) => Ok(()),
            Pdu::Fault(fault) => Err(format!("RPC fault: {:?}", fault.status).into()),
            _ => Err("Unexpected response".into()),
        }
    }

    async fn null_call(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let call_id = self.call_id;
        self.call_id += 1;

        let mut request = RequestPdu::new(call_id, OP_NULL, Bytes::new());
        request.context_id = self.context_id;
        self.transport.write_pdu(&Pdu::Request(request).encode()).await?;

        // Read response
        let response = self.transport.read_pdu_decoded().await?;
        match response {
            Pdu::Response(_) => Ok(()),
            Pdu::Fault(fault) => Err(format!("RPC fault: {:?}", fault.status).into()),
            _ => Err("Unexpected response".into()),
        }
    }
}

/// Client abstraction to handle all transport combinations
enum PrintClient {
    Tcp(TcpPrintClient),
    Udp(UdpPrintClient),
    #[cfg(windows)]
    Pipe(PipePrintClient),
}

impl PrintClient {
    async fn send_message(&mut self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            PrintClient::Tcp(c) => c.send_message(message).await,
            PrintClient::Udp(c) => c.send_message(message).await,
            #[cfg(windows)]
            PrintClient::Pipe(c) => c.send_message(message).await,
        }
    }

    async fn null_call(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            PrintClient::Tcp(c) => c.null_call().await,
            PrintClient::Udp(c) => c.null_call().await,
            #[cfg(windows)]
            PrintClient::Pipe(c) => c.null_call().await,
        }
    }
}

fn get_protocol_display(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "DCE RPC / TCP",
        Protocol::Udp => "DCE RPC / UDP",
        Protocol::Pipe => "DCE RPC / Named Pipe",
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

    // Connect to server based on protocol
    let (client, connection_info) = match args.protocol {
        Protocol::Tcp => {
            let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
            info!("Connecting to {} using TCP", addr);
            let c = TcpPrintClient::connect(addr).await?;
            (PrintClient::Tcp(c), addr.to_string())
        }
        Protocol::Udp => {
            let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
            info!("Connecting to {} using UDP", addr);
            let c = UdpPrintClient::connect(addr).await?;
            (PrintClient::Udp(c), addr.to_string())
        }
        Protocol::Pipe => {
            #[cfg(windows)]
            {
                let full_pipe_name = local_pipe_name(&args.pipe);
                info!("Connecting to {} using Named Pipe", full_pipe_name);
                let c = PipePrintClient::connect(&args.pipe).await?;
                (PrintClient::Pipe(c), full_pipe_name)
            }
            #[cfg(not(windows))]
            {
                eprintln!("Error: Named pipe transport is only available on Windows.");
                eprintln!("Please use --protocol tcp or --protocol udp on this platform.");
                std::process::exit(1);
            }
        }
    };

    if !args.quiet {
        let proto_name = get_protocol_display(args.protocol);
        println!("Connected to {} via {}", connection_info, proto_name);
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
