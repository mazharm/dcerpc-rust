//! DCOM Calculator Service Client
//!
//! An interactive client that calls methods on the Calculator COM object.
//!
//! USAGE:
//!   dcom-client [OPTIONS] [OPERATION]
//!
//! EXAMPLES:
//!   dcom-client                          # Interactive mode
//!   dcom-client "add 5 3"                # Add 5 + 3
//!   dcom-client "mul 6 7"                # Multiply 6 * 7
//!   dcom-client --host 192.168.1.1       # Connect to remote server

mod common;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::Parser;
use common::*;
use dcerpc::{DceRpcClient, SyntaxId, Uuid};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "dcom-client")]
#[command(version)]
#[command(about = "DCOM Calculator client - calls methods on the Calculator COM object")]
#[command(
    long_about = "A DCOM client that connects to the Calculator service and invokes methods.\n\n\
If no operation is provided, enters interactive mode.\n\n\
OPERATIONS:\n\
  add <a> <b>      Add two numbers\n\
  sub <a> <b>      Subtract b from a\n\
  mul <a> <b>      Multiply two numbers\n\
  div <a> <b>      Divide a by b\n\n\
INTERACTIVE COMMANDS:\n\
  add <a> <b>      Add two numbers\n\
  sub <a> <b>      Subtract two numbers\n\
  mul <a> <b>      Multiply two numbers\n\
  div <a> <b>      Divide two numbers\n\
  help             Show help\n\
  quit/exit        Disconnect and exit"
)]
struct Args {
    /// Host address to connect to
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Port number to connect to
    #[arg(long, default_value_t = DEFAULT_RPC_PORT)]
    port: u16,

    /// Operation to perform (e.g., "add 5 3")
    #[arg(value_name = "OPERATION")]
    operation: Option<String>,

    /// Quiet mode - suppress informational output
    #[arg(short, long)]
    quiet: bool,
}

/// Calculator client wrapper
struct CalculatorClient {
    client: DceRpcClient,
}

impl CalculatorClient {
    async fn connect(addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let interface = SyntaxId::new(
            Uuid::parse(ICALCULATOR_IID).expect("Invalid UUID"),
            1,
            0,
        );
        let client = DceRpcClient::connect(addr, interface).await?;
        Ok(Self { client })
    }

    /// Encode two i32 arguments
    fn encode_args(a: i32, b: i32) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_i32_le(a);
        buf.put_i32_le(b);
        buf.freeze()
    }

    /// Decode i32 result
    fn decode_result(mut data: Bytes) -> Result<i32, Box<dyn std::error::Error>> {
        if data.remaining() < 4 {
            return Err("insufficient data in response".into());
        }
        Ok(data.get_i32_le())
    }

    async fn add(&self, a: i32, b: i32) -> Result<i32, Box<dyn std::error::Error>> {
        let args = Self::encode_args(a, b);
        let response = self.client.call(opnum::ADD, args).await?;
        Self::decode_result(response)
    }

    async fn subtract(&self, a: i32, b: i32) -> Result<i32, Box<dyn std::error::Error>> {
        let args = Self::encode_args(a, b);
        let response = self.client.call(opnum::SUBTRACT, args).await?;
        Self::decode_result(response)
    }

    async fn multiply(&self, a: i32, b: i32) -> Result<i32, Box<dyn std::error::Error>> {
        let args = Self::encode_args(a, b);
        let response = self.client.call(opnum::MULTIPLY, args).await?;
        Self::decode_result(response)
    }

    async fn divide(&self, a: i32, b: i32) -> Result<i32, Box<dyn std::error::Error>> {
        let args = Self::encode_args(a, b);
        let response = self.client.call(opnum::DIVIDE, args).await?;
        Self::decode_result(response)
    }
}

/// Parse an operation string like "add 5 3"
fn parse_operation(input: &str) -> Option<(&str, i32, i32)> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }

    let _op = parts[0].to_lowercase();
    let a = parts[1].parse::<i32>().ok()?;
    let b = parts[2].parse::<i32>().ok()?;

    Some((parts[0], a, b))
}

/// Execute an operation
async fn execute_operation(
    client: &CalculatorClient,
    op: &str,
    a: i32,
    b: i32,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = match op.to_lowercase().as_str() {
        "add" => {
            let r = client.add(a, b).await?;
            if !quiet {
                println!("{} + {} = {}", a, b, r);
            } else {
                println!("{}", r);
            }
            Ok(())
        }
        "sub" | "subtract" => {
            let r = client.subtract(a, b).await?;
            if !quiet {
                println!("{} - {} = {}", a, b, r);
            } else {
                println!("{}", r);
            }
            Ok(())
        }
        "mul" | "multiply" => {
            let r = client.multiply(a, b).await?;
            if !quiet {
                println!("{} * {} = {}", a, b, r);
            } else {
                println!("{}", r);
            }
            Ok(())
        }
        "div" | "divide" => {
            let r = client.divide(a, b).await?;
            if !quiet {
                println!("{} / {} = {}", a, b, r);
            } else {
                println!("{}", r);
            }
            Ok(())
        }
        _ => Err(format!("unknown operation: {}", op).into()),
    };

    result
}

fn print_help() {
    println!("Available commands:");
    println!("  add <a> <b>      Add two numbers");
    println!("  sub <a> <b>      Subtract b from a");
    println!("  mul <a> <b>      Multiply two numbers");
    println!("  div <a> <b>      Divide a by b");
    println!("  help             Show this help");
    println!("  quit/exit        Exit the client");
}

async fn run_interactive(
    client: CalculatorClient,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !quiet {
        println!("========================================================");
        println!("         DCOM Calculator Client - Interactive Mode");
        println!("========================================================");
        println!("  Type 'help' for available commands");
        println!("  Type 'quit' or 'exit' to disconnect");
        println!("========================================================");
        println!();
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

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

        // Check for help
        if line.eq_ignore_ascii_case("help") {
            print_help();
            continue;
        }

        // Parse and execute operation
        match parse_operation(line) {
            Some((op, a, b)) => {
                if let Err(e) = execute_operation(&client, op, a, b, quiet).await {
                    eprintln!("Error: {}", e);
                }
            }
            None => {
                eprintln!("Invalid command. Format: <op> <a> <b>");
                eprintln!("Example: add 5 3");
                eprintln!("Type 'help' for available commands.");
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

    if !args.quiet {
        println!("Connecting to DCOM Calculator at {}...", addr);
    }

    let client = CalculatorClient::connect(addr).await?;

    if !args.quiet {
        println!("Connected!");
        println!();
    }

    // If operation provided, execute it; otherwise enter interactive mode
    if let Some(operation) = args.operation {
        match parse_operation(&operation) {
            Some((op, a, b)) => {
                execute_operation(&client, op, a, b, args.quiet).await?;
            }
            None => {
                eprintln!("Invalid operation format. Expected: <op> <a> <b>");
                eprintln!("Example: add 5 3");
                std::process::exit(1);
            }
        }
    } else {
        run_interactive(client, args.quiet).await?;
    }

    Ok(())
}
