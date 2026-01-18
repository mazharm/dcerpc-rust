//! Named Pipe Transport for DCE RPC (Windows)
//!
//! This module implements the NCACN_NP (Named Pipe) transport for DCE RPC
//! as specified in MS-RPCE section 2.1.1.2.
//!
//! # Overview
//!
//! Named pipes provide a reliable, connection-oriented transport for RPC
//! on Windows systems. They are commonly used for local IPC and can also
//! be accessed remotely via SMB.
//!
//! # Pipe Naming
//!
//! Named pipes follow the format: `\\.\pipe\<pipename>` for local pipes
//! or `\\<server>\pipe\<pipename>` for remote pipes.
//!
//! Common well-known pipes:
//! - `\pipe\epmapper` - Endpoint Mapper
//! - `\pipe\lsarpc` - Local Security Authority
//! - `\pipe\samr` - Security Account Manager
//! - `\pipe\netlogon` - Netlogon service
//! - `\pipe\srvsvc` - Server Service
//! - `\pipe\wkssvc` - Workstation Service
//!
//! # Protocol Details
//!
//! - Protocol ID: 0x0F (in EPM protocol towers)
//! - PDUs sent via named pipe writes
//! - PDUs received via named pipe reads
//! - Uses connection-oriented RPC (not connectionless)

use crate::dcerpc::Pdu;
use crate::error::{Result, RpcError};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};

/// Named pipe protocol identifier for EPM towers
pub const NAMED_PIPE_PROTOCOL_ID: u8 = 0x0F;

/// Well-known endpoint mapper pipe name
pub const EPM_PIPE_NAME: &str = r"\pipe\epmapper";

/// Default pipe buffer size
pub const DEFAULT_PIPE_BUFFER_SIZE: u32 = 65536;

/// Maximum PDU size for named pipe transport
pub const DEFAULT_MAX_PIPE_PDU_SIZE: usize = 65536;

/// Named pipe transport for DCE RPC
///
/// This transport wraps a named pipe connection and provides
/// PDU framing for DCE RPC messages.
pub struct NamedPipeTransport<S> {
    stream: S,
    max_pdu_size: usize,
}

impl<S> NamedPipeTransport<S> {
    /// Create a new named pipe transport
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            max_pdu_size: DEFAULT_MAX_PIPE_PDU_SIZE,
        }
    }

    /// Set maximum PDU size
    pub fn with_max_pdu_size(mut self, size: usize) -> Self {
        self.max_pdu_size = size;
        self
    }

    /// Get a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consume the transport and return the underlying stream
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + Unpin> NamedPipeTransport<S> {
    /// Read a complete PDU from the pipe
    pub async fn read_pdu(&mut self) -> Result<Bytes> {
        // Read the PDU header (16 bytes minimum)
        let mut header_buf = [0u8; 16];
        self.stream.read_exact(&mut header_buf).await?;

        // Parse fragment length from header (bytes 8-9, little-endian)
        let frag_length = u16::from_le_bytes([header_buf[8], header_buf[9]]) as usize;

        if frag_length < 16 {
            return Err(RpcError::InvalidPduData(format!(
                "PDU fragment length {} is less than header size",
                frag_length
            )));
        }

        if frag_length > self.max_pdu_size {
            return Err(RpcError::PduTooLarge {
                size: frag_length,
                max: self.max_pdu_size,
            });
        }

        // Read the rest of the PDU
        let mut pdu = BytesMut::with_capacity(frag_length);
        pdu.extend_from_slice(&header_buf);

        if frag_length > 16 {
            pdu.resize(frag_length, 0);
            self.stream.read_exact(&mut pdu[16..]).await?;
        }

        Ok(pdu.freeze())
    }

    /// Read and decode a PDU
    pub async fn read_pdu_decoded(&mut self) -> Result<Pdu> {
        let data = self.read_pdu().await?;

        // Check for connection closed (empty read would error above)
        if data.is_empty() {
            return Err(RpcError::ConnectionClosed);
        }

        Pdu::decode(&data)
    }
}

impl<S: AsyncWrite + Unpin> NamedPipeTransport<S> {
    /// Write a PDU to the pipe
    pub async fn write_pdu(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Encode and write a PDU
    pub async fn write_pdu_encoded(&mut self, pdu: &Pdu) -> Result<()> {
        let data = pdu.encode();
        self.write_pdu(&data).await
    }
}

/// Configuration for named pipe server
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct NamedPipeServerConfig {
    /// Pipe name (e.g., r"\\.\pipe\mypipe")
    pub pipe_name: String,
    /// Maximum number of pipe instances
    pub max_instances: usize,
    /// Input buffer size
    pub in_buffer_size: u32,
    /// Output buffer size
    pub out_buffer_size: u32,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

#[cfg(windows)]
impl Default for NamedPipeServerConfig {
    fn default() -> Self {
        Self {
            pipe_name: String::new(),
            max_instances: 254, // Windows maximum is 254
            in_buffer_size: DEFAULT_PIPE_BUFFER_SIZE,
            out_buffer_size: DEFAULT_PIPE_BUFFER_SIZE,
            max_connections: 10000,
        }
    }
}

#[cfg(windows)]
impl NamedPipeServerConfig {
    /// Create a new config with the specified pipe name
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            ..Default::default()
        }
    }
}

/// Named pipe server for accepting DCE RPC connections
#[cfg(windows)]
pub struct DceRpcNamedPipeServer {
    config: NamedPipeServerConfig,
}

#[cfg(windows)]
impl DceRpcNamedPipeServer {
    /// Create a new named pipe server
    pub fn new(config: NamedPipeServerConfig) -> Self {
        Self { config }
    }

    /// Create a server for a specific pipe name
    pub fn with_pipe_name(pipe_name: impl Into<String>) -> Self {
        Self::new(NamedPipeServerConfig::new(pipe_name))
    }

    /// Create a new pipe instance for accepting a connection
    pub fn create_pipe_instance(&self) -> Result<NamedPipeServer> {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .max_instances(self.config.max_instances)
            .in_buffer_size(self.config.in_buffer_size)
            .out_buffer_size(self.config.out_buffer_size)
            .pipe_mode(PipeMode::Message)
            .create(&self.config.pipe_name)?;

        Ok(server)
    }

    /// Create the first pipe instance
    pub fn create_first_pipe_instance(&self) -> Result<NamedPipeServer> {
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(self.config.max_instances)
            .in_buffer_size(self.config.in_buffer_size)
            .out_buffer_size(self.config.out_buffer_size)
            .pipe_mode(PipeMode::Message)
            .create(&self.config.pipe_name)?;

        Ok(server)
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.config.pipe_name
    }
}

/// Named pipe client for connecting to DCE RPC servers
#[cfg(windows)]
pub struct DceRpcNamedPipeClient;

#[cfg(windows)]
impl DceRpcNamedPipeClient {
    /// Connect to a named pipe server
    ///
    /// # Arguments
    /// * `pipe_name` - Full pipe path (e.g., r"\\.\pipe\mypipe" or r"\\server\pipe\mypipe")
    pub async fn connect(pipe_name: &str) -> Result<NamedPipeClient> {
        let client = ClientOptions::new()
            .pipe_mode(PipeMode::Message)
            .open(pipe_name)?;

        Ok(client)
    }

    /// Connect to a local pipe
    pub async fn connect_local(pipe_name: &str) -> Result<NamedPipeClient> {
        let full_path = format!(r"\\.\pipe\{}", pipe_name.trim_start_matches(r"\pipe\"));
        Self::connect(&full_path).await
    }

    /// Connect to a remote pipe via SMB
    pub async fn connect_remote(server: &str, pipe_name: &str) -> Result<NamedPipeClient> {
        let full_path = format!(
            r"\\{}\pipe\{}",
            server,
            pipe_name.trim_start_matches(r"\pipe\")
        );
        Self::connect(&full_path).await
    }

    /// Connect to the endpoint mapper
    pub async fn connect_epm_local() -> Result<NamedPipeClient> {
        Self::connect_local("epmapper").await
    }

    /// Connect to a remote endpoint mapper
    pub async fn connect_epm_remote(server: &str) -> Result<NamedPipeClient> {
        Self::connect_remote(server, "epmapper").await
    }
}

/// Helper to format a pipe name for local access
pub fn local_pipe_name(name: &str) -> String {
    let name = name.trim_start_matches(r"\pipe\").trim_start_matches(r"\\.\pipe\");
    format!(r"\\.\pipe\{}", name)
}

/// Helper to format a pipe name for remote access
pub fn remote_pipe_name(server: &str, name: &str) -> String {
    let name = name.trim_start_matches(r"\pipe\").trim_start_matches(r"\\.\pipe\");
    format!(r"\\{}\pipe\{}", server, name)
}

/// Parse a pipe endpoint into (server, pipe_name) components
/// Returns None for the server component if it's a local pipe
pub fn parse_pipe_endpoint(endpoint: &str) -> Option<(Option<&str>, &str)> {
    // Remove leading backslashes
    let path = endpoint.trim_start_matches('\\');

    // Check for UNC path format: \\server\pipe\name or .\pipe\name
    if let Some(rest) = path.strip_prefix('.') {
        // Local pipe: \\.\pipe\name
        let pipe_name = rest.trim_start_matches('\\').strip_prefix("pipe\\")?;
        Some((None, pipe_name))
    } else if let Some(idx) = path.find('\\') {
        // Remote pipe: \\server\pipe\name
        let server = &path[..idx];
        let rest = &path[idx + 1..];
        let pipe_name = rest.strip_prefix("pipe\\")?.trim_start_matches('\\');
        Some((Some(server), pipe_name))
    } else {
        // Just a pipe name
        Some((None, path.strip_prefix("pipe\\").unwrap_or(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_pipe_name() {
        assert_eq!(local_pipe_name("mypipe"), r"\\.\pipe\mypipe");
        assert_eq!(local_pipe_name(r"\pipe\mypipe"), r"\\.\pipe\mypipe");
        assert_eq!(local_pipe_name(r"\\.\pipe\mypipe"), r"\\.\pipe\mypipe");
    }

    #[test]
    fn test_remote_pipe_name() {
        assert_eq!(
            remote_pipe_name("server", "mypipe"),
            r"\\server\pipe\mypipe"
        );
        assert_eq!(
            remote_pipe_name("server", r"\pipe\mypipe"),
            r"\\server\pipe\mypipe"
        );
    }

    #[test]
    fn test_parse_pipe_endpoint() {
        // Local pipes
        assert_eq!(
            parse_pipe_endpoint(r"\\.\pipe\mypipe"),
            Some((None, "mypipe"))
        );
        assert_eq!(
            parse_pipe_endpoint(r".\pipe\mypipe"),
            Some((None, "mypipe"))
        );

        // Remote pipes
        assert_eq!(
            parse_pipe_endpoint(r"\\server\pipe\mypipe"),
            Some((Some("server"), "mypipe"))
        );
        assert_eq!(
            parse_pipe_endpoint(r"server\pipe\mypipe"),
            Some((Some("server"), "mypipe"))
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_pipe_transport_roundtrip() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions, PipeMode};
        use std::time::Duration;

        let pipe_name = format!(r"\\.\pipe\dcerpc_test_{}", std::process::id());

        // Create server
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Byte)
            .create(&pipe_name)
            .expect("Failed to create pipe server");

        // Spawn server task
        let server_handle = tokio::spawn(async move {
            server.connect().await.expect("Failed to accept connection");

            let _transport = NamedPipeTransport::new(server);

            // Note: This test verifies the transport can be created
            // A full PDU roundtrip test would need actual RPC PDU data
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let client = ClientOptions::new()
            .pipe_mode(PipeMode::Byte)
            .open(&pipe_name)
            .expect("Failed to connect to pipe");

        let _transport = NamedPipeTransport::new(client);

        // Clean up
        drop(_transport);
        let _ = server_handle.await;
    }
}
