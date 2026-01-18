//! Common definitions shared between client and server

// =============================================================================
// DCE RPC Constants (MS-RPCE)
// =============================================================================

/// Interface UUID for the print service
/// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
pub const PRINT_INTERFACE_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
pub const PRINT_INTERFACE_VERSION: u16 = 1;

/// Operation numbers for DCE RPC
#[allow(dead_code)]
pub const OP_NULL: u16 = 0;
pub const OP_PRINT: u16 = 1;

// =============================================================================
// Shared Constants
// =============================================================================

/// Default server address
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 12346;

/// Default named pipe name (Windows)
pub const DEFAULT_PIPE_NAME: &str = "printservice";
