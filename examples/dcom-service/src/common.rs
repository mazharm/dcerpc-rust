//! Common definitions shared between DCOM client and server

#![allow(dead_code)]

// =============================================================================
// DCOM Constants
// =============================================================================

/// CLSID for our example calculator COM object
/// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
pub const CALCULATOR_CLSID: &str = "12345678-1234-1234-1234-123456789abc";

/// IID for ICalculator interface
pub const ICALCULATOR_IID: &str = "87654321-4321-4321-4321-cba987654321";

/// Operation numbers for ICalculator
pub mod opnum {
    /// Add two numbers
    pub const ADD: u16 = 3;
    /// Subtract two numbers
    pub const SUBTRACT: u16 = 4;
    /// Multiply two numbers
    pub const MULTIPLY: u16 = 5;
    /// Divide two numbers
    pub const DIVIDE: u16 = 6;
}

// =============================================================================
// Shared Constants
// =============================================================================

/// Default server address
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Default RPC port (for DCOM object calls)
pub const DEFAULT_RPC_PORT: u16 = 12350;
/// Default OXID resolver port (standard DCOM port is 135)
pub const DEFAULT_OXID_PORT: u16 = 12351;
