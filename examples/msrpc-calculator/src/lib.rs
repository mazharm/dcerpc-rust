//! MSRPC Calculator Example
//!
//! This example demonstrates how to use MIDL-generated stubs for a simple
//! RPC calculator service.

// Re-export the generated stubs
#[allow(dead_code)]
#[allow(non_snake_case)]
mod calculator_rpc;

pub use calculator_rpc::*;
