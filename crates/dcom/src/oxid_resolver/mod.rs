//! IObjectExporter implementation (MS-DCOM 3.1.2.5)
//!
//! The Object Exporter interface runs on port 135 and provides:
//! - OXID resolution (ResolveOxid, ResolveOxid2)
//! - Ping-based garbage collection (SimplePing, ComplexPing)
//! - Health checks (ServerAlive, ServerAlive2)

mod protocol;
mod server;
mod client;

pub use protocol::*;
pub use server::*;
pub use client::*;
