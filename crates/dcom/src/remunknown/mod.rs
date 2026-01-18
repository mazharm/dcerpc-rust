//! IRemUnknown and IRemUnknown2 implementation (MS-DCOM 3.1.1.5)
//!
//! Remote IUnknown interface for distributed reference counting:
//! - RemQueryInterface - Query additional interfaces on remote object
//! - RemAddRef - Increment remote reference counts
//! - RemRelease - Decrement remote reference counts

mod protocol;
mod server;
mod client;

pub use protocol::*;
pub use server::*;
pub use client::*;
