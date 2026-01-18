//! IActivation and IRemoteSCMActivator implementation (MS-DCOM 3.1.2.5.2)
//!
//! Object activation interfaces:
//! - RemoteActivation - Create remote COM objects
//! - GetClassObject - Get class factory

mod protocol;
mod server;
mod client;

pub use protocol::*;
pub use server::*;
pub use client::*;
