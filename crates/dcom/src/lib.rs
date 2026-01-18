//! DCOM (Distributed Component Object Model) implementation
//!
//! This crate provides a Rust implementation of DCOM on top of DCE RPC,
//! following the MS-DCOM specification.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    DCOM Layer (this crate)                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Apartment Runtime    │  Object Exporter  │  Marshaling     │
//! │  - MTA (concurrent)   │  - OXID/OID/IPID  │  - Proxy/Stub   │
//! │  - STA (serialized)   │  - Ref counting   │  - OBJREF       │
//! │  - Call dispatcher    │  - GC (pinging)   │                 │
//! ├─────────────────────────────────────────────────────────────┤
//! │  IObjectExporter      │  IRemUnknown      │  IActivation    │
//! │  (port 135)           │  (per exporter)   │  (activation)   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  DCE RPC Layer (dcerpc crate)               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Concepts
//!
//! - **Object Exporter**: Manages COM objects and their lifecycle
//! - **OXID**: Object Exporter ID - identifies an apartment/process
//! - **OID**: Object ID - identifies an object within an exporter
//! - **IPID**: Interface Pointer ID - identifies an interface on an object
//! - **Apartment**: Threading model (MTA or STA)
//!
//! # Modules
//!
//! - [`types`]: Core DCOM data types
//! - [`oxid_resolver`]: IObjectExporter implementation (OXID resolution, pinging)
//! - [`remunknown`]: IRemUnknown implementation (remote reference counting)
//! - [`activation`]: Object activation (IActivation)
//! - [`exporter`]: Object exporter runtime
//! - [`apartment`]: Threading model implementation

pub mod types;
pub mod oxid_resolver;
pub mod remunknown;
pub mod activation;
pub mod exporter;
pub mod apartment;

mod client;
mod server;

// Re-export main types and client/server APIs
pub use types::{
    DcomError, Result,
    Oxid, Oid, Ipid, SetId,
    StdObjRef, ObjRef, ObjRefStandard,
    DualStringArray, StringBinding,
    OrpcThis, OrpcThat, ComVersion,
};
pub use client::DcomClient;
pub use server::DcomServer;

/// DCOM version supported by this implementation
pub const DCOM_VERSION: ComVersion = ComVersion::DCOM_5_7;

/// Default ping timeout in seconds (as per MS-DCOM)
pub const DEFAULT_PING_PERIOD_SECS: u64 = 120;

/// Number of ping periods before considering an object dead
pub const DEFAULT_PING_TIMEOUT_PERIODS: u32 = 3;
