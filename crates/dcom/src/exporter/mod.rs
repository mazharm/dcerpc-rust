//! Object Exporter runtime
//!
//! The Object Exporter manages COM objects within an apartment:
//! - OXID/OID/IPID table management
//! - Distributed reference counting
//! - Ping-based garbage collection

mod object_exporter;
mod tables;
mod reference_counting;
mod garbage_collection;

pub use object_exporter::*;
pub use tables::*;
pub use reference_counting::*;
pub use garbage_collection::*;
