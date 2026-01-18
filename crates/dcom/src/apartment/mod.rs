//! Apartment threading model implementation
//!
//! Supports both MTA (Multi-Threaded Apartment) and STA (Single-Threaded Apartment):
//! - MTA: Concurrent call execution, objects must be thread-safe
//! - STA: Serialized calls via message queue, objects don't need synchronization

mod apartment;
mod mta;
mod sta;
mod dispatcher;

pub use apartment::*;
pub use mta::*;
pub use sta::*;
pub use dispatcher::*;
