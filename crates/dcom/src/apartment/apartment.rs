//! Apartment trait and common types
//!
//! Apartments define the threading model for COM objects.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use bytes::Bytes;
use crate::types::{Result, Ipid, Oid, OrpcThis, OrpcThat};

/// Unique identifier for an apartment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApartmentId(pub u64);

impl ApartmentId {
    /// Generate a new apartment ID
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self(timestamp)
    }
}

impl Default for ApartmentId {
    fn default() -> Self {
        Self::generate()
    }
}

/// Apartment type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApartmentType {
    /// Multi-Threaded Apartment - concurrent call execution
    Mta,
    /// Single-Threaded Apartment - serialized call execution
    Sta,
}

/// Result of a COM call
pub type CallResult = Result<Bytes>;

/// Future type for call results
pub type CallFuture = Pin<Box<dyn Future<Output = CallResult> + Send>>;

/// Handler for ORPC calls
pub type OrpcHandler = Arc<
    dyn Fn(OrpcThis, Ipid, u16, Bytes) -> CallFuture + Send + Sync
>;

/// Trait for COM object implementations
pub trait ComObject: Send + Sync + 'static {
    /// Get the OID for this object
    fn oid(&self) -> Oid;

    /// Get the supported interface IIDs
    fn supported_interfaces(&self) -> Vec<dcerpc::Uuid>;

    /// Invoke a method on this object
    fn invoke(
        &self,
        iid: &dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture;

    /// Cast to Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Trait for apartment implementations
pub trait Apartment: Send + Sync {
    /// Get the apartment ID
    fn id(&self) -> ApartmentId;

    /// Get the apartment type
    fn apartment_type(&self) -> ApartmentType;

    /// Register an object in this apartment
    fn register_object(&self, object: Arc<dyn ComObject>) -> Oid;

    /// Look up an object by OID
    fn get_object(&self, oid: &Oid) -> Option<Arc<dyn ComObject>>;

    /// Dispatch a call to an object
    fn dispatch(
        &self,
        oid: Oid,
        iid: dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture;

    /// Shutdown the apartment
    fn shutdown(&self);

    /// Check if the apartment is running
    fn is_running(&self) -> bool;
}

/// Call context for ORPC calls
#[derive(Clone, Debug)]
pub struct CallContext {
    /// ORPC request header
    pub orpc_this: OrpcThis,
    /// Target IPID
    pub ipid: Ipid,
    /// Operation number
    pub opnum: u16,
    /// Apartment ID where the call is executed
    pub apartment_id: ApartmentId,
}

impl CallContext {
    /// Create a new call context
    pub fn new(orpc_this: OrpcThis, ipid: Ipid, opnum: u16, apartment_id: ApartmentId) -> Self {
        Self {
            orpc_this,
            ipid,
            opnum,
            apartment_id,
        }
    }

    /// Create a response header
    pub fn create_response(&self) -> OrpcThat {
        OrpcThat::new()
    }
}
