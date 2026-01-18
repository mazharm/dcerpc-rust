//! Multi-Threaded Apartment (MTA) implementation
//!
//! In an MTA, calls are dispatched concurrently. Objects must be thread-safe.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use crate::types::{Oid, DcomError};
use super::apartment::{Apartment, ApartmentId, ApartmentType, CallFuture, ComObject};

/// Multi-Threaded Apartment
///
/// All calls are executed concurrently using the Tokio runtime.
/// Objects registered in this apartment must be thread-safe.
pub struct MultithreadedApartment {
    /// Apartment ID
    id: ApartmentId,
    /// Registered objects by OID
    objects: RwLock<HashMap<Oid, Arc<dyn ComObject>>>,
    /// Running flag
    running: AtomicBool,
}

impl MultithreadedApartment {
    /// Create a new MTA
    pub fn new() -> Self {
        Self {
            id: ApartmentId::generate(),
            objects: RwLock::new(HashMap::new()),
            running: AtomicBool::new(true),
        }
    }

    /// Create with a specific ID
    pub fn with_id(id: ApartmentId) -> Self {
        Self {
            id,
            objects: RwLock::new(HashMap::new()),
            running: AtomicBool::new(true),
        }
    }
}

impl Default for MultithreadedApartment {
    fn default() -> Self {
        Self::new()
    }
}

impl Apartment for MultithreadedApartment {
    fn id(&self) -> ApartmentId {
        self.id
    }

    fn apartment_type(&self) -> ApartmentType {
        ApartmentType::Mta
    }

    fn register_object(&self, object: Arc<dyn ComObject>) -> Oid {
        let oid = object.oid();
        let mut objects = self.objects.write().unwrap();
        objects.insert(oid, object);
        oid
    }

    fn get_object(&self, oid: &Oid) -> Option<Arc<dyn ComObject>> {
        let objects = self.objects.read().unwrap();
        objects.get(oid).cloned()
    }

    fn dispatch(
        &self,
        oid: Oid,
        iid: dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture {
        if !self.running.load(Ordering::SeqCst) {
            return Box::pin(async move {
                Err(DcomError::ApartmentError("apartment is shutdown".to_string()))
            });
        }

        let object = {
            let objects = self.objects.read().unwrap();
            objects.get(&oid).cloned()
        };

        match object {
            Some(obj) => {
                // In MTA, we can invoke directly - the object is thread-safe
                obj.invoke(&iid, opnum, args)
            }
            None => {
                Box::pin(async move {
                    Err(DcomError::ObjectNotFound(oid.0))
                })
            }
        }
    }

    fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        let mut objects = self.objects.write().unwrap();
        objects.clear();
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    struct TestObject {
        oid: Oid,
    }

    impl ComObject for TestObject {
        fn oid(&self) -> Oid {
            self.oid
        }

        fn supported_interfaces(&self) -> Vec<dcerpc::Uuid> {
            vec![dcerpc::Uuid::NIL]
        }

        fn invoke(
            &self,
            _iid: &dcerpc::Uuid,
            _opnum: u16,
            args: Bytes,
        ) -> CallFuture {
            // Echo the input
            Box::pin(async move { Ok(args) })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_mta_basic() {
        let mta = MultithreadedApartment::new();
        let obj = Arc::new(TestObject { oid: Oid::generate() });
        let oid = obj.oid();

        mta.register_object(obj);

        let result = mta
            .dispatch(oid, dcerpc::Uuid::NIL, 0, Bytes::from("test"))
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("test"));
    }

    #[tokio::test]
    async fn test_mta_shutdown() {
        let mta = MultithreadedApartment::new();
        assert!(mta.is_running());

        mta.shutdown();
        assert!(!mta.is_running());

        // Dispatch should fail after shutdown
        let result = mta
            .dispatch(Oid::new(1), dcerpc::Uuid::NIL, 0, Bytes::new())
            .await;
        assert!(result.is_err());
    }
}
