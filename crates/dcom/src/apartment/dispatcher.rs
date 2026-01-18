//! Call dispatcher for routing calls to the correct apartment

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use bytes::Bytes;
use crate::types::{Ipid, Oid};
use super::apartment::{Apartment, ApartmentId, CallFuture};
use super::mta::MultithreadedApartment;

/// Call dispatcher
///
/// Routes ORPC calls to the correct apartment based on IPID.
pub struct CallDispatcher {
    /// IPID to apartment ID mapping
    ipid_to_apartment: RwLock<HashMap<Ipid, ApartmentId>>,
    /// OID to apartment ID mapping
    oid_to_apartment: RwLock<HashMap<Oid, ApartmentId>>,
    /// Registered apartments
    apartments: RwLock<HashMap<ApartmentId, Arc<dyn Apartment>>>,
    /// Default MTA for objects without explicit apartment assignment
    default_mta: Arc<MultithreadedApartment>,
}

impl CallDispatcher {
    /// Create a new call dispatcher
    pub fn new() -> Self {
        let default_mta = Arc::new(MultithreadedApartment::new());
        let mut apartments = HashMap::new();
        apartments.insert(default_mta.id(), default_mta.clone() as Arc<dyn Apartment>);

        Self {
            ipid_to_apartment: RwLock::new(HashMap::new()),
            oid_to_apartment: RwLock::new(HashMap::new()),
            apartments: RwLock::new(apartments),
            default_mta,
        }
    }

    /// Get the default MTA
    pub fn default_mta(&self) -> Arc<MultithreadedApartment> {
        self.default_mta.clone()
    }

    /// Register an apartment
    pub fn register_apartment(&self, apartment: Arc<dyn Apartment>) {
        let mut apartments = self.apartments.write().unwrap();
        apartments.insert(apartment.id(), apartment);
    }

    /// Unregister an apartment
    pub fn unregister_apartment(&self, id: ApartmentId) {
        let mut apartments = self.apartments.write().unwrap();
        apartments.remove(&id);
    }

    /// Associate an IPID with an apartment
    pub fn associate_ipid(&self, ipid: Ipid, apartment_id: ApartmentId) {
        let mut map = self.ipid_to_apartment.write().unwrap();
        map.insert(ipid, apartment_id);
    }

    /// Associate an OID with an apartment
    pub fn associate_oid(&self, oid: Oid, apartment_id: ApartmentId) {
        let mut map = self.oid_to_apartment.write().unwrap();
        map.insert(oid, apartment_id);
    }

    /// Get the apartment for an IPID
    pub fn get_apartment_for_ipid(&self, ipid: &Ipid) -> Option<Arc<dyn Apartment>> {
        let map = self.ipid_to_apartment.read().unwrap();
        if let Some(&apt_id) = map.get(ipid) {
            let apartments = self.apartments.read().unwrap();
            apartments.get(&apt_id).cloned()
        } else {
            None
        }
    }

    /// Get the apartment for an OID
    pub fn get_apartment_for_oid(&self, oid: &Oid) -> Option<Arc<dyn Apartment>> {
        let map = self.oid_to_apartment.read().unwrap();
        if let Some(&apt_id) = map.get(oid) {
            let apartments = self.apartments.read().unwrap();
            apartments.get(&apt_id).cloned()
        } else {
            Some(self.default_mta.clone())
        }
    }

    /// Dispatch a call to the appropriate apartment
    pub fn dispatch(
        &self,
        oid: Oid,
        iid: dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture {
        let apartment = self.get_apartment_for_oid(&oid);

        match apartment {
            Some(apt) => apt.dispatch(oid, iid, opnum, args),
            None => {
                // Use default MTA
                self.default_mta.dispatch(oid, iid, opnum, args)
            }
        }
    }

    /// Dispatch by IPID (requires OID lookup)
    pub fn dispatch_by_ipid(
        &self,
        ipid: Ipid,
        oid: Oid,
        iid: dcerpc::Uuid,
        opnum: u16,
        args: Bytes,
    ) -> CallFuture {
        // First try to find apartment by IPID
        if let Some(apt) = self.get_apartment_for_ipid(&ipid) {
            return apt.dispatch(oid, iid, opnum, args);
        }

        // Fall back to OID-based dispatch
        self.dispatch(oid, iid, opnum, args)
    }

    /// Remove IPID association
    pub fn remove_ipid(&self, ipid: &Ipid) {
        let mut map = self.ipid_to_apartment.write().unwrap();
        map.remove(ipid);
    }

    /// Remove OID association
    pub fn remove_oid(&self, oid: &Oid) {
        let mut map = self.oid_to_apartment.write().unwrap();
        map.remove(oid);
    }

    /// Shutdown all apartments
    pub fn shutdown(&self) {
        let apartments = self.apartments.read().unwrap();
        for (_, apt) in apartments.iter() {
            apt.shutdown();
        }
    }
}

impl Default for CallDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apartment::{ComObject, SinglethreadedApartment};
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
            Box::pin(async move { Ok(args) })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_dispatcher_default_mta() {
        let dispatcher = CallDispatcher::new();
        let obj = Arc::new(TestObject { oid: Oid::generate() });
        let oid = obj.oid();

        // Register in default MTA
        dispatcher.default_mta().register_object(obj);

        // Dispatch should work
        let result = dispatcher
            .dispatch(oid, dcerpc::Uuid::NIL, 0, Bytes::from("test"))
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("test"));
    }

    #[tokio::test]
    async fn test_dispatcher_sta() {
        let dispatcher = CallDispatcher::new();

        // Create and register an STA
        let sta = Arc::new(SinglethreadedApartment::new());
        dispatcher.register_apartment(sta.clone());

        let obj = Arc::new(TestObject { oid: Oid::generate() });
        let oid = obj.oid();

        // Register object in STA
        sta.register_object(obj);
        dispatcher.associate_oid(oid, sta.id());

        // Dispatch should route to STA
        let result = dispatcher
            .dispatch(oid, dcerpc::Uuid::NIL, 0, Bytes::from("sta test"))
            .await;

        assert!(result.is_ok());
    }
}
