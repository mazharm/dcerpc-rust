//! Core Object Exporter implementation
//!
//! The Object Exporter is the central runtime component that manages
//! COM objects, their references, and garbage collection.

use std::sync::Arc;
use crate::types::{
    Oxid, Oid, Ipid, SetId, DualStringArray, Result, DcomError,
};
use super::tables::{OxidTable, OxidEntry, OidTable, OidEntry, IpidTable, IpidEntry};
use super::reference_counting::RefCountManager;
use super::garbage_collection::GarbageCollector;

/// Object Exporter - manages COM objects within an apartment
pub struct ObjectExporter {
    /// This exporter's OXID
    oxid: Oxid,
    /// Bindings for this exporter
    bindings: DualStringArray,
    /// OXID table (for multi-exporter scenarios)
    oxid_table: Arc<OxidTable>,
    /// OID table
    oid_table: Arc<OidTable>,
    /// IPID table
    ipid_table: Arc<IpidTable>,
    /// Reference count manager
    ref_manager: Arc<RefCountManager>,
    /// Garbage collector
    gc: Arc<GarbageCollector>,
    /// IRemUnknown IPID for this exporter
    remunknown_ipid: Ipid,
}

impl ObjectExporter {
    /// Create a new object exporter
    pub fn new(bindings: DualStringArray) -> Self {
        let oxid = Oxid::generate();
        let remunknown_ipid = Ipid::generate();

        let exporter = Self {
            oxid,
            bindings: bindings.clone(),
            oxid_table: Arc::new(OxidTable::new()),
            oid_table: Arc::new(OidTable::new()),
            ipid_table: Arc::new(IpidTable::new()),
            ref_manager: Arc::new(RefCountManager::new()),
            gc: Arc::new(GarbageCollector::new()),
            remunknown_ipid,
        };

        // Register our own OXID
        let oxid_entry = OxidEntry::new(oxid, bindings, remunknown_ipid);
        exporter.oxid_table.register(oxid_entry);

        exporter
    }

    /// Get the OXID for this exporter
    pub fn oxid(&self) -> Oxid {
        self.oxid
    }

    /// Get the bindings for this exporter
    pub fn bindings(&self) -> &DualStringArray {
        &self.bindings
    }

    /// Get the IRemUnknown IPID for this exporter
    pub fn remunknown_ipid(&self) -> Ipid {
        self.remunknown_ipid
    }

    /// Register a new object
    pub fn register_object(&self) -> Oid {
        let oid = Oid::generate();
        let entry = OidEntry::new(oid, self.oxid);
        self.oid_table.register(entry);
        self.oxid_table.add_object(&self.oxid, oid);
        oid
    }

    /// Register an interface on an object
    pub fn register_interface(&self, oid: Oid, iid: dcerpc::Uuid) -> Result<Ipid> {
        // Check if we already have this interface
        if let Some(existing) = self.ipid_table.find_by_oid_and_iid(&oid, &iid) {
            return Ok(existing);
        }

        let ipid = Ipid::generate();
        let entry = IpidEntry::new(ipid, oid, iid);
        self.ipid_table.register(entry);
        self.oid_table.add_interface(&oid, ipid);
        self.ref_manager.register(ipid, oid);
        Ok(ipid)
    }

    /// Look up the IRemUnknown IPID for an OXID
    pub fn get_remunknown_ipid(&self, oxid: &Oxid) -> Option<Ipid> {
        self.oxid_table.lookup(oxid).map(|e| e.remunknown_ipid)
    }

    /// Look up binding information for an OXID
    pub fn resolve_oxid(&self, oxid: &Oxid) -> Option<(DualStringArray, Ipid)> {
        self.oxid_table
            .lookup(oxid)
            .map(|e| (e.bindings, e.remunknown_ipid))
    }

    /// Handle a simple ping
    pub fn simple_ping(&self, set_id: SetId) -> Result<()> {
        self.gc.simple_ping(set_id)
    }

    /// Handle a complex ping
    pub fn complex_ping(
        &self,
        set_id: SetId,
        sequence_num: u16,
        add_oids: &[Oid],
        del_oids: &[Oid],
    ) -> Result<SetId> {
        // Validate that all add_oids exist
        for oid in add_oids {
            if !self.oid_table.contains(oid) {
                return Err(DcomError::ObjectNotFound(oid.0));
            }
        }
        self.gc.complex_ping(set_id, sequence_num, add_oids, del_oids)
    }

    /// Query for an interface on an object
    pub fn query_interface(&self, ipid: &Ipid, iid: &dcerpc::Uuid) -> Result<Ipid> {
        // Get the OID from the source IPID
        let entry = self
            .ipid_table
            .lookup(ipid)
            .ok_or_else(|| DcomError::InterfaceNotFound(ipid.to_string()))?;

        // Look up or create the requested interface
        if let Some(existing) = self.ipid_table.find_by_oid_and_iid(&entry.oid, iid) {
            Ok(existing)
        } else {
            // Register the new interface
            self.register_interface(entry.oid, *iid)
        }
    }

    /// Add public references
    pub fn add_refs(&self, ipid: &Ipid, count: u32, client_id: Option<u64>) -> Result<u32> {
        self.ref_manager.add_public_refs(ipid, count, client_id)
    }

    /// Release public references
    pub fn release_refs(
        &self,
        ipid: &Ipid,
        count: u32,
        client_id: Option<u64>,
    ) -> Result<bool> {
        let (_, should_release) = self
            .ref_manager
            .release_public_refs(ipid, count, client_id)?;
        Ok(should_release)
    }

    /// Run garbage collection
    pub fn run_gc(&self) -> Vec<Oid> {
        let orphaned = self.gc.collect();

        // Release orphaned objects
        for oid in &orphaned {
            // Remove all interfaces for this object
            let ipids = self.ipid_table.get_by_oid(oid);
            for ipid in ipids {
                self.ipid_table.remove(&ipid);
                self.ref_manager.remove(&ipid);
            }
            // Remove the object
            self.oid_table.remove(oid);
        }

        orphaned
    }

    /// Get the reference counts for an IPID
    pub fn get_ref_counts(&self, ipid: &Ipid) -> Option<(u32, u32)> {
        self.ref_manager.get_counts(ipid)
    }

    /// Look up an IPID entry
    pub fn lookup_ipid(&self, ipid: &Ipid) -> Option<IpidEntry> {
        self.ipid_table.lookup(ipid)
    }

    /// Look up an OID entry
    pub fn lookup_oid(&self, oid: &Oid) -> Option<OidEntry> {
        self.oid_table.lookup(oid)
    }

    /// Pin an object to prevent garbage collection
    pub fn pin_object(&self, oid: &Oid) -> bool {
        self.oid_table.pin(oid)
    }

    /// Unpin an object
    pub fn unpin_object(&self, oid: &Oid) -> bool {
        self.oid_table.unpin(oid)
    }

    /// Get all registered OIDs
    pub fn all_oids(&self) -> Vec<Oid> {
        self.oid_table.get_by_oxid(&self.oxid)
    }

    /// Get all interfaces for an object
    pub fn get_interfaces(&self, oid: &Oid) -> Vec<Ipid> {
        self.ipid_table.get_by_oid(oid)
    }
}

impl Default for ObjectExporter {
    fn default() -> Self {
        Self::new(DualStringArray::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::generate_uuid;

    #[test]
    fn test_object_registration() {
        let exporter = ObjectExporter::new(DualStringArray::new());

        let oid = exporter.register_object();
        assert!(exporter.lookup_oid(&oid).is_some());

        let iid = generate_uuid();
        let ipid = exporter.register_interface(oid, iid).unwrap();
        assert!(exporter.lookup_ipid(&ipid).is_some());

        // Registering same interface should return same IPID
        let ipid2 = exporter.register_interface(oid, iid).unwrap();
        assert_eq!(ipid, ipid2);
    }

    #[test]
    fn test_query_interface() {
        let exporter = ObjectExporter::new(DualStringArray::new());

        let oid = exporter.register_object();
        let iid1 = generate_uuid();
        let iid2 = generate_uuid();

        let ipid1 = exporter.register_interface(oid, iid1).unwrap();
        let ipid2 = exporter.query_interface(&ipid1, &iid2).unwrap();

        assert_ne!(ipid1, ipid2);

        // Query same interface should return same IPID
        let ipid2_again = exporter.query_interface(&ipid1, &iid2).unwrap();
        assert_eq!(ipid2, ipid2_again);
    }

    #[test]
    fn test_reference_counting() {
        let exporter = ObjectExporter::new(DualStringArray::new());

        let oid = exporter.register_object();
        let iid = generate_uuid();
        let ipid = exporter.register_interface(oid, iid).unwrap();

        // Initially has 1 private ref
        let counts = exporter.get_ref_counts(&ipid).unwrap();
        assert_eq!(counts, (0, 1));

        // Add refs
        exporter.add_refs(&ipid, 5, None).unwrap();
        let counts = exporter.get_ref_counts(&ipid).unwrap();
        assert_eq!(counts, (5, 1));

        // Release refs
        let should_release = exporter.release_refs(&ipid, 5, None).unwrap();
        assert!(!should_release); // Still has private ref
    }

    #[test]
    fn test_oxid_resolution() {
        let bindings = DualStringArray::with_tcp_binding("127.0.0.1");
        let exporter = ObjectExporter::new(bindings.clone());

        let result = exporter.resolve_oxid(&exporter.oxid());
        assert!(result.is_some());

        let (_resolved_bindings, ipid) = result.unwrap();
        assert_eq!(ipid, exporter.remunknown_ipid());
    }
}
