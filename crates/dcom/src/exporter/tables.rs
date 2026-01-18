//! OXID/OID/IPID table management
//!
//! These tables track the relationships between exporters, objects, and interfaces.

use std::collections::HashMap;
use std::sync::RwLock;
use crate::types::{Oxid, Oid, Ipid, DualStringArray};

/// Entry in the OXID table
#[derive(Clone, Debug)]
pub struct OxidEntry {
    /// The OXID value
    pub oxid: Oxid,
    /// Binding strings for this OXID
    pub bindings: DualStringArray,
    /// IPID for IRemUnknown on this OXID
    pub remunknown_ipid: Ipid,
    /// Objects registered under this OXID
    pub objects: Vec<Oid>,
}

impl OxidEntry {
    /// Create a new OXID entry
    pub fn new(oxid: Oxid, bindings: DualStringArray, remunknown_ipid: Ipid) -> Self {
        Self {
            oxid,
            bindings,
            remunknown_ipid,
            objects: Vec::new(),
        }
    }
}

/// Entry in the OID table
#[derive(Clone, Debug)]
pub struct OidEntry {
    /// The OID value
    pub oid: Oid,
    /// The OXID this object belongs to
    pub oxid: Oxid,
    /// Interfaces registered on this object
    pub interfaces: Vec<Ipid>,
    /// Whether this object is pinned (won't be garbage collected)
    pub pinned: bool,
}

impl OidEntry {
    /// Create a new OID entry
    pub fn new(oid: Oid, oxid: Oxid) -> Self {
        Self {
            oid,
            oxid,
            interfaces: Vec::new(),
            pinned: false,
        }
    }
}

/// Entry in the IPID table
#[derive(Clone, Debug)]
pub struct IpidEntry {
    /// The IPID value
    pub ipid: Ipid,
    /// The OID this interface belongs to
    pub oid: Oid,
    /// Interface IID
    pub iid: dcerpc::Uuid,
    /// Public reference count (from remote clients)
    pub public_refs: u32,
    /// Private reference count (local references)
    pub private_refs: u32,
}

impl IpidEntry {
    /// Create a new IPID entry
    pub fn new(ipid: Ipid, oid: Oid, iid: dcerpc::Uuid) -> Self {
        Self {
            ipid,
            oid,
            iid,
            public_refs: 0,
            private_refs: 1, // Local reference
        }
    }

    /// Total reference count
    pub fn total_refs(&self) -> u32 {
        self.public_refs + self.private_refs
    }
}

/// Thread-safe table for OXIDs
pub struct OxidTable {
    entries: RwLock<HashMap<Oxid, OxidEntry>>,
}

impl OxidTable {
    /// Create a new OXID table
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new OXID
    pub fn register(&self, entry: OxidEntry) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(entry.oxid, entry);
    }

    /// Look up an OXID
    pub fn lookup(&self, oxid: &Oxid) -> Option<OxidEntry> {
        let entries = self.entries.read().unwrap();
        entries.get(oxid).cloned()
    }

    /// Remove an OXID
    pub fn remove(&self, oxid: &Oxid) -> Option<OxidEntry> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(oxid)
    }

    /// Add an object to an OXID
    pub fn add_object(&self, oxid: &Oxid, oid: Oid) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(oxid) {
            entry.objects.push(oid);
            true
        } else {
            false
        }
    }

    /// Get all registered OXIDs
    pub fn all_oxids(&self) -> Vec<Oxid> {
        let entries = self.entries.read().unwrap();
        entries.keys().cloned().collect()
    }
}

impl Default for OxidTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe table for OIDs
pub struct OidTable {
    entries: RwLock<HashMap<Oid, OidEntry>>,
}

impl OidTable {
    /// Create a new OID table
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new OID
    pub fn register(&self, entry: OidEntry) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(entry.oid, entry);
    }

    /// Look up an OID
    pub fn lookup(&self, oid: &Oid) -> Option<OidEntry> {
        let entries = self.entries.read().unwrap();
        entries.get(oid).cloned()
    }

    /// Remove an OID
    pub fn remove(&self, oid: &Oid) -> Option<OidEntry> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(oid)
    }

    /// Add an interface to an OID
    pub fn add_interface(&self, oid: &Oid, ipid: Ipid) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(oid) {
            entry.interfaces.push(ipid);
            true
        } else {
            false
        }
    }

    /// Pin an OID (prevent garbage collection)
    pub fn pin(&self, oid: &Oid) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(oid) {
            entry.pinned = true;
            true
        } else {
            false
        }
    }

    /// Unpin an OID
    pub fn unpin(&self, oid: &Oid) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(oid) {
            entry.pinned = false;
            true
        } else {
            false
        }
    }

    /// Check if an OID exists
    pub fn contains(&self, oid: &Oid) -> bool {
        let entries = self.entries.read().unwrap();
        entries.contains_key(oid)
    }

    /// Get all OIDs for a given OXID
    pub fn get_by_oxid(&self, oxid: &Oxid) -> Vec<Oid> {
        let entries = self.entries.read().unwrap();
        entries
            .values()
            .filter(|e| &e.oxid == oxid)
            .map(|e| e.oid)
            .collect()
    }
}

impl Default for OidTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe table for IPIDs
pub struct IpidTable {
    entries: RwLock<HashMap<Ipid, IpidEntry>>,
}

impl IpidTable {
    /// Create a new IPID table
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new IPID
    pub fn register(&self, entry: IpidEntry) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(entry.ipid, entry);
    }

    /// Look up an IPID
    pub fn lookup(&self, ipid: &Ipid) -> Option<IpidEntry> {
        let entries = self.entries.read().unwrap();
        entries.get(ipid).cloned()
    }

    /// Remove an IPID
    pub fn remove(&self, ipid: &Ipid) -> Option<IpidEntry> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(ipid)
    }

    /// Add public references
    pub fn add_public_refs(&self, ipid: &Ipid, count: u32) -> Option<u32> {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(ipid) {
            entry.public_refs = entry.public_refs.saturating_add(count);
            Some(entry.public_refs)
        } else {
            None
        }
    }

    /// Release public references
    pub fn release_public_refs(&self, ipid: &Ipid, count: u32) -> Option<u32> {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(ipid) {
            entry.public_refs = entry.public_refs.saturating_sub(count);
            Some(entry.public_refs)
        } else {
            None
        }
    }

    /// Get all IPIDs for a given OID
    pub fn get_by_oid(&self, oid: &Oid) -> Vec<Ipid> {
        let entries = self.entries.read().unwrap();
        entries
            .values()
            .filter(|e| &e.oid == oid)
            .map(|e| e.ipid)
            .collect()
    }

    /// Find IPID by OID and IID
    pub fn find_by_oid_and_iid(&self, oid: &Oid, iid: &dcerpc::Uuid) -> Option<Ipid> {
        let entries = self.entries.read().unwrap();
        entries
            .values()
            .find(|e| &e.oid == oid && &e.iid == iid)
            .map(|e| e.ipid)
    }
}

impl Default for IpidTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oxid_table() {
        let table = OxidTable::new();
        let oxid = Oxid::generate();
        let entry = OxidEntry::new(oxid, DualStringArray::new(), Ipid::generate());

        table.register(entry.clone());
        assert!(table.lookup(&oxid).is_some());

        table.remove(&oxid);
        assert!(table.lookup(&oxid).is_none());
    }

    #[test]
    fn test_oid_table() {
        let table = OidTable::new();
        let oid = Oid::generate();
        let oxid = Oxid::generate();
        let entry = OidEntry::new(oid, oxid);

        table.register(entry);
        assert!(table.contains(&oid));

        table.pin(&oid);
        let entry = table.lookup(&oid).unwrap();
        assert!(entry.pinned);
    }

    #[test]
    fn test_ipid_table_refs() {
        let table = IpidTable::new();
        let ipid = Ipid::generate();
        let oid = Oid::generate();
        let entry = IpidEntry::new(ipid, oid, dcerpc::Uuid::NIL);

        table.register(entry);

        // Add refs
        let count = table.add_public_refs(&ipid, 5).unwrap();
        assert_eq!(count, 5);

        // Release some
        let count = table.release_public_refs(&ipid, 2).unwrap();
        assert_eq!(count, 3);
    }
}
