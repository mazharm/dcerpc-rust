//! Distributed reference counting
//!
//! DCOM uses distributed reference counting to manage object lifetimes.
//! Objects are kept alive as long as there are references from remote clients.

use std::collections::HashMap;
use std::sync::RwLock;
use crate::types::{Oid, Ipid, Result, DcomError};

/// Reference count entry for an interface
#[derive(Clone, Debug)]
pub struct RefCountEntry {
    /// Interface pointer ID
    pub ipid: Ipid,
    /// Object ID
    pub oid: Oid,
    /// Public references (from remote clients)
    pub public_refs: u32,
    /// Private references (local references)
    pub private_refs: u32,
    /// References held by specific clients (by causality ID hash)
    pub client_refs: HashMap<u64, u32>,
}

impl RefCountEntry {
    /// Create a new reference count entry
    pub fn new(ipid: Ipid, oid: Oid) -> Self {
        Self {
            ipid,
            oid,
            public_refs: 0,
            private_refs: 1, // Initial local reference
            client_refs: HashMap::new(),
        }
    }

    /// Total reference count
    pub fn total_refs(&self) -> u32 {
        self.public_refs + self.private_refs
    }

    /// Check if the object should be released
    pub fn should_release(&self) -> bool {
        self.total_refs() == 0
    }
}

/// Reference counting manager
pub struct RefCountManager {
    /// Reference counts by IPID
    entries: RwLock<HashMap<Ipid, RefCountEntry>>,
}

impl RefCountManager {
    /// Create a new reference count manager
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new interface for reference counting
    pub fn register(&self, ipid: Ipid, oid: Oid) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(ipid, RefCountEntry::new(ipid, oid));
    }

    /// Add public references (from RemAddRef)
    pub fn add_public_refs(&self, ipid: &Ipid, count: u32, client_id: Option<u64>) -> Result<u32> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(ipid)
            .ok_or_else(|| DcomError::InterfaceNotFound(ipid.to_string()))?;

        entry.public_refs = entry.public_refs.saturating_add(count);

        if let Some(client) = client_id {
            *entry.client_refs.entry(client).or_insert(0) += count;
        }

        Ok(entry.public_refs)
    }

    /// Release public references (from RemRelease)
    pub fn release_public_refs(
        &self,
        ipid: &Ipid,
        count: u32,
        client_id: Option<u64>,
    ) -> Result<(u32, bool)> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(ipid)
            .ok_or_else(|| DcomError::InterfaceNotFound(ipid.to_string()))?;

        entry.public_refs = entry.public_refs.saturating_sub(count);

        if let Some(client) = client_id {
            if let Some(client_count) = entry.client_refs.get_mut(&client) {
                *client_count = client_count.saturating_sub(count);
                if *client_count == 0 {
                    entry.client_refs.remove(&client);
                }
            }
        }

        let should_release = entry.should_release();
        Ok((entry.public_refs, should_release))
    }

    /// Add a private reference (local)
    pub fn add_private_ref(&self, ipid: &Ipid) -> Result<u32> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(ipid)
            .ok_or_else(|| DcomError::InterfaceNotFound(ipid.to_string()))?;

        entry.private_refs = entry.private_refs.saturating_add(1);
        Ok(entry.private_refs)
    }

    /// Release a private reference (local)
    pub fn release_private_ref(&self, ipid: &Ipid) -> Result<(u32, bool)> {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(ipid)
            .ok_or_else(|| DcomError::InterfaceNotFound(ipid.to_string()))?;

        entry.private_refs = entry.private_refs.saturating_sub(1);
        let should_release = entry.should_release();
        Ok((entry.private_refs, should_release))
    }

    /// Get the current reference counts
    pub fn get_counts(&self, ipid: &Ipid) -> Option<(u32, u32)> {
        let entries = self.entries.read().unwrap();
        entries.get(ipid).map(|e| (e.public_refs, e.private_refs))
    }

    /// Remove an entry
    pub fn remove(&self, ipid: &Ipid) -> Option<RefCountEntry> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(ipid)
    }

    /// Get all IPIDs with zero references
    pub fn get_zero_ref_ipids(&self) -> Vec<Ipid> {
        let entries = self.entries.read().unwrap();
        entries
            .values()
            .filter(|e| e.should_release())
            .map(|e| e.ipid)
            .collect()
    }

    /// Release all references for a specific client
    pub fn release_client_refs(&self, client_id: u64) -> Vec<(Ipid, bool)> {
        let mut entries = self.entries.write().unwrap();
        let mut results = Vec::new();

        for entry in entries.values_mut() {
            if let Some(count) = entry.client_refs.remove(&client_id) {
                entry.public_refs = entry.public_refs.saturating_sub(count);
                results.push((entry.ipid, entry.should_release()));
            }
        }

        results
    }
}

impl Default for RefCountManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch reference operation
#[derive(Clone, Debug)]
pub struct RefOperation {
    /// IPID to operate on
    pub ipid: Ipid,
    /// Number of public references to add (positive) or release (negative encoded as count)
    pub public_refs: i32,
    /// Number of private references to add
    pub private_refs: i32,
}

impl RefOperation {
    /// Create an add-ref operation
    pub fn add_ref(ipid: Ipid, public: u32, private: u32) -> Self {
        Self {
            ipid,
            public_refs: public as i32,
            private_refs: private as i32,
        }
    }

    /// Create a release operation
    pub fn release(ipid: Ipid, public: u32, private: u32) -> Self {
        Self {
            ipid,
            public_refs: -(public as i32),
            private_refs: -(private as i32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_counting() {
        let manager = RefCountManager::new();
        let ipid = Ipid::generate();
        let oid = Oid::generate();

        manager.register(ipid, oid);

        // Initially has 1 private ref
        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts, (0, 1));

        // Add public refs
        manager.add_public_refs(&ipid, 5, None).unwrap();
        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts, (5, 1));

        // Release some
        let (_, should_release) = manager.release_public_refs(&ipid, 3, None).unwrap();
        assert!(!should_release);
        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts, (2, 1));

        // Release private ref
        manager.release_private_ref(&ipid).unwrap();
        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts, (2, 0));

        // Release remaining public refs
        let (_, should_release) = manager.release_public_refs(&ipid, 2, None).unwrap();
        assert!(should_release);
    }

    #[test]
    fn test_client_tracking() {
        let manager = RefCountManager::new();
        let ipid = Ipid::generate();
        let oid = Oid::generate();

        manager.register(ipid, oid);

        // Add refs from two clients
        manager.add_public_refs(&ipid, 3, Some(100)).unwrap();
        manager.add_public_refs(&ipid, 2, Some(200)).unwrap();

        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts.0, 5);

        // Release all refs from client 100
        let results = manager.release_client_refs(100);
        assert_eq!(results.len(), 1);

        let counts = manager.get_counts(&ipid).unwrap();
        assert_eq!(counts.0, 2);
    }
}
