//! Ping-based garbage collection
//!
//! DCOM uses a ping-based garbage collection scheme. Clients must periodically
//! ping the server to keep their references alive. If a client fails to ping
//! within the timeout period, its references are released.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use crate::types::{Oid, SetId, Result, DcomError};

/// Default ping period (2 minutes as per MS-DCOM)
pub const DEFAULT_PING_PERIOD: Duration = Duration::from_secs(120);

/// Number of missed pings before timeout
pub const DEFAULT_PING_TIMEOUT_COUNT: u32 = 3;

/// Entry in a ping set
#[derive(Clone, Debug)]
pub struct PingSetEntry {
    /// Set ID
    pub set_id: SetId,
    /// OIDs in this set
    pub oids: HashSet<Oid>,
    /// Last ping time
    pub last_ping: Instant,
    /// Sequence number for complex ping
    pub sequence_num: u16,
    /// Ping period for this set
    pub ping_period: Duration,
}

impl PingSetEntry {
    /// Create a new ping set
    pub fn new(set_id: SetId) -> Self {
        Self {
            set_id,
            oids: HashSet::new(),
            last_ping: Instant::now(),
            sequence_num: 0,
            ping_period: DEFAULT_PING_PERIOD,
        }
    }

    /// Check if this set has timed out
    pub fn is_timed_out(&self) -> bool {
        let timeout = self.ping_period * DEFAULT_PING_TIMEOUT_COUNT;
        self.last_ping.elapsed() > timeout
    }

    /// Update the last ping time
    pub fn touch(&mut self) {
        self.last_ping = Instant::now();
    }
}

/// Garbage collector for DCOM objects
pub struct GarbageCollector {
    /// Ping sets by SetId
    sets: RwLock<HashMap<SetId, PingSetEntry>>,
    /// OID to SetId mapping
    oid_to_set: RwLock<HashMap<Oid, HashSet<SetId>>>,
    /// Ping period
    ping_period: Duration,
}

impl GarbageCollector {
    /// Create a new garbage collector
    pub fn new() -> Self {
        Self {
            sets: RwLock::new(HashMap::new()),
            oid_to_set: RwLock::new(HashMap::new()),
            ping_period: DEFAULT_PING_PERIOD,
        }
    }

    /// Create with custom ping period
    pub fn with_ping_period(ping_period: Duration) -> Self {
        Self {
            sets: RwLock::new(HashMap::new()),
            oid_to_set: RwLock::new(HashMap::new()),
            ping_period,
        }
    }

    /// Handle a simple ping
    pub fn simple_ping(&self, set_id: SetId) -> Result<()> {
        let mut sets = self.sets.write().unwrap();
        let set = sets
            .get_mut(&set_id)
            .ok_or_else(|| DcomError::InvalidData(format!("unknown set: {:?}", set_id)))?;

        set.touch();
        Ok(())
    }

    /// Handle a complex ping
    pub fn complex_ping(
        &self,
        set_id: SetId,
        sequence_num: u16,
        add_oids: &[Oid],
        del_oids: &[Oid],
    ) -> Result<SetId> {
        let mut sets = self.sets.write().unwrap();
        let mut oid_to_set = self.oid_to_set.write().unwrap();

        // Create new set if set_id is 0
        let actual_set_id = if set_id.0 == 0 {
            let new_id = SetId::generate();
            sets.insert(new_id, PingSetEntry::new(new_id));
            new_id
        } else {
            set_id
        };

        let set = sets
            .get_mut(&actual_set_id)
            .ok_or_else(|| DcomError::InvalidData(format!("unknown set: {:?}", actual_set_id)))?;

        // Update sequence number
        set.sequence_num = sequence_num;
        set.touch();

        // Add OIDs
        for oid in add_oids {
            set.oids.insert(*oid);
            oid_to_set
                .entry(*oid)
                .or_insert_with(HashSet::new)
                .insert(actual_set_id);
        }

        // Remove OIDs
        for oid in del_oids {
            set.oids.remove(oid);
            if let Some(set_ids) = oid_to_set.get_mut(oid) {
                set_ids.remove(&actual_set_id);
                if set_ids.is_empty() {
                    oid_to_set.remove(oid);
                }
            }
        }

        Ok(actual_set_id)
    }

    /// Get timed out sets
    pub fn get_timed_out_sets(&self) -> Vec<SetId> {
        let sets = self.sets.read().unwrap();
        sets.values()
            .filter(|s| s.is_timed_out())
            .map(|s| s.set_id)
            .collect()
    }

    /// Remove a set and return the OIDs that are no longer in any set
    pub fn remove_set(&self, set_id: SetId) -> Vec<Oid> {
        let mut sets = self.sets.write().unwrap();
        let mut oid_to_set = self.oid_to_set.write().unwrap();

        let mut orphaned_oids = Vec::new();

        if let Some(set) = sets.remove(&set_id) {
            for oid in set.oids {
                if let Some(set_ids) = oid_to_set.get_mut(&oid) {
                    set_ids.remove(&set_id);
                    if set_ids.is_empty() {
                        oid_to_set.remove(&oid);
                        orphaned_oids.push(oid);
                    }
                }
            }
        }

        orphaned_oids
    }

    /// Check if an OID is in any ping set
    pub fn is_oid_in_set(&self, oid: &Oid) -> bool {
        let oid_to_set = self.oid_to_set.read().unwrap();
        oid_to_set.contains_key(oid)
    }

    /// Get the ping period
    pub fn ping_period(&self) -> Duration {
        self.ping_period
    }

    /// Run garbage collection and return OIDs to release
    pub fn collect(&self) -> Vec<Oid> {
        let timed_out = self.get_timed_out_sets();
        let mut orphaned = Vec::new();

        for set_id in timed_out {
            orphaned.extend(self.remove_set(set_id));
        }

        orphaned
    }

    /// Get all OIDs in a set
    pub fn get_set_oids(&self, set_id: &SetId) -> Option<Vec<Oid>> {
        let sets = self.sets.read().unwrap();
        sets.get(set_id).map(|s| s.oids.iter().cloned().collect())
    }
}

impl Default for GarbageCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_ping() {
        let gc = GarbageCollector::new();

        // Create a set first via complex ping
        let set_id = gc
            .complex_ping(SetId::default(), 1, &[Oid::new(1)], &[])
            .unwrap();

        // Simple ping should work
        gc.simple_ping(set_id).unwrap();

        // Unknown set should fail
        assert!(gc.simple_ping(SetId::new(999)).is_err());
    }

    #[test]
    fn test_complex_ping() {
        let gc = GarbageCollector::new();

        let oid1 = Oid::new(1);
        let oid2 = Oid::new(2);
        let oid3 = Oid::new(3);

        // Create new set with oid1 and oid2
        let set_id = gc
            .complex_ping(SetId::default(), 1, &[oid1, oid2], &[])
            .unwrap();

        assert!(gc.is_oid_in_set(&oid1));
        assert!(gc.is_oid_in_set(&oid2));
        assert!(!gc.is_oid_in_set(&oid3));

        // Add oid3, remove oid1
        gc.complex_ping(set_id, 2, &[oid3], &[oid1]).unwrap();

        assert!(!gc.is_oid_in_set(&oid1));
        assert!(gc.is_oid_in_set(&oid2));
        assert!(gc.is_oid_in_set(&oid3));
    }

    #[test]
    fn test_set_removal() {
        let gc = GarbageCollector::new();

        let oid1 = Oid::new(1);
        let oid2 = Oid::new(2);

        // Create set with both OIDs
        let set_id = gc
            .complex_ping(SetId::default(), 1, &[oid1, oid2], &[])
            .unwrap();

        // Remove the set
        let orphaned = gc.remove_set(set_id);

        // Both OIDs should be orphaned
        assert!(orphaned.contains(&oid1));
        assert!(orphaned.contains(&oid2));
        assert!(!gc.is_oid_in_set(&oid1));
        assert!(!gc.is_oid_in_set(&oid2));
    }
}
