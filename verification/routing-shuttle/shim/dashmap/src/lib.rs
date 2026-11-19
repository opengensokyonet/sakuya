//! The part of the `dashmap` 6 API that `sakuya_sync_std` uses, over one
//! Shuttle `RwLock` per map.
//!
//! Every access takes the lock, as an access to a real shard does, and each
//! acquisition is a scheduling point of Shuttle. One lock serializes accesses
//! to different keys, which real shards may run at once; accesses to one key
//! are ordered the same way. The entries are kept in a vector and found by
//! equality: the maps of the tests hold a few keys.

use std::borrow::Borrow;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use shuttle::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

type Entries<K, V> = Vec<(K, V)>;

fn position<K: Borrow<Q>, V, Q: Eq + ?Sized>(entries: &Entries<K, V>, key: &Q) -> Option<usize> {
    entries
        .iter()
        .position(|(current, _)| current.borrow() == key)
}

/// A map whose accesses each hold its lock.
pub struct DashMap<K, V> {
    entries: RwLock<Entries<K, V>>,
}

impl<K, V> DashMap<K, V> {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + Hash, V> DashMap<K, V> {
    pub fn get<Q>(&self, key: &Q) -> Option<Ref<'_, K, V>>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let guard = self.entries.read().unwrap();
        let index = position(&guard, key)?;
        Some(Ref { guard, index })
    }

    pub fn entry(&self, key: K) -> mapref::entry::Entry<'_, K, V> {
        let guard = self.entries.write().unwrap();
        match position(&guard, &key) {
            Some(index) => {
                mapref::entry::Entry::Occupied(mapref::entry::OccupiedEntry { guard, index })
            }
            None => mapref::entry::Entry::Vacant(mapref::entry::VacantEntry { guard, key }),
        }
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let mut guard = self.entries.write().unwrap();
        match position(&guard, &key) {
            Some(index) => Some(std::mem::replace(&mut guard[index].1, value)),
            None => {
                guard.push((key, value));
                None
            }
        }
    }

    pub fn remove<Q>(&self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let mut guard = self.entries.write().unwrap();
        let index = position(&guard, key)?;
        Some(guard.swap_remove(index))
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        position(&self.entries.read().unwrap(), key).is_some()
    }
}

impl<K, V> Default for DashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A value of a map, read while its lock is held for reading.
pub struct Ref<'a, K, V> {
    guard: RwLockReadGuard<'a, Entries<K, V>>,
    index: usize,
}

impl<K, V> Deref for Ref<'_, K, V> {
    type Target = V;

    fn deref(&self) -> &V {
        &self.guard[self.index].1
    }
}

/// A value of a map, changed while its lock is held for writing.
pub struct RefMut<'a, K, V> {
    guard: RwLockWriteGuard<'a, Entries<K, V>>,
    index: usize,
}

impl<K, V> Deref for RefMut<'_, K, V> {
    type Target = V;

    fn deref(&self) -> &V {
        &self.guard[self.index].1
    }
}

impl<K, V> DerefMut for RefMut<'_, K, V> {
    fn deref_mut(&mut self) -> &mut V {
        &mut self.guard[self.index].1
    }
}

pub mod mapref {
    pub mod entry {
        use shuttle::sync::RwLockWriteGuard;

        use crate::{Entries, RefMut};

        /// The entry of one key, holding the map's lock for writing.
        pub enum Entry<'a, K, V> {
            Occupied(OccupiedEntry<'a, K, V>),
            Vacant(VacantEntry<'a, K, V>),
        }

        pub struct OccupiedEntry<'a, K, V> {
            pub(crate) guard: RwLockWriteGuard<'a, Entries<K, V>>,
            pub(crate) index: usize,
        }

        pub struct VacantEntry<'a, K, V> {
            pub(crate) guard: RwLockWriteGuard<'a, Entries<K, V>>,
            pub(crate) key: K,
        }

        impl<K, V> OccupiedEntry<'_, K, V> {
            pub fn get(&self) -> &V {
                &self.guard[self.index].1
            }

            pub fn get_mut(&mut self) -> &mut V {
                &mut self.guard[self.index].1
            }

            pub fn remove(mut self) -> V {
                self.guard.swap_remove(self.index).1
            }
        }

        impl<'a, K, V> VacantEntry<'a, K, V> {
            pub fn insert(mut self, value: V) -> RefMut<'a, K, V> {
                self.guard.push((self.key, value));
                let index = self.guard.len() - 1;
                RefMut {
                    guard: self.guard,
                    index,
                }
            }
        }
    }
}

/// A set whose accesses each hold its lock.
pub struct DashSet<K> {
    map: DashMap<K, ()>,
}

impl<K> DashSet<K> {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }
}

impl<K: Eq + Hash> DashSet<K> {
    /// Whether `key` was not in the set yet.
    pub fn insert(&self, key: K) -> bool {
        self.map.insert(key, ()).is_none()
    }

    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.contains_key(key)
    }

    pub fn remove<Q>(&self, key: &Q) -> Option<K>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.map.remove(key).map(|(key, ())| key)
    }
}

impl<K> Default for DashSet<K> {
    fn default() -> Self {
        Self::new()
    }
}
