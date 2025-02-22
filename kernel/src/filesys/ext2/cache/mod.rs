use alloc::sync::Arc;
use core::{
    hash::Hash,
    sync::atomic::{AtomicU64, Ordering},
};
use spin::Mutex;

pub mod block;
pub mod inode;

pub use block::BlockCache;
pub use inode::InodeCache;

/// Represents errors that can occur during cache operations
#[derive(Debug)]
pub enum CacheError {
    /// Item not found in cache
    NotFound,
    /// Error loading item from backing store
    LoadError,
    /// Error writing item back to storage
    WriteError,
    /// Cache is full and no items can be evicted
    CacheFull,
}

pub type CacheResult<T> = Result<T, CacheError>;

/// Trait for cached items that can be written back to storage
pub trait CacheableItem: Clone {
    /// Whether this item has been modified and needs writing back
    fn is_dirty(&self) -> bool;

    /// Mark this item as clean (after writing back)
    fn mark_clean(&mut self);

    /// Mark this item as dirty (after modification)
    fn mark_dirty(&mut self);
}

/// Statistics for cache operations
#[derive(Clone, Default, Debug)]
pub struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    writebacks: u64,
}

impl CacheStats {
    /// Get current statistics
    pub fn get(&self) -> (u64, u64, u64, u64) {
        (self.hits, self.misses, self.evictions, self.writebacks)
    }

    /// Calculate hit rate as percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Trait for cache implementations
pub trait Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: CacheableItem,
{
    /// Get an item from the cache, loading it if necessary
    fn get(&self, key: K) -> CacheResult<Arc<Mutex<V>>>;

    /// Insert an item into the cache
    fn insert(&self, key: K, value: V) -> CacheResult<()>;

    /// Remove an item from the cache, writing back if dirty
    fn remove(&self, key: &K) -> CacheResult<()>;

    /// Clear all items from the cache, writing back dirty items
    fn clear(&self) -> CacheResult<()>;

    /// Get cache statistics
    fn stats(&self) -> CacheStats;
}

/// Helper struct for items in the cache
#[derive(Debug)]
struct CacheEntry<V: CacheableItem> {
    value: Arc<Mutex<V>>,
    last_access: u64,
    access_count: u64,
}

impl<V: CacheableItem> CacheEntry<V> {
    fn new(value: V) -> Self {
        Self {
            value: Arc::new(Mutex::new(value)),
            last_access: 0,
            access_count: 0,
        }
    }

    fn touch(&mut self, timestamp: u64) {
        self.last_access = timestamp;
        self.access_count += 1;
    }
}

/// Base implementation of cache functionality
pub(crate) struct CacheBase<K, V>
where
    K: Eq + Hash + Clone,
    V: CacheableItem,
{
    // Implementation details will be filled in by specific cache types
    _marker: core::marker::PhantomData<(K, V)>,
}

/// Trait for implementing the storage backend of a cache
pub(crate) trait CacheStorage<K, V>
where
    K: Eq + Hash + Clone,
    V: CacheableItem,
{
    /// Load an item from storage
    fn load(&self, key: &K) -> CacheResult<V>;

    /// Write an item back to storage
    fn write(&self, key: &K, value: &V) -> CacheResult<()>;
}

/// Clock source for cache entry aging
pub(crate) trait Clock {
    /// Get current timestamp for cache entry aging
    fn now(&self) -> u64;
}

/// Simple monotonic clock
#[derive(Default)]
pub(crate) struct MonotonicClock(AtomicU64);

impl Clock for MonotonicClock {
    fn now(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}
