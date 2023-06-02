use parking_lot::Mutex;

use crate::Directory;

use self::lru::LookupCache;

pub mod config;
pub mod lookup;
pub mod lru;

pub struct CachedDirectory<T: Directory> {
    inner: T,
    cached_domains: Mutex<LookupCache<String>>,
    cached_rcpts: Mutex<LookupCache<String>>,
}
