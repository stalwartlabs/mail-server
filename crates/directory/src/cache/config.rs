use std::{sync::Arc, time::Duration};

use parking_lot::lock_api::Mutex;
use utils::config::Config;

use crate::Directory;

use super::{lru::LookupCache, CachedDirectory};

impl<T: Directory + 'static> CachedDirectory<T> {
    pub fn try_from_config(
        config: &Config,
        prefix: &str,
        inner: T,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        if let Some(cached_entries) = config.property((prefix, "cache.entries"))? {
            let cache_ttl_positive = config
                .property((prefix, "cache.ttl.positive"))?
                .unwrap_or(Duration::from_secs(86400));
            let cache_ttl_negative = config
                .property((prefix, "cache.ttl.positive"))?
                .unwrap_or_else(|| Duration::from_secs(3600));

            Ok(Arc::new(CachedDirectory {
                inner,
                cached_domains: Mutex::new(LookupCache::new(
                    cached_entries,
                    cache_ttl_positive,
                    cache_ttl_negative,
                )),
                cached_rcpts: Mutex::new(LookupCache::new(
                    cached_entries,
                    cache_ttl_positive,
                    cache_ttl_negative,
                )),
            }))
        } else {
            Ok(Arc::new(inner))
        }
    }
}
