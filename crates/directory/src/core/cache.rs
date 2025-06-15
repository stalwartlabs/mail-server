/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use utils::{
    cache::CacheWithTtl,
    config::{Config, utils::AsKey},
};

use crate::backend::RcptType;

pub struct CachedDirectory {
    cached_domains: CacheWithTtl<String, bool>,
    cached_rcpts: CacheWithTtl<String, bool>,
    ttl_pos: Duration,
    ttl_neg: Duration,
}

impl CachedDirectory {
    pub fn try_from_config(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let cached_size = config
            .property_or_default::<Option<u64>>((&prefix, "cache.size"), "1048576")
            .unwrap_or_default()?;

        Some(CachedDirectory {
            cached_domains: CacheWithTtl::new(50, cached_size),
            cached_rcpts: CacheWithTtl::new(100, cached_size),
            ttl_pos: config
                .property((&prefix, "cache.ttl.positive"))
                .unwrap_or(Duration::from_secs(86400)),
            ttl_neg: config
                .property((&prefix, "cache.ttl.negative"))
                .unwrap_or_else(|| Duration::from_secs(3600)),
        })
    }

    pub fn get_rcpt(&self, address: &str) -> Option<RcptType> {
        self.cached_rcpts.get(address).map(Into::into)
    }

    pub fn set_rcpt(&self, address: &str, exists: &RcptType) {
        let (exists, ttl) = match exists {
            RcptType::Mailbox => (true, self.ttl_pos),
            RcptType::Invalid => (false, self.ttl_neg),
            RcptType::List(_) => return,
        };

        self.cached_rcpts.insert(address.to_string(), exists, ttl);
    }

    pub fn get_domain(&self, domain: &str) -> Option<bool> {
        self.cached_domains.get(domain)
    }

    pub fn set_domain(&self, domain: &str, exists: bool) {
        self.cached_domains.insert(
            domain.to_string(),
            exists,
            if exists { self.ttl_pos } else { self.ttl_neg },
        );
    }
}
