/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

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
