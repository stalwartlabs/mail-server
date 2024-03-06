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

use std::{collections::HashMap, sync::Arc};

use futures_util::TryFutureExt;
use jmap_proto::{
    error::method::MethodError,
    types::{collection::Collection, property::Property},
};
use utils::lru_cache::LruCached;

use crate::JMAP;

#[derive(Debug, Default)]
pub struct Threads {
    pub threads: HashMap<u32, u32>,
    pub modseq: Option<u64>,
}

impl JMAP {
    pub async fn get_cached_thread_ids(
        &self,
        account_id: u32,
        message_ids: impl Iterator<Item = u32>,
    ) -> Result<Vec<(u32, u32)>, MethodError> {
        // Obtain current state
        let modseq = self
            .store
            .get_last_change_id(account_id, Collection::Thread)
            .map_err(|err| {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                error = ?err,
                                "Failed to retrieve threads last change id");
                MethodError::ServerPartialFail
            })
            .await?;

        // Lock the cache
        let thread_cache = if let Some(thread_cache) =
            self.cache_threads.get(&account_id).and_then(|t| {
                if t.modseq.unwrap_or(0) >= modseq.unwrap_or(0) {
                    Some(t)
                } else {
                    None
                }
            }) {
            thread_cache
        } else {
            let thread_cache = Arc::new(Threads {
                threads: self
                    .get_properties::<u32, _, _>(
                        account_id,
                        Collection::Email,
                        &(),
                        Property::ThreadId,
                    )
                    .await?
                    .into_iter()
                    .collect(),
                modseq,
            });
            self.cache_threads.insert(account_id, thread_cache.clone());
            thread_cache
        };

        // Obtain threadIds for matching messages
        let mut thread_ids = Vec::with_capacity(message_ids.size_hint().0);
        for document_id in message_ids {
            if let Some(thread_id) = thread_cache.threads.get(&document_id) {
                thread_ids.push((document_id, *thread_id));
            }
        }

        Ok(thread_ids)
    }
}
