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

use jmap_proto::types::{collection::Collection, property::Property};
use store::{ahash::AHashMap, write::ValueClass, ValueKey};
use utils::CachedItem;

use crate::JMAP;

#[derive(Debug, Default)]
pub struct Threads {
    pub threads: AHashMap<u32, u32>,
    pub modseq: Option<u64>,
}

impl JMAP {
    pub async fn get_cached_thread_ids(
        &self,
        account_id: u32,
        message_ids: impl Iterator<Item = u32>,
    ) -> store::Result<Vec<Option<u32>>> {
        // Obtain current state
        let modseq = self
            .store
            .get_last_change_id(account_id, Collection::Thread)
            .await?;

        // Lock the cache
        let thread_cache_ = self
            .cache_threads
            .entry(account_id)
            .or_insert_with(|| CachedItem::new(Threads::default()));
        let mut thread_cache = thread_cache_.get().await;

        // Invalidate cache if the modseq has changed
        if thread_cache.modseq != modseq {
            thread_cache.threads.clear();
        }

        // Obtain threadIds for matching messages
        let mut thread_ids = Vec::with_capacity(message_ids.size_hint().0);
        for document_id in message_ids {
            if let Some(thread_id) = thread_cache.threads.get(&document_id) {
                thread_ids.push((*thread_id).into());
            } else if let Some(thread_id) = self
                .store
                .get_value::<u32>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(Property::ThreadId.into()),
                })
                .await?
            {
                thread_ids.push(thread_id.into());
                thread_cache.threads.insert(document_id, thread_id);
            } else {
                thread_ids.push(None);
            }
        }
        thread_cache.modseq = modseq;

        Ok(thread_ids)
    }
}
