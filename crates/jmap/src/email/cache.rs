/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Server, Threads};
use jmap_proto::types::{collection::Collection, property::Property};
use std::future::Future;
use trc::AddContext;
use utils::lru_cache::LruCached;

use crate::JmapMethods;

pub trait ThreadCache: Sync + Send {
    fn get_cached_thread_ids(
        &self,
        account_id: u32,
        message_ids: impl Iterator<Item = u32> + Send,
    ) -> impl Future<Output = trc::Result<Vec<(u32, u32)>>> + Send;
}

impl ThreadCache for Server {
    async fn get_cached_thread_ids(
        &self,
        account_id: u32,
        message_ids: impl Iterator<Item = u32> + Send,
    ) -> trc::Result<Vec<(u32, u32)>> {
        // Obtain current state
        let modseq = self
            .core
            .storage
            .data
            .get_last_change_id(account_id, Collection::Thread)
            .await
            .caused_by(trc::location!())?;

        // Lock the cache
        let thread_cache = if let Some(thread_cache) = self
            .inner
            .data
            .threads_cache
            .get(&account_id)
            .and_then(|t| {
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
            self.inner
                .data
                .threads_cache
                .insert(account_id, thread_cache.clone());
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
