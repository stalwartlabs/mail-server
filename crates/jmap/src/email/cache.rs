/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
            .core
            .storage
            .data
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
            self.inner.cache_threads.get(&account_id).and_then(|t| {
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
                .cache_threads
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
