/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Server, Threads};
use jmap_proto::types::{collection::Collection, property::Property};
use std::future::Future;
use store::{
    BitmapKey, IterateParams, U32_LEN,
    ahash::AHashMap,
    write::{BitmapClass, TagValue, key::DeserializeBigEndian},
};
use trc::AddContext;
use utils::codec::leb128::Leb128Reader;

pub trait ThreadCache: Sync + Send {
    fn get_cached_thread_ids(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<Threads>>> + Send;
}

impl ThreadCache for Server {
    async fn get_cached_thread_ids(&self, account_id: u32) -> trc::Result<Arc<Threads>> {
        // Obtain current state
        let modseq = self
            .core
            .storage
            .data
            .get_last_change_id(account_id, Collection::Thread)
            .await
            .caused_by(trc::location!())?;

        // Lock the cache
        if let Some(thread_cache) = self.inner.cache.threads.get(&account_id).and_then(|t| {
            if t.modseq.unwrap_or(0) >= modseq.unwrap_or(0) {
                Some(t)
            } else {
                None
            }
        }) {
            Ok(thread_cache)
        } else {
            let mut threads = AHashMap::new();
            self.core
                .storage
                .data
                .iterate(
                    IterateParams::new(
                        BitmapKey {
                            account_id,
                            collection: Collection::Email.into(),
                            class: BitmapClass::Tag {
                                field: Property::ThreadId.into(),
                                value: TagValue::Id(0),
                            },
                            document_id: 0,
                        },
                        BitmapKey {
                            account_id,
                            collection: Collection::Email.into(),
                            class: BitmapClass::Tag {
                                field: Property::ThreadId.into(),
                                value: TagValue::Id(u32::MAX),
                            },
                            document_id: u32::MAX,
                        },
                    )
                    .no_values(),
                    |key, _| {
                        let (thread_id, _) = key
                            .get(U32_LEN + 2..)
                            .and_then(|bytes| bytes.read_leb128::<u32>())
                            .ok_or_else(|| {
                                trc::Error::corrupted_key(key, None, trc::location!())
                            })?;
                        let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                        threads.insert(document_id, thread_id);

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            let thread_cache = Arc::new(Threads { threads, modseq });
            self.inner
                .cache
                .threads
                .insert(account_id, thread_cache.clone());
            Ok(thread_cache)
        }
    }
}

/*


        // Obtain threadIds for matching messages
        let mut thread_ids = Vec::with_capacity(message_ids.size_hint().0);
        for document_id in message_ids {
            if let Some(thread_id) = thread_cache.threads.get(&document_id) {
                thread_ids.push((document_id, *thread_id));
            }
        }

        Ok(thread_ids)

*/
