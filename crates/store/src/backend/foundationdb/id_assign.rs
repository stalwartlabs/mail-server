/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use crate::{write::key::DeserializeBigEndian, Deserialize, Key, Serialize, U32_LEN};
use ahash::AHashSet;
use foundationdb::{options::StreamingMode, FdbError, KeySelector, RangeOption};
use futures::StreamExt;
use rand::Rng;
use std::time::Instant;

use crate::{write::now, BitmapKey, IndexKey};

use super::{
    bitmap::{next_available_index, BITS_PER_BLOCK},
    write::MAX_COMMIT_TIME,
    FdbStore,
};

impl FdbStore {
    pub(crate) async fn assign_document_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<u32> {
        let start = Instant::now();
        let collection = collection.into();

        loop {
            // First try to reuse an expired assigned id
            let trx = self.db.create_trx()?;
            let mut reserved_ids = AHashSet::new();
            let mut expired_ids = Vec::new();
            {
                let begin = IndexKey {
                    account_id,
                    collection,
                    document_id: 0,
                    field: u8::MAX,
                    key: &[],
                }
                .serialize(true);
                let end = IndexKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    field: u8::MAX,
                    key: &[],
                }
                .serialize(true);

                let mut values = trx.get_ranges(
                    RangeOption {
                        begin: KeySelector::first_greater_or_equal(begin),
                        end: KeySelector::first_greater_or_equal(end),
                        mode: StreamingMode::Iterator,
                        reverse: false,
                        ..RangeOption::default()
                    },
                    true,
                );

                #[cfg(not(feature = "test_mode"))]
                let expired_timestamp = now() - ID_ASSIGNMENT_EXPIRY;
                #[cfg(feature = "test_mode")]
                let expired_timestamp = now()
                    - crate::backend::ID_ASSIGNMENT_EXPIRY
                        .load(std::sync::atomic::Ordering::Relaxed);
                while let Some(values) = values.next().await {
                    for value in values? {
                        let key = value.key();
                        let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                        if u64::deserialize(value.value())? <= expired_timestamp {
                            // Found an expired id, reuse it
                            expired_ids.push(document_id);
                        } else {
                            // Keep track of all reserved ids
                            reserved_ids.insert(document_id);
                        }
                    }
                }
            }

            let mut document_id = u32::MAX;

            if !expired_ids.is_empty() {
                // Obtain a random id from the expired ids
                if expired_ids.len() > 1 {
                    document_id = expired_ids[rand::thread_rng().gen_range(0..expired_ids.len())];
                } else {
                    document_id = expired_ids[0];
                }
            } else {
                // Find the next available id
                let mut key = BitmapKey::document_ids(account_id, collection);
                let begin = key.serialize(true);
                key.block_num = u32::MAX;
                let end = key.serialize(true);
                let mut values = trx.get_ranges(
                    RangeOption {
                        begin: KeySelector::first_greater_or_equal(begin),
                        end: KeySelector::first_greater_or_equal(end),
                        mode: StreamingMode::Iterator,
                        reverse: false,
                        ..RangeOption::default()
                    },
                    true,
                );

                'outer: while let Some(values) = values.next().await {
                    for value in values? {
                        let key = value.key();
                        if let Some(next_id) = next_available_index(
                            value.value(),
                            key.deserialize_be_u32(key.len() - U32_LEN)?,
                            &reserved_ids,
                        ) {
                            document_id = next_id;
                            //assign_source = 3;

                            break 'outer;
                        }
                    }
                }
            }

            // If no ids were found, assign the first available id that is not reserved
            if document_id == u32::MAX {
                document_id = 1024;
                for document_id_ in 0..BITS_PER_BLOCK {
                    if !reserved_ids.contains(&document_id_) {
                        document_id = document_id_;
                        break;
                    }
                }
            }

            // Reserve the id
            let key = IndexKey {
                account_id,
                collection,
                document_id,
                field: u8::MAX,
                key: &[],
            }
            .serialize(true);
            trx.get(&key, false).await?; // Read to create conflict range
            trx.set(&key, &now().serialize());

            match trx.commit().await {
                Ok(_) => {
                    return Ok(document_id);
                }
                Err(err) => {
                    if start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }
}
