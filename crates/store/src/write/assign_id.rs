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

use std::time::Instant;

use crate::{
    backend::ID_ASSIGNMENT_EXPIRY, write::key::DeserializeBigEndian, Deserialize, IterateParams,
    Serialize, Store, ValueKey, U32_LEN,
};
use ahash::AHashMap;
use rand::Rng;
use roaring::RoaringBitmap;

use crate::{write::now, BitmapKey};

use super::{BatchBuilder, ValueClass, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME};

impl Store {
    pub async fn assign_document_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<u32> {
        let start = Instant::now();
        let mut retry_count = 0;
        let collection = collection.into();

        loop {
            // First try to reuse an expired assigned id
            let mut reserved_ids = RoaringBitmap::new();
            let mut expired_ids = AHashMap::new();
            {
                let from_key = ValueKey {
                    account_id,
                    collection,
                    document_id: 0,
                    class: ValueClass::ReservedId,
                };
                let to_key = ValueKey {
                    account_id,
                    collection,
                    document_id: u32::MAX,
                    class: ValueClass::ReservedId,
                };

                let expired_timestamp = now();
                self.iterate(
                    IterateParams::new(from_key, to_key).ascending(),
                    |key, value| {
                        let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                        let ttl = u64::deserialize(value)?;

                        if ttl <= expired_timestamp {
                            // Found an expired id, reuse it
                            expired_ids.insert(document_id, ttl);
                        } else {
                            // Keep track of all reserved ids
                            reserved_ids.insert(document_id);
                        }

                        Ok(true)
                    },
                )
                .await?;
            }

            // Prepare the patch the id
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(collection);

            let document_id = if !expired_ids.is_empty() {
                // Obtain a random id from the expired ids
                let pos = if expired_ids.len() > 1 {
                    rand::thread_rng().gen_range(0..expired_ids.len())
                } else {
                    0
                };
                let (document_id, expiry) = expired_ids.into_iter().nth(pos).unwrap();

                batch
                    .update_document(document_id)
                    .assert_value(ValueClass::ReservedId, expiry);
                document_id
            } else {
                // Obtain documentIds
                let document_ids = if let Some(document_ids) = self
                    .get_bitmap(BitmapKey::document_ids(account_id, collection))
                    .await?
                {
                    if !reserved_ids.is_empty() {
                        document_ids | reserved_ids
                    } else {
                        document_ids
                    }
                } else {
                    reserved_ids
                };

                let document_id = if retry_count == 0 {
                    // Find the next available id
                    (0..(document_ids.len() + 1) as u32)
                        .find(|&x| !document_ids.contains(x))
                        .unwrap()
                } else {
                    // High contention, pick a random id
                    const RAND_IDS: usize = 10;
                    let mut available_ids = Vec::with_capacity(RAND_IDS);
                    for id in 0..(document_ids.len() as u32 + RAND_IDS as u32) {
                        if !document_ids.contains(id) {
                            available_ids.push(id);
                            if available_ids.len() == RAND_IDS {
                                break;
                            }
                        }
                    }
                    available_ids[rand::thread_rng().gen_range(0..available_ids.len())]
                };

                batch
                    .update_document(document_id)
                    .assert_value(ValueClass::ReservedId, ());
                document_id
            };

            #[cfg(not(feature = "test_mode"))]
            let expired_timestamp = now() + ID_ASSIGNMENT_EXPIRY;
            #[cfg(feature = "test_mode")]
            let expired_timestamp =
                now() + ID_ASSIGNMENT_EXPIRY.load(std::sync::atomic::Ordering::Relaxed);

            batch.set(ValueClass::ReservedId, expired_timestamp.serialize());

            match self.write(batch.build()).await {
                Ok(_) => {
                    return Ok(document_id);
                }
                Err(crate::Error::AssertValueFailed)
                    if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME =>
                {
                    // Retry
                    retry_count += 1;
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }
}
