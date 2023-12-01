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

use std::time::{Duration, Instant};

use ahash::AHashMap;
use foundationdb::{options::MutationType, FdbError};
use rand::Rng;

use crate::{
    write::{
        bitmap::{block_contains, DenseBitmap},
        Batch, BitmapClass, Operation, ValueClass, ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, BlobKey, IndexKey, Key, LogKey, ValueKey,
};

use super::FdbStore;

#[cfg(feature = "test_mode")]
lazy_static::lazy_static! {
pub static ref BITMAPS: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<Vec<u8>, std::collections::HashSet<u32>>>> =
                    std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
}

impl FdbStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut set_bitmaps = AHashMap::new();
        let mut clear_bitmaps = AHashMap::new();

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;

            let trx = self.db.create_trx()?;

            for op in &batch.ops {
                match op {
                    Operation::AccountId {
                        account_id: account_id_,
                    } => {
                        account_id = *account_id_;
                    }
                    Operation::Collection {
                        collection: collection_,
                    } => {
                        collection = *collection_;
                    }
                    Operation::DocumentId {
                        document_id: document_id_,
                    } => {
                        document_id = *document_id_;
                    }
                    Operation::Value {
                        class,
                        op: ValueOp::Add(by),
                    } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(true);

                        trx.atomic_op(&key, &by.to_le_bytes()[..], MutationType::Add);
                    }
                    Operation::Value { class, op } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(true);

                        if let ValueOp::Set(value) = op {
                            trx.set(&key, value);

                            if matches!(class, ValueClass::ReservedId) {
                                let block_num = DenseBitmap::block_num(document_id);
                                if let Ok(Some(bytes)) = trx
                                    .get(
                                        &BitmapKey {
                                            account_id,
                                            collection,
                                            class: BitmapClass::DocumentIds,
                                            block_num,
                                        }
                                        .serialize(true),
                                        true,
                                    )
                                    .await
                                {
                                    if block_contains(&bytes, block_num, document_id) {
                                        trx.cancel();
                                        return Err(crate::Error::AssertValueFailed);
                                    }
                                }
                            }
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Index { field, key, set } => {
                        let key = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }
                        .serialize(true);

                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        if retry_count == 0 {
                            if *set {
                                &mut set_bitmaps
                            } else {
                                &mut clear_bitmaps
                            }
                            .entry(
                                BitmapKey {
                                    account_id,
                                    collection,
                                    class,
                                    block_num: DenseBitmap::block_num(document_id),
                                }
                                .serialize(true),
                            )
                            .or_insert_with(DenseBitmap::empty)
                            .set(document_id);
                        }
                    }
                    Operation::Blob { hash, op, set } => {
                        let key = BlobKey {
                            account_id,
                            collection,
                            document_id,
                            hash,
                            op: *op,
                        }
                        .serialize(true);

                        if *set {
                            trx.set(&key, &[]);
                        } else {
                            trx.clear(&key);
                        }
                    }
                    Operation::Log {
                        collection,
                        change_id,
                        set,
                    } => {
                        let key = LogKey {
                            account_id,
                            collection: *collection,
                            change_id: *change_id,
                        }
                        .serialize(true);
                        trx.set(&key, set);
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(true);

                        let matches = if let Ok(bytes) = trx.get(&key, false).await {
                            if let Some(bytes) = bytes {
                                assert_value.matches(bytes.as_ref())
                            } else {
                                assert_value.is_none()
                            }
                        } else {
                            false
                        };

                        if !matches {
                            trx.cancel();
                            return Err(crate::Error::AssertValueFailed);
                        }
                    }
                }
            }

            for (key, bitmap) in &set_bitmaps {
                trx.atomic_op(key, &bitmap.bitmap, MutationType::BitOr);
            }

            for (key, bitmap) in &clear_bitmaps {
                trx.atomic_op(key, &bitmap.bitmap, MutationType::BitXor);
            }

            match trx.commit().await {
                Ok(_) => {
                    /*#[cfg(feature = "test_mode")]
                    {
                        for op in &batch.ops {
                            match op {
                                Operation::AccountId {
                                    account_id: account_id_,
                                } => {
                                    account_id = *account_id_;
                                }
                                Operation::Collection {
                                    collection: collection_,
                                } => {
                                    collection = *collection_;
                                }
                                Operation::DocumentId {
                                    document_id: document_id_,
                                } => {
                                    document_id = *document_id_;
                                }
                                Operation::Bitmap { class, set } => {
                                    let key = BitmapKey {
                                        account_id,
                                        collection,
                                        class,
                                        block_num: DenseBitmap::block_num(document_id),
                                    }
                                    .serialize(true);
                                    if *set {
                                        assert!(
                                            BITMAPS
                                                .lock()
                                                .entry(key.clone())
                                                .or_default()
                                                .insert(document_id),
                                            "key {key:?} ({op:?}) already contains document {document_id}"
                                        );
                                    } else {
                                        assert!(
                                            BITMAPS
                                                .lock()
                                                .get_mut(&key)
                                                .unwrap()
                                                .remove(&document_id),
                                            "key {key:?} ({op:?}) does not contain document {document_id}"
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }*/

                    return Ok(());
                }
                Err(err) => {
                    if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                        let backoff = rand::thread_rng().gen_range(50..=300);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        retry_count += 1;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }

    #[cfg(feature = "test_mode")]
    pub(crate) async fn destroy(&self) {
        let trx = self.db.create_trx().unwrap();
        trx.clear_range(&[0u8], &[u8::MAX]);
        trx.commit().await.unwrap();
        BITMAPS.lock().clear();
    }
}
