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

use crate::{
    write::{key::KeySerializer, Batch, Operation, ValueClass},
    AclKey, BitmapKey, IndexKey, Key, LogKey, StoreWrite, ValueKey, SUBSPACE_QUOTAS,
    SUBSPACE_VALUES,
};

use super::{bitmap::DenseBitmap, FdbStore};

#[cfg(not(feature = "test_mode"))]
pub const ID_ASSIGNMENT_EXPIRY: u64 = 60 * 60; // seconds
#[cfg(not(feature = "test_mode"))]
pub const MAX_COMMIT_ATTEMPTS: u32 = 10;
#[cfg(not(feature = "test_mode"))]
pub const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

#[cfg(feature = "test_mode")]
pub static ID_ASSIGNMENT_EXPIRY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(60 * 60); // seconds
#[cfg(feature = "test_mode")]
pub const MAX_COMMIT_ATTEMPTS: u32 = 1000;
#[cfg(feature = "test_mode")]
pub const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

#[cfg(feature = "test_mode")]
lazy_static::lazy_static! {
pub static ref BITMAPS: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<Vec<u8>, std::collections::HashSet<u32>>>> =
                    std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
}

#[async_trait::async_trait]
impl StoreWrite for FdbStore {
    async fn write(&self, batch: Batch) -> crate::Result<()> {
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
                    Operation::Value { class, set } => {
                        let key = match class {
                            ValueClass::Property { field, family } => ValueKey {
                                account_id,
                                collection,
                                document_id,
                                family: *family,
                                field: *field,
                            }
                            .serialize(true),
                            ValueClass::Acl { grant_account_id } => AclKey {
                                grant_account_id: *grant_account_id,
                                to_account_id: account_id,
                                to_collection: collection,
                                to_document_id: document_id,
                            }
                            .serialize(true),
                            ValueClass::Custom { bytes } => {
                                let mut key = Vec::with_capacity(1 + bytes.len());
                                key.push(SUBSPACE_VALUES);
                                key.extend_from_slice(bytes);
                                key
                            }
                        };
                        if let Some(value) = set {
                            trx.set(&key, value);
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
                    Operation::Bitmap {
                        family,
                        field,
                        key,
                        set,
                    } => {
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
                                    family: *family,
                                    field: *field,
                                    block_num: DenseBitmap::block_num(document_id),
                                    key,
                                }
                                .serialize(true),
                            )
                            .or_insert_with(DenseBitmap::empty)
                            .set(document_id);
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
                        let key = match class {
                            ValueClass::Property { field, family } => ValueKey {
                                account_id,
                                collection,
                                document_id,
                                family: *family,
                                field: *field,
                            }
                            .serialize(true),
                            ValueClass::Acl { grant_account_id } => AclKey {
                                grant_account_id: *grant_account_id,
                                to_account_id: account_id,
                                to_collection: collection,
                                to_document_id: document_id,
                            }
                            .serialize(true),
                            ValueClass::Custom { bytes } => {
                                let mut key = Vec::with_capacity(1 + bytes.len());
                                key.push(SUBSPACE_VALUES);
                                key.extend_from_slice(bytes);
                                key
                            }
                        };

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
                    Operation::UpdateQuota { bytes } => {
                        trx.atomic_op(
                            &KeySerializer::new(5)
                                .write(SUBSPACE_QUOTAS)
                                .write(account_id)
                                .finalize(),
                            &bytes.to_le_bytes()[..],
                            MutationType::Add,
                        );
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
                    #[cfg(feature = "test_mode")]
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
                                Operation::Bitmap {
                                    family,
                                    field,
                                    key,
                                    set,
                                } => {
                                    let key = BitmapKey {
                                        account_id,
                                        collection,
                                        family: *family,
                                        field: *field,
                                        block_num: DenseBitmap::block_num(document_id),
                                        key,
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
                    }

                    return Ok(());
                }
                Err(err) => {
                    if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
                        err.on_error().await?;
                        retry_count += 1;
                    } else {
                        return Err(FdbError::from(err).into());
                    }
                }
            }
        }
    }

    #[cfg(feature = "test_mode")]
    async fn destroy(&self) {
        let trx = self.db.create_trx().unwrap();
        trx.clear_range(&[0u8], &[u8::MAX]);
        trx.commit().await.unwrap();
        BITMAPS.lock().clear();
    }
}
