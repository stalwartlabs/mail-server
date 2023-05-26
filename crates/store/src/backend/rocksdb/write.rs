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

use roaring::RoaringBitmap;
use rocksdb::ErrorKind;
use utils::map::vec_map::VecMap;

use crate::{
    write::{AccountCollection, Batch, Operation, WriteResult},
    AclKey, BitmapKey, BlobKey, Deserialize, Error, IndexKey, LogKey, Serialize, Store, ValueKey,
    BM_DOCUMENT_IDS, UNASSIGNED_ID,
};

use super::{
    bitmap::{clear_bit, set_bit},
    CF_BITMAPS, CF_BLOBS, CF_INDEXES, CF_LOGS, CF_VALUES,
};

impl Store {
    pub fn write(&self, batch: Batch) -> crate::Result<WriteResult> {
        let cf_values = self.db.cf_handle(CF_VALUES).unwrap();
        let cf_bitmaps = self.db.cf_handle(CF_BITMAPS).unwrap();
        let cf_indexes = self.db.cf_handle(CF_INDEXES).unwrap();
        let cf_logs = self.db.cf_handle(CF_LOGS).unwrap();
        let cf_blobs = self.db.cf_handle(CF_BLOBS).unwrap();
        let start = Instant::now();

        loop {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut result = WriteResult {
                change_ids: VecMap::new(),
                assigned_ids: VecMap::new(),
            };
            let txn = self.db.transaction();
            let mut wb = txn.get_writebatch();

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
                        set,
                    } => {
                        if *document_id_ == UNASSIGNED_ID {
                            let key = BitmapKey {
                                account_id,
                                collection,
                                family: BM_DOCUMENT_IDS,
                                field: u8::MAX,
                                key: b"",
                            }
                            .serialize();
                            let mut document_ids = if let Some(bytes) = txn
                                .get_pinned_for_update_cf(&cf_bitmaps, &key, true)
                                .map_err(|err| {
                                    Error::InternalError(format!("get_cf failed: {}", err))
                                })? {
                                RoaringBitmap::deserialize(&bytes).ok_or_else(|| {
                                    Error::InternalError(format!(
                                        "Failed to deserialize key: {:?}",
                                        key
                                    ))
                                })?
                            } else {
                                RoaringBitmap::new()
                            };
                            document_id = if let Some(max_id) = document_ids.max() {
                                let mask = if max_id < 20000 {
                                    RoaringBitmap::from_sorted_iter(0..max_id + 2).unwrap()
                                } else {
                                    RoaringBitmap::full()
                                };
                                document_ids ^= mask;
                                document_ids.min().unwrap()
                            } else {
                                0
                            };
                            result
                                .assigned_ids
                                .append((account_id, collection).into(), document_id);
                            wb.merge_cf(&cf_bitmaps, key, set_bit(document_id));
                        } else {
                            document_id = *document_id_;
                            if !*set {
                                wb.merge_cf(
                                    &cf_bitmaps,
                                    BitmapKey {
                                        account_id,
                                        collection,
                                        family: BM_DOCUMENT_IDS,
                                        field: u8::MAX,
                                        key: b"",
                                    }
                                    .serialize(),
                                    clear_bit(document_id),
                                );
                            }
                        }
                    }
                    Operation::Value { family, field, set } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            family: *family,
                            field: *field,
                        }
                        .serialize();
                        if let Some(value) = set {
                            wb.put_cf(&cf_values, key, value);
                        } else {
                            wb.delete_cf(&cf_values, key);
                        }
                    }
                    Operation::Index { field, key, set } => {
                        let key_ = IndexKey {
                            account_id,
                            collection,
                            document_id,
                            field: *field,
                            key,
                        }
                        .serialize();
                        if *set {
                            wb.put_cf(&cf_indexes, key_, []);
                        } else {
                            wb.delete_cf(&cf_indexes, key_);
                        }
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
                            key,
                        }
                        .serialize();
                        let value = if *set {
                            set_bit(document_id)
                        } else {
                            clear_bit(document_id)
                        };
                        wb.merge_cf(&cf_bitmaps, key, value);
                    }
                    Operation::Blob { key, set } => {
                        let key = BlobKey {
                            account_id,
                            collection,
                            document_id,
                            hash: key,
                        }
                        .serialize();
                        if *set {
                            wb.put_cf(&cf_blobs, key, []);
                        } else {
                            wb.delete_cf(&cf_blobs, key);
                        }
                    }
                    Operation::Acl {
                        grant_account_id,
                        set,
                    } => {
                        let key = AclKey {
                            grant_account_id: *grant_account_id,
                            to_account_id: account_id,
                            to_collection: collection,
                            to_document_id: document_id,
                        }
                        .serialize();
                        if let Some(value) = set {
                            wb.put_cf(&cf_values, key, value);
                        } else {
                            wb.delete_cf(&cf_values, key);
                        }
                    }
                    Operation::Log {
                        collection,
                        changes,
                    } => {
                        let ac: AccountCollection = (account_id, *collection).into();
                        let coco = "read for write";
                        let change_id = self
                            .get_last_change_id(account_id, *collection)?
                            .map(|id| id + 1)
                            .unwrap_or(0);
                        let key = LogKey {
                            account_id,
                            collection: *collection,
                            change_id,
                        }
                        .serialize();
                        wb.put_cf(
                            &cf_logs,
                            key,
                            changes.serialize(
                                result.assigned_ids.get(&ac).copied().unwrap_or_default(),
                            ),
                        );
                        result.change_ids.append(ac, change_id);
                    }
                }
            }

            match self.db.write(wb) {
                Ok(_) => {
                    //println!("Success with id {}", document_id);
                    return Ok(result);
                }
                Err(err) => match err.kind() {
                    ErrorKind::Busy | ErrorKind::MergeInProgress | ErrorKind::TryAgain
                        if start.elapsed().as_secs() < 5 => {}
                    _ => return Err(err.into()),
                },
            }
        }
    }
}
