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

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use rand::Rng;
use rocksdb::ErrorKind;

use super::{
    bitmap::{clear_bit, set_bit},
    RocksDbStore, CF_BITMAPS, CF_BLOBS, CF_BLOB_DATA, CF_COUNTERS, CF_INDEXES, CF_INDEX_VALUES,
    CF_LOGS, CF_VALUES,
};
use crate::{
    write::{Batch, Operation, ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME},
    BitmapKey, BlobKey, IndexKey, Key, LogKey, ValueKey, SUBSPACE_INDEX_VALUES, SUBSPACE_VALUES,
};

impl RocksDbStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let start = Instant::now();
            let mut retry_count = 0;

            let cf_bitmaps = db.cf_handle(CF_BITMAPS).unwrap();
            let cf_values = db.cf_handle(CF_VALUES).unwrap();
            let cf_indexes = db.cf_handle(CF_INDEXES).unwrap();
            let cf_logs = db.cf_handle(CF_LOGS).unwrap();
            let cf_blobs = db.cf_handle(CF_BLOBS).unwrap();
            let cf_index_values = db.cf_handle(CF_INDEX_VALUES).unwrap();
            let cf_counters = db.cf_handle(CF_COUNTERS).unwrap();

            loop {
                let mut account_id = u32::MAX;
                let mut collection = u8::MAX;
                let mut document_id = u32::MAX;

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
                            .serialize(false);

                            wb.merge_cf(&cf_counters, &key, &by.to_le_bytes()[..]);
                        }
                        Operation::Value { class, op } => {
                            let key = ValueKey {
                                account_id,
                                collection,
                                document_id,
                                class,
                            };
                            let cf = match key.subspace() {
                                SUBSPACE_VALUES => &cf_values,
                                SUBSPACE_INDEX_VALUES => &cf_index_values,
                                _ => unreachable!(),
                            };
                            let key = key.serialize(false);

                            if let ValueOp::Set(value) = op {
                                wb.put_cf(cf, &key, value);
                            } else {
                                wb.delete_cf(cf, &key);
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
                            .serialize(false);

                            if *set {
                                wb.put_cf(&cf_indexes, &key, []);
                            } else {
                                wb.delete_cf(&cf_indexes, &key);
                            }
                        }
                        Operation::Bitmap { class, set } => {
                            let key = BitmapKey {
                                account_id,
                                collection,
                                class,
                                block_num: 0,
                            }
                            .serialize(false);

                            let value = if *set {
                                set_bit(document_id)
                            } else {
                                clear_bit(document_id)
                            };

                            wb.merge_cf(&cf_bitmaps, key, value);
                        }
                        Operation::Blob { hash, op, set } => {
                            let key = BlobKey {
                                account_id,
                                collection,
                                document_id,
                                hash,
                                op: *op,
                            }
                            .serialize(false);

                            if *set {
                                wb.put_cf(&cf_blobs, &key, []);
                            } else {
                                wb.delete_cf(&cf_blobs, &key);
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
                            .serialize(false);

                            wb.put_cf(&cf_logs, &key, set);
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
                            };
                            let cf = match key.subspace() {
                                SUBSPACE_VALUES => &cf_values,
                                SUBSPACE_INDEX_VALUES => &cf_index_values,
                                _ => unreachable!(),
                            };
                            let key = key.serialize(false);
                            let matches = txn
                                .get_cf(cf, &key)?
                                .map(|value| assert_value.matches(&value))
                                .unwrap_or_else(|| assert_value.is_none());
                            if !matches {
                                return Err(crate::Error::AssertValueFailed);
                            }
                        }
                    }
                }

                match db.write(wb) {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::Busy | ErrorKind::MergeInProgress | ErrorKind::TryAgain
                            if retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME =>
                        {
                            let backoff = rand::thread_rng().gen_range(50..=300);
                            sleep(Duration::from_millis(backoff));
                            retry_count += 1;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }
        })
        .await
    }

    #[cfg(feature = "test_mode")]
    pub(crate) async fn destroy(&self) {
        use rocksdb::IteratorMode;

        self.db.cancel_all_background_work(false);

        for cf_name in [
            CF_VALUES,
            CF_LOGS,
            CF_BITMAPS,
            CF_INDEXES,
            CF_BLOBS,
            CF_INDEX_VALUES,
            CF_COUNTERS,
            CF_BLOB_DATA,
        ] {
            let mut delete_keys = Vec::new();
            let it_mode = IteratorMode::Start;
            let cf = self.db.cf_handle(cf_name).unwrap();

            for row in self.db.iterator_cf(&cf, it_mode) {
                let (k, _) = row.unwrap();
                delete_keys.push(k);
            }

            for k in delete_keys {
                self.db.delete_cf(&cf, &k).unwrap();
            }
        }
    }
}
