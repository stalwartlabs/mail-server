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
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

use rand::Rng;
use roaring::RoaringBitmap;
use rocksdb::{
    BoundColumnFamily, Direction, ErrorKind, IteratorMode, OptimisticTransactionDB,
    OptimisticTransactionOptions, WriteOptions,
};

use super::{
    bitmap::{clear_bit, set_bit},
    RocksDbStore, CF_BITMAPS, CF_COUNTERS, CF_INDEXES, CF_LOGS, CF_VALUES,
};
use crate::{
    write::{
        Batch, BitmapClass, LookupClass, Operation, ValueClass, ValueOp, MAX_COMMIT_ATTEMPTS,
        MAX_COMMIT_TIME,
    },
    BitmapKey, Deserialize, IndexKey, Key, LogKey, ValueKey, SUBSPACE_COUNTERS, WITHOUT_BLOCK_NUM,
};

impl RocksDbStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let mut txn = RocksDBTransaction {
                db: &db,
                cf_bitmaps: db.cf_handle(CF_BITMAPS).unwrap(),
                cf_values: db.cf_handle(CF_VALUES).unwrap(),
                cf_indexes: db.cf_handle(CF_INDEXES).unwrap(),
                cf_logs: db.cf_handle(CF_LOGS).unwrap(),
                cf_counters: db.cf_handle(CF_COUNTERS).unwrap(),
                txn_opts: OptimisticTransactionOptions::default(),
                batch: &batch,
            };
            txn.txn_opts.set_snapshot(true);

            // Begin write
            let mut retry_count = 0;
            let start = Instant::now();
            loop {
                match txn.commit() {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(CommitError::Internal(err)) => return Err(err),
                    Err(CommitError::RocksDB(err)) => match err.kind() {
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

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> crate::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            let cf = db
                .cf_handle(std::str::from_utf8(&[from.subspace()]).unwrap())
                .unwrap();

            // TODO use delete_range when implemented (see https://github.com/rust-rocksdb/rust-rocksdb/issues/839)
            let from = from.serialize(0);
            let to = to.serialize(0);
            let mut delete_keys = Vec::new();
            let it_mode = IteratorMode::From(&from, Direction::Forward);

            for row in db.iterator_cf(&cf, it_mode) {
                let (key, _) = row?;

                if key.as_ref() < from.as_slice() || key.as_ref() >= to.as_slice() {
                    break;
                }
                delete_keys.push(key);
            }

            for k in delete_keys {
                db.delete_cf(&cf, &k)?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> crate::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            let cf = db
                .cf_handle(std::str::from_utf8(&[SUBSPACE_COUNTERS]).unwrap())
                .unwrap();

            let mut delete_keys = Vec::new();

            for row in db.iterator_cf(&cf, IteratorMode::Start) {
                let (key, value) = row?;

                if i64::deserialize(&value)? <= 0 {
                    delete_keys.push(key);
                }
            }

            let txn_opts = OptimisticTransactionOptions::default();
            for key in delete_keys {
                let txn = db.transaction_opt(&WriteOptions::default(), &txn_opts);
                if txn
                    .get_pinned_for_update_cf(&cf, &key, true)?
                    .map(|value| i64::deserialize(&value).map(|v| v == 0).unwrap_or(false))
                    .unwrap_or(false)
                {
                    txn.delete(key)?;
                    txn.commit()?;
                } else {
                    txn.rollback()?;
                }
            }

            Ok(())
        })
        .await
    }
}

struct RocksDBTransaction<'x> {
    db: &'x OptimisticTransactionDB,
    cf_bitmaps: Arc<BoundColumnFamily<'x>>,
    cf_values: Arc<BoundColumnFamily<'x>>,
    cf_indexes: Arc<BoundColumnFamily<'x>>,
    cf_logs: Arc<BoundColumnFamily<'x>>,
    cf_counters: Arc<BoundColumnFamily<'x>>,
    txn_opts: OptimisticTransactionOptions,
    batch: &'x Batch,
}

enum CommitError {
    Internal(crate::Error),
    RocksDB(rocksdb::Error),
}

impl<'x> RocksDBTransaction<'x> {
    fn commit(&self) -> Result<(), CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;

        let txn = self
            .db
            .transaction_opt(&WriteOptions::default(), &self.txn_opts);

        if !self.batch.is_atomic() {
            for op in &self.batch.ops {
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
                        op: ValueOp::AtomicAdd(by),
                    } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(0);

                        txn.merge_cf(&self.cf_counters, &key, &by.to_le_bytes()[..])?;
                    }
                    Operation::Value { class, op } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(0);

                        if let ValueOp::Set(value) = op {
                            txn.put_cf(&self.cf_values, &key, value)?;

                            if matches!(class, ValueClass::ReservedId) {
                                if let Some(bitmap) = txn
                                    .get_pinned_for_update_cf(
                                        &self.cf_bitmaps,
                                        &BitmapKey {
                                            account_id,
                                            collection,
                                            class: BitmapClass::DocumentIds,
                                            block_num: 0,
                                        }
                                        .serialize(WITHOUT_BLOCK_NUM),
                                        true,
                                    )
                                    .map_err(CommitError::from)
                                    .and_then(|bytes| {
                                        if let Some(bytes) = bytes {
                                            RoaringBitmap::deserialize(&bytes)
                                                .map(Some)
                                                .map_err(CommitError::from)
                                        } else {
                                            Ok(None)
                                        }
                                    })?
                                {
                                    if bitmap.contains(document_id) {
                                        txn.rollback()?;
                                        return Err(CommitError::Internal(
                                            crate::Error::AssertValueFailed,
                                        ));
                                    }
                                }
                            }
                        } else {
                            txn.delete_cf(
                                if matches!(class, ValueClass::Lookup(LookupClass::Counter(_))) {
                                    &self.cf_counters
                                } else {
                                    &self.cf_values
                                },
                                &key,
                            )?;
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
                        .serialize(0);

                        if *set {
                            txn.put_cf(&self.cf_indexes, &key, [])?;
                        } else {
                            txn.delete_cf(&self.cf_indexes, &key)?;
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            class,
                            block_num: 0,
                        }
                        .serialize(WITHOUT_BLOCK_NUM);

                        let value = if *set {
                            set_bit(document_id)
                        } else {
                            clear_bit(document_id)
                        };

                        txn.merge_cf(&self.cf_bitmaps, key, value)?;
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
                        .serialize(0);

                        txn.put_cf(&self.cf_logs, &key, set)?;
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
                        .serialize(0);
                        let matches = txn
                            .get_pinned_for_update_cf(&self.cf_values, &key, true)?
                            .map(|value| assert_value.matches(&value))
                            .unwrap_or_else(|| assert_value.is_none());

                        if !matches {
                            txn.rollback()?;
                            return Err(CommitError::Internal(crate::Error::AssertValueFailed));
                        }
                    }
                }
            }

            txn.commit().map_err(Into::into)
        } else {
            let mut wb = txn.get_writebatch();
            for op in &self.batch.ops {
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
                        op: ValueOp::AtomicAdd(by),
                    } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(0);

                        wb.merge_cf(&self.cf_counters, &key, &by.to_le_bytes()[..]);
                    }
                    Operation::Value { class, op } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        };
                        let key = key.serialize(0);

                        if let ValueOp::Set(value) = op {
                            wb.put_cf(&self.cf_values, &key, value);
                        } else {
                            wb.delete_cf(
                                if matches!(class, ValueClass::Lookup(LookupClass::Counter(_))) {
                                    &self.cf_counters
                                } else {
                                    &self.cf_values
                                },
                                &key,
                            );
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
                        .serialize(0);

                        if *set {
                            wb.put_cf(&self.cf_indexes, &key, []);
                        } else {
                            wb.delete_cf(&self.cf_indexes, &key);
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            class,
                            block_num: 0,
                        }
                        .serialize(WITHOUT_BLOCK_NUM);

                        let value = if *set {
                            set_bit(document_id)
                        } else {
                            clear_bit(document_id)
                        };

                        wb.merge_cf(&self.cf_bitmaps, key, value);
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
                        .serialize(0);

                        wb.put_cf(&self.cf_logs, &key, set);
                    }
                    Operation::AssertValue { .. } => unreachable!(),
                }
            }

            self.db.write(wb).map_err(Into::into)
        }
    }
}

impl From<rocksdb::Error> for CommitError {
    fn from(err: rocksdb::Error) -> Self {
        CommitError::RocksDB(err)
    }
}

impl From<crate::Error> for CommitError {
    fn from(err: crate::Error) -> Self {
        CommitError::Internal(err)
    }
}
