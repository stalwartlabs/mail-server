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

use super::{RocksDbStore, CF_BITMAPS, CF_COUNTERS, CF_INDEXES, CF_LOGS, CF_VALUES};
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::DeserializeBigEndian, AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId,
        ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, Deserialize, IndexKey, Key, LogKey, SUBSPACE_COUNTERS, U32_LEN,
};

impl RocksDbStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<AssignedIds> {
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
                    Ok(result) => {
                        return Ok(result);
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
    fn commit(&self) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut result = AssignedIds::default();

        let txn = self
            .db
            .transaction_opt(&WriteOptions::default(), &self.txn_opts);

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
                Operation::Value { class, op } => {
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());
                    let is_counter = class.is_counter(collection);

                    match op {
                        ValueOp::Set(value) => {
                            txn.put_cf(&self.cf_values, &key, value.resolve(&result)?.as_ref())?;
                        }
                        ValueOp::AtomicAdd(by) => {
                            txn.merge_cf(&self.cf_counters, &key, &by.to_le_bytes()[..])?;
                        }
                        ValueOp::AddAndGet(by) => {
                            let num = txn
                                .get_pinned_for_update_cf(&self.cf_counters, &key, true)
                                .map_err(CommitError::from)
                                .and_then(|bytes| {
                                    if let Some(bytes) = bytes {
                                        deserialize_i64_le(&bytes)
                                            .map(|v| v + *by)
                                            .map_err(CommitError::from)
                                    } else {
                                        Ok(*by)
                                    }
                                })?;
                            txn.put_cf(&self.cf_counters, &key, &num.to_le_bytes()[..])?;
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            txn.delete_cf(
                                if is_counter {
                                    &self.cf_counters
                                } else {
                                    &self.cf_values
                                },
                                &key,
                            )?;
                        }
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
                    let is_document_id = matches!(class, BitmapClass::DocumentIds);
                    if *set && is_document_id && document_id == u32::MAX {
                        let begin = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: 0,
                        }
                        .serialize(0);
                        let end = BitmapKey {
                            account_id,
                            collection,
                            class: BitmapClass::DocumentIds,
                            document_id: u32::MAX,
                        }
                        .serialize(0);
                        let key_len = begin.len();
                        let mut found_ids = RoaringBitmap::new();

                        for row in txn.iterator_cf(
                            &self.cf_bitmaps,
                            IteratorMode::From(&begin, Direction::Forward),
                        ) {
                            let (key, _) = row?;
                            let key = key.as_ref();
                            if key.len() == key_len
                                && key >= begin.as_slice()
                                && key <= end.as_slice()
                            {
                                found_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                            } else {
                                break;
                            }
                        }

                        document_id = found_ids.random_available_id();
                        result.push_document_id(document_id);
                    }
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());

                    if *set {
                        txn.put_cf(&self.cf_bitmaps, &key, [])?;
                    } else {
                        txn.delete_cf(&self.cf_bitmaps, &key)?;
                    }
                }
                Operation::Log { set } => {
                    let key = LogKey {
                        account_id,
                        collection,
                        change_id: self.batch.change_id,
                    }
                    .serialize(0);

                    txn.put_cf(&self.cf_logs, &key, set.resolve(&result)?.as_ref())?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());

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

        txn.commit().map(|_| result).map_err(Into::into)
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
