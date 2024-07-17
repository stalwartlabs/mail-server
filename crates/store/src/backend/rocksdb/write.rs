/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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

use super::{into_error, CfHandle, RocksDbStore, CF_INDEXES, CF_LOGS};
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::DeserializeBigEndian, AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId,
        ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, Deserialize, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN,
};

impl RocksDbStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let mut txn = RocksDBTransaction {
                db: &db,
                cf_indexes: db.cf_handle(CF_INDEXES).unwrap(),
                cf_logs: db.cf_handle(CF_LOGS).unwrap(),
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
                        _ => return Err(into_error(err)),
                    },
                }
            }
        })
        .await
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
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
                let (key, _) = row.map_err(into_error)?;

                if key.as_ref() < from.as_slice() || key.as_ref() >= to.as_slice() {
                    break;
                }
                delete_keys.push(key);
            }

            for k in delete_keys {
                db.delete_cf(&cf, &k).map_err(into_error)?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
                let cf = db
                    .cf_handle(std::str::from_utf8(&[subspace]).unwrap())
                    .unwrap();

                let mut delete_keys = Vec::new();

                for row in db.iterator_cf(&cf, IteratorMode::Start) {
                    let (key, value) = row.map_err(into_error)?;

                    if i64::deserialize(&value)? == 0 {
                        delete_keys.push(key);
                    }
                }

                let txn_opts = OptimisticTransactionOptions::default();
                for key in delete_keys {
                    let txn = db.transaction_opt(&WriteOptions::default(), &txn_opts);
                    if txn
                        .get_pinned_for_update_cf(&cf, &key, true)
                        .map_err(into_error)?
                        .map(|value| i64::deserialize(&value).map(|v| v == 0).unwrap_or(false))
                        .unwrap_or(false)
                    {
                        txn.delete_cf(&cf, key).map_err(into_error)?;
                        txn.commit().map_err(into_error)?;
                    } else {
                        txn.rollback().map_err(into_error)?;
                    }
                }
            }

            Ok(())
        })
        .await
    }
}

struct RocksDBTransaction<'x> {
    db: &'x OptimisticTransactionDB,
    cf_indexes: Arc<BoundColumnFamily<'x>>,
    cf_logs: Arc<BoundColumnFamily<'x>>,
    txn_opts: OptimisticTransactionOptions,
    batch: &'x Batch,
}

enum CommitError {
    Internal(trc::Error),
    RocksDB(rocksdb::Error),
}

impl<'x> RocksDBTransaction<'x> {
    fn commit(&self) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = u64::MAX;
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
                Operation::ChangeId {
                    change_id: change_id_,
                } => {
                    change_id = *change_id_;
                }
                Operation::Value { class, op } => {
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    match op {
                        ValueOp::Set(value) => {
                            txn.put_cf(&cf, &key, value.resolve(&result)?.as_ref())?;
                        }
                        ValueOp::AtomicAdd(by) => {
                            txn.merge_cf(&cf, &key, &by.to_le_bytes()[..])?;
                        }
                        ValueOp::AddAndGet(by) => {
                            let num = txn
                                .get_pinned_for_update_cf(&cf, &key, true)
                                .map_err(CommitError::from)
                                .and_then(|bytes| {
                                    if let Some(bytes) = bytes {
                                        deserialize_i64_le(&key, &bytes)
                                            .map(|v| v + *by)
                                            .map_err(CommitError::from)
                                    } else {
                                        Ok(*by)
                                    }
                                })?;
                            txn.put_cf(&cf, &key, &num.to_le_bytes()[..])?;
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            txn.delete_cf(&cf, &key)?;
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
                    let cf = self.db.subspace_handle(class.subspace());
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

                        for row in
                            txn.iterator_cf(&cf, IteratorMode::From(&begin, Direction::Forward))
                        {
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
                        txn.put_cf(&cf, &key, [])?;
                    } else {
                        txn.delete_cf(&cf, &key)?;
                    }
                }
                Operation::Log { set } => {
                    let key = LogKey {
                        account_id,
                        collection,
                        change_id,
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
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    let matches = txn
                        .get_pinned_for_update_cf(&cf, &key, true)?
                        .map(|value| assert_value.matches(&value))
                        .unwrap_or_else(|| assert_value.is_none());

                    if !matches {
                        txn.rollback()?;
                        return Err(CommitError::Internal(trc::StoreCause::AssertValue.into()));
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

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}
