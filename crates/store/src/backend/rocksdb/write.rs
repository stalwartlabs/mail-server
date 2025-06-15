/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

use rand::Rng;
use rocksdb::{
    BoundColumnFamily, ErrorKind, IteratorMode, OptimisticTransactionDB,
    OptimisticTransactionOptions, WriteOptions,
};

use super::{CF_INDEXES, CF_LOGS, CfHandle, RocksDbStore, into_error};
use crate::{
    Deserialize, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_QUOTA, U64_LEN,
    backend::deserialize_i64_le,
    write::{
        AssignedIds, Batch, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, Operation, ValueClass, ValueOp,
    },
};

impl RocksDbStore {
    pub(crate) async fn write(&self, mut batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let mut txn = RocksDBTransaction {
                db: &db,
                cf_indexes: db.cf_handle(CF_INDEXES).unwrap(),
                cf_logs: db.cf_handle(CF_LOGS).unwrap(),
                txn_opts: OptimisticTransactionOptions::default(),
                batch: &mut batch,
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
                            let backoff = rand::rng().random_range(50..=300);
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
            db.delete_range_cf(
                &db.cf_handle(std::str::from_utf8(&[from.subspace()]).unwrap())
                    .unwrap(),
                from.serialize(0),
                to.serialize(0),
            )
            .map_err(into_error)
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
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

struct RocksDBTransaction<'x, 'y> {
    db: &'x OptimisticTransactionDB,
    cf_indexes: Arc<BoundColumnFamily<'x>>,
    cf_logs: Arc<BoundColumnFamily<'x>>,
    txn_opts: OptimisticTransactionOptions,
    batch: &'x mut Batch<'y>,
}

enum CommitError {
    Internal(trc::Error),
    RocksDB(rocksdb::Error),
}

impl RocksDBTransaction<'_, '_> {
    fn commit(&mut self) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = 0u64;
        let mut result = AssignedIds::default();
        let has_changes = !self.batch.changes.is_empty();

        let txn = self
            .db
            .transaction_opt(&WriteOptions::default(), &self.txn_opts);

        if has_changes {
            let cf = self.db.cf_handle("n").unwrap();
            for &account_id in self.batch.changes.keys() {
                let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                let change_id = txn
                    .get_pinned_for_update_cf(&cf, &key, true)
                    .map_err(CommitError::from)
                    .and_then(|bytes| {
                        if let Some(bytes) = bytes {
                            deserialize_i64_le(&key, &bytes)
                                .map(|v| v + 1)
                                .map_err(CommitError::from)
                        } else {
                            Ok(1)
                        }
                    })?;
                txn.put_cf(&cf, &key, &change_id.to_le_bytes()[..])?;
                result.push_change_id(account_id, change_id as u64);
            }
        }

        for op in self.batch.ops.iter_mut() {
            match op {
                Operation::AccountId {
                    account_id: account_id_,
                } => {
                    account_id = *account_id_;
                    if has_changes {
                        change_id = result.last_change_id(account_id)?;
                    }
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
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    match op {
                        ValueOp::Set {
                            value,
                            version_offset,
                        } => {
                            if let Some(offset) = version_offset {
                                value[*offset..*offset + U64_LEN]
                                    .copy_from_slice(&change_id.to_be_bytes());
                            }

                            txn.put_cf(&cf, &key, value)?;
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
                        key: &*key,
                    }
                    .serialize(0);

                    if *set {
                        txn.put_cf(&self.cf_indexes, &key, [])?;
                    } else {
                        txn.delete_cf(&self.cf_indexes, &key)?;
                    }
                }
                Operation::Bitmap { class, set } => {
                    let cf = self.db.subspace_handle(class.subspace());
                    let key = class.serialize(account_id, collection, document_id, 0);

                    if *set {
                        txn.put_cf(&cf, &key, [])?;
                    } else {
                        txn.delete_cf(&cf, &key)?;
                    }
                }
                Operation::Log { collection, set } => {
                    let key = LogKey {
                        account_id,
                        collection: *collection,
                        change_id,
                    }
                    .serialize(0);

                    txn.put_cf(&self.cf_logs, &key, set)?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let cf = self.db.subspace_handle(class.subspace(collection));

                    let matches = txn
                        .get_pinned_for_update_cf(&cf, &key, true)?
                        .map(|value| assert_value.matches(&value))
                        .unwrap_or_else(|| assert_value.is_none());

                    if !matches {
                        txn.rollback()?;
                        return Err(CommitError::Internal(
                            trc::StoreEvent::AssertValueFailed.into(),
                        ));
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
