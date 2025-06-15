/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use ahash::AHashMap;
use mysql_async::{Conn, Error, IsolationLevel, TxOpts, params, prelude::Queryable};
use rand::Rng;

use crate::{
    IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_QUOTA, U64_LEN,
    write::{
        AssignedIds, Batch, BitmapClass, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, Operation,
        ValueClass, ValueOp,
    },
};

use super::{MysqlStore, into_error};

#[derive(Debug)]
enum CommitError {
    Mysql(mysql_async::Error),
    Internal(trc::Error),
    Retry,
}

impl MysqlStore {
    pub(crate) async fn write(&self, mut batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        loop {
            let err = match self.write_trx(&mut conn, &mut batch).await {
                Ok(result) => {
                    return Ok(result);
                }
                Err(err) => err,
            };

            let _ = conn.query_drop("ROLLBACK;").await;

            match err {
                CommitError::Mysql(Error::Server(err))
                    if [1062, 1213].contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME => {}
                CommitError::Retry => {
                    if retry_count > MAX_COMMIT_ATTEMPTS || start.elapsed() > MAX_COMMIT_TIME {
                        return Err(trc::StoreEvent::AssertValueFailed
                            .into_err()
                            .caused_by(trc::location!()));
                    }
                }
                CommitError::Mysql(err) => {
                    return Err(into_error(err));
                }
                CommitError::Internal(err) => {
                    return Err(err);
                }
            }

            let backoff = rand::rng().random_range(50..=300);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            retry_count += 1;
        }
    }

    async fn write_trx(
        &self,
        conn: &mut Conn,
        batch: &mut Batch<'_>,
    ) -> Result<AssignedIds, CommitError> {
        let has_changes = !batch.changes.is_empty();
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = 0u64;
        let mut asserted_values = AHashMap::new();
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await?;
        let mut result = AssignedIds::default();

        if has_changes {
            for &account_id in batch.changes.keys() {
                let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                let s = trx
                    .prep(concat!(
                        "INSERT INTO n (k, v) VALUES (:k, LAST_INSERT_ID(1)) ",
                        "ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + 1)"
                    ))
                    .await?;
                trx.exec_drop(&s, params! {"k" => key}).await?;
                let s = trx.prep("SELECT LAST_INSERT_ID()").await?;
                let change_id = trx.exec_first::<i64, _, _>(&s, ()).await?.ok_or_else(|| {
                    mysql_async::Error::Io(mysql_async::IoError::Io(std::io::Error::other(
                        "LAST_INSERT_ID() did not return a value",
                    )))
                })?;
                result.push_change_id(account_id, change_id as u64);
            }
        }

        for op in batch.ops.iter_mut() {
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
                    let table = char::from(class.subspace(collection));

                    match op {
                        ValueOp::Set {
                            value,
                            version_offset,
                        } => {
                            if let Some(offset) = version_offset {
                                value[*offset..*offset + U64_LEN]
                                    .copy_from_slice(&change_id.to_be_bytes());
                            }

                            let exists = asserted_values.get(&key);
                            let s = if let Some(exists) = exists {
                                if *exists {
                                    trx.prep(format!("UPDATE {} SET v = :v WHERE k = :k", table))
                                        .await?
                                } else {
                                    trx.prep(format!(
                                        "INSERT INTO {} (k, v) VALUES (:k, :v)",
                                        table
                                    ))
                                    .await?
                                }
                            } else {
                                trx
                            .prep(
                                format!("INSERT INTO {} (k, v) VALUES (:k, :v) ON DUPLICATE KEY UPDATE v = VALUES(v)", table),
                            )
                            .await?
                            };

                            match trx
                                .exec_drop(&s, params! {"k" => key, "v" => &*value})
                                .await
                            {
                                Ok(_) => {
                                    if exists.is_some() && trx.affected_rows() == 0 {
                                        trx.rollback().await?;
                                        return Err(trc::StoreEvent::AssertValueFailed
                                            .into_err()
                                            .caused_by(trc::location!())
                                            .into());
                                    }
                                }
                                Err(err) => {
                                    trx.rollback().await?;
                                    return Err(err.into());
                                }
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx
                                    .prep(format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON DUPLICATE KEY UPDATE v = v + VALUES(v)"
                                        ),
                                        table
                                    ))
                                    .await?;
                                trx.exec_drop(&s, (key, &*by)).await?;
                            } else {
                                let s = trx
                                    .prep(format!("UPDATE {table} SET v = v + ? WHERE k = ?"))
                                    .await?;
                                trx.exec_drop(&s, (&*by, key)).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx
                                .prep(format!(
                                    concat!(
                                        "INSERT INTO {} (k, v) VALUES (:k, LAST_INSERT_ID(:v)) ",
                                        "ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + :v)"
                                    ),
                                    table
                                ))
                                .await?;
                            trx.exec_drop(&s, params! {"k" => key, "v" => &*by}).await?;
                            let s = trx.prep("SELECT LAST_INSERT_ID()").await?;
                            result.push_counter_id(
                                trx.exec_first::<i64, _, _>(&s, ()).await?.ok_or_else(|| {
                                    mysql_async::Error::Io(mysql_async::IoError::Io(
                                        std::io::Error::other(
                                            "LAST_INSERT_ID() did not return a value",
                                        ),
                                    ))
                                })?,
                            );
                        }
                        ValueOp::Clear => {
                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(&key) {
                                *exists = false;
                            }

                            let s = trx
                                .prep(format!("DELETE FROM {} WHERE k = ?", table))
                                .await?;
                            trx.exec_drop(&s, (key,)).await?;
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

                    let s = if *set {
                        trx.prep("INSERT IGNORE INTO i (k) VALUES (?)").await?
                    } else {
                        trx.prep("DELETE FROM i WHERE k = ?").await?
                    };
                    trx.exec_drop(&s, (key,)).await?;
                }
                Operation::Bitmap { class, set } => {
                    let is_document_id = matches!(class, BitmapClass::DocumentIds);
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = char::from(class.subspace());

                    let s = if *set {
                        if is_document_id {
                            trx.prep("INSERT INTO b (k) VALUES (?)").await?
                        } else {
                            trx.prep(format!("INSERT IGNORE INTO {} (k) VALUES (?)", table))
                                .await?
                        }
                    } else {
                        trx.prep(format!("DELETE FROM {} WHERE k = ?", table))
                            .await?
                    };

                    if let Err(err) = trx.exec_drop(&s, (key,)).await {
                        trx.rollback().await?;
                        return Err(
                            if is_document_id
                                && matches!(&err, Error::Server(err) if [1062, 1213].contains(&err.code))
                            {
                                CommitError::Retry
                            } else {
                                CommitError::Mysql(err)
                            },
                        );
                    }
                }
                Operation::Log { collection, set } => {
                    let key = LogKey {
                        account_id,
                        collection: *collection,
                        change_id,
                    }
                    .serialize(0);

                    let s = trx
                        .prep("INSERT INTO l (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)")
                        .await?;

                    trx.exec_drop(&s, (key, &*set)).await?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = char::from(class.subspace(collection));

                    let s = trx
                        .prep(format!("SELECT v FROM {} WHERE k = ? FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .exec_first::<Vec<u8>, _, _>(&s, (&key,))
                        .await?
                        .map(|bytes| (true, assert_value.matches(&bytes)))
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
                        trx.rollback().await?;
                        return Err(trc::StoreEvent::AssertValueFailed
                            .into_err()
                            .caused_by(trc::location!())
                            .into());
                    }
                    asserted_values.insert(key, exists);
                }
            }
        }

        trx.commit().await.map(|_| result).map_err(Into::into)
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
            let s = conn
                .prep(format!("DELETE FROM {} WHERE v = 0", char::from(subspace),))
                .await
                .map_err(into_error)?;
            conn.exec_drop(&s, ()).await.map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        let s = conn
            .prep(format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                char::from(from.subspace()),
            ))
            .await
            .map_err(into_error)?;
        conn.exec_drop(&s, (&from.serialize(0), &to.serialize(0)))
            .await
            .map_err(into_error)
    }
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}

impl From<mysql_async::Error> for CommitError {
    fn from(err: mysql_async::Error) -> Self {
        CommitError::Mysql(err)
    }
}
