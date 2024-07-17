/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use ahash::AHashMap;
use futures::TryStreamExt;
use mysql_async::{params, prelude::Queryable, Conn, Error, IsolationLevel, TxOpts};
use rand::Rng;
use roaring::RoaringBitmap;

use crate::{
    write::{
        key::DeserializeBigEndian, AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId,
        ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN,
};

use super::{into_error, MysqlStore};

#[derive(Debug)]
enum CommitError {
    Mysql(mysql_async::Error),
    Internal(trc::Error),
    Retry,
}

impl MysqlStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        loop {
            match self.write_trx(&mut conn, &batch).await {
                Ok(result) => {
                    return Ok(result);
                }
                Err(CommitError::Mysql(Error::Server(err)))
                    if [1062, 1213].contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME => {}
                Err(CommitError::Retry) => {
                    if retry_count > MAX_COMMIT_ATTEMPTS || start.elapsed() > MAX_COMMIT_TIME {
                        return Err(trc::StoreCause::AssertValue.into());
                    }
                }
                Err(CommitError::Mysql(err)) => {
                    return Err(into_error(err));
                }
                Err(CommitError::Internal(err)) => {
                    return Err(err);
                }
            }

            let backoff = rand::thread_rng().gen_range(50..=300);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            retry_count += 1;
        }
    }

    async fn write_trx(&self, conn: &mut Conn, batch: &Batch) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = u64::MAX;
        let mut asserted_values = AHashMap::new();
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await?;
        let mut result = AssignedIds::default();

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
                Operation::ChangeId {
                    change_id: change_id_,
                } => {
                    change_id = *change_id_;
                }
                Operation::Value { class, op } => {
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());
                    let table = char::from(class.subspace(collection));

                    match op {
                        ValueOp::Set(value) => {
                            let exists = asserted_values.get(&key);
                            let s = if let Some(exists) = exists {
                                if *exists {
                                    trx.prep(&format!("UPDATE {} SET v = :v WHERE k = :k", table))
                                        .await?
                                } else {
                                    trx.prep(&format!(
                                        "INSERT INTO {} (k, v) VALUES (:k, :v)",
                                        table
                                    ))
                                    .await?
                                }
                            } else {
                                trx
                            .prep(
                                &format!("INSERT INTO {} (k, v) VALUES (:k, :v) ON DUPLICATE KEY UPDATE v = VALUES(v)", table),
                            )
                            .await?
                            };

                            match trx
                                .exec_drop(
                                    &s,
                                    params! {"k" => key, "v" => value.resolve(&result)?.as_ref()},
                                )
                                .await
                            {
                                Ok(_) => {
                                    if exists.is_some() && trx.affected_rows() == 0 {
                                        trx.rollback().await?;
                                        return Err(trc::StoreCause::AssertValue.into_err().into());
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
                                    .prep(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON DUPLICATE KEY UPDATE v = v + VALUES(v)"
                                        ),
                                        table
                                    ))
                                    .await?;
                                trx.exec_drop(&s, (key, by)).await?;
                            } else {
                                let s = trx
                                    .prep(&format!("UPDATE {table} SET v = v + ? WHERE k = ?"))
                                    .await?;
                                trx.exec_drop(&s, (by, key)).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx
                                .prep(&format!(
                                    concat!(
                                        "INSERT INTO {} (k, v) VALUES (:k, LAST_INSERT_ID(:v)) ",
                                        "ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + :v)"
                                    ),
                                    table
                                ))
                                .await?;
                            trx.exec_drop(&s, params! {"k" => key, "v" => by}).await?;
                            let s = trx.prep("SELECT LAST_INSERT_ID()").await?;
                            result.push_counter_id(
                                trx.exec_first::<i64, _, _>(&s, ()).await?.ok_or_else(|| {
                                    mysql_async::Error::Io(mysql_async::IoError::Io(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "LAST_INSERT_ID() did not return a value",
                                        ),
                                    ))
                                })?,
                            );
                        }
                        ValueOp::Clear => {
                            let s = trx
                                .prep(&format!("DELETE FROM {} WHERE k = ?", table))
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
                        key,
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
                    // Find the next available document id
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

                        let s = trx.prep("SELECT k FROM b WHERE k >= ? AND k <= ?").await?;
                        let mut rows = trx.exec_stream::<Vec<u8>, _, _>(&s, (begin, end)).await?;
                        let mut found_ids = RoaringBitmap::new();

                        while let Some(key) = rows.try_next().await? {
                            if key.len() == key_len {
                                found_ids.insert(
                                    key.as_slice().deserialize_be_u32(key.len() - U32_LEN)?,
                                );
                            }
                        }

                        document_id = found_ids.random_available_id();
                        result.push_document_id(document_id);
                    }
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());
                    let table = char::from(class.subspace());

                    let s = if *set {
                        if is_document_id {
                            trx.prep("INSERT INTO b (k) VALUES (?)").await?
                        } else {
                            trx.prep(&format!("INSERT IGNORE INTO {} (k) VALUES (?)", table))
                                .await?
                        }
                    } else {
                        trx.prep(&format!("DELETE FROM {} WHERE k = ?", table))
                            .await?
                    };

                    if let Err(err) = trx.exec_drop(&s, (key,)).await {
                        return Err(
                            if is_document_id
                                && matches!(&err, Error::Server(err) if [1062, 1213].contains(&err.code))
                            {
                                trx.rollback().await?;
                                CommitError::Retry
                            } else {
                                CommitError::Mysql(err)
                            },
                        );
                    }
                }
                Operation::Log { set } => {
                    let key = LogKey {
                        account_id,
                        collection,
                        change_id,
                    }
                    .serialize(0);

                    let s = trx
                        .prep("INSERT INTO l (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)")
                        .await?;

                    trx.exec_drop(&s, (key, set.resolve(&result)?.as_ref()))
                        .await?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key =
                        class.serialize(account_id, collection, document_id, 0, (&result).into());
                    let table = char::from(class.subspace(collection));

                    let s = trx
                        .prep(&format!("SELECT v FROM {} WHERE k = ? FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .exec_first::<Vec<u8>, _, _>(&s, (&key,))
                        .await?
                        .map(|bytes| (true, assert_value.matches(&bytes)))
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
                        trx.rollback().await?;
                        return Err(trc::StoreCause::AssertValue.into_err().into());
                    }
                    asserted_values.insert(key, exists);
                }
            }
        }

        trx.commit().await.map(|_| result).map_err(Into::into)
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
            let s = conn
                .prep(&format!("DELETE FROM {} WHERE v = 0", char::from(subspace),))
                .await
                .map_err(into_error)?;
            conn.exec_drop(&s, ()).await.map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

        let s = conn
            .prep(&format!(
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
