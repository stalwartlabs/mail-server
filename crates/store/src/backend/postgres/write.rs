/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use ahash::AHashMap;
use deadpool_postgres::Object;
use rand::Rng;
use tokio_postgres::{IsolationLevel, error::SqlState};

use crate::{
    IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_QUOTA, U64_LEN,
    write::{
        AssignedIds, Batch, BitmapClass, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, Operation,
        ValueClass, ValueOp,
    },
};

use super::{PostgresStore, into_error};

#[derive(Debug)]
enum CommitError {
    Postgres(tokio_postgres::Error),
    Internal(trc::Error),
    Retry,
}

impl PostgresStore {
    pub(crate) async fn write(&self, mut batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let mut conn = self.conn_pool.get().await.map_err(into_error)?;
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            match self.write_trx(&mut conn, &mut batch).await {
                Ok(result) => {
                    return Ok(result);
                }
                Err(err) => {
                    match err {
                        CommitError::Postgres(err) => match err.code() {
                            Some(
                                &SqlState::T_R_SERIALIZATION_FAILURE
                                | &SqlState::T_R_DEADLOCK_DETECTED,
                            ) if retry_count < MAX_COMMIT_ATTEMPTS
                                && start.elapsed() < MAX_COMMIT_TIME => {}
                            Some(&SqlState::UNIQUE_VIOLATION) => {
                                return Err(trc::StoreEvent::AssertValueFailed
                                    .into_err()
                                    .caused_by(trc::location!()));
                            }
                            _ => return Err(into_error(err)),
                        },
                        CommitError::Internal(err) => return Err(err),
                        CommitError::Retry => {
                            if retry_count > MAX_COMMIT_ATTEMPTS
                                || start.elapsed() > MAX_COMMIT_TIME
                            {
                                return Err(trc::StoreEvent::AssertValueFailed
                                    .into_err()
                                    .caused_by(trc::location!()));
                            }
                        }
                    }

                    let backoff = rand::rng().random_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    retry_count += 1;
                }
            }
        }
    }

    async fn write_trx(
        &self,
        conn: &mut Object,
        batch: &mut Batch<'_>,
    ) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = 0u64;
        let mut asserted_values = AHashMap::new();
        let trx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let mut result = AssignedIds::default();
        let has_changes = !batch.changes.is_empty();

        if has_changes {
            for &account_id in batch.changes.keys() {
                let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                let s = trx
                    .prepare_cached(concat!(
                        "INSERT INTO n (k, v) VALUES ($1, 1) ",
                        "ON CONFLICT(k) DO UPDATE SET v = n.v + 1 RETURNING v"
                    ))
                    .await?;
                let change_id = trx
                    .query_one(&s, &[&key])
                    .await
                    .and_then(|row| row.try_get::<_, i64>(0))?;
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

                            let s = if let Some(exists) = asserted_values.get(&key) {
                                if *exists {
                                    trx.prepare_cached(&format!(
                                        "UPDATE {} SET v = $2 WHERE k = $1",
                                        table
                                    ))
                                    .await?
                                } else {
                                    trx.prepare_cached(&format!(
                                        "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                        table
                                    ))
                                    .await?
                                }
                            } else {
                                trx.prepare_cached(&format!(
                                    concat!(
                                        "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                        "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                                    ),
                                    table
                                ))
                                .await?
                            };

                            if trx.execute(&s, &[&key, &(*value)]).await? == 0 {
                                return Err(trc::StoreEvent::AssertValueFailed
                                    .into_err()
                                    .caused_by(trc::location!())
                                    .into());
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx
                                    .prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v"
                                        ),
                                        table, table
                                    ))
                                    .await?;
                                trx.execute(&s, &[&key, &*by]).await?;
                            } else {
                                let s = trx
                                    .prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + $1 WHERE k = $2"
                                    ))
                                    .await?;
                                trx.execute(&s, &[&*by, &key]).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            let s = trx
                                .prepare_cached(&format!(
                                    concat!(
                                    "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                    "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v RETURNING v"
                                ),
                                    table, table
                                ))
                                .await?;
                            result.push_counter_id(
                                trx.query_one(&s, &[&key, &*by])
                                    .await
                                    .and_then(|row| row.try_get::<_, i64>(0))?,
                            );
                        }
                        ValueOp::Clear => {
                            let s = trx
                                .prepare_cached(&format!("DELETE FROM {} WHERE k = $1", table))
                                .await?;
                            trx.execute(&s, &[&key]).await?;

                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(&key) {
                                *exists = false;
                            }
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
                        trx.prepare_cached(
                            "INSERT INTO i (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                        )
                        .await?
                    } else {
                        trx.prepare_cached("DELETE FROM i WHERE k = $1").await?
                    };
                    trx.execute(&s, &[&key]).await?;
                }
                Operation::Bitmap { class, set } => {
                    let is_document_id = matches!(class, BitmapClass::DocumentIds);
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = char::from(class.subspace());

                    let s = if *set {
                        if is_document_id {
                            trx.prepare_cached("INSERT INTO b (k) VALUES ($1)").await?
                        } else {
                            trx.prepare_cached(&format!(
                                "INSERT INTO {} (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                                table
                            ))
                            .await?
                        }
                    } else {
                        trx.prepare_cached(&format!("DELETE FROM {} WHERE k = $1", table))
                            .await?
                    };

                    trx.execute(&s, &[&key]).await.map_err(|err| {
                        if is_document_id && matches!(err.code(), Some(&SqlState::UNIQUE_VIOLATION))
                        {
                            CommitError::Retry
                        } else {
                            CommitError::Postgres(err)
                        }
                    })?;
                }
                Operation::Log { collection, set } => {
                    let key = LogKey {
                        account_id,
                        collection: *collection,
                        change_id,
                    }
                    .serialize(0);

                    let s = trx
                        .prepare_cached(concat!(
                            "INSERT INTO l (k, v) VALUES ($1, $2) ",
                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                        ))
                        .await?;

                    trx.execute(&s, &[&key, &*set]).await?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = char::from(class.subspace(collection));

                    let s = trx
                        .prepare_cached(&format!("SELECT v FROM {} WHERE k = $1 FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .query_opt(&s, &[&key])
                        .await?
                        .map(|row| {
                            row.try_get::<_, &[u8]>(0)
                                .map_or((true, false), |v| (true, assert_value.matches(v)))
                        })
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
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
        let conn = self.conn_pool.get().await.map_err(into_error)?;

        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
            let s = conn
                .prepare_cached(&format!("DELETE FROM {} WHERE v = 0", char::from(subspace),))
                .await
                .map_err(into_error)?;
            conn.execute(&s, &[])
                .await
                .map(|_| ())
                .map_err(into_error)?
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_error)?;

        let s = conn
            .prepare_cached(&format!(
                "DELETE FROM {} WHERE k >= $1 AND k < $2",
                char::from(from.subspace()),
            ))
            .await
            .map_err(into_error)?;
        conn.execute(&s, &[&from.serialize(0), &to.serialize(0)])
            .await
            .map(|_| ())
            .map_err(into_error)
    }
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}

impl From<tokio_postgres::Error> for CommitError {
    fn from(err: tokio_postgres::Error) -> Self {
        CommitError::Postgres(err)
    }
}
