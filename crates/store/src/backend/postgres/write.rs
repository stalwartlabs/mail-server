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
use deadpool_postgres::Object;
use rand::Rng;
use tokio_postgres::{error::SqlState, IsolationLevel};

use crate::{
    write::{
        Batch, BitmapClass, Operation, ValueClass, ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, ValueKey,
};

use super::PostgresStore;

impl PostgresStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let mut conn = self.conn_pool.get().await?;
        let start = Instant::now();
        let mut retry_count = 0;

        loop {
            match self.write_trx(&mut conn, &batch).await {
                Ok(success) => {
                    return if success {
                        Ok(())
                    } else {
                        Err(crate::Error::AssertValueFailed)
                    };
                }
                Err(err) => match err.code() {
                    Some(
                        &SqlState::T_R_SERIALIZATION_FAILURE | &SqlState::T_R_DEADLOCK_DETECTED,
                    ) if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME => {
                        let backoff = rand::thread_rng().gen_range(50..=300);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        retry_count += 1;
                    }
                    Some(&SqlState::UNIQUE_VIOLATION) => {
                        return Err(crate::Error::AssertValueFailed);
                    }
                    _ => return Err(err.into()),
                },
            }
        }
    }

    async fn write_trx(
        &self,
        conn: &mut Object,
        batch: &Batch,
    ) -> Result<bool, tokio_postgres::Error> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut asserted_values = AHashMap::new();
        let trx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;

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
                    .serialize(0);

                    if *by >= 0 {
                        let s = trx
                            .prepare_cached(concat!(
                                "INSERT INTO c (k, v) VALUES ($1, $2) ",
                                "ON CONFLICT(k) DO UPDATE SET v = c.v + EXCLUDED.v"
                            ))
                            .await?;
                        trx.execute(&s, &[&key, &by]).await?;
                    } else {
                        let s = trx
                            .prepare_cached("UPDATE c SET v = v + $1 WHERE k = $2")
                            .await?;
                        trx.execute(&s, &[&by, &key]).await?;
                    }
                }
                Operation::Value { class, op } => {
                    let key = ValueKey {
                        account_id,
                        collection,
                        document_id,
                        class,
                    };
                    let table = char::from(key.subspace());
                    let key = key.serialize(0);

                    if let ValueOp::Set(value) = op {
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

                        if trx.execute(&s, &[&key, value]).await? == 0 {
                            return Ok(false);
                        }

                        if matches!(class, ValueClass::ReservedId) {
                            // Make sure the reserved id is not already in use
                            let s = trx.prepare_cached("SELECT 1 FROM b WHERE k = $1").await?;
                            let key = BitmapKey {
                                account_id,
                                collection,
                                class: BitmapClass::DocumentIds,
                                block_num: document_id,
                            }
                            .serialize(0);
                            if trx.query_opt(&s, &[&key]).await?.is_some() {
                                return Ok(false);
                            }
                        }
                    } else {
                        let s = trx
                            .prepare_cached(&format!("DELETE FROM {} WHERE k = $1", table))
                            .await?;
                        trx.execute(&s, &[&key]).await?;
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
                    let key = BitmapKey {
                        account_id,
                        collection,
                        class,
                        block_num: document_id,
                    }
                    .serialize(0);

                    let s = if *set {
                        if matches!(class, BitmapClass::DocumentIds) {
                            trx.prepare_cached("INSERT INTO b (k) VALUES ($1)").await?
                        } else {
                            trx.prepare_cached(
                                "INSERT INTO b (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                            )
                            .await?
                        }
                    } else {
                        trx.prepare_cached("DELETE FROM b WHERE k = $1").await?
                    };
                    trx.execute(&s, &[&key]).await?;
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

                    let s = trx
                        .prepare_cached(concat!(
                            "INSERT INTO l (k, v) VALUES ($1, $2) ",
                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                        ))
                        .await?;
                    trx.execute(&s, &[&key, set]).await?;
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
                    let table = char::from(key.subspace());
                    let key = key.serialize(0);

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
                        return Ok(false);
                    }
                    asserted_values.insert(key, exists);
                }
            }
        }

        trx.commit().await.map(|_| true)
    }

    pub(crate) async fn purge_bitmaps(&self) -> crate::Result<()> {
        // Not needed for PostgreSQL
        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> crate::Result<()> {
        let conn = self.conn_pool.get().await?;

        let s = conn
            .prepare_cached(&format!(
                "DELETE FROM {} WHERE k >= $1 AND k < $2",
                char::from(from.subspace()),
            ))
            .await?;
        conn.execute(&s, &[&from.serialize(0), &to.serialize(0)])
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}
