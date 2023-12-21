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
use mysql_async::{params, prelude::Queryable, Conn, Error, IsolationLevel, Row, TxOpts};
use rand::Rng;

use crate::{
    write::{
        Batch, BitmapClass, Operation, ValueClass, ValueOp, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, ValueKey,
};

use super::MysqlStore;

impl MysqlStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut conn = self.conn_pool.get_conn().await?;

        loop {
            match self.write_trx(&mut conn, &batch).await {
                Ok(success) => {
                    return if success {
                        Ok(())
                    } else {
                        Err(crate::Error::AssertValueFailed)
                    };
                }
                Err(Error::Server(err))
                    if [1062, 1213].contains(&err.code)
                        && retry_count < MAX_COMMIT_ATTEMPTS
                        && start.elapsed() < MAX_COMMIT_TIME =>
                {
                    let backoff = rand::thread_rng().gen_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    retry_count += 1;
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
    }

    async fn write_trx(&self, conn: &mut Conn, batch: &Batch) -> Result<bool, mysql_async::Error> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut asserted_values = AHashMap::new();
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await?;

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
                            .prep(concat!(
                                "INSERT INTO c (k, v) VALUES (?, ?) ",
                                "ON DUPLICATE KEY UPDATE v = v + VALUES(v)"
                            ))
                            .await?;
                        trx.exec_drop(&s, (key, by)).await?;
                    } else {
                        let s = trx.prep("UPDATE c SET v = v + ? WHERE k = ?").await?;
                        trx.exec_drop(&s, (by, key)).await?;
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
                        let exists = asserted_values.get(&key);
                        let s = if let Some(exists) = exists {
                            if *exists {
                                trx.prep(&format!("UPDATE {} SET v = :v WHERE k = :k", table))
                                    .await?
                            } else {
                                trx.prep(&format!("INSERT INTO {} (k, v) VALUES (:k, :v)", table))
                                    .await?
                            }
                        } else {
                            trx
                            .prep(
                                &format!("INSERT INTO {} (k, v) VALUES (:k, :v) ON DUPLICATE KEY UPDATE v = VALUES(v)", table),
                            )
                            .await?
                        };

                        match trx.exec_drop(&s, params! {"k" => key, "v" => value}).await {
                            Ok(_) => {
                                if exists.is_some() && trx.affected_rows() == 0 {
                                    trx.rollback().await?;
                                    return Ok(false);
                                }
                            }
                            Err(err) => {
                                trx.rollback().await?;
                                return Err(err);
                            }
                        }

                        if matches!(class, ValueClass::ReservedId) {
                            // Make sure the reserved id is not already in use
                            let s = trx.prep("SELECT 1 FROM b WHERE k = ?").await?;
                            let key = BitmapKey {
                                account_id,
                                collection,
                                class: BitmapClass::DocumentIds,
                                block_num: document_id,
                            }
                            .serialize(0);
                            if trx.exec_first::<Row, _, _>(&s, (key,)).await?.is_some() {
                                trx.rollback().await?;
                                return Ok(false);
                            }
                        }
                    } else {
                        let s = trx
                            .prep(&format!("DELETE FROM {} WHERE k = ?", table))
                            .await?;
                        trx.exec_drop(&s, (key,)).await?;
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
                    let key = BitmapKey {
                        account_id,
                        collection,
                        class,
                        block_num: document_id,
                    }
                    .serialize(0);

                    let s = if *set {
                        if matches!(class, BitmapClass::DocumentIds) {
                            trx.prep("INSERT INTO b (k) VALUES (?)").await?
                        } else {
                            trx.prep("INSERT IGNORE INTO b (k) VALUES (?)").await?
                        }
                    } else {
                        trx.prep("DELETE FROM b WHERE k = ?").await?
                    };
                    trx.exec_drop(&s, (key,)).await?;
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
                        .prep("INSERT INTO l (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)")
                        .await?;
                    trx.exec_drop(&s, (key, set)).await?;
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
                        .prep(&format!("SELECT v FROM {} WHERE k = ? FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .exec_first::<Vec<u8>, _, _>(&s, (&key,))
                        .await?
                        .map(|bytes| (true, assert_value.matches(&bytes)))
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
                        trx.rollback().await?;
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
        let mut conn = self.conn_pool.get_conn().await?;

        let s = conn
            .prep(&format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                char::from(from.subspace()),
            ))
            .await?;
        conn.exec_drop(&s, (&from.serialize(0), &to.serialize(0)))
            .await
            .map_err(Into::into)
    }
}
