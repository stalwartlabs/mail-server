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

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    write::{Batch, Operation, ValueOp},
    BitmapKey, IndexKey, Key, LogKey, StoreWrite, ValueKey,
};

use super::{SqliteStore, BITS_MASK, BITS_PER_BLOCK};

const INSERT_QUERIES: &[&str] = &[
    "INSERT INTO b (z, a) VALUES (?, ?)",
    "INSERT INTO b (z, b) VALUES (?, ?)",
    "INSERT INTO b (z, c) VALUES (?, ?)",
    "INSERT INTO b (z, d) VALUES (?, ?)",
    "INSERT INTO b (z, e) VALUES (?, ?)",
    "INSERT INTO b (z, f) VALUES (?, ?)",
    "INSERT INTO b (z, g) VALUES (?, ?)",
    "INSERT INTO b (z, h) VALUES (?, ?)",
    "INSERT INTO b (z, i) VALUES (?, ?)",
    "INSERT INTO b (z, j) VALUES (?, ?)",
    "INSERT INTO b (z, k) VALUES (?, ?)",
    "INSERT INTO b (z, l) VALUES (?, ?)",
    "INSERT INTO b (z, m) VALUES (?, ?)",
    "INSERT INTO b (z, n) VALUES (?, ?)",
    "INSERT INTO b (z, o) VALUES (?, ?)",
    "INSERT INTO b (z, p) VALUES (?, ?)",
];
const SET_QUERIES: &[&str] = &[
    "UPDATE b SET a = a | ? WHERE z = ?",
    "UPDATE b SET b = b | ? WHERE z = ?",
    "UPDATE b SET c = c | ? WHERE z = ?",
    "UPDATE b SET d = d | ? WHERE z = ?",
    "UPDATE b SET e = e | ? WHERE z = ?",
    "UPDATE b SET f = f | ? WHERE z = ?",
    "UPDATE b SET g = g | ? WHERE z = ?",
    "UPDATE b SET h = h | ? WHERE z = ?",
    "UPDATE b SET i = i | ? WHERE z = ?",
    "UPDATE b SET j = j | ? WHERE z = ?",
    "UPDATE b SET k = k | ? WHERE z = ?",
    "UPDATE b SET l = l | ? WHERE z = ?",
    "UPDATE b SET m = m | ? WHERE z = ?",
    "UPDATE b SET n = n | ? WHERE z = ?",
    "UPDATE b SET o = o | ? WHERE z = ?",
    "UPDATE b SET p = p | ? WHERE z = ?",
];
const CLEAR_QUERIES: &[&str] = &[
    "UPDATE b SET a = a & ? WHERE z = ?",
    "UPDATE b SET b = b & ? WHERE z = ?",
    "UPDATE b SET c = c & ? WHERE z = ?",
    "UPDATE b SET d = d & ? WHERE z = ?",
    "UPDATE b SET e = e & ? WHERE z = ?",
    "UPDATE b SET f = f & ? WHERE z = ?",
    "UPDATE b SET g = g & ? WHERE z = ?",
    "UPDATE b SET h = h & ? WHERE z = ?",
    "UPDATE b SET i = i & ? WHERE z = ?",
    "UPDATE b SET j = j & ? WHERE z = ?",
    "UPDATE b SET k = k & ? WHERE z = ?",
    "UPDATE b SET l = l & ? WHERE z = ?",
    "UPDATE b SET m = m & ? WHERE z = ?",
    "UPDATE b SET n = n & ? WHERE z = ?",
    "UPDATE b SET o = o & ? WHERE z = ?",
    "UPDATE b SET p = p & ? WHERE z = ?",
];

#[async_trait::async_trait]
impl StoreWrite for SqliteStore {
    async fn write(&self, batch: Batch) -> crate::Result<()> {
        let mut conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut bitmap_block_num = 0;
            let mut bitmap_col_num = 0;
            let mut bitmap_value_set = 0i64;
            let mut bitmap_value_clear = 0i64;
            let trx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

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
                        bitmap_block_num = document_id / BITS_PER_BLOCK;
                        let index = document_id & BITS_MASK;
                        bitmap_col_num = (index / 64) as usize;
                        bitmap_value_set = (1u64 << (index as u64 & 63)) as i64;
                        bitmap_value_clear = (!(1u64 << (index as u64 & 63))) as i64;
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

                        if *by >= 0 {
                            trx.prepare_cached(concat!(
                                "INSERT INTO q (k, v) VALUES (?, ?) ",
                                "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                            ))?
                            .execute(params![&key, *by])?;
                        } else {
                            trx.prepare_cached("UPDATE q SET v = v + ? WHERE k = ?")?
                                .execute(params![*by, &key])?;
                        }
                    }
                    Operation::Value { class, op } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            class,
                        }
                        .serialize(false);

                        if let ValueOp::Set(value) = op {
                            trx.prepare_cached("INSERT OR REPLACE INTO v (k, v) VALUES (?, ?)")?
                                .execute([&key, value])?;
                        } else {
                            trx.prepare_cached("DELETE FROM v WHERE k = ?")?
                                .execute([&key])?;
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
                            trx.prepare_cached("INSERT OR IGNORE INTO i (k) VALUES (?)")?
                                .execute([&key])?;
                        } else {
                            trx.prepare_cached("DELETE FROM i WHERE k = ?")?
                                .execute([&key])?;
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            class,
                            block_num: bitmap_block_num,
                        }
                        .serialize(false);

                        if *set {
                            trx.prepare_cached(SET_QUERIES[bitmap_col_num])?
                                .execute(params![bitmap_value_set, &key])?;
                            if trx.changes() == 0 {
                                trx.prepare_cached(INSERT_QUERIES[bitmap_col_num])?
                                    .execute(params![&key, bitmap_value_set])?;
                            }
                        } else {
                            trx.prepare_cached(CLEAR_QUERIES[bitmap_col_num])?
                                .execute(params![bitmap_value_clear, &key])?;
                        };
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

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")?
                            .execute([&key, set])?;
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
                        .serialize(false);

                        let matches = trx
                            .prepare_cached("SELECT v FROM v WHERE k = ?")?
                            .query_row([&key], |row| {
                                Ok(assert_value.matches(row.get_ref(0)?.as_bytes()?))
                            })
                            .optional()?
                            .unwrap_or_else(|| assert_value.is_none());
                        if !matches {
                            return Err(crate::Error::AssertValueFailed);
                        }
                    }
                }
            }

            trx.commit().map_err(Into::into)
        })
        .await
    }

    #[cfg(feature = "test_mode")]
    async fn destroy(&self) {
        use crate::{
            SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_QUOTAS, SUBSPACE_VALUES,
        };

        let conn = self.conn_pool.get().unwrap();
        for table in [
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_BITMAPS,
            SUBSPACE_INDEXES,
            SUBSPACE_QUOTAS,
        ] {
            conn.execute(&format!("DROP TABLE {}", char::from(table)), [])
                .unwrap();
        }
        self.create_tables().unwrap();
    }
}
