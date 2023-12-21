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
    BitmapKey, IndexKey, Key, LogKey, ValueKey,
};

use super::SqliteStore;

impl SqliteStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<()> {
        let mut conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
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
                            trx.prepare_cached(concat!(
                                "INSERT INTO c (k, v) VALUES (?, ?) ",
                                "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                            ))?
                            .execute(params![&key, *by])?;
                        } else {
                            trx.prepare_cached("UPDATE c SET v = v + ? WHERE k = ?")?
                                .execute(params![*by, &key])?;
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
                            trx.prepare_cached(&format!(
                                "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                table
                            ))?
                            .execute([&key, value])?;
                        } else {
                            trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))?
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
                        .serialize(0);

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
                            block_num: document_id,
                        }
                        .serialize(0);

                        if *set {
                            trx.prepare_cached("INSERT OR IGNORE INTO b (k) VALUES (?)")?
                                .execute(params![&key])?;
                        } else {
                            trx.prepare_cached("DELETE FROM b WHERE k = ?")?
                                .execute(params![&key])?;
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
                        .serialize(0);

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
                        };
                        let table = char::from(key.subspace());
                        let key = key.serialize(0);

                        let matches = trx
                            .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))?
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

    pub(crate) async fn purge_bitmaps(&self) -> crate::Result<()> {
        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            conn.prepare_cached(&format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                char::from(from.subspace()),
            ))?
            .execute([from.serialize(0), to.serialize(0)])?;

            Ok(())
        })
        .await
    }
}
