/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    write::{
        key::DeserializeBigEndian, AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId,
        ValueOp,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN,
};

use super::SqliteStore;

impl SqliteStore {
    pub(crate) async fn write(&self, batch: Batch) -> crate::Result<AssignedIds> {
        let mut conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = u64::MAX;
            let trx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
                        let key = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            0,
                            (&result).into(),
                        );
                        let table = char::from(class.subspace(collection));

                        match op {
                            ValueOp::Set(value) => {
                                trx.prepare_cached(&format!(
                                    "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                    table
                                ))?
                                .execute([&key, value.resolve(&result)?.as_ref()])?;
                            }
                            ValueOp::AtomicAdd(by) => {
                                if *by >= 0 {
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                                        ),
                                        table
                                    ))?
                                    .execute(params![&key, *by])?;
                                } else {
                                    trx.prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + ? WHERE k = ?"
                                    ))?
                                    .execute(params![*by, &key])?;
                                }
                            }
                            ValueOp::AddAndGet(by) => {
                                result.push_counter_id(
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = v + ",
                                            "excluded.v RETURNING v"
                                        ),
                                        table
                                    ))?
                                    .query_row(params![&key, &by], |row| row.get::<_, i64>(0))?,
                                );
                            }
                            ValueOp::Clear => {
                                trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))?
                                    .execute([&key])?;
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
                            trx.prepare_cached("INSERT OR IGNORE INTO i (k) VALUES (?)")?
                                .execute([&key])?;
                        } else {
                            trx.prepare_cached("DELETE FROM i WHERE k = ?")?
                                .execute([&key])?;
                        }
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

                            let mut query =
                                trx.prepare_cached("SELECT k FROM b WHERE k >= ? AND k <= ?")?;
                            let mut rows = query.query([&begin, &end])?;
                            let mut found_ids = RoaringBitmap::new();
                            while let Some(row) = rows.next()? {
                                let key = row.get_ref(0)?.as_bytes()?;
                                if key.len() == key_len {
                                    found_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                                }
                            }

                            document_id = found_ids.random_available_id();
                            result.push_document_id(document_id);
                        }
                        let key = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            0,
                            (&result).into(),
                        );
                        let table = char::from(class.subspace());

                        if *set {
                            if is_document_id {
                                trx.prepare_cached("INSERT INTO b (k) VALUES (?)")?
                                    .execute(params![&key])?;
                            } else {
                                trx.prepare_cached(&format!(
                                    "INSERT OR IGNORE INTO {} (k) VALUES (?)",
                                    table
                                ))?
                                .execute(params![&key])?;
                            }
                        } else {
                            trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))?
                                .execute(params![&key])?;
                        };
                    }
                    Operation::Log { set } => {
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id,
                        }
                        .serialize(0);

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")?
                            .execute([&key, set.resolve(&result)?.as_ref()])?;
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        let key = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            0,
                            (&result).into(),
                        );
                        let table = char::from(class.subspace(collection));

                        let matches = trx
                            .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))?
                            .query_row([&key], |row| {
                                Ok(assert_value.matches(row.get_ref(0)?.as_bytes()?))
                            })
                            .optional()?
                            .unwrap_or_else(|| assert_value.is_none());
                        if !matches {
                            trx.rollback()?;
                            return Err(crate::Error::AssertValueFailed);
                        }
                    }
                }
            }

            trx.commit().map(|_| result).map_err(Into::into)
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
                conn.prepare_cached(&format!("DELETE FROM {} WHERE v = 0", char::from(subspace),))?
                    .execute([])?;
            }

            Ok(())
        })
        .await
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
