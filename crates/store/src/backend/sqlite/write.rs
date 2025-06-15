/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error};
use crate::{
    IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_QUOTA, U64_LEN,
    write::{AssignedIds, Batch, BitmapClass, Operation, ValueClass, ValueOp},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use trc::AddContext;

impl SqliteStore {
    pub(crate) async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let mut conn = self
            .conn_pool
            .get()
            .map_err(into_error)
            .caused_by(trc::location!())?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = 0u64;
            let trx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(into_error)
                .caused_by(trc::location!())?;
            let mut result = AssignedIds::default();
            let has_changes = !batch.changes.is_empty();

            if has_changes {
                for &account_id in batch.changes.keys() {
                    let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                    let change_id = trx
                        .prepare_cached(concat!(
                            "INSERT INTO n (k, v) VALUES (?, ?) ",
                            "ON CONFLICT(k) DO UPDATE SET v = v + ",
                            "excluded.v RETURNING v"
                        ))
                        .map_err(into_error)
                        .caused_by(trc::location!())?
                        .query_row(params![&key, &1i64], |row| row.get::<_, i64>(0))
                        .map_err(into_error)
                        .caused_by(trc::location!())?;
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

                                trx.prepare_cached(&format!(
                                    "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                    table
                                ))
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key, value])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                            }
                            ValueOp::AtomicAdd(by) => {
                                if *by >= 0 {
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                                        ),
                                        table
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute(params![&key, *by])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                                } else {
                                    trx.prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + ? WHERE k = ?"
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute(params![*by, &key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
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
                                    ))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .query_row(params![&key, &*by], |row| row.get::<_, i64>(0))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?,
                                );
                            }
                            ValueOp::Clear => {
                                trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute([&key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
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
                            trx.prepare_cached("INSERT OR IGNORE INTO i (k) VALUES (?)")
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        } else {
                            trx.prepare_cached("DELETE FROM i WHERE k = ?")
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute([&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        }
                    }
                    Operation::Bitmap { class, set } => {
                        let is_document_id = matches!(class, BitmapClass::DocumentIds);
                        let key = class.serialize(account_id, collection, document_id, 0);
                        let table = char::from(class.subspace());

                        if *set {
                            if is_document_id {
                                trx.prepare_cached("INSERT INTO b (k) VALUES (?)")
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?
                                    .execute(params![&key])
                                    .map_err(into_error)
                                    .caused_by(trc::location!())?;
                            } else {
                                trx.prepare_cached(&format!(
                                    "INSERT OR IGNORE INTO {} (k) VALUES (?)",
                                    table
                                ))
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute(params![&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                            }
                        } else {
                            trx.prepare_cached(&format!("DELETE FROM {} WHERE k = ?", table))
                                .map_err(into_error)
                                .caused_by(trc::location!())?
                                .execute(params![&key])
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                        };
                    }
                    Operation::Log { collection, set } => {
                        let key = LogKey {
                            account_id,
                            collection: *collection,
                            change_id,
                        }
                        .serialize(0);

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .execute([&key, set])
                            .map_err(into_error)
                            .caused_by(trc::location!())?;
                    }
                    Operation::AssertValue {
                        class,
                        assert_value,
                    } => {
                        let key = class.serialize(account_id, collection, document_id, 0);
                        let table = char::from(class.subspace(collection));

                        let matches = trx
                            .prepare_cached(&format!("SELECT v FROM {} WHERE k = ?", table))
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .query_row([&key], |row| {
                                Ok(assert_value.matches(row.get_ref(0)?.as_bytes()?))
                            })
                            .optional()
                            .map_err(into_error)
                            .caused_by(trc::location!())?
                            .unwrap_or_else(|| assert_value.is_none());
                        if !matches {
                            trx.rollback()
                                .map_err(into_error)
                                .caused_by(trc::location!())?;
                            return Err(trc::StoreEvent::AssertValueFailed
                                .into_err()
                                .caused_by(trc::location!()));
                        }
                    }
                }
            }

            trx.commit().map(|_| result).map_err(into_error)
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let conn = self
            .conn_pool
            .get()
            .map_err(into_error)
            .caused_by(trc::location!())?;
        self.spawn_worker(move || {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
                conn.prepare_cached(&format!("DELETE FROM {} WHERE v = 0", char::from(subspace),))
                    .map_err(into_error)
                    .caused_by(trc::location!())?
                    .execute([])
                    .map_err(into_error)
                    .caused_by(trc::location!())?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self
            .conn_pool
            .get()
            .map_err(into_error)
            .caused_by(trc::location!())?;
        self.spawn_worker(move || {
            conn.prepare_cached(&format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                char::from(from.subspace()),
            ))
            .map_err(into_error)
            .caused_by(trc::location!())?
            .execute([from.serialize(0), to.serialize(0)])
            .map_err(into_error)
            .caused_by(trc::location!())?;

            Ok(())
        })
        .await
    }
}
