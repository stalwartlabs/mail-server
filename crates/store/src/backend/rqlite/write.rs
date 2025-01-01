/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;
use rqlite_rs::query::RqliteQuery;

use crate::{
    write::{
        key::DeserializeBigEndian, AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId,
        ValueOp,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN,
};

use super::{into_error, RqliteStore};

impl RqliteStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        let mut conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut change_id = u64::MAX;
            let queries: Vec<RqliteQuery> = vec![];
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
                                queries.push(
                                    rqlite_rs::query!(
                                        &format!(
                                            "INSERT OR REPLACE INTO {} (k, v) VALUES (?, ?)",
                                            table
                                        ),
                                        key,
                                        value.resolve(&result)?.as_ref()
                                    )
                                    .await,
                                );
                            }
                            ValueOp::AtomicAdd(by) => {
                                if *by >= 0 {
                                    queries.push(
                                        rqlite_rs::query!(
                                            &format!(
                                                concat!(
                                                "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                                "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
                                            ),
                                                table
                                            ),
                                            key,
                                            *by
                                        )
                                        .await,
                                    );
                                } else {
                                    queries.push(
                                        rqlite_rs::query!(
                                            &format!("UPDATE {table} SET v = v + ? WHERE k = ?"),
                                            *by,
                                            key
                                        )
                                        .await,
                                    );
                                }
                            }
                            ValueOp::AddAndGet(by) => {
                                // NOTE: escapes the transaction
                                result.push_counter_id(
                                    conn.fetch(
                                        rqlite_rs::query!(
                                            &format!(
                                                concat!(
                                                    "INSERT INTO {} (k, v) VALUES (?, ?) ",
                                                    "ON CONFLICT(k) DO UPDATE SET v = v + ",
                                                    "excluded.v RETURNING v"
                                                ),
                                                table
                                            ),
                                            key,
                                            *by
                                        )
                                        .await,
                                    )
                                    .await
                                    .map_err(into_error)?
                                    .first()
                                    .map(|row| row.get::<_, i64>(0))
                                    .map_err(into_error)?,
                                );
                            }
                            ValueOp::Clear => {
                                queries.push(rqlite_rs::query!(
                                    &format!("DELETE FROM {} WHERE k = ?", table),
                                    key
                                ));
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
                            queries.push(
                                rqlite_rs::query!("INSERT OR IGNORE INTO i (k) VALUES (?)", key)
                                    .await,
                            );
                        } else {
                            queries.push(rqlite_rs::query!("DELETE FROM i WHERE k = ?", key).await);
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

                            // NOTE: escapes the transaction
                            let rows = rqlite_rs::query!(
                                "SELECT k FROM b WHERE k >= ? AND k <= ?",
                                begin,
                                end
                            )
                            .await
                            .map_err(into_error)?;

                            let mut found_ids = RoaringBitmap::new();
                            for row in rows {
                                let key = row
                                    .get_by_index(0)
                                    .map_err(into_error)?
                                    .as_bytes()
                                    .map_err(into_error)?;
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
                                queries.push(
                                    rqlite_rs::query!("INSERT INTO b (k) VALUES (?)", key).await,
                                );
                            } else {
                                queries.push(
                                    rqlite_rs::query!(
                                        &format!("INSERT OR IGNORE INTO {} (k) VALUES (?)", table),
                                        key
                                    )
                                    .await,
                                );
                            }
                        } else {
                            queries.push(
                                rqlite_rs::query!(
                                    &format!("DELETE FROM {} WHERE k = ?", table),
                                    key
                                )
                                .await,
                            );
                        };
                    }
                    Operation::Log { set } => {
                        let key = LogKey {
                            account_id,
                            collection,
                            change_id,
                        }
                        .serialize(0);

                        queries.push(
                            rqlite_rs::query!(
                                "INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)",
                                key,
                                set.resolve(&result).map_err(into_error)?.as_ref()
                            )
                            .await,
                        );
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

                        // NOTE: escapes the transaction
                        let matches = conn
                            .fetch(
                                rqlite_rs::query!(
                                    &format!("SELECT v FROM {} WHERE k = ?", table),
                                    key
                                )
                                .await,
                            )
                            .await
                            .map_err(into_error)?
                            .first()
                            .map(|row| Ok(assert_value.matches(row.get_by_index(0)?.as_bytes()?)))
                            .map_err(into_error)?
                            .unwrap_or_else(|| assert_value.is_none());

                        if !matches {
                            return Err(trc::StoreEvent::AssertValueFailed.into());
                        }
                    }
                }
            }

            conn.transaction(queries).await.map_err(into_error)?;
        })
        .await
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
                conn.exec(rqlite_rs::query!(&format!(
                    "DELETE FROM {} WHERE v = 0",
                    char::from(subspace),
                )))
                .await
                .map_err(into_error)?;
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            conn.exec(rqlite_rs::query!(&format!(
                "DELETE FROM {} WHERE k >= ? AND k < ?",
                char::from(from.subspace()),
            )))
            .await
            .map_err(into_error)?
            .execute([from.serialize(0), to.serialize(0)])
            .map_err(into_error)?;

            Ok(())
        })
        .await
    }
}
