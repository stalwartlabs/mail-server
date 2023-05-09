use rusqlite::{params, OptionalExtension};

use crate::{
    write::{Batch, Operation},
    AclKey, BitmapKey, IndexKey, Key, LogKey, Serialize, Store, ValueKey,
};

use super::{BITS_MASK, BITS_PER_BLOCK};

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

impl Store {
    pub async fn write(&self, batch: Batch) -> crate::Result<()> {
        let mut conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;
            let mut bitmap_block_num = 0;
            let mut bitmap_col_num = 0;
            let mut bitmap_value_set = 0i64;
            let mut bitmap_value_clear = 0i64;
            let trx = conn.transaction()?;

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
                    Operation::Value { family, field, set } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            family: *family,
                            field: *field,
                        }
                        .serialize();

                        if let Some(value) = set {
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
                        .serialize();

                        if *set {
                            trx.prepare_cached("INSERT OR REPLACE INTO i (k) VALUES (?)")?
                                .execute([&key])?;
                        } else {
                            trx.prepare_cached("DELETE FROM i WHERE k = ?")?
                                .execute([&key])?;
                        }
                    }
                    Operation::Bitmap {
                        family,
                        field,
                        key,
                        set,
                    } => {
                        let key = BitmapKey {
                            account_id,
                            collection,
                            family: *family,
                            field: *field,
                            block_num: bitmap_block_num,
                            key,
                        }
                        .serialize();

                        if *set {
                            //trx.prepare_cached("INSERT OR IGNORE INTO b (z) VALUES (?)")?
                            //    .execute([&key])?;
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
                    Operation::Acl {
                        grant_account_id,
                        set,
                    } => {
                        let key = AclKey {
                            grant_account_id: *grant_account_id,
                            to_account_id: account_id,
                            to_collection: collection,
                            to_document_id: document_id,
                        }
                        .serialize();

                        if let Some(value) = set {
                            trx.prepare_cached("INSERT OR REPLACE INTO v (k, v) VALUES (?, ?)")?
                                .execute([&key, value])?;
                        } else {
                            trx.prepare_cached("DELETE FROM v WHERE k = ?")?
                                .execute([&key])?;
                        }
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
                        .serialize();

                        trx.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")?
                            .execute([&key, set])?;
                    }
                    Operation::AssertValue {
                        field,
                        family,
                        assert_value,
                    } => {
                        let key = ValueKey {
                            account_id,
                            collection,
                            document_id,
                            family: *family,
                            field: *field,
                        }
                        .serialize();
                        let matches = trx
                            .prepare_cached("SELECT v FROM v WHERE k = ?")?
                            .query_row([&key], |row| {
                                Ok(assert_value.matches(row.get_ref(0)?.as_bytes()?))
                            })
                            .optional()?
                            .unwrap_or(false);
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

    #[inline(always)]
    pub async fn set_value(&self, key: impl Key, value: impl Serialize) -> crate::Result<()> {
        let key = key.serialize();
        let value = value.serialize();

        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            conn.prepare_cached("INSERT OR REPLACE INTO l (k, v) VALUES (?, ?)")?
                .execute([&key, &value])
                .map_err(Into::into)
        })
        .await?;

        Ok(())
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        use crate::{SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_VALUES};

        let conn = self.conn_pool.get().unwrap();
        for table in [
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_BITMAPS,
            SUBSPACE_INDEXES,
        ] {
            conn.execute(&format!("DROP TABLE {}", char::from(table)), [])
                .unwrap();
        }
        self.create_tables().unwrap();
    }
}
