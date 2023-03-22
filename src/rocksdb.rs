/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::{convert::TryInto, path::PathBuf, sync::Arc};

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBIteratorWithThreadMode, MergeOperands,
    MultiThreaded, OptimisticTransactionDB, Options,
};

use crate::{Deserialize, Error, InnerStore};

pub struct RocksDB {
    db: OptimisticTransactionDB<MultiThreaded>,
}

pub struct RocksDBIterator<'x> {
    it: DBIteratorWithThreadMode<'x, OptimisticTransactionDB<MultiThreaded>>,
}

impl Iterator for RocksDBIterator<'_> {
    type Item = (Box<[u8]>, Box<[u8]>);

    #[allow(clippy::while_let_on_iterator)]
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(result) = self.it.next() {
            if let Ok(item) = result {
                return Some(item);
            }
        }
        None
    }
}

impl InnerStore for RocksDB {
    type Iterator<'x> = RocksDBIterator<'x>;

    #[inline(always)]
    fn delete(&self, cf: crate::ColumnFamily, key: &[u8]) -> crate::Result<()> {
        self.db
            .delete_cf(&self.cf_handle(cf)?, key)
            .map_err(|err| Error::InternalError(format!("delete_cf failed: {}", err)))
    }

    #[inline(always)]
    fn set(&self, cf: crate::ColumnFamily, key: &[u8], value: &[u8]) -> crate::Result<()> {
        self.db
            .put_cf(&self.cf_handle(cf)?, key, value)
            .map_err(|err| Error::InternalError(format!("put_cf failed: {}", err)))
    }

    #[inline(always)]
    fn get<U>(&self, cf: crate::ColumnFamily, key: &[u8]) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        if let Some(bytes) = self
            .db
            .get_pinned_cf(&self.cf_handle(cf)?, key)
            .map_err(|err| Error::InternalError(format!("get_cf failed: {}", err)))?
        {
            Ok(Some(U::deserialize(&bytes).ok_or_else(|| {
                Error::DeserializeError(format!("Failed to deserialize key: {:?}", key))
            })?))
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    fn merge(&self, cf: crate::ColumnFamily, key: &[u8], value: &[u8]) -> crate::Result<()> {
        self.db
            .merge_cf(&self.cf_handle(cf)?, key, value)
            .map_err(|err| Error::InternalError(format!("merge_cf failed: {}", err)))
    }

    /*
        #[inline(always)]
        fn write(&self, batch: Vec<WriteOperation>) -> crate::Result<()> {
            let mut rocks_batch = rocksdb::WriteBatch::default();
            let cf_bitmaps = self.cf_handle(crate::ColumnFamily::Bitmaps)?;
            let cf_values = self.cf_handle(crate::ColumnFamily::Values)?;
            let cf_indexes = self.cf_handle(crate::ColumnFamily::Indexes)?;
            let cf_blobs = self.cf_handle(crate::ColumnFamily::Blobs)?;
            let cf_logs = self.cf_handle(crate::ColumnFamily::Logs)?;

            for op in batch {
                match op {
                    WriteOperation::Set { cf, key, value } => {
                        rocks_batch.put_cf(
                            match cf {
                                crate::ColumnFamily::Bitmaps => &cf_bitmaps,
                                crate::ColumnFamily::Values => &cf_values,
                                crate::ColumnFamily::Indexes => &cf_indexes,
                                crate::ColumnFamily::Blobs => &cf_blobs,
                                crate::ColumnFamily::Logs => &cf_logs,
                            },
                            key,
                            value,
                        );
                    }
                    WriteOperation::Delete { cf, key } => {
                        rocks_batch.delete_cf(
                            match cf {
                                crate::ColumnFamily::Bitmaps => &cf_bitmaps,
                                crate::ColumnFamily::Values => &cf_values,
                                crate::ColumnFamily::Indexes => &cf_indexes,
                                crate::ColumnFamily::Blobs => &cf_blobs,
                                crate::ColumnFamily::Logs => &cf_logs,
                            },
                            key,
                        );
                    }
                    WriteOperation::Merge { cf, key, value } => {
                        rocks_batch.merge_cf(
                            match cf {
                                crate::ColumnFamily::Bitmaps => &cf_bitmaps,
                                crate::ColumnFamily::Values => &cf_values,
                                crate::ColumnFamily::Indexes => &cf_indexes,
                                crate::ColumnFamily::Blobs => &cf_blobs,
                                crate::ColumnFamily::Logs => &cf_logs,
                            },
                            key,
                            value,
                        );
                    }
                }
            }
            self.db
                .write(rocks_batch)
                .map_err(|err| Error::InternalError(format!("batch write failed: {}", err)))
        }

    */

    #[inline(always)]
    fn exists(&self, cf: crate::ColumnFamily, key: &[u8]) -> crate::Result<bool> {
        Ok(self
            .db
            .get_pinned_cf(&self.cf_handle(cf)?, key)
            .map_err(|err| Error::InternalError(format!("get_cf failed: {}", err)))?
            .is_some())
    }

    #[inline(always)]
    fn multi_get<T, U>(
        &self,
        cf: crate::ColumnFamily,
        keys: Vec<U>,
    ) -> crate::Result<Vec<Option<T>>>
    where
        T: Deserialize,
        U: AsRef<[u8]>,
    {
        let cf_handle = self.cf_handle(cf)?;
        let mut results = Vec::with_capacity(keys.len());
        for value in self
            .db
            .multi_get_cf(keys.iter().map(|key| (&cf_handle, key)).collect::<Vec<_>>())
        {
            results.push(
                if let Some(bytes) = value
                    .map_err(|err| Error::InternalError(format!("multi_get_cf failed: {}", err)))?
                {
                    T::deserialize(&bytes)
                        .ok_or_else(|| {
                            Error::DeserializeError("Failed to deserialize keys.".to_string())
                        })?
                        .into()
                } else {
                    None
                },
            );
        }

        Ok(results)
    }

    #[inline(always)]
    fn iterator<'x>(
        &'x self,
        cf: crate::ColumnFamily,
        start: &[u8],
        direction: crate::Direction,
    ) -> crate::Result<Self::Iterator<'x>> {
        Ok(RocksDBIterator {
            it: self.db.iterator_cf(
                &self.cf_handle(cf)?,
                rocksdb::IteratorMode::From(
                    start,
                    match direction {
                        crate::Direction::Forward => rocksdb::Direction::Forward,
                        crate::Direction::Backward => rocksdb::Direction::Reverse,
                    },
                ),
            ),
        })
    }

    fn compact(&self, cf: crate::ColumnFamily) -> crate::Result<()> {
        self.db
            .compact_range_cf(&self.cf_handle(cf)?, None::<&[u8]>, None::<&[u8]>);
        Ok(())
    }

    fn open() -> crate::Result<Self> {
        // Create the database directory if it doesn't exist
        let path = PathBuf::from(
            "/tmp/rocksdb.test", /*&settings
                                 .get("db-path")
                                 .unwrap_or_else(|| "/usr/local/stalwart-jmap/data".to_string())*/
        );
        let mut idx_path = path;
        idx_path.push("idx");
        std::fs::create_dir_all(&idx_path).map_err(|err| {
            Error::InternalError(format!(
                "Failed to create index directory {}: {:?}",
                idx_path.display(),
                err
            ))
        })?;

        // Bitmaps
        let cf_bitmaps = {
            let mut cf_opts = Options::default();
            //cf_opts.set_max_write_buffer_number(16);
            //cf_opts.set_merge_operator("merge", bitmap_merge, bitmap_partial_merge);
            //cf_opts.set_compaction_filter("compact", bitmap_compact);
            ColumnFamilyDescriptor::new("bitmaps", cf_opts)
        };

        // Stored values
        let cf_values = {
            let mut cf_opts = Options::default();
            cf_opts.set_merge_operator_associative("merge", numeric_value_merge);
            ColumnFamilyDescriptor::new("values", cf_opts)
        };

        // Secondary indexes
        let cf_indexes = {
            let cf_opts = Options::default();
            ColumnFamilyDescriptor::new("indexes", cf_opts)
        };

        // Blobs
        let cf_blobs = {
            let mut cf_opts = Options::default();
            cf_opts.set_enable_blob_files(true);
            cf_opts.set_min_blob_size(
                16834, /*settings.parse("blob-min-size").unwrap_or(16384) */
            );
            ColumnFamilyDescriptor::new("blobs", cf_opts)
        };

        // Raft log and change log
        let cf_log = {
            let cf_opts = Options::default();
            ColumnFamilyDescriptor::new("logs", cf_opts)
        };

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);

        Ok(RocksDB {
            db: OptimisticTransactionDB::open_cf_descriptors(
                &db_opts,
                idx_path,
                vec![cf_bitmaps, cf_values, cf_indexes, cf_blobs, cf_log],
            )
            .map_err(|e| Error::InternalError(e.into_string()))?,
        })
    }

    fn close(&self) -> crate::Result<()> {
        self.db
            .flush()
            .map_err(|e| Error::InternalError(e.to_string()))?;
        self.db.cancel_all_background_work(true);
        Ok(())
    }
}

impl RocksDB {
    #[inline(always)]
    fn cf_handle(&self, cf: crate::ColumnFamily) -> crate::Result<Arc<BoundColumnFamily>> {
        self.db
            .cf_handle(match cf {
                crate::ColumnFamily::Bitmaps => "bitmaps",
                crate::ColumnFamily::Values => "values",
                crate::ColumnFamily::Indexes => "indexes",
                crate::ColumnFamily::Blobs => "blobs",
                crate::ColumnFamily::Logs => "logs",
            })
            .ok_or_else(|| {
                Error::InternalError(format!(
                    "Failed to get handle for '{:?}' column family.",
                    cf
                ))
            })
    }
}

pub fn numeric_value_merge(
    _key: &[u8],
    value: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut value = if let Some(value) = value {
        i64::from_le_bytes(value.try_into().ok()?)
    } else {
        0
    };

    for op in operands.iter() {
        value += i64::from_le_bytes(op.try_into().ok()?);
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of::<i64>());
    bytes.extend_from_slice(&value.to_le_bytes());
    Some(bytes)
}
