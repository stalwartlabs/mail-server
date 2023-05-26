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

use std::path::PathBuf;

use roaring::RoaringBitmap;
use rocksdb::{ColumnFamilyDescriptor, MergeOperands, OptimisticTransactionDB, Options};

use crate::{Deserialize, Error, Store};

use super::{CF_BITMAPS, CF_BLOBS, CF_INDEXES, CF_LOGS, CF_VALUES};

impl Store {
    pub fn open() -> crate::Result<Self> {
        // Create the database directory if it doesn't exist
        let path = PathBuf::from(
            "/tmp/rocksdb_test", /*&settings
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
            cf_opts.set_merge_operator("merge", bitmap_merge, bitmap_partial_merge);
            cf_opts.set_compaction_filter("compact", bitmap_compact);
            ColumnFamilyDescriptor::new(CF_BITMAPS, cf_opts)
        };

        // Stored values
        let cf_values = {
            let mut cf_opts = Options::default();
            cf_opts.set_merge_operator_associative("merge", numeric_value_merge);
            ColumnFamilyDescriptor::new(CF_VALUES, cf_opts)
        };

        // Secondary indexes
        let cf_indexes = {
            let cf_opts = Options::default();
            ColumnFamilyDescriptor::new(CF_INDEXES, cf_opts)
        };

        // Blobs
        let cf_blobs = {
            let mut cf_opts = Options::default();
            cf_opts.set_enable_blob_files(true);
            cf_opts.set_min_blob_size(
                16834, /*settings.parse("blob-min-size").unwrap_or(16384) */
            );
            ColumnFamilyDescriptor::new(CF_BLOBS, cf_opts)
        };

        // Raft log and change log
        let cf_log = {
            let cf_opts = Options::default();
            ColumnFamilyDescriptor::new(CF_LOGS, cf_opts)
        };

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);

        Ok(Store {
            db: OptimisticTransactionDB::open_cf_descriptors(
                &db_opts,
                idx_path,
                vec![cf_bitmaps, cf_values, cf_indexes, cf_blobs, cf_log],
            )
            .map_err(|e| Error::InternalError(e.into_string()))?,
        })
    }

    pub fn close(&self) -> crate::Result<()> {
        self.db
            .flush()
            .map_err(|e| Error::InternalError(e.to_string()))?;
        self.db.cancel_all_background_work(true);
        Ok(())
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

pub fn bitmap_merge(
    _new_key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    super::bitmap::bitmap_merge(existing_val, operands.len(), operands.into_iter())
}

pub fn bitmap_partial_merge(
    _new_key: &[u8],
    _existing_val: Option<&[u8]>,
    _operands: &MergeOperands,
) -> Option<Vec<u8>> {
    // Force a full merge
    None
}

pub fn bitmap_compact(
    _level: u32,
    _key: &[u8],
    value: &[u8],
) -> rocksdb::compaction_filter::Decision {
    match RoaringBitmap::deserialize(value) {
        Some(bm) if bm.is_empty() => rocksdb::compaction_filter::Decision::Remove,
        _ => rocksdb::compaction_filter::Decision::Keep,
    }
}
