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
use rocksdb::{
    compaction_filter::Decision, ColumnFamilyDescriptor, MergeOperands, OptimisticTransactionDB,
    Options,
};

use tokio::sync::oneshot;
use utils::config::{utils::AsKey, Config};

use crate::Deserialize;

use super::{RocksDbStore, CF_BITMAPS, CF_BLOBS, CF_COUNTERS, CF_INDEXES, CF_LOGS, CF_VALUES};

impl RocksDbStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        // Create the database directory if it doesn't exist
        let idx_path: PathBuf = PathBuf::from(config.value_require((&prefix, "path"))?);
        std::fs::create_dir_all(&idx_path)
            .map_err(|err| {
                config.new_build_error(
                    (&prefix, "path"),
                    format!(
                        "Failed to create database directory {}: {:?}",
                        idx_path.display(),
                        err
                    ),
                )
            })
            .ok()?;

        let mut cfs = Vec::new();

        // Bitmaps
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        cf_opts.set_merge_operator("merge", bitmap_merge, bitmap_partial_merge);
        cf_opts.set_compaction_filter("compact", bitmap_compact);
        cfs.push(ColumnFamilyDescriptor::new(CF_BITMAPS, cf_opts));

        // Counters
        let mut cf_opts = Options::default();
        cf_opts.set_merge_operator_associative("merge", numeric_value_merge);
        cfs.push(ColumnFamilyDescriptor::new(CF_COUNTERS, cf_opts));

        // Blobs
        let mut cf_opts = Options::default();
        cf_opts.set_enable_blob_files(true);
        cf_opts.set_min_blob_size(
            config
                .property_or_default((&prefix, "min-blob-size"), "16834")
                .unwrap_or(16834),
        );
        cfs.push(ColumnFamilyDescriptor::new(CF_BLOBS, cf_opts));

        // Other cfs
        for cf in [CF_INDEXES, CF_LOGS, CF_VALUES] {
            let cf_opts = Options::default();
            cfs.push(ColumnFamilyDescriptor::new(cf, cf_opts));
        }

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        db_opts.set_max_background_jobs(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts.increase_parallelism(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts.set_level_zero_file_num_compaction_trigger(1);
        db_opts.set_level_compaction_dynamic_level_bytes(true);
        //db_opts.set_keep_log_file_num(100);
        //db_opts.set_max_successive_merges(100);
        db_opts.set_write_buffer_size(
            config
                .property_or_default((&prefix, "write-buffer-size"), "134217728")
                .unwrap_or(134217728),
        );

        Some(RocksDbStore {
            db: OptimisticTransactionDB::open_cf_descriptors(&db_opts, idx_path, cfs)
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!("Failed to open database: {:?}", err),
                    )
                })
                .ok()?
                .into(),
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .property::<usize>((&prefix, "pool.workers"))
                        .filter(|v| *v > 0)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| {
                    config.new_build_error(
                        (&prefix, "pool.workers"),
                        format!("Failed to build worker pool: {:?}", err),
                    )
                })
                .ok()?,
        })
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> crate::Result<V>
    where
        U: FnMut() -> crate::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(crate::Error::InternalError(format!(
                "Worker thread failed: {}",
                err
            ))),
        }
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
    super::bitmap::bitmap_merge(existing_val, operands.len(), operands)
}

pub fn bitmap_partial_merge(
    _new_key: &[u8],
    _existing_val: Option<&[u8]>,
    _operands: &MergeOperands,
) -> Option<Vec<u8>> {
    // Force a full merge
    None
}

pub fn bitmap_compact(_level: u32, _key: &[u8], value: &[u8]) -> Decision {
    match RoaringBitmap::deserialize(value) {
        Ok(bm) if bm.is_empty() => Decision::Remove,
        _ => Decision::Keep,
    }
}
