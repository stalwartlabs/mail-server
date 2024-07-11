/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::PathBuf;

use rocksdb::{ColumnFamilyDescriptor, MergeOperands, OptimisticTransactionDB, Options};

use tokio::sync::oneshot;
use utils::config::{utils::AsKey, Config};

use crate::*;

use super::{RocksDbStore, CF_BLOBS};

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
        for subspace in [
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
        ] {
            let mut cf_opts = Options::default();
            cf_opts.set_max_write_buffer_number(16);
            cfs.push(ColumnFamilyDescriptor::new(
                std::str::from_utf8(&[subspace]).unwrap(),
                cf_opts,
            ));
        }

        // Counters
        for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            let mut cf_opts = Options::default();
            cf_opts.set_merge_operator_associative("merge", numeric_value_merge);
            cfs.push(ColumnFamilyDescriptor::new(
                std::str::from_utf8(&[subspace]).unwrap(),
                cf_opts,
            ));
        }

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
        for subspace in [
            SUBSPACE_INDEXES,
            SUBSPACE_ACL,
            SUBSPACE_DIRECTORY,
            SUBSPACE_FTS_QUEUE,
            SUBSPACE_BLOB_RESERVE,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_LOOKUP_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_SETTINGS,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_FTS_INDEX,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
        ] {
            let cf_opts = Options::default();
            cfs.push(ColumnFamilyDescriptor::new(
                std::str::from_utf8(&[subspace]).unwrap(),
                cf_opts,
            ));
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

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
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
            Err(err) => Err(trc::Cause::Thread.reason(err)),
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
