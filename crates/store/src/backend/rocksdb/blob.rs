/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use super::{RocksDbStore, CF_BLOBS};

impl RocksDbStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(&db.cf_handle(CF_BLOBS).unwrap(), key)
                .map(|obj| {
                    obj.map(|bytes| {
                        if range.start == 0 && range.end == usize::MAX {
                            bytes.to_vec()
                        } else {
                            bytes
                                .get(range.start..std::cmp::min(bytes.len(), range.end))
                                .unwrap_or_default()
                                .to_vec()
                        }
                    })
                })
                .map_err(|e| crate::Error::InternalError(format!("Failed to fetch blob: {}", e)))
        })
        .await
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.put_cf(&db.cf_handle(CF_BLOBS).unwrap(), key, data)
                .map_err(|e| crate::Error::InternalError(format!("Failed to insert blob: {}", e)))
        })
        .await
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.delete_cf(&db.cf_handle(CF_BLOBS).unwrap(), key)
                .map_err(|e| crate::Error::InternalError(format!("Failed to delete blob: {}", e)))
                .map(|_| true)
        })
        .await
    }
}
