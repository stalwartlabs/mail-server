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

use std::ops::Range;

use super::{RocksDbStore, CF_BLOBS};

impl RocksDbStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(&db.cf_handle(CF_BLOBS).unwrap(), key)
                .map(|obj| {
                    obj.map(|bytes| {
                        if range.start == 0 && range.end == u32::MAX {
                            bytes.to_vec()
                        } else {
                            bytes
                                .get(
                                    range.start as usize
                                        ..std::cmp::min(bytes.len(), range.end as usize),
                                )
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
