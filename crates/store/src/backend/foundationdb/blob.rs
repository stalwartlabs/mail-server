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

use foundationdb::{options::StreamingMode, FdbError, KeySelector, RangeOption};
use futures::StreamExt;

use crate::{write::key::KeySerializer, Error, BLOB_HASH_LEN, SUBSPACE_BLOB_DATA};

use super::FdbStore;

const MAX_BLOCK_SIZE: usize = 100000;

impl FdbStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let block_start = range.start as usize / MAX_BLOCK_SIZE;
        let bytes_start = range.start as usize % MAX_BLOCK_SIZE;
        let block_end = (range.end as usize / MAX_BLOCK_SIZE) + 1;

        let begin = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOB_DATA)
            .write(key)
            .write(block_start as u16)
            .finalize();
        let end = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOB_DATA)
            .write(key)
            .write(block_end as u16)
            .finalize();
        let key_len = begin.len();
        let trx = self.db.create_trx()?;
        let mut values = trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(begin),
                end: KeySelector::first_greater_or_equal(end),
                mode: StreamingMode::WantAll,
                reverse: false,
                ..RangeOption::default()
            },
            true,
        );
        let mut blob_data: Option<Vec<u8>> = None;
        let blob_range = (range.end - range.start) as usize;

        'outer: while let Some(values) = values.next().await {
            for value in values? {
                let key = value.key();
                if key.len() == key_len {
                    let value = value.value();
                    if let Some(blob_data) = &mut blob_data {
                        blob_data.extend_from_slice(
                            value
                                .get(
                                    ..std::cmp::min(
                                        blob_range.saturating_sub(blob_data.len()),
                                        value.len(),
                                    ),
                                )
                                .unwrap_or(&[]),
                        );
                        if blob_data.len() == blob_range {
                            break 'outer;
                        }
                    } else {
                        let blob_size = if blob_range <= (5 * (1 << 20)) {
                            blob_range
                        } else if value.len() == MAX_BLOCK_SIZE {
                            MAX_BLOCK_SIZE * 2
                        } else {
                            value.len()
                        };
                        let mut blob_data_ = Vec::with_capacity(blob_size);
                        blob_data_.extend_from_slice(
                            value
                                .get(
                                    bytes_start
                                        ..std::cmp::min(bytes_start + blob_range, value.len()),
                                )
                                .unwrap_or(&[]),
                        );
                        if blob_data_.len() == blob_range {
                            return Ok(Some(blob_data_));
                        }
                        blob_data = blob_data_.into();
                    }
                }
            }
        }

        Ok(blob_data)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        for (chunk_pos, chunk_bytes) in data.chunks(MAX_BLOCK_SIZE).enumerate() {
            let trx = self.db.create_trx()?;
            trx.set(
                &KeySerializer::new(key.len() + 3)
                    .write(SUBSPACE_BLOB_DATA)
                    .write(key)
                    .write(chunk_pos as u16)
                    .finalize(),
                chunk_bytes,
            );
            trx.commit()
                .await
                .map_err(|err| Error::from(FdbError::from(err)))?;
        }

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        if key.len() < BLOB_HASH_LEN {
            return Ok(false);
        }

        let trx = self.db.create_trx()?;
        trx.clear_range(
            &KeySerializer::new(key.len() + 3)
                .write(SUBSPACE_BLOB_DATA)
                .write(key)
                .write(0u16)
                .finalize(),
            &KeySerializer::new(key.len() + 3)
                .write(SUBSPACE_BLOB_DATA)
                .write(key)
                .write(u16::MAX)
                .finalize(),
        );
        match trx.commit().await {
            Ok(_) => Ok(true),
            Err(err) => Err(FdbError::from(err).into()),
        }
    }
}
