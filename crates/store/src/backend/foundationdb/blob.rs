/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use foundationdb::{options::StreamingMode, KeySelector, RangeOption};
use futures::TryStreamExt;
use utils::BLOB_HASH_LEN;

use crate::{backend::foundationdb::into_error, write::key::KeySerializer, SUBSPACE_BLOBS};

use super::{FdbStore, MAX_VALUE_SIZE};

impl FdbStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let block_start = range.start / MAX_VALUE_SIZE;
        let bytes_start = range.start % MAX_VALUE_SIZE;
        let block_end = (range.end / MAX_VALUE_SIZE) + 1;

        let begin = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_start as u16)
            .finalize();
        let end = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_end as u16)
            .finalize();
        let key_len = begin.len();
        let trx = self.read_trx().await?;
        let mut values = trx.get_ranges_keyvalues(
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
        let blob_range = range.end - range.start;

        'outer: while let Some(value) = values.try_next().await.map_err(into_error)? {
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
                    } else if value.len() == MAX_VALUE_SIZE {
                        MAX_VALUE_SIZE * 2
                    } else {
                        value.len()
                    };
                    let mut blob_data_ = Vec::with_capacity(blob_size);
                    blob_data_.extend_from_slice(
                        value
                            .get(bytes_start..std::cmp::min(bytes_start + blob_range, value.len()))
                            .unwrap_or(&[]),
                    );
                    if blob_data_.len() == blob_range {
                        return Ok(Some(blob_data_));
                    }
                    blob_data = blob_data_.into();
                }
            }
        }

        Ok(blob_data)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        const N_CHUNKS: usize = (1 << 5) - 1;
        let last_chunk = std::cmp::max(
            (data.len() / MAX_VALUE_SIZE)
                + if data.len() % MAX_VALUE_SIZE > 0 {
                    1
                } else {
                    0
                },
            1,
        ) - 1;
        let mut trx = self.db.create_trx().map_err(into_error)?;

        for (chunk_pos, chunk_bytes) in data.chunks(MAX_VALUE_SIZE).enumerate() {
            trx.set(
                &KeySerializer::new(key.len() + 3)
                    .write(SUBSPACE_BLOBS)
                    .write(key)
                    .write(chunk_pos as u16)
                    .finalize(),
                chunk_bytes,
            );
            if chunk_pos == last_chunk || (chunk_pos > 0 && chunk_pos % N_CHUNKS == 0) {
                self.commit(trx, false).await?;
                if chunk_pos < last_chunk {
                    trx = self.db.create_trx().map_err(into_error)?;
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        if key.len() < BLOB_HASH_LEN {
            return Ok(false);
        }

        let trx = self.db.create_trx().map_err(into_error)?;
        trx.clear_range(
            &KeySerializer::new(key.len() + 3)
                .write(SUBSPACE_BLOBS)
                .write(key)
                .write(0u16)
                .finalize(),
            &KeySerializer::new(key.len() + 3)
                .write(SUBSPACE_BLOBS)
                .write(key)
                .write(u16::MAX)
                .finalize(),
        );

        self.commit(trx, false).await
    }
}
