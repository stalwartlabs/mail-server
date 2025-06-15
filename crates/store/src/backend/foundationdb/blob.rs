/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FdbStore, MAX_VALUE_SIZE};
use crate::{
    IterateParams, SUBSPACE_BLOBS,
    backend::foundationdb::into_error,
    write::{AnyKey, key::KeySerializer},
};
use std::ops::Range;
use trc::AddContext;
use utils::BLOB_HASH_LEN;

impl FdbStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let block_start = range.start / MAX_VALUE_SIZE;
        let bytes_start = range.start % MAX_VALUE_SIZE;
        let block_end = (range.end / MAX_VALUE_SIZE) + 1;

        let begin = KeySerializer::new(key.len() + 2)
            .write(key)
            .write(block_start as u16)
            .finalize();
        let end = KeySerializer::new(key.len() + 2)
            .write(key)
            .write(block_end as u16)
            .finalize();
        let key_len = begin.len();

        let mut blob_data: Option<Vec<u8>> = None;
        let blob_range = range.end - range.start;

        self.iterate(
            IterateParams::new(
                AnyKey {
                    subspace: SUBSPACE_BLOBS,
                    key: begin,
                },
                AnyKey {
                    subspace: SUBSPACE_BLOBS,
                    key: end,
                },
            ),
            |key, value| {
                if key.len() == key_len {
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
                            return Ok(false);
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
                                .get(
                                    bytes_start
                                        ..std::cmp::min(bytes_start + blob_range, value.len()),
                                )
                                .unwrap_or(&[]),
                        );
                        let is_done = blob_data_.len() == blob_range;
                        blob_data = blob_data_.into();
                        if is_done {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

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
