/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::{Bound, Range};
use tikv_client::{BoundRange, Key as TikvKey};
use trc::EventType::Store;
use trc::StoreEvent;
use utils::BLOB_HASH_LEN;
use crate::SUBSPACE_BLOBS;
use crate::write::key::KeySerializer;
use super::{into_error, MAX_KEY_SIZE, MAX_SCAN_KEYS_SIZE, MAX_SCAN_VALUES_SIZE, MAX_VALUE_SIZE, TikvStore};

// TODO: Allow handling of more than MAX_SCAN_KEYS_SIZE

impl TikvStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let block_start = range.start / MAX_VALUE_SIZE as usize;
        let bytes_start = range.start % MAX_VALUE_SIZE as usize;
        let block_end = (range.end / MAX_VALUE_SIZE as usize) + 1;

        let begin = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_start as u16)
            .finalize();
        let key_len = begin.len();
        let mut begin_range = Bound::Included(TikvKey::from(begin));
        let end = KeySerializer::new(key.len() + 3)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_end as u16)
            .finalize();
        let end_range = Bound::Included(TikvKey::from(end));

        let mut trx = self.snapshot_trx().await?;

        let mut blob_data: Option<Vec<u8>> = None;
        let blob_range = range.end - range.start;

        'outer: loop {
            let bound_range = BoundRange::new(begin_range, end_range.clone());
            let mut keys = trx
                .scan_keys(bound_range, MAX_SCAN_KEYS_SIZE)
                .await
                .map_err(into_error)?;
            let mut last_key = TikvKey::default();
            let mut count = 0;
            'inner: while let Some(key) = keys.next() {
                count += 1;
                if key.len() == key_len {
                    let value = trx.get(key.clone()).await.map_err(into_error)?.unwrap();
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
                        } else if value.len() == MAX_VALUE_SIZE as usize {
                            MAX_VALUE_SIZE as usize * 2
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
                last_key = key;
            }
            if count < MAX_SCAN_KEYS_SIZE {
                break;
            } else {
                begin_range = Bound::Excluded(last_key);
                continue;
            }
        }

        Ok(blob_data)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        const N_CHUNKS: usize = (1 << 5) - 1;
        let last_chunk = std::cmp::max(
            (data.len() / MAX_VALUE_SIZE as usize)
                + if data.len() % MAX_VALUE_SIZE as usize > 0 {
                1
            } else {
                0
            },
            1,
        ) - 1;

        let mut trx = self.trx_client
            .begin_with_options(self.write_trx_options.clone())
            .await
            .map_err(into_error)?;

        for (chunk_pos, chunk_bytes) in data.chunks(MAX_VALUE_SIZE as usize).enumerate() {
            trx.put(
                KeySerializer::new(key.len() + 3)
                    .write(SUBSPACE_BLOBS)
                    .write(key)
                    .write(chunk_pos as u16)
                    .finalize(),
                chunk_bytes
            ).await.map_err(into_error)?;
            if chunk_pos == last_chunk || (chunk_pos > 0 && chunk_pos % N_CHUNKS == 0) {
                self.commit(trx, None).await?;
                if ! chunk_pos < last_chunk {
                    trx = self.trx_client
                        .begin_with_options(self.write_trx_options.clone())
                        .await
                        .map_err(into_error)?;
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

        let mut trx = self.trx_client
            .begin_with_options(self.write_trx_options.clone())
            .await
            .map_err(into_error)?;

        // Since we are deleting the entire range anyway,
        // there is absolutely no point on moving the range bounds.
        loop {
            let mut keys = trx.scan_keys(
                (
                    KeySerializer::new(key.len() + 3)
                        .write(SUBSPACE_BLOBS)
                        .write(key)
                        .write(0u16)
                        .finalize(),
                    KeySerializer::new(key.len() + 3)
                        .write(SUBSPACE_BLOBS)
                        .write(key)
                        .write(u16::MAX)
                        .finalize()
                ),
                MAX_SCAN_KEYS_SIZE
            ).await.map_err(into_error)?;

            let mut count = 1;
            while let Some(key) = keys.next() {
                count += 1;
                trx.delete(key).await.map_err(into_error)?;
            }

            // TODO: Replace with MAX_SCAN_KEYS_SIZE
            if count == 0 {
                break;
            }
        }

        self.commit(trx, None).await
    }
}