/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::{Bound, Range};
use roaring::RoaringBitmap;
use tikv_client::{BoundRange, Key as TikvKey};
use trc::EventType::Store;
use trc::StoreEvent;
use utils::BLOB_HASH_LEN;
use crate::{write::key::KeySerializer, SUBSPACE_BLOBS};
use super::write::chunking::{delete_chunked_value, put_chunked_value};
use super::read::chunking::get_chunked_value;
use super::{into_error, MAX_KEY_SIZE, MAX_SCAN_KEYS_SIZE, MAX_SCAN_VALUES_SIZE, MAX_VALUE_SIZE, TikvStore, MAX_CHUNKED_SIZED};

// TODO: Allow handling of more than MAX_SCAN_KEYS_SIZE

impl TikvStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let mut trx = self.snapshot_read().await?;

        let block_start = range.start / MAX_VALUE_SIZE;
        let bytes_start = range.start % MAX_VALUE_SIZE;
        let block_end = (range.end / MAX_VALUE_SIZE) + 1;

        let mut begin = KeySerializer::new(1 + key.len() + 2)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_start as u16)
            .finalize();
        let end = KeySerializer::new(1 + key.len() + 2)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(block_end as u16)
            .write(u8::MIN) // Null byte to make the end inclusive
            .finalize();

        let mut blob_data_opt: Option<Vec<u8>> = None;
        let mut blob_range = range.end - range.start;

        'outer: loop {
            let mut keys = trx.scan((begin, end.clone()), MAX_SCAN_VALUES_SIZE)
                .await
                .map_err(into_error)?;

            let mut counter = 0;
            let mut last_key = None;
            while let Some(kv_pair) = keys.next() {
                let key: Vec<u8> = kv_pair.0.into();
                let mut value: Vec<u8> = kv_pair.1.into();

                if let Some(blob_data) = &mut blob_data_opt {
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
                    let mut blob_data = Vec::with_capacity(blob_size);
                    blob_data.extend_from_slice(
                        value
                            .get(bytes_start..std::cmp::min(bytes_start + blob_range, value.len()))
                            .unwrap_or(&[]),
                    );
                    if blob_data.len() == blob_range {
                        return Ok(Some(blob_data));
                    }
                    blob_data_opt = Some(blob_data)
                }

                last_key = Some(key);
            }

            if counter == MAX_SCAN_VALUES_SIZE {
                // Guaranteed to have the last key
                begin = last_key.unwrap();
                continue;
            } else {
                break;
            }

        }

        Ok(blob_data_opt)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let mut trx = self.write_trx_with_backoff().await?;

        for (chunk_pos, chunk_value) in data.chunks(MAX_VALUE_SIZE).enumerate() {
            let chunk_key = KeySerializer::new(1 + key.len() + 2)
                .write(SUBSPACE_BLOBS)
                .write(key)
                .write(chunk_pos as u16)
                .finalize();

            trx.put(chunk_key, chunk_value).await.map_err(into_error)?;
        }

        trx.commit().await.map_err(into_error)?;
        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        if key.len() < BLOB_HASH_LEN {
            return Ok(false);
        }

        let begin = KeySerializer::new(1 + key.len() + 1)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(u16::MIN)
            .finalize();
        let end = KeySerializer::new(1 + key.len() + 3)
            .write(SUBSPACE_BLOBS)
            .write(key)
            .write(u16::MAX)
            .write(u8::MIN) // Null byte to make the end inclusive
            .finalize();

        let range = BoundRange::from((begin, end));

        let mut trx = self.write_trx_with_backoff().await?;

        loop {
            let keys = trx
                .scan_keys(range.clone(), MAX_SCAN_KEYS_SIZE)
                .await
                .map_err(into_error)?;

            let mut count = 0;
            for key in keys {
                count += 1;
                trx.delete(key).await.map_err(into_error)?;
            }

            if count < MAX_SCAN_KEYS_SIZE {
                break;
            }
        }

        trx.commit().await.map_err(into_error)?;

        Ok(true)
    }
}