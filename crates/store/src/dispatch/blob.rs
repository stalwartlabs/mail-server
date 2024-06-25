/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, ops::Range};

use utils::config::utils::ParseValue;

use crate::{BlobBackend, BlobStore, CompressionAlgo, Store};

impl BlobStore {
    pub async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let read_range = match self.compression {
            CompressionAlgo::None => range.clone(),
            CompressionAlgo::Lz4 => 0..usize::MAX,
        };

        let result = match &self.backend {
            BlobBackend::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.get_blob(key, read_range).await,
                Store::None => Err(crate::Error::InternalError("No store configured".into())),
            },
            BlobBackend::Fs(store) => store.get_blob(key, read_range).await,
            #[cfg(feature = "s3")]
            BlobBackend::S3(store) => store.get_blob(key, read_range).await,
        };

        let decompressed = match self.compression {
            CompressionAlgo::Lz4 => match result? {
                Some(data)
                    if data.last().copied().unwrap_or_default()
                        == CompressionAlgo::Lz4.marker() =>
                {
                    lz4_flex::decompress_size_prepended(
                        data.get(..data.len() - 1).unwrap_or_default(),
                    )
                    .map_err(|err| {
                        crate::Error::InternalError(format!(
                            "Failed to decompress LZ4 data: {}",
                            err
                        ))
                    })?
                }
                Some(data) => {
                    tracing::debug!("Warning: Missing LZ4 marker for key: {key:?}");
                    data
                }
                None => return Ok(None),
            },
            _ => return result,
        };

        if range.end >= decompressed.len() {
            Ok(Some(decompressed))
        } else {
            Ok(Some(
                decompressed
                    .get(range.start..range.end)
                    .unwrap_or_default()
                    .to_vec(),
            ))
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let data: Cow<[u8]> = match self.compression {
            CompressionAlgo::None => data.into(),
            CompressionAlgo::Lz4 => {
                let mut compressed = lz4_flex::compress_prepend_size(data);
                compressed.push(CompressionAlgo::Lz4.marker());
                compressed.into()
            }
        };

        match &self.backend {
            BlobBackend::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.put_blob(key, data.as_ref()).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.put_blob(key, data.as_ref()).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.put_blob(key, data.as_ref()).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.put_blob(key, data.as_ref()).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.put_blob(key, data.as_ref()).await,
                Store::None => Err(crate::Error::InternalError("No store configured".into())),
            },
            BlobBackend::Fs(store) => store.put_blob(key, data.as_ref()).await,
            #[cfg(feature = "s3")]
            BlobBackend::S3(store) => store.put_blob(key, data.as_ref()).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match &self.backend {
            BlobBackend::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.delete_blob(key).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.delete_blob(key).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.delete_blob(key).await,
                Store::None => Err(crate::Error::InternalError("No store configured".into())),
            },
            BlobBackend::Fs(store) => store.delete_blob(key).await,
            #[cfg(feature = "s3")]
            BlobBackend::S3(store) => store.delete_blob(key).await,
        }
    }

    pub fn with_compression(self, compression: CompressionAlgo) -> Self {
        Self {
            backend: self.backend,
            compression,
        }
    }
}

const MAGIC_MARKER: u8 = 0xa0;

impl CompressionAlgo {
    pub fn marker(&self) -> u8 {
        match self {
            CompressionAlgo::Lz4 => MAGIC_MARKER | 0x01,
            //CompressionAlgo::Zstd => MAGIC_MARKER | 0x02,
            CompressionAlgo::None => 0,
        }
    }
}

impl ParseValue for CompressionAlgo {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        match value {
            "lz4" => Ok(CompressionAlgo::Lz4),
            //"zstd" => Ok(CompressionAlgo::Zstd),
            "none" | "false" | "disable" | "disabled" => Ok(CompressionAlgo::None),
            algo => Err(format!("Invalid compression algorithm: {algo}",)),
        }
    }
}
