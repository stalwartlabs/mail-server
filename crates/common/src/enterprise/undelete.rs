/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use serde::{Deserialize, Serialize};
use store::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, BatchBuilder, BlobOp, ValueClass,
    },
    IterateParams, ValueKey, U32_LEN, U64_LEN,
};
use utils::{BlobHash, BLOB_HASH_LEN};

use crate::Core;

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedBlob<H, T, C> {
    pub hash: H,
    pub size: usize,
    #[serde(rename = "deletedAt")]
    pub deleted_at: T,
    #[serde(rename = "expiresAt")]
    pub expires_at: T,
    pub collection: C,
}

impl Core {
    pub fn hold_undelete(
        &self,
        batch: &mut BatchBuilder,
        collection: u8,
        blob_hash: &BlobHash,
        blob_size: usize,
    ) {
        if let Some(hold_period) = self.enterprise.as_ref().and_then(|e| e.undelete_period) {
            let now = now();

            batch.set(
                BlobOp::Reserve {
                    hash: blob_hash.clone(),
                    until: now + hold_period.as_secs(),
                },
                KeySerializer::new(U64_LEN + U64_LEN)
                    .write(blob_size as u32)
                    .write(now)
                    .write(collection)
                    .finalize(),
            );
        }
    }

    pub async fn list_deleted(
        &self,
        account_id: u32,
    ) -> store::Result<Vec<DeletedBlob<BlobHash, u64, u8>>> {
        let from_key = ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: account_id + 1,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(),
                until: 0,
            }),
        };

        let now = now();
        let mut results = Vec::new();

        self.storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let expires_at = key.deserialize_be_u64(key.len() - U64_LEN)?;
                    if value.len() == U32_LEN + U64_LEN + 1 && expires_at > now {
                        results.push(DeletedBlob {
                            hash: BlobHash::try_from_hash_slice(
                                key.get(U32_LEN..U32_LEN + BLOB_HASH_LEN).ok_or_else(|| {
                                    store::Error::InternalError(format!(
                                        "Invalid key {key:?} in blob hash tables"
                                    ))
                                })?,
                            )
                            .unwrap(),
                            size: value.deserialize_be_u32(0)? as usize,
                            deleted_at: value.deserialize_be_u64(U32_LEN)?,
                            expires_at,
                            collection: *value.last().unwrap(),
                        });
                    }
                    Ok(true)
                },
            )
            .await?;

        Ok(results)
    }
}
