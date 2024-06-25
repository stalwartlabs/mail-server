/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{blob::BlobId, id::Id};

pub mod copy;
pub mod download;
pub mod get;
pub mod upload;

#[derive(Debug, serde::Serialize)]
pub struct UploadResponse {
    #[serde(rename(serialize = "accountId"))]
    account_id: Id,
    #[serde(rename(serialize = "blobId"))]
    blob_id: BlobId,
    #[serde(rename(serialize = "type"))]
    c_type: String,
    size: usize,
}

pub struct DownloadResponse {
    pub filename: String,
    pub content_type: String,
    pub blob: Vec<u8>,
}
