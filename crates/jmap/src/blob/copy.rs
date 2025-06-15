/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::copy::{CopyBlobRequest, CopyBlobResponse},
    types::blob::BlobId,
};
use trc::AddContext;

use std::future::Future;
use store::{
    BlobClass, SerializeInfallible,
    write::{BatchBuilder, BlobOp, now},
};
use utils::map::vec_map::VecMap;

use super::download::BlobDownload;

pub trait BlobCopy: Sync + Send {
    fn blob_copy(
        &self,
        request: CopyBlobRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<CopyBlobResponse>> + Send;
}

impl BlobCopy for Server {
    async fn blob_copy(
        &self,
        request: CopyBlobRequest,
        access_token: &AccessToken,
    ) -> trc::Result<CopyBlobResponse> {
        let mut response = CopyBlobResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            copied: VecMap::with_capacity(request.blob_ids.len()),
            not_copied: VecMap::new(),
        };
        let account_id = request.account_id.document_id();

        for blob_id in request.blob_ids {
            if self.has_access_blob(&blob_id, access_token).await? {
                let mut batch = BatchBuilder::new();
                let until = now() + self.core.jmap.upload_tmp_ttl;
                batch.with_account_id(account_id).set(
                    BlobOp::Reserve {
                        until,
                        hash: blob_id.hash.clone(),
                    },
                    0u32.serialize(),
                );
                self.store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                let dest_blob_id = BlobId {
                    hash: blob_id.hash.clone(),
                    class: BlobClass::Reserved {
                        account_id,
                        expires: until,
                    },
                    section: blob_id.section.clone(),
                };

                response.copied.append(blob_id, dest_blob_id);
            } else {
                response.not_copied.append(
                    blob_id,
                    SetError::new(SetErrorType::BlobNotFound).with_description(
                        "blobId does not exist or not enough permissions to access it.",
                    ),
                );
            }
        }

        Ok(response)
    }
}
