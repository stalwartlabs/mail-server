/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::copy::{CopyBlobRequest, CopyBlobResponse},
    types::blob::BlobId,
};

use store::{
    write::{now, BatchBuilder, BlobOp},
    BlobClass, Serialize,
};
use utils::map::vec_map::VecMap;

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn blob_copy(
        &self,
        request: CopyBlobRequest,
        access_token: &AccessToken,
    ) -> Result<CopyBlobResponse, MethodError> {
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
                let until = now() + self.config.upload_tmp_ttl;
                batch.with_account_id(account_id).set(
                    BlobOp::Reserve {
                        until,
                        hash: blob_id.hash.clone(),
                    },
                    0u32.serialize(),
                );
                self.write_batch(batch).await?;
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
