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
                let dest_blob_id = BlobId::temporary(account_id);
                match self
                    .store
                    .copy_blob(
                        &blob_id.kind,
                        &dest_blob_id.kind,
                        blob_id
                            .section
                            .as_ref()
                            .map(|s| (s.offset_start as u32)..((s.offset_start + s.size) as u32)),
                    )
                    .await
                {
                    Ok(success) => {
                        if success {
                            response.copied.append(blob_id, dest_blob_id);
                        } else {
                            response.not_copied.append(
                                blob_id,
                                SetError::new(SetErrorType::BlobNotFound)
                                    .with_description("blobId does not exist."),
                            );
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            context = "copy_blob",
                            event = "error",
                            reason = %err,
                            "Failed to copy blob");
                        return Err(MethodError::ServerPartialFail);
                    }
                }
            } else {
                response.not_copied.append(
                    blob_id,
                    SetError::forbidden()
                        .with_description("You do not have access to this blobId."),
                );
            }
        }

        Ok(response)
    }
}
