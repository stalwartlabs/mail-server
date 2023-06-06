/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::sync::Arc;

use jmap_proto::{
    error::{method::MethodError, request::RequestError},
    types::{blob::BlobId, id::Id},
};
use store::BlobKind;

use crate::{auth::AccessToken, JMAP};

use super::UploadResponse;

impl JMAP {
    pub async fn blob_upload(
        &self,
        account_id: Id,
        content_type: &str,
        data: &[u8],
        access_token: Arc<AccessToken>,
    ) -> Result<UploadResponse, RequestError> {
        // Limit concurrent uploads
        let _in_flight = self.is_upload_allowed(&access_token)?;

        #[cfg(feature = "test_mode")]
        {
            // Used for concurrent upload tests
            if data == b"sleep" {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        let blob_id = BlobId::temporary(account_id.document_id());

        match self.store.put_blob(&blob_id.kind, data).await {
            Ok(_) => Ok(UploadResponse {
                account_id,
                blob_id,
                c_type: content_type.to_string(),
                size: data.len(),
            }),
            Err(err) => {
                tracing::error!(event = "error",
                    context = "blob_store",
                    account_id = account_id.document_id(),
                    blob_id = ?blob_id,
                    size = data.len(),
                    error = ?err,
                    "Failed to upload blob");
                Err(RequestError::internal_server_error())
            }
        }
    }

    pub async fn put_blob(&self, kind: &BlobKind, data: &[u8]) -> Result<(), MethodError> {
        self.store.put_blob(kind, data).await.map_err(|err| {
            tracing::error!(
                    event = "error",
                    context = "blob_put",
                    kind = ?kind,
                    error = ?err,
                    "Failed to store blob.");
            MethodError::ServerPartialFail
        })
    }

    pub async fn delete_blob(&self, kind: &BlobKind) -> Result<bool, MethodError> {
        self.store.delete_blob(kind).await.map_err(|err| {
            tracing::error!(
                    event = "error",
                    context = "delete_blob",
                    kind = ?kind,
                    error = ?err,
                    "Failed to delete blob.");
            MethodError::ServerPartialFail
        })
    }
}
