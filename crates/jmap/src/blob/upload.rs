use std::sync::Arc;

use jmap_proto::{
    error::{method::MethodError, request::RequestError},
    types::{blob::BlobId, id::Id},
};
use store::BlobKind;

use crate::{auth::AclToken, JMAP};

use super::UploadResponse;

impl JMAP {
    pub async fn blob_upload(
        &self,
        account_id: Id,
        content_type: &str,
        data: &[u8],
        acl_token: Arc<AclToken>,
    ) -> Result<UploadResponse, RequestError> {
        // Limit concurrent uploads
        let _in_flight = self.is_upload_allowed(acl_token.primary_id())?;

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

    pub async fn put_blob(&self, kind: &BlobKind, data: &[u8]) -> Result<bool, MethodError> {
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
