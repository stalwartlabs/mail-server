use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::copy::{CopyBlobRequest, CopyBlobResponse},
    types::blob::BlobId,
};

use utils::map::vec_map::VecMap;

use crate::{auth::AclToken, JMAP};

impl JMAP {
    pub async fn blob_copy(
        &self,
        request: CopyBlobRequest,
        acl_token: &AclToken,
    ) -> Result<CopyBlobResponse, MethodError> {
        let mut response = CopyBlobResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            copied: VecMap::with_capacity(request.blob_ids.len()),
            not_copied: VecMap::new(),
        };
        let account_id = request.account_id.document_id();

        for blob_id in request.blob_ids {
            if self.has_access_blob(&blob_id, acl_token).await? {
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
