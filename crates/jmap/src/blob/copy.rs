use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::copy::{CopyBlobRequest, CopyBlobResponse},
    types::{acl::Acl, blob::BlobId},
};
use store::BlobKind;
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
            let has_access = match &blob_id.kind {
                BlobKind::Linked {
                    account_id,
                    collection,
                    document_id,
                } => {
                    acl_token.is_member(*account_id)
                        || (acl_token.has_access(*account_id, *collection)
                            && self
                                .has_access_to_document(
                                    acl_token,
                                    *account_id,
                                    *collection,
                                    *document_id,
                                    Acl::Read,
                                )
                                .await?)
                }
                BlobKind::LinkedMaildir {
                    account_id,
                    document_id,
                } => {
                    acl_token.is_member(*account_id)
                        || self
                            .shared_messages(acl_token, *account_id, Acl::ReadItems)
                            .await?
                            .contains(*document_id)
                }
                BlobKind::Temporary { account_id, .. } => acl_token.is_member(*account_id),
            };

            if has_access {
                let dest_blob_id = BlobId::temporary(account_id);
                match self
                    .store
                    .copy_blob(&blob_id.kind, &dest_blob_id.kind)
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
