use jmap_proto::{
    error::request::RequestError,
    types::{blob::BlobId, id::Id},
};

use crate::JMAP;

use super::UploadResponse;

impl JMAP {
    pub async fn blob_upload(
        &self,
        account_id: Id,
        content_type: &str,
        data: &[u8],
    ) -> Result<UploadResponse, RequestError> {
        let blob_id = BlobId::temporary(account_id.document_id());

        self.store
            .put_blob(&blob_id.kind, data)
            .await
            .map_err(|err| RequestError::internal_server_error())?;

        Ok(UploadResponse {
            account_id,
            blob_id,
            c_type: content_type.to_string(),
            size: data.len(),
        })
    }
}
