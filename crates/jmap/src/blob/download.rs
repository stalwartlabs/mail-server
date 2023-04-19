use std::ops::Range;

use jmap_proto::{error::method::MethodError, types::blob::BlobId};
use mail_parser::{
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
    Encoding,
};
use store::BlobKind;

use crate::JMAP;

impl JMAP {
    pub async fn blob_download(
        &self,
        blob_id: &BlobId,
        account_id: u32,
    ) -> store::Result<Option<Vec<u8>>> {
        if !blob_id.has_access(account_id) {
            // TODO: validate ACL
            let acl = "true";
            return Ok(None);
        }

        if let Some(section) = &blob_id.section {
            Ok(self
                .store
                .get_blob(
                    &blob_id.kind,
                    (section.offset_start as u32)
                        ..(section.offset_start.saturating_add(section.size) as u32),
                )
                .await?
                .and_then(|bytes| match Encoding::from(section.encoding) {
                    Encoding::None => Some(bytes),
                    Encoding::Base64 => base64_decode(&bytes),
                    Encoding::QuotedPrintable => quoted_printable_decode(&bytes),
                }))
        } else {
            self.store.get_blob(&blob_id.kind, 0..u32::MAX).await
        }
    }

    pub async fn get_blob(
        &self,
        kind: &BlobKind,
        range: Range<u32>,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        match self.store.get_blob(kind, range).await {
            Ok(blob) => Ok(blob),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "blob_store",
                                blob_id = ?kind,
                                error = ?err,
                                "Failed to retrieve blob");
                Err(MethodError::ServerPartialFail)
            }
        }
    }
}
