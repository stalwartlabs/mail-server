use mail_parser::{
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
    Encoding,
};
use protocol::types::blob::BlobId;

use crate::JMAP;

impl JMAP {
    pub async fn blob_retrieve(
        &self,
        blob_id: &BlobId,
        account_id: u32,
    ) -> store::Result<Option<Vec<u8>>> {
        if !self
            .store
            .has_blob_access(&blob_id.hash, vec![account_id])
            .await?
        {
            // TODO: validate ACL
            let acl = "true";
            return Ok(None);
        }

        if let Some(section) = &blob_id.section {
            Ok(self
                .store
                .get_blob(
                    &blob_id.hash,
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
            self.store.get_blob(&blob_id.hash, 0..u32::MAX).await
        }
    }
}
