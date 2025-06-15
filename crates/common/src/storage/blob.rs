/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::blob::BlobSection;
use mail_parser::{
    Encoding,
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
};
use utils::BlobHash;

use crate::Server;

impl Server {
    pub async fn get_blob_section(
        &self,
        hash: &BlobHash,
        section: &BlobSection,
    ) -> trc::Result<Option<Vec<u8>>> {
        Ok(self
            .blob_store()
            .get_blob(
                hash.as_slice(),
                (section.offset_start)..(section.offset_start.saturating_add(section.size)),
            )
            .await?
            .and_then(|bytes| match Encoding::from(section.encoding) {
                Encoding::None => Some(bytes),
                Encoding::Base64 => base64_decode(&bytes),
                Encoding::QuotedPrintable => quoted_printable_decode(&bytes),
            }))
    }
}
