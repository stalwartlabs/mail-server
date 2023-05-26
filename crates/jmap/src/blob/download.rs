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

use std::ops::Range;

use jmap_proto::{
    error::method::MethodError,
    types::{acl::Acl, blob::BlobId},
};
use mail_parser::{
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
    Encoding,
};
use store::BlobKind;

use crate::{auth::AclToken, JMAP};

impl JMAP {
    pub async fn blob_download(
        &self,
        blob_id: &BlobId,
        acl_token: &AclToken,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        if !acl_token.is_member(blob_id.account_id()) {
            match &blob_id.kind {
                BlobKind::Linked {
                    account_id,
                    collection,
                    document_id,
                } => {
                    match self
                        .has_access_to_document(
                            acl_token,
                            *account_id,
                            *collection,
                            *document_id,
                            Acl::Read,
                        )
                        .await
                    {
                        Ok(has_access) if has_access => (),
                        _ => return Ok(None),
                    }
                }
                BlobKind::LinkedMaildir {
                    account_id,
                    document_id,
                } => {
                    match self
                        .shared_messages(acl_token, *account_id, Acl::ReadItems)
                        .await
                    {
                        Ok(shared_messages) if shared_messages.contains(*document_id) => (),
                        _ => return Ok(None),
                    }
                }
                BlobKind::Temporary { .. } => return Ok(None),
            }
        }

        if let Some(section) = &blob_id.section {
            Ok(self
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
            self.get_blob(&blob_id.kind, 0..u32::MAX).await
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

    pub async fn has_access_blob(
        &self,
        blob_id: &BlobId,
        acl_token: &AclToken,
    ) -> Result<bool, MethodError> {
        Ok(match &blob_id.kind {
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
        })
    }
}
