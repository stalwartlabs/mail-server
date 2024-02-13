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

use std::ops::Range;

use jmap_proto::{
    error::method::MethodError,
    types::{
        acl::Acl,
        blob::{BlobId, BlobSection},
        collection::Collection,
    },
};
use mail_parser::{
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
    Encoding,
};
use store::BlobClass;
use utils::BlobHash;

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    #[allow(clippy::blocks_in_conditions)]
    pub async fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        if !self
            .store
            .blob_has_access(&blob_id.hash, &blob_id.class)
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                            context = "blob_download",
                            error = ?err,
                            "Failed to validate blob access");
                MethodError::ServerPartialFail
            })?
        {
            return Ok(None);
        }

        if !access_token.is_member(blob_id.class.account_id()) {
            match &blob_id.class {
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } => {
                    if Collection::from(*collection) == Collection::Email {
                        match self
                            .shared_messages(access_token, *account_id, Acl::ReadItems)
                            .await
                        {
                            Ok(shared_messages) if shared_messages.contains(*document_id) => (),
                            _ => return Ok(None),
                        }
                    } else {
                        match self
                            .has_access_to_document(
                                access_token,
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
                }
                BlobClass::Reserved { .. } => {
                    return Ok(None);
                }
            }
        }

        if let Some(section) = &blob_id.section {
            self.get_blob_section(&blob_id.hash, section).await
        } else {
            self.get_blob(&blob_id.hash, 0..u32::MAX).await
        }
    }

    pub async fn get_blob_section(
        &self,
        hash: &BlobHash,
        section: &BlobSection,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        Ok(self
            .get_blob(
                hash,
                (section.offset_start as u32)
                    ..(section.offset_start.saturating_add(section.size) as u32),
            )
            .await?
            .and_then(|bytes| match Encoding::from(section.encoding) {
                Encoding::None => Some(bytes),
                Encoding::Base64 => base64_decode(&bytes),
                Encoding::QuotedPrintable => quoted_printable_decode(&bytes),
            }))
    }

    pub async fn get_blob(
        &self,
        hash: &BlobHash,
        range: Range<u32>,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        match self.blob_store.get_blob(hash.as_ref(), range).await {
            Ok(blob) => Ok(blob),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "blob_store",
                                blob_id = ?hash,
                                error = ?err,
                                "Failed to retrieve blob");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> Result<bool, MethodError> {
        Ok(self
            .store
            .blob_has_access(&blob_id.hash, &blob_id.class)
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                                context = "has_access_blob",
                                error = ?err,
                                "Failed to validate blob access");
                MethodError::ServerPartialFail
            })?
            && match &blob_id.class {
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } => {
                    if Collection::from(*collection) == Collection::Email {
                        access_token.is_member(*account_id)
                            || self
                                .shared_messages(access_token, *account_id, Acl::ReadItems)
                                .await?
                                .contains(*document_id)
                    } else {
                        access_token.is_member(*account_id)
                            || (access_token.has_access(*account_id, *collection)
                                && self
                                    .has_access_to_document(
                                        access_token,
                                        *account_id,
                                        *collection,
                                        *document_id,
                                        Acl::Read,
                                    )
                                    .await?)
                    }
                }
                BlobClass::Reserved { account_id, .. } => access_token.is_member(*account_id),
            })
    }
}
