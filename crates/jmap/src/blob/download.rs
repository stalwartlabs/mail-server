/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
            .core
            .storage
            .data
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
            self.get_blob(&blob_id.hash, 0..usize::MAX).await
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
                (section.offset_start)..(section.offset_start.saturating_add(section.size)),
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
        range: Range<usize>,
    ) -> Result<Option<Vec<u8>>, MethodError> {
        match self.core.storage.blob.get_blob(hash.as_ref(), range).await {
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
            .core
            .storage
            .data
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
