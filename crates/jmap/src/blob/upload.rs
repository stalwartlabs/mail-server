/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use jmap_proto::{
    error::set::SetError,
    method::upload::{
        BlobUploadRequest, BlobUploadResponse, BlobUploadResponseObject, DataSourceObject,
    },
    request::reference::MaybeReference,
    types::{blob::BlobId, id::Id},
};
use store::{
    write::{now, BatchBuilder, BlobOp},
    BlobClass, Serialize,
};
use trc::AddContext;
use utils::BlobHash;

use crate::{auth::AccessToken, JMAP};

use super::UploadResponse;

#[cfg(feature = "test_mode")]
pub static DISABLE_UPLOAD_QUOTA: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

impl JMAP {
    pub async fn blob_upload_many(
        &self,
        request: BlobUploadRequest,
        access_token: &AccessToken,
    ) -> trc::Result<BlobUploadResponse> {
        let mut response = BlobUploadResponse {
            account_id: request.account_id,
            created: Default::default(),
            not_created: Default::default(),
        };
        let account_id = request.account_id.document_id();

        if request.create.len() > self.core.jmap.set_max_objects {
            return Err(trc::JmapCause::RequestTooLarge.into_err());
        }

        'outer: for (create_id, upload_object) in request.create {
            let mut data = Vec::new();

            for data_source in upload_object.data {
                let bytes = match data_source {
                    DataSourceObject::Id { id, length, offset } => {
                        let id = match id {
                            MaybeReference::Value(id) => id,
                            MaybeReference::Reference(reference) => {
                                if let Some(obj) = response.created.get(&reference) {
                                    obj.id.clone()
                                } else {
                                    response.not_created.append(
                                        create_id,
                                        SetError::not_found().with_description(format!(
                                            "Id reference {reference:?} not found."
                                        )),
                                    );
                                    continue 'outer;
                                }
                            }
                        };

                        if !self.has_access_blob(&id, access_token).await? {
                            response.not_created.append(
                                create_id,
                                SetError::forbidden().with_description(format!(
                                    "You do not have access to blobId {id}."
                                )),
                            );
                            continue 'outer;
                        }

                        let offset = offset.unwrap_or(0);
                        let length = length
                            .map(|length| length.saturating_add(offset))
                            .unwrap_or(usize::MAX);
                        let bytes = if let Some(section) = &id.section {
                            self.get_blob_section(&id.hash, section)
                                .await?
                                .map(|bytes| {
                                    if offset == 0 && length == usize::MAX {
                                        bytes
                                    } else {
                                        bytes
                                            .get(offset..std::cmp::min(length, bytes.len()))
                                            .unwrap_or_default()
                                            .to_vec()
                                    }
                                })
                        } else {
                            self.get_blob(&id.hash, offset..length).await?
                        };
                        if let Some(bytes) = bytes {
                            bytes
                        } else {
                            response.not_created.append(
                                create_id,
                                SetError::blob_not_found()
                                    .with_description(format!("BlobId {id} not found.")),
                            );
                            continue 'outer;
                        }
                    }
                    DataSourceObject::Value(bytes) => bytes,
                };

                if bytes.len() + data.len() < self.core.jmap.upload_max_size {
                    data.extend(bytes);
                } else {
                    response.not_created.append(
                        create_id,
                        SetError::too_large().with_description(format!(
                            "Upload size exceeds maximum of {} bytes.",
                            self.core.jmap.upload_max_size
                        )),
                    );
                    continue 'outer;
                }
            }

            if data.is_empty() {
                response.not_created.append(
                    create_id,
                    SetError::invalid_properties()
                        .with_description("Must specify at least one valid DataSourceObject."),
                );
                continue 'outer;
            }

            // Enforce quota
            let used = self
                .core
                .storage
                .data
                .blob_quota(account_id)
                .await
                .caused_by(trc::location!())?;

            if ((self.core.jmap.upload_tmp_quota_size > 0
                && used.bytes + data.len() > self.core.jmap.upload_tmp_quota_size)
                || (self.core.jmap.upload_tmp_quota_amount > 0
                    && used.count + 1 > self.core.jmap.upload_tmp_quota_amount))
                && !access_token.is_super_user()
            {
                response.not_created.append(
                    create_id,
                    SetError::over_quota().with_description(format!(
                        "You have exceeded the blob upload quota of {} files or {} bytes.",
                        self.core.jmap.upload_tmp_quota_amount,
                        self.core.jmap.upload_tmp_quota_size
                    )),
                );
                continue 'outer;
            }

            // Write blob
            response.created.insert(
                create_id,
                BlobUploadResponseObject {
                    id: self.put_blob(account_id, &data, true).await?,
                    type_: upload_object.type_,
                    size: data.len(),
                },
            );
        }

        Ok(response)
    }

    pub async fn blob_upload(
        &self,
        account_id: Id,
        content_type: &str,
        data: &[u8],
        access_token: Arc<AccessToken>,
    ) -> trc::Result<UploadResponse> {
        // Limit concurrent uploads
        let _in_flight = self
            .is_upload_allowed(&access_token)
            .caused_by(trc::location!())?;

        #[cfg(feature = "test_mode")]
        {
            // Used for concurrent upload tests
            if data == b"sleep" {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        // Enforce quota
        let used = self
            .core
            .storage
            .data
            .blob_quota(account_id.document_id())
            .await
            .caused_by(trc::location!())?;

        if ((self.core.jmap.upload_tmp_quota_size > 0
            && used.bytes + data.len() > self.core.jmap.upload_tmp_quota_size)
            || (self.core.jmap.upload_tmp_quota_amount > 0
                && used.count + 1 > self.core.jmap.upload_tmp_quota_amount))
            && !access_token.is_super_user()
        {
            let err = Err(trc::LimitCause::BlobQuota
                .into_err()
                .ctx(trc::Key::Size, self.core.jmap.upload_tmp_quota_size)
                .ctx(trc::Key::Total, self.core.jmap.upload_tmp_quota_amount));

            #[cfg(feature = "test_mode")]
            if !DISABLE_UPLOAD_QUOTA.load(std::sync::atomic::Ordering::Relaxed) {
                return err;
            }

            #[cfg(not(feature = "test_mode"))]
            return err;
        }

        Ok(UploadResponse {
            account_id,
            blob_id: self
                .put_blob(account_id.document_id(), data, true)
                .await
                .caused_by(trc::location!())?,
            c_type: content_type.to_string(),
            size: data.len(),
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    pub async fn put_blob(
        &self,
        account_id: u32,
        data: &[u8],
        set_quota: bool,
    ) -> trc::Result<BlobId> {
        // First reserve the hash
        let hash = BlobHash::from(data);
        let mut batch = BatchBuilder::new();
        let until = now() + self.core.jmap.upload_tmp_ttl;

        batch.with_account_id(account_id).set(
            BlobOp::Reserve {
                hash: hash.clone(),
                until,
            },
            (if set_quota { data.len() as u32 } else { 0u32 }).serialize(),
        );
        self.write_batch(batch).await?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.write_batch(batch).await?;
        }

        Ok(BlobId {
            hash,
            class: BlobClass::Reserved {
                account_id,
                expires: until,
            },
            section: None,
        })
    }
}
