/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ETag, ExtractETag,
        acl::ResourceAcl,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
    fix_percent_encoding,
};
use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use dav_proto::{RequestHeaders, Return, schema::property::Rfc1123DateTime};
use groupware::{
    cache::GroupwareCache,
    file::{FileNode, FileProperties},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::{BatchBuilder, now};
use trc::AddContext;
use utils::BlobHash;

pub(crate) trait FileUpdateRequestHandler: Sync + Send {
    fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileUpdateRequestHandler for Server {
    async fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        bytes: Vec<u8>,
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let resource_name = fix_percent_encoding(
            resource
                .resource
                .ok_or(DavError::Code(StatusCode::CONFLICT))?,
        );

        if bytes.len() > self.core.groupware.max_file_size {
            return Err(DavError::Code(StatusCode::PAYLOAD_TOO_LARGE));
        }

        if let Some(document_id) = resources
            .by_path(resource_name.as_ref())
            .map(|r| r.document_id())
        {
            // Update
            let node_ = self
                .get_archive(account_id, Collection::FileNode, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let node = node_
                .to_unarchived::<FileNode>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !node
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains(Acl::Modify)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            match self
                .validate_headers(
                    access_token,
                    headers,
                    vec![ResourceState {
                        account_id,
                        collection: resource.collection,
                        document_id: Some(document_id),
                        etag: node.etag().into(),
                        path: resource_name.as_ref(),
                        ..Default::default()
                    }],
                    Default::default(),
                    DavMethod::PUT,
                )
                .await
            {
                Ok(_) => {}
                Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                    if headers.ret == Return::Representation =>
                {
                    let file = node.inner.file.as_ref().unwrap();
                    let contents = self
                        .blob_store()
                        .get_blob(file.blob_hash.0.as_slice(), 0..usize::MAX)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or(DavError::Code(StatusCode::PRECONDITION_FAILED))?;

                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type(
                            file.media_type
                                .as_ref()
                                .map(|v| v.as_str())
                                .unwrap_or("application/octet-stream"),
                        )
                        .with_etag(node.etag())
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(node.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(contents));
                }
                Err(e) => return Err(e),
            }

            // Verify that the node is a file
            if let Some(file) = node.inner.file.as_ref() {
                if BlobHash::generate(&bytes).as_slice() == file.blob_hash.0.as_slice() {
                    return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
                }
            } else {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate quota
            let extra_bytes = (bytes.len() as u64)
                .saturating_sub(u32::from(node.inner.file.as_ref().unwrap().size) as u64);
            if extra_bytes > 0 {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    extra_bytes,
                )
                .await?;
            }

            // Write blob
            let blob_hash = self
                .put_blob(account_id, &bytes, false)
                .await
                .caused_by(trc::location!())?
                .hash;

            // Build node
            let mut new_node = node.deserialize::<FileNode>().caused_by(trc::location!())?;
            let new_file = new_node.file.as_mut().unwrap();
            new_file.blob_hash = blob_hash;
            new_file.media_type = headers
                .content_type
                .filter(|ct| !ct.is_empty() && *ct != "application/octet-stream")
                .map(|v| v.to_string());
            new_file.size = bytes.len() as u32;
            new_node.modified = now() as i64;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(node)
                        .with_changes(new_node)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else {
            // Insert
            let orig_resource_name = resource_name;
            let (parent, resource_name) = resources
                .map_parent(orig_resource_name.as_ref())
                .ok_or(DavError::Code(StatusCode::CONFLICT))?;

            // Validate ACL
            let parent_id = resources.validate_and_map_parent_acl(
                access_token,
                access_token.is_member(account_id),
                parent.map(|r| r.document_id()),
                Acl::AddItems,
            )?;

            // Verify that parent is a collection
            if parent.as_ref().is_some_and(|r| !r.is_container()) {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: orig_resource_name.as_ref(),
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    bytes.len() as u64,
                )
                .await?;
            }

            // Write blob
            let blob_hash = self
                .put_blob(account_id, &bytes, false)
                .await
                .caused_by(trc::location!())?
                .hash;

            // Build node
            let now = now();
            let node = FileNode {
                parent_id,
                name: resource_name.to_string(),
                display_name: None,
                file: Some(FileProperties {
                    blob_hash,
                    size: bytes.len() as u32,
                    media_type: headers.content_type.map(|v| v.to_string()),
                    executable: false,
                }),
                created: now as i64,
                modified: now as i64,
                dead_properties: Default::default(),
                acls: Default::default(),
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::FileNode, 1)
                .await
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .create_document(document_id)
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(node)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        }
    }
}
