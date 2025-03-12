/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::RequestHeaders;
use groupware::file::{FileNode, FileProperties, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl, collection::Collection, property::Property, type_state::DataType,
};
use store::write::{
    AlignedBytes, Archive, BatchBuilder,
    log::{Changes, LogInsert},
    now,
};
use trc::AddContext;
use utils::BlobHash;

use crate::{
    DavError, DavMethod,
    common::{
        ETag, ExtractETag,
        acl::DavAclHandler,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

use super::acl::FileAclRequestHandler;

pub(crate) trait FileUpdateRequestHandler: Sync + Send {
    fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileUpdateRequestHandler for Server {
    async fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        bytes: Vec<u8>,
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self.validate_uri(access_token, headers.uri).await?;
        let account_id = resource.account_id()?;
        let files = self
            .fetch_file_hierarchy(account_id)
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        if let Some(document_id) = files.files.by_name(resource_name).map(|r| r.document_id) {
            // Update
            let node_archive_ = self
                .get_property::<Archive<AlignedBytes>>(
                    account_id,
                    Collection::FileNode,
                    document_id,
                    Property::Value,
                )
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let node_archive = node_archive_
                .to_unarchived::<FileNode>()
                .caused_by(trc::location!())?;
            let node = node_archive.inner;

            // Validate ACL
            self.validate_file_acl(
                access_token,
                account_id,
                node,
                Acl::Modify,
                Acl::ModifyItems,
            )
            .await?;

            // Validate headers
            self.validate_headers(
                access_token,
                &headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(document_id),
                    etag: node_archive_.etag().into(),
                    lock_token: None,
                    path: resource_name,
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Verify that the node is a file
            if let Some(file) = node.file.as_ref() {
                if BlobHash::generate(&bytes).as_slice() == file.blob_hash.0.as_slice() {
                    return Ok(HttpResponse::new(StatusCode::OK));
                }
            } else {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate quota
            let extra_bytes = (bytes.len() as u64)
                .saturating_sub(u32::from(node.file.as_ref().unwrap().size) as u64);
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
            let change_id = self.generate_snowflake_id().caused_by(trc::location!())?;
            let node = node_archive.to_deserialized().caused_by(trc::location!())?;
            let mut new_node = node.inner.clone();
            let new_file = new_node.file.as_mut().unwrap();
            new_file.blob_hash = blob_hash;
            new_file.media_type = headers.content_type.map(|v| v.to_string());
            new_file.size = bytes.len() as u32;
            new_node.modified = now() as i64;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            batch
                .with_change_id(change_id)
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .update_document(document_id)
                .log(Changes::update([document_id]))
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(node)
                        .with_changes(new_node)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;

            // Broadcast state change
            self.broadcast_single_state_change(account_id, change_id, DataType::FileNode)
                .await;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else {
            // Insert
            let orig_resource_name = resource_name;
            let (parent_id, resource_name) = files
                .map_parent(resource_name)
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            // Validate ACL
            let parent_id = self
                .validate_and_map_parent_acl(
                    access_token,
                    account_id,
                    Collection::FileNode,
                    parent_id,
                    Acl::AddItems,
                )
                .await?;

            // Verify that parent is a collection
            if parent_id > 0
                && self
                    .get_property::<Archive<AlignedBytes>>(
                        account_id,
                        Collection::FileNode,
                        parent_id - 1,
                        Property::Value,
                    )
                    .await
                    .caused_by(trc::location!())?
                    .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
                    .unarchive::<FileNode>()
                    .caused_by(trc::location!())?
                    .file
                    .is_some()
            {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                &headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    etag: None,
                    lock_token: None,
                    path: orig_resource_name,
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
            let change_id = self.generate_snowflake_id().caused_by(trc::location!())?;
            let now = now();
            let node = FileNode {
                parent_id,
                name: resource_name.into_owned(),
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
            batch
                .with_change_id(change_id)
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .create_document()
                .log(LogInsert())
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(node)
                        .with_tenant_id(access_token),
                )
                .caused_by(trc::location!())?;
            let etag = batch.etag();
            self.store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;

            // Broadcast state change
            self.broadcast_single_state_change(account_id, change_id, DataType::FileNode)
                .await;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        }
    }
}
