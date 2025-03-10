/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::file::{FileNode, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection, property::Property};
use store::write::Archive;
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::{DavFileResource, acl::FileAclRequestHandler},
};

pub(crate) trait FileGetRequestHandler: Sync + Send {
    fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileGetRequestHandler for Server {
    async fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self.validate_uri(access_token, headers.uri).await?;
        let account_id = resource_.account_id()?;
        let files = self
            .fetch_file_hierarchy(account_id)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        // Fetch node
        let node_ = self
            .get_property::<Archive>(
                account_id,
                Collection::FileNode,
                resource.resource,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_.unarchive::<FileNode>().caused_by(trc::location!())?;

        // Validate ACL
        self.validate_file_acl(access_token, account_id, node, Acl::Read, Acl::ReadItems)
            .await?;

        let (hash, size, content_type) = if let Some(file) = node.file.as_ref() {
            (
                file.blob_hash.0.as_ref(),
                u32::from(file.size) as usize,
                file.media_type.as_ref().map(|s| s.as_str()),
            )
        } else {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        };

        // Validate headers
        let etag = node_.etag();
        self.validate_headers(
            access_token,
            &headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: resource.resource.into(),
                etag: etag.clone().into(),
                lock_token: None,
                path: resource_.resource.unwrap(),
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_etag(etag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(node.modified)).to_string());

        if !is_head {
            Ok(response.with_binary_body(
                self.blob_store()
                    .get_blob(hash, 0..usize::MAX)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
            ))
        } else {
            Ok(response.with_content_length(size))
        }
    }
}
