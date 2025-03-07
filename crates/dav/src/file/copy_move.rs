/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Files, Server, auth::AccessToken};
use dav_proto::{Depth, RequestHeaders};
use groupware::file::hierarchy::FileHierarchy;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{
    DavError,
    common::{
        acl::DavAclHandler,
        uri::{DavUriResource, UriResource},
    },
    file::{DavFileResource, FileItemId},
};

pub(crate) trait FileCopyMoveRequestHandler: Sync + Send {
    fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileCopyMoveRequestHandler for Server {
    async fn handle_file_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource = self.validate_uri(access_token, headers.uri).await?;
        let from_account_id = from_resource.account_id()?;
        let from_files = self
            .fetch_file_hierarchy(from_account_id)
            .await
            .caused_by(trc::location!())?;
        let from_resource = from_files.map_resource::<FileItemId>(from_resource)?;

        // Validate source ACLs
        let mut child_acl = Bitmap::new();
        let mut parent_acl = Bitmap::new();
        match (from_resource.resource.is_container, is_move) {
            (true, true) => {
                child_acl.insert(Acl::Delete);
                child_acl.insert(Acl::RemoveItems);
                parent_acl.insert(Acl::RemoveItems);
            }
            (true, false) => {
                child_acl.insert(Acl::Read);
                child_acl.insert(Acl::ReadItems);
                parent_acl.insert(Acl::ReadItems);
            }
            (false, true) => {
                child_acl.insert(Acl::Delete);
                parent_acl.insert(Acl::RemoveItems);
            }
            (false, false) => {
                child_acl.insert(Acl::Read);
                parent_acl.insert(Acl::ReadItems);
            }
        }
        self.validate_child_or_parent_acl(
            access_token,
            from_account_id,
            Collection::FileNode,
            from_resource.resource.document_id,
            from_resource.resource.parent_id,
            child_acl,
            parent_acl,
        )
        .await?;

        // Validate destination
        let to_resource = self
            .validate_uri(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
            )
            .await?;
        let to_account_id = to_resource
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_files = if to_account_id == from_account_id {
            from_files.clone()
        } else {
            self.fetch_file_hierarchy(to_account_id)
                .await
                .caused_by(trc::location!())?
        };
        let to_resource = to_files.map_destination::<FileItemId>(to_resource)?;
        if from_resource.collection != to_resource.collection
            || (from_resource.account_id == to_resource.account_id
                && to_resource
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.document_id == from_resource.resource.document_id))
        {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }

        // Validate destination ACLs
        if let Some(to_resource) = &to_resource.resource {
            let mut child_acl = Bitmap::new();

            if to_resource.is_container {
                child_acl.insert(Acl::ModifyItems);
            } else {
                child_acl.insert(Acl::Modify);
            }

            self.validate_child_or_parent_acl(
                access_token,
                to_account_id,
                Collection::FileNode,
                to_resource.document_id,
                to_resource.parent_id,
                child_acl,
                Acl::ModifyItems,
            )
            .await?;
        } else if !access_token.is_member(to_account_id) {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        match (
            from_resource.resource.is_container,
            to_resource.resource.as_ref().is_none_or(|r| r.is_container),
            is_move,
        ) {
            (true, true, true) => {
                move_container(
                    self,
                    from_files,
                    to_files,
                    from_resource,
                    to_resource,
                    headers.depth,
                )
                .await
            }
            (true, true, false) => {
                copy_container(
                    self,
                    from_files,
                    to_files,
                    from_resource,
                    to_resource,
                    headers.depth,
                )
                .await
            }
            (false, false, true) => replace_item(from_resource, to_resource.unwrap()).await,
            (false, false, false) => overwrite_item(from_resource, to_resource.unwrap()).await,
            (false, true, true) => move_item(from_resource, to_resource).await,
            (false, true, false) => copy_item(from_resource, to_resource).await,
            _ => Err(DavError::Code(StatusCode::BAD_GATEWAY)),
        }
    }
}

async fn move_container(
    server: &Server,
    from_files: Arc<Files>,
    to_files: Arc<Files>,
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<Option<FileItemId>>,
    depth: Depth,
) -> crate::Result<HttpResponse> {
    // check ancestors
    todo!()
}

async fn copy_container(
    server: &Server,
    from_files: Arc<Files>,
    to_files: Arc<Files>,
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<Option<FileItemId>>,
    depth: Depth,
) -> crate::Result<HttpResponse> {
    // check ancestors
    todo!()
}

async fn replace_item(
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<FileItemId>,
) -> crate::Result<HttpResponse> {
    todo!()
}

async fn overwrite_item(
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<FileItemId>,
) -> crate::Result<HttpResponse> {
    todo!()
}

async fn move_item(
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<Option<FileItemId>>,
) -> crate::Result<HttpResponse> {
    todo!()
}

async fn copy_item(
    from_resource: UriResource<FileItemId>,
    to_resource: UriResource<Option<FileItemId>>,
) -> crate::Result<HttpResponse> {
    todo!()
}
