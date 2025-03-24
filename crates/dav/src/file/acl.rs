/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::file::{ArchivedFileNode, FileNode, hierarchy::FileHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection, property::Property};
use store::write::{AlignedBytes, Archive};
use trc::AddContext;

use crate::{DavError, common::uri::DavUriResource, file::DavFileResource};

pub(crate) trait FileAclRequestHandler: Sync + Send {
    fn handle_file_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: dav_proto::schema::request::Acl,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn validate_file_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        node: &ArchivedFileNode,
        acl_child: Acl,
        acl_parent: Acl,
    ) -> impl Future<Output = crate::Result<()>> + Send;
}

impl FileAclRequestHandler for Server {
    async fn handle_file_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: dav_proto::schema::request::Acl,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let files = self
            .fetch_file_hierarchy(account_id)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        // Fetch node
        let node_ = self
            .get_property::<Archive<AlignedBytes>>(
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
        self.validate_file_acl(
            access_token,
            account_id,
            node,
            Acl::Administer,
            Acl::Administer,
        )
        .await?;

        for ace in request.aces {}

        todo!()
    }

    async fn validate_file_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        node: &ArchivedFileNode,
        acl_child: Acl,
        acl_parent: Acl,
    ) -> crate::Result<()> {
        if access_token.is_member(account_id)
            || node.acls.effective_acl(access_token).contains(acl_child)
            || (u32::from(node.parent_id) > 0
                && self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::FileNode,
                        u32::from(node.parent_id) - 1,
                        acl_parent,
                    )
                    .await
                    .caused_by(trc::location!())?)
        {
            Ok(())
        } else {
            Err(DavError::Code(StatusCode::FORBIDDEN))
        }
    }
}
