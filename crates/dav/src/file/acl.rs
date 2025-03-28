/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::{
    file::{ArchivedFileNode, FileNode},
    hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection, property::Property};
use store::write::{AlignedBytes, Archive};
use trc::AddContext;

use crate::{
    DavError,
    common::{acl::DavAclHandler, uri::DavUriResource},
    file::{DavFileResource, update_file_node},
};

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
            .fetch_dav_hierarchy(account_id, Collection::FileNode)
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
        let node = node_
            .to_unarchived::<FileNode>()
            .caused_by(trc::location!())?;

        // Validate ACL
        self.validate_file_acl(
            access_token,
            account_id,
            node.inner,
            Acl::Administer,
            Acl::Administer,
        )
        .await?;

        let grants = self
            .validate_and_map_aces(access_token, request, Collection::FileNode)
            .await?;

        if grants.len() != node.inner.acls.len()
            || node
                .inner
                .acls
                .iter()
                .zip(grants.iter())
                .any(|(a, b)| a != b)
        {
            let mut new_node = node.deserialize().caused_by(trc::location!())?;
            new_node.acls = grants;
            update_file_node(
                self,
                access_token,
                node,
                new_node,
                account_id,
                resource.resource,
                false,
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::OK))
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
