/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::{file::FileNode, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
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
            .fetch_dav_resources(account_id, Collection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        // Fetch node
        let node_ = self
            .get_archive(account_id, Collection::FileNode, resource.resource)
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
                .contains(Acl::Administer)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

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
            let mut batch = BatchBuilder::new();
            update_file_node(
                access_token,
                node,
                new_node,
                account_id,
                resource.resource,
                false,
                &mut batch,
            )
            .caused_by(trc::location!())?;
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::OK))
    }
}
