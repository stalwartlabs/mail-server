/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::RequestHeaders;
use groupware::file::ArchivedFileNode;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use trc::AddContext;

use crate::DavError;

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
