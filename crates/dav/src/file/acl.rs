/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::Acl};
use http_proto::HttpResponse;

pub(crate) trait FileAclRequestHandler: Sync + Send {
    fn handle_file_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Acl,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileAclRequestHandler for Server {
    async fn handle_file_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Acl,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
