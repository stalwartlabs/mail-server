/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::MkCol};
use http_proto::HttpResponse;

pub(crate) trait FileMkColRequestHandler: Sync + Send {
    fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileMkColRequestHandler for Server {
    async fn handle_file_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
