/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::PropFind};
use http_proto::HttpResponse;

pub(crate) trait FilePropFindRequestHandler: Sync + Send {
    fn handle_file_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FilePropFindRequestHandler for Server {
    async fn handle_file_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
