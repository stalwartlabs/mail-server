/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::RequestHeaders;
use http_proto::HttpResponse;

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
        todo!()
    }
}
