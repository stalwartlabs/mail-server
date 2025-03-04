/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::RequestHeaders;
use http_proto::HttpResponse;

pub(crate) trait FileDeleteRequestHandler: Sync + Send {
    fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileDeleteRequestHandler for Server {
    async fn handle_file_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
