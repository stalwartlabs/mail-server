/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::PropertyUpdate};
use http_proto::HttpResponse;

pub(crate) trait FilePropPatchRequestHandler: Sync + Send {
    fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FilePropPatchRequestHandler for Server {
    async fn handle_file_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
