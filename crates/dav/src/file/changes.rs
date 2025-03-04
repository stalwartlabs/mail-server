/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::SyncCollection};
use http_proto::HttpResponse;

pub(crate) trait FileChangesRequestHandler: Sync + Send {
    fn handle_file_changes_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: SyncCollection,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileChangesRequestHandler for Server {
    async fn handle_file_changes_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: SyncCollection,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
