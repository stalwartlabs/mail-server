/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::SyncCollection};
use http_proto::HttpResponse;

use super::UpdateType;

pub(crate) trait FileUpdateRequestHandler: Sync + Send {
    fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: UpdateType,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileUpdateRequestHandler for Server {
    async fn handle_file_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: UpdateType,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
