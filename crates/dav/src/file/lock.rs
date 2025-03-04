/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::LockInfo};
use http_proto::HttpResponse;

pub(crate) trait FileLockRequestHandler: Sync + Send {
    fn handle_file_lock_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<LockInfo>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileLockRequestHandler for Server {
    async fn handle_file_lock_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<LockInfo>,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
