/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::AddressbookQuery};
use http_proto::HttpResponse;

pub(crate) trait CardQueryRequestHandler: Sync + Send {
    fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardQueryRequestHandler for Server {
    async fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
