/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::MultiGet};
use http_proto::HttpResponse;

use crate::common::uri::DavUriResource;

pub(crate) trait CardGetRequestHandler: Sync + Send {
    fn handle_card_get_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_card_multiget_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: MultiGet,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardGetRequestHandler for Server {
    async fn handle_card_get_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;

        todo!()
    }

    async fn handle_card_multiget_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: MultiGet,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;

        todo!()
    }
}
