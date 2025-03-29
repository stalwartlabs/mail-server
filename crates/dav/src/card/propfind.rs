/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::MultiGet};
use http_proto::HttpResponse;

use crate::common::{DavQuery, uri::DavUriResource};

pub(crate) trait CardPropFindRequestHandler: Sync + Send {
    fn handle_card_propfind_request(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_card_multiget_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: MultiGet,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardPropFindRequestHandler for Server {
    async fn handle_card_propfind_request(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI

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
