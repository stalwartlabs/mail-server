/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::MkCol};
use http_proto::HttpResponse;
use hyper::StatusCode;

use crate::{DavError, common::uri::DavUriResource};

pub(crate) trait CardMkColRequestHandler: Sync + Send {
    fn handle_card_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardMkColRequestHandler for Server {
    async fn handle_card_mkcol_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Option<MkCol>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        if resource.resource.is_none_or(|r| r.contains('/'))
            || !access_token.is_member(resource.account_id)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        todo!()
    }
}
