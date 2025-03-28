/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::Acl};
use http_proto::HttpResponse;

use crate::common::uri::DavUriResource;

pub(crate) trait CardAclRequestHandler: Sync + Send {
    fn handle_card_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Acl,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardAclRequestHandler for Server {
    async fn handle_card_acl_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: Acl,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;

        todo!()
    }
}
