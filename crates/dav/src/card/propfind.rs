/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{RequestHeaders, schema::request::PropFind};
use http_proto::HttpResponse;

use crate::common::{DavQuery, uri::DavUriResource};

pub(crate) trait CardPropFindRequestHandler: Sync + Send {
    fn handle_card_propfind_request(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
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
}
