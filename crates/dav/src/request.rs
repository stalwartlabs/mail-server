/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Server, auth::AccessToken};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData};

use crate::{DavMethod, DavResource};

pub trait DavRequestHandler: Sync + Send {
    fn handle_dav_request(
        &self,
        request: HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
        resource: DavResource,
        method: DavMethod,
        body: Vec<u8>,
    ) -> impl Future<Output = HttpResponse> + Send;
}

impl DavRequestHandler for Server {
    async fn handle_dav_request(
        &self,
        request: HttpRequest,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
        resource: DavResource,
        method: DavMethod,
        body: Vec<u8>,
    ) -> HttpResponse {
        todo!()
    }
}
