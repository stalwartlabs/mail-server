/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{request::PropFind, response::MultiStatus},
};
use http_proto::HttpResponse;
use store::roaring::RoaringBitmap;

pub(crate) enum PrincipalResource<'x> {
    Id(u32),
    Uri(&'x str),
    Ids(RoaringBitmap),
}

pub(crate) trait PrincipalPropFind: Sync + Send {
    fn prepare_principal_propfind_response(
        &self,
        access_token: &AccessToken,
        resource: PrincipalResource<'_>,
        request: &PropFind,
        response: &mut MultiStatus,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PrincipalPropFind for Server {
    async fn prepare_principal_propfind_response(
        &self,
        access_token: &AccessToken,
        resource: PrincipalResource<'_>,
        request: &PropFind,
        response: &mut MultiStatus,
    ) -> crate::Result<HttpResponse> {
        todo!()
    }
}
