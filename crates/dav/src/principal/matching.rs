/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        property::{DavProperty, WebDavProperty},
        request::{PrincipalMatch, PropFind},
        response::MultiStatus,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::roaring::RoaringBitmap;

use crate::{
    DavError,
    common::{DavQuery, uri::DavUriResource},
    file::propfind::HandleFilePropFindRequest,
};

use super::propfind::PrincipalPropFind;

pub(crate) trait PrincipalMatching: Sync + Send {
    fn handle_principal_match(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PrincipalMatch,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PrincipalMatching for Server {
    async fn handle_principal_match(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        mut request: PrincipalMatch,
    ) -> crate::Result<HttpResponse> {
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await
            .and_then(|uri| uri.into_owned_uri())?;

        let todo = "implement cal, card";

        match resource.collection {
            Collection::Calendar => todo!(),
            Collection::AddressBook => todo!(),
            Collection::FileNode => {
                self.handle_file_propfind_request(
                    access_token,
                    DavQuery {
                        resource,
                        base_uri: headers.uri,
                        propfind: PropFind::Prop(request.properties),
                        from_change_id: None,
                        depth: usize::MAX,
                        limit: None,
                        ret: headers.ret,
                        depth_no_root: headers.depth_no_root,
                    },
                )
                .await
            }
            Collection::Principal => {
                let mut response = MultiStatus::new(Vec::with_capacity(16));
                if request.properties.is_empty() {
                    request
                        .properties
                        .push(DavProperty::WebDav(WebDavProperty::DisplayName));
                }
                let request = PropFind::Prop(request.properties);
                self.prepare_principal_propfind_response(
                    access_token,
                    Collection::Principal,
                    RoaringBitmap::from_iter(access_token.all_ids()).into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
                Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
            }
            _ => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
        }
    }
}
