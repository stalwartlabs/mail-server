/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
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
    common::{
        DavQuery, DavQueryResource,
        propfind::PropFindRequestHandler,
        uri::{DavUriResource, UriResource},
    },
};

use super::propfind::PrincipalPropFind;

pub(crate) trait PrincipalMatching: Sync + Send {
    fn handle_principal_match(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PrincipalMatch,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PrincipalMatching for Server {
    async fn handle_principal_match(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: PrincipalMatch,
    ) -> crate::Result<HttpResponse> {
        let resource = self.validate_uri(access_token, headers.uri).await?;

        match resource.collection {
            Collection::AddressBook | Collection::Calendar | Collection::FileNode => {
                if request.properties.is_empty() {
                    request
                        .properties
                        .push(DavProperty::WebDav(WebDavProperty::Owner));
                }
                if let Some(account_id) = resource.account_id {
                    return self
                        .handle_dav_query(
                            access_token,
                            DavQuery {
                                resource: DavQueryResource::Uri(UriResource {
                                    collection: resource.collection,
                                    account_id,
                                    resource: resource.resource,
                                }),
                                propfind: PropFind::Prop(request.properties),
                                depth: usize::MAX,
                                ret: headers.ret,
                                depth_no_root: headers.depth_no_root,
                                uri: headers.uri,
                                sync_type: Default::default(),
                                limit: Default::default(),
                                max_vcard_version: Default::default(),
                                expand: Default::default(),
                            },
                        )
                        .await;
                }
            }
            Collection::Principal => {}
            _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
        }

        let mut response = MultiStatus::new(Vec::with_capacity(16));
        if request.properties.is_empty() {
            request
                .properties
                .push(DavProperty::WebDav(WebDavProperty::DisplayName));
        }
        let request = PropFind::Prop(request.properties);
        self.prepare_principal_propfind_response(
            access_token,
            resource.collection,
            RoaringBitmap::from_iter(access_token.all_ids()).into_iter(),
            &request,
            &mut response,
        )
        .await?;
        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }
}
