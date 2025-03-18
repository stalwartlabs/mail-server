/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    Depth, RequestHeaders,
    schema::{
        request::PropFind,
        response::{BaseCondition, MultiStatus, Response},
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::roaring::RoaringBitmap;

use crate::{
    DavErrorCondition,
    common::uri::DavUriResource,
    file::propfind::HandleFilePropFindRequest,
    principal::propfind::{PrincipalPropFind, PrincipalResource},
};

use super::{DavQuery, uri::UriResource};

pub(crate) trait PropFindRequestHandler: Sync + Send {
    fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PropFindRequestHandler for Server {
    async fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self.validate_uri(access_token, headers.uri).await?;

        // Reject Infinity depth for certain queries
        let return_children = match headers.depth {
            Depth::One | Depth::None => true,
            Depth::Zero => false,
            Depth::Infinity => {
                if resource.account_id.is_none()
                    || matches!(resource.collection, Collection::FileNode)
                {
                    return Err(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::PropFindFiniteDepth,
                    )
                    .into());
                }
                true
            }
        };

        // List shared resources
        if let Some(account_id) = resource.account_id {
            match resource.collection {
                Collection::FileNode => {
                    self.handle_file_propfind_request(
                        access_token,
                        DavQuery::propfind(
                            UriResource::new_owned(
                                Collection::FileNode,
                                account_id,
                                resource.resource,
                            ),
                            request,
                            headers,
                        ),
                    )
                    .await
                }
                Collection::Calendar => todo!(),
                Collection::AddressBook => todo!(),
                Collection::Principal => {
                    let mut response = MultiStatus::new(Vec::with_capacity(16));

                    if let Some(resource) = resource.resource {
                        response.add_response(Response::new_status(
                            [headers.format_to_base_uri(resource)],
                            StatusCode::NOT_FOUND,
                        ));
                    } else {
                        self.prepare_principal_propfind_response(
                            access_token,
                            PrincipalResource::Id(account_id),
                            &request,
                            &mut response,
                        )
                        .await?;
                    }

                    Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()))
                }
                _ => unreachable!(),
            }
        } else {
            let mut response = MultiStatus::new(Vec::with_capacity(16));

            // Add container info
            if !headers.depth_no_root {
                let blah = 1;
            }

            if return_children {
                let ids = if !matches!(resource.collection, Collection::Principal) {
                    RoaringBitmap::from_iter(access_token.all_ids())
                } else {
                    // Return all principals
                    self.get_document_ids(u32::MAX, Collection::Principal)
                        .await?
                        .unwrap_or_default()
                };

                self.prepare_principal_propfind_response(
                    access_token,
                    PrincipalResource::Ids(ids),
                    &request,
                    &mut response,
                )
                .await?;
            }

            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
        }
    }
}
