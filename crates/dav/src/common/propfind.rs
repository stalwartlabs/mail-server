/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::{AccessToken, AsTenantId},
};
use dav_proto::{
    Depth, RequestHeaders,
    schema::{
        property::{DavProperty, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropFind},
        response::{BaseCondition, MultiStatus, PropStat, Response},
    },
};
use directory::{
    Type,
    backend::internal::{PrincipalField, manage::ManageDirectory},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::roaring::RoaringBitmap;
use trc::AddContext;

use crate::{
    DavErrorCondition,
    common::uri::DavUriResource,
    file::propfind::HandleFilePropFindRequest,
    principal::{CurrentUserPrincipal, propfind::PrincipalPropFind},
};

use super::{DavQuery, uri::UriResource};

pub(crate) trait PropFindRequestHandler: Sync + Send {
    fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropFind,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn dav_quota(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<(u64, u64)>> + Send;
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
                            Collection::Principal,
                            [account_id].into_iter(),
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
                let mut prop_stat = match &request {
                    PropFind::PropName | PropFind::AllProp(_) => {
                        vec![
                            DavPropertyValue::empty(DavProperty::WebDav(
                                WebDavProperty::ResourceType,
                            )),
                            DavPropertyValue::empty(DavProperty::WebDav(
                                WebDavProperty::CurrentUserPrincipal,
                            )),
                        ]
                    }
                    PropFind::Prop(items) => {
                        items.iter().cloned().map(DavPropertyValue::empty).collect()
                    }
                };

                if !matches!(request, PropFind::PropName) {
                    for prop in &mut prop_stat {
                        match &prop.property {
                            DavProperty::WebDav(WebDavProperty::ResourceType) => {
                                prop.value = vec![ResourceType::Collection].into();
                            }
                            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal) => {
                                prop.value = vec![access_token.current_user_principal()].into();
                            }
                            _ => (),
                        }
                    }
                }

                response.add_response(Response::new_propstat(
                    resource.base_path(),
                    vec![PropStat::new_list(prop_stat)],
                ));
            }

            if return_children {
                let ids = if !matches!(resource.collection, Collection::Principal) {
                    RoaringBitmap::from_iter(access_token.all_ids())
                } else {
                    // Return all principals
                    let principals = self
                        .store()
                        .list_principals(
                            None,
                            access_token.tenant_id(),
                            &[Type::Individual, Type::Group],
                            &[PrincipalField::Name],
                            0,
                            0,
                        )
                        .await
                        .caused_by(trc::location!())?;

                    RoaringBitmap::from_iter(principals.items.into_iter().map(|p| p.id()))
                };

                self.prepare_principal_propfind_response(
                    access_token,
                    resource.collection,
                    ids.into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
            }

            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
        }
    }

    async fn dav_quota(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<(u64, u64)> {
        let resource_token = self
            .get_resource_token(access_token, account_id)
            .await
            .caused_by(trc::location!())?;
        let quota = if resource_token.quota > 0 {
            resource_token.quota
        } else if let Some(tenant) = resource_token.tenant.filter(|t| t.quota > 0) {
            tenant.quota
        } else {
            u64::MAX
        };
        let quota_used = self
            .get_used_quota(account_id)
            .await
            .caused_by(trc::location!())? as u64;
        let quota_available = quota.saturating_sub(quota_used);

        Ok((quota_used, quota_available))
    }
}
