/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::{AccessToken, AsTenantId},
};
use dav_proto::schema::{
    property::{DavProperty, WebDavProperty},
    request::{PrincipalPropertySearch, PropFind},
    response::MultiStatus,
};
use directory::{Type, backend::internal::manage::ManageDirectory};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::roaring::RoaringBitmap;
use trc::AddContext;

use super::propfind::PrincipalPropFind;

pub(crate) trait PrincipalPropSearch: Sync + Send {
    fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        request: PrincipalPropertySearch,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl PrincipalPropSearch for Server {
    async fn handle_principal_property_search(
        &self,
        access_token: &AccessToken,
        mut request: PrincipalPropertySearch,
    ) -> crate::Result<HttpResponse> {
        let mut search_for = None;

        for prop_search in request.property_search {
            if matches!(
                prop_search.property,
                DavProperty::WebDav(WebDavProperty::DisplayName)
            ) && !prop_search.match_.is_empty()
            {
                search_for = Some(prop_search.match_);
            }
        }

        let mut response = MultiStatus::new(Vec::with_capacity(16));
        if let Some(search_for) = search_for {
            // Return all principals
            let principals = self
                .store()
                .list_principals(
                    search_for.as_str().into(),
                    access_token.tenant_id(),
                    &[Type::Individual, Type::Group],
                    false,
                    0,
                    0,
                )
                .await
                .caused_by(trc::location!())?;

            let ids = RoaringBitmap::from_iter(principals.items.into_iter().map(|p| p.id()));

            if !ids.is_empty() {
                if request.properties.is_empty() {
                    request
                        .properties
                        .push(DavProperty::WebDav(WebDavProperty::DisplayName));
                }
                let request = PropFind::Prop(request.properties);
                self.prepare_principal_propfind_response(
                    access_token,
                    Collection::Principal,
                    ids.into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
            }
        }

        Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
    }
}
