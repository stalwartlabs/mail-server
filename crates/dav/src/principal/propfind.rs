/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    property::{DavProperty, ReportSet, ResourceType, WebDavProperty},
    request::{DavPropertyValue, PropFind},
    response::{Href, MultiStatus, PropStat, Response},
};
use directory::{QueryBy, backend::internal::PrincipalField};
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use percent_encoding::NON_ALPHANUMERIC;
use trc::AddContext;

use crate::{
    DavResource,
    common::{propfind::PropFindRequestHandler, uri::Urn},
};

use super::CurrentUserPrincipal;

pub(crate) trait PrincipalPropFind: Sync + Send {
    fn prepare_principal_propfind_response(
        &self,
        access_token: &AccessToken,
        collection: Collection,
        documents: impl Iterator<Item = u32> + Sync + Send,
        request: &PropFind,
        response: &mut MultiStatus,
    ) -> impl Future<Output = crate::Result<()>> + Send;

    fn owner_href(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Href>> + Send;
}

impl PrincipalPropFind for Server {
    async fn prepare_principal_propfind_response(
        &self,
        access_token: &AccessToken,
        collection: Collection,
        account_ids: impl Iterator<Item = u32> + Sync + Send,
        request: &PropFind,
        response: &mut MultiStatus,
    ) -> crate::Result<()> {
        let properties = match request {
            PropFind::PropName => {
                let props = all_props(collection, None);
                for account_id in account_ids {
                    response.add_response(Response::new_propstat(
                        self.owner_href(access_token, account_id)
                            .await
                            .caused_by(trc::location!())?,
                        vec![PropStat::new_list(
                            props.iter().cloned().map(DavPropertyValue::empty).collect(),
                        )],
                    ));
                }
                return Ok(());
            }
            PropFind::AllProp(items) => Cow::Owned(all_props(collection, items.as_slice().into())),
            PropFind::Prop(items) => Cow::Borrowed(items),
        };
        let is_principal = collection == Collection::Principal;
        let base_path = DavResource::from(collection).base_path();
        let needs_quota = properties.iter().any(|property| {
            matches!(
                property,
                DavProperty::WebDav(
                    WebDavProperty::QuotaAvailableBytes | WebDavProperty::QuotaUsedBytes
                )
            )
        });

        for account_id in account_ids {
            let mut fields = Vec::with_capacity(properties.len());
            let mut fields_not_found = Vec::new();

            let (name, description) = if access_token.primary_id() == account_id {
                (
                    Cow::Borrowed(access_token.name.as_str()),
                    access_token
                        .description
                        .as_deref()
                        .unwrap_or(&access_token.name)
                        .to_string(),
                )
            } else {
                self.directory()
                    .query(QueryBy::Id(account_id), false)
                    .await
                    .caused_by(trc::location!())?
                    .map(|mut p| {
                        let name = p
                            .take_str(PrincipalField::Name)
                            .unwrap_or_else(|| format!("_{account_id}"));
                        let description = p
                            .take_str(PrincipalField::Description)
                            .unwrap_or_else(|| name.clone());
                        (Cow::Owned(name), description)
                    })
                    .unwrap_or_else(|| {
                        (
                            Cow::Owned(format!("_{}", account_id)),
                            format!("_{}", account_id),
                        )
                    })
            };

            // Fetch quota
            let (quota_used, quota_available) = if needs_quota {
                self.dav_quota(access_token, account_id)
                    .await
                    .caused_by(trc::location!())?
            } else {
                (0, 0)
            };

            for property in properties.as_slice() {
                match property {
                    DavProperty::WebDav(dav_property) => match dav_property {
                        WebDavProperty::DisplayName => {
                            fields
                                .push(DavPropertyValue::new(property.clone(), description.clone()));
                        }
                        WebDavProperty::ResourceType => {
                            if !is_principal {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![ResourceType::Collection],
                                ));
                            } else {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::SupportedReportSet if !is_principal => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![ReportSet::SyncCollection],
                            ));
                        }
                        WebDavProperty::CurrentUserPrincipal => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![access_token.current_user_principal()],
                            ));
                        }
                        WebDavProperty::QuotaAvailableBytes if !is_principal => {
                            fields.push(DavPropertyValue::new(property.clone(), quota_available));
                        }
                        WebDavProperty::QuotaUsedBytes if !is_principal => {
                            fields.push(DavPropertyValue::new(property.clone(), quota_used));
                        }
                        WebDavProperty::SyncToken if !is_principal => {
                            let id = self
                                .store()
                                .get_last_change_id(account_id, collection)
                                .await
                                .caused_by(trc::location!())?
                                .unwrap_or_default();
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                Urn::Sync { id }.to_string(),
                            ));
                        }
                        WebDavProperty::AlternateURISet if is_principal => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::GroupMemberSet if is_principal => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::GroupMembership if is_principal => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::Owner | WebDavProperty::PrincipalURL => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(format!(
                                    "{}/{}",
                                    DavResource::Principal.base_path(),
                                    percent_encoding::utf8_percent_encode(&name, NON_ALPHANUMERIC),
                                ))],
                            ));
                        }
                        WebDavProperty::Group if !is_principal => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::PrincipalCollectionSet => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(DavResource::Principal.base_path().to_string())],
                            ));
                        }
                        _ => {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    },
                    _ => {
                        fields_not_found.push(DavPropertyValue::empty(property.clone()));
                    }
                }
            }

            let mut prop_stats = Vec::with_capacity(2);

            if !fields.is_empty() {
                prop_stats.push(PropStat::new_list(fields));
            }

            if !fields_not_found.is_empty() {
                prop_stats
                    .push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
            }

            response.add_response(Response::new_propstat(
                Href(format!(
                    "{}/{}",
                    base_path,
                    percent_encoding::utf8_percent_encode(&name, NON_ALPHANUMERIC),
                )),
                prop_stats,
            ));
        }

        Ok(())
    }

    async fn owner_href(&self, access_token: &AccessToken, account_id: u32) -> trc::Result<Href> {
        if access_token.primary_id() == account_id {
            Ok(access_token.current_user_principal())
        } else {
            let name = self
                .directory()
                .query(QueryBy::Id(account_id), false)
                .await
                .caused_by(trc::location!())?
                .and_then(|mut p| p.take_str(PrincipalField::Name))
                .unwrap_or_else(|| format!("_{account_id}"));
            Ok(Href(format!(
                "{}/{}",
                DavResource::Principal.base_path(),
                percent_encoding::utf8_percent_encode(&name, NON_ALPHANUMERIC),
            )))
        }
    }
}

fn all_props(collection: Collection, all_props: Option<&[DavProperty]>) -> Vec<DavProperty> {
    if collection == Collection::Principal {
        vec![
            DavProperty::WebDav(WebDavProperty::DisplayName),
            DavProperty::WebDav(WebDavProperty::ResourceType),
            DavProperty::WebDav(WebDavProperty::SupportedReportSet),
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
            DavProperty::WebDav(WebDavProperty::AlternateURISet),
            DavProperty::WebDav(WebDavProperty::PrincipalURL),
            DavProperty::WebDav(WebDavProperty::GroupMemberSet),
            DavProperty::WebDav(WebDavProperty::GroupMembership),
            DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
        ]
    } else if let Some(all_props) = all_props {
        let mut props = vec![
            DavProperty::WebDav(WebDavProperty::DisplayName),
            DavProperty::WebDav(WebDavProperty::ResourceType),
            DavProperty::WebDav(WebDavProperty::SupportedReportSet),
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
            DavProperty::WebDav(WebDavProperty::SyncToken),
            DavProperty::WebDav(WebDavProperty::Owner),
            DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
        ];

        props.extend(all_props.iter().filter(|p| !p.is_all_prop()).cloned());
        props
    } else {
        vec![
            DavProperty::WebDav(WebDavProperty::DisplayName),
            DavProperty::WebDav(WebDavProperty::ResourceType),
            DavProperty::WebDav(WebDavProperty::SupportedReportSet),
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
            DavProperty::WebDav(WebDavProperty::SyncToken),
            DavProperty::WebDav(WebDavProperty::Owner),
            DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
        ]
    }
}
