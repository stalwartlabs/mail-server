/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::{Server, auth::AccessToken};
use dav_proto::schema::{
    Namespace,
    property::{
        DavProperty, DavValue, PrincipalProperty, Privilege, ReportSet, ResourceType,
        WebDavProperty,
    },
    request::{DavPropertyValue, PropFind},
    response::{Href, MultiStatus, PropStat, Response},
};
use directory::{QueryBy, backend::internal::manage::ManageDirectory};
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use groupware::RFC_3986;
use trc::AddContext;

use crate::{
    DavResourceName,
    common::propfind::{PropFindRequestHandler, SyncTokenUrn},
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

    fn expand_principal(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        propfind: &PropFind,
    ) -> impl Future<Output = crate::Result<Option<Response>>> + Send;

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
        let is_principal = match collection {
            Collection::AddressBook | Collection::ContactCard => {
                response.set_namespace(Namespace::CardDav);
                false
            }
            Collection::Calendar | Collection::CalendarEvent => {
                response.set_namespace(Namespace::CalDav);
                false
            }
            Collection::Principal => true,
            _ => false,
        };
        let base_path = DavResourceName::from(collection).base_path();
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
                    .map(|p| {
                        let name = p.name;
                        let description = p.description.unwrap_or_else(|| name.clone());
                        (Cow::Owned(name.to_string()), description.to_string())
                    })
                    .unwrap_or_else(|| {
                        (
                            Cow::Owned(format!("_{}", account_id)),
                            format!("_{}", account_id),
                        )
                    })
            };

            // Fetch quota
            let quota = if needs_quota {
                self.dav_quota(access_token, account_id)
                    .await
                    .caused_by(trc::location!())?
            } else {
                Default::default()
            };

            for property in properties.as_slice() {
                match property {
                    DavProperty::WebDav(dav_property) => match dav_property {
                        WebDavProperty::DisplayName => {
                            fields
                                .push(DavPropertyValue::new(property.clone(), description.clone()));
                        }
                        WebDavProperty::ResourceType => {
                            let resource_type = if !is_principal {
                                vec![ResourceType::Collection]
                            } else {
                                vec![ResourceType::Principal, ResourceType::Collection]
                            };

                            fields.push(DavPropertyValue::new(property.clone(), resource_type));
                        }
                        WebDavProperty::SupportedReportSet => {
                            let reports = match collection {
                                Collection::Principal => ReportSet::principal(),
                                Collection::Calendar | Collection::CalendarEvent => {
                                    ReportSet::calendar()
                                }
                                Collection::AddressBook | Collection::ContactCard => {
                                    ReportSet::addressbook()
                                }
                                _ => ReportSet::file(),
                            };

                            fields.push(DavPropertyValue::new(property.clone(), reports));
                        }
                        WebDavProperty::CurrentUserPrincipal => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![access_token.current_user_principal()],
                            ));
                        }
                        WebDavProperty::QuotaAvailableBytes if !is_principal => {
                            fields.push(DavPropertyValue::new(property.clone(), quota.available));
                        }
                        WebDavProperty::QuotaUsedBytes if !is_principal => {
                            fields.push(DavPropertyValue::new(property.clone(), quota.used));
                        }
                        WebDavProperty::SyncToken if !is_principal => {
                            let sync_token = self
                                .fetch_dav_resources(access_token, account_id, collection.into())
                                .await
                                .caused_by(trc::location!())?
                                .sync_token();

                            fields.push(DavPropertyValue::new(property.clone(), sync_token));
                        }
                        WebDavProperty::GetCTag if !is_principal => {
                            let ctag = self
                                .fetch_dav_resources(access_token, account_id, collection.into())
                                .await
                                .caused_by(trc::location!())?
                                .highest_change_id;

                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String(format!("\"{ctag}\"")),
                            ));
                        }
                        WebDavProperty::Owner => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(format!(
                                    "{}/{}/",
                                    DavResourceName::Principal.base_path(),
                                    percent_encoding::utf8_percent_encode(&name, RFC_3986),
                                ))],
                            ));
                        }
                        WebDavProperty::Group if !is_principal => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::CurrentUserPrivilegeSet if !is_principal => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                if access_token.is_member(account_id) {
                                    Privilege::all(matches!(
                                        collection,
                                        Collection::Calendar | Collection::CalendarEvent
                                    ))
                                } else {
                                    vec![Privilege::Read]
                                },
                            ));
                        }
                        WebDavProperty::PrincipalCollectionSet => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(
                                    DavResourceName::Principal.collection_path().to_string(),
                                )],
                            ));
                        }
                        _ => {
                            response.set_namespace(property.namespace());
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    },
                    DavProperty::Principal(principal_property) => match principal_property {
                        PrincipalProperty::AlternateURISet
                        | PrincipalProperty::GroupMemberSet
                        | PrincipalProperty::GroupMembership => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        PrincipalProperty::PrincipalURL => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(format!(
                                    "{}/{}/",
                                    DavResourceName::Principal.base_path(),
                                    percent_encoding::utf8_percent_encode(&name, RFC_3986),
                                ))],
                            ));
                        }
                        PrincipalProperty::CalendarHomeSet => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(format!(
                                    "{}/{}/",
                                    DavResourceName::Cal.base_path(),
                                    percent_encoding::utf8_percent_encode(&name, RFC_3986),
                                ))],
                            ));
                            response.set_namespace(Namespace::CalDav);
                        }
                        PrincipalProperty::AddressbookHomeSet => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(format!(
                                    "{}/{}/",
                                    DavResourceName::Card.base_path(),
                                    percent_encoding::utf8_percent_encode(&name, RFC_3986),
                                ))],
                            ));
                            response.set_namespace(Namespace::CardDav);
                        }
                        PrincipalProperty::PrincipalAddress => {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            response.set_namespace(Namespace::CardDav);
                        }
                    },
                    _ => {
                        response.set_namespace(property.namespace());
                        fields_not_found.push(DavPropertyValue::empty(property.clone()));
                    }
                }
            }

            let mut prop_stats = Vec::with_capacity(2);

            if !fields_not_found.is_empty() {
                prop_stats
                    .push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
            }

            if !fields.is_empty() || prop_stats.is_empty() {
                prop_stats.push(PropStat::new_list(fields));
            }

            response.add_response(Response::new_propstat(
                Href(format!(
                    "{}/{}/",
                    base_path,
                    percent_encoding::utf8_percent_encode(&name, RFC_3986),
                )),
                prop_stats,
            ));
        }

        Ok(())
    }

    async fn expand_principal(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        propfind: &PropFind,
    ) -> crate::Result<Option<Response>> {
        let mut status = MultiStatus::new(vec![]);
        self.prepare_principal_propfind_response(
            access_token,
            Collection::Principal,
            [account_id].into_iter(),
            propfind,
            &mut status,
        )
        .await?;

        Ok(status.response.0.into_iter().next())
    }

    async fn owner_href(&self, access_token: &AccessToken, account_id: u32) -> trc::Result<Href> {
        if access_token.primary_id() == account_id {
            Ok(access_token.current_user_principal())
        } else {
            let name = self
                .store()
                .get_principal_name(account_id)
                .await
                .caused_by(trc::location!())?
                .unwrap_or_else(|| format!("_{account_id}"));
            Ok(Href(format!(
                "{}/{}/",
                DavResourceName::Principal.base_path(),
                percent_encoding::utf8_percent_encode(&name, RFC_3986),
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
            DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
            DavProperty::Principal(PrincipalProperty::AlternateURISet),
            DavProperty::Principal(PrincipalProperty::PrincipalURL),
            DavProperty::Principal(PrincipalProperty::GroupMemberSet),
            DavProperty::Principal(PrincipalProperty::GroupMembership),
        ]
    } else {
        let mut props = vec![
            DavProperty::WebDav(WebDavProperty::DisplayName),
            DavProperty::WebDav(WebDavProperty::ResourceType),
            DavProperty::WebDav(WebDavProperty::SupportedReportSet),
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
            DavProperty::WebDav(WebDavProperty::SyncToken),
            DavProperty::WebDav(WebDavProperty::Owner),
            DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
        ];

        if let Some(all_props) = all_props {
            props.extend(all_props.iter().filter(|p| !p.is_all_prop()).cloned());
            props
        } else {
            props
        }
    }
}
