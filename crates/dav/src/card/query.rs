/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError,
    common::{
        AddressbookFilter, DavQuery,
        propfind::{PropFindItem, PropFindRequestHandler},
        uri::DavUriResource,
    },
};
use calcard::vcard::{
    ArchivedVCard, ArchivedVCardEntry, ArchivedVCardParameter, VCardParameterName, VCardProperty,
    VCardVersion,
};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::CardDavPropertyName,
        request::{AddressbookQuery, Filter, FilterOp, VCardPropertyWithGroup},
    },
};
use groupware::cache::GroupwareCache;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::SyncCollection};
use std::fmt::Write;
use trc::AddContext;

pub(crate) trait CardQueryRequestHandler: Sync + Send {
    fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardQueryRequestHandler for Server {
    async fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .by_path(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Obtain shared ids
        let shared_ids = if !access_token.is_member(account_id) {
            resources
                .shared_containers(access_token, [Acl::ReadItems], false)
                .into()
        } else {
            None
        };

        // Obtain document ids in folder
        let mut items = Vec::with_capacity(16);
        for resource in resources.children(resource.document_id()) {
            if shared_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(resource.document_id()))
            {
                items.push(PropFindItem::new(
                    resources.format_resource(resource),
                    account_id,
                    resource,
                ));
            }
        }

        self.handle_dav_query(
            access_token,
            DavQuery::addressbook_query(request, items, headers),
        )
        .await
    }
}

pub(crate) fn vcard_query(card: &ArchivedVCard, filters: &AddressbookFilter) -> bool {
    let mut is_all = true;
    let mut matches_one = false;

    for filter in filters {
        match filter {
            Filter::AnyOf => {
                is_all = false;
            }
            Filter::AllOf => {
                is_all = true;
            }
            Filter::Property { prop, op, .. } => {
                let mut properties = find_properties(card, prop).peekable();
                let result = if properties.peek().is_some() {
                    properties.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            let mut matched_any = false;

                            for value in entry.values.iter() {
                                if let Some(text) = value.as_text() {
                                    if text_match.matches(text) {
                                        matched_any = true;
                                        break;
                                    }
                                }
                            }

                            matched_any
                        }
                        FilterOp::TimeRange(_) => false,
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                };

                if result {
                    matches_one = true;
                } else if is_all {
                    return false;
                }
            }
            Filter::Parameter {
                prop, param, op, ..
            } => {
                let mut properties = find_properties(card, prop)
                    .filter_map(|entry| find_parameter(entry, param))
                    .peekable();
                let result = if properties.peek().is_some() {
                    properties.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            if let Some(text) = entry.as_text() {
                                text_match.matches(text)
                            } else {
                                false
                            }
                        }
                        FilterOp::TimeRange(_) => false,
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                };

                if result {
                    matches_one = true;
                } else if is_all {
                    return false;
                }
            }
            Filter::Component { .. } => {}
        }
    }

    is_all || matches_one
}

#[inline(always)]
fn find_properties<'x>(
    card: &'x ArchivedVCard,
    prop: &VCardPropertyWithGroup,
) -> impl Iterator<Item = &'x ArchivedVCardEntry> {
    card.entries
        .iter()
        .filter(move |entry| entry.name == prop.name && entry.group == prop.group)
}

#[inline(always)]
fn find_parameter<'x>(
    entry: &'x ArchivedVCardEntry,
    name: &VCardParameterName,
) -> Option<&'x ArchivedVCardParameter> {
    entry.params.iter().find(|param| param.matches_name(name))
}

pub(crate) fn serialize_vcard_with_props(
    card: &ArchivedVCard,
    props: &[CardDavPropertyName],
    version: Option<VCardVersion>,
) -> String {
    let mut vcard = String::with_capacity(128);
    let version = version.or_else(|| card.version()).unwrap_or_default();
    if !props.is_empty() {
        let _ = write!(&mut vcard, "BEGIN:VCARD\r\n");
        let is_v4 = matches!(version, VCardVersion::V4_0);

        for entry in card.entries.iter() {
            for item in props {
                if entry.name == item.name && entry.group == item.group {
                    if item.name != VCardProperty::Version {
                        let _ = entry.write_to(&mut vcard, !item.no_value, is_v4);
                    } else {
                        let _ = write!(&mut vcard, "VERSION:{version}\r\n");
                    }
                    break;
                }
            }
        }
        let _ = write!(&mut vcard, "END:VCARD\r\n");
    } else {
        let _ = card.write_to(&mut vcard, version);
    }

    vcard
}
