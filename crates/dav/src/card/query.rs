/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::vcard::{
    ArchivedVCard, ArchivedVCardEntry, ArchivedVCardParameter, VCardParameterName,
};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::request::{AddressbookQuery, Filter, FilterOp, VCardPropertyWithGroup},
};
use groupware::hierarchy::DavHierarchy;
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use trc::AddContext;

use crate::{
    DavError,
    common::{
        AddressbookFilter, DavQuery,
        propfind::{PropFindItem, PropFindRequestHandler},
        uri::DavUriResource,
    },
};

pub(crate) trait CardQueryRequestHandler: Sync + Send {
    fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardQueryRequestHandler for Server {
    async fn handle_card_query_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: AddressbookQuery,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .paths
            .by_name(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.is_container {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }

        // Obtain shared ids
        let shared_ids = if !access_token.is_member(account_id) {
            self.shared_containers(
                access_token,
                account_id,
                Collection::AddressBook,
                Acl::ReadItems,
            )
            .await
            .caused_by(trc::location!())?
            .into()
        } else {
            None
        };

        // Obtain document ids in folder
        let mut items = Vec::with_capacity(16);
        for resource in resources.children(resource.document_id) {
            if shared_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(resource.document_id))
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
                let result = if let Some(entry) = find_property(card, prop) {
                    match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            let mut matched_any = false;

                            for value in entry.values.iter() {
                                if let Some(text) = value.as_text() {
                                    if text_match.matches(&text.to_lowercase()) {
                                        matched_any = true;
                                        break;
                                    }
                                }
                            }

                            matched_any
                        }
                        FilterOp::TimeRange(_) => false,
                    }
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
                let result = if let Some(entry) =
                    find_property(card, prop).and_then(|entry| find_parameter(entry, param))
                {
                    match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            if let Some(text) = entry.as_text() {
                                text_match.matches(&text.to_lowercase())
                            } else {
                                false
                            }
                        }
                        FilterOp::TimeRange(_) => false,
                    }
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
fn find_property<'x>(
    card: &'x ArchivedVCard,
    prop: &VCardPropertyWithGroup,
) -> Option<&'x ArchivedVCardEntry> {
    card.entries
        .iter()
        .find(|entry| entry.name == prop.name && entry.group == prop.group)
}

#[inline(always)]
fn find_parameter<'x>(
    entry: &'x ArchivedVCardEntry,
    name: &VCardParameterName,
) -> Option<&'x ArchivedVCardParameter> {
    entry.params.iter().find(|param| param.matches_name(name))
}
