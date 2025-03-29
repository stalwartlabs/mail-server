/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{
        property::{CardDavProperty, DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, PropStat},
    },
};
use groupware::contact::AddressBook;
use http_proto::HttpResponse;
use hyper::StatusCode;

use crate::common::uri::DavUriResource;

pub(crate) trait CardPropPatchRequestHandler: Sync + Send {
    fn handle_card_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_addressbook_properties(
        &self,
        address_book: &mut AddressBook,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut Vec<PropStat>,
    ) -> bool;
}

impl CardPropPatchRequestHandler for Server {
    async fn handle_card_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;

        todo!()
    }

    fn apply_addressbook_properties(
        &self,
        address_book: &mut AddressBook,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut Vec<PropStat>,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.dav.live_property_size {
                        address_book.display_name = Some(name);
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                                .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                                .with_status(StatusCode::INSUFFICIENT_STORAGE)
                                .with_response_description("Display name too long"),
                        );
                        has_errors = true;
                    }
                }
                (
                    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
                    DavValue::String(name),
                ) => {
                    if name.len() <= self.core.dav.live_property_size {
                        address_book.description = Some(name);
                        items.push(
                            PropStat::new(DavProperty::CardDav(
                                CardDavProperty::AddressbookDescription,
                            ))
                            .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::CardDav(
                                CardDavProperty::AddressbookDescription,
                            ))
                            .with_status(StatusCode::INSUFFICIENT_STORAGE)
                            .with_response_description("Addressbook description too long"),
                        );
                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    address_book.created = dt;
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) => {
                    if types.0.iter().all(|rt| {
                        matches!(rt, ResourceType::Collection | ResourceType::AddressBook)
                    }) {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::ResourceType))
                                .with_status(StatusCode::FORBIDDEN)
                                .with_error(BaseCondition::ValidResourceType),
                        );
                        has_errors = true;
                    } else {
                        items.push(
                            PropStat::new(DavProperty::WebDav(WebDavProperty::ResourceType))
                                .with_status(StatusCode::OK),
                        );
                    }
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.dav.dead_property_size.is_some() =>
                {
                    if is_update {
                        address_book.dead_properties.remove_element(&dead);
                    }

                    if address_book.dead_properties.size() + values.size() + dead.size()
                        < self.core.dav.dead_property_size.unwrap()
                    {
                        address_book
                            .dead_properties
                            .add_element(dead.clone(), values.0);
                        items.push(
                            PropStat::new(DavProperty::DeadProperty(dead))
                                .with_status(StatusCode::OK),
                        );
                    } else {
                        items.push(
                            PropStat::new(DavProperty::DeadProperty(dead))
                                .with_status(StatusCode::INSUFFICIENT_STORAGE)
                                .with_response_description("Dead property is too large."),
                        );
                        has_errors = true;
                    }
                }
                (property, _) => {
                    items.push(
                        PropStat::new(property)
                            .with_status(StatusCode::CONFLICT)
                            .with_response_description("Property cannot be modified"),
                    );
                    has_errors = true;
                }
            }
        }

        !has_errors
    }
}
