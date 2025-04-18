/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        Namespace,
        property::{CardDavProperty, DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, MultiStatus, PropStat, Response},
    },
};
use groupware::{
    contact::{AddressBook, ContactCard},
    hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

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

    fn apply_card_properties(
        &self,
        card: &mut ContactCard,
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
        mut request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let uri = headers.uri;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.paths.by_name(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = resource.document_id;
        let collection = if resource.is_container {
            Collection::AddressBook
        } else {
            Collection::ContactCard
        };

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Verify ACL
        if !access_token.is_member(account_id) {
            let (acl, document_id) = if resource.is_container {
                (Acl::Read, resource.document_id)
            } else {
                (Acl::ReadItems, resource.parent_id.unwrap())
            };

            if !self
                .has_access_to_document(
                    access_token,
                    account_id,
                    Collection::AddressBook,
                    document_id,
                    acl,
                )
                .await
                .caused_by(trc::location!())?
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Fetch archive
        let archive = self
            .get_archive(account_id, collection, document_id)
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate headers
        self.validate_headers(
            access_token,
            &headers,
            vec![ResourceState {
                account_id,
                collection,
                document_id: document_id.into(),
                etag: archive.etag().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        let is_success;
        let mut batch = BatchBuilder::new();
        let mut items = Vec::with_capacity(request.remove.len() + request.set.len());

        let etag = if resource.is_container {
            // Deserialize
            let book = archive
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;
            let mut new_book = archive
                .deserialize::<AddressBook>()
                .caused_by(trc::location!())?;

            // Remove properties
            if !request.set_first && !request.remove.is_empty() {
                remove_addressbook_properties(
                    &mut new_book,
                    std::mem::take(&mut request.remove),
                    &mut items,
                );
            }

            // Set properties
            is_success =
                self.apply_addressbook_properties(&mut new_book, true, request.set, &mut items);

            // Remove properties
            if is_success && !request.remove.is_empty() {
                remove_addressbook_properties(&mut new_book, request.remove, &mut items);
            }

            if is_success {
                new_book
                    .update(access_token, book, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?
                    .etag()
            } else {
                book.etag().into()
            }
        } else {
            // Deserialize
            let card = archive
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_card = archive
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;

            // Remove properties
            if !request.set_first && !request.remove.is_empty() {
                remove_card_properties(
                    &mut new_card,
                    std::mem::take(&mut request.remove),
                    &mut items,
                );
            }

            // Set properties
            is_success = self.apply_card_properties(&mut new_card, true, request.set, &mut items);

            // Remove properties
            if is_success && !request.remove.is_empty() {
                remove_card_properties(&mut new_card, request.remove, &mut items);
            }

            if is_success {
                new_card
                    .update(access_token, card, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?
                    .etag()
            } else {
                card.etag().into()
            }
        };

        if is_success {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items)])
                        .with_namespace(Namespace::CardDav)
                        .to_string(),
                )
                .with_etag_opt(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        }
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

    fn apply_card_properties(
        &self,
        card: &mut ContactCard,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut Vec<PropStat>,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.dav.live_property_size {
                        card.display_name = Some(name);
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
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    card.created = dt;
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.dav.dead_property_size.is_some() =>
                {
                    if is_update {
                        card.dead_properties.remove_element(&dead);
                    }

                    if card.dead_properties.size() + values.size() + dead.size()
                        < self.core.dav.dead_property_size.unwrap()
                    {
                        card.dead_properties.add_element(dead.clone(), values.0);
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

fn remove_card_properties(
    card: &mut ContactCard,
    properties: Vec<DavProperty>,
    items: &mut Vec<PropStat>,
) {
    for property in properties {
        match property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                card.display_name = None;
                items.push(
                    PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                        .with_status(StatusCode::OK),
                );
            }
            DavProperty::DeadProperty(dead) => {
                card.dead_properties.remove_element(&dead);
                items.push(
                    PropStat::new(DavProperty::DeadProperty(dead)).with_status(StatusCode::OK),
                );
            }
            property => {
                items.push(
                    PropStat::new(property)
                        .with_status(StatusCode::CONFLICT)
                        .with_response_description("Property cannot be modified"),
                );
            }
        }
    }
}

fn remove_addressbook_properties(
    book: &mut AddressBook,
    properties: Vec<DavProperty>,
    items: &mut Vec<PropStat>,
) {
    for property in properties {
        match property {
            DavProperty::CardDav(CardDavProperty::AddressbookDescription) => {
                book.description = None;
                items.push(
                    PropStat::new(DavProperty::CardDav(
                        CardDavProperty::AddressbookDescription,
                    ))
                    .with_status(StatusCode::OK),
                );
            }
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                book.display_name = None;
                items.push(
                    PropStat::new(DavProperty::WebDav(WebDavProperty::DisplayName))
                        .with_status(StatusCode::OK),
                );
            }
            DavProperty::DeadProperty(dead) => {
                book.dead_properties.remove_element(&dead);
                items.push(
                    PropStat::new(DavProperty::DeadProperty(dead)).with_status(StatusCode::OK),
                );
            }
            property => {
                items.push(
                    PropStat::new(property)
                        .with_status(StatusCode::CONFLICT)
                        .with_response_description("Property cannot be modified"),
                );
            }
        }
    }
}
