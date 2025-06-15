/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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
        response::{BaseCondition, MultiStatus, Response},
    },
};
use groupware::{
    cache::GroupwareCache,
    contact::{AddressBook, ContactCard},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavMethod, PropStatBuilder,
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
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_addressbook_properties(
        &self,
        address_book: &mut AddressBook,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool;

    fn apply_card_properties(
        &self,
        card: &mut ContactCard,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool;
}

impl CardPropPatchRequestHandler for Server {
    async fn handle_card_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
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
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.by_path(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = resource.document_id();
        let collection = if resource.is_container() {
            Collection::AddressBook
        } else {
            Collection::ContactCard
        };

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Verify ACL
        if !access_token.is_member(account_id) {
            let (acl, document_id) = if resource.is_container() {
                (Acl::Modify, resource.document_id())
            } else {
                (Acl::ModifyItems, resource.parent_id().unwrap())
            };

            if !resources.has_access_to_container(access_token, document_id, acl) {
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
            headers,
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
        let mut items = PropStatBuilder::default();

        let etag = if resource.is_container() {
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
                    MultiStatus::new(vec![Response::new_propstat(uri, items.build())])
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
        items: &mut PropStatBuilder,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        address_book.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (
                    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
                    DavValue::String(name),
                ) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        address_book.description = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );

                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    address_book.created = dt;
                    items.insert_ok(property.property);
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) => {
                    if !types.0.iter().all(|rt| {
                        matches!(rt, ResourceType::Collection | ResourceType::AddressBook)
                    }) {
                        items.insert_precondition_failed(
                            property.property,
                            StatusCode::FORBIDDEN,
                            BaseCondition::ValidResourceType,
                        );
                        has_errors = true;
                    } else {
                        items.insert_ok(property.property);
                    }
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.groupware.dead_property_size.is_some() =>
                {
                    if is_update {
                        address_book.dead_properties.remove_element(dead);
                    }

                    if address_book.dead_properties.size() + values.size() + dead.size()
                        < self.core.groupware.dead_property_size.unwrap()
                    {
                        address_book
                            .dead_properties
                            .add_element(dead.clone(), values.0);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
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
        items: &mut PropStatBuilder,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        card.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    card.created = dt;
                    items.insert_ok(property.property);
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.groupware.dead_property_size.is_some() =>
                {
                    if is_update {
                        card.dead_properties.remove_element(dead);
                    }

                    if card.dead_properties.size() + values.size() + dead.size()
                        < self.core.groupware.dead_property_size.unwrap()
                    {
                        card.dead_properties.add_element(dead.clone(), values.0);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
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
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                card.display_name = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::DeadProperty(dead) => {
                card.dead_properties.remove_element(dead);
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}

fn remove_addressbook_properties(
    book: &mut AddressBook,
    properties: Vec<DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::CardDav(CardDavProperty::AddressbookDescription) => {
                book.description = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                book.display_name = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::DeadProperty(dead) => {
                book.dead_properties.remove_element(dead);
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}
