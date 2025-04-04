/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use dav_proto::{Depth, RequestHeaders, schema::response::CardCondition};
use groupware::{
    DavName,
    contact::{AddressBook, ContactCard},
    hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavErrorCondition,
    card::{delete::delete_address_book, insert_addressbook, insert_card, update_card},
    common::uri::DavUriResource,
    file::DavFileResource,
};

use super::{
    assert_is_unique_uid,
    delete::{delete_address_book_and_cards, delete_card},
    update_addressbook,
};

pub(crate) trait CardCopyMoveRequestHandler: Sync + Send {
    fn handle_card_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardCopyMoveRequestHandler for Server {
    async fn handle_card_copy_move_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        is_move: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate source
        let from_resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let from_account_id = from_resource_.account_id;
        let from_resources = self
            .fetch_dav_resources(from_account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let from_resource_name = from_resource_
            .resource
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let from_resource = from_resources
            .paths
            .by_name(from_resource_name)
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate ACL
        if !access_token.is_member(from_account_id)
            && !self
                .has_access_to_document(
                    access_token,
                    from_account_id,
                    Collection::AddressBook,
                    if from_resource.is_container {
                        from_resource.document_id
                    } else {
                        from_resource.parent_id.unwrap()
                    },
                    Acl::ReadItems,
                )
                .await
                .caused_by(trc::location!())?
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        // Validate destination
        let destination = self
            .validate_uri(
                access_token,
                headers
                    .destination
                    .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
            )
            .await?;
        if destination.collection != Collection::AddressBook {
            return Err(DavError::Code(StatusCode::BAD_GATEWAY));
        }
        let to_account_id = destination
            .account_id
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        let to_resources = if to_account_id == from_account_id {
            from_resources.clone()
        } else {
            self.fetch_dav_resources(to_account_id, Collection::AddressBook)
                .await
                .caused_by(trc::location!())?
        };

        // Map destination
        let destination_resource_name = destination
            .resource
            .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?;
        if let Some(to_resource) = to_resources.paths.by_name(destination_resource_name) {
            if from_resource.name == to_resource.name {
                // Same resource
                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
            }
            let new_name = destination_resource_name
                .rsplit_once('/')
                .map(|(_, name)| name)
                .unwrap_or(destination_resource_name);

            match (from_resource.is_container, to_resource.is_container) {
                (true, true) => {
                    let from_children_ids = from_resources
                        .subtree(from_resource_name)
                        .filter(|r| !r.is_container)
                        .map(|r| r.document_id)
                        .collect::<Vec<_>>();
                    let to_document_ids = to_resources
                        .subtree(destination_resource_name)
                        .filter(|r| !r.is_container)
                        .map(|r| r.document_id)
                        .collect::<Vec<_>>();

                    // Validate ACLs
                    if !access_token.is_member(to_account_id)
                        || (!access_token.is_member(from_account_id)
                            && !self
                                .has_access_to_document(
                                    access_token,
                                    from_account_id,
                                    Collection::AddressBook,
                                    from_resource.document_id,
                                    if is_move {
                                        Acl::RemoveItems
                                    } else {
                                        Acl::ReadItems
                                    },
                                )
                                .await
                                .caused_by(trc::location!())?)
                    {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }

                    // Overwrite container
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        from_children_ids,
                        to_account_id,
                        to_resource.document_id.into(),
                        to_document_ids,
                        new_name,
                        is_move,
                    )
                    .await
                }
                (false, false) => {
                    // Overwrite card
                    let from_addressbook_id = from_resource.parent_id.unwrap();
                    let to_addressbook_id = to_resource.parent_id.unwrap();
                    let to_base_path = headers.format_to_base_uri(
                        destination_resource_name
                            .rsplit_once('/')
                            .map(|(base, _)| base)
                            .unwrap_or(destination_resource_name),
                    );

                    // Validate ACL
                    if (!access_token.is_member(from_account_id)
                        && !self
                            .has_access_to_document(
                                access_token,
                                from_account_id,
                                Collection::AddressBook,
                                from_addressbook_id,
                                if is_move {
                                    Acl::RemoveItems
                                } else {
                                    Acl::ReadItems
                                },
                            )
                            .await
                            .caused_by(trc::location!())?)
                        || (!access_token.is_member(to_account_id)
                            && !self
                                .has_access_to_document(
                                    access_token,
                                    to_account_id,
                                    Collection::AddressBook,
                                    to_addressbook_id,
                                    Acl::RemoveItems,
                                )
                                .await
                                .caused_by(trc::location!())?)
                    {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }

                    if is_move {
                        move_card(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_addressbook_id,
                            to_account_id,
                            to_resource.document_id.into(),
                            to_addressbook_id,
                            to_base_path,
                            new_name,
                        )
                        .await
                    } else {
                        copy_card(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            to_account_id,
                            to_resource.document_id.into(),
                            to_addressbook_id,
                            to_base_path,
                            new_name,
                        )
                        .await
                    }
                }
                _ => Err(DavError::Code(StatusCode::BAD_GATEWAY)),
            }
        } else if let Some((parent_resource, new_name)) =
            to_resources.map_parent(destination_resource_name)
        {
            if let Some(parent_resource) = parent_resource {
                // Creating items under a card is not allowed
                // Copying/moving containers under a container is not allowed
                if !parent_resource.is_container || from_resource.is_container {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Validate ACL
                let from_addressbook_id = from_resource.parent_id.unwrap();
                let to_addressbook_id = parent_resource.document_id;
                if (!access_token.is_member(from_account_id)
                    && !self
                        .has_access_to_document(
                            access_token,
                            from_account_id,
                            Collection::AddressBook,
                            from_addressbook_id,
                            if is_move {
                                Acl::RemoveItems
                            } else {
                                Acl::ReadItems
                            },
                        )
                        .await
                        .caused_by(trc::location!())?)
                    || (!access_token.is_member(to_account_id)
                        && !self
                            .has_access_to_document(
                                access_token,
                                to_account_id,
                                Collection::AddressBook,
                                to_addressbook_id,
                                Acl::AddItems,
                            )
                            .await
                            .caused_by(trc::location!())?)
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move card
                if is_move {
                    if from_account_id != to_account_id
                        || parent_resource.document_id != from_addressbook_id
                    {
                        move_card(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_addressbook_id,
                            to_account_id,
                            None,
                            to_addressbook_id,
                            headers.format_to_base_uri(&parent_resource.name),
                            new_name,
                        )
                        .await
                    } else {
                        rename_card(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            from_addressbook_id,
                            new_name,
                        )
                        .await
                    }
                } else {
                    copy_card(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        from_addressbook_id,
                        None,
                        to_addressbook_id,
                        headers.format_to_base_uri(&parent_resource.name),
                        new_name,
                    )
                    .await
                }
            } else {
                // Copying/moving cards to the root is not allowed
                if !from_resource.is_container {
                    return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                }

                // Shared users cannot create containers
                if !access_token.is_member(to_account_id) {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Validate ACLs
                if !access_token.is_member(from_account_id)
                    && !self
                        .has_access_to_document(
                            access_token,
                            from_account_id,
                            Collection::AddressBook,
                            from_resource.document_id,
                            if is_move {
                                Acl::RemoveItems
                            } else {
                                Acl::ReadItems
                            },
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }

                // Copy/move container
                let from_children_ids = from_resources
                    .subtree(from_resource_name)
                    .filter(|r| !r.is_container)
                    .map(|r| r.document_id)
                    .collect::<Vec<_>>();
                if is_move {
                    if from_account_id != to_account_id {
                        copy_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            if headers.depth != Depth::Zero {
                                from_children_ids
                            } else {
                                return Err(DavError::Code(StatusCode::BAD_GATEWAY));
                            },
                            to_account_id,
                            None,
                            vec![],
                            new_name,
                            true,
                        )
                        .await
                    } else {
                        rename_container(
                            self,
                            access_token,
                            from_account_id,
                            from_resource.document_id,
                            new_name,
                        )
                        .await
                    }
                } else {
                    copy_container(
                        self,
                        access_token,
                        from_account_id,
                        from_resource.document_id,
                        if headers.depth != Depth::Zero {
                            from_children_ids
                        } else {
                            vec![]
                        },
                        to_account_id,
                        None,
                        vec![],
                        new_name,
                        false,
                    )
                    .await
                }
            }
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn copy_card(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_addressbook_id: u32,
    to_base_path: String,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch card
    let card_ = server
        .get_archive(from_account_id, Collection::ContactCard, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let card = card_
        .to_unarchived::<ContactCard>()
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();

    if from_account_id == to_account_id {
        if let Some(name) = card
            .inner
            .names
            .iter()
            .find(|n| n.parent_id == to_addressbook_id)
        {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CardCondition::NoUidConflict(format!("{}/{}", to_base_path, name.name).into()),
            )));
        }
        let mut new_card = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        new_card.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_addressbook_id,
        });
        update_card(
            access_token,
            card,
            new_card,
            from_account_id,
            from_document_id,
            false,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    } else {
        // Validate UID
        assert_is_unique_uid(
            server,
            server
                .fetch_dav_resources(to_account_id, Collection::AddressBook)
                .await
                .caused_by(trc::location!())?
                .as_ref(),
            to_account_id,
            to_addressbook_id,
            card.inner.card.uid(),
            &to_base_path,
        )
        .await?;

        let mut new_card = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        new_card.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_addressbook_id,
        }];
        let to_document_id = server
            .store()
            .assign_document_ids(to_account_id, Collection::ContactCard, 1)
            .await
            .caused_by(trc::location!())?;
        insert_card(
            access_token,
            new_card,
            to_account_id,
            to_document_id,
            false,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite card on destination
        let card_ = server
            .get_archive(to_account_id, Collection::ContactCard, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(card_) = card_ {
            let card = card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;

            delete_card(
                access_token,
                to_account_id,
                to_document_id,
                to_addressbook_id,
                card,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn move_card(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_addressbook_id: u32,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_addressbook_id: u32,
    to_base_path: String,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch card
    let card_ = server
        .get_archive(from_account_id, Collection::ContactCard, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let card = card_
        .to_unarchived::<ContactCard>()
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    if from_account_id == to_account_id {
        let mut name_idx = None;
        for (idx, name) in card.inner.names.iter().enumerate() {
            if name.parent_id == to_addressbook_id {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CardCondition::NoUidConflict(format!("{}/{}", to_base_path, name.name).into()),
                )));
            } else if name.parent_id == from_addressbook_id {
                name_idx = Some(idx);
                break;
            }
        }

        let name_idx = if let Some(name_idx) = name_idx {
            name_idx
        } else {
            return Err(DavError::Code(StatusCode::NOT_FOUND));
        };

        let mut new_card = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        new_card.names.swap_remove(name_idx);
        new_card.names.push(DavName {
            name: new_name.to_string(),
            parent_id: to_addressbook_id,
        });
        update_card(
            access_token,
            card.clone(),
            new_card,
            from_account_id,
            from_document_id,
            false,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    } else {
        // Validate UID
        assert_is_unique_uid(
            server,
            server
                .fetch_dav_resources(to_account_id, Collection::AddressBook)
                .await
                .caused_by(trc::location!())?
                .as_ref(),
            to_account_id,
            to_addressbook_id,
            card.inner.card.uid(),
            &to_base_path,
        )
        .await?;

        let mut new_card = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        new_card.names = vec![DavName {
            name: new_name.to_string(),
            parent_id: to_addressbook_id,
        }];

        delete_card(
            access_token,
            from_account_id,
            from_document_id,
            from_addressbook_id,
            card,
            &mut batch,
        )
        .caused_by(trc::location!())?;

        let to_document_id = server
            .store()
            .assign_document_ids(to_account_id, Collection::ContactCard, 1)
            .await
            .caused_by(trc::location!())?;
        insert_card(
            access_token,
            new_card,
            to_account_id,
            to_document_id,
            false,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    }

    let response = if let Some(to_document_id) = to_document_id {
        // Overwrite card on destination
        let card_ = server
            .get_archive(to_account_id, Collection::ContactCard, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(card_) = card_ {
            let card = card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;

            delete_card(
                access_token,
                to_account_id,
                to_document_id,
                to_addressbook_id,
                card,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        }

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    } else {
        Ok(HttpResponse::new(StatusCode::CREATED))
    };

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    response
}

#[allow(clippy::too_many_arguments)]
async fn rename_card(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    addressbook_id: u32,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch card
    let card_ = server
        .get_archive(account_id, Collection::ContactCard, document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let card = card_
        .to_unarchived::<ContactCard>()
        .caused_by(trc::location!())?;

    let name_idx = card
        .inner
        .names
        .iter()
        .position(|n| n.parent_id == addressbook_id)
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let mut new_card = card
        .deserialize::<ContactCard>()
        .caused_by(trc::location!())?;
    new_card.names[name_idx].name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    update_card(
        access_token,
        card,
        new_card,
        account_id,
        document_id,
        false,
        &mut batch,
    )
    .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}

#[allow(clippy::too_many_arguments)]
async fn copy_container(
    server: &Server,
    access_token: &AccessToken,
    from_account_id: u32,
    from_document_id: u32,
    from_children_ids: Vec<u32>,
    to_account_id: u32,
    to_document_id: Option<u32>,
    to_children_ids: Vec<u32>,
    new_name: &str,
    remove_source: bool,
) -> crate::Result<HttpResponse> {
    // Fetch book
    let book_ = server
        .get_archive(from_account_id, Collection::AddressBook, from_document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let old_book = book_
        .to_unarchived::<AddressBook>()
        .caused_by(trc::location!())?;
    let mut book = old_book
        .deserialize::<AddressBook>()
        .caused_by(trc::location!())?;

    // Prepare write batch
    let mut batch = BatchBuilder::new();

    if remove_source {
        delete_address_book(
            access_token,
            from_account_id,
            from_document_id,
            old_book,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    }

    book.name = new_name.to_string();
    book.subscribers.clear();
    book.acls.clear();
    book.is_default = false;

    let is_overwrite = to_document_id.is_some();
    let to_document_id = if let Some(to_document_id) = to_document_id {
        // Overwrite destination
        let book_ = server
            .get_archive(to_account_id, Collection::AddressBook, to_document_id)
            .await
            .caused_by(trc::location!())?;
        if let Some(book_) = book_ {
            let book = book_
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;

            delete_address_book_and_cards(
                server,
                access_token,
                to_account_id,
                to_document_id,
                to_children_ids,
                book,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        }

        to_document_id
    } else {
        server
            .store()
            .assign_document_ids(to_account_id, Collection::AddressBook, 1)
            .await
            .caused_by(trc::location!())?
    };
    insert_addressbook(
        access_token,
        book,
        to_account_id,
        to_document_id,
        false,
        &mut batch,
    )
    .caused_by(trc::location!())?;

    // Copy children
    let mut required_space = 0;
    for from_child_document_id in from_children_ids {
        if let Some(card_) = server
            .get_archive(
                from_account_id,
                Collection::ContactCard,
                from_child_document_id,
            )
            .await?
        {
            let card = card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_name = None;

            for name in card.inner.names.iter() {
                if name.parent_id == to_document_id {
                    continue;
                } else if name.parent_id == from_document_id {
                    new_name = Some(name.name.to_string());
                }
            }
            let new_name = if let Some(new_name) = new_name {
                DavName {
                    name: new_name,
                    parent_id: to_document_id,
                }
            } else {
                continue;
            };
            let card = card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_card = card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;

            if from_account_id == to_account_id {
                if remove_source {
                    new_card
                        .names
                        .retain(|name| name.parent_id != from_document_id);
                }

                new_card.names.push(new_name);
                update_card(
                    access_token,
                    card,
                    new_card,
                    from_account_id,
                    from_document_id,
                    false,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            } else {
                if remove_source {
                    delete_card(
                        access_token,
                        from_account_id,
                        from_child_document_id,
                        from_document_id,
                        card,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
                }

                let to_document_id = server
                    .store()
                    .assign_document_ids(to_account_id, Collection::ContactCard, 1)
                    .await
                    .caused_by(trc::location!())?;
                new_card.names = vec![new_name];
                required_space += new_card.size as u64;
                insert_card(
                    access_token,
                    new_card,
                    to_account_id,
                    to_document_id,
                    false,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            }
        }
    }

    if from_account_id != to_account_id && required_space > 0 {
        server
            .has_available_quota(
                &server
                    .get_resource_token(access_token, to_account_id)
                    .await?,
                required_space,
            )
            .await?;
    }

    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    if !is_overwrite {
        Ok(HttpResponse::new(StatusCode::CREATED))
    } else {
        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}

#[allow(clippy::too_many_arguments)]
async fn rename_container(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    new_name: &str,
) -> crate::Result<HttpResponse> {
    // Fetch book
    let book_ = server
        .get_archive(account_id, Collection::AddressBook, document_id)
        .await
        .caused_by(trc::location!())?
        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
    let book = book_
        .to_unarchived::<AddressBook>()
        .caused_by(trc::location!())?;
    let mut new_book = book
        .deserialize::<AddressBook>()
        .caused_by(trc::location!())?;
    new_book.name = new_name.to_string();

    let mut batch = BatchBuilder::new();
    update_addressbook(
        access_token,
        book,
        new_book,
        account_id,
        document_id,
        false,
        &mut batch,
    )
    .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(HttpResponse::new(StatusCode::CREATED))
}
