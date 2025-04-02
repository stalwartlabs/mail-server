/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use dav_proto::RequestHeaders;
use groupware::{
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
    hierarchy::DavHierarchy,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::{Archive, BatchBuilder};
use trc::AddContext;

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};

pub(crate) trait CardDeleteRequestHandler: Sync + Send {
    fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CardDeleteRequestHandler for Server {
    async fn handle_card_delete_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let delete_path = resource
            .resource
            .filter(|r| !r.is_empty())
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let resources = self
            .fetch_dav_resources(account_id, Collection::AddressBook)
            .await
            .caused_by(trc::location!())?;

        // Check resource type
        let delete_resource = resources
            .paths
            .by_name(delete_path)
            .ok_or(DavError::Code(StatusCode::FORBIDDEN))?;
        let document_id = delete_resource.document_id;

        // Fetch entry
        let mut batch = BatchBuilder::new();
        if delete_resource.is_container {
            let book_ = self
                .get_archive(account_id, Collection::AddressBook, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            let book = book_
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;

            // Validate ACL
            if !access_token.is_member(account_id)
                && !book
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                &headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::AddressBook,
                    document_id: document_id.into(),
                    etag: book.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete addressbook and cards
            delete_address_book(
                self,
                access_token,
                account_id,
                document_id,
                resources
                    .subtree(delete_path)
                    .filter(|r| !r.is_container)
                    .map(|r| r.document_id)
                    .collect::<Vec<_>>(),
                book,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        } else {
            // Validate ACL
            let addressbook_id = delete_resource.parent_id.unwrap();
            if !access_token.is_member(account_id)
                && !self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::AddressBook,
                        addressbook_id,
                        Acl::RemoveItems,
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            let card_ = self
                .get_archive(account_id, Collection::ContactCard, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

            // Validate headers
            self.validate_headers(
                access_token,
                &headers,
                vec![ResourceState {
                    account_id,
                    collection: Collection::ContactCard,
                    document_id: document_id.into(),
                    etag: card_.etag().into(),
                    path: delete_path,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::DELETE,
            )
            .await?;

            // Delete card
            delete_card(
                access_token,
                account_id,
                document_id,
                addressbook_id,
                card_
                    .to_unarchived::<ContactCard>()
                    .caused_by(trc::location!())?,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        }

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(HttpResponse::new(StatusCode::NO_CONTENT))
    }
}

pub(crate) async fn delete_address_book(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    children_ids: Vec<u32>,
    book: Archive<&ArchivedAddressBook>,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    // Process deletions
    let addressbook_id = document_id;
    for document_id in children_ids {
        if let Some(card_) = server
            .get_archive(account_id, Collection::ContactCard, document_id)
            .await?
        {
            delete_card(
                access_token,
                account_id,
                document_id,
                addressbook_id,
                card_
                    .to_unarchived::<ContactCard>()
                    .caused_by(trc::location!())?,
                batch,
            )
            .await?;
        }
    }

    // Delete addressbook
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::AddressBook)
        .delete_document(document_id)
        .custom(
            ObjectIndexBuilder::<_, ()>::new()
                .with_tenant_id(access_token)
                .with_current(book),
        )
        .caused_by(trc::location!())?;

    Ok(())
}

pub(crate) async fn delete_card(
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    addressbook_id: u32,
    card: Archive<&ArchivedContactCard>,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    if let Some(delete_idx) = card
        .inner
        .names
        .iter()
        .position(|name| name.parent_id == addressbook_id)
    {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard);

        if card.inner.names.len() > 1 {
            // Unlink addressbook id from card
            let mut new_card = card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;
            new_card.names.swap_remove(delete_idx);
            batch
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_tenant_id(access_token)
                        .with_current(card)
                        .with_changes(new_card),
                )
                .caused_by(trc::location!())?;
        } else {
            // Delete card
            batch
                .delete_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_tenant_id(access_token)
                        .with_current(card),
                )
                .caused_by(trc::location!())?;
        }

        batch.commit_point();
    }

    Ok(())
}
