/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::collection::{Collection, VanishedCollection};
use store::write::{Archive, BatchBuilder, now};
use trc::AddContext;

use crate::DestroyArchive;

use super::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};

impl ContactCard {
    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        card: Archive<&ArchivedContactCard>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        let mut new_card = self;

        // Build card
        new_card.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(card)
                    .with_changes(new_card)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build card
        let mut card = self;
        let now = now() as i64;
        card.modified = now;
        card.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(card)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl AddressBook {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address book
        let mut book = self;
        let now = now() as i64;
        book.modified = now;
        book.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(book)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        book: Archive<&ArchivedAddressBook>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address book
        let mut new_book = self;
        new_book.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(book)
                    .with_changes(new_book)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedAddressBook>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_with_cards(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        children_ids: Vec<u32>,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Process deletions
        let addressbook_id = document_id;
        for document_id in children_ids {
            if let Some(card_) = server
                .get_archive(account_id, Collection::ContactCard, document_id)
                .await?
            {
                DestroyArchive(
                    card_
                        .to_unarchived::<ContactCard>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    access_token,
                    account_id,
                    document_id,
                    addressbook_id,
                    None,
                    batch,
                )?;
            }
        }

        self.delete(access_token, account_id, document_id, delete_path, batch)
    }

    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let book = self.0;
        // Delete addressbook
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

        if let Some(delete_path) = delete_path {
            batch.log_vanished_item(VanishedCollection::AddressBook, delete_path);
        }

        batch.commit_point();

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedContactCard>> {
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        addressbook_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let card = self.0;
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

            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::AddressBook, delete_path);
            }

            batch.commit_point();
        }

        Ok(())
    }
}
