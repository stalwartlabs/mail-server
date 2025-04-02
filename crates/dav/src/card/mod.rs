/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{auth::AccessToken, storage::index::ObjectIndexBuilder};
use groupware::contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};
use jmap_proto::types::collection::Collection;
use store::write::{Archive, BatchBuilder, now};

use crate::common::ExtractETag;

pub mod acl;
pub mod copy_move;
pub mod delete;
pub mod get;
pub mod mkcol;
pub mod propfind;
pub mod proppatch;
pub mod query;
pub mod update;

pub(crate) fn update_card(
    access_token: &AccessToken,
    card: Archive<&ArchivedContactCard>,
    mut new_card: ContactCard,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
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
        )?
        .commit_point();

    Ok(if with_etag { batch.etag() } else { None })
}

pub(crate) fn insert_card(
    access_token: &AccessToken,
    mut card: ContactCard,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
    // Build card
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
        )?
        .commit_point();

    Ok(if with_etag { batch.etag() } else { None })
}

pub(crate) fn update_addressbook(
    access_token: &AccessToken,
    book: Archive<&ArchivedAddressBook>,
    mut new_book: AddressBook,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
    // Build card
    new_book.modified = now() as i64;

    // Prepare write batch
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::AddressBook)
        .update_document(document_id)
        .custom(
            ObjectIndexBuilder::new()
                .with_current(book)
                .with_changes(new_book)
                .with_tenant_id(access_token),
        )?
        .commit_point();

    Ok(if with_etag { batch.etag() } else { None })
}
