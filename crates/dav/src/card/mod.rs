/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DavResources, Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use dav_proto::schema::{
    property::{CardDavProperty, DavProperty, WebDavProperty},
    response::CardCondition,
};
use groupware::{
    IDX_CARD_UID,
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
};
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::{
    query::Filter,
    write::{Archive, BatchBuilder, now},
};
use trc::AddContext;

use crate::{DavError, DavErrorCondition, common::ExtractETag};

pub mod copy_move;
pub mod delete;
pub mod get;
pub mod mkcol;
pub mod proppatch;
pub mod query;
pub mod update;

pub(crate) static CARD_CONTAINER_PROPS: [DavProperty; 23] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
    DavProperty::CardDav(CardDavProperty::SupportedAddressData),
    DavProperty::CardDav(CardDavProperty::SupportedCollationSet),
    DavProperty::CardDav(CardDavProperty::MaxResourceSize),
];

pub(crate) static CARD_ITEM_PROPS: [DavProperty; 20] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::CardDav(CardDavProperty::AddressData(vec![])),
];

pub(crate) static CARD_ALL_PROPS: [DavProperty; 22] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::CardDav(CardDavProperty::AddressData(vec![])),
    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
    DavProperty::CardDav(CardDavProperty::SupportedAddressData),
    DavProperty::CardDav(CardDavProperty::SupportedCollationSet),
    DavProperty::CardDav(CardDavProperty::MaxResourceSize),
];

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

pub(crate) fn insert_addressbook(
    access_token: &AccessToken,
    mut book: AddressBook,
    account_id: u32,
    document_id: u32,
    with_etag: bool,
    batch: &mut BatchBuilder,
) -> trc::Result<Option<String>> {
    // Build card
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

pub(crate) async fn assert_is_unique_uid(
    server: &Server,
    resources: &DavResources,
    account_id: u32,
    addressbook_id: u32,
    uid: Option<&str>,
    base_uri: &str,
) -> crate::Result<()> {
    if let Some(uid) = uid {
        let hits = server
            .store()
            .filter(
                account_id,
                Collection::ContactCard,
                vec![Filter::eq(IDX_CARD_UID, uid.as_bytes().to_vec())],
            )
            .await
            .caused_by(trc::location!())?;
        if !hits.results.is_empty() {
            for path in resources.paths.iter() {
                if !path.is_container
                    && hits.results.contains(path.document_id)
                    && path.parent_id.unwrap() == addressbook_id
                {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CardCondition::NoUidConflict(format!("{}/{}", base_uri, path.name).into()),
                    )));
                }
            }
        }
    }

    Ok(())
}
