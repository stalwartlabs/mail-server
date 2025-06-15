/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::IDX_UID;
use common::{DavResources, Server};
use dav_proto::schema::{
    property::{CardDavProperty, DavProperty, WebDavProperty},
    response::CardCondition,
};
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use store::query::Filter;
use trc::AddContext;

use crate::{DavError, DavErrorCondition};

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

pub(crate) async fn assert_is_unique_uid(
    server: &Server,
    resources: &DavResources,
    account_id: u32,
    addressbook_id: u32,
    uid: Option<&str>,
) -> crate::Result<()> {
    if let Some(uid) = uid {
        let hits = server
            .store()
            .filter(
                account_id,
                Collection::ContactCard,
                vec![Filter::eq(IDX_UID, uid.as_bytes().to_vec())],
            )
            .await
            .caused_by(trc::location!())?;
        if !hits.results.is_empty() {
            for path in resources.children(addressbook_id) {
                if hits.results.contains(path.document_id()) {
                    return Err(DavError::Condition(DavErrorCondition::new(
                        StatusCode::PRECONDITION_FAILED,
                        CardCondition::NoUidConflict(resources.format_resource(path).into()),
                    )));
                }
            }
        }
    }

    Ok(())
}
