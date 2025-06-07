/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::GroupwareCache;
use crate::{
    DavResourceName, RFC_3986,
    calendar::{ArchivedCalendar, ArchivedCalendarEvent, Calendar, CalendarEvent},
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
};
use calcard::common::timezone::Tz;
use common::{
    DavName, DavPath, DavResource, DavResourceMetadata, DavResources, Server, auth::AccessToken,
};
use directory::backend::internal::manage::ManageDirectory;
use jmap_proto::types::{
    collection::{Collection, SyncCollection},
    value::AclGrant,
};
use std::sync::Arc;
use store::ahash::{AHashMap, AHashSet};
use tokio::sync::Semaphore;
use trc::AddContext;
use utils::map::bitmap::Bitmap;

pub(super) async fn build_calcard_resources(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    sync_collection: SyncCollection,
    container_collection: Collection,
    item_collection: Collection,
    update_lock: Arc<Semaphore>,
) -> trc::Result<DavResources> {
    let mut last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, sync_collection)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    // Create default folders
    let is_calendar = matches!(sync_collection, SyncCollection::Calendar);
    let mut container_ids = server
        .get_document_ids(account_id, container_collection)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    if container_ids.is_empty() {
        if is_calendar {
            server
                .create_default_calendar(access_token, account_id)
                .await?
        } else {
            server
                .create_default_addressbook(access_token, account_id)
                .await?
        }
        last_change_id = server
            .core
            .storage
            .data
            .get_last_change_id(account_id, sync_collection)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();

        container_ids = server
            .get_document_ids(account_id, container_collection)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
    }
    let item_ids = server
        .get_document_ids(account_id, item_collection)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));

    let mut cache = DavResources {
        base_path: format!(
            "{}/{}/",
            if is_calendar {
                DavResourceName::Cal
            } else {
                DavResourceName::Card
            }
            .base_path(),
            percent_encoding::utf8_percent_encode(&name, RFC_3986),
        ),
        paths: AHashSet::with_capacity((container_ids.len() + item_ids.len()) as usize),
        resources: Vec::with_capacity((container_ids.len() + item_ids.len()) as usize),
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        size: std::mem::size_of::<DavResources>() as u64,
        update_lock,
    };

    for document_id in container_ids {
        if let Some(archive) = server
            .get_archive(account_id, container_collection, document_id)
            .await
            .caused_by(trc::location!())?
        {
            let resource = if is_calendar {
                resource_from_calendar(archive.unarchive::<Calendar>()?, document_id)
            } else {
                resource_from_addressbook(archive.unarchive::<AddressBook>()?, document_id)
            };
            let path = DavPath {
                path: resource.container_name().unwrap().to_string(),
                parent_id: None,
                hierarchy_seq: 1,
                resource_idx: cache.resources.len(),
            };

            cache.size += (std::mem::size_of::<DavPath>()
                + std::mem::size_of::<DavResource>()
                + (path.path.len()) * 2) as u64;
            cache.paths.insert(path);
            cache.resources.push(resource);
        }
    }
    let parent_range = cache.resources.len();

    for document_id in item_ids {
        if let Some(archive) = server
            .get_archive(account_id, item_collection, document_id)
            .await
            .caused_by(trc::location!())?
        {
            let resource = if is_calendar {
                resource_from_event(archive.unarchive::<CalendarEvent>()?, document_id)
            } else {
                resource_from_card(archive.unarchive::<ContactCard>()?, document_id)
            };
            let resource_idx = cache.resources.len();

            for name in resource.child_names().unwrap_or_default().iter() {
                if let Some(parent) = cache.resources.get(..parent_range).and_then(|resources| {
                    resources.iter().find(|r| r.document_id == name.parent_id)
                }) {
                    let path = DavPath {
                        path: format!("{}/{}", parent.container_name().unwrap(), name.name),
                        parent_id: Some(name.parent_id),
                        hierarchy_seq: 0,
                        resource_idx,
                    };

                    cache.size +=
                        (std::mem::size_of::<DavPath>() + name.name.len() + path.path.len()) as u64;
                    cache.paths.insert(path);
                }
            }
            cache.size += std::mem::size_of::<DavResource>() as u64;
            cache.resources.push(resource);
        }
    }

    Ok(cache)
}

pub(super) fn build_simple_hierarchy(cache: &mut DavResources) {
    cache.paths = AHashSet::with_capacity(cache.resources.len());
    let name_idx = cache
        .resources
        .iter()
        .filter_map(|resource| {
            resource
                .container_name()
                .map(|name| (resource.document_id, name))
        })
        .collect::<AHashMap<_, _>>();

    for (resource_idx, resource) in cache.resources.iter().enumerate() {
        match &resource.data {
            DavResourceMetadata::Calendar { name, .. }
            | DavResourceMetadata::AddressBook { name, .. } => {
                let path = DavPath {
                    path: name.to_string(),
                    parent_id: None,
                    hierarchy_seq: 1,
                    resource_idx,
                };
                cache.size +=
                    (std::mem::size_of::<DavPath>() + name.len() + path.path.len()) as u64;
                cache.paths.insert(path);
            }
            DavResourceMetadata::CalendarEvent { names, .. }
            | DavResourceMetadata::ContactCard { names } => {
                for name in names {
                    if let Some(parent_name) = name_idx.get(&name.parent_id) {
                        let path = DavPath {
                            path: format!("{parent_name}/{}", name.name),
                            parent_id: Some(name.parent_id),
                            hierarchy_seq: 1,
                            resource_idx,
                        };
                        cache.size += (std::mem::size_of::<DavPath>()
                            + name.name.len()
                            + path.path.len()) as u64;
                        cache.paths.insert(path);
                    }
                }
            }
            _ => unreachable!(),
        }
        cache.size += std::mem::size_of::<DavResource>() as u64;
    }
}

pub(super) fn resource_from_calendar(calendar: &ArchivedCalendar, document_id: u32) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::Calendar {
            name: calendar.name.to_string(),
            acls: calendar
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
            tz: calendar
                .preferences
                .first()
                .and_then(|pref| pref.time_zone.tz())
                .unwrap_or(Tz::UTC),
        },
    }
}

pub(super) fn resource_from_event(event: &ArchivedCalendarEvent, document_id: u32) -> DavResource {
    let (start, duration) = event.data.event_range().unwrap_or_default();
    DavResource {
        document_id,
        data: DavResourceMetadata::CalendarEvent {
            names: event
                .names
                .iter()
                .map(|name| DavName {
                    name: name.name.to_string(),
                    parent_id: name.parent_id.to_native(),
                })
                .collect(),
            start,
            duration,
        },
    }
}

pub(super) fn resource_from_addressbook(
    book: &ArchivedAddressBook,
    document_id: u32,
) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::AddressBook {
            name: book.name.to_string(),
            acls: book
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
        },
    }
}

pub(super) fn resource_from_card(card: &ArchivedContactCard, document_id: u32) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::ContactCard {
            names: card
                .names
                .iter()
                .map(|name| DavName {
                    name: name.name.to_string(),
                    parent_id: name.parent_id.to_native(),
                })
                .collect(),
        },
    }
}
