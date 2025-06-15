/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    calendar::{Calendar, CalendarEvent, CalendarPreferences},
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use calcard::{
    build_calcard_resources, build_simple_hierarchy, resource_from_addressbook,
    resource_from_calendar, resource_from_card, resource_from_event,
};
use common::{CacheSwap, DavResource, DavResources, Server, auth::AccessToken};
use file::{build_file_resources, build_nested_hierarchy, resource_from_file};
use jmap_proto::types::collection::{Collection, SyncCollection};
use std::{sync::Arc, time::Instant};
use store::{
    ahash::AHashMap,
    query::log::{Change, Query},
    write::{AlignedBytes, Archive, BatchBuilder},
};
use tokio::sync::Semaphore;
use trc::{AddContext, StoreEvent};

pub mod calcard;
pub mod file;

pub trait GroupwareCache: Sync + Send {
    fn fetch_dav_resources(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<Arc<DavResources>>> + Send;

    fn create_default_addressbook(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn create_default_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<DavResources>>;
}

impl GroupwareCache for Server {
    async fn fetch_dav_resources(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: SyncCollection,
    ) -> trc::Result<Arc<DavResources>> {
        let cache_store = match collection {
            SyncCollection::Calendar => &self.inner.cache.events,
            SyncCollection::AddressBook => &self.inner.cache.contacts,
            SyncCollection::FileNode => &self.inner.cache.files,
            _ => unreachable!(),
        };
        let cache_ = match cache_store.get_value_or_guard_async(&account_id).await {
            Ok(cache) => cache,
            Err(guard) => {
                let start_time = Instant::now();
                let cache = full_cache_build(
                    self,
                    account_id,
                    collection,
                    Arc::new(Semaphore::new(1)),
                    access_token,
                )
                .await?;

                if guard.insert(CacheSwap::new(cache.clone())).is_err() {
                    cache_store.insert(account_id, CacheSwap::new(cache.clone()));
                }

                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    AccountId = account_id,
                    Collection = collection.as_str(),
                    Total = cache.resources.len(),
                    ChangeId = cache.highest_change_id,
                    Elapsed = start_time.elapsed(),
                );

                return Ok(cache);
            }
        };

        // Obtain current state
        let cache = cache_.load_full();
        let start_time = Instant::now();
        let changes = self
            .core
            .storage
            .data
            .changes(
                account_id,
                collection,
                Query::Since(cache.highest_change_id),
            )
            .await
            .caused_by(trc::location!())?;

        // Regenerate cache if the change log has been truncated
        if changes.is_truncated {
            let cache = full_cache_build(
                self,
                account_id,
                collection,
                cache.update_lock.clone(),
                access_token,
            )
            .await?;
            cache_.update(cache.clone());

            trc::event!(
                Store(StoreEvent::CacheStale),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Total = cache.resources.len(),
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Verify changes
        if changes.changes.is_empty() {
            trc::event!(
                Store(StoreEvent::CacheHit),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Lock for updates
        let _permit = cache.update_lock.acquire().await;
        let cache = cache_.load_full();
        if cache.highest_change_id >= changes.to_change_id {
            trc::event!(
                Store(StoreEvent::CacheHit),
                AccountId = account_id,
                Collection = collection.as_str(),
                ChangeId = cache.highest_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        let mut updated_resources = AHashMap::with_capacity(8);
        let has_no_children = collection == SyncCollection::FileNode;
        let num_changes = changes.changes.len();

        for change in changes.changes {
            match change {
                Change::InsertItem(id) | Change::UpdateItem(id) => {
                    let document_id = id as u32;
                    if let Some(archive) = self
                        .get_archive(account_id, collection.collection(false), document_id)
                        .await
                        .caused_by(trc::location!())?
                    {
                        updated_resources.insert(
                            (has_no_children, document_id),
                            Some(resource_from_archive(
                                archive,
                                document_id,
                                collection,
                                false,
                            )?),
                        );
                    } else {
                        updated_resources.insert((has_no_children, document_id), None);
                    }
                }
                Change::DeleteItem(id) => {
                    updated_resources.insert((has_no_children, id as u32), None);
                }
                Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                    let document_id = id as u32;
                    if let Some(archive) = self
                        .get_archive(account_id, collection.collection(true), document_id)
                        .await
                        .caused_by(trc::location!())?
                    {
                        updated_resources.insert(
                            (true, document_id),
                            Some(resource_from_archive(
                                archive,
                                document_id,
                                collection,
                                true,
                            )?),
                        );
                    } else {
                        updated_resources.insert((true, document_id), None);
                    }
                }
                Change::DeleteContainer(id) => {
                    updated_resources.insert((true, id as u32), None);
                }
                Change::UpdateContainerProperty(_) => (),
            }
        }

        let mut rebuild_hierarchy = false;
        let mut resources = Vec::with_capacity(cache.resources.len());

        for resource in &cache.resources {
            let is_container = has_no_children || resource.is_container();
            if let Some(updated_resource) =
                updated_resources.remove(&(is_container, resource.document_id))
            {
                if let Some(updated_resource) = updated_resource {
                    rebuild_hierarchy =
                        rebuild_hierarchy || updated_resource.has_hierarchy_changes(resource);
                    resources.push(updated_resource);
                } else {
                    // Deleted resource
                    rebuild_hierarchy = true;
                }
            } else {
                resources.push(resource.clone());
            }
        }

        // Add new resources
        for resource in updated_resources.into_values().flatten() {
            resources.push(resource);
            rebuild_hierarchy = true;
        }

        let cache = if rebuild_hierarchy {
            let mut cache = DavResources {
                base_path: cache.base_path.clone(),
                paths: Default::default(),
                resources,
                item_change_id: changes.item_change_id.unwrap_or(cache.item_change_id),
                container_change_id: changes
                    .container_change_id
                    .unwrap_or(cache.container_change_id),
                highest_change_id: changes.to_change_id,
                size: std::mem::size_of::<DavResources>() as u64,
                update_lock: cache.update_lock.clone(),
            };

            if matches!(collection, SyncCollection::FileNode) {
                build_nested_hierarchy(&mut cache);
            } else {
                build_simple_hierarchy(&mut cache);
            }
            cache
        } else {
            DavResources {
                base_path: cache.base_path.clone(),
                paths: cache.paths.clone(),
                resources,
                item_change_id: changes.item_change_id.unwrap_or(cache.item_change_id),
                container_change_id: changes
                    .container_change_id
                    .unwrap_or(cache.container_change_id),
                highest_change_id: changes.to_change_id,
                size: cache.size,
                update_lock: cache.update_lock.clone(),
            }
        };

        let cache = Arc::new(cache);
        cache_.update(cache.clone());

        trc::event!(
            Store(StoreEvent::CacheUpdate),
            AccountId = account_id,
            Collection = collection.as_str(),
            ChangeId = cache.highest_change_id,
            Details = num_changes,
            Total = cache.resources.len(),
            Elapsed = start_time.elapsed(),
        );

        Ok(cache)
    }

    async fn create_default_addressbook(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<()> {
        if let Some(name) = &self.core.groupware.default_addressbook_name {
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::AddressBook, 1)
                .await?;
            AddressBook {
                name: name.clone(),
                display_name: self.core.groupware.default_addressbook_display_name.clone(),
                is_default: true,
                ..Default::default()
            }
            .insert(access_token, account_id, document_id, &mut batch)?;
            self.commit_batch(batch).await?;
        }

        Ok(())
    }

    async fn create_default_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<()> {
        if let Some(name) = &self.core.groupware.default_calendar_name {
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::Calendar, 3)
                .await?;
            Calendar {
                name: name.clone(),
                preferences: vec![CalendarPreferences {
                    account_id,
                    name: self
                        .core
                        .groupware
                        .default_calendar_display_name
                        .clone()
                        .unwrap_or_else(|| name.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .insert(access_token, account_id, document_id, &mut batch)?;
            self.commit_batch(batch).await?;
        }

        Ok(())
    }

    fn cached_dav_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<DavResources>> {
        (match collection {
            SyncCollection::Calendar => &self.inner.cache.events,
            SyncCollection::AddressBook => &self.inner.cache.contacts,
            SyncCollection::FileNode => &self.inner.cache.files,
            _ => unreachable!(),
        })
        .get(&account_id)
        .map(|cache| cache.load_full())
    }
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    collection: SyncCollection,
    update_lock: Arc<Semaphore>,
    access_token: &AccessToken,
) -> trc::Result<Arc<DavResources>> {
    match collection {
        SyncCollection::Calendar => {
            build_calcard_resources(
                server,
                access_token,
                account_id,
                SyncCollection::Calendar,
                Collection::Calendar,
                Collection::CalendarEvent,
                update_lock,
            )
            .await
        }
        SyncCollection::AddressBook => {
            build_calcard_resources(
                server,
                access_token,
                account_id,
                SyncCollection::AddressBook,
                Collection::AddressBook,
                Collection::ContactCard,
                update_lock,
            )
            .await
        }
        SyncCollection::FileNode => build_file_resources(server, account_id, update_lock).await,
        _ => unreachable!(),
    }
    .map(Arc::new)
}

fn resource_from_archive(
    archive: Archive<AlignedBytes>,
    document_id: u32,
    collection: SyncCollection,
    is_container: bool,
) -> trc::Result<DavResource> {
    Ok(match collection {
        SyncCollection::Calendar => {
            if is_container {
                resource_from_calendar(
                    archive
                        .unarchive::<Calendar>()
                        .caused_by(trc::location!())?,
                    document_id,
                )
            } else {
                resource_from_event(
                    archive
                        .unarchive::<CalendarEvent>()
                        .caused_by(trc::location!())?,
                    document_id,
                )
            }
        }
        SyncCollection::AddressBook => {
            if is_container {
                resource_from_addressbook(
                    archive
                        .unarchive::<AddressBook>()
                        .caused_by(trc::location!())?,
                    document_id,
                )
            } else {
                resource_from_card(
                    archive
                        .unarchive::<ContactCard>()
                        .caused_by(trc::location!())?,
                    document_id,
                )
            }
        }
        SyncCollection::FileNode => resource_from_file(
            archive
                .unarchive::<FileNode>()
                .caused_by(trc::location!())?,
            document_id,
        ),
        _ => unreachable!(),
    })
}
