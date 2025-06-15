/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::hash_map::Entry, sync::Arc, time::Instant};

use common::{CacheSwap, MessageStoreCache, Server};
use email::{full_email_cache_build, update_email_cache};
use jmap_proto::types::collection::SyncCollection;
use mailbox::{full_mailbox_cache_build, update_mailbox_cache};
use store::{
    ahash::AHashMap,
    query::log::{Change, Query},
};
use tokio::sync::Semaphore;
use trc::{AddContext, StoreEvent};

pub mod email;
pub mod mailbox;

pub trait MessageCacheFetch: Sync + Send {
    fn get_cached_messages(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<MessageStoreCache>>> + Send;
}

impl MessageCacheFetch for Server {
    async fn get_cached_messages(&self, account_id: u32) -> trc::Result<Arc<MessageStoreCache>> {
        let cache_ = match self
            .inner
            .cache
            .messages
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(cache) => cache,
            Err(guard) => {
                let start_time = Instant::now();
                let cache = full_cache_build(self, account_id, Arc::new(Semaphore::new(1))).await?;

                if guard.insert(CacheSwap::new(cache.clone())).is_err() {
                    self.inner
                        .cache
                        .messages
                        .insert(account_id, CacheSwap::new(cache.clone()));
                }

                trc::event!(
                    Store(StoreEvent::CacheMiss),
                    AccountId = account_id,
                    Collection = SyncCollection::Email.as_str(),
                    Total = vec![cache.emails.items.len(), cache.mailboxes.items.len()],
                    ChangeId = cache.last_change_id,
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
                SyncCollection::Email,
                Query::Since(cache.last_change_id),
            )
            .await
            .caused_by(trc::location!())?;

        // Regenerate cache if the change log has been truncated
        if changes.is_truncated {
            let cache = full_cache_build(self, account_id, cache.update_lock.clone()).await?;
            cache_.update(cache.clone());

            trc::event!(
                Store(StoreEvent::CacheStale),
                AccountId = account_id,
                Collection = SyncCollection::Email.as_str(),
                ChangeId = cache.last_change_id,
                Total = vec![cache.emails.items.len(), cache.mailboxes.items.len()],
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Verify changes
        if changes.changes.is_empty() {
            trc::event!(
                Store(StoreEvent::CacheHit),
                AccountId = account_id,
                Collection = SyncCollection::Email.as_str(),
                ChangeId = cache.last_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache);
        }

        // Lock for updates
        let _permit = cache.update_lock.acquire().await;
        let cache = cache_.0.load();
        let mut cache = if cache.last_change_id >= changes.to_change_id {
            trc::event!(
                Store(StoreEvent::CacheHit),
                AccountId = account_id,
                Collection = SyncCollection::Email.as_str(),
                ChangeId = cache.last_change_id,
                Elapsed = start_time.elapsed(),
            );

            return Ok(cache.clone());
        } else {
            cache.as_ref().clone()
        };

        let mut changed_items: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());
        let mut changed_containers: AHashMap<u32, bool> =
            AHashMap::with_capacity(changes.changes.len());

        for change in changes.changes {
            match change {
                Change::InsertItem(id) => match changed_items.entry(id as u32) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = true;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(true);
                    }
                },
                Change::UpdateItem(id) => {
                    changed_items.insert(id as u32, true);
                }
                Change::DeleteItem(id) => {
                    match changed_items.entry(id as u32) {
                        Entry::Occupied(mut entry) => {
                            // Thread reassignment
                            *entry.get_mut() = true;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(false);
                        }
                    }
                }
                Change::InsertContainer(id) | Change::UpdateContainer(id) => {
                    changed_containers.insert(id as u32, true);
                }
                Change::DeleteContainer(id) => {
                    changed_containers.insert(id as u32, false);
                }
                Change::UpdateContainerProperty(_) => (),
            }
        }

        if !changed_items.is_empty() {
            let mut email_cache =
                update_email_cache(self, account_id, &changed_items, &cache).await?;
            email_cache.change_id = changes.item_change_id.unwrap_or(changes.to_change_id);
            cache.emails = Arc::new(email_cache);
        }

        if !changed_containers.is_empty() {
            let mut mailbox_cache =
                update_mailbox_cache(self, account_id, &changed_containers, &cache).await?;
            mailbox_cache.change_id = changes.container_change_id.unwrap_or(changes.to_change_id);
            cache.mailboxes = Arc::new(mailbox_cache);
        }
        cache.size = cache.emails.size + cache.mailboxes.size;
        cache.last_change_id = changes.to_change_id;

        let cache = Arc::new(cache);
        cache_.update(cache.clone());

        trc::event!(
            Store(StoreEvent::CacheUpdate),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            ChangeId = cache.last_change_id,
            Details = vec![changed_items.len(), changed_containers.len()],
            Total = vec![cache.emails.items.len(), cache.mailboxes.items.len()],
            Elapsed = start_time.elapsed(),
        );

        Ok(cache)
    }
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<Arc<MessageStoreCache>> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::Email)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let mut emails = full_email_cache_build(server, account_id).await?;
    let mut mailboxes = full_mailbox_cache_build(server, account_id).await?;
    let size = emails.size + mailboxes.size;
    emails.change_id = last_change_id;
    mailboxes.change_id = last_change_id;

    Ok(Arc::new(MessageStoreCache {
        update_lock,
        emails: Arc::new(emails),
        mailboxes: Arc::new(mailboxes),
        last_change_id,
        size,
    }))
}
