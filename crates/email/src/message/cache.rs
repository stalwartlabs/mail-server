/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{
    CacheSwap, MailboxCache, MessageItemCache, MessageStoreCache, MessageUidCache, Server,
    auth::AccessToken, sharing::EffectiveAcl,
};
use jmap_proto::types::{acl::Acl, collection::Collection, keyword::Keyword};
use std::future::Future;
use store::{
    ahash::{AHashMap, AHashSet},
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use tokio::sync::Semaphore;
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use super::metadata::{ArchivedMessageData, MessageData};

pub trait MessageCache: Sync + Send {
    fn get_cached_messages(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<MessageStoreCache<MessageItemCache>>>> + Send;
}

impl MessageCache for Server {
    async fn get_cached_messages(
        &self,
        account_id: u32,
    ) -> trc::Result<Arc<MessageStoreCache<MessageItemCache>>> {
        let cache_ = match self
            .inner
            .cache
            .messages
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(cache) => cache,
            Err(guard) => {
                let cache = full_cache_build(self, account_id, Arc::new(Semaphore::new(1))).await?;
                if guard.insert(CacheSwap::new(cache.clone())).is_err() {
                    self.inner
                        .cache
                        .messages
                        .insert(account_id, CacheSwap::new(cache.clone()));
                }
                return Ok(cache);
            }
        };

        // Perform full refresh on stale ids
        let cache = cache_.load_full();
        if cache.change_id > 0
            && self
                .core
                .jmap
                .changes_max_history
                .and_then(|history| self.inner.data.jmap_id_gen.past_id(history))
                .is_some_and(|last_change_id| cache.change_id < last_change_id)
        {
            let cache = full_cache_build(self, account_id, cache.update_lock.clone()).await?;
            cache_.update(cache.clone());
            return Ok(cache);
        }

        // Obtain current state
        let changes = self
            .core
            .storage
            .data
            .changes(account_id, Collection::Email, Query::Since(cache.change_id))
            .await
            .caused_by(trc::location!())?;

        // Verify changes
        if changes.changes.is_empty() {
            return Ok(cache);
        }

        // Lock for updates
        let _permit = cache.update_lock.acquire().await;
        let cache = cache_.load_full();
        if cache.change_id >= changes.to_change_id {
            return Ok(cache);
        }

        let mut cache = cache.as_ref().clone();
        cache.change_id = changes.to_change_id;
        let mut delete = AHashSet::with_capacity(changes.changes.len() / 2);
        let mut update = AHashMap::with_capacity(changes.changes.len());

        for change in changes.changes {
            match change {
                Change::Insert(id) => {
                    if let Some(item) = cache.items.get_mut(&(id as u32)) {
                        item.thread_id = (id >> 32) as u32;
                    }
                    update.insert(id as u32, true);
                }
                Change::Update(id) | Change::ChildUpdate(id) => {
                    update.insert(id as u32, false);
                }
                Change::Delete(id) => {
                    delete.insert(id as u32);
                }
            }
        }

        for document_id in delete {
            if update.remove(&document_id).is_none() {
                if let Some(item) = cache.items.remove(&document_id) {
                    cache.size -= (std::mem::size_of::<MessageItemCache>()
                        + std::mem::size_of::<u32>()
                        + (item.mailboxes.len() * std::mem::size_of::<MessageUidCache>()))
                        as u64;
                }
            }
        }

        for (document_id, is_insert) in update {
            if let Some(archive) = self
                .get_archive(account_id, Collection::Email, document_id)
                .await
                .caused_by(trc::location!())?
            {
                let message = archive.unarchive::<MessageData>()?;
                insert_item(&mut cache, document_id, message, is_insert);
            }
        }

        let cache = Arc::new(cache);
        cache_.update(cache.clone());

        Ok(cache)
    }
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<Arc<MessageStoreCache<MessageItemCache>>> {
    // Build cache
    let mut cache = MessageStoreCache {
        items: AHashMap::with_capacity(16),
        size: 0,
        change_id: 0,
        update_lock,
    };

    server
        .get_archives(
            account_id,
            Collection::Email,
            &(),
            |document_id, archive| {
                let message = archive.unarchive::<MessageData>()?;
                cache.change_id = std::cmp::max(cache.change_id, message.change_id.to_native());

                insert_item(&mut cache, document_id, message, true);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(Arc::new(cache))
}

fn insert_item(
    cache: &mut MessageStoreCache<MessageItemCache>,
    document_id: u32,
    message: &ArchivedMessageData,
    update_size: bool,
) {
    let item = MessageItemCache {
        mailboxes: message
            .mailboxes
            .iter()
            .map(|m| MessageUidCache {
                mailbox_id: m.mailbox_id.to_native(),
                uid: m.uid.to_native(),
            })
            .collect(),
        keywords: message.keywords.iter().map(Into::into).collect(),
        thread_id: message.thread_id.to_native(),
        change_id: message.change_id.to_native(),
    };

    if update_size {
        cache.size += (std::mem::size_of::<MessageItemCache>()
            + std::mem::size_of::<u32>()
            + (item.mailboxes.len() * std::mem::size_of::<MessageUidCache>()))
            as u64;
    }
    cache.items.insert(document_id, item);
}

pub trait MessageCacheAccess {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = (&u32, &MessageItemCache)>;

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = (&u32, &MessageItemCache)>;

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = (&u32, &MessageItemCache)>;

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = (&u32, &MessageItemCache)>;

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = (&u32, &MessageItemCache)>;

    fn document_ids(&self) -> RoaringBitmap;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        mailboxes: &MessageStoreCache<MailboxCache>,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;
}

impl MessageCacheAccess for MessageStoreCache<MessageItemCache> {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = (&u32, &MessageItemCache)> {
        self.items
            .iter()
            .filter(move |(_, m)| m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id))
    }

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = (&u32, &MessageItemCache)> {
        self.items
            .iter()
            .filter(move |(_, m)| m.thread_id == thread_id)
    }

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = (&u32, &MessageItemCache)> {
        self.items
            .iter()
            .filter(move |(_, m)| m.keywords.contains(keyword))
    }

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = (&u32, &MessageItemCache)> {
        self.items.iter().filter(move |(_, m)| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id) && m.keywords.contains(keyword)
        })
    }

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = (&u32, &MessageItemCache)> {
        self.items.iter().filter(move |(_, m)| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id) && !m.keywords.contains(keyword)
        })
    }

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        mailboxes: &MessageStoreCache<MailboxCache>,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();
        let mut shared_messages = RoaringBitmap::new();
        for (mailbox_id, mailbox) in &mailboxes.items {
            if mailbox
                .acls
                .as_slice()
                .effective_acl(access_token)
                .contains_all(check_acls)
            {
                shared_messages.extend(self.in_mailbox(*mailbox_id).map(|(id, _)| *id));
            }
        }
        shared_messages
    }

    fn document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_iter(self.items.keys())
    }
}
