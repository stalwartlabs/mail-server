/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::metadata::{ArchivedMessageData, MessageData};
use common::{
    CacheSwap, MailboxStoreCache, MessageCache, MessageStoreCache, MessageUidCache, Server,
    auth::AccessToken, sharing::EffectiveAcl,
};
use compact_str::CompactString;
use jmap_proto::types::{
    acl::Acl,
    collection::Collection,
    keyword::{Keyword, OTHER},
};
use std::sync::Arc;
use std::{collections::hash_map::Entry, future::Future};
use store::{
    ahash::AHashMap,
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use tokio::sync::Semaphore;
use trc::AddContext;
use utils::map::bitmap::Bitmap;

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

        let mut new_cache = MessageStoreCache {
            index: AHashMap::with_capacity(cache.items.len()),
            items: Vec::with_capacity(cache.items.len()),
            size: 0,
            change_id: changes.to_change_id,
            update_lock: cache.update_lock.clone(),
            keywords: cache.keywords.clone(),
        };
        let mut changed_ids: AHashMap<u32, bool> = AHashMap::with_capacity(changes.changes.len());

        for change in changes.changes {
            match change {
                Change::Insert(id) => match changed_ids.entry(id as u32) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = true;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(true);
                    }
                },
                Change::Update(id) => {
                    changed_ids.insert(id as u32, true);
                }
                Change::Delete(id) => {
                    match changed_ids.entry(id as u32) {
                        Entry::Occupied(mut entry) => {
                            // Thread reassignment
                            *entry.get_mut() = true;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(false);
                        }
                    }
                }
            }
        }

        for (document_id, is_update) in &changed_ids {
            if *is_update {
                if let Some(archive) = self
                    .get_archive(account_id, Collection::Email, *document_id)
                    .await
                    .caused_by(trc::location!())?
                {
                    insert_item(
                        &mut new_cache,
                        *document_id,
                        archive.unarchive::<MessageData>()?,
                    );
                }
            }
        }

        for item in &cache.items {
            if !changed_ids.contains_key(&item.document_id) {
                new_cache.insert(item.clone());
            }
        }

        if cache.items.len() > new_cache.items.len() {
            new_cache.items.shrink_to_fit();
            new_cache.index.shrink_to_fit();
        }
        if cache.keywords.len() > new_cache.keywords.len() {
            new_cache.keywords.shrink_to_fit();
        }

        let cache = Arc::new(new_cache);
        cache_.update(cache.clone());

        Ok(cache)
    }
}

async fn full_cache_build(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<Arc<MessageStoreCache>> {
    // Build cache
    let mut cache = MessageStoreCache {
        items: Vec::with_capacity(16),
        index: AHashMap::with_capacity(16),
        keywords: Vec::new(),
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

                insert_item(&mut cache, document_id, message);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(Arc::new(cache))
}

fn insert_item(cache: &mut MessageStoreCache, document_id: u32, message: &ArchivedMessageData) {
    let mut item = MessageCache {
        mailboxes: message
            .mailboxes
            .iter()
            .map(|m| MessageUidCache {
                mailbox_id: m.mailbox_id.to_native(),
                uid: m.uid.to_native(),
            })
            .collect(),
        keywords: 0,
        thread_id: message.thread_id.to_native(),
        change_id: message.change_id.to_native(),
        document_id,
    };
    for keyword in message.keywords.iter() {
        match keyword.id() {
            Ok(id) => {
                item.keywords |= 1 << id;
            }
            Err(custom) => {
                if let Some(idx) = cache.keywords.iter().position(|k| k == custom) {
                    item.keywords |= 1 << (OTHER + idx);
                } else if cache.keywords.len() < (128 - OTHER) {
                    cache.keywords.push(CompactString::from(custom));
                    item.keywords |= 1 << (OTHER + cache.keywords.len() - 1);
                }
            }
        }
    }

    cache.insert(item);
}

pub trait MessageCacheAccess {
    fn by_id(&self, id: &u32) -> Option<&MessageCache>;

    fn has_id(&self, id: &u32) -> bool;

    fn by_id_mut(&mut self, id: &u32) -> Option<&mut MessageCache>;

    fn insert(&mut self, item: MessageCache);

    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache>;

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache>;

    fn document_ids(&self) -> RoaringBitmap;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        mailboxes: &MailboxStoreCache,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword>;

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool;
}

impl MessageCacheAccess for MessageStoreCache {
    fn in_mailbox(&self, mailbox_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.items
            .iter()
            .filter(move |m| m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id))
    }

    fn in_thread(&self, thread_id: u32) -> impl Iterator<Item = &MessageCache> {
        self.items.iter().filter(move |m| m.thread_id == thread_id)
    }

    fn with_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.items
            .iter()
            .filter(move |m| keyword_id.is_some_and(|id| m.keywords & (1 << id) != 0))
    }

    fn without_keyword(&self, keyword: &Keyword) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.items
            .iter()
            .filter(move |m| keyword_id.is_none_or(|id| m.keywords & (1 << id) == 0))
    }

    fn in_mailbox_with_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
                && keyword_id.is_some_and(|id| m.keywords & (1 << id) != 0)
        })
    }

    fn in_mailbox_without_keyword(
        &self,
        mailbox_id: u32,
        keyword: &Keyword,
    ) -> impl Iterator<Item = &MessageCache> {
        let keyword_id = keyword_to_id(self, keyword);
        self.items.iter().filter(move |m| {
            m.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
                && keyword_id.is_none_or(|id| m.keywords & (1 << id) == 0)
        })
    }

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        mailboxes: &MailboxStoreCache,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();
        let mut shared_messages = RoaringBitmap::new();
        for mailbox in &mailboxes.items {
            if mailbox
                .acls
                .as_slice()
                .effective_acl(access_token)
                .contains_all(check_acls)
            {
                shared_messages.extend(
                    self.in_mailbox(mailbox.document_id)
                        .map(|item| item.document_id),
                );
            }
        }
        shared_messages
    }

    fn document_ids(&self) -> RoaringBitmap {
        RoaringBitmap::from_iter(self.index.keys())
    }

    fn by_id(&self, id: &u32) -> Option<&MessageCache> {
        self.index
            .get(id)
            .and_then(|idx| self.items.get(*idx as usize))
    }

    fn by_id_mut(&mut self, id: &u32) -> Option<&mut MessageCache> {
        self.index
            .get(id)
            .and_then(|idx| self.items.get_mut(*idx as usize))
    }

    fn insert(&mut self, item: MessageCache) {
        let id = item.document_id;
        if let Some(idx) = self.index.get(&id) {
            self.items[*idx as usize] = item;
        } else {
            self.size += (std::mem::size_of::<MessageCache>()
                + (std::mem::size_of::<u32>() * 2)
                + (item.mailboxes.len() * std::mem::size_of::<MessageUidCache>()))
                as u64;

            let idx = self.items.len() as u32;
            self.items.push(item);
            self.index.insert(id, idx);
        }
    }

    fn has_id(&self, id: &u32) -> bool {
        self.index.contains_key(id)
    }

    fn expand_keywords(&self, message: &MessageCache) -> impl Iterator<Item = Keyword> {
        KeywordsIter(message.keywords).map(move |id| match Keyword::try_from_id(id) {
            Ok(keyword) => keyword,
            Err(id) => Keyword::Other(self.keywords[id - OTHER].clone()),
        })
    }

    fn has_keyword(&self, message: &MessageCache, keyword: &Keyword) -> bool {
        keyword_to_id(self, keyword).is_some_and(|id| message.keywords & (1 << id) != 0)
    }
}

#[inline]
fn keyword_to_id(cache: &MessageStoreCache, keyword: &Keyword) -> Option<u32> {
    match keyword.id() {
        Ok(id) => Some(id),
        Err(name) => cache
            .keywords
            .iter()
            .position(|k| k == name)
            .map(|idx| (OTHER + idx) as u32),
    }
}

#[derive(Clone, Copy, Debug)]
struct KeywordsIter(u128);

impl Iterator for KeywordsIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0 != 0 {
            let item = 127 - self.0.leading_zeros();
            self.0 ^= 1 << item;
            Some(item as usize)
        } else {
            None
        }
    }
}
