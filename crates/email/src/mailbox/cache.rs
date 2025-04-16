/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{
    CacheSwap, MailboxCache, MailboxStoreCache, Server, auth::AccessToken,
    config::jmap::settings::SpecialUse, sharing::EffectiveAcl,
};

use jmap_proto::types::{acl::Acl, collection::Collection, value::AclGrant};
use std::future::Future;
use store::{
    ahash::{AHashMap, AHashSet},
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use tokio::sync::Semaphore;
use trc::AddContext;
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

use super::{ArchivedMailbox, Mailbox, manage::MailboxFnc};

pub trait MessageMailboxCache: Sync + Send {
    fn get_cached_mailboxes(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<MailboxStoreCache>>> + Send;
}

impl MessageMailboxCache for Server {
    async fn get_cached_mailboxes(&self, account_id: u32) -> trc::Result<Arc<MailboxStoreCache>> {
        let cache_ = match self
            .inner
            .cache
            .mailboxes
            .get_value_or_guard_async(&account_id)
            .await
        {
            Ok(cache) => cache,
            Err(guard) => {
                let cache = full_cache_build(self, account_id, Arc::new(Semaphore::new(1))).await?;

                if guard.insert(CacheSwap::new(cache.clone())).is_err() {
                    self.inner
                        .cache
                        .mailboxes
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
            .changes(
                account_id,
                Collection::Mailbox,
                Query::Since(cache.change_id),
            )
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

        let mut changed_ids = AHashSet::with_capacity(changes.changes.len());
        let mut new_cache = MailboxStoreCache {
            items: Vec::with_capacity(cache.items.len()),
            index: AHashMap::with_capacity(cache.items.len()),
            size: 0,
            change_id: changes.to_change_id,
            update_lock: cache.update_lock.clone(),
        };

        for change in changes.changes {
            match change {
                Change::Insert(id) | Change::Update(id) => {
                    let document_id = id as u32;
                    if let Some(archive) = self
                        .get_archive(account_id, Collection::Mailbox, document_id)
                        .await
                        .caused_by(trc::location!())?
                    {
                        insert_item(&mut new_cache, document_id, archive.unarchive::<Mailbox>()?);
                        changed_ids.insert(document_id);
                    }
                }
                Change::Delete(id) => {
                    changed_ids.insert(id as u32);
                }
            }
        }

        for item in cache.items.iter() {
            if !changed_ids.contains(&item.document_id) {
                new_cache.insert(item.clone());
            }
        }

        build_tree(&mut new_cache);

        if cache.items.len() > new_cache.items.len() {
            new_cache.items.shrink_to_fit();
            new_cache.index.shrink_to_fit();
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
) -> trc::Result<Arc<MailboxStoreCache>> {
    // Build cache
    let mut cache = MailboxStoreCache {
        items: Default::default(),
        index: Default::default(),
        size: 0,
        change_id: 0,
        update_lock,
    };

    server
        .get_archives(
            account_id,
            Collection::Mailbox,
            &(),
            |document_id, archive| {
                insert_item(&mut cache, document_id, archive.unarchive::<Mailbox>()?);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if cache.items.is_empty() {
        server
            .create_system_folders(account_id)
            .await
            .caused_by(trc::location!())?;
        server
            .get_archives(
                account_id,
                Collection::Mailbox,
                &(),
                |document_id, archive| {
                    insert_item(&mut cache, document_id, archive.unarchive::<Mailbox>()?);
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    build_tree(&mut cache);

    Ok(Arc::new(cache))
}

fn insert_item(cache: &mut MailboxStoreCache, document_id: u32, mailbox: &ArchivedMailbox) {
    let parent_id = mailbox.parent_id.to_native();
    let item = MailboxCache {
        document_id,
        name: mailbox.name.as_str().into(),
        path: "".into(),
        role: (&mailbox.role).into(),
        parent_id: if parent_id > 0 {
            parent_id - 1
        } else {
            u32::MAX
        },
        sort_order: mailbox
            .sort_order
            .as_ref()
            .map(|s| s.to_native())
            .unwrap_or(u32::MAX),
        subscribers: mailbox.subscribers.iter().map(|s| s.to_native()).collect(),
        uid_validity: mailbox.uid_validity.to_native(),
        acls: mailbox
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect(),
    };

    cache.insert(item);
}

fn build_tree(cache: &mut MailboxStoreCache) {
    cache.size = 0;
    let mut topological_sort = TopologicalSort::with_capacity(cache.items.len());

    for (idx, mailbox) in cache.items.iter_mut().enumerate() {
        topological_sort.insert(
            if mailbox.parent_id == u32::MAX {
                0
            } else {
                mailbox.parent_id + 1
            },
            mailbox.document_id + 1,
        );
        mailbox.path = if matches!(mailbox.role, SpecialUse::Inbox) {
            "INBOX".into()
        } else if mailbox.is_root() && mailbox.name.as_str().eq_ignore_ascii_case("inbox") {
            format!("INBOX {}", idx + 1)
        } else {
            mailbox.name.clone()
        };

        cache.size += item_size(mailbox);
    }

    for folder_id in topological_sort.into_iterator() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            if let Some((path, parent_path)) = cache
                .by_id(&folder_id)
                .and_then(|folder| {
                    folder
                        .parent_id()
                        .map(|parent_id| (&folder.path, parent_id))
                })
                .and_then(|(path, parent_id)| {
                    cache.by_id(&parent_id).map(|folder| (path, &folder.path))
                })
            {
                let mut new_path = String::with_capacity(parent_path.len() + path.len() + 1);
                new_path.push_str(parent_path.as_str());
                new_path.push('/');
                new_path.push_str(path.as_str());
                let folder = cache.by_id_mut(&folder_id).unwrap();
                folder.path = new_path;
            }
        }
    }
}

pub trait MailboxCacheAccess {
    fn by_id(&self, id: &u32) -> Option<&MailboxCache>;
    fn by_id_mut(&mut self, id: &u32) -> Option<&mut MailboxCache>;
    fn insert(&mut self, item: MailboxCache);
    fn by_name(&self, name: &str) -> Option<&MailboxCache>;
    fn by_path(&self, name: &str) -> Option<&MailboxCache>;
    fn by_role(&self, role: &SpecialUse) -> Option<&MailboxCache>;
    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;
    fn has_id(&self, id: &u32) -> bool;
}

impl MailboxCacheAccess for MailboxStoreCache {
    fn by_name(&self, name: &str) -> Option<&MailboxCache> {
        self.items
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    fn by_path(&self, path: &str) -> Option<&MailboxCache> {
        self.items
            .iter()
            .find(|m| m.path.eq_ignore_ascii_case(path))
    }

    fn by_role(&self, role: &SpecialUse) -> Option<&MailboxCache> {
        self.items.iter().find(|m| &m.role == role)
    }

    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();

        RoaringBitmap::from_iter(
            self.items
                .iter()
                .filter(|m| {
                    m.acls
                        .as_slice()
                        .effective_acl(access_token)
                        .contains_all(check_acls)
                })
                .map(|m| m.document_id),
        )
    }

    fn by_id(&self, id: &u32) -> Option<&MailboxCache> {
        self.index
            .get(id)
            .and_then(|idx| self.items.get(*idx as usize))
    }

    fn by_id_mut(&mut self, id: &u32) -> Option<&mut MailboxCache> {
        self.index
            .get(id)
            .and_then(|idx| self.items.get_mut(*idx as usize))
    }

    fn insert(&mut self, item: MailboxCache) {
        let id = item.document_id;
        if let Some(idx) = self.index.get(&id) {
            self.items[*idx as usize] = item;
        } else {
            let idx = self.items.len() as u32;
            self.items.push(item);
            self.index.insert(id, idx);
        }
    }

    fn has_id(&self, id: &u32) -> bool {
        self.index.contains_key(id)
    }
}

#[inline(always)]
fn item_size(item: &MailboxCache) -> u64 {
    (std::mem::size_of::<MailboxCache>()
        + (if item.name.len() > std::mem::size_of::<String>() {
            item.name.len()
        } else {
            0
        })
        + (if item.path.len() > std::mem::size_of::<String>() {
            item.path.len()
        } else {
            0
        })) as u64
}
