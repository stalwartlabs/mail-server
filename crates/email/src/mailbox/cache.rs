/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{
    CacheSwap, MailboxCache, MessageStoreCache, Server, auth::AccessToken,
    config::jmap::settings::SpecialUse, sharing::EffectiveAcl,
};
use compact_str::CompactString;
use jmap_proto::types::{acl::Acl, collection::Collection, value::AclGrant};
use std::future::Future;
use store::{
    ahash::AHashMap,
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
    ) -> impl Future<Output = trc::Result<Arc<MessageStoreCache<MailboxCache>>>> + Send;
}

impl MessageMailboxCache for Server {
    async fn get_cached_mailboxes(
        &self,
        account_id: u32,
    ) -> trc::Result<Arc<MessageStoreCache<MailboxCache>>> {
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

        let mut has_changes = false;
        let mut cache = cache.as_ref().clone();
        cache.change_id = changes.to_change_id;

        for change in changes.changes {
            match change {
                Change::Insert(id) | Change::Update(id) => {
                    let document_id = id as u32;
                    if let Some(archive) = self
                        .get_archive(account_id, Collection::Mailbox, document_id)
                        .await
                        .caused_by(trc::location!())?
                    {
                        insert_item(&mut cache, document_id, archive.unarchive::<Mailbox>()?);
                        has_changes = true;
                    }
                }
                Change::Delete(id) => {
                    if cache.items.remove(&(id as u32)).is_some() {
                        has_changes = true;
                    }
                }
                Change::ChildUpdate(_) => {}
            }
        }

        if has_changes {
            build_tree(&mut cache);
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
) -> trc::Result<Arc<MessageStoreCache<MailboxCache>>> {
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

fn insert_item(
    cache: &mut MessageStoreCache<MailboxCache>,
    document_id: u32,
    mailbox: &ArchivedMailbox,
) {
    let parent_id = mailbox.parent_id.to_native();
    let item = MailboxCache {
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

    cache.items.insert(document_id, item);
}

fn build_tree(cache: &mut MessageStoreCache<MailboxCache>) {
    cache.size = 0;
    let mut topological_sort = TopologicalSort::with_capacity(cache.items.len());

    for (idx, (&document_id, mailbox)) in cache.items.iter_mut().enumerate() {
        topological_sort.insert(
            if mailbox.parent_id == u32::MAX {
                0
            } else {
                mailbox.parent_id + 1
            },
            document_id + 1,
        );
        mailbox.path = if matches!(mailbox.role, SpecialUse::Inbox) {
            "INBOX".into()
        } else if mailbox.is_root() && mailbox.name.as_str().eq_ignore_ascii_case("inbox") {
            format!("INBOX {}", idx + 1).into()
        } else {
            mailbox.name.clone()
        };

        cache.size += (std::mem::size_of::<MailboxCache>()
            + std::mem::size_of::<u32>()
            + mailbox.name.len()
            + mailbox.path.len()) as u64;
    }

    for folder_id in topological_sort.into_iterator() {
        if folder_id != 0 {
            let folder_id = folder_id - 1;
            if let Some((path, parent_path)) = cache
                .items
                .get(&folder_id)
                .and_then(|folder| {
                    folder
                        .parent_id()
                        .map(|parent_id| (&folder.path, parent_id))
                })
                .and_then(|(path, parent_id)| {
                    cache
                        .items
                        .get(&parent_id)
                        .map(|folder| (path, &folder.path))
                })
            {
                let mut new_path = CompactString::with_capacity(parent_path.len() + path.len() + 1);
                new_path.push_str(parent_path.as_str());
                new_path.push('/');
                new_path.push_str(path.as_str());
                let folder = cache.items.get_mut(&folder_id).unwrap();
                folder.path = new_path;
            }
        }
    }
}

pub trait MailboxCacheAccess {
    fn by_name(&self, name: &str) -> Option<(&u32, &MailboxCache)>;
    fn by_path(&self, name: &str) -> Option<(&u32, &MailboxCache)>;
    fn by_role(&self, role: &SpecialUse) -> Option<(&u32, &MailboxCache)>;
    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;
}

impl MailboxCacheAccess for MessageStoreCache<MailboxCache> {
    fn by_name(&self, name: &str) -> Option<(&u32, &MailboxCache)> {
        self.items
            .iter()
            .find(|(_, m)| m.name.eq_ignore_ascii_case(name))
    }

    fn by_path(&self, path: &str) -> Option<(&u32, &MailboxCache)> {
        self.items
            .iter()
            .find(|(_, m)| m.path.eq_ignore_ascii_case(path))
    }

    fn by_role(&self, role: &SpecialUse) -> Option<(&u32, &MailboxCache)> {
        self.items.iter().find(|(_, m)| &m.role == role)
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
                .filter(|(_, m)| {
                    m.acls
                        .as_slice()
                        .effective_acl(access_token)
                        .contains_all(check_acls)
                })
                .map(|(id, _)| *id),
        )
    }
}
