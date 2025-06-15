/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mailbox::{ArchivedMailbox, Mailbox, manage::MailboxFnc};
use common::{
    MailboxCache, MailboxesCache, MessageStoreCache, Server, auth::AccessToken,
    config::jmap::settings::SpecialUse, sharing::EffectiveAcl,
};
use jmap_proto::types::{acl::Acl, collection::Collection, value::AclGrant};
use store::{ahash::AHashMap, roaring::RoaringBitmap};
use trc::AddContext;
use utils::{map::bitmap::Bitmap, topological::TopologicalSort};

pub(crate) async fn update_mailbox_cache(
    server: &Server,
    account_id: u32,
    changed_ids: &AHashMap<u32, bool>,
    store_cache: &MessageStoreCache,
) -> trc::Result<MailboxesCache> {
    let mut new_cache = MailboxesCache {
        items: Vec::with_capacity(store_cache.mailboxes.items.len()),
        index: AHashMap::with_capacity(store_cache.mailboxes.items.len()),
        size: 0,
        change_id: 0,
    };

    for (document_id, is_update) in changed_ids {
        if *is_update {
            if let Some(archive) = server
                .get_archive(account_id, Collection::Mailbox, *document_id)
                .await
                .caused_by(trc::location!())?
            {
                insert_item(
                    &mut new_cache,
                    *document_id,
                    archive.unarchive::<Mailbox>()?,
                );
            }
        }
    }

    for item in store_cache.mailboxes.items.iter() {
        if !changed_ids.contains_key(&item.document_id) {
            mailbox_insert(&mut new_cache, item.clone());
        }
    }

    build_tree(&mut new_cache);

    if store_cache.mailboxes.items.len() > new_cache.items.len() {
        new_cache.items.shrink_to_fit();
        new_cache.index.shrink_to_fit();
    }

    Ok(new_cache)
}

pub(crate) async fn full_mailbox_cache_build(
    server: &Server,
    account_id: u32,
) -> trc::Result<MailboxesCache> {
    // Build cache
    let mut cache = MailboxesCache {
        items: Default::default(),
        index: Default::default(),
        size: 0,
        change_id: 0,
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

    Ok(cache)
}

fn insert_item(cache: &mut MailboxesCache, document_id: u32, mailbox: &ArchivedMailbox) {
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

    mailbox_insert(cache, item);
}

fn build_tree(cache: &mut MailboxesCache) {
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
            if let Some((path, parent_path)) = by_id(cache, &folder_id)
                .and_then(|folder| {
                    folder
                        .parent_id()
                        .map(|parent_id| (&folder.path, parent_id))
                })
                .and_then(|(path, parent_id)| {
                    by_id(cache, &parent_id).map(|folder| (path, &folder.path))
                })
            {
                let mut new_path = String::with_capacity(parent_path.len() + path.len() + 1);
                new_path.push_str(parent_path.as_str());
                new_path.push('/');
                new_path.push_str(path.as_str());
                let folder = by_id_mut(cache, &folder_id).unwrap();
                folder.path = new_path;
            }
        }
    }
}

pub trait MailboxCacheAccess {
    fn mailbox_by_id(&self, id: &u32) -> Option<&MailboxCache>;
    fn mailbox_by_name(&self, name: &str) -> Option<&MailboxCache>;
    fn mailbox_by_path(&self, name: &str) -> Option<&MailboxCache>;
    fn mailbox_by_role(&self, role: &SpecialUse) -> Option<&MailboxCache>;
    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap;
    fn has_mailbox_id(&self, id: &u32) -> bool;
}

impl MailboxCacheAccess for MessageStoreCache {
    fn mailbox_by_name(&self, name: &str) -> Option<&MailboxCache> {
        self.mailboxes
            .items
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    fn mailbox_by_path(&self, path: &str) -> Option<&MailboxCache> {
        self.mailboxes
            .items
            .iter()
            .find(|m| m.path.eq_ignore_ascii_case(path))
    }

    fn mailbox_by_role(&self, role: &SpecialUse) -> Option<&MailboxCache> {
        self.mailboxes.items.iter().find(|m| &m.role == role)
    }

    fn shared_mailboxes(
        &self,
        access_token: &AccessToken,
        check_acls: impl Into<Bitmap<Acl>> + Sync + Send,
    ) -> RoaringBitmap {
        let check_acls = check_acls.into();

        RoaringBitmap::from_iter(
            self.mailboxes
                .items
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

    fn mailbox_by_id(&self, id: &u32) -> Option<&MailboxCache> {
        self.mailboxes
            .index
            .get(id)
            .and_then(|idx| self.mailboxes.items.get(*idx as usize))
    }

    fn has_mailbox_id(&self, id: &u32) -> bool {
        self.mailboxes.index.contains_key(id)
    }
}

#[inline(always)]
fn by_id<'x>(cache: &'x MailboxesCache, id: &u32) -> Option<&'x MailboxCache> {
    cache
        .index
        .get(id)
        .and_then(|idx| cache.items.get(*idx as usize))
}

#[inline(always)]
fn by_id_mut<'x>(cache: &'x mut MailboxesCache, id: &u32) -> Option<&'x mut MailboxCache> {
    cache
        .index
        .get(id)
        .and_then(|idx| cache.items.get_mut(*idx as usize))
}

fn mailbox_insert(cache: &mut MailboxesCache, item: MailboxCache) {
    let id = item.document_id;
    if let Some(idx) = cache.index.get(&id) {
        cache.items[*idx as usize] = item;
    } else {
        let idx = cache.items.len() as u32;
        cache.items.push(item);
        cache.index.insert(id, idx);
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
