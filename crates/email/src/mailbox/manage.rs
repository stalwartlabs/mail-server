/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{Server, config::jmap::settings::SpecialUse, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, keyword::Keyword, property::Property};
use store::{
    SerializeInfallible,
    ahash::{AHashMap, AHashSet},
    query::Filter,
    roaring::RoaringBitmap,
    write::BatchBuilder,
};
use trc::AddContext;

use crate::thread::cache::ThreadCache;

use super::*;

pub trait MailboxFnc: Sync + Send {
    fn mailbox_get_or_create(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn mailbox_create_path(
        &self,
        account_id: u32,
        path: &str,
    ) -> impl Future<Output = trc::Result<Option<(u32, Option<u64>)>>> + Send;

    fn mailbox_count_threads(
        &self,
        account_id: u32,
        document_ids: Option<RoaringBitmap>,
    ) -> impl Future<Output = trc::Result<usize>> + Send;

    fn mailbox_unread_tags(
        &self,
        account_id: u32,
        document_id: u32,
        message_ids: &Option<RoaringBitmap>,
    ) -> impl Future<Output = trc::Result<Option<RoaringBitmap>>> + Send;

    fn mailbox_get_by_name(
        &self,
        account_id: u32,
        path: &str,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn mailbox_get_by_role(
        &self,
        account_id: u32,
        role: SpecialUse,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;
}

impl MailboxFnc for Server {
    async fn mailbox_get_or_create(&self, account_id: u32) -> trc::Result<RoaringBitmap> {
        let mut mailbox_ids = self
            .get_document_ids(account_id, Collection::Mailbox)
            .await?
            .unwrap_or_default();
        if !mailbox_ids.is_empty() {
            return Ok(mailbox_ids);
        }

        #[cfg(feature = "test_mode")]
        if mailbox_ids.is_empty() && account_id == 0 {
            return Ok(mailbox_ids);
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox);

        // Create mailboxes
        let mut last_document_id = ARCHIVE_ID;
        for folder in &self.core.jmap.default_folders {
            let document_id = match folder.special_use {
                SpecialUse::Inbox => INBOX_ID,
                SpecialUse::Trash => TRASH_ID,
                SpecialUse::Junk => JUNK_ID,
                SpecialUse::Drafts => DRAFTS_ID,
                SpecialUse::Sent => SENT_ID,
                SpecialUse::Archive => ARCHIVE_ID,
                SpecialUse::None | SpecialUse::Important => {
                    last_document_id += 1;
                    last_document_id
                }
                SpecialUse::Shared => unreachable!(),
            };

            let mut object = Mailbox::new(folder.name.clone()).with_role(folder.special_use);
            if folder.subscribe {
                object.add_subscriber(account_id);
            }
            batch
                .create_document_with_id(document_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(object))
                .caused_by(trc::location!())?;
            mailbox_ids.insert(document_id);
        }

        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .caused_by(trc::location!())
            .map(|_| mailbox_ids)
    }

    async fn mailbox_create_path(
        &self,
        account_id: u32,
        path: &str,
    ) -> trc::Result<Option<(u32, Option<u64>)>> {
        let folders = self
            .fetch_folders::<Mailbox>(account_id, Collection::Mailbox)
            .await
            .caused_by(trc::location!())?
            .format(|f| {
                f.name = if f.document_id == INBOX_ID {
                    "inbox".to_string()
                } else {
                    f.name.to_lowercase()
                };
            })
            .into_iterator()
            .map(|e| (e.name, e.document_id))
            .collect::<AHashMap<String, u32>>();

        let mut next_parent_id = 0;
        let mut create_paths = Vec::with_capacity(2);

        let mut path = path.split('/').map(|v| v.trim());
        let mut found_path = String::with_capacity(16);
        {
            while let Some(name) = path.next() {
                if !found_path.is_empty() {
                    found_path.push('/');
                }

                for ch in name.chars() {
                    for ch in ch.to_lowercase() {
                        found_path.push(ch);
                    }
                }

                if let Some(document_id) = folders.get(&found_path) {
                    next_parent_id = *document_id + 1;
                } else {
                    create_paths.push(name.to_string());
                    create_paths.extend(path.map(|v| v.to_string()));
                    break;
                }
            }
        }

        // Create missing folders
        if !create_paths.is_empty() {
            let mut changes = self.begin_changes(account_id)?;

            for name in create_paths {
                if name.len() > self.core.jmap.mailbox_name_max_len {
                    return Ok(None);
                }
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Mailbox)
                    .create_document()
                    .custom(
                        ObjectIndexBuilder::<(), _>::new()
                            .with_changes(Mailbox::new(name).with_parent_id(next_parent_id)),
                    )
                    .caused_by(trc::location!())?;
                let document_id = self
                    .store()
                    .write_expect_id(batch)
                    .await
                    .caused_by(trc::location!())?;
                changes.log_insert(Collection::Mailbox, document_id);
                next_parent_id = document_id + 1;
            }
            let change_id = changes.change_id;
            let mut batch = BatchBuilder::new();

            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .custom(changes)
                .caused_by(trc::location!())?;
            self.store()
                .write(batch.build())
                .await
                .caused_by(trc::location!())?;

            Ok(Some((next_parent_id - 1, Some(change_id))))
        } else {
            Ok(Some((next_parent_id - 1, None)))
        }
    }

    async fn mailbox_count_threads(
        &self,
        account_id: u32,
        document_ids: Option<RoaringBitmap>,
    ) -> trc::Result<usize> {
        if let Some(document_ids) = document_ids {
            let mut thread_ids = AHashSet::default();
            self.get_cached_thread_ids(account_id, document_ids.into_iter())
                .await
                .caused_by(trc::location!())?
                .into_iter()
                .for_each(|(_, thread_id)| {
                    thread_ids.insert(thread_id);
                });
            Ok(thread_ids.len())
        } else {
            Ok(0)
        }
    }

    async fn mailbox_unread_tags(
        &self,
        account_id: u32,
        document_id: u32,
        message_ids: &Option<RoaringBitmap>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        if let (Some(message_ids), Some(mailbox_message_ids)) = (
            message_ids,
            self.get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                document_id,
            )
            .await?,
        ) {
            if let Some(mut seen) = self
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::Keywords,
                    Keyword::Seen,
                )
                .await?
            {
                seen ^= message_ids;
                seen &= &mailbox_message_ids;
                if !seen.is_empty() {
                    Ok(Some(seen))
                } else {
                    Ok(None)
                }
            } else {
                Ok(mailbox_message_ids.into())
            }
        } else {
            Ok(None)
        }
    }

    async fn mailbox_get_by_name(&self, account_id: u32, path: &str) -> trc::Result<Option<u32>> {
        self.fetch_folders::<Mailbox>(account_id, Collection::Mailbox)
            .await
            .map(|folders| {
                folders
                    .format(|f| {
                        if f.document_id == INBOX_ID {
                            f.name = "INBOX".to_string();
                        }
                    })
                    .into_iterator()
                    .find(|e| e.name.eq_ignore_ascii_case(path))
                    .map(|e| e.document_id)
            })
    }

    async fn mailbox_get_by_role(
        &self,
        account_id: u32,
        role: SpecialUse,
    ) -> trc::Result<Option<u32>> {
        if let Some(role) = role.as_str() {
            self.store()
                .filter(
                    account_id,
                    Collection::Mailbox,
                    vec![Filter::eq(Property::Role, role.serialize())],
                )
                .await
                .caused_by(trc::location!())
                .map(|r| r.results.min())
        } else {
            Ok(None)
        }
    }
}
