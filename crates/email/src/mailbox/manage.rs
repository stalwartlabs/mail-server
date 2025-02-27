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
    ahash::AHashSet,
    query::Filter,
    roaring::RoaringBitmap,
    write::{Archive, BatchBuilder},
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

    fn mailbox_expand_path<'x>(
        &self,
        account_id: u32,
        path: &'x str,
        exact_match: bool,
    ) -> impl Future<Output = trc::Result<Option<ExpandPath<'x>>>> + Send;

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
                .custom(ObjectIndexBuilder::new().with_changes(object))
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
        let expanded_path =
            if let Some(expand_path) = self.mailbox_expand_path(account_id, path, false).await? {
                expand_path
            } else {
                return Ok(None);
            };

        let mut next_parent_id = 0;
        let mut path = expanded_path.path.into_iter().enumerate().peekable();
        'outer: while let Some((pos, name)) = path.peek() {
            let is_inbox = *pos == 0 && name.eq_ignore_ascii_case("inbox");

            for (part, parent_id, document_id) in &expanded_path.found_names {
                if (part.eq(name) || (is_inbox && part.eq_ignore_ascii_case("inbox")))
                    && *parent_id == next_parent_id
                {
                    next_parent_id = *document_id;
                    path.next();
                    continue 'outer;
                }
            }
            break;
        }

        // Create missing folders
        if path.peek().is_some() {
            let mut changes = self.begin_changes(account_id)?;

            for (_, name) in path {
                if name.len() > self.core.jmap.mailbox_name_max_len {
                    return Ok(None);
                }
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Mailbox)
                    .create_document()
                    .custom(
                        ObjectIndexBuilder::new()
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

    async fn mailbox_expand_path<'x>(
        &self,
        account_id: u32,
        path: &'x str,
        exact_match: bool,
    ) -> trc::Result<Option<ExpandPath<'x>>> {
        let path = path
            .split('/')
            .filter_map(|p| {
                let p = p.trim();
                if !p.is_empty() { p.into() } else { None }
            })
            .collect::<Vec<_>>();
        if path.is_empty() || path.len() > self.core.jmap.mailbox_max_depth {
            return Ok(None);
        }

        let mut filter = Vec::with_capacity(path.len() + 2);
        let mut has_inbox = false;
        filter.push(Filter::Or);
        for (pos, item) in path.iter().enumerate() {
            if pos == 0 && item.eq_ignore_ascii_case("inbox") {
                has_inbox = true;
            } else {
                filter.push(Filter::eq(Property::Name, item.serialize()));
            }
        }
        filter.push(Filter::End);

        let mut document_ids = if filter.len() > 2 {
            self.store()
                .filter(account_id, Collection::Mailbox, filter)
                .await
                .caused_by(trc::location!())?
                .results
        } else {
            RoaringBitmap::new()
        };
        if has_inbox {
            document_ids.insert(INBOX_ID);
        }
        if exact_match && (document_ids.len() as usize) < path.len() {
            return Ok(None);
        }

        let mut found_names = Vec::new();
        for document_id in document_ids {
            if let Some(obj) = self
                .get_property::<Archive>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                let obj = obj.unarchive::<ArchivedMailbox>()?;
                found_names.push((
                    obj.name.to_string(),
                    u32::from(obj.parent_id),
                    document_id + 1,
                ));
            } else {
                return Ok(None);
            }
        }

        Ok(Some(ExpandPath { path, found_names }))
    }

    async fn mailbox_get_by_name(&self, account_id: u32, path: &str) -> trc::Result<Option<u32>> {
        Ok(self
            .mailbox_expand_path(account_id, path, true)
            .await?
            .and_then(|ep| {
                let mut next_parent_id = 0;
                'outer: for (pos, name) in ep.path.iter().enumerate() {
                    let is_inbox = pos == 0 && name.eq_ignore_ascii_case("inbox");

                    for (part, parent_id, document_id) in &ep.found_names {
                        if (part.eq(name) || (is_inbox && part.eq_ignore_ascii_case("inbox")))
                            && *parent_id == next_parent_id
                        {
                            next_parent_id = *document_id;
                            continue 'outer;
                        }
                    }
                    return None;
                }
                Some(next_parent_id - 1)
            }))
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
