/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, slice::Iter};

use common::{config::jmap::settings::SpecialUse, Server};
use jmap_proto::{
    object::{
        index::{IndexAs, IndexProperty, ObjectIndexBuilder},
        Object,
    },
    types::{collection::Collection, id::Id, keyword::Keyword, property::Property, value::Value},
};
use store::{
    ahash::AHashSet,
    query::Filter,
    rand,
    roaring::RoaringBitmap,
    write::{
        BatchBuilder, BitmapClass, DeserializeFrom, MaybeDynamicId, Operation, SerializeInto,
        TagValue, ToBitmaps,
    },
    Serialize, U32_LEN,
};
use trc::AddContext;
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::cache::ThreadCache;

pub const INBOX_ID: u32 = 0;
pub const TRASH_ID: u32 = 1;
pub const JUNK_ID: u32 = 2;
pub const DRAFTS_ID: u32 = 3;
pub const SENT_ID: u32 = 4;
pub const ARCHIVE_ID: u32 = 5;
pub const TOMBSTONE_ID: u32 = u32::MAX - 1;

#[derive(Debug)]
pub struct ExpandPath<'x> {
    pub path: Vec<&'x str>,
    pub found_names: Vec<(String, u32, u32)>,
}

pub static SCHEMA: &[IndexProperty] = &[
    IndexProperty::new(Property::Name)
        .index_as(IndexAs::Text {
            tokenize: true,
            index: true,
        })
        .required(),
    IndexProperty::new(Property::Role).index_as(IndexAs::Text {
        tokenize: false,
        index: true,
    }),
    IndexProperty::new(Property::Role).index_as(IndexAs::HasProperty),
    IndexProperty::new(Property::ParentId).index_as(IndexAs::Integer),
    IndexProperty::new(Property::SortOrder).index_as(IndexAs::Integer),
    IndexProperty::new(Property::IsSubscribed).index_as(IndexAs::IntegerList),
    IndexProperty::new(Property::Acl).index_as(IndexAs::Acl),
];

#[derive(Debug, Clone, Copy)]
pub struct UidMailbox {
    pub mailbox_id: u32,
    pub uid: u32,
}

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
        role: &str,
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
            let (role, document_id) = match folder.special_use {
                SpecialUse::Inbox => ("inbox", INBOX_ID),
                SpecialUse::Trash => ("trash", TRASH_ID),
                SpecialUse::Junk => ("junk", JUNK_ID),
                SpecialUse::Drafts => ("drafts", DRAFTS_ID),
                SpecialUse::Sent => ("sent", SENT_ID),
                SpecialUse::Archive => ("archive", ARCHIVE_ID),
                SpecialUse::None => {
                    last_document_id += 1;
                    ("", last_document_id)
                }
                SpecialUse::Shared => unreachable!(),
            };

            let mut object = Object::with_capacity(4)
                .with_property(Property::Name, folder.name.clone())
                .with_property(Property::ParentId, Value::Id(0u64.into()))
                .with_property(
                    Property::Cid,
                    Value::UnsignedInt(rand::random::<u32>() as u64),
                );
            if !role.is_empty() {
                object.set(Property::Role, role);
            }
            if folder.subscribe {
                object.set(
                    Property::IsSubscribed,
                    Value::List(vec![Value::Id(account_id.into())]),
                );
            }
            batch
                .create_document_with_id(document_id)
                .custom(ObjectIndexBuilder::new(SCHEMA).with_changes(object));
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
                        ObjectIndexBuilder::new(SCHEMA).with_changes(
                            Object::with_capacity(3)
                                .with_property(Property::Name, name)
                                .with_property(
                                    Property::ParentId,
                                    Value::Id(Id::from(next_parent_id)),
                                )
                                .with_property(
                                    Property::Cid,
                                    Value::UnsignedInt(rand::random::<u32>() as u64),
                                ),
                        ),
                    );
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
                .custom(changes);
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
                if !p.is_empty() {
                    p.into()
                } else {
                    None
                }
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
                filter.push(Filter::eq(Property::Name, *item));
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
            if let Some(mut obj) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                if let Some(Value::Text(value)) = obj.properties.remove(&Property::Name) {
                    found_names.push((
                        value,
                        if let Some(Value::Id(value)) = obj.properties.remove(&Property::ParentId) {
                            value.document_id()
                        } else {
                            0
                        },
                        document_id + 1,
                    ));
                } else {
                    return Ok(None);
                }
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

    async fn mailbox_get_by_role(&self, account_id: u32, role: &str) -> trc::Result<Option<u32>> {
        self.store()
            .filter(
                account_id,
                Collection::Mailbox,
                vec![Filter::eq(Property::Role, role)],
            )
            .await
            .caused_by(trc::location!())
            .map(|r| r.results.min())
    }
}

impl PartialEq for UidMailbox {
    fn eq(&self, other: &Self) -> bool {
        self.mailbox_id == other.mailbox_id
    }
}

impl Eq for UidMailbox {}

impl ToBitmaps for UidMailbox {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field,
                value: TagValue::Id(MaybeDynamicId::Static(self.mailbox_id)),
            },
            set,
        });
    }
}

impl SerializeInto for UidMailbox {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.mailbox_id);
        buf.push_leb128(self.uid);
    }
}

impl DeserializeFrom for UidMailbox {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Some(UidMailbox {
            mailbox_id: bytes.next_leb128()?,
            uid: bytes.next_leb128()?,
        })
    }
}

impl Serialize for UidMailbox {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(U32_LEN * 2);
        self.serialize_into(&mut buf);
        buf
    }
}

impl UidMailbox {
    pub fn new(mailbox_id: u32, uid: u32) -> Self {
        UidMailbox { mailbox_id, uid }
    }

    pub fn new_unassigned(mailbox_id: u32) -> Self {
        UidMailbox { mailbox_id, uid: 0 }
    }
}
