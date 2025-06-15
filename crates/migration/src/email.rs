/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LegacyBincode, get_properties};
use common::Server;
use email::{
    mailbox::{TOMBSTONE_ID, UidMailbox},
    message::{
        index::{MAX_ID_LENGTH, VisitText},
        metadata::{
            MessageData, MessageMetadata, MessageMetadataContents, MessageMetadataPart,
            MetadataPartType,
        },
    },
};
use jmap_proto::types::{collection::Collection, keyword::*, property::Property};
use mail_parser::{
    Address, Attribute, ContentType, DateTime, Encoding, Header, HeaderName, HeaderValue, Received,
};
use std::{borrow::Cow, collections::VecDeque};
use store::{
    BitmapKey, Deserialize, SUBSPACE_BITMAP_TAG, SUBSPACE_INDEXES, SUBSPACE_PROPERTY, Serialize,
    U64_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, BitmapClass, TagValue, ValueClass,
        key::KeySerializer,
    },
};
use trc::AddContext;
use utils::{BlobHash, codec::leb128::Leb128Iterator};

const BM_MARKER: u8 = 1 << 7;

pub(crate) async fn migrate_emails(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let mut message_ids = server
        .get_document_ids(account_id, Collection::Email)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_emails = message_ids.len();
    if num_emails == 0 {
        return Ok(0);
    }
    let tombstoned_ids = server
        .store()
        .get_bitmap(BitmapKey {
            account_id,
            collection: Collection::Email.into(),
            class: BitmapClass::Tag {
                field: Property::MailboxIds.into(),
                value: TagValue::Id(TOMBSTONE_ID),
            },
            document_id: 0,
        })
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let mut message_data: AHashMap<u32, MessageData> = AHashMap::with_capacity(num_emails as usize);
    let mut did_migrate = false;

    // Obtain mailboxes
    for (message_id, uid_mailbox) in get_properties::<Mailboxes, _, _>(
        server,
        account_id,
        Collection::Email,
        &(),
        Property::MailboxIds,
    )
    .await
    .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().mailboxes = uid_mailbox.0;
    }

    // Obtain keywords
    for (message_id, keywords) in get_properties::<Keywords, _, _>(
        server,
        account_id,
        Collection::Email,
        &(),
        Property::Keywords,
    )
    .await
    .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().keywords = keywords.0;
    }

    // Obtain threadIds
    for (message_id, thread_id) in get_properties::<u32, _, _>(
        server,
        account_id,
        Collection::Email,
        &(),
        Property::ThreadId,
    )
    .await
    .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().thread_id = thread_id;
    }

    // Write message data
    for (message_id, data) in message_data {
        if !tombstoned_ids.contains(message_id) {
            message_ids.insert(message_id);
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .update_document(message_id);

            for mailbox in &data.mailboxes {
                batch.untag(Property::MailboxIds, TagValue::Id(mailbox.mailbox_id));
            }

            did_migrate = true;

            batch.set(
                Property::Value,
                Archiver::new(data)
                    .serialize()
                    .caused_by(trc::location!())?,
            );
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }
    }

    // Migrate message metadata
    for message_id in &message_ids {
        match server
            .store()
            .get_value::<LegacyBincode<LegacyMessageMetadata>>(ValueKey {
                account_id,
                collection: Collection::Email.into(),
                document_id: message_id,
                class: ValueClass::Property(Property::BodyStructure.into()),
            })
            .await
        {
            Ok(Some(legacy_metadata)) => {
                let metadata = MessageMetadata::from_legacy(legacy_metadata.inner);

                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .update_document(message_id);

                for header in metadata.root_part().headers.iter().rev() {
                    if matches!(header.name, HeaderName::MessageId) {
                        header.value.visit_text(|id| {
                            if id.len() < MAX_ID_LENGTH {
                                batch.index(Property::References, encode_message_id(id));
                            }
                        });
                    }
                }

                batch.set(
                    Property::BodyStructure,
                    Archiver::new(metadata)
                        .serialize()
                        .caused_by(trc::location!())?,
                );

                did_migrate = true;

                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: message_id,
                        class: ValueClass::Property(Property::BodyStructure.into()),
                    })
                    .await
                    .is_err()
                {
                    return Err(err
                        .account_id(account_id)
                        .document_id(message_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    // Delete keyword bitmaps
    for field in [
        u8::from(Property::Keywords),
        u8::from(Property::Keywords) | BM_MARKER,
    ] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace: SUBSPACE_BITMAP_TAG,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(field)
                        .finalize(),
                },
                AnyKey {
                    subspace: SUBSPACE_BITMAP_TAG,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(field)
                        .write(&[u8::MAX; 8][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    // Delete messageId index, now in References
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_INDEXES,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Email))
                    .write(u8::from(Property::MessageId))
                    .finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_INDEXES,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Email))
                    .write(u8::from(Property::MessageId))
                    .write(&[u8::MAX; 8][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Delete values
    for property in [
        Property::MailboxIds,
        Property::Keywords,
        Property::ThreadId,
        Property::Cid,
    ] {
        let property: u8 = property.into();
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(property)
                        .finalize(),
                },
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(property)
                        .write(&[u8::MAX; 8][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    // Increment document id counter
    if did_migrate {
        server
            .store()
            .assign_document_ids(
                account_id,
                Collection::Email,
                message_ids.max().map(|id| id as u64).unwrap_or(num_emails) + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_emails)
    } else {
        Ok(0)
    }
}

pub trait FromLegacy {
    fn from_legacy(legacy: LegacyMessageMetadata<'_>) -> Self;
}

impl FromLegacy for MessageMetadata {
    fn from_legacy(legacy: LegacyMessageMetadata<'_>) -> Self {
        let mut metadata = MessageMetadata {
            contents: vec![],
            blob_hash: legacy.blob_hash,
            size: legacy.size as u32,
            received_at: legacy.received_at,
            preview: legacy.preview,
            has_attachments: legacy.has_attachments,
            raw_headers: legacy.raw_headers,
        };

        let mut messages = VecDeque::from([legacy.contents]);
        let mut message_id = 0;

        while let Some(message) = messages.pop_front() {
            let mut contents = MessageMetadataContents {
                html_body: message.html_body.into_iter().map(|c| c as u16).collect(),
                text_body: message.text_body.into_iter().map(|c| c as u16).collect(),
                attachments: message.attachments.into_iter().map(|c| c as u16).collect(),
                parts: Vec::with_capacity(message.parts.len()),
            };

            for part in message.parts {
                let body = match part.body {
                    LegacyMetadataPartType::Text => MetadataPartType::Text,
                    LegacyMetadataPartType::Html => MetadataPartType::Html,
                    LegacyMetadataPartType::Binary => MetadataPartType::Binary,
                    LegacyMetadataPartType::InlineBinary => MetadataPartType::InlineBinary,
                    LegacyMetadataPartType::Message(message) => {
                        messages.push_back(message);
                        message_id += 1;
                        MetadataPartType::Message(message_id)
                    }
                    LegacyMetadataPartType::Multipart(parts) => {
                        MetadataPartType::Multipart(parts.into_iter().map(|p| p as u16).collect())
                    }
                };

                contents.parts.push(MessageMetadataPart {
                    headers: part
                        .headers
                        .into_iter()
                        .map(|hdr| Header {
                            name: hdr.name.into_owned(),
                            value: hdr.value.into(),
                            offset_field: hdr.offset_field as u32,
                            offset_start: hdr.offset_start as u32,
                            offset_end: hdr.offset_end as u32,
                        })
                        .collect(),
                    is_encoding_problem: part.is_encoding_problem,
                    encoding: part.encoding,
                    body,
                    size: part.size as u32,
                    offset_header: part.offset_header as u32,
                    offset_body: part.offset_body as u32,
                    offset_end: part.offset_end as u32,
                });
            }
            metadata.contents.push(contents);
        }

        metadata
    }
}

pub struct Mailboxes(Vec<UidMailbox>);
pub struct Keywords(Vec<Keyword>);

impl Deserialize for Mailboxes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(UidMailbox {
                mailbox_id: bytes
                    .next_leb128()
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
                uid: bytes
                    .next_leb128()
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            });
        }
        Ok(Mailboxes(list))
    }
}

impl Deserialize for Keywords {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(
                deserialize_keyword(&mut bytes)
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            );
        }
        Ok(Keywords(list))
    }
}

fn deserialize_keyword(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Keyword> {
    match bytes.next_leb128::<usize>()? {
        SEEN => Some(Keyword::Seen),
        DRAFT => Some(Keyword::Draft),
        FLAGGED => Some(Keyword::Flagged),
        ANSWERED => Some(Keyword::Answered),
        RECENT => Some(Keyword::Recent),
        IMPORTANT => Some(Keyword::Important),
        PHISHING => Some(Keyword::Phishing),
        JUNK => Some(Keyword::Junk),
        NOTJUNK => Some(Keyword::NotJunk),
        DELETED => Some(Keyword::Deleted),
        FORWARDED => Some(Keyword::Forwarded),
        MDN_SENT => Some(Keyword::MdnSent),
        other => {
            let len = other - OTHER;
            let mut keyword = Vec::with_capacity(len);
            for _ in 0..len {
                keyword.push(*bytes.next()?);
            }
            Some(Keyword::Other(String::from_utf8(keyword).ok()?))
        }
    }
}

pub type LegacyMessagePartId = usize;
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadata<'x> {
    pub contents: LegacyMessageMetadataContents<'x>,
    pub blob_hash: BlobHash,
    pub size: usize,
    pub received_at: u64,
    pub preview: String,
    pub has_attachments: bool,
    pub raw_headers: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadataContents<'x> {
    pub html_body: Vec<LegacyMessagePartId>,
    pub text_body: Vec<LegacyMessagePartId>,
    pub attachments: Vec<LegacyMessagePartId>,
    pub parts: Vec<LegacyMessageMetadataPart<'x>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadataPart<'x> {
    pub headers: Vec<LegacyHeader<'x>>,
    pub is_encoding_problem: bool,
    pub body: LegacyMetadataPartType<'x>,
    pub encoding: Encoding,
    pub size: usize,
    pub offset_header: usize,
    pub offset_body: usize,
    pub offset_end: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyHeader<'x> {
    pub name: HeaderName<'x>,
    pub value: LegacyHeaderValue<'x>,
    pub offset_field: usize,
    pub offset_start: usize,
    pub offset_end: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub enum LegacyHeaderValue<'x> {
    /// Address list or group
    Address(Address<'x>),

    /// String
    Text(Cow<'x, str>),

    /// List of strings
    TextList(Vec<Cow<'x, str>>),

    /// Datetime
    DateTime(DateTime),

    /// Content-Type or Content-Disposition header
    ContentType(LegacyContentType<'x>),

    /// Received header
    Received(Box<Received<'x>>),

    #[default]
    Empty,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyContentType<'x> {
    pub c_type: Cow<'x, str>,
    pub c_subtype: Option<Cow<'x, str>>,
    pub attributes: Option<Vec<(Cow<'x, str>, Cow<'x, str>)>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum LegacyMetadataPartType<'x> {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(LegacyMessageMetadataContents<'x>),
    Multipart(Vec<LegacyMessagePartId>),
}

impl From<LegacyHeaderValue<'_>> for HeaderValue<'static> {
    fn from(value: LegacyHeaderValue<'_>) -> Self {
        match value {
            LegacyHeaderValue::Address(address) => HeaderValue::Address(address.into_owned()),
            LegacyHeaderValue::Text(cow) => HeaderValue::Text(cow.into_owned().into()),
            LegacyHeaderValue::TextList(cows) => HeaderValue::TextList(
                cows.into_iter()
                    .map(|cow| cow.into_owned().into())
                    .collect(),
            ),
            LegacyHeaderValue::DateTime(date_time) => HeaderValue::DateTime(date_time),
            LegacyHeaderValue::ContentType(legacy_content_type) => {
                HeaderValue::ContentType(ContentType {
                    c_type: legacy_content_type.c_type.into_owned().into(),
                    c_subtype: legacy_content_type.c_subtype.map(|s| s.into_owned().into()),
                    attributes: legacy_content_type.attributes.map(|attrs| {
                        attrs
                            .into_iter()
                            .map(|(k, v)| Attribute {
                                name: k.into_owned().into(),
                                value: v.into_owned().into(),
                            })
                            .collect()
                    }),
                })
            }
            LegacyHeaderValue::Received(received) => {
                HeaderValue::Received(Box::new(received.into_owned()))
            }
            LegacyHeaderValue::Empty => HeaderValue::Empty,
        }
    }
}

pub(crate) fn encode_message_id(message_id: &str) -> Vec<u8> {
    let mut msg_id = Vec::with_capacity(message_id.len() + 1);
    msg_id.extend_from_slice(message_id.as_bytes());
    msg_id.push(0);
    msg_id
}
