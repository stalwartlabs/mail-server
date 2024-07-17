/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::BTreeMap;

use common::listener::SessionStream;
use jmap::mailbox::{UidMailbox, INBOX_ID};
use jmap_proto::{
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use store::{
    ahash::AHashMap, write::key::DeserializeBigEndian, IndexKey, IterateParams, Serialize, U32_LEN,
};
use trc::AddContext;

use crate::Session;

#[derive(Default)]
pub struct Mailbox {
    pub messages: Vec<Message>,
    pub account_id: u32,
    pub uid_validity: u32,
    pub total: u32,
    pub size: u32,
}

pub struct Message {
    pub id: u32,
    pub uid: u32,
    pub size: u32,
    pub deleted: bool,
}

impl<T: SessionStream> Session<T> {
    pub async fn fetch_mailbox(&self, account_id: u32) -> trc::Result<Mailbox> {
        // Obtain message ids
        let message_ids = self
            .jmap
            .get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                INBOX_ID,
            )
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();

        if message_ids.is_empty() {
            return Ok(Mailbox::default());
        }

        let mut message_map = BTreeMap::new();
        let mut message_sizes = AHashMap::new();

        // Obtain UID validity
        self.jmap
            .mailbox_get_or_create(account_id)
            .await
            .caused_by(trc::location!())?;
        let uid_validity = self
            .jmap
            .get_property::<Object<Value>>(
                account_id,
                Collection::Mailbox,
                INBOX_ID,
                &Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .and_then(|obj| obj.get(&Property::Cid).as_uint())
            .ok_or_else(|| {
                trc::StoreCause::Unexpected
                    .caused_by(trc::location!())
                    .details("Failed to obtain UID validity")
                    .account_id(account_id)
                    .document_id(INBOX_ID)
            })
            .map(|v| v as u32)?;

        // Obtain message sizes
        self.jmap
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: message_ids.min().unwrap(),
                        field: Property::Size.into(),
                        key: 0u32.serialize(),
                    },
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: message_ids.max().unwrap(),
                        field: Property::Size.into(),
                        key: u32::MAX.serialize(),
                    },
                )
                .no_values(),
                |key, _| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if message_ids.contains(document_id) {
                        message_sizes.insert(
                            document_id,
                            key.deserialize_be_u32(key.len() - (U32_LEN * 2))?,
                        );
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        // Sort by UID
        for (message_id, uid_mailbox) in self
            .jmap
            .get_properties::<Vec<UidMailbox>, _, _>(
                account_id,
                Collection::Email,
                &message_ids,
                Property::MailboxIds,
            )
            .await
            .caused_by(trc::location!())?
            .into_iter()
        {
            // Make sure the message is still in Inbox
            if let Some(item) = uid_mailbox.iter().find(|item| item.mailbox_id == INBOX_ID) {
                debug_assert!(item.uid != 0, "UID is zero for message {item:?}");
                message_map.insert(item.uid, message_id);
            }
        }

        // Create mailbox
        let mut mailbox = Mailbox {
            messages: Vec::with_capacity(message_map.len()),
            uid_validity,
            account_id,
            ..Default::default()
        };
        for (uid, id) in message_map {
            if let Some(size) = message_sizes.get(&id) {
                mailbox.messages.push(Message {
                    id,
                    uid,
                    size: *size,
                    deleted: false,
                });
                mailbox.total += 1;
                mailbox.size += *size;
            }
        }

        Ok(mailbox)
    }
}
