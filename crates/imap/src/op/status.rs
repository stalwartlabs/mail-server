/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::core::{Mailbox, Session, SessionData};
use common::listener::SessionStream;
use imap_proto::{
    parser::PushUnique,
    protocol::status::{Status, StatusItem, StatusItemType},
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};
use jmap_proto::{
    object::Object,
    types::{collection::Collection, id::Id, keyword::Keyword, property::Property, value::Value},
};
use store::{
    roaring::RoaringBitmap,
    write::{key::DeserializeBigEndian, ValueClass},
    IndexKeyPrefix, IterateParams, ValueKey,
};
use store::{Deserialize, U32_LEN};

use super::ToModSeq;

impl<T: SessionStream> Session<T> {
    pub async fn handle_status(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_status(self.version) {
            Ok(arguments) => {
                let version = self.version;
                let data = self.state.session_data();
                tokio::spawn(async move {
                    // Refresh mailboxes
                    if let Err(err) = data.synchronize_mailboxes(false).await {
                        data.write_bytes(err.with_tag(arguments.tag).into_bytes())
                            .await;
                        return;
                    }

                    // Fetch status
                    match data.status(arguments.mailbox_name, &arguments.items).await {
                        Ok(status) => {
                            let mut buf = Vec::with_capacity(32);
                            status.serialize(&mut buf, version.is_rev2());
                            data.write_bytes(
                                StatusResponse::completed(Command::Status)
                                    .with_tag(arguments.tag)
                                    .serialize(buf),
                            )
                            .await;
                        }
                        Err(mut response) => {
                            response.tag = arguments.tag.into();
                            data.write_bytes(response.into_bytes()).await;
                        }
                    }
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn status(
        &self,
        mailbox_name: String,
        items: &[Status],
    ) -> super::Result<StatusItem> {
        // Get mailbox id
        let mailbox = if let Some(mailbox) = self.get_mailbox_by_name(&mailbox_name) {
            mailbox
        } else {
            // Some IMAP clients will try to get the status of a mailbox with the NoSelect flag
            return if mailbox_name == self.jmap.core.jmap.shared_folder
                || mailbox_name
                    .split_once('/')
                    .map_or(false, |(base_name, path)| {
                        base_name == self.jmap.core.jmap.shared_folder && !path.contains('/')
                    })
            {
                Ok(StatusItem {
                    mailbox_name,
                    items: items
                        .iter()
                        .map(|item| {
                            (
                                *item,
                                match item {
                                    Status::Messages
                                    | Status::Size
                                    | Status::Unseen
                                    | Status::Recent
                                    | Status::Deleted
                                    | Status::HighestModSeq => StatusItemType::Number(0),
                                    Status::UidNext | Status::UidValidity => {
                                        StatusItemType::Number(1)
                                    }
                                    Status::MailboxId => StatusItemType::String("none".to_string()),
                                },
                            )
                        })
                        .collect(),
                })
            } else {
                Err(StatusResponse::no("Mailbox does not exist.")
                    .with_code(ResponseCode::NonExistent))
            };
        };

        // Make sure all requested fields are up to date
        let mut items_update = Vec::with_capacity(items.len());
        let mut items_response = Vec::with_capacity(items.len());

        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == mailbox.account_id {
                let mailbox_state = account
                    .mailbox_state
                    .entry(mailbox.mailbox_id)
                    .or_insert_with(Mailbox::default);
                let update_recent = mailbox_state.total_messages.is_none();
                for item in items {
                    match item {
                        Status::Messages => {
                            if let Some(value) = mailbox_state.total_messages {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::UidNext => {
                            if let Some(value) = mailbox_state.uid_next {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::UidValidity => {
                            if let Some(value) = mailbox_state.uid_validity {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::Unseen => {
                            if let Some(value) = mailbox_state.total_unseen {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::Deleted => {
                            if let Some(value) = mailbox_state.total_deleted {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::Size => {
                            if let Some(value) = mailbox_state.size {
                                items_response.push((*item, StatusItemType::Number(value as u64)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::HighestModSeq => {
                            items_response.push((
                                *item,
                                StatusItemType::Number(account.state_email.to_modseq()),
                            ));
                        }
                        Status::MailboxId => {
                            items_response.push((
                                *item,
                                StatusItemType::String(
                                    Id::from_parts(mailbox.account_id, mailbox.mailbox_id)
                                        .to_string(),
                                ),
                            ));
                        }
                        Status::Recent => {
                            if !update_recent {
                                items_response.push((*item, StatusItemType::Number(0)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                    }
                }
                break;
            }
        }

        if !items_update.is_empty() {
            // Retrieve latest values
            let mut values_update = Vec::with_capacity(items_update.len());
            let mailbox_message_ids = self
                .jmap
                .get_tag(
                    mailbox.account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    mailbox.mailbox_id,
                )
                .await?
                .map(Arc::new);
            let message_ids = self
                .jmap
                .get_document_ids(mailbox.account_id, Collection::Email)
                .await?;

            for item in items_update {
                let result = match item {
                    Status::Messages => mailbox_message_ids.as_ref().map(|v| v.len()).unwrap_or(0),
                    Status::UidNext => {
                        (self
                            .jmap
                            .core
                            .storage
                            .data
                            .get_counter(ValueKey {
                                account_id: mailbox.account_id,
                                collection: Collection::Mailbox.into(),
                                document_id: mailbox.mailbox_id,
                                class: ValueClass::Property(Property::EmailIds.into()),
                            })
                            .await
                            .map_err(|err| {
                                tracing::debug!(event = "error",
                                context = "store",
                                account_id = mailbox.account_id,
                                collection = ?Collection::Mailbox,
                                mailbox_id = mailbox.mailbox_id,
                                reason = ?err,
                                "Failed to obtain uid next");
                                StatusResponse::no("Mailbox unavailable.")
                            })?
                            + 1) as u64
                    }
                    Status::UidValidity => self
                        .jmap
                        .get_property::<Object<Value>>(
                            mailbox.account_id,
                            Collection::Mailbox,
                            mailbox.mailbox_id,
                            &Property::Value,
                        )
                        .await?
                        .and_then(|obj| obj.get(&Property::Cid).as_uint())
                        .ok_or_else(|| {
                            tracing::debug!(event = "error",
                                            context = "store",
                                            account_id = mailbox.account_id,
                                            collection = ?Collection::Mailbox,
                                            mailbox_id = mailbox.mailbox_id,
                                            "Failed to obtain uid validity");
                            StatusResponse::no("Mailbox unavailable.")
                        })?,
                    Status::Unseen => {
                        if let (Some(message_ids), Some(mailbox_message_ids)) =
                            (&message_ids, &mailbox_message_ids)
                        {
                            if let Some(mut seen) = self
                                .jmap
                                .get_tag(
                                    mailbox.account_id,
                                    Collection::Email,
                                    Property::Keywords,
                                    Keyword::Seen,
                                )
                                .await?
                            {
                                seen ^= message_ids;
                                seen &= mailbox_message_ids.as_ref();
                                seen.len()
                            } else {
                                mailbox_message_ids.len()
                            }
                        } else {
                            0
                        }
                    }
                    Status::Deleted => {
                        if let (Some(mailbox_message_ids), Some(mut deleted)) = (
                            &mailbox_message_ids,
                            self.jmap
                                .get_tag(
                                    mailbox.account_id,
                                    Collection::Email,
                                    Property::Keywords,
                                    Keyword::Deleted,
                                )
                                .await?,
                        ) {
                            deleted &= mailbox_message_ids.as_ref();
                            deleted.len()
                        } else {
                            0
                        }
                    }
                    Status::Size => {
                        if let Some(mailbox_message_ids) = &mailbox_message_ids {
                            self.calculate_mailbox_size(mailbox.account_id, mailbox_message_ids)
                                .await? as u64
                        } else {
                            0
                        }
                    }
                    Status::Recent => {
                        self.fetch_messages(&mailbox).await?;
                        0
                    }
                    Status::HighestModSeq | Status::MailboxId => {
                        unreachable!()
                    }
                };

                items_response.push((item, StatusItemType::Number(result)));
                values_update.push((item, result as u32));
            }

            // Update cache
            for account in self.mailboxes.lock().iter_mut() {
                if account.account_id == mailbox.account_id {
                    let mailbox_state = account
                        .mailbox_state
                        .entry(mailbox.mailbox_id)
                        .or_insert_with(Mailbox::default);

                    for (item, value) in values_update {
                        match item {
                            Status::Messages => mailbox_state.total_messages = value.into(),
                            Status::UidNext => mailbox_state.uid_next = value.into(),
                            Status::UidValidity => mailbox_state.uid_validity = value.into(),
                            Status::Unseen => mailbox_state.total_unseen = value.into(),
                            Status::Deleted => mailbox_state.total_deleted = value.into(),
                            Status::Size => mailbox_state.size = value.into(),
                            Status::Recent => {
                                items_response
                                    .iter_mut()
                                    .find(|(i, _)| *i == Status::Recent)
                                    .unwrap()
                                    .1 = StatusItemType::Number(0);
                            }
                            Status::HighestModSeq | Status::MailboxId => {
                                unreachable!()
                            }
                        }
                    }

                    break;
                }
            }
        }

        // Generate response
        Ok(StatusItem {
            mailbox_name,
            items: items_response,
        })
    }

    async fn calculate_mailbox_size(
        &self,
        account_id: u32,
        message_ids: &Arc<RoaringBitmap>,
    ) -> super::Result<u32> {
        let mut total_size = 0u32;
        self.jmap
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    IndexKeyPrefix {
                        account_id,
                        collection: Collection::Email.into(),
                        field: Property::Size.into(),
                    },
                    IndexKeyPrefix {
                        account_id,
                        collection: Collection::Email.into(),
                        field: u8::from(Property::Size) + 1,
                    },
                )
                .ascending()
                .no_values(),
                |key, _| {
                    let id_pos = key.len() - U32_LEN;
                    let document_id = key.deserialize_be_u32(id_pos)?;

                    if message_ids.contains(document_id) {
                        key.get(IndexKeyPrefix::len()..id_pos)
                            .ok_or_else(|| {
                                store::Error::InternalError("Invalid key length".to_string())
                            })
                            .and_then(u32::deserialize)
                            .map(|size| {
                                total_size += size;
                            })?;
                    }
                    Ok(true)
                },
            )
            .await
            .map_err(|err| {
                tracing::warn!(parent: &self.span,
                               event = "error", 
                               reason = ?err,
                               "Failed to calculate mailbox size");
                StatusResponse::database_failure()
            })?;

        Ok(total_size)
    }
}
