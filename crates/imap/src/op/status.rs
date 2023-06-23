/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::sync::Arc;

use ahash::AHashSet;
use imap_proto::{
    protocol::status::{Status, StatusItem, StatusItemType},
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};
use jmap_proto::types::{collection::Collection, id::Id, keyword::Keyword, property::Property};
use store::roaring::RoaringBitmap;
use store::Deserialize;
use tokio::io::AsyncRead;

use crate::core::{Mailbox, Session, SessionData};

impl<T: AsyncRead> Session<T> {
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

impl SessionData {
    pub async fn status(
        &self,
        mailbox_name: String,
        items: &[Status],
    ) -> super::Result<StatusItem> {
        // Get mailbox id
        let mailbox = if let Some(mailbox) = self.get_mailbox_by_name(&mailbox_name) {
            mailbox
        } else {
            return Err(
                StatusResponse::no("Mailbox does not exist.").with_code(ResponseCode::NonExistent)
            );
        };

        // Make sure all requested fields are up to date
        let mut items_update = AHashSet::with_capacity(items.len());
        let mut items_response = Vec::with_capacity(items.len());
        let mut do_synchronize = false;

        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == mailbox.account_id {
                let mailbox_state = account
                    .mailbox_state
                    .entry(mailbox.mailbox_id.as_ref().cloned().unwrap_or_default())
                    .or_insert_with(Mailbox::default);
                for item in items {
                    match item {
                        Status::Messages => {
                            if let Some(value) = mailbox_state.total_messages {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                            }
                        }
                        Status::UidNext => {
                            if let Some(value) = mailbox_state.uid_next {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                                do_synchronize = true;
                            }
                        }
                        Status::UidValidity => {
                            if let Some(value) = mailbox_state.uid_validity {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                                do_synchronize = true;
                            }
                        }
                        Status::Unseen => {
                            if let Some(value) = mailbox_state.total_unseen {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                            }
                        }
                        Status::Deleted => {
                            if let Some(value) = mailbox_state.total_deleted {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                            }
                        }
                        Status::Size => {
                            if let Some(value) = mailbox_state.size {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.insert(*item);
                            }
                        }
                        Status::HighestModSeq => {
                            items_response.push((
                                *item,
                                StatusItemType::Number(
                                    account.state_email.map(|id| id + 1).unwrap_or(0) as u32,
                                ),
                            ));
                        }
                        Status::MailboxId => {
                            items_response.push((
                                *item,
                                StatusItemType::String(
                                    Id::from_parts(
                                        mailbox.account_id,
                                        mailbox.mailbox_id.unwrap_or(u32::MAX),
                                    )
                                    .to_string(),
                                ),
                            ));
                        }
                        Status::Recent => {
                            items_response.push((*item, StatusItemType::Number(0)));
                        }
                    }
                }
                break;
            }
        }

        if !items_update.is_empty() {
            // Retrieve latest values
            let mut values_update = Vec::with_capacity(items_update.len());
            let mailbox_state = if do_synchronize {
                self.fetch_messages(&mailbox).await?.into()
            } else {
                None
            };

            if let Some(mailbox_id) = mailbox.mailbox_id {
                let mailbox_message_ids = self
                    .jmap
                    .get_tag(
                        mailbox.account_id,
                        Collection::Email,
                        Property::MailboxIds,
                        mailbox_id,
                    )
                    .await?
                    .map(Arc::new);
                let message_ids = self
                    .jmap
                    .get_document_ids(mailbox.account_id, Collection::Email)
                    .await?;

                for item in items_update {
                    let result = match item {
                        Status::Messages => {
                            message_ids.as_ref().map(|v| v.len()).unwrap_or(0) as u32
                        }
                        Status::UidNext => mailbox_state.as_ref().unwrap().uid_next,
                        Status::UidValidity => mailbox_state.as_ref().unwrap().uid_validity,
                        Status::Unseen => {
                            if let (Some(message_ids), Some(mailbox_message_ids), Some(mut seen)) = (
                                &message_ids,
                                &mailbox_message_ids,
                                self.jmap
                                    .get_tag(
                                        mailbox.account_id,
                                        Collection::Email,
                                        Property::Keywords,
                                        Keyword::Seen,
                                    )
                                    .await?,
                            ) {
                                seen ^= message_ids;
                                seen &= mailbox_message_ids.as_ref();
                                seen.len() as u32
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
                                deleted.len() as u32
                            } else {
                                0
                            }
                        }
                        Status::Size => {
                            if let Some(mailbox_message_ids) = &mailbox_message_ids {
                                self.calculate_mailbox_size(mailbox.account_id, mailbox_message_ids)
                                    .await?
                            } else {
                                0
                            }
                        }
                        Status::HighestModSeq | Status::MailboxId | Status::Recent => {
                            unreachable!()
                        }
                    };

                    items_response.push((item, StatusItemType::Number(result)));
                    values_update.push((item, result));
                }
            } else {
                let message_ids = Arc::new(
                    self.jmap
                        .get_document_ids(mailbox.account_id, Collection::Email)
                        .await?
                        .unwrap_or_default(),
                );
                for item in items_update {
                    let result = match item {
                        Status::Messages => message_ids.len() as u32,
                        Status::UidNext => mailbox_state.as_ref().unwrap().uid_next,
                        Status::UidValidity => mailbox_state.as_ref().unwrap().uid_validity,
                        Status::Unseen => self
                            .jmap
                            .get_tag(
                                mailbox.account_id,
                                Collection::Email,
                                Property::Keywords,
                                Keyword::Seen,
                            )
                            .await?
                            .map(|mut seen| {
                                seen ^= message_ids.as_ref();
                                seen.len()
                            })
                            .unwrap_or(0) as u32,
                        Status::Deleted => self
                            .jmap
                            .get_tag(
                                mailbox.account_id,
                                Collection::Email,
                                Property::Keywords,
                                Keyword::Deleted,
                            )
                            .await?
                            .map(|v| v.len())
                            .unwrap_or(0) as u32,
                        Status::Size => {
                            if !message_ids.is_empty() {
                                self.calculate_mailbox_size(mailbox.account_id, &message_ids)
                                    .await?
                            } else {
                                0
                            }
                        }
                        Status::HighestModSeq | Status::MailboxId | Status::Recent => {
                            unreachable!()
                        }
                    };

                    items_response.push((item, StatusItemType::Number(result)));
                    values_update.push((item, result));
                }
            }

            // Update cache
            for account in self.mailboxes.lock().iter_mut() {
                if account.account_id == mailbox.account_id {
                    let mailbox_state = account
                        .mailbox_state
                        .entry(mailbox.mailbox_id.as_ref().cloned().unwrap_or_default())
                        .or_insert_with(Mailbox::default);

                    for (item, value) in values_update {
                        match item {
                            Status::Messages => mailbox_state.total_messages = value.into(),
                            Status::UidNext => mailbox_state.uid_next = value.into(),
                            Status::UidValidity => mailbox_state.uid_validity = value.into(),
                            Status::Unseen => mailbox_state.total_unseen = value.into(),
                            Status::Deleted => mailbox_state.total_deleted = value.into(),
                            Status::Size => mailbox_state.size = value.into(),
                            Status::HighestModSeq | Status::MailboxId | Status::Recent => {
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
        self.jmap
            .store
            .index_values(
                (message_ids.clone(), 0u32),
                account_id,
                Collection::Email,
                Property::Size,
                true,
                |(message_ids, total_size), document_id, bytes| {
                    if message_ids.contains(document_id) {
                        u32::deserialize(bytes).map(|size| {
                            *total_size += size;
                        })?;
                    }
                    Ok(true)
                },
            )
            .await
            .map(|(_, size)| size)
            .map_err(|err| {
                tracing::warn!(parent: &self.span,
                               event = "error", 
                               reason = ?err,
                               "Failed to calculate mailbox size");
                StatusResponse::database_failure()
            })
    }
}
