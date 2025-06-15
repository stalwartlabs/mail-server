/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ToModSeq;
use crate::{
    core::{Mailbox, Session, SessionData},
    op::ImapContext,
    spawn_op,
};
use common::listener::SessionStream;
use directory::Permission;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    parser::PushUnique,
    protocol::status::{Status, StatusItem, StatusItemType},
    receiver::Request,
};
use jmap_proto::types::{collection::Collection, id::Id, keyword::Keyword, property::Property};
use std::time::Instant;
use store::{Deserialize, U32_LEN};
use store::{
    IndexKeyPrefix, IterateParams, roaring::RoaringBitmap, write::key::DeserializeBigEndian,
};
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_status(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStatus)?;

        let version = self.version;
        let data = self.state.session_data();

        spawn_op!(data, {
            let mut did_sync = false;

            for request in requests.into_iter() {
                match request.parse_status(version) {
                    Ok(arguments) => {
                        let op_start = Instant::now();
                        if !did_sync {
                            // Refresh mailboxes
                            data.synchronize_mailboxes(false)
                                .await
                                .imap_ctx(&arguments.tag, trc::location!())?;
                            did_sync = true;
                        }

                        // Fetch status
                        let status = data
                            .status(arguments.mailbox_name, &arguments.items)
                            .await
                            .imap_ctx(&arguments.tag, trc::location!())?;

                        trc::event!(
                            Imap(trc::ImapEvent::Status),
                            SpanId = data.session_id,
                            MailboxName = status.mailbox_name.clone(),
                            Details = arguments
                                .items
                                .iter()
                                .map(|c| trc::Value::from(format!("{c:?}")))
                                .collect::<Vec<_>>(),
                            Elapsed = op_start.elapsed()
                        );

                        let mut buf = Vec::with_capacity(32);
                        status.serialize(&mut buf, version.is_rev2());
                        data.write_bytes(
                            StatusResponse::completed(Command::Status)
                                .with_tag(arguments.tag)
                                .serialize(buf),
                        )
                        .await?;
                    }
                    Err(err) => data.write_error(err).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn status(&self, mailbox_name: String, items: &[Status]) -> trc::Result<StatusItem> {
        // Get mailbox id
        let mailbox = if let Some(mailbox) = self.get_mailbox_by_name(&mailbox_name) {
            mailbox
        } else {
            // Some IMAP clients will try to get the status of a mailbox with the NoSelect flag
            return if mailbox_name == self.server.core.jmap.shared_folder
                || mailbox_name
                    .split_once('/')
                    .is_some_and(|(base_name, path)| {
                        base_name == self.server.core.jmap.shared_folder && !path.contains('/')
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
                                    | Status::HighestModSeq
                                    | Status::DeletedStorage => StatusItemType::Number(0),
                                    Status::UidNext | Status::UidValidity => {
                                        StatusItemType::Number(1)
                                    }
                                    Status::MailboxId => StatusItemType::String("none".into()),
                                },
                            )
                        })
                        .collect(),
                })
            } else {
                Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent))
            };
        };

        // Make sure all requested fields are up to date
        let mut items_update = Vec::with_capacity(items.len());
        let mut items_response = Vec::with_capacity(items.len());

        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == mailbox.account_id {
                let mailbox_state =
                    if let Some(mailbox_state) = account.mailbox_state.get(&mailbox.mailbox_id) {
                        mailbox_state
                    } else {
                        continue;
                    };
                for item in items {
                    match item {
                        Status::Messages => {
                            items_response.push((
                                *item,
                                StatusItemType::Number(mailbox_state.total_messages),
                            ));
                        }
                        Status::UidNext => {
                            items_response
                                .push((*item, StatusItemType::Number(mailbox_state.uid_next)));
                        }
                        Status::UidValidity => {
                            items_response
                                .push((*item, StatusItemType::Number(mailbox_state.uid_validity)));
                        }
                        Status::Unseen => {
                            items_response
                                .push((*item, StatusItemType::Number(mailbox_state.total_unseen)));
                        }
                        Status::Deleted => {
                            items_response
                                .push((*item, StatusItemType::Number(mailbox_state.total_deleted)));
                        }
                        Status::DeletedStorage => {
                            if let Some(value) = mailbox_state.total_deleted_storage {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::Size => {
                            if let Some(value) = mailbox_state.size {
                                items_response.push((*item, StatusItemType::Number(value)));
                            } else {
                                items_update.push_unique(*item);
                            }
                        }
                        Status::HighestModSeq => {
                            items_response.push((
                                *item,
                                StatusItemType::Number(account.last_change_id.to_modseq()),
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

            let cache = self
                .server
                .get_cached_messages(mailbox.account_id)
                .await
                .caused_by(trc::location!())?;

            for item in items_update {
                let result = match item {
                    Status::DeletedStorage => self
                        .calculate_mailbox_size(
                            mailbox.account_id,
                            &RoaringBitmap::from_iter(
                                cache
                                    .in_mailbox_with_keyword(mailbox.mailbox_id, &Keyword::Deleted)
                                    .map(|x| x.document_id),
                            ),
                        )
                        .await
                        .caused_by(trc::location!())?,
                    Status::Size => self
                        .calculate_mailbox_size(
                            mailbox.account_id,
                            &RoaringBitmap::from_iter(
                                cache.in_mailbox(mailbox.mailbox_id).map(|x| x.document_id),
                            ),
                        )
                        .await
                        .caused_by(trc::location!())?,

                    _ => {
                        unreachable!()
                    }
                };

                items_response.push((item, StatusItemType::Number(result)));
                values_update.push((item, result));
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
                            Status::DeletedStorage => {
                                mailbox_state.total_deleted_storage = value.into()
                            }
                            Status::Size => mailbox_state.size = value.into(),
                            Status::Recent => {
                                items_response
                                    .iter_mut()
                                    .find(|(i, _)| *i == Status::Recent)
                                    .unwrap()
                                    .1 = StatusItemType::Number(0);
                            }
                            _ => {
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
        message_ids: &RoaringBitmap,
    ) -> trc::Result<u64> {
        let mut total_size = 0u64;
        self.server
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
                            .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
                            .and_then(u32::deserialize)
                            .map(|size| {
                                total_size += size as u64;
                            })?;
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| total_size)
    }
}
