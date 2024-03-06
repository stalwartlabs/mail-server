/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use imap_proto::{
    protocol::copy_move::Arguments, receiver::Request, Command, ResponseCode, ResponseType,
    StatusResponse,
};

use jmap::{email::set::TagManager, mailbox::UidMailbox};
use jmap_proto::{
    error::{method::MethodError, set::SetErrorType},
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::DataType,
    },
};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_VALUE};
use utils::listener::SessionStream;

use crate::core::{MailboxId, SelectedMailbox, Session, SessionData};

impl<T: SessionStream> Session<T> {
    pub async fn handle_copy_move(
        &mut self,
        request: Request<Command>,
        is_move: bool,
        is_uid: bool,
    ) -> crate::OpResult {
        match request.parse_copy_move(self.version) {
            Ok(arguments) => {
                let (data, src_mailbox) = self.state.mailbox_state();

                let is_qresync = self.is_qresync;
                tokio::spawn(async move {
                    // Refresh mailboxes
                    if let Err(err) = data.synchronize_mailboxes(false).await {
                        return data
                            .write_bytes(err.with_tag(arguments.tag).into_bytes())
                            .await;
                    }

                    // Make sure the mailbox exists.
                    let dest_mailbox =
                        if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
                            mailbox
                        } else {
                            return data
                                .write_bytes(
                                    StatusResponse::no("Destination mailbox does not exist.")
                                        .with_tag(arguments.tag)
                                        .with_code(ResponseCode::TryCreate)
                                        .into_bytes(),
                                )
                                .await;
                        };

                    // Check that the destination mailbox is not the same as the source mailbox.
                    if src_mailbox.id.account_id == dest_mailbox.account_id
                        && src_mailbox.id.mailbox_id == dest_mailbox.mailbox_id
                    {
                        return data
                            .write_bytes(
                                StatusResponse::no(
                                    "Source and destination mailboxes are the same.",
                                )
                                .with_tag(arguments.tag)
                                .with_code(ResponseCode::Cannot)
                                .into_bytes(),
                            )
                            .await;
                    }

                    if let Err(err) = data
                        .copy_move(
                            arguments,
                            src_mailbox,
                            dest_mailbox,
                            is_move,
                            is_uid,
                            is_qresync,
                        )
                        .await
                    {
                        data.write_bytes(err.into_bytes()).await;
                    }

                    true
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn copy_move(
        &self,
        arguments: Arguments,
        src_mailbox: Arc<SelectedMailbox>,
        dest_mailbox: MailboxId,
        is_move: bool,
        is_uid: bool,
        is_qresync: bool,
    ) -> Result<(), StatusResponse> {
        // Convert IMAP ids to JMAP ids.
        let ids = match src_mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
        {
            Ok(ids) => {
                if ids.is_empty() {
                    return Err(
                        StatusResponse::no("No messages were found.").with_tag(arguments.tag)
                    );
                }
                ids
            }
            Err(response) => {
                return Err(response.with_tag(arguments.tag));
            }
        };

        // Verify that the user can delete messages from the source mailbox.
        if is_move
            && !self
                .check_mailbox_acl(
                    src_mailbox.id.account_id,
                    src_mailbox.id.mailbox_id,
                    Acl::RemoveItems,
                )
                .await
                .map_err(|_| StatusResponse::database_failure().with_tag(&arguments.tag))?
        {
            return Err(StatusResponse::no(
                    "You do not have the required permissions to remove messages from the source mailbox.",
                )
                .with_tag(arguments.tag).with_code(ResponseCode::NoPerm));
        }

        // Verify that the user can append messages to the destination mailbox.
        let dest_mailbox_id = dest_mailbox.mailbox_id;
        if !self
            .check_mailbox_acl(dest_mailbox.account_id, dest_mailbox_id, Acl::AddItems)
            .await
            .map_err(|_| StatusResponse::database_failure().with_tag(&arguments.tag))?
        {
            return Err(StatusResponse::no(
                    "You do not have the required permissions to add messages to the destination mailbox.",
                )
                .with_tag(arguments.tag).with_code(ResponseCode::NoPerm));
        }

        let mut response = StatusResponse::completed(if is_move {
            Command::Move(is_uid)
        } else {
            Command::Copy(is_uid)
        });
        let mut changelog = ChangeLogBuilder::new();
        let mut did_move = false;
        let mut copied_ids = Vec::with_capacity(ids.len());
        if src_mailbox.id.account_id == dest_mailbox.account_id {
            // Mailboxes are in the same account
            let account_id = src_mailbox.id.account_id;
            let dest_mailbox_id = UidMailbox::new_unassigned(dest_mailbox_id);
            for (id, imap_id) in ids {
                // Obtain mailbox tags
                let (mut mailboxes, thread_id) = if let Some(result) = self
                    .get_mailbox_tags(account_id, id)
                    .await
                    .map_err(|_| StatusResponse::database_failure().with_tag(&arguments.tag))?
                {
                    result
                } else {
                    continue;
                };

                // Make sure the message still belongs to this mailbox
                if !mailboxes
                    .current()
                    .contains(&UidMailbox::new_unassigned(src_mailbox.id.mailbox_id))
                    || mailboxes.current().contains(&dest_mailbox_id)
                {
                    tracing::debug!(
                        account_id = account_id,
                        document_id = id,
                        "Message does not belong to this mailbox"
                    );
                    continue;
                }

                // Add destination folder
                mailboxes.update(dest_mailbox_id, true);
                if is_move {
                    mailboxes.update(UidMailbox::new_unassigned(src_mailbox.id.mailbox_id), false);
                }

                // Assign IMAP UIDs
                for uid_mailbox in mailboxes.inner_tags_mut() {
                    if uid_mailbox.uid == 0 {
                        uid_mailbox.uid = match self
                            .jmap
                            .assign_imap_uid(account_id, uid_mailbox.mailbox_id)
                            .await
                        {
                            Ok(assigned_uid) => {
                                debug_assert!(assigned_uid > 0);
                                copied_ids.push((imap_id.uid, assigned_uid));

                                assigned_uid
                            }
                            Err(_) => {
                                return Err(
                                    StatusResponse::database_failure().with_tag(&arguments.tag)
                                );
                            }
                        };
                    }
                }

                // Write changes
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .update_document(id);
                mailboxes.update_batch(&mut batch, Property::MailboxIds);
                if changelog.change_id == u64::MAX {
                    changelog.change_id =
                        self.jmap.assign_change_id(account_id).await.map_err(|_| {
                            StatusResponse::database_failure().with_tag(&arguments.tag)
                        })?
                }
                batch.value(Property::Cid, changelog.change_id, F_VALUE);
                match self.jmap.write_batch(batch).await {
                    Ok(_) => {
                        changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));
                        changelog.log_child_update(Collection::Mailbox, dest_mailbox_id.mailbox_id);
                        if is_move {
                            changelog
                                .log_child_update(Collection::Mailbox, src_mailbox.id.mailbox_id);
                            did_move = true;
                        }
                    }
                    Err(MethodError::ServerUnavailable) => {
                        response.rtype = ResponseType::No;
                        response.message = "Some messages could not be copied.".into();
                    }
                    Err(_) => {
                        return Err(StatusResponse::database_failure().with_tag(&arguments.tag));
                    }
                }
            }
        } else {
            // Obtain quota for target account
            let src_account_id = src_mailbox.id.account_id;
            let mut dest_change_id = None;
            let dest_account_id = dest_mailbox.account_id;
            let dest_quota = self
                .jmap
                .get_cached_access_token(dest_account_id)
                .await
                .ok_or_else(|| {
                    StatusResponse::no("Failed to obtain access token")
                        .with_code(ResponseCode::ContactAdmin)
                })?
                .quota as i64;
            for (id, imap_id) in ids {
                match self
                    .jmap
                    .copy_message(
                        src_account_id,
                        id,
                        dest_account_id,
                        dest_quota,
                        vec![dest_mailbox_id],
                        Vec::new(),
                        None,
                    )
                    .await
                {
                    Ok(Ok(email)) => {
                        dest_change_id = email.change_id.into();
                        if let Some(assigned_uid) = email.imap_uids.first() {
                            debug_assert!(*assigned_uid > 0);
                            copied_ids.push((imap_id.uid, *assigned_uid));
                        }
                    }
                    Ok(Err(err)) => {
                        if err.type_ != SetErrorType::NotFound {
                            response.rtype = ResponseType::No;
                            response.code = Some(err.type_.into());
                            if let Some(message) = err.description {
                                response.message = message;
                            }
                        }
                        continue;
                    }
                    Err(_) => {
                        return Err(StatusResponse::database_failure().with_tag(arguments.tag))
                    }
                };

                if is_move {
                    // Obtain mailbox tags
                    let (mut mailboxes, thread_id) = if let Some(result) = self
                        .get_mailbox_tags(src_account_id, id)
                        .await
                        .map_err(|_| StatusResponse::database_failure().with_tag(&arguments.tag))?
                    {
                        result
                    } else {
                        continue;
                    };

                    // Make sure the message is still in the mailbox
                    let src_mailbox_id = UidMailbox::new_unassigned(src_mailbox.id.mailbox_id);
                    if !mailboxes.current().contains(&src_mailbox_id) {
                        continue;
                    } else if mailboxes.current().len() == 1 {
                        // Delete message if it is no longer in any mailbox
                        if let Ok(changes) = self
                            .jmap
                            .email_delete(src_account_id, id)
                            .await
                            .map_err(|_| {
                                StatusResponse::database_failure().with_tag(&arguments.tag)
                            })?
                        {
                            did_move = true;
                            changelog.merge(changes);
                        }
                    } else {
                        // Remove mailbox tag from message
                        let mut batch = BatchBuilder::new();
                        batch
                            .with_account_id(src_account_id)
                            .with_collection(Collection::Email)
                            .update_document(id);
                        mailboxes.update(src_mailbox_id, false);
                        mailboxes.update_batch(&mut batch, Property::MailboxIds);
                        if changelog.change_id == u64::MAX {
                            changelog.change_id = self
                                .jmap
                                .assign_change_id(src_account_id)
                                .await
                                .map_err(|_| {
                                StatusResponse::database_failure().with_tag(&arguments.tag)
                            })?
                        }
                        batch.value(Property::Cid, changelog.change_id, F_VALUE);
                        match self.jmap.write_batch(batch).await {
                            Ok(_) => {
                                changelog
                                    .log_update(Collection::Email, Id::from_parts(thread_id, id));
                                changelog.log_child_update(
                                    Collection::Mailbox,
                                    src_mailbox_id.mailbox_id,
                                );
                                did_move = true;
                            }
                            Err(MethodError::ServerUnavailable) => {
                                response.rtype = ResponseType::No;
                                response.message = "Some messages could not be moved.".into();
                            }
                            Err(_) => {
                                return Err(
                                    StatusResponse::database_failure().with_tag(&arguments.tag)
                                );
                            }
                        }
                    }
                }
            }

            // Broadcast changes on destination account
            if let Some(change_id) = dest_change_id {
                self.jmap
                    .broadcast_state_change(
                        StateChange::new(dest_account_id)
                            .with_change(DataType::Email, change_id)
                            .with_change(DataType::Thread, change_id)
                            .with_change(DataType::Mailbox, change_id),
                    )
                    .await;
            }
        }

        // Write changes on source account
        if !changelog.is_empty() {
            let change_id = self
                .jmap
                .commit_changes(src_mailbox.id.account_id, changelog)
                .await
                .map_err(|_| {
                    StatusResponse::database_failure().with_tag(response.tag.as_ref().unwrap())
                })?;
            self.jmap
                .broadcast_state_change(
                    StateChange::new(src_mailbox.id.account_id)
                        .with_change(DataType::Email, change_id)
                        .with_change(DataType::Mailbox, change_id),
                )
                .await;
        }

        // Map copied JMAP Ids to IMAP UIDs in the destination folder.
        if copied_ids.is_empty() {
            return Err(if response.rtype != ResponseType::Ok {
                response
            } else {
                StatusResponse::no("No messages were copied.")
            }
            .with_tag(arguments.tag));
        }

        // Prepare response
        let uid_validity = self
            .get_uid_validity(&dest_mailbox)
            .await
            .map_err(|r| r.with_tag(&arguments.tag))?;
        let mut src_uids = Vec::with_capacity(copied_ids.len());
        let mut dest_uids = Vec::with_capacity(copied_ids.len());
        for (src_uid, dest_uid) in copied_ids {
            src_uids.push(src_uid);
            dest_uids.push(dest_uid);
        }
        src_uids.sort_unstable();
        dest_uids.sort_unstable();

        let response = if is_move {
            self.write_bytes(
                StatusResponse::ok("Copied UIDs")
                    .with_code(ResponseCode::CopyUid {
                        uid_validity,
                        src_uids,
                        dest_uids,
                    })
                    .into_bytes(),
            )
            .await;

            if did_move {
                // Resynchronize source mailbox on a successful move
                self.write_mailbox_changes(&src_mailbox, is_qresync)
                    .await
                    .map_err(|r| r.with_tag(&arguments.tag))?;
            }

            response.with_tag(arguments.tag).into_bytes()
        } else {
            response
                .with_tag(arguments.tag)
                .with_code(ResponseCode::CopyUid {
                    uid_validity,
                    src_uids,
                    dest_uids,
                })
                .into_bytes()
        };

        self.write_bytes(response).await;

        Ok(())
    }

    pub async fn get_mailbox_tags(
        &self,
        account_id: u32,
        id: u32,
    ) -> Result<Option<(TagManager<UidMailbox>, u32)>, MethodError> {
        // Obtain mailbox tags
        if let (Some(mailboxes), Some(thread_id)) = (
            self.jmap
                .get_property::<HashedValue<Vec<UidMailbox>>>(
                    account_id,
                    Collection::Email,
                    id,
                    Property::MailboxIds,
                )
                .await?,
            self.jmap
                .get_property::<u32>(account_id, Collection::Email, id, Property::ThreadId)
                .await?,
        ) {
            Ok(Some((TagManager::new(mailboxes), thread_id)))
        } else {
            tracing::debug!(
                account_id = account_id,
                document_id = id,
                "Message not found"
            );
            Ok(None)
        }
    }
}
