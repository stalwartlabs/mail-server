/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use imap_proto::{
    protocol::copy_move::Arguments, receiver::Request, Command, ResponseCode, ResponseType,
    StatusResponse,
};

use crate::{
    core::{MailboxId, SelectedMailbox, Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use jmap::{email::set::TagManager, mailbox::UidMailbox};
use jmap_proto::{
    error::set::SetErrorType,
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::DataType,
    },
};
use store::{
    roaring::RoaringBitmap,
    write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_VALUE},
};

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_copy_move(
        &mut self,
        request: Request<Command>,
        is_move: bool,
        is_uid: bool,
    ) -> trc::Result<()> {
        let op_start = Instant::now();
        let arguments = request.parse_copy_move(self.version)?;
        let (data, src_mailbox) = self.state.mailbox_state();
        let is_qresync = self.is_qresync;

        spawn_op!(data, {
            // Refresh mailboxes
            data.synchronize_mailboxes(false)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            // Make sure the mailbox exists.
            let dest_mailbox =
                if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
                    mailbox
                } else {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Destination mailbox does not exist.")
                        .code(ResponseCode::TryCreate)
                        .id(arguments.tag));
                };

            // Check that the destination mailbox is not the same as the source mailbox.
            if src_mailbox.id.account_id == dest_mailbox.account_id
                && src_mailbox.id.mailbox_id == dest_mailbox.mailbox_id
            {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Source and destination mailboxes are the same.")
                    .code(ResponseCode::Cannot)
                    .id(arguments.tag));
            }

            data.copy_move(
                arguments,
                src_mailbox,
                dest_mailbox,
                is_move,
                is_uid,
                is_qresync,
                op_start,
            )
            .await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn copy_move(
        &self,
        arguments: Arguments,
        src_mailbox: Arc<SelectedMailbox>,
        dest_mailbox: MailboxId,
        is_move: bool,
        is_uid: bool,
        is_qresync: bool,
        op_start: Instant,
    ) -> trc::Result<()> {
        // Convert IMAP ids to JMAP ids.
        let ids = src_mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        if ids.is_empty() {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("No messages were found.")
                .id(arguments.tag));
        }

        // Verify that the user can delete messages from the source mailbox.
        if is_move
            && !self
                .check_mailbox_acl(
                    src_mailbox.id.account_id,
                    src_mailbox.id.mailbox_id,
                    Acl::RemoveItems,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions to ",
                    "remove messages from the source mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(arguments.tag));
        }

        // Verify that the user can append messages to the destination mailbox.
        let dest_mailbox_id = dest_mailbox.mailbox_id;
        if !self
            .check_mailbox_acl(dest_mailbox.account_id, dest_mailbox_id, Acl::AddItems)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions to ",
                    "add messages to the destination mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(arguments.tag));
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
                    .imap_ctx(&arguments.tag, trc::location!())?
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
                        let assigned_uid = self
                            .jmap
                            .assign_imap_uid(account_id, uid_mailbox.mailbox_id)
                            .await
                            .imap_ctx(&arguments.tag, trc::location!())?;
                        debug_assert!(assigned_uid > 0);
                        copied_ids.push((imap_id.uid, assigned_uid));
                        uid_mailbox.uid = assigned_uid;
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
                    changelog.change_id = self
                        .jmap
                        .assign_change_id(account_id)
                        .await
                        .imap_ctx(&arguments.tag, trc::location!())?;
                }
                batch.value(Property::Cid, changelog.change_id, F_VALUE);
                self.jmap
                    .write_batch(batch)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
                changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));
                changelog.log_child_update(Collection::Mailbox, dest_mailbox_id.mailbox_id);
                if is_move {
                    changelog.log_child_update(Collection::Mailbox, src_mailbox.id.mailbox_id);
                    did_move = true;
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
                .imap_ctx(&arguments.tag, trc::location!())?
                .quota as i64;
            let mut destroy_ids = RoaringBitmap::new();
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
                        self.session_id,
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    Ok(email) => {
                        dest_change_id = email.change_id.into();
                        if let Some(assigned_uid) = email.imap_uids.first() {
                            debug_assert!(*assigned_uid > 0);
                            copied_ids.push((imap_id.uid, *assigned_uid));
                        }
                    }
                    Err(err) => {
                        if err.type_ != SetErrorType::NotFound {
                            response.rtype = ResponseType::No;
                            response.code = Some(err.type_.into());
                            if let Some(message) = err.description {
                                response.message = message;
                            }
                        }
                        continue;
                    }
                };

                if is_move {
                    destroy_ids.insert(id);
                }
            }

            // Untag or delete emails
            if !destroy_ids.is_empty() {
                self.email_untag_or_delete(
                    src_account_id,
                    src_mailbox.id.mailbox_id,
                    &destroy_ids,
                    &mut changelog,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
                did_move = true;
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
                .imap_ctx(&arguments.tag, trc::location!())?;
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
                trc::ImapEvent::Error
                    .into_err()
                    .details(response.message)
                    .ctx_opt(trc::Key::Code, response.code)
            } else {
                trc::ImapEvent::Error.into_err().details(if is_move {
                    "No messages were moved."
                } else {
                    "No messages were copied."
                })
            }
            .id(arguments.tag));
        }

        // Prepare response
        let uid_validity = self
            .get_uid_validity(&dest_mailbox)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        let mut src_uids = Vec::with_capacity(copied_ids.len());
        let mut dest_uids = Vec::with_capacity(copied_ids.len());
        for (src_uid, dest_uid) in copied_ids {
            src_uids.push(src_uid);
            dest_uids.push(dest_uid);
        }
        src_uids.sort_unstable();
        dest_uids.sort_unstable();

        trc::event!(
            Imap(if is_move {
                trc::ImapEvent::Move
            } else {
                trc::ImapEvent::Copy
            }),
            SpanId = self.session_id,
            Source = src_mailbox.id.account_id,
            Details = src_uids
                .iter()
                .map(|r| trc::Value::from(*r))
                .collect::<Vec<_>>(),
            AccountId = dest_mailbox.account_id,
            MailboxId = dest_mailbox.mailbox_id,
            Uid = dest_uids
                .iter()
                .map(|r| trc::Value::from(*r))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

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
            .await?;

            if did_move {
                // Resynchronize source mailbox on a successful move
                self.write_mailbox_changes(&src_mailbox, is_qresync)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
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

        self.write_bytes(response).await
    }

    pub async fn get_mailbox_tags(
        &self,
        account_id: u32,
        id: u32,
    ) -> trc::Result<Option<(TagManager<UidMailbox>, u32)>> {
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
            trc::event!(
                Store(trc::StoreEvent::NotFound),
                AccountId = account_id,
                Collection = Collection::Email,
                MessageId = id,
                SpanId = self.session_id,
                Details = "Message not found"
            );

            Ok(None)
        }
    }
}
