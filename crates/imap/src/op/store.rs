/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::{
    core::{message::MAX_RETRIES, SelectedMailbox, Session, SessionData},
    spawn_op,
};
use ahash::AHashSet;
use common::listener::SessionStream;
use imap_proto::{
    protocol::{
        fetch::{DataItem, FetchItem},
        store::{Arguments, Operation, Response},
        Flag, ImapResponse,
    },
    receiver::Request,
    Command, ResponseCode, ResponseType, StatusResponse,
};
use jmap::{email::set::TagManager, mailbox::UidMailbox};
use jmap_proto::types::{
    acl::Acl, collection::Collection, id::Id, keyword::Keyword, property::Property,
    state::StateChange, type_state::DataType,
};
use store::{
    query::log::{Change, Query},
    write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_VALUE},
};

use super::{FromModSeq, ImapContext};

impl<T: SessionStream> Session<T> {
    pub async fn handle_store(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        let arguments = request.parse_store()?;

        let (data, mailbox) = self.state.select_data();
        let is_condstore = self.is_condstore || mailbox.is_condstore;

        spawn_op!(data, {
            let response = data.store(arguments, mailbox, is_uid, is_condstore).await?;

            data.write_bytes(response).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn store(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        is_condstore: bool,
    ) -> trc::Result<Vec<u8>> {
        // Resync messages if needed
        let account_id = mailbox.id.account_id;
        self.synchronize_messages(&mailbox)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let mut ids = mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        if ids.is_empty() {
            return Ok(StatusResponse::completed(Command::Store(is_uid))
                .with_tag(arguments.tag)
                .into_bytes());
        }

        // Verify that the user can modify messages in this mailbox.
        if !self
            .check_mailbox_acl(
                mailbox.id.account_id,
                mailbox.id.mailbox_id,
                Acl::ModifyItems,
            )
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::Cause::Imap
                .into_err()
                .details(
                    "You do not have the required permissions to modify messages in this mailbox.",
                )
                .id(arguments.tag)
                .code(ResponseCode::NoPerm)
                .caused_by(trc::location!()));
        }

        // Filter out unchanged since ids
        let mut response_code = None;
        let mut unchanged_failed = false;
        if let Some(unchanged_since) = arguments.unchanged_since {
            // Obtain changes since the modseq.
            let changelog = self
                .jmap
                .changes_(
                    account_id,
                    Collection::Email,
                    Query::from_modseq(unchanged_since),
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            let mut modified = mailbox
                .sequence_expand_missing(&arguments.sequence_set, is_uid)
                .await;

            // Add all IDs that changed in this mailbox
            for change in changelog.changes {
                let (Change::Insert(id)
                | Change::Update(id)
                | Change::ChildUpdate(id)
                | Change::Delete(id)) = change;
                let id = (id & u32::MAX as u64) as u32;
                if let Some(imap_id) = ids.remove(&id) {
                    if is_uid {
                        modified.push(imap_id.uid);
                    } else {
                        modified.push(imap_id.seqnum);
                        if matches!(change, Change::Delete(_)) {
                            unchanged_failed = true;
                        }
                    }
                }
            }

            if !modified.is_empty() {
                modified.sort_unstable();
                response_code = ResponseCode::Modified { ids: modified }.into();
            }
        }

        // Build response
        let mut response = if !unchanged_failed {
            StatusResponse::completed(Command::Store(is_uid))
        } else {
            StatusResponse::no("Some of the messages no longer exist.")
        }
        .with_tag(arguments.tag);
        if let Some(response_code) = response_code {
            response = response.with_code(response_code)
        }
        if ids.is_empty() {
            return Ok(response.into_bytes());
        }
        let mut items = Response {
            items: Vec::with_capacity(ids.len()),
        };

        // Process each change
        let set_keywords = arguments
            .keywords
            .into_iter()
            .map(Keyword::from)
            .collect::<Vec<_>>();
        let mut changelog = ChangeLogBuilder::new();
        let mut changed_mailboxes = AHashSet::new();
        'outer: for (id, imap_id) in ids {
            let mut try_count = 0;
            loop {
                // Obtain current keywords
                let (mut keywords, thread_id) = if let (Some(keywords), Some(thread_id)) = (
                    self.jmap
                        .get_property::<HashedValue<Vec<Keyword>>>(
                            account_id,
                            Collection::Email,
                            id,
                            Property::Keywords,
                        )
                        .await
                        .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?,
                    self.jmap
                        .get_property::<u32>(account_id, Collection::Email, id, Property::ThreadId)
                        .await
                        .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?,
                ) {
                    (TagManager::new(keywords), thread_id)
                } else {
                    continue 'outer;
                };

                // Apply changes
                match arguments.operation {
                    Operation::Set => {
                        keywords.set(set_keywords.clone());
                    }
                    Operation::Add => {
                        for keyword in &set_keywords {
                            keywords.update(keyword.clone(), true);
                        }
                    }
                    Operation::Clear => {
                        for keyword in &set_keywords {
                            keywords.update(keyword.clone(), false);
                        }
                    }
                }

                if keywords.has_changes() {
                    // Convert keywords to flags
                    let seen_changed = keywords
                        .changed_tags()
                        .any(|keyword| keyword == &Keyword::Seen);
                    let flags = if !arguments.is_silent {
                        keywords
                            .current()
                            .iter()
                            .cloned()
                            .map(Flag::from)
                            .collect::<Vec<_>>()
                    } else {
                        vec![]
                    };

                    // Write changes
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .update_document(id);
                    keywords.update_batch(&mut batch, Property::Keywords);
                    if changelog.change_id == u64::MAX {
                        changelog.change_id = self
                            .jmap
                            .assign_change_id(account_id)
                            .await
                            .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?
                    }
                    batch.value(Property::Cid, changelog.change_id, F_VALUE);
                    match self.jmap.write_batch(batch).await {
                        Ok(_) => {
                            // Set all current mailboxes as changed if the Seen tag changed
                            if seen_changed {
                                if let Some(mailboxes) = self
                                    .jmap
                                    .get_property::<Vec<UidMailbox>>(
                                        account_id,
                                        Collection::Email,
                                        id,
                                        Property::MailboxIds,
                                    )
                                    .await
                                    .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?
                                {
                                    for mailbox_id in mailboxes {
                                        changed_mailboxes.insert(mailbox_id.mailbox_id);
                                    }
                                }
                            }
                            changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));

                            // Add item to response
                            let modseq = changelog.change_id + 1;
                            if !arguments.is_silent {
                                let mut data_items = vec![DataItem::Flags { flags }];
                                if is_uid {
                                    data_items.push(DataItem::Uid { uid: imap_id.uid });
                                }
                                if is_condstore {
                                    data_items.push(DataItem::ModSeq { modseq });
                                }
                                items.items.push(FetchItem {
                                    id: imap_id.seqnum,
                                    items: data_items,
                                });
                            } else if is_condstore {
                                items.items.push(FetchItem {
                                    id: imap_id.seqnum,
                                    items: if is_uid {
                                        vec![
                                            DataItem::ModSeq { modseq },
                                            DataItem::Uid { uid: imap_id.uid },
                                        ]
                                    } else {
                                        vec![DataItem::ModSeq { modseq }]
                                    },
                                });
                            }
                        }
                        Err(err) if err.is_assertion_failure() => {
                            if try_count < MAX_RETRIES {
                                try_count += 1;
                                continue;
                            } else {
                                response.rtype = ResponseType::No;
                                response.message = "Some messages could not be updated.".into();
                            }
                        }
                        Err(err) => {
                            return Err(err.id(response.tag.unwrap()));
                        }
                    }
                }
                break;
            }
        }

        // Log mailbox changes
        for mailbox_id in &changed_mailboxes {
            changelog.log_child_update(Collection::Mailbox, *mailbox_id);
        }

        // Write changes
        if !changelog.is_empty() {
            let change_id = self
                .jmap
                .commit_changes(account_id, changelog)
                .await
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
            self.jmap
                .broadcast_state_change(if !changed_mailboxes.is_empty() {
                    StateChange::new(account_id)
                        .with_change(DataType::Email, change_id)
                        .with_change(DataType::Mailbox, change_id)
                } else {
                    StateChange::new(account_id).with_change(DataType::Email, change_id)
                })
                .await;
        }

        // Send response
        Ok(response.serialize(items.serialize()))
    }
}
