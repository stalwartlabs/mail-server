/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FromModSeq, ImapContext};
use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
use ahash::AHashSet;
use common::{listener::SessionStream, storage::index::ObjectIndexBuilder};
use directory::Permission;
use email::message::{bayes::EmailBayesTrain, ingest::EmailIngest, metadata::MessageData};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        Flag, ImapResponse,
        fetch::{DataItem, FetchItem},
        store::{Arguments, Operation, Response},
    },
    receiver::Request,
};
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    keyword::Keyword,
};
use std::{sync::Arc, time::Instant};
use store::{
    query::log::{Change, Query},
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_store(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStore)?;

        let op_start = Instant::now();
        let arguments = request.parse_store()?;
        let (data, mailbox) = self.state.select_data();
        let is_condstore = self.is_condstore || mailbox.is_condstore;

        spawn_op!(data, {
            let response = data
                .store(arguments, mailbox, is_uid, is_condstore, op_start)
                .await?;

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
        op_start: Instant,
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
            return Err(trc::ImapEvent::Error
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
                .server
                .store()
                .changes(
                    account_id,
                    SyncCollection::Email,
                    Query::from_modseq(unchanged_since),
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            let mut modified = mailbox
                .sequence_expand_missing(&arguments.sequence_set, is_uid)
                .await;

            // Add all IDs that changed in this mailbox
            for (id, is_delete) in changelog.changes.into_iter().filter_map(|change| {
                change.item_id().map(|id| {
                    (
                        (id & u32::MAX as u64) as u32,
                        matches!(change, Change::DeleteItem(_)),
                    )
                })
            }) {
                if let Some(imap_id) = ids.remove(&id) {
                    if is_uid {
                        modified.push(imap_id.uid);
                    } else {
                        modified.push(imap_id.seqnum);
                        if is_delete {
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
            trc::event!(
                Imap(trc::ImapEvent::Store),
                SpanId = self.session_id,
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Type = format!("{:?}", arguments.operation),
                Details = arguments
                    .keywords
                    .iter()
                    .map(|c| trc::Value::from(format!("{c:?}")))
                    .collect::<Vec<_>>(),
                Elapsed = op_start.elapsed()
            );

            return Ok(response.into_bytes());
        }
        let mut items = Response {
            items: Vec::with_capacity(ids.len()),
        };

        // Process each change
        let set_keywords = arguments
            .keywords
            .iter()
            .map(|k| Keyword::from(k.clone()))
            .collect::<Vec<_>>();
        let access_token = self
            .server
            .get_access_token(account_id)
            .await
            .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
        let mut changed_mailboxes = AHashSet::new();
        let can_spam_train = self.server.email_bayes_can_train(&access_token);
        let mut has_spam_train_tasks = false;
        let mut batch = BatchBuilder::new();

        for (id, imap_id) in &ids {
            // Obtain message data
            let data_ = if let Some(data) = self
                .server
                .get_archive(account_id, Collection::Email, *id)
                .await
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?
            {
                data
            } else {
                continue;
            };

            // Deserialize
            let data = data_
                .to_unarchived::<MessageData>()
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
            let mut new_data = data
                .deserialize()
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;

            // Apply changes
            let mut seen_changed = false;
            match arguments.operation {
                Operation::Set => {
                    seen_changed = set_keywords.contains(&Keyword::Seen)
                        != new_data.has_keyword(&Keyword::Seen);
                    new_data.set_keywords(set_keywords.clone());
                }
                Operation::Add => {
                    for keyword in &set_keywords {
                        if new_data.add_keyword(keyword.clone()) && keyword == &Keyword::Seen {
                            seen_changed = true;
                        }
                    }
                }
                Operation::Clear => {
                    for keyword in &set_keywords {
                        if new_data.remove_keyword(keyword) && keyword == &Keyword::Seen {
                            seen_changed = true;
                        }
                    }
                }
            }

            if !new_data.has_keyword_changes(data.inner) {
                continue;
            }

            // Train spam filter
            let mut train_spam = None;
            if can_spam_train {
                for keyword in new_data.added_keywords(data.inner) {
                    if keyword == &Keyword::Junk {
                        train_spam = Some(true);
                        break;
                    } else if keyword == &Keyword::NotJunk {
                        train_spam = Some(false);
                        break;
                    }
                }
                if train_spam.is_none() {
                    for keyword in new_data.removed_keywords(data.inner) {
                        if keyword == &Keyword::Junk {
                            train_spam = Some(false);
                            break;
                        }
                    }
                }
            };

            // Convert keywords to flags
            let flags = if !arguments.is_silent {
                new_data
                    .keywords
                    .iter()
                    .cloned()
                    .map(Flag::from)
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            // Set all current mailboxes as changed if the Seen tag changed
            if seen_changed {
                for mailbox_id in new_data.mailboxes.iter() {
                    changed_mailboxes.insert(mailbox_id.mailbox_id);
                }
            }

            // Write changes
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .update_document(*id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(data)
                        .with_changes(new_data),
                )
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;

            // Add spam train task
            if let Some(learn_spam) = train_spam {
                batch.set(
                    ValueClass::TaskQueue(
                        self.server
                            .email_bayes_queue_task_build(account_id, *id, learn_spam)
                            .await
                            .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?,
                    ),
                    vec![],
                );
                has_spam_train_tasks = true;
            }

            // Set commit point
            batch.commit_point();

            // Add item to response
            if !arguments.is_silent {
                let mut data_items = vec![DataItem::Flags { flags }];
                if is_uid {
                    data_items.push(DataItem::Uid { uid: imap_id.uid });
                }
                items.items.push(FetchItem {
                    id: imap_id.seqnum,
                    items: data_items,
                });
            } else if is_condstore {
                items.items.push(FetchItem {
                    id: imap_id.seqnum,
                    items: if is_uid {
                        vec![DataItem::Uid { uid: imap_id.uid }]
                    } else {
                        vec![]
                    },
                });
            }
        }

        // Log mailbox changes
        if !changed_mailboxes.is_empty() {
            for parent_id in changed_mailboxes {
                batch.log_container_property_change(SyncCollection::Email, parent_id);
            }
        }

        // Trigger Bayes training
        if has_spam_train_tasks {
            self.server.notify_task_queue();
        }

        // Write changes
        if !batch.is_empty() {
            match self
                .server
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(mailbox.id.account_id))
                .caused_by(trc::location!())
            {
                Ok(change_id) => {
                    if is_condstore {
                        let modseq = change_id + 1;
                        for item in items.items.iter_mut() {
                            item.items.push(DataItem::ModSeq { modseq });
                        }
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    items.items.clear();
                    response.rtype = ResponseType::No;
                    response.message = "Some messages were modified by another process.".into();
                }
                Err(err) => {
                    return Err(err.id(response.tag.unwrap()));
                }
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::Store),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = ids
                .iter()
                .map(|id| trc::Value::from(*id.0))
                .collect::<Vec<_>>(),
            Type = format!("{:?}", arguments.operation),
            Details = arguments
                .keywords
                .iter()
                .map(|c| trc::Value::from(format!("{c:?}")))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Send response
        Ok(response.serialize(items.serialize()))
    }
}
