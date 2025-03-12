/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use ahash::AHashMap;
use directory::Permission;
use email::message::{delete::EmailDeletion, metadata::MessageData};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    parser::parse_sequence_set,
    receiver::{Request, Token},
};
use trc::AddContext;

use crate::core::{SavedSearch, SelectedMailbox, Session, SessionData};
use common::{ImapId, listener::SessionStream, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{
    acl::Acl, collection::Collection, id::Id, keyword::Keyword, property::Property,
    state::StateChange, type_state::DataType,
};
use store::{
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, log::ChangeLogBuilder},
};

use super::{ImapContext, ToModSeq};

impl<T: SessionStream> Session<T> {
    pub async fn handle_expunge(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapExpunge)?;

        let op_start = Instant::now();
        let (data, mailbox) = self.state.select_data();

        // Validate ACL
        if !data
            .check_mailbox_acl(
                mailbox.id.account_id,
                mailbox.id.mailbox_id,
                Acl::RemoveItems,
            )
            .await
            .imap_ctx(&request.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions ",
                    "to remove messages from this mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(request.tag));
        }

        // Parse sequence to operate on
        let sequence = match request.tokens.into_iter().next() {
            Some(Token::Argument(value)) if is_uid => {
                let sequence = parse_sequence_set(&value).map_err(|err| {
                    trc::ImapEvent::Error
                        .into_err()
                        .details(err)
                        .ctx(trc::Key::Type, ResponseType::Bad)
                        .id(request.tag.clone())
                })?;
                Some(
                    mailbox
                        .sequence_to_ids(&sequence, true)
                        .await
                        .map_err(|err| err.id(request.tag.clone()))?,
                )
            }

            _ => None,
        };

        // Expunge
        data.expunge(mailbox.clone(), sequence, op_start)
            .await
            .imap_ctx(&request.tag, trc::location!())?;

        // Clear saved searches
        *mailbox.saved_search.lock() = SavedSearch::None;

        // Synchronize messages
        let modseq = data
            .write_mailbox_changes(&mailbox, self.is_qresync)
            .await
            .imap_ctx(&request.tag, trc::location!())?;
        let mut response =
            StatusResponse::completed(Command::Expunge(is_uid)).with_tag(request.tag);

        if self.is_condstore {
            response = response.with_code(ResponseCode::HighestModseq {
                modseq: modseq.to_modseq(),
            });
        }

        self.write_bytes(response.into_bytes()).await
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn expunge(
        &self,
        mailbox: Arc<SelectedMailbox>,
        sequence: Option<AHashMap<u32, ImapId>>,
        op_start: Instant,
    ) -> trc::Result<()> {
        // Obtain message ids
        let account_id = mailbox.id.account_id;
        let mut deleted_ids = self
            .server
            .get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                mailbox.id.mailbox_id,
            )
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default()
            & self
                .server
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::Keywords,
                    Keyword::Deleted,
                )
                .await
                .caused_by(trc::location!())?
                .unwrap_or_default();

        // Filter by sequence
        if let Some(sequence) = &sequence {
            deleted_ids &= RoaringBitmap::from_iter(sequence.keys());
        }

        // Delete ids
        let mut changelog = ChangeLogBuilder::new();
        self.email_untag_or_delete(
            account_id,
            mailbox.id.mailbox_id,
            &deleted_ids,
            &mut changelog,
        )
        .await
        .caused_by(trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::Expunge),
            SpanId = self.session_id,
            AccountId = account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = deleted_ids.iter().map(trc::Value::from).collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Write changes on source account
        if !changelog.is_empty() {
            let change_id = self.server.commit_changes(account_id, changelog).await?;
            self.server
                .broadcast_state_change(
                    StateChange::new(account_id)
                        .with_change(DataType::Email, change_id)
                        .with_change(DataType::Mailbox, change_id)
                        .with_change(DataType::Thread, change_id),
                )
                .await;
        }

        Ok(())
    }

    pub async fn email_untag_or_delete(
        &self,
        account_id: u32,
        mailbox_id: u32,
        deleted_ids: &RoaringBitmap,
        changelog: &mut ChangeLogBuilder,
    ) -> trc::Result<()> {
        let mut destroy_ids = RoaringBitmap::new();

        for (id, data_) in self
            .server
            .get_properties::<Archive<AlignedBytes>, _>(
                account_id,
                Collection::Email,
                deleted_ids,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
        {
            let data = data_
                .to_unarchived::<MessageData>()
                .caused_by(trc::location!())?;

            if !data.inner.has_mailbox_id(mailbox_id) {
                continue;
            } else if data.inner.mailboxes.len() == 1 {
                destroy_ids.insert(id);
                continue;
            }

            // Prepare changes
            let mut new_data = data.deserialize().caused_by(trc::location!())?;
            if changelog.change_id == u64::MAX {
                changelog.change_id = self.server.assign_change_id(account_id)?
            }
            new_data.change_id = changelog.change_id;
            let thread_id = new_data.thread_id;

            // Untag message from this mailbox and remove Deleted flag
            new_data.remove_mailbox(mailbox_id);
            new_data.remove_keyword(&Keyword::Deleted);

            // Write changes
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .update_document(id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(data)
                        .with_changes(new_data),
                )
                .caused_by(trc::location!())?;
            match self
                .server
                .store()
                .write(batch)
                .await
                .caused_by(trc::location!())
            {
                Ok(_) => {
                    changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));
                    changelog.log_child_update(Collection::Mailbox, mailbox_id);
                }
                Err(err) => {
                    if !err.is_assertion_failure() {
                        return Err(err.caused_by(trc::location!()));
                    }
                }
            }
        }

        if !destroy_ids.is_empty() {
            // Delete message from all mailboxes
            let (changes, _) = self
                .server
                .emails_tombstone(account_id, destroy_ids)
                .await
                .caused_by(trc::location!())?;
            changelog.merge(changes);
        }

        Ok(())
    }
}
