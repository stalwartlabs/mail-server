/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashMap;
use imap_proto::{
    parser::parse_sequence_set,
    receiver::{Request, Token},
    Command, ResponseCode, ResponseType, StatusResponse,
};
use trc::AddContext;

use crate::core::{ImapId, SavedSearch, SelectedMailbox, Session, SessionData};
use common::listener::SessionStream;
use jmap::{email::set::TagManager, mailbox::UidMailbox};
use jmap_proto::types::{
    acl::Acl, collection::Collection, id::Id, keyword::Keyword, property::Property,
    state::StateChange, type_state::DataType,
};
use store::{
    roaring::RoaringBitmap,
    write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_VALUE},
};

use super::{ImapContext, ToModSeq};

impl<T: SessionStream> Session<T> {
    pub async fn handle_expunge(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
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
            return Err(trc::Cause::Imap
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
                    trc::Cause::Imap
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
        data.expunge(mailbox.clone(), sequence)
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
    ) -> trc::Result<()> {
        // Obtain message ids
        let account_id = mailbox.id.account_id;
        let mut deleted_ids = self
            .jmap
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
                .jmap
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
            deleted_ids,
            &mut changelog,
        )
        .await
        .caused_by(trc::location!())?;

        // Write changes on source account
        if !changelog.is_empty() {
            let change_id = self.jmap.commit_changes(account_id, changelog).await?;
            self.jmap
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
        deleted_ids: RoaringBitmap,
        changelog: &mut ChangeLogBuilder,
    ) -> trc::Result<()> {
        let mailbox_id = UidMailbox::new_unassigned(mailbox_id);
        let mut destroy_ids = RoaringBitmap::new();

        for (id, mailbox_ids) in self
            .jmap
            .get_properties::<HashedValue<Vec<UidMailbox>>, _, _>(
                account_id,
                Collection::Email,
                &deleted_ids,
                Property::MailboxIds,
            )
            .await
            .caused_by(trc::location!())?
        {
            let mut mailboxes = TagManager::new(mailbox_ids);

            if mailboxes.current().contains(&mailbox_id) {
                if mailboxes.current().len() > 1 {
                    // Remove deleted flag
                    let (mut keywords, thread_id) = if let (Some(keywords), Some(thread_id)) = (
                        self.jmap
                            .get_property::<HashedValue<Vec<Keyword>>>(
                                account_id,
                                Collection::Email,
                                id,
                                Property::Keywords,
                            )
                            .await
                            .caused_by(trc::location!())?,
                        self.jmap
                            .get_property::<u32>(
                                account_id,
                                Collection::Email,
                                id,
                                Property::ThreadId,
                            )
                            .await
                            .caused_by(trc::location!())?,
                    ) {
                        (TagManager::new(keywords), thread_id)
                    } else {
                        continue;
                    };

                    // Untag message from this mailbox and remove Deleted flag
                    mailboxes.update(mailbox_id, false);
                    keywords.update(Keyword::Deleted, false);

                    // Write changes
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .update_document(id);
                    mailboxes.update_batch(&mut batch, Property::MailboxIds);
                    keywords.update_batch(&mut batch, Property::Keywords);
                    if changelog.change_id == u64::MAX {
                        changelog.change_id = self.jmap.assign_change_id(account_id).await?
                    }
                    batch.value(Property::Cid, changelog.change_id, F_VALUE);
                    match self.jmap.write_batch(batch).await {
                        Ok(_) => {
                            changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));
                            changelog.log_child_update(Collection::Mailbox, mailbox_id.mailbox_id);
                        }
                        Err(err) => {
                            if !err.matches(trc::Cause::AssertValue) {
                                return Err(err.caused_by(trc::location!()));
                            }
                        }
                    }
                } else {
                    destroy_ids.insert(id);
                }
            }
        }

        if !destroy_ids.is_empty() {
            // Delete message from all mailboxes
            let (changes, _) = self
                .jmap
                .emails_tombstone(account_id, destroy_ids)
                .await
                .caused_by(trc::location!())?;
            changelog.merge(changes);
        }

        Ok(())
    }
}
