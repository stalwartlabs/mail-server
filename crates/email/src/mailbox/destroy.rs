/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use directory::Permission;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    types::{acl::Acl, collection::Collection, id::Id, property::Property},
};
use store::{
    Serialize, SerializeInfallible,
    query::Filter,
    roaring::RoaringBitmap,
    write::{Archive, Archiver, BatchBuilder, assert::HashedValue, log::ChangeLogBuilder},
};
use trc::AddContext;

use crate::message::delete::EmailDeletion;

use super::*;

pub trait MailboxDestroy: Sync + Send {
    fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        changes: &mut ChangeLogBuilder,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> impl Future<Output = trc::Result<Result<bool, SetError>>> + Send;
}

impl MailboxDestroy for Server {
    async fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        changes: &mut ChangeLogBuilder,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> trc::Result<Result<bool, SetError>> {
        // Internal folders cannot be deleted
        #[cfg(feature = "test_mode")]
        if [INBOX_ID, TRASH_ID].contains(&document_id)
            && !access_token.has_permission(Permission::DeleteSystemFolders)
        {
            return Ok(Err(SetError::forbidden().with_description(
                "You are not allowed to delete Inbox, Junk or Trash folders.",
            )));
        }

        #[cfg(not(feature = "test_mode"))]
        if [INBOX_ID, TRASH_ID, JUNK_ID].contains(&document_id)
            && !access_token.has_permission(Permission::DeleteSystemFolders)
        {
            return Ok(Err(SetError::forbidden().with_description(
                "You are not allowed to delete Inbox, Junk or Trash folders.",
            )));
        }

        // Verify that this mailbox does not have sub-mailboxes
        if !self
            .store()
            .filter(
                account_id,
                Collection::Mailbox,
                vec![Filter::eq(
                    Property::ParentId,
                    (document_id + 1).serialize(),
                )],
            )
            .await?
            .results
            .is_empty()
        {
            return Ok(Err(SetError::new(SetErrorType::MailboxHasChild)
                .with_description("Mailbox has at least one children.")));
        }

        // Verify that the mailbox is empty
        let mut did_remove_emails = false;
        if let Some(message_ids) = self
            .get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                document_id,
            )
            .await?
        {
            if remove_emails {
                // Flag removal for state change notification
                did_remove_emails = true;

                // If the message is in multiple mailboxes, untag it from the current mailbox,
                // otherwise delete it.
                let mut destroy_ids = RoaringBitmap::new();
                for (message_id, mailbox_ids) in self
                    .get_properties::<HashedValue<Archive>, _, _>(
                        account_id,
                        Collection::Email,
                        &message_ids,
                        Property::MailboxIds,
                    )
                    .await?
                {
                    // Remove mailbox from list
                    let mut mailbox_ids = mailbox_ids
                        .into_deserialized::<Vec<UidMailbox>>()
                        .caused_by(trc::location!())?;
                    let orig_len = mailbox_ids.inner.len();
                    mailbox_ids.inner.retain(|id| id.mailbox_id != document_id);
                    if mailbox_ids.inner.len() == orig_len {
                        continue;
                    }

                    if !mailbox_ids.inner.is_empty() {
                        // Obtain threadId
                        if let Some(thread_id) = self
                            .get_property::<u32>(
                                account_id,
                                Collection::Email,
                                message_id,
                                Property::ThreadId,
                            )
                            .await?
                        {
                            // Untag message from mailbox
                            let mut batch = BatchBuilder::new();
                            batch
                                .with_account_id(account_id)
                                .with_collection(Collection::Email)
                                .update_document(message_id)
                                .assert_value(Property::MailboxIds, &mailbox_ids)
                                .set(
                                    Property::MailboxIds,
                                    Archiver::new(mailbox_ids.inner)
                                        .serialize()
                                        .caused_by(trc::location!())?,
                                )
                                .untag(Property::MailboxIds, document_id);
                            match self.core.storage.data.write(batch.build()).await {
                                Ok(_) => changes.log_update(
                                    Collection::Email,
                                    Id::from_parts(thread_id, message_id),
                                ),
                                Err(err) if err.is_assertion_failure() => {
                                    return Ok(Err(SetError::forbidden().with_description(
                                        concat!(
                                            "Another process modified a message in this mailbox ",
                                            "while deleting it, please try again."
                                        ),
                                    )));
                                }
                                Err(err) => {
                                    return Err(err.caused_by(trc::location!()));
                                }
                            }
                        } else {
                            trc::event!(
                                Store(trc::StoreEvent::NotFound),
                                AccountId = account_id,
                                MessageId = message_id,
                                MailboxId = document_id,
                                Details = "Message does not have a threadId.",
                                CausedBy = trc::location!(),
                            );
                        }
                    } else {
                        // Delete message
                        destroy_ids.insert(message_id);
                    }
                }

                // Bulk delete messages
                if !destroy_ids.is_empty() {
                    let (mut change, _) = self.emails_tombstone(account_id, destroy_ids).await?;
                    change.changes.remove(&(Collection::Mailbox as u8));
                    changes.merge(change);
                }
            } else {
                return Ok(Err(SetError::new(SetErrorType::MailboxHasEmail)
                    .with_description("Mailbox is not empty.")));
            }
        }

        // Obtain mailbox
        if let Some(mailbox) = self
            .get_property::<HashedValue<Archive>>(
                account_id,
                Collection::Mailbox,
                document_id,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
        {
            let mailbox = mailbox
                .into_deserialized::<Mailbox>()
                .caused_by(trc::location!())?;
            // Validate ACLs
            if access_token.is_shared(account_id) {
                let acl = mailbox.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Administer) {
                    if !acl.contains(Acl::Delete) {
                        return Ok(Err(SetError::forbidden()
                            .with_description("You are not allowed to delete this mailbox.")));
                    } else if remove_emails && !acl.contains(Acl::RemoveItems) {
                        return Ok(Err(SetError::forbidden().with_description(
                            "You are not allowed to delete emails from this mailbox.",
                        )));
                    }
                }
            }

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .delete_document(document_id)
                .clear(Property::EmailIds)
                .custom(ObjectIndexBuilder::new().with_current(mailbox))
                .caused_by(trc::location!())?;

            match self.core.storage.data.write(batch.build()).await {
                Ok(_) => {
                    changes.log_delete(Collection::Mailbox, document_id);
                    Ok(Ok(did_remove_emails))
                }
                Err(err) if err.is_assertion_failure() => Ok(Err(SetError::forbidden()
                    .with_description(concat!(
                        "Another process modified this mailbox ",
                        "while deleting it, please try again."
                    )))),
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        } else {
            Ok(Err(SetError::not_found()))
        }
    }
}
