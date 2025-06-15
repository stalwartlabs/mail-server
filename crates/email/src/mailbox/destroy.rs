/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{delete::EmailDeletion, metadata::MessageData},
};
use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
use directory::Permission;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    types::{acl::Acl, collection::Collection, property::Property},
};
use store::{roaring::RoaringBitmap, write::BatchBuilder};
use trc::AddContext;

pub trait MailboxDestroy: Sync + Send {
    fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> impl Future<Output = trc::Result<Result<Option<u64>, SetError>>> + Send;
}

impl MailboxDestroy for Server {
    async fn mailbox_destroy(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        remove_emails: bool,
    ) -> trc::Result<Result<Option<u64>, SetError>> {
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
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        if cache
            .mailboxes
            .items
            .iter()
            .any(|item| item.parent_id == document_id)
        {
            return Ok(Err(SetError::new(SetErrorType::MailboxHasChild)
                .with_description("Mailbox has at least one children.")));
        }

        // Verify that the mailbox is empty
        let mut batch = BatchBuilder::new();

        batch.with_account_id(account_id);

        let message_ids =
            RoaringBitmap::from_iter(cache.in_mailbox(document_id).map(|m| m.document_id));

        if !message_ids.is_empty() {
            if remove_emails {
                // If the message is in multiple mailboxes, untag it from the current mailbox,
                // otherwise delete it.

                let mut destroy_ids = RoaringBitmap::new();

                self.get_archives(
                    account_id,
                    Collection::Email,
                    &message_ids,
                    |message_id, message_data_| {
                        // Remove mailbox from list
                        let prev_message_data = message_data_
                            .to_unarchived::<MessageData>()
                            .caused_by(trc::location!())?;
                        if !prev_message_data
                            .inner
                            .mailboxes
                            .iter()
                            .any(|id| id.mailbox_id == document_id)
                        {
                            return Ok(true);
                        }

                        if prev_message_data.inner.mailboxes.len() == 1 {
                            // Delete message
                            destroy_ids.insert(message_id);
                            return Ok(true);
                        }

                        let mut new_message_data = prev_message_data
                            .deserialize()
                            .caused_by(trc::location!())?;

                        new_message_data
                            .mailboxes
                            .retain(|id| id.mailbox_id != document_id);

                        // Untag message from mailbox
                        batch
                            .with_collection(Collection::Email)
                            .update_document(message_id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_changes(new_message_data)
                                    .with_current(prev_message_data),
                            )
                            .caused_by(trc::location!())?
                            .commit_point();
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

                // Bulk delete messages
                if !destroy_ids.is_empty() {
                    self.emails_tombstone(account_id, &mut batch, destroy_ids)
                        .await?;
                }
            } else {
                return Ok(Err(SetError::new(SetErrorType::MailboxHasEmail)
                    .with_description("Mailbox is not empty.")));
            }
        }

        // Obtain mailbox
        if let Some(mailbox_) = self
            .get_archive(account_id, Collection::Mailbox, document_id)
            .await
            .caused_by(trc::location!())?
        {
            let mailbox = mailbox_
                .to_unarchived::<Mailbox>()
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
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .delete_document(document_id)
                .clear(Property::EmailIds)
                .custom(ObjectIndexBuilder::<_, ()>::new().with_current(mailbox))
                .caused_by(trc::location!())?;
        } else {
            return Ok(Err(SetError::not_found()));
        };

        if !batch.is_empty() {
            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id) => Ok(Ok(Some(change_id))),
                Err(err) if err.is_assertion_failure() => Ok(Err(SetError::forbidden()
                    .with_description(concat!(
                        "Another process modified a message in this mailbox ",
                        "while deleting it, please try again."
                    )))),
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        } else {
            Ok(Ok(None))
        }
    }
}
