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
    SerializeInfallible,
    query::Filter,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, log::ChangeLogBuilder},
};
use trc::AddContext;

use crate::message::{delete::EmailDeletion, metadata::MessageData};

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
                for (message_id, message_data_) in self
                    .get_properties::<Archive<AlignedBytes>, _>(
                        account_id,
                        Collection::Email,
                        &message_ids,
                        Property::Value,
                    )
                    .await?
                {
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
                        continue;
                    }

                    if prev_message_data.inner.mailboxes.len() == 1 {
                        // Delete message
                        destroy_ids.insert(message_id);
                        continue;
                    }

                    let mut new_message_data = prev_message_data
                        .deserialize()
                        .caused_by(trc::location!())?;
                    let thread_id = new_message_data.thread_id;

                    new_message_data
                        .mailboxes
                        .retain(|id| id.mailbox_id != document_id);

                    // Untag message from mailbox
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .update_document(message_id)
                        .custom(
                            ObjectIndexBuilder::new()
                                .with_changes(new_message_data)
                                .with_current(prev_message_data),
                        )
                        .caused_by(trc::location!())?;
                    match self.core.storage.data.write(batch.build()).await {
                        Ok(_) => changes
                            .log_update(Collection::Email, Id::from_parts(thread_id, message_id)),
                        Err(err) if err.is_assertion_failure() => {
                            return Ok(Err(SetError::forbidden().with_description(concat!(
                                "Another process modified a message in this mailbox ",
                                "while deleting it, please try again."
                            ))));
                        }
                        Err(err) => {
                            return Err(err.caused_by(trc::location!()));
                        }
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
        if let Some(mailbox_) = self
            .get_property::<Archive<AlignedBytes>>(
                account_id,
                Collection::Mailbox,
                document_id,
                Property::Value,
            )
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

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .delete_document(document_id)
                .clear(Property::EmailIds)
                .custom(ObjectIndexBuilder::<_, ()>::new().with_current(mailbox))
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
