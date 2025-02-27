/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::{listener::SessionStream, storage::index::ObjectIndexBuilder};
use directory::Permission;
use email::mailbox::ArchivedMailbox;
use imap_proto::{Command, ResponseCode, StatusResponse, receiver::Request};
use jmap_proto::types::{
    collection::Collection, property::Property, state::StateChange, type_state::DataType,
};
use store::write::{Archive, BatchBuilder, assert::HashedValue};

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_subscribe(
        &mut self,
        request: Request<Command>,
        is_subscribe: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapSubscribe)?;

        let op_start = Instant::now();
        let arguments = request.parse_subscribe(self.version)?;
        let data = self.state.session_data();

        spawn_op!(data, {
            let response = data
                .subscribe_folder(
                    arguments.tag,
                    arguments.mailbox_name,
                    is_subscribe,
                    op_start,
                )
                .await?;

            data.write_bytes(response.into_bytes()).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn subscribe_folder(
        &self,
        tag: String,
        mailbox_name: String,
        subscribe: bool,
        op_start: Instant,
    ) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) = match self.get_mailbox_by_name(&mailbox_name) {
            Some(mailbox) => (mailbox.account_id, mailbox.mailbox_id),
            None => {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
                    .id(tag)
                    .caused_by(trc::location!()));
            }
        };

        // Verify if mailbox is already subscribed/unsubscribed
        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == account_id {
                if let Some(mailbox) = account.mailbox_state.get(&mailbox_id) {
                    if mailbox.is_subscribed == subscribe {
                        return Err(trc::ImapEvent::Error
                            .into_err()
                            .details(if subscribe {
                                "Mailbox is already subscribed."
                            } else {
                                "Mailbox is already unsubscribed."
                            })
                            .id(tag));
                    }
                }
                break;
            }
        }

        // Obtain mailbox
        let mailbox = self
            .server
            .get_property::<HashedValue<Archive>>(
                account_id,
                Collection::Mailbox,
                mailbox_id,
                Property::Value,
            )
            .await
            .imap_ctx(&tag, trc::location!())?
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
                    .id(tag.clone())
                    .caused_by(trc::location!())
            })?
            .into_deserialized::<ArchivedMailbox, email::mailbox::Mailbox>()
            .imap_ctx(&tag, trc::location!())?;

        if (subscribe && !mailbox.inner.is_subscribed(self.account_id))
            || (!subscribe && mailbox.inner.is_subscribed(self.account_id))
        {
            // Build batch
            let mut changes = self
                .server
                .begin_changes(account_id)
                .imap_ctx(&tag, trc::location!())?;
            let mut new_mailbox = mailbox.inner.clone();
            if subscribe {
                new_mailbox.subscribers.push(self.account_id);
            } else {
                new_mailbox.remove_subscriber(self.account_id);
            }
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .update_document(mailbox_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(mailbox)
                        .with_changes(new_mailbox),
                )
                .imap_ctx(&tag, trc::location!())?;
            changes.log_update(Collection::Mailbox, mailbox_id);

            let change_id = changes.change_id;
            batch.custom(changes).imap_ctx(&tag, trc::location!())?;
            self.server
                .store()
                .write(batch)
                .await
                .imap_ctx(&tag, trc::location!())?;

            // Broadcast changes
            self.server
                .broadcast_state_change(
                    StateChange::new(account_id).with_change(DataType::Mailbox, change_id),
                )
                .await;

            // Update mailbox cache
            for account in self.mailboxes.lock().iter_mut() {
                if account.account_id == account_id {
                    account.state_mailbox = change_id.into();
                    if let Some(mailbox) = account.mailbox_state.get_mut(&mailbox_id) {
                        mailbox.is_subscribed = subscribe;
                    }
                    break;
                }
            }
        }

        trc::event!(
            Imap(if subscribe {
                trc::ImapEvent::Subscribe
            } else {
                trc::ImapEvent::Unsubscribe
            }),
            SpanId = self.session_id,
            AccountId = account_id,
            MailboxId = mailbox_id,
            MailboxName = mailbox_name,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok(if subscribe {
            "Mailbox subscribed."
        } else {
            "Mailbox unsubscribed."
        })
        .with_tag(tag))
    }
}
