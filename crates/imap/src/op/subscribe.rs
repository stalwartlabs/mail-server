/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, ResponseCode, StatusResponse};
use jmap::mailbox::set::{MailboxSubscribe, SCHEMA};
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{
        collection::Collection, property::Property, state::StateChange, type_state::DataType,
        value::Value,
    },
};
use store::write::{assert::HashedValue, BatchBuilder};

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_subscribe(
        &mut self,
        request: Request<Command>,
        is_subscribe: bool,
    ) -> trc::Result<()> {
        let arguments = request.parse_subscribe(self.version)?;
        let data = self.state.session_data();

        spawn_op!(data, {
            let response = data
                .subscribe_folder(arguments.tag, arguments.mailbox_name, is_subscribe)
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
    ) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) = match self.get_mailbox_by_name(&mailbox_name) {
            Some(mailbox) => (mailbox.account_id, mailbox.mailbox_id),
            None => {
                return Err(trc::Cause::Imap
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
                        return Err(trc::Cause::Imap
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
            .jmap
            .get_property::<HashedValue<Object<Value>>>(
                account_id,
                Collection::Mailbox,
                mailbox_id,
                Property::Value,
            )
            .await
            .imap_ctx(&tag, trc::location!())?
            .ok_or_else(|| {
                trc::Cause::Imap
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
                    .id(tag.clone())
                    .caused_by(trc::location!())
            })?;

        // Subscribe/unsubscribe to mailbox
        if let Some(value) = mailbox.inner.mailbox_subscribe(self.account_id, subscribe) {
            // Build batch
            let mut changes = self
                .jmap
                .begin_changes(account_id)
                .await
                .imap_ctx(&tag, trc::location!())?;
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .update_document(mailbox_id)
                .custom(
                    ObjectIndexBuilder::new(SCHEMA)
                        .with_current(mailbox)
                        .with_changes(
                            Object::with_capacity(1).with_property(Property::IsSubscribed, value),
                        ),
                );
            changes.log_update(Collection::Mailbox, mailbox_id);

            let change_id = changes.change_id;
            batch.custom(changes);
            self.jmap
                .write_batch(batch)
                .await
                .imap_ctx(&tag, trc::location!())?;

            // Broadcast changes
            self.jmap
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

        Ok(StatusResponse::ok(if subscribe {
            "Mailbox subscribed."
        } else {
            "Mailbox unsubscribed."
        })
        .with_tag(tag))
    }
}
