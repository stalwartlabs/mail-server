/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, SessionData};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, ResponseCode, StatusResponse};
use jmap::mailbox::set::{MailboxSubscribe, SCHEMA};
use jmap_proto::{
    error::method::MethodError,
    object::{index::ObjectIndexBuilder, Object},
    types::{
        collection::Collection, property::Property, state::StateChange, type_state::DataType,
        value::Value,
    },
};
use store::write::{assert::HashedValue, BatchBuilder};

impl<T: SessionStream> Session<T> {
    pub async fn handle_subscribe(
        &mut self,
        request: Request<Command>,
        is_subscribe: bool,
    ) -> crate::OpResult {
        match request.parse_subscribe(self.version) {
            Ok(arguments) => {
                let data = self.state.session_data();
                tokio::spawn(async move {
                    data.write_bytes(
                        data.subscribe_folder(arguments.tag, arguments.mailbox_name, is_subscribe)
                            .await
                            .into_bytes(),
                    )
                    .await;
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn subscribe_folder(
        &self,
        tag: String,
        mailbox_name: String,
        subscribe: bool,
    ) -> StatusResponse {
        // Refresh mailboxes
        if let Err(err) = self.synchronize_mailboxes(false).await {
            return err.with_tag(tag);
        }

        // Validate mailbox
        let (account_id, mailbox_id) = match self.get_mailbox_by_name(&mailbox_name) {
            Some(mailbox) => (mailbox.account_id, mailbox.mailbox_id),
            None => {
                return StatusResponse::no("Mailbox does not exist.")
                    .with_tag(tag)
                    .with_code(ResponseCode::NonExistent);
            }
        };

        // Verify if mailbox is already subscribed/unsubscribed
        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == account_id {
                if let Some(mailbox) = account.mailbox_state.get(&mailbox_id) {
                    if mailbox.is_subscribed == subscribe {
                        return StatusResponse::ok(if subscribe {
                            "Already subscribed."
                        } else {
                            "Already unsubscribed"
                        })
                        .with_tag(tag);
                    }
                }
                break;
            }
        }

        // Obtain mailbox
        let mailbox = if let Ok(Some(mailbox)) = self
            .jmap
            .get_property::<HashedValue<Object<Value>>>(
                account_id,
                Collection::Mailbox,
                mailbox_id,
                Property::Value,
            )
            .await
        {
            mailbox
        } else {
            return StatusResponse::database_failure().with_tag(tag);
        };

        // Subscribe/unsubscribe to mailbox
        if let Some(value) = mailbox.inner.mailbox_subscribe(account_id, subscribe) {
            // Build batch
            let mut changes = match self.jmap.begin_changes(account_id).await {
                Ok(changes) => changes,
                Err(_) => {
                    return StatusResponse::database_failure().with_tag(tag);
                }
            };
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
            match self.jmap.write_batch(batch).await {
                Ok(_) => (),
                Err(MethodError::ServerUnavailable) => {
                    return StatusResponse::no(
                        "Another process modified this mailbox, please try again.",
                    )
                    .with_tag(tag);
                }
                Err(_) => {
                    return StatusResponse::database_failure().with_tag(tag);
                }
            }

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

        StatusResponse::ok(if subscribe {
            "Mailbox subscribed."
        } else {
            "Mailbox unsubscribed."
        })
        .with_tag(tag)
    }
}
