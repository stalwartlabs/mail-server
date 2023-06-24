/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use imap_proto::{receiver::Request, Command, ResponseCode, StatusResponse};
use jmap::mailbox::set::{MailboxSubscribe, SCHEMA};
use jmap_proto::{
    error::method::MethodError,
    object::{index::ObjectIndexBuilder, Object},
    types::{
        collection::Collection, property::Property, state::StateChange, type_state::TypeState,
        value::Value,
    },
};
use store::write::{assert::HashedValue, BatchBuilder};
use tokio::io::AsyncRead;

use crate::core::{Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_subscribe(
        &mut self,
        request: Request<Command>,
        is_subscribe: bool,
    ) -> Result<(), ()> {
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

impl SessionData {
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
            Some(mailbox) => {
                if let Some(mailbox_id) = mailbox.mailbox_id {
                    (mailbox.account_id, mailbox_id)
                } else {
                    return StatusResponse::no("Subscribing to this mailbox is not supported.")
                        .with_tag(tag)
                        .with_code(ResponseCode::Cannot);
                }
            }
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
                    StateChange::new(account_id).with_change(TypeState::Mailbox, change_id),
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
