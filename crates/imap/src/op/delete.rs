/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, SessionData};
use common::listener::SessionStream;
use imap_proto::{protocol::delete::Arguments, receiver::Request, Command, StatusResponse};
use jmap_proto::types::{state::StateChange, type_state::DataType};
use store::write::log::ChangeLogBuilder;

impl<T: SessionStream> Session<T> {
    pub async fn handle_delete(&mut self, requests: Vec<Request<Command>>) -> crate::OpResult {
        let mut arguments = Vec::with_capacity(requests.len());

        for request in requests {
            match request.parse_delete(self.version) {
                Ok(argument) => {
                    arguments.push(argument);
                }
                Err(response) => self.write_bytes(response.into_bytes()).await?,
            }
        }

        if !arguments.is_empty() {
            let data = self.state.session_data();
            tokio::spawn(async move {
                for argument in arguments {
                    data.write_bytes(data.delete_folder(argument).await.into_bytes())
                        .await;
                }
            });
        }
        Ok(())
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn delete_folder(&self, arguments: Arguments) -> StatusResponse {
        // Refresh mailboxes
        if let Err(err) = self.synchronize_mailboxes(false).await {
            return err.with_tag(arguments.tag);
        }

        // Validate mailbox
        let (account_id, mailbox_id) =
            if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
                (mailbox.account_id, mailbox.mailbox_id)
            } else {
                return StatusResponse::no("Mailbox does not exist.").with_tag(arguments.tag);
            };

        // Delete message
        let access_token = match self.get_access_token().await {
            Ok(access_token) => access_token,
            Err(response) => return response.with_tag(arguments.tag),
        };
        let mut changelog = ChangeLogBuilder::new();
        let did_remove_emails = match self
            .jmap
            .mailbox_destroy(account_id, mailbox_id, &mut changelog, &access_token, true)
            .await
        {
            Ok(Ok(did_remove_emails)) => did_remove_emails,
            Ok(Err(err)) => {
                return StatusResponse::no(err.description.unwrap_or("Delete failed".into()))
                    .with_code(err.type_.into())
                    .with_tag(arguments.tag)
            }
            Err(_) => return StatusResponse::database_failure().with_tag(arguments.tag),
        };

        // Write changes
        let change_id = match self.jmap.commit_changes(account_id, changelog).await {
            Ok(change_id) => change_id,
            Err(_) => {
                return StatusResponse::database_failure().with_tag(arguments.tag);
            }
        };

        // Broadcast changes
        self.jmap
            .broadcast_state_change(if did_remove_emails {
                StateChange::new(account_id)
                    .with_change(DataType::Mailbox, change_id)
                    .with_change(DataType::Email, change_id)
                    .with_change(DataType::Thread, change_id)
            } else {
                StateChange::new(account_id).with_change(DataType::Mailbox, change_id)
            })
            .await;

        // Update mailbox cache
        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == account_id {
                account.mailbox_names.remove(&arguments.mailbox_name);
                account.mailbox_state.remove(&mailbox_id);
                break;
            }
        }

        StatusResponse::ok("Mailbox deleted.").with_tag(arguments.tag)
    }
}
