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
use imap_proto::{
    protocol::delete::Arguments, receiver::Request, Command, ResponseCode, StatusResponse,
};
use jmap_proto::types::{state::StateChange, type_state::DataType};
use store::write::log::ChangeLogBuilder;

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_delete(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        let data = self.state.session_data();
        let version = self.version;

        spawn_op!(data, {
            for request in requests {
                match request.parse_delete(version) {
                    Ok(argument) => match data.delete_folder(argument).await {
                        Ok(response) => {
                            data.write_bytes(response.into_bytes()).await?;
                        }
                        Err(error) => {
                            data.write_error(error).await?;
                        }
                    },
                    Err(response) => data.write_error(response).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn delete_folder(&self, arguments: Arguments) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) =
            if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
                (mailbox.account_id, mailbox.mailbox_id)
            } else {
                return Err(trc::Cause::Imap
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::TryCreate)
                    .id(arguments.tag));
            };

        // Delete message
        let access_token = self
            .get_access_token()
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        let mut changelog = ChangeLogBuilder::new();
        let did_remove_emails = match self
            .jmap
            .mailbox_destroy(account_id, mailbox_id, &mut changelog, &access_token, true)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            Ok(did_remove_emails) => did_remove_emails,
            Err(err) => {
                return Err(trc::Cause::Imap
                    .into_err()
                    .details(err.description.unwrap_or("Delete failed".into()))
                    .code(ResponseCode::from(err.type_))
                    .id(arguments.tag));
            }
        };

        // Write changes
        let change_id = self
            .jmap
            .commit_changes(account_id, changelog)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

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

        Ok(StatusResponse::ok("Mailbox deleted.").with_tag(arguments.tag))
    }
}
