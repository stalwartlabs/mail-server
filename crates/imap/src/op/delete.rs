/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use directory::Permission;
use email::mailbox::destroy::MailboxDestroy;
use imap_proto::{
    Command, ResponseCode, StatusResponse, protocol::delete::Arguments, receiver::Request,
};

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_delete(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapDelete)?;

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
        let op_start = Instant::now();

        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) =
            if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
                (mailbox.account_id, mailbox.mailbox_id)
            } else {
                return Err(trc::ImapEvent::Error
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

        if let Err(err) = self
            .server
            .mailbox_destroy(account_id, mailbox_id, &access_token, true)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(err.description.unwrap_or("Delete failed".into()))
                .code(ResponseCode::from(err.type_))
                .id(arguments.tag));
        }

        // Update mailbox cache
        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == account_id {
                account.mailbox_names.remove(&arguments.mailbox_name);
                account.mailbox_state.remove(&mailbox_id);
                break;
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::DeleteMailbox),
            SpanId = self.session_id,
            MailboxName = arguments.mailbox_name,
            AccountId = account_id,
            MailboxId = mailbox_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Mailbox deleted.").with_tag(arguments.tag))
    }
}
