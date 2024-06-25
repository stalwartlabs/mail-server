/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use imap_proto::{
    protocol::{append::Arguments, select::HighestModSeq},
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};

use crate::core::{ImapUidToId, MailboxId, SelectedMailbox, Session, SessionData};
use common::listener::SessionStream;
use jmap::email::ingest::{IngestEmail, IngestSource};
use jmap_proto::types::{acl::Acl, keyword::Keyword, state::StateChange, type_state::DataType};
use mail_parser::MessageParser;

use super::ToModSeq;

impl<T: SessionStream> Session<T> {
    pub async fn handle_append(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_append(self.version) {
            Ok(arguments) => {
                let (data, selected_mailbox) = self.state.session_mailbox_state();

                // Refresh mailboxes
                if let Err(err) = data.synchronize_mailboxes(false).await {
                    return self
                        .write_bytes(err.with_tag(arguments.tag).into_bytes())
                        .await;
                }

                // Obtain mailbox
                let mailbox =
                    if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
                        mailbox
                    } else {
                        return self
                            .write_bytes(
                                StatusResponse::no("Mailbox does not exist.")
                                    .with_tag(arguments.tag)
                                    .with_code(ResponseCode::TryCreate)
                                    .into_bytes(),
                            )
                            .await;
                    };
                let is_qresync = self.is_qresync;

                tokio::spawn(async move {
                    data.write_bytes(
                        match data
                            .append_messages(arguments, selected_mailbox, mailbox, is_qresync)
                            .await
                        {
                            Ok(response) => response,
                            Err(response) => response,
                        }
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
    async fn append_messages(
        &self,
        arguments: Arguments,
        selected_mailbox: Option<Arc<SelectedMailbox>>,
        mailbox: MailboxId,
        is_qresync: bool,
    ) -> crate::op::Result<StatusResponse> {
        // Verify ACLs
        let account_id = mailbox.account_id;
        let mailbox_id = mailbox.mailbox_id;
        if !self
            .check_mailbox_acl(account_id, mailbox_id, Acl::AddItems)
            .await
            .map_err(|r| r.with_tag(&arguments.tag))?
        {
            return Ok(StatusResponse::no(
                "You do not have the required permissions to append messages to this mailbox.",
            )
            .with_tag(arguments.tag)
            .with_code(ResponseCode::NoPerm));
        }

        // Obtain quota
        let account_quota = self
            .get_access_token()
            .await
            .map_err(|r| r.with_tag(&arguments.tag))?
            .quota as i64;

        // Append messages
        let mut response = StatusResponse::completed(Command::Append);
        let mut created_ids = Vec::with_capacity(arguments.messages.len());
        let mut last_change_id = None;
        for message in arguments.messages {
            match self
                .jmap
                .email_ingest(IngestEmail {
                    raw_message: &message.message,
                    message: MessageParser::new().parse(&message.message),
                    account_id,
                    account_quota,
                    mailbox_ids: vec![mailbox_id],
                    keywords: message.flags.into_iter().map(Keyword::from).collect(),
                    received_at: message.received_at.map(|d| d as u64),
                    source: IngestSource::Imap,
                    encrypt: self.jmap.core.jmap.encrypt && self.jmap.core.jmap.encrypt_append,
                })
                .await
            {
                Ok(email) => {
                    created_ids.push(ImapUidToId {
                        uid: email.imap_uids[0],
                        id: email.id.document_id(),
                    });
                    last_change_id = Some(email.change_id);
                }
                Err(err) => {
                    match err {
                        jmap::IngestError::Temporary => {
                            response = StatusResponse::database_failure();
                        }
                        jmap::IngestError::OverQuota => {
                            response = StatusResponse::no("Disk quota exceeded.")
                                .with_code(ResponseCode::OverQuota);
                        }
                        jmap::IngestError::Permanent { reason, .. } => {
                            response = StatusResponse::no(reason);
                        }
                    }
                    break;
                }
            }
        }

        // Broadcast changes
        if let Some(change_id) = last_change_id {
            self.jmap
                .broadcast_state_change(
                    StateChange::new(account_id)
                        .with_change(DataType::Email, change_id)
                        .with_change(DataType::Mailbox, change_id)
                        .with_change(DataType::Thread, change_id),
                )
                .await;
        }

        if !created_ids.is_empty() {
            let uids = created_ids.iter().map(|id| id.uid).collect();
            let uid_validity = match selected_mailbox {
                Some(selected_mailbox) if selected_mailbox.id == mailbox => {
                    // Write updated modseq
                    if is_qresync {
                        self.write_bytes(
                            HighestModSeq::new(last_change_id.to_modseq()).into_bytes(),
                        )
                        .await;
                    }

                    selected_mailbox.append_messages(created_ids, last_change_id)
                }
                _ => self
                    .get_uid_validity(&mailbox)
                    .await
                    .map_err(|r| r.with_tag(&arguments.tag))?,
            };

            response = response.with_code(ResponseCode::AppendUid { uid_validity, uids });
        }

        Ok(response.with_tag(arguments.tag))
    }
}
