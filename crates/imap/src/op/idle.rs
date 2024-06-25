/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashSet;
use imap_proto::{
    protocol::{
        fetch,
        list::{Attribute, ListItem},
        status::Status,
        Sequence,
    },
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};

use common::listener::SessionStream;
use jmap_proto::types::{collection::Collection, type_state::DataType};
use store::query::log::Query;
use tokio::io::AsyncReadExt;
use utils::map::bitmap::Bitmap;

use crate::core::{SelectedMailbox, Session, SessionData, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_idle(&mut self, request: Request<Command>) -> crate::OpResult {
        let (data, mailbox, types) = match &self.state {
            State::Authenticated { data, .. } => {
                (data.clone(), None, Bitmap::from_iter([DataType::Mailbox]))
            }
            State::Selected { data, mailbox, .. } => (
                data.clone(),
                mailbox.clone().into(),
                Bitmap::from_iter([DataType::Email, DataType::Mailbox, DataType::EmailDelivery]),
            ),
            _ => unreachable!(),
        };
        let is_rev2 = self.version.is_rev2();
        let is_qresync = self.is_qresync;

        // Register with state manager
        let mut change_rx = if let Some(change_rx) = self
            .jmap
            .subscribe_state_manager(data.account_id, types)
            .await
        {
            change_rx
        } else {
            return self
                .write_bytes(
                    StatusResponse::no("It was not possible to start IDLE.")
                        .with_tag(request.tag)
                        .with_code(ResponseCode::ContactAdmin)
                        .into_bytes(),
                )
                .await;
        };

        // Send continuation response
        self.write_bytes(b"+ Idling, send 'DONE' to stop.\r\n".to_vec())
            .await?;
        tracing::debug!(parent: &self.span, event = "start", context = "idle", "Starting IDLE.");
        let mut buf = vec![0; 1024];
        loop {
            tokio::select! {
                result = tokio::time::timeout(self.jmap.core.imap.timeout_idle, self.stream_rx.read(&mut buf)) => {
                    match result {
                        Ok(Ok(bytes_read)) => {
                            if bytes_read > 0 {
                                if (buf[..bytes_read]).windows(4).any(|w| w == b"DONE") {
                                    tracing::debug!(parent: &self.span, event = "stop", context = "idle", "Stopping IDLE.");
                                    return self.write_bytes(StatusResponse::completed(Command::Idle)
                                                                    .with_tag(request.tag)
                                                                    .into_bytes()).await;
                                }
                            } else {
                                tracing::debug!(parent: &self.span, event = "close", "IMAP connection closed by client.");
                                return Err(());
                            }
                        },
                        Ok(Err(err)) => {
                            tracing::debug!(parent: &self.span, event = "error", reason = %err, "IMAP connection error.");
                            return Err(());
                        },
                        Err(_) => {
                            self.write_bytes(&b"* BYE IDLE timed out.\r\n"[..]).await.ok();
                            tracing::debug!(parent: &self.span, "IDLE timed out.");
                            return Err(());
                        }
                    }
                }
                state_change = change_rx.recv() => {
                    if let Some(state_change) = state_change {
                        let mut has_mailbox_changes = false;
                        let mut has_email_changes = false;

                        for (type_state, _) in state_change.types {
                            match type_state {
                                DataType::Email | DataType::EmailDelivery => {
                                    has_email_changes = true;
                                }
                                DataType::Mailbox => {
                                    has_mailbox_changes = true;
                                }
                                _ => {}
                            }
                        }

                        if has_mailbox_changes || has_email_changes {
                            data.write_changes(&mailbox, has_mailbox_changes, has_email_changes, is_qresync, is_rev2).await;
                        }
                    } else {
                        self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
                        tracing::debug!(parent: &self.span, "IDLE channel closed.");
                        return Err(());
                    }
                }
            }
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn write_changes(
        &self,
        mailbox: &Option<Arc<SelectedMailbox>>,
        check_mailboxes: bool,
        check_emails: bool,
        is_qresync: bool,
        is_rev2: bool,
    ) {
        // Fetch all changed mailboxes
        if check_mailboxes {
            match self.synchronize_mailboxes(true).await {
                Ok(Some(changes)) => {
                    let mut buf = Vec::with_capacity(64);

                    // List deleted mailboxes
                    for mailbox_name in changes.deleted {
                        ListItem {
                            mailbox_name,
                            attributes: vec![Attribute::NonExistent],
                            tags: vec![],
                        }
                        .serialize(&mut buf, is_rev2, false);
                    }

                    // List added mailboxes
                    for mailbox_name in changes.added {
                        ListItem {
                            mailbox_name: mailbox_name.to_string(),
                            attributes: vec![],
                            tags: vec![],
                        }
                        .serialize(&mut buf, is_rev2, false);
                    }
                    // Obtain status of changed mailboxes
                    for mailbox_name in changes.changed {
                        if let Ok(status) = self
                            .status(
                                mailbox_name,
                                &[
                                    Status::Messages,
                                    Status::Unseen,
                                    Status::UidNext,
                                    Status::UidValidity,
                                ],
                            )
                            .await
                        {
                            status.serialize(&mut buf, is_rev2);
                        }
                    }

                    if !buf.is_empty() {
                        self.write_bytes(buf).await;
                    }
                }
                Err(_) => {
                    tracing::debug!(parent: &self.span, "Failed to refresh mailboxes.");
                }
                _ => unreachable!(),
            }
        }

        // Fetch selected mailbox changes
        if check_emails {
            // Synchronize emails
            if let Some(mailbox) = mailbox {
                // Obtain changes since last sync
                let modseq = mailbox.state.lock().modseq;
                match self.write_mailbox_changes(mailbox, is_qresync).await {
                    Ok(new_state) => {
                        if new_state == modseq {
                            return;
                        }
                    }
                    Err(response) => {
                        self.write_bytes(response.into_bytes()).await;
                        return;
                    }
                }

                // Obtain changed messages
                let changed_ids = match self
                    .jmap
                    .changes_(
                        mailbox.id.account_id,
                        Collection::Email,
                        modseq.map(Query::Since).unwrap_or(Query::All),
                    )
                    .await
                {
                    Ok(changelog) => {
                        let state = mailbox.state.lock();
                        changelog
                            .changes
                            .into_iter()
                            .filter_map(|change| {
                                state
                                    .id_to_imap
                                    .get(&((change.unwrap_id() & u32::MAX as u64) as u32))
                                    .map(|id| id.uid)
                            })
                            .collect::<AHashSet<_>>()
                    }
                    Err(_) => {
                        self.write_bytes(StatusResponse::database_failure().into_bytes())
                            .await;
                        return;
                    }
                };

                if !changed_ids.is_empty() {
                    self.fetch(
                        fetch::Arguments {
                            tag: String::new(),
                            sequence_set: Sequence::List {
                                items: changed_ids
                                    .into_iter()
                                    .map(|uid| Sequence::Number { value: uid })
                                    .collect(),
                            },
                            attributes: vec![fetch::Attribute::Flags, fetch::Attribute::Uid],
                            changed_since: None,
                            include_vanished: false,
                        },
                        mailbox.clone(),
                        true,
                        is_qresync,
                        is_rev2,
                        false,
                    )
                    .await;
                }
            }
        }
    }
}
