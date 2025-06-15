/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use directory::Permission;
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{
        ImapResponse, Sequence, fetch,
        list::ListItem,
        select::{HighestModSeq, Response},
    },
    receiver::Request,
};

use crate::core::{SavedSearch, SelectedMailbox, Session, State};
use common::listener::SessionStream;
use jmap_proto::types::id::Id;

use super::{ImapContext, ToModSeq};

impl<T: SessionStream> Session<T> {
    pub async fn handle_select(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(if request.command == Command::Select {
            Permission::ImapSelect
        } else {
            Permission::ImapExamine
        })?;

        let op_start = Instant::now();
        let is_select = request.command == Command::Select;
        let command = request.command;
        let arguments = request.parse_select(self.version)?;
        let data = self.state.session_data();

        // Refresh mailboxes
        data.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
            // Try obtaining the mailbox from the cache
            let state = data
                .fetch_messages(&mailbox, None)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
                .unwrap();

            // Synchronize messages
            let closed_previous = self.state.close_mailbox();
            let is_condstore = self.is_condstore || arguments.condstore;

            // Build new state
            let is_rev2 = self.version.is_rev2();
            let mailbox_state = data.mailbox_state(&mailbox).unwrap();
            let total_messages = state.total_messages;
            let highest_modseq = if is_condstore {
                HighestModSeq::new(state.modseq.to_modseq()).into()
            } else {
                None
            };
            let mailbox = Arc::new(SelectedMailbox {
                id: mailbox,
                state: parking_lot::Mutex::new(state),
                saved_search: parking_lot::Mutex::new(SavedSearch::None),
                is_select,
                is_condstore,
            });

            // Validate QRESYNC arguments
            if let Some(qresync) = arguments.qresync {
                if !self.is_qresync {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("QRESYNC is not enabled.")
                        .id(arguments.tag));
                }
                if qresync.uid_validity == mailbox_state.uid_validity as u32 {
                    // Send flags for changed messages
                    data.fetch(
                        fetch::Arguments {
                            tag: "".into(),
                            sequence_set: qresync
                                .known_uids
                                .or_else(|| qresync.seq_match.map(|(_, s)| s))
                                .unwrap_or(Sequence::Range {
                                    start: 1.into(),
                                    end: None,
                                }),
                            attributes: vec![fetch::Attribute::Flags],
                            changed_since: qresync.modseq.into(),
                            include_vanished: true,
                        },
                        mailbox.clone(),
                        true,
                        true,
                        is_rev2,
                        false,
                        Instant::now(),
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
                }
            }

            trc::event!(
                Imap(trc::ImapEvent::Select),
                SpanId = self.session_id,
                MailboxName = arguments.mailbox_name.clone(),
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Total = total_messages,
                UidNext = mailbox_state.uid_next,
                UidValidity = mailbox_state.uid_validity,
                Elapsed = op_start.elapsed()
            );

            // Build response
            let response = Response {
                mailbox: ListItem::new(arguments.mailbox_name),
                total_messages,
                recent_messages: 0,
                unseen_seq: 0,
                uid_validity: mailbox_state.uid_validity as u32,
                uid_next: mailbox_state.uid_next as u32,
                closed_previous,
                is_rev2,
                highest_modseq,
                mailbox_id: Id::from_parts(mailbox.id.account_id, mailbox.id.mailbox_id)
                    .to_string(),
            };

            // Update state
            self.state = State::Selected { data, mailbox };

            self.write_bytes(
                StatusResponse::completed(command)
                    .with_tag(arguments.tag)
                    .with_code(if is_select {
                        ResponseCode::ReadWrite
                    } else {
                        ResponseCode::ReadOnly
                    })
                    .serialize(response.serialize()),
            )
            .await
        } else {
            Err(trc::ImapEvent::Error
                .into_err()
                .details("Mailbox does not exist.")
                .code(ResponseCode::NonExistent)
                .id(arguments.tag))
        }
    }

    pub async fn handle_unselect(&mut self, request: Request<Command>) -> trc::Result<()> {
        self.state.close_mailbox();
        self.state = State::Authenticated {
            data: self.state.session_data(),
        };
        self.write_bytes(
            StatusResponse::completed(Command::Unselect)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
