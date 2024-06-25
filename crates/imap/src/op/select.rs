/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use imap_proto::{
    protocol::{
        fetch,
        list::ListItem,
        select::{HighestModSeq, Response},
        ImapResponse, Sequence,
    },
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};

use crate::core::{SavedSearch, SelectedMailbox, Session, State};
use common::listener::SessionStream;
use jmap_proto::types::id::Id;
use utils::lru_cache::LruCached;

use super::ToModSeq;

impl<T: SessionStream> Session<T> {
    pub async fn handle_select(&mut self, request: Request<Command>) -> crate::OpResult {
        let is_select = request.command == Command::Select;
        let command = request.command;
        match request.parse_select(self.version) {
            Ok(arguments) => {
                let data = self.state.session_data();

                // Refresh mailboxes
                if let Err(err) = data.synchronize_mailboxes(false).await {
                    return self
                        .write_bytes(err.with_tag(arguments.tag).into_bytes())
                        .await;
                }

                if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
                    // Try obtaining the mailbox from the cache
                    let state = {
                        let modseq = match data.get_modseq(mailbox.account_id).await {
                            Ok(modseq) => modseq,
                            Err(mut response) => {
                                response.tag = arguments.tag.into();
                                return self.write_bytes(response.into_bytes()).await;
                            }
                        };

                        if let Some(cached_state) =
                            self.imap
                                .cache_mailbox
                                .get(&mailbox)
                                .and_then(|cached_state| {
                                    if cached_state.modseq.unwrap_or(0) >= modseq.unwrap_or(0) {
                                        Some(cached_state)
                                    } else {
                                        None
                                    }
                                })
                        {
                            cached_state.as_ref().clone()
                        } else {
                            match data.fetch_messages(&mailbox).await {
                                Ok(new_state) => {
                                    let new_state = Arc::new(new_state);
                                    self.imap.cache_mailbox.insert(mailbox, new_state.clone());
                                    new_state.as_ref().clone()
                                }
                                Err(mut response) => {
                                    response.tag = arguments.tag.into();
                                    return self.write_bytes(response.into_bytes()).await;
                                }
                            }
                        }
                    };

                    // Synchronize messages
                    let closed_previous = self.state.close_mailbox();
                    let is_condstore = self.is_condstore || arguments.condstore;

                    // Build new state
                    let is_rev2 = self.version.is_rev2();
                    let uid_validity = state.uid_validity;
                    let uid_next = state.uid_next;
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
                            return self
                                .write_bytes(
                                    StatusResponse::no("QRESYNC is not enabled.")
                                        .with_tag(arguments.tag)
                                        .into_bytes(),
                                )
                                .await;
                        }
                        if qresync.uid_validity == uid_validity {
                            // Send flags for changed messages
                            data.fetch(
                                fetch::Arguments {
                                    tag: String::new(),
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
                            )
                            .await;
                        }
                    }

                    // Build response
                    let response = Response {
                        mailbox: ListItem::new(arguments.mailbox_name),
                        total_messages,
                        recent_messages: 0,
                        unseen_seq: 0,
                        uid_validity,
                        uid_next,
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
                    self.write_bytes(
                        StatusResponse::no("Mailbox does not exist.")
                            .with_tag(arguments.tag)
                            .with_code(ResponseCode::NonExistent)
                            .into_bytes(),
                    )
                    .await
                }
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }

    pub async fn handle_unselect(&mut self, request: Request<Command>) -> crate::OpResult {
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
