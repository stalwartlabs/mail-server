/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use jmap_proto::types::{state::StateChange, type_state::DataType};
use store::roaring::RoaringBitmap;
use trc::AddContext;

use crate::{protocol::response::Response, Session, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_dele(&mut self, msgs: Vec<u32>) -> trc::Result<()> {
        let op_start = Instant::now();
        let mailbox = self.state.mailbox_mut();
        let mut response = Vec::new();

        for msg in &msgs {
            if let Some(message) = mailbox.messages.get_mut(msg.saturating_sub(1) as usize) {
                if !message.deleted {
                    response.extend_from_slice(format!("+OK message {msg} deleted\r\n").as_bytes());
                    message.deleted = true;
                } else {
                    response.extend_from_slice(
                        format!("-ERR message {msg} already deleted\r\n").as_bytes(),
                    );
                }
            } else {
                response.extend_from_slice("-ERR no such message\r\n".as_bytes());
            }
        }

        trc::event!(
            Pop3(trc::Pop3Event::Delete),
            SpanId = self.session_id,
            Total = msgs.len(),
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(response).await
    }

    pub async fn handle_rset(&mut self) -> trc::Result<()> {
        let op_start = Instant::now();
        let mut count = 0;
        let mailbox = self.state.mailbox_mut();
        for message in &mut mailbox.messages {
            if message.deleted {
                count += 1;
                message.deleted = false;
            }
        }

        trc::event!(
            Pop3(trc::Pop3Event::Reset),
            SpanId = self.session_id,
            Total = count as u64,
            Elapsed = op_start.elapsed()
        );

        self.write_ok(format!("{count} messages undeleted")).await
    }

    pub async fn handle_quit(&mut self) -> trc::Result<()> {
        let op_start = Instant::now();
        let mut deleted_docs = Vec::new();

        if let State::Authenticated { mailbox, .. } = &self.state {
            let mut deleted = RoaringBitmap::new();
            for message in &mailbox.messages {
                if message.deleted {
                    deleted.insert(message.id);
                    deleted_docs.push(trc::Value::from(message.id));
                }
            }

            if !deleted.is_empty() {
                let num_deleted = deleted.len();
                let (changes, not_deleted) = self
                    .jmap
                    .emails_tombstone(mailbox.account_id, deleted)
                    .await
                    .caused_by(trc::location!())?;

                if !changes.is_empty() {
                    if let Ok(change_id) =
                        self.jmap.commit_changes(mailbox.account_id, changes).await
                    {
                        self.jmap
                            .broadcast_state_change(
                                StateChange::new(mailbox.account_id)
                                    .with_change(DataType::Email, change_id)
                                    .with_change(DataType::Mailbox, change_id)
                                    .with_change(DataType::Thread, change_id),
                            )
                            .await;
                    }
                }
                if not_deleted.is_empty() {
                    self.write_ok(format!(
                        "Stalwart POP3 bids you farewell ({num_deleted} messages deleted)."
                    ))
                    .await?;
                } else {
                    self.write_bytes(
                        Response::Err::<u32>("Some messages could not be deleted".into())
                            .serialize(),
                    )
                    .await?;
                }
            } else {
                self.write_ok("Stalwart POP3 bids you farewell (no messages deleted).")
                    .await?;
            }
        } else {
            self.write_ok("Stalwart POP3 bids you farewell.").await?;
        }

        trc::event!(
            Pop3(trc::Pop3Event::Quit),
            SpanId = self.session_id,
            DocumentId = deleted_docs,
            Elapsed = op_start.elapsed()
        );

        Ok(())
    }
}
