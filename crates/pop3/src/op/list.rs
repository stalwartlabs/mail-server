/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;

use crate::{protocol::response::Response, Session};

impl<T: SessionStream> Session<T> {
    pub async fn handle_list(&mut self, msg: Option<u32>) -> trc::Result<()> {
        let op_start = Instant::now();
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                trc::event!(
                    Pop3(trc::Pop3Event::ListMessage),
                    SpanId = self.session_id,
                    DocumentId = message.id,
                    Size = message.size,
                    Elapsed = op_start.elapsed()
                );

                self.write_ok(format!("{} {}", msg, message.size)).await
            } else {
                Err(trc::Pop3Event::Error
                    .into_err()
                    .details("No such message.")
                    .caused_by(trc::location!()))
            }
        } else {
            trc::event!(
                Pop3(trc::Pop3Event::List),
                SpanId = self.session_id,
                Count = mailbox.messages.len(),
                Elapsed = op_start.elapsed()
            );

            self.write_bytes(
                Response::List(mailbox.messages.iter().map(|m| m.size).collect::<Vec<_>>())
                    .serialize(),
            )
            .await
        }
    }

    pub async fn handle_uidl(&mut self, msg: Option<u32>) -> trc::Result<()> {
        let op_start = Instant::now();
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                trc::event!(
                    Pop3(trc::Pop3Event::UidlMessage),
                    SpanId = self.session_id,
                    DocumentId = message.id,
                    Uid = message.uid,
                    UidValidity = mailbox.uid_validity,
                    Elapsed = op_start.elapsed()
                );

                self.write_ok(format!("{} {}{}", msg, mailbox.uid_validity, message.uid))
                    .await
            } else {
                Err(trc::Pop3Event::Error
                    .into_err()
                    .details("No such message.")
                    .caused_by(trc::location!()))
            }
        } else {
            trc::event!(
                Pop3(trc::Pop3Event::Uidl),
                SpanId = self.session_id,
                Count = mailbox.messages.len(),
                Elapsed = op_start.elapsed()
            );

            self.write_bytes(
                Response::List(
                    mailbox
                        .messages
                        .iter()
                        .map(|m| format!("{}{}", mailbox.uid_validity, m.uid))
                        .collect::<Vec<_>>(),
                )
                .serialize(),
            )
            .await
        }
    }

    pub async fn handle_stat(&mut self) -> trc::Result<()> {
        let op_start = Instant::now();
        let mailbox = self.state.mailbox();

        trc::event!(
            Pop3(trc::Pop3Event::Stat),
            SpanId = self.session_id,
            Count = mailbox.total,
            Size = mailbox.size,
            Elapsed = op_start.elapsed()
        );

        self.write_ok(format!("{} {}", mailbox.total, mailbox.size))
            .await
    }
}
