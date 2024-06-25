/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;

use crate::{protocol::response::Response, Session};

impl<T: SessionStream> Session<T> {
    pub async fn handle_list(&mut self, msg: Option<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                self.write_ok(format!("{} {}", msg, message.size)).await
            } else {
                self.write_err("No such message").await
            }
        } else {
            self.write_bytes(
                Response::List(mailbox.messages.iter().map(|m| m.size).collect::<Vec<_>>())
                    .serialize(),
            )
            .await
        }
    }

    pub async fn handle_uidl(&mut self, msg: Option<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                self.write_ok(format!("{} {}{}", msg, mailbox.uid_validity, message.uid))
                    .await
            } else {
                self.write_err("No such message").await
            }
        } else {
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

    pub async fn handle_stat(&mut self) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        self.write_ok(format!("{} {}", mailbox.total, mailbox.size))
            .await
    }
}
