/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::core::{Session, State};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_close(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();
        let (data, mailbox) = self.state.select_data();

        if mailbox.is_select {
            data.expunge(mailbox.clone(), None, op_start)
                .await
                .caused_by(trc::location!())?;
        }

        trc::event!(
            Imap(trc::ImapEvent::Close),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            Elapsed = op_start.elapsed()
        );

        self.state = State::Authenticated { data };
        self.write_bytes(
            StatusResponse::completed(Command::Close)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
