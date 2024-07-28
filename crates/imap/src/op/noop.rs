/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::core::{Session, State};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_noop(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();

        if let State::Selected { data, mailbox, .. } = &self.state {
            data.write_changes(
                &Some(mailbox.clone()),
                false,
                true,
                self.is_qresync,
                self.version.is_rev2(),
            )
            .await?;
        }

        trc::event!(
            Imap(trc::ImapEvent::Noop),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::completed(request.command)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
