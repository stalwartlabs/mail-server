/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::core::Session;
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_logout(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();

        let mut response = StatusResponse::bye(
            concat!(
                "Stalwart IMAP4rev2 v",
                env!("CARGO_PKG_VERSION"),
                " bids you farewell."
            )
            .to_string(),
        )
        .into_bytes();

        trc::event!(
            Imap(trc::ImapEvent::Logout),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        response.extend(
            StatusResponse::completed(Command::Logout)
                .with_tag(request.tag)
                .into_bytes(),
        );
        self.write_bytes(response).await
    }
}
