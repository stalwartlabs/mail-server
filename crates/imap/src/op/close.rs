/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, State};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_close(&mut self, request: Request<Command>) -> crate::OpResult {
        let (data, mailbox) = self.state.select_data();
        if mailbox.is_select {
            data.expunge(mailbox, None).await.ok();
        }

        self.state = State::Authenticated { data };
        self.write_bytes(
            StatusResponse::completed(Command::Close)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
