/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::{Session, State};
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_noop(&mut self, request: Request<Command>) -> trc::Result<()> {
        if let State::Selected { data, mailbox, .. } = &self.state {
            data.write_changes(
                &Some(mailbox.clone()),
                false,
                true,
                self.is_qresync,
                self.version.is_rev2(),
            )
            .await;
        }

        self.write_bytes(
            StatusResponse::completed(request.command)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
