/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::{receiver::Request, Command};

use crate::core::Session;
use common::listener::SessionStream;
use mail_send::Credentials;

impl<T: SessionStream> Session<T> {
    pub async fn handle_login(&mut self, request: Request<Command>) -> trc::Result<()> {
        let arguments = request.parse_login()?;

        self.authenticate(
            Credentials::Plain {
                username: arguments.username,
                secret: arguments.password,
            },
            arguments.tag,
        )
        .await
    }
}
