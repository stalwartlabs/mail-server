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
    pub async fn handle_login(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_login() {
            Ok(args) => {
                self.authenticate(
                    Credentials::Plain {
                        username: args.username,
                        secret: args.password,
                    },
                    args.tag,
                )
                .await
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}
