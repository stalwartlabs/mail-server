/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::listener::SessionStream;
use imap_proto::{receiver::Request, Command, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_logout(&mut self, request: Request<Command>) -> crate::OpResult {
        let mut response = StatusResponse::bye(
            concat!(
                "Stalwart IMAP4rev2 v",
                env!("CARGO_PKG_VERSION"),
                " bids you farewell."
            )
            .to_string(),
        )
        .into_bytes();
        response.extend(
            StatusResponse::completed(Command::Logout)
                .with_tag(request.tag)
                .into_bytes(),
        );
        self.write_bytes(response).await?;
        Err(())
    }
}
