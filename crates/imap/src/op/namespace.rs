/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::listener::SessionStream;
use imap_proto::{
    protocol::{namespace::Response, ImapResponse},
    receiver::Request,
    Command, StatusResponse,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_namespace(&mut self, request: Request<Command>) -> crate::OpResult {
        self.write_bytes(
            StatusResponse::completed(Command::Namespace)
                .with_tag(request.tag)
                .serialize(
                    Response {
                        shared_prefix: if self.state.session_data().mailboxes.lock().len() > 1 {
                            self.jmap.core.jmap.shared_folder.clone().into()
                        } else {
                            None
                        },
                    }
                    .serialize(),
                ),
        )
        .await
    }
}
