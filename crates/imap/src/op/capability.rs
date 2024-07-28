/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::core::Session;
use common::listener::SessionStream;
use imap_proto::{
    protocol::{
        capability::{Capability, Response},
        ImapResponse,
    },
    receiver::Request,
    Command, StatusResponse,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_capability(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();
        trc::event!(
            Imap(trc::ImapEvent::Capabilities),
            SpanId = self.session_id,
            Tls = self.is_tls,
            Strict = !self.jmap.core.imap.allow_plain_auth,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::completed(Command::Capability)
                .with_tag(request.tag)
                .serialize(
                    Response {
                        capabilities: Capability::all_capabilities(
                            self.state.is_authenticated(),
                            self.is_tls,
                        ),
                    }
                    .serialize(),
                ),
        )
        .await
    }

    pub async fn handle_id(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();
        trc::event!(
            Imap(trc::ImapEvent::Id),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::completed(Command::Id)
                .with_tag(request.tag)
                .serialize(
                    concat!(
                        "* ID (\"name\" \"Stalwart IMAP\" \"version\" \"",
                        env!("CARGO_PKG_VERSION"),
                        "\" \"vendor\" \"Stalwart Labs Ltd.\" ",
                        "\"support-url\" \"https://stalw.art\")\r\n"
                    )
                    .as_bytes()
                    .to_vec(),
                ),
        )
        .await
    }
}
