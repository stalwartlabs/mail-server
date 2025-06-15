/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::core::Session;
use common::listener::SessionStream;
use directory::Permission;
use imap_proto::{
    Command, StatusResponse,
    protocol::{
        ImapResponse,
        capability::{Capability, Response},
    },
    receiver::Request,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_capability(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapCapability)?;

        let op_start = Instant::now();
        trc::event!(
            Imap(trc::ImapEvent::Capabilities),
            SpanId = self.session_id,
            Tls = self.is_tls,
            Strict = !self.server.core.imap.allow_plain_auth,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(
            StatusResponse::completed(Command::Capability)
                .with_tag(request.tag)
                .serialize(
                    Response {
                        capabilities: Capability::all_capabilities(
                            self.state.is_authenticated(),
                            !self.is_tls && self.instance.acceptor.is_tls(),
                        ),
                    }
                    .serialize(),
                ),
        )
        .await
    }

    pub async fn handle_id(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapId)?;

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
                        "* ID (\"name\" \"Stalwart\" \"version\" \"1.0.0\" \"vendor\" \"Stalwart Labs LLC\" ",
                        "\"support-url\" \"https://stalw.art\")\r\n"
                    )
                    .as_bytes()
                    .to_vec(),
                ),
        )
        .await
    }
}
