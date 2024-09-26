/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;

use crate::{
    protocol::{response::Response, Mechanism},
    Session,
};

pub mod authenticate;
pub mod delete;
pub mod fetch;
pub mod list;

impl<T: SessionStream> Session<T> {
    pub async fn handle_capa(&mut self) -> trc::Result<()> {
        let mechanisms = if self.stream.is_tls() || self.server.core.imap.allow_plain_auth {
            vec![Mechanism::Plain, Mechanism::OAuthBearer]
        } else {
            vec![Mechanism::OAuthBearer]
        };

        trc::event!(
            Pop3(trc::Pop3Event::Capabilities),
            SpanId = self.session_id,
            Tls = self.stream.is_tls(),
            Strict = !self.server.core.imap.allow_plain_auth,
            Elapsed = trc::Value::Duration(0)
        );

        self.write_bytes(
            Response::Capability::<u32> {
                mechanisms,
                stls: !self.stream.is_tls(),
            }
            .serialize(),
        )
        .await
    }

    pub async fn handle_stls(&mut self) -> trc::Result<()> {
        trc::event!(
            Pop3(trc::Pop3Event::StartTls),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        self.write_ok("Begin TLS negotiation now").await
    }

    pub async fn handle_utf8(&mut self) -> trc::Result<()> {
        trc::event!(
            Pop3(trc::Pop3Event::Utf8),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        self.write_ok("UTF8 enabled").await
    }
}
