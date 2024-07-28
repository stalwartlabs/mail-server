/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use jmap_proto::request::capability::Capabilities;

use crate::core::{Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_capability(&self, message: &'static str) -> trc::Result<Vec<u8>> {
        let op_start = Instant::now();

        let mut response = Vec::with_capacity(128);
        response.extend_from_slice(b"\"IMPLEMENTATION\" \"Stalwart ManageSieve\"\r\n");
        response.extend_from_slice(b"\"VERSION\" \"1.0\"\r\n");
        if !self.stream.is_tls() {
            response.extend_from_slice(b"\"STARTTLS\"\r\n");
        }
        if self.stream.is_tls() || self.jmap.core.imap.allow_plain_auth {
            response.extend_from_slice(b"\"SASL\" \"PLAIN OAUTHBEARER\"\r\n");
        } else {
            response.extend_from_slice(b"\"SASL\" \"OAUTHBEARER\"\r\n");
        };
        if let Some(sieve) =
            self.jmap
                .core
                .jmap
                .capabilities
                .account
                .iter()
                .find_map(|(_, item)| {
                    if let Capabilities::SieveAccount(sieve) = item {
                        Some(sieve)
                    } else {
                        None
                    }
                })
        {
            response.extend_from_slice(b"\"SIEVE\" \"");
            response.extend_from_slice(sieve.extensions.join(" ").as_bytes());
            response.extend_from_slice(b"\"\r\n");
            if let Some(notification_methods) = &sieve.notification_methods {
                response.extend_from_slice(b"\"NOTIFY\" \"");
                response.extend_from_slice(notification_methods.join(" ").as_bytes());
                response.extend_from_slice(b"\"\r\n");
            }
            if sieve.max_redirects > 0 {
                response.extend_from_slice(b"\"MAXREDIRECTS\" \"");
                response.extend_from_slice(sieve.max_redirects.to_string().as_bytes());
                response.extend_from_slice(b"\"\r\n");
            }
        } else {
            response.extend_from_slice(b"\"SIEVE\" \"\"\r\n");
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::Capabilities),
            SpanId = self.session_id,
            Tls = self.stream.is_tls(),
            Strict = !self.jmap.core.imap.allow_plain_auth,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok(message).serialize(response))
    }
}
