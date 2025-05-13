/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::receiver::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_noop(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        trc::event!(
            ManageSieve(trc::ManageSieveEvent::Noop),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        Ok(if let Some(tag) = request
            .tokens
            .into_iter()
            .next()
            .and_then(|t| t.unwrap_string().ok())
        {
            StatusResponse::ok("Done").with_code(ResponseCode::Tag(tag))
        } else {
            StatusResponse::ok("Done")
        }
        .into_bytes())
    }
}
