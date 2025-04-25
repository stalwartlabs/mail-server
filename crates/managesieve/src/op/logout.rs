/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_logout(&mut self) -> trc::Result<Vec<u8>> {
        trc::event!(
            ManageSieve(trc::ManageSieveEvent::Logout),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        Ok(StatusResponse::ok("Stalwart ManageSieve bids you farewell.")

        .into_bytes())
    }
}
