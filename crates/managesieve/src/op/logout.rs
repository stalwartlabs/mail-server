/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_logout(&mut self) -> trc::Result<Vec<u8>> {
        Ok(StatusResponse::ok(concat!(
            "Stalwart ManageSieve v",
            env!("CARGO_PKG_VERSION"),
            " bids you farewell."
        ))
        .into_bytes())
    }
}
