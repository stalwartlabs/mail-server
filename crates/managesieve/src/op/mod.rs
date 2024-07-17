/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;

use crate::core::{Session, StatusResponse};

pub mod authenticate;
pub mod capability;
pub mod checkscript;
pub mod deletescript;
pub mod getscript;
pub mod havespace;
pub mod listscripts;
pub mod logout;
pub mod noop;
pub mod putscript;
pub mod renamescript;
pub mod setactive;

impl<T: SessionStream> Session<T> {
    pub async fn handle_start_tls(&self) -> trc::Result<Vec<u8>> {
        Ok(StatusResponse::ok("Begin TLS negotiation now").into_bytes())
    }
}
