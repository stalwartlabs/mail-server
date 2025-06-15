/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use directory::Permission;

use crate::core::{Session, State, StatusResponse};

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
        trc::event!(
            ManageSieve(trc::ManageSieveEvent::StartTls),
            SpanId = self.session_id,
            Elapsed = trc::Value::Duration(0)
        );

        Ok(StatusResponse::ok("Begin TLS negotiation now").into_bytes())
    }

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<bool> {
        match &self.state {
            State::Authenticated { access_token, .. } => {
                access_token.assert_has_permission(permission)
            }
            State::NotAuthenticated { .. } => Ok(false),
        }
    }
}
