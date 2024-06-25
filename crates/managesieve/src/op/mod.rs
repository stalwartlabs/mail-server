/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::error::method::MethodError;

use crate::core::StatusResponse;

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

impl From<MethodError> for StatusResponse {
    fn from(_: MethodError) -> Self {
        StatusResponse::database_failure()
    }
}

pub type OpResult = std::result::Result<Vec<u8>, StatusResponse>;
