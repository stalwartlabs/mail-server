/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::LazyLock;

use imap_proto::{protocol::capability::Capability, ResponseCode, StatusResponse};

pub mod core;
pub mod op;

static SERVER_GREETING: &str = "Stalwart IMAP4rev2 at your service.";

pub(crate) static GREETING_WITH_TLS: LazyLock<Vec<u8>> = LazyLock::new(|| {
    StatusResponse::ok(SERVER_GREETING)
        .with_code(ResponseCode::Capability {
            capabilities: Capability::all_capabilities(false, true),
        })
        .into_bytes()
});

pub(crate) static GREETING_WITHOUT_TLS: LazyLock<Vec<u8>> = LazyLock::new(|| {
    StatusResponse::ok(SERVER_GREETING)
        .with_code(ResponseCode::Capability {
            capabilities: Capability::all_capabilities(false, false),
        })
        .into_bytes()
});

pub struct ImapError;
