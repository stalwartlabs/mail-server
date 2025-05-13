/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{capability::Capability, ImapResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub capabilities: Vec<Capability>,
}

pub struct Response {
    pub enabled: Vec<Capability>,
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        if !self.enabled.is_empty() {
            let mut buf = Vec::with_capacity(64);
            buf.extend(b"* ENABLED");
            for capability in self.enabled {
                buf.push(b' ');
                capability.serialize(&mut buf);
            }
            buf.push(b'\r');
            buf.push(b'\n');
            buf
        } else {
            Vec::new()
        }
    }
}
