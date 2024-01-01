/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
