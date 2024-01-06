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

use jmap::api::session::Capabilities;
use utils::listener::SessionStream;

use crate::core::{Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_capability(&self, message: &'static str) -> super::OpResult {
        let mut response = Vec::with_capacity(128);
        response.extend_from_slice(b"\"IMPLEMENTATION\" \"Stalwart ManageSieve v");
        response.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
        response.extend_from_slice(b"\"\r\n");
        response.extend_from_slice(b"\"VERSION\" \"1.0\"\r\n");
        if !self.stream.is_tls() {
            response.extend_from_slice(b"\"SASL\" \"\"\r\n");
            response.extend_from_slice(b"\"STARTTLS\"\r\n");
        } else {
            response.extend_from_slice(b"\"SASL\" \"PLAIN OAUTHBEARER\"\r\n");
        };
        if let Some(sieve) = self
            .jmap
            .config
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

        Ok(StatusResponse::ok(message).serialize(response))
    }
}
