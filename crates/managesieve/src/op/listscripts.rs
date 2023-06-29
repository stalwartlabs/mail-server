/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

use jmap_proto::{
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_listscripts(&mut self) -> super::OpResult {
        let account_id = self.state.access_token().primary_id();
        let document_ids = self
            .jmap
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .unwrap_or_default();

        if document_ids.is_empty() {
            return Ok(StatusResponse::ok("").into_bytes());
        }

        let mut response = Vec::with_capacity(128);

        for document_id in document_ids {
            if let Some(script) = self
                .jmap
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                response.push(b'\"');
                if let Some(name) = script.get(&Property::Name).as_string() {
                    for ch in name.as_bytes() {
                        if [b'\\', b'\"'].contains(ch) {
                            response.push(b'\\');
                        }
                        response.push(*ch);
                    }
                }

                if script.get(&Property::IsActive).as_bool() == Some(true) {
                    response.extend_from_slice(b"\" ACTIVE\r\n");
                } else {
                    response.extend_from_slice(b"\"\r\n");
                }
            }
        }

        Ok(StatusResponse::ok("").serialize(response))
    }
}
