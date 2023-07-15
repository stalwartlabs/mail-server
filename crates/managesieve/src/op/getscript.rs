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

use imap_proto::receiver::Request;
use jmap_proto::{
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use store::BlobKind;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_getscript(&mut self, request: Request<Command>) -> super::OpResult {
        let name = request
            .tokens
            .into_iter()
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected script name as a parameter."))?;
        let account_id = self.state.access_token().primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        let script_size = self
            .jmap
            .get_property::<Object<Value>>(
                account_id,
                Collection::SieveScript,
                document_id,
                Property::Value,
            )
            .await?
            .ok_or_else(|| {
                StatusResponse::no("Script not found").with_code(ResponseCode::NonExistent)
            })?
            .remove(&Property::Size)
            .try_unwrap_uint()
            .ok_or_else(|| {
                StatusResponse::no("Filed to retrieve blob size").with_code(ResponseCode::TryLater)
            })? as u32;
        let script = self
            .jmap
            .get_blob(
                &BlobKind::Linked {
                    account_id,
                    collection: Collection::SieveScript.into(),
                    document_id,
                },
                0..script_size,
            )
            .await?
            .ok_or_else(|| {
                StatusResponse::no("Script blob not found").with_code(ResponseCode::NonExistent)
            })?;
        debug_assert_eq!(script.len() as u32, script_size);

        let mut response = Vec::with_capacity(script.len() + 30);
        response.push(b'{');
        response.extend_from_slice(script_size.to_string().as_bytes());
        response.extend_from_slice(b"}\r\n");
        response.extend(script);

        Ok(StatusResponse::ok("").serialize(response))
    }
}
