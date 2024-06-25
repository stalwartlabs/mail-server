/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::receiver::Request;
use jmap::sieve::set::ObjectBlobId;
use jmap_proto::{
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
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
        let (blob_section, blob_hash) = self
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
            .blob_id()
            .and_then(|id| (id.section.as_ref()?.clone(), id.hash.clone()).into())
            .ok_or_else(|| {
                StatusResponse::no("Filed to retrieve blobId").with_code(ResponseCode::TryLater)
            })?;
        let script = self
            .jmap
            .get_blob_section(&blob_hash, &blob_section)
            .await?
            .ok_or_else(|| {
                StatusResponse::no("Script blob not found").with_code(ResponseCode::NonExistent)
            })?;
        debug_assert_eq!(script.len(), blob_section.size);

        let mut response = Vec::with_capacity(script.len() + 30);
        response.push(b'{');
        response.extend_from_slice(blob_section.size.to_string().as_bytes());
        response.extend_from_slice(b"}\r\n");
        response.extend(script);

        Ok(StatusResponse::ok("").serialize(response))
    }
}
