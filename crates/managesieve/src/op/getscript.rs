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
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_getscript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        let name = request
            .tokens
            .into_iter()
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::Cause::ManageSieve
                    .into_err()
                    .details("Expected script name as a parameter.")
            })?;
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
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::Cause::ManageSieve
                    .into_err()
                    .details("Script not found")
                    .code(ResponseCode::NonExistent)
            })?
            .blob_id()
            .and_then(|id| (id.section.as_ref()?.clone(), id.hash.clone()).into())
            .ok_or_else(|| {
                trc::Cause::ManageSieve
                    .into_err()
                    .details("Failed to retrieve blobId")
                    .code(ResponseCode::TryLater)
            })?;
        let script = self
            .jmap
            .get_blob_section(&blob_hash, &blob_section)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::Cause::ManageSieve
                    .into_err()
                    .details("Script blob not found")
                    .code(ResponseCode::NonExistent)
            })?;
        debug_assert_eq!(script.len(), blob_section.size);

        let mut response = Vec::with_capacity(script.len() + 32);
        response.push(b'{');
        response.extend_from_slice(blob_section.size.to_string().as_bytes());
        response.extend_from_slice(b"}\r\n");
        response.extend(script);
        response.extend_from_slice(b"\r\n");

        Ok(StatusResponse::ok("").serialize(response))
    }
}
