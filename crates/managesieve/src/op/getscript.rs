/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use email::sieve::SieveScript;
use imap_proto::receiver::Request;
use jmap_proto::types::{blob::BlobSection, collection::Collection};
use trc::AddContext;
use utils::BlobHash;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_getscript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveGetScript)?;

        let op_start = Instant::now();
        let name = request
            .tokens
            .into_iter()
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script name as a parameter.")
            })?;
        let account_id = self.state.access_token().primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        let sieve_ = self
            .server
            .get_archive(account_id, Collection::SieveScript, document_id)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script not found")
                    .code(ResponseCode::NonExistent)
            })?;
        let sieve = sieve_
            .unarchive::<SieveScript>()
            .caused_by(trc::location!())?;
        let blob_size = u32::from(sieve.size) as usize;
        let script = self
            .server
            .get_blob_section(
                &BlobHash::from(&sieve.blob_hash),
                &BlobSection {
                    size: blob_size,
                    ..Default::default()
                },
            )
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script blob not found")
                    .code(ResponseCode::NonExistent)
            })?;
        debug_assert_eq!(script.len(), blob_size);

        let mut response = Vec::with_capacity(script.len() + 32);
        response.push(b'{');
        response.extend_from_slice(blob_size.to_string().as_bytes());
        response.extend_from_slice(b"}\r\n");
        response.extend(script);
        response.extend_from_slice(b"\r\n");

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::GetScript),
            SpanId = self.session_id,
            Id = name,
            DocumentId = document_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("").serialize(response))
    }
}
