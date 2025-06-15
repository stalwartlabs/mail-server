/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use email::sieve::delete::SieveScriptDelete;
use imap_proto::receiver::Request;
use store::write::BatchBuilder;
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_deletescript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveDeleteScript)?;

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

        let access_token = self.state.access_token();
        let account_id = access_token.primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        let mut batch = BatchBuilder::new();

        match self
            .server
            .sieve_script_delete(
                &access_token.as_resource_token(),
                document_id,
                true,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?
        {
            Some(true) => {
                if !batch.is_empty() {
                    self.server
                        .commit_batch(batch)
                        .await
                        .caused_by(trc::location!())?;
                }

                trc::event!(
                    ManageSieve(trc::ManageSieveEvent::DeleteScript),
                    SpanId = self.session_id,
                    Id = name,
                    DocumentId = document_id,
                    Elapsed = op_start.elapsed()
                );

                Ok(StatusResponse::ok("Deleted.").into_bytes())
            }
            Some(false) => Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("You may not delete an active script")
                .code(ResponseCode::Active)),
            None => Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("Script not found")),
        }
    }
}
