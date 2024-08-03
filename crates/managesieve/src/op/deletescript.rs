/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use imap_proto::receiver::Request;
use jmap_proto::types::collection::Collection;
use store::write::log::ChangeLogBuilder;
use tokio::io::{AsyncRead, AsyncWrite};
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_deletescript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
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
        if self
            .jmap
            .sieve_script_delete(account_id, document_id, true)
            .await
            .caused_by(trc::location!())?
        {
            // Write changes
            let mut changelog = ChangeLogBuilder::new();
            changelog.log_delete(Collection::SieveScript, document_id);
            self.jmap
                .commit_changes(account_id, changelog)
                .await
                .caused_by(trc::location!())?;

            trc::event!(
                ManageSieve(trc::ManageSieveEvent::DeleteScript),
                SpanId = self.session_id,
                Id = name,
                DocumentId = document_id,
                Elapsed = op_start.elapsed()
            );

            Ok(StatusResponse::ok("Deleted.").into_bytes())
        } else {
            Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("You may not delete an active script")
                .code(ResponseCode::Active))
        }
    }
}
