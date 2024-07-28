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

use crate::core::{Command, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_setactive(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
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

        // De/activate script
        let account_id = self.state.access_token().primary_id();
        let changes = self
            .jmap
            .sieve_activate_script(
                account_id,
                if !name.is_empty() {
                    self.get_script_id(account_id, &name).await?.into()
                } else {
                    None
                },
            )
            .await
            .caused_by(trc::location!())?;

        // Write changes
        if !changes.is_empty() {
            let mut changelog = ChangeLogBuilder::new();
            for (document_id, _) in changes {
                changelog.log_update(Collection::SieveScript, document_id);
            }
            self.jmap
                .commit_changes(account_id, changelog)
                .await
                .caused_by(trc::location!())?;
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::SetActive),
            SpanId = self.session_id,
            Name = name,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Success").into_bytes())
    }
}
