/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::{listener::SessionStream, storage::index::ObjectIndexBuilder};
use directory::Permission;
use email::sieve::SieveScript;
use imap_proto::receiver::Request;
use jmap_proto::types::collection::Collection;
use store::write::BatchBuilder;
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_renamescript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveRenameScript)?;

        let op_start = Instant::now();
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected old script name as a parameter.")
            })?
            .trim()
            .to_string();
        let new_name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected new script name as a parameter.")
            })?
            .trim()
            .to_string();

        // Validate name
        if name == new_name {
            return Ok(StatusResponse::ok("Old and new script names are the same.").into_bytes());
        }
        let account_id = self.state.access_token().primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        if self.validate_name(account_id, &new_name).await?.is_some() {
            return Err(trc::ManageSieveEvent::Error
                .into_err()
                .details(format!("A sieve script with name '{name}' already exists.",))
                .code(ResponseCode::AlreadyExists));
        }

        // Obtain script values
        let script = self
            .server
            .get_archive(account_id, Collection::SieveScript, document_id)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script not found")
                    .code(ResponseCode::NonExistent)
            })?
            .into_deserialized::<SieveScript>()
            .caused_by(trc::location!())?;

        // Write record
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_changes(script.inner.clone().with_name(new_name.clone()))
                    .with_current(script),
            )
            .caused_by(trc::location!())?;
        if !batch.is_empty() {
            self.server
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?;
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::RenameScript),
            SpanId = self.session_id,
            Id = new_name,
            DocumentId = document_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Success.").into_bytes())
    }
}
