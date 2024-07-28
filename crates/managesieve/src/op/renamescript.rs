/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use imap_proto::receiver::Request;
use jmap::sieve::set::SCHEMA;
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{collection::Collection, property::Property, value::Value},
};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder};
use tokio::io::{AsyncRead, AsyncWrite};
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_renamescript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
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
            .jmap
            .get_property::<HashedValue<Object<Value>>>(
                account_id,
                Collection::SieveScript,
                document_id,
                Property::Value,
            )
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Script not found")
                    .code(ResponseCode::NonExistent)
            })?;

        // Write record
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new(SCHEMA)
                    .with_current(script)
                    .with_changes(
                        Object::with_capacity(1).with_property(Property::Name, new_name.clone()),
                    ),
            );
        if !batch.is_empty() {
            self.jmap
                .write_batch(batch)
                .await
                .caused_by(trc::location!())?;
            let mut changelog = ChangeLogBuilder::new();
            changelog.log_update(Collection::SieveScript, document_id);
            self.jmap
                .commit_changes(account_id, changelog)
                .await
                .caused_by(trc::location!())?;
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::RenameScript),
            SpanId = self.session_id,
            OldName = name,
            Name = new_name,
            DocumentId = document_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Success.").into_bytes())
    }
}
