/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::receiver::Request;
use jmap::sieve::set::SCHEMA;
use jmap_proto::{
    error::method::MethodError,
    object::{index::ObjectIndexBuilder, Object},
    types::{collection::Collection, property::Property, value::Value},
};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_renamescript(&mut self, request: Request<Command>) -> super::OpResult {
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected old script name as a parameter."))?
            .trim()
            .to_string();
        let new_name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected new script name as a parameter."))?
            .trim()
            .to_string();

        // Validate name
        if name == new_name {
            return Ok(StatusResponse::ok("Old and new script names are the same.").into_bytes());
        }
        let account_id = self.state.access_token().primary_id();
        let document_id = self.get_script_id(account_id, &name).await?;
        if self.validate_name(account_id, &new_name).await?.is_some() {
            return Err(StatusResponse::no(format!(
                "A sieve script with name '{name}' already exists.",
            ))
            .with_code(ResponseCode::AlreadyExists));
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
            .await?
            .ok_or_else(|| {
                StatusResponse::no("Script not found").with_code(ResponseCode::NonExistent)
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
                    .with_changes(Object::with_capacity(1).with_property(Property::Name, new_name)),
            );
        if !batch.is_empty() {
            match self.jmap.write_batch(batch).await {
                Ok(_) => {
                    let mut changelog = ChangeLogBuilder::new();
                    changelog.log_update(Collection::SieveScript, document_id);
                    self.jmap.commit_changes(account_id, changelog).await?;
                }
                Err(MethodError::ServerUnavailable) => {
                    return Err(StatusResponse::no(
                        "Another process modified this script, please try again.",
                    )
                    .with_code(ResponseCode::TryLater));
                }
                Err(_) => {
                    return Err(StatusResponse::database_failure());
                }
            }
        }

        Ok(StatusResponse::ok("Success.").into_bytes())
    }
}
