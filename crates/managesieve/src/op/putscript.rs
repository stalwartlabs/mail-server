/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::{listener::SessionStream, storage::index::ObjectIndexBuilder};
use directory::Permission;
use email::sieve::SieveScript;
use imap_proto::receiver::Request;
use jmap_proto::types::{collection::Collection, property::Property};
use sieve::compiler::ErrorType;
use store::{
    query::Filter,
    write::{Archive, BatchBuilder, assert::HashedValue, log::LogInsert},
};
use trc::AddContext;

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_putscript(&mut self, request: Request<Command>) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SievePutScript)?;

        let op_start = Instant::now();
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script name as a parameter.")
            })?
            .trim()
            .to_string();
        let mut script_bytes = tokens
            .next()
            .ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Expected script as a parameter.")
            })?
            .unwrap_bytes();
        let script_size = script_bytes.len() as i64;

        // Check quota
        let resource_token = self.state.access_token().as_resource_token();
        let account_id = resource_token.account_id;
        self.server
            .has_available_quota(&resource_token, script_bytes.len() as u64)
            .await
            .caused_by(trc::location!())?;

        if self
            .server
            .get_document_ids(account_id, Collection::SieveScript)
            .await
            .caused_by(trc::location!())?
            .map(|ids| ids.len() as usize)
            .unwrap_or(0)
            > self.server.core.jmap.sieve_max_scripts
        {
            return Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("Too many scripts.")
                .code(ResponseCode::QuotaMaxScripts));
        }

        // Compile script
        match self
            .server
            .core
            .sieve
            .untrusted_compiler
            .compile(&script_bytes)
        {
            Ok(compiled_script) => {
                script_bytes.extend(bincode::serialize(&compiled_script).unwrap_or_default());
            }
            Err(err) => {
                return Err(if let ErrorType::ScriptTooLong = &err.error_type() {
                    trc::ManageSieveEvent::Error
                        .into_err()
                        .details(err.to_string())
                        .code(ResponseCode::QuotaMaxSize)
                } else {
                    trc::ManageSieveEvent::Error
                        .into_err()
                        .details(err.to_string())
                });
            }
        }

        // Validate name
        if let Some(document_id) = self.validate_name(account_id, &name).await? {
            // Obtain script values
            let script = self
                .server
                .get_property::<HashedValue<Archive>>(
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
                })?
                .into_deserialized::<SieveScript>()
                .caused_by(trc::location!())?;

            // Write script blob
            let blob_hash = self
                .server
                .put_blob(account_id, &script_bytes, false)
                .await
                .caused_by(trc::location!())?
                .hash;

            // Write record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_changes(
                            script
                                .inner
                                .clone()
                                .with_size(script_size as u32)
                                .with_blob_hash(blob_hash.clone()),
                        )
                        .with_current(script)
                        .with_tenant_id(&resource_token),
                )
                .caused_by(trc::location!())?;

            self.server
                .store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;

            trc::event!(
                ManageSieve(trc::ManageSieveEvent::UpdateScript),
                SpanId = self.session_id,
                Id = name.to_string(),
                DocumentId = document_id,
                Size = script_size,
                Elapsed = op_start.elapsed(),
            );
        } else {
            // Write script blob
            let blob_hash = self
                .server
                .put_blob(account_id, &script_bytes, false)
                .await?
                .hash;

            // Write record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .create_document()
                .log(LogInsert())
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(
                            SieveScript::new(name.clone(), blob_hash.clone())
                                .with_is_active(false)
                                .with_size(script_size as u32),
                        )
                        .with_tenant_id(&resource_token),
                )
                .caused_by(trc::location!())?;

            let assigned_ids = self
                .server
                .store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;

            trc::event!(
                ManageSieve(trc::ManageSieveEvent::CreateScript),
                SpanId = self.session_id,
                Id = name,
                DocumentId = assigned_ids.last_document_id().ok(),
                Elapsed = op_start.elapsed()
            );
        }

        Ok(StatusResponse::ok("Success.").into_bytes())
    }

    pub async fn validate_name(&self, account_id: u32, name: &str) -> trc::Result<Option<u32>> {
        if name.is_empty() {
            Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("Script name cannot be empty."))
        } else if name.len() > self.server.core.jmap.sieve_max_script_name {
            Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("Script name is too long."))
        } else if name.eq_ignore_ascii_case("vacation") {
            Err(trc::ManageSieveEvent::Error
                .into_err()
                .details("The 'vacation' name is reserved, please use a different name."))
        } else {
            Ok(self
                .server
                .store()
                .filter(
                    account_id,
                    Collection::SieveScript,
                    vec![Filter::eq(Property::Name, name.to_lowercase().into_bytes())],
                )
                .await
                .caused_by(trc::location!())?
                .results
                .min())
        }
    }
}
