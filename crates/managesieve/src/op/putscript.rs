/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use imap_proto::receiver::Request;
use jmap::{
    blob::upload::BlobUpload,
    sieve::set::{ObjectBlobId, SCHEMA},
    JmapMethods,
};
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{blob::BlobId, collection::Collection, property::Property, value::Value},
};
use sieve::compiler::ErrorType;
use store::{
    query::Filter,
    write::{assert::HashedValue, log::LogInsert, BatchBuilder, BlobOp, DirectoryClass},
    BlobClass,
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
            let prev_blob_id = script.inner.blob_id().ok_or_else(|| {
                trc::ManageSieveEvent::Error
                    .into_err()
                    .details("Internal error while obtaining blobId")
                    .code(ResponseCode::TryLater)
            })?;

            // Write script blob
            let blob_id = BlobId::new(
                self.server
                    .put_blob(account_id, &script_bytes, false)
                    .await
                    .caused_by(trc::location!())?
                    .hash,
                BlobClass::Linked {
                    account_id,
                    collection: Collection::SieveScript.into(),
                    document_id,
                },
            )
            .with_section_size(script_size as usize);

            // Write record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .update_document(document_id)
                .clear(BlobOp::Link {
                    hash: prev_blob_id.hash.clone(),
                })
                .set(
                    BlobOp::Link {
                        hash: blob_id.hash.clone(),
                    },
                    Vec::new(),
                );

            // Update quota
            let prev_script_size = prev_blob_id.section.as_ref().unwrap().size as i64;
            let update_quota = match script_size.cmp(&prev_script_size) {
                std::cmp::Ordering::Greater => script_size - prev_script_size,
                std::cmp::Ordering::Less => -prev_script_size + script_size,
                std::cmp::Ordering::Equal => 0,
            };
            if update_quota != 0 {
                batch.add(DirectoryClass::UsedQuota(account_id), update_quota);

                // Update tenant quota
                #[cfg(feature = "enterprise")]
                if self.server.core.is_enterprise_edition() {
                    if let Some(tenant) = resource_token.tenant {
                        batch.add(DirectoryClass::UsedQuota(tenant.id), update_quota);
                    }
                }
            }

            batch.custom(
                ObjectIndexBuilder::new(SCHEMA)
                    .with_current(script)
                    .with_changes(
                        Object::with_capacity(1)
                            .with_property(Property::BlobId, Value::BlobId(blob_id)),
                    ),
            );
            self.server
                .write_batch(batch)
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
            let blob_id = BlobId::new(
                self.server
                    .put_blob(account_id, &script_bytes, false)
                    .await?
                    .hash,
                BlobClass::Linked {
                    account_id,
                    collection: Collection::SieveScript.into(),
                    document_id: 0,
                },
            )
            .with_section_size(script_size as usize);

            // Write record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .create_document()
                .log(LogInsert())
                .add(DirectoryClass::UsedQuota(account_id), script_size)
                .set(
                    BlobOp::Link {
                        hash: blob_id.hash.clone(),
                    },
                    Vec::new(),
                )
                .custom(
                    ObjectIndexBuilder::new(SCHEMA).with_changes(
                        Object::with_capacity(3)
                            .with_property(Property::Name, name.clone())
                            .with_property(Property::IsActive, Value::Bool(false))
                            .with_property(Property::BlobId, Value::BlobId(blob_id)),
                    ),
                );

            // Update tenant quota
            #[cfg(feature = "enterprise")]
            if self.server.core.is_enterprise_edition() {
                if let Some(tenant) = resource_token.tenant {
                    batch.add(DirectoryClass::UsedQuota(tenant.id), script_size);
                }
            }

            let assigned_ids = self
                .server
                .write_batch(batch)
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
                .filter(
                    account_id,
                    Collection::SieveScript,
                    vec![Filter::eq(Property::Name, name)],
                )
                .await
                .caused_by(trc::location!())?
                .results
                .min())
        }
    }
}
