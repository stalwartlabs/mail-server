/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::receiver::Request;
use jmap::sieve::set::{ObjectBlobId, SCHEMA};
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
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Command, ResponseCode, Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_putscript(&mut self, request: Request<Command>) -> super::OpResult {
        let mut tokens = request.tokens.into_iter();
        let name = tokens
            .next()
            .and_then(|s| s.unwrap_string().ok())
            .ok_or_else(|| StatusResponse::no("Expected script name as a parameter."))?
            .trim()
            .to_string();
        let mut script_bytes = tokens
            .next()
            .ok_or_else(|| StatusResponse::no("Expected script as a parameter."))?
            .unwrap_bytes();
        let script_size = script_bytes.len() as i64;

        // Check quota
        let access_token = self.state.access_token();
        let account_id = access_token.primary_id();
        if !self
            .jmap
            .has_available_quota(
                account_id,
                access_token.quota as i64,
                script_bytes.len() as i64,
            )
            .await?
        {
            return Err(StatusResponse::no("Quota exceeded.").with_code(ResponseCode::Quota));
        }

        if self
            .jmap
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .map(|ids| ids.len() as usize)
            .unwrap_or(0)
            > self.jmap.core.jmap.sieve_max_scripts
        {
            return Err(
                StatusResponse::no("Too many scripts.").with_code(ResponseCode::QuotaMaxScripts)
            );
        }

        // Compile script
        match self
            .jmap
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
                    StatusResponse::no(err.to_string()).with_code(ResponseCode::QuotaMaxSize)
                } else {
                    StatusResponse::no(err.to_string())
                });
            }
        }

        // Validate name
        if let Some(document_id) = self.validate_name(account_id, &name).await? {
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
            let prev_blob_id = script.inner.blob_id().ok_or_else(|| {
                StatusResponse::no("Internal error while obtaining blobId")
                    .with_code(ResponseCode::TryLater)
            })?;

            // Write script blob
            let blob_id = BlobId::new(
                self.jmap
                    .put_blob(account_id, &script_bytes, false)
                    .await?
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
            }

            batch.custom(
                ObjectIndexBuilder::new(SCHEMA)
                    .with_current(script)
                    .with_changes(
                        Object::with_capacity(1)
                            .with_property(Property::BlobId, Value::BlobId(blob_id)),
                    ),
            );
            self.jmap.write_batch(batch).await?;
        } else {
            // Write script blob
            let blob_id = BlobId::new(
                self.jmap
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
                            .with_property(Property::Name, name)
                            .with_property(Property::IsActive, Value::Bool(false))
                            .with_property(Property::BlobId, Value::BlobId(blob_id)),
                    ),
                );
            self.jmap.write_batch(batch).await?;
        }

        Ok(StatusResponse::ok("Success.").into_bytes())
    }

    pub async fn validate_name(
        &self,
        account_id: u32,
        name: &str,
    ) -> Result<Option<u32>, StatusResponse> {
        if name.is_empty() {
            Err(StatusResponse::no("Script name cannot be empty."))
        } else if name.len() > self.jmap.core.jmap.sieve_max_script_name {
            Err(StatusResponse::no("Script name is too long."))
        } else if name.eq_ignore_ascii_case("vacation") {
            Err(StatusResponse::no(
                "The 'vacation' name is reserved, please use a different name.",
            ))
        } else {
            Ok(self
                .jmap
                .filter(
                    account_id,
                    Collection::SieveScript,
                    vec![Filter::eq(Property::Name, name)],
                )
                .await?
                .results
                .min())
        }
    }
}
