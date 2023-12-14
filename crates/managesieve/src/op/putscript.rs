/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
    write::{assert::HashedValue, BatchBuilder, BlobOp, DirectoryValue, F_CLEAR},
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
        if access_token.quota > 0
            && script_bytes.len() as i64 + self.jmap.get_used_quota(account_id).await?
                > access_token.quota as i64
        {
            return Err(StatusResponse::no("Quota exceeded.").with_code(ResponseCode::Quota));
        }
        if self
            .jmap
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .map(|ids| ids.len() as usize)
            .unwrap_or(0)
            > self.jmap.config.sieve_max_scripts
        {
            return Err(
                StatusResponse::no("Too many scripts.").with_code(ResponseCode::QuotaMaxScripts)
            );
        }

        // Compile script
        match self.jmap.sieve_compiler.compile(&script_bytes) {
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
                .blob(prev_blob_id.hash.clone(), BlobOp::Link, F_CLEAR)
                .blob(blob_id.hash.clone(), BlobOp::Link, 0);

            // Update quota
            let prev_script_size = prev_blob_id.section.as_ref().unwrap().size as i64;
            let update_quota = match script_size.cmp(&prev_script_size) {
                std::cmp::Ordering::Greater => script_size - prev_script_size,
                std::cmp::Ordering::Less => -prev_script_size + script_size,
                std::cmp::Ordering::Equal => 0,
            };
            if update_quota != 0 {
                batch.add(DirectoryValue::UsedQuota(account_id), update_quota);
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
            // Obtain document id
            let document_id = self
                .jmap
                .assign_document_id(account_id, Collection::SieveScript)
                .await?;

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
            let mut changelog = self.jmap.begin_changes(account_id).await?;
            changelog.log_insert(Collection::SieveScript, document_id);
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .create_document(document_id)
                .add(DirectoryValue::UsedQuota(account_id), script_size)
                .blob(blob_id.hash.clone(), BlobOp::Link, 0)
                .custom(
                    ObjectIndexBuilder::new(SCHEMA).with_changes(
                        Object::with_capacity(3)
                            .with_property(Property::Name, name)
                            .with_property(Property::IsActive, Value::Bool(false))
                            .with_property(Property::BlobId, Value::BlobId(blob_id)),
                    ),
                )
                .custom(changelog);
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
        } else if name.len() > self.jmap.config.sieve_max_script_name {
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
