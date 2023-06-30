/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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
use jmap::sieve::set::SCHEMA;
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{blob::BlobId, collection::Collection, property::Property, value::Value},
};
use sieve::compiler::ErrorType;
use store::{query::Filter, write::BatchBuilder};
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
        let mut script = tokens
            .next()
            .ok_or_else(|| StatusResponse::no("Expected script as a parameter."))?
            .unwrap_bytes();
        let script_len = script.len() as u64;

        // Check quota
        let access_token = self.state.access_token();
        let account_id = access_token.primary_id();
        if access_token.quota > 0
            && script.len() as i64 + self.jmap.get_used_quota(account_id).await?
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

        // Validate name
        self.validate_name(account_id, &name).await?;

        // Compile script
        match self.jmap.sieve_compiler.compile(&script) {
            Ok(compiled_script) => {
                script.extend(bincode::serialize(&compiled_script).unwrap_or_default());
            }
            Err(err) => {
                return Err(if let ErrorType::ScriptTooLong = &err.error_type() {
                    StatusResponse::no(err.to_string()).with_code(ResponseCode::QuotaMaxSize)
                } else {
                    StatusResponse::no(err.to_string())
                });
            }
        }

        // Obtain document id
        let document_id = self
            .jmap
            .assign_document_id(account_id, Collection::SieveScript)
            .await?;

        // Store blob
        self.jmap
            .put_blob(
                &BlobId::linked(account_id, Collection::SieveScript, document_id).kind,
                &script,
            )
            .await?;

        // Write record
        let mut changelog = self.jmap.begin_changes(account_id).await?;
        changelog.log_insert(Collection::SieveScript, document_id);
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::new(SCHEMA).with_changes(
                    Object::with_capacity(3)
                        .with_property(Property::Name, name)
                        .with_property(Property::IsActive, Value::Bool(false))
                        .with_property(Property::Size, Value::UnsignedInt(script_len)),
                ),
            )
            .custom(changelog);
        self.jmap.write_batch(batch).await?;

        Ok(StatusResponse::ok("Success.").into_bytes())
    }

    pub async fn validate_name(&self, account_id: u32, name: &str) -> Result<(), StatusResponse> {
        if name.is_empty() {
            Err(StatusResponse::no("Script name cannot be empty."))
        } else if name.len() > self.jmap.config.sieve_max_script_name {
            Err(StatusResponse::no("Script name is too long."))
        } else if name.eq_ignore_ascii_case("vacation") {
            Err(StatusResponse::no(
                "The 'vacation' name is reserved, please use a different name.",
            ))
        } else if !self
            .jmap
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::Name, name)],
            )
            .await?
            .results
            .is_empty()
        {
            Err(
                StatusResponse::no(format!("A sieve script with name '{name}' already exists.",))
                    .with_code(ResponseCode::AlreadyExists),
            )
        } else {
            Ok(())
        }
    }
}
