/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use std::sync::Arc;

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{blob::BlobId, collection::Collection, property::Property, value::Value},
};
use sieve::Sieve;
use store::{query::Filter, BlobKind, Deserialize, Serialize};

use crate::{sieve::SeenIds, Bincode, JMAP};

use super::ActiveScript;

impl JMAP {
    pub async fn sieve_script_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
        let properties =
            request.unwrap_properties(&[Property::Id, Property::Name, Property::BlobId]);
        let account_id = request.account_id.document_id();
        let push_ids = self
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            push_ids
                .iter()
                .take(self.config.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, Collection::SieveScript)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the sieve script object
            let document_id = id.document_id();
            if !push_ids.contains(document_id) {
                response.not_found.push(id.into());
                continue;
            }
            let mut push = if let Some(push) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                push
            } else {
                response.not_found.push(id.into());
                continue;
            };
            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                match property {
                    Property::Id => {
                        result.append(Property::Id, Value::Id(id));
                    }
                    Property::BlobId => {
                        if let Some(Value::UnsignedInt(blob_size)) =
                            push.properties.remove(&Property::Size)
                        {
                            result.append(
                                Property::BlobId,
                                BlobId::linked(account_id, Collection::SieveScript, document_id)
                                    .with_section_size(blob_size as usize),
                            );
                        }
                    }
                    Property::Name | Property::IsActive => {
                        result.append(property.clone(), push.remove(property));
                    }
                    property => {
                        result.append(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }

    pub async fn sieve_script_get_active(
        &self,
        account_id: u32,
    ) -> Result<Option<ActiveScript>, MethodError> {
        // Find the currently active script
        if let Some(document_id) = self
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::IsActive, 1u32)],
            )
            .await?
            .results
            .min()
        {
            let (script, mut script_object) =
                self.sieve_script_compile(account_id, document_id).await?;
            Ok(Some(ActiveScript {
                document_id,
                script: Arc::new(script),
                script_name: script_object
                    .properties
                    .remove(&Property::Name)
                    .and_then(|name| name.try_unwrap_string())
                    .unwrap_or_else(|| account_id.to_string()),
                seen_ids: self
                    .get_property::<Bincode<SeenIds>>(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                        Property::EmailIds,
                    )
                    .await?
                    .map(|seen_ids| seen_ids.inner)
                    .unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn sieve_script_get_by_name(
        &self,
        account_id: u32,
        name: &str,
    ) -> Result<Option<Sieve>, MethodError> {
        // Find the script by name
        if let Some(document_id) = self
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::Name, name)],
            )
            .await?
            .results
            .min()
        {
            self.sieve_script_compile(account_id, document_id)
                .await
                .map(|(sieve, _)| Some(sieve))
        } else {
            Ok(None)
        }
    }

    async fn sieve_script_compile(
        &self,
        account_id: u32,
        document_id: u32,
    ) -> Result<(Sieve, Object<Value>), MethodError> {
        // Obtain script object
        let script_object = self
            .get_property::<Object<Value>>(
                account_id,
                Collection::SieveScript,
                document_id,
                Property::Value,
            )
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    context = "sieve_script_compile",
                    event = "error",
                    account_id = account_id,
                    document_id = document_id,
                    "Failed to obtain sieve script object"
                );

                MethodError::ServerPartialFail
            })?;

        // Obtain the sieve script length
        let script_offset = script_object
            .properties
            .get(&Property::Size)
            .and_then(|value| value.as_uint())
            .ok_or_else(|| {
                tracing::warn!(
                    context = "sieve_script_compile",
                    event = "error",
                    account_id = account_id,
                    document_id = document_id,
                    "Failed to obtain sieve script offset"
                );

                MethodError::ServerPartialFail
            })? as usize;

        // Obtain the sieve script blob
        let script_bytes = self
            .get_blob(
                &BlobKind::Linked {
                    account_id,
                    collection: Collection::SieveScript.into(),
                    document_id,
                },
                0..u32::MAX,
            )
            .await?
            .ok_or(MethodError::ServerPartialFail)?;

        // Obtain the precompiled script
        if let Some(sieve) = script_bytes
            .get(script_offset..)
            .and_then(|bytes| Bincode::<Sieve>::deserialize(bytes).ok())
        {
            Ok((sieve.inner, script_object))
        } else {
            // Deserialization failed, probably because the script compiler version changed
            match self
                .sieve_compiler
                .compile(script_bytes.get(0..script_offset).ok_or_else(|| {
                    tracing::warn!(
                        context = "sieve_script_compile",
                        event = "error",
                        account_id = account_id,
                        document_id = document_id,
                        "Invalid sieve script offset"
                    );

                    MethodError::ServerPartialFail
                })?) {
                Ok(sieve) => {
                    // Store updated compiled sieve script
                    let sieve = Bincode::new(sieve);
                    let compiled_bytes = (&sieve).serialize();
                    let mut updated_sieve_bytes =
                        Vec::with_capacity(script_offset + compiled_bytes.len());
                    updated_sieve_bytes.extend_from_slice(&script_bytes[0..script_offset]);
                    updated_sieve_bytes.extend_from_slice(&compiled_bytes);
                    let _ = self
                        .put_blob(
                            &BlobKind::Linked {
                                account_id,
                                collection: Collection::SieveScript.into(),
                                document_id,
                            },
                            &updated_sieve_bytes,
                        )
                        .await;

                    Ok((sieve.inner, script_object))
                }
                Err(error) => {
                    tracing::warn!(
                            context = "sieve_script_compile",
                            event = "error",
                            account_id = account_id,
                            document_id = document_id,
                            reason = %error,
                            "Failed to compile sieve script");
                    Err(MethodError::ServerPartialFail)
                }
            }
        }
    }
}
