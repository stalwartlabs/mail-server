/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use sieve::Sieve;
use store::{
    query::Filter,
    write::{assert::HashedValue, BatchBuilder, Bincode, BlobOp},
    BlobClass, Deserialize, Serialize,
};

use crate::{sieve::SeenIds, JMAP};

use super::ActiveScript;

impl JMAP {
    pub async fn sieve_script_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
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
                .take(self.core.jmap.get_max_objects)
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
                    Property::Name | Property::IsActive => {
                        result.append(property.clone(), push.remove(property));
                    }
                    Property::BlobId => {
                        result.append(
                            Property::BlobId,
                            match push.remove(&Property::BlobId) {
                                Value::BlobId(mut blob_id) => {
                                    blob_id.class = BlobClass::Linked {
                                        account_id,
                                        collection: Collection::SieveScript.into(),
                                        document_id,
                                    };
                                    Value::BlobId(blob_id)
                                }
                                other => other,
                            },
                        );
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
    ) -> trc::Result<Option<ActiveScript>> {
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
    ) -> trc::Result<Option<Sieve>> {
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

    #[allow(clippy::blocks_in_conditions)]
    async fn sieve_script_compile(
        &self,
        account_id: u32,
        document_id: u32,
    ) -> trc::Result<(Sieve, Object<Value>)> {
        // Obtain script object
        let script_object = self
            .get_property::<HashedValue<Object<Value>>>(
                account_id,
                Collection::SieveScript,
                document_id,
                Property::Value,
            )
            .await?
            .ok_or_else(|| {
                trc::StoreCause::NotFound
                    .into_err()
                    .caused_by(trc::location!())
                    .document_id(document_id)
            })?;

        // Obtain the sieve script length
        let (script_offset, blob_id) = script_object
            .inner
            .properties
            .get(&Property::BlobId)
            .and_then(|v| v.as_blob_id())
            .and_then(|v| (v.section.as_ref()?.size, v).into())
            .ok_or_else(|| {
                trc::StoreCause::NotFound
                    .into_err()
                    .caused_by(trc::location!())
                    .document_id(document_id)
            })?;

        // Obtain the sieve script blob
        let script_bytes = self
            .get_blob(&blob_id.hash, 0..usize::MAX)
            .await?
            .ok_or_else(|| {
                trc::StoreCause::NotFound
                    .into_err()
                    .caused_by(trc::location!())
                    .document_id(document_id)
            })?;

        // Obtain the precompiled script
        if let Some(sieve) = script_bytes
            .get(script_offset..)
            .and_then(|bytes| Bincode::<Sieve>::deserialize(bytes).ok())
        {
            Ok((sieve.inner, script_object.inner))
        } else {
            // Deserialization failed, probably because the script compiler version changed
            match self.core.sieve.untrusted_compiler.compile(
                script_bytes.get(0..script_offset).ok_or_else(|| {
                    trc::StoreCause::NotFound
                        .into_err()
                        .caused_by(trc::location!())
                        .document_id(document_id)
                })?,
            ) {
                Ok(sieve) => {
                    // Store updated compiled sieve script
                    let sieve = Bincode::new(sieve);
                    let compiled_bytes = (&sieve).serialize();
                    let mut updated_sieve_bytes =
                        Vec::with_capacity(script_offset + compiled_bytes.len());
                    updated_sieve_bytes.extend_from_slice(&script_bytes[0..script_offset]);
                    updated_sieve_bytes.extend_from_slice(&compiled_bytes);

                    // Store updated blob
                    let mut new_blob_id = blob_id.clone();
                    new_blob_id.hash = self
                        .put_blob(account_id, &updated_sieve_bytes, false)
                        .await?
                        .hash;
                    let mut new_script_object = script_object.inner.clone();
                    new_script_object.set(Property::BlobId, new_blob_id.clone());

                    // Update script object
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::SieveScript)
                        .update_document(document_id)
                        .assert_value(Property::Value, &script_object)
                        .set(Property::Value, (&new_script_object).serialize())
                        .clear(BlobOp::Link {
                            hash: blob_id.hash.clone(),
                        })
                        .set(
                            BlobOp::Link {
                                hash: new_blob_id.hash,
                            },
                            Vec::new(),
                        );
                    self.write_batch(batch).await?;

                    Ok((sieve.inner, new_script_object))
                }
                Err(error) => Err(trc::StoreCause::Unexpected
                    .caused_by(trc::location!())
                    .reason(error)
                    .details("Failed to compile Sieve script")),
            }
        }
    }
}
