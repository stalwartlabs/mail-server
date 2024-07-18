/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{RequestArguments, SetRequest, SetResponse},
    object::{index::ObjectIndexBuilder, Object},
    response::references::EvalObjectReferences,
    types::{
        blob::BlobId,
        collection::Collection,
        id::Id,
        property::Property,
        value::{MaybePatchValue, Value},
    },
};
use mail_builder::MessageBuilder;
use mail_parser::decoders::html::html_to_text;
use store::write::{
    assert::HashedValue,
    log::{Changes, LogInsert},
    BatchBuilder, BlobOp, DirectoryClass, F_CLEAR, F_VALUE,
};

use crate::{
    sieve::set::{ObjectBlobId, SCHEMA},
    JMAP,
};

impl JMAP {
    pub async fn vacation_response_set(
        &self,
        mut request: SetRequest<RequestArguments>,
    ) -> trc::Result<SetResponse> {
        let account_id = request.account_id.document_id();
        let mut response = self
            .prepare_set_response(&request, Collection::SieveScript)
            .await?;
        let will_destroy = request.unwrap_destroy();

        // Process set or update requests
        let mut create_id = None;
        let mut changes = None;
        match (request.create, request.update) {
            (Some(create), Some(update)) if !create.is_empty() && !update.is_empty() => {
                return Err(trc::JmapCause::InvalidArguments
                    .into_err()
                    .details("Creating and updating on the same request is not allowed."));
            }
            (Some(create), _) if !create.is_empty() => {
                for (id, obj) in create {
                    if will_destroy.contains(&Id::singleton()) {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::WillDestroy)
                                .with_description("ID will be destroyed."),
                        );
                    } else if create_id.is_some() {
                        response.not_created.append(
                            id,
                            SetError::forbidden()
                                .with_description("Only one object can be created."),
                        );
                    } else {
                        create_id = Some(id);
                        changes = Some(obj);
                    }
                }
            }
            (_, Some(update)) if !update.is_empty() => {
                for (id, obj) in update {
                    if id.is_singleton() {
                        if !will_destroy.contains(&id) {
                            changes = Some(obj);
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::new(SetErrorType::WillDestroy)
                                    .with_description("ID will be destroyed."),
                            );
                        }
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::new(SetErrorType::NotFound).with_description("ID not found."),
                        );
                    }
                }
            }
            _ => {
                if will_destroy.is_empty() {
                    return Ok(response);
                }
            }
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        let change_id = self.assign_change_id(account_id).await?;
        batch
            .with_change_id(change_id)
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript);

        // Process changes
        if let Some(changes_) = changes {
            // Parse properties
            let mut changes = Object::with_capacity(changes_.properties.len());
            let mut is_active = false;
            let mut build_script = create_id.is_some();

            for (property, value) in changes_.properties {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        return Ok(set_error(response, create_id, err));
                    }
                };
                match (&property, value) {
                    (Property::Subject, MaybePatchValue::Value(Value::Text(value)))
                        if value.len() < 512 =>
                    {
                        build_script = true;
                        changes.append(property, Value::Text(value));
                    }
                    (
                        Property::HtmlBody | Property::TextBody,
                        MaybePatchValue::Value(Value::Text(value)),
                    ) if value.len() < 2048 => {
                        build_script = true;

                        changes.append(property, Value::Text(value));
                    }
                    (
                        Property::ToDate | Property::FromDate,
                        MaybePatchValue::Value(value @ Value::Date(_)),
                    ) => {
                        build_script = true;
                        changes.append(property, value);
                    }
                    (Property::IsEnabled, MaybePatchValue::Value(Value::Bool(value))) => {
                        is_active = value;
                        changes.append(Property::IsActive, value);
                    }
                    (Property::IsEnabled, MaybePatchValue::Value(Value::Null)) => {
                        changes.append(Property::IsActive, Value::Bool(false));
                    }
                    (
                        Property::Subject
                        | Property::HtmlBody
                        | Property::TextBody
                        | Property::ToDate
                        | Property::FromDate,
                        MaybePatchValue::Value(Value::Null),
                    ) => {
                        if create_id.is_none() {
                            build_script = true;

                            changes.append(property, Value::Null);
                        }
                    }
                    _ => {
                        return Ok(set_error(
                            response,
                            create_id,
                            SetError::invalid_properties()
                                .with_property(property)
                                .with_description("Field could not be set."),
                        ));
                    }
                }
            }

            // Add name and isActive
            if create_id.is_some() {
                changes.append(Property::Name, Value::Text("vacation".into()));
                if !changes.properties.contains_key(&Property::IsActive) {
                    changes.append(Property::IsActive, Value::Bool(false));
                }
            }

            // Obtain current script
            let document_id = self.get_vacation_sieve_script_id(account_id).await?;
            let mut was_active = false;

            let mut obj = ObjectIndexBuilder::new(SCHEMA)
                .with_current_opt(if let Some(document_id) = document_id {
                    self.get_property::<HashedValue<Object<Value>>>(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                        Property::Value,
                    )
                    .await?
                    .map(|value| {
                        was_active = value.inner.properties.get(&Property::IsActive)
                            == Some(&Value::Bool(true));
                        value
                    })
                    .ok_or_else(|| {
                        trc::StoreCause::NotFound
                            .into_err()
                            .caused_by(trc::location!())
                    })?
                    .into()
                } else {
                    None
                })
                .with_changes(changes);

            // Update id
            if let Some(document_id) = document_id {
                batch
                    .update_document(document_id)
                    .value(Property::EmailIds, (), F_VALUE | F_CLEAR)
                    .log(Changes::update([document_id]));
            } else {
                batch.create_document().log(LogInsert());
            }

            // Create sieve script only if there are changes
            if build_script {
                // Upload new blob
                let hash = self
                    .put_blob(account_id, &self.build_script(&mut obj)?, false)
                    .await?
                    .hash;
                let blob_id = obj.changes_mut().unwrap().blob_id_mut().unwrap();
                blob_id.hash = hash;
                /*blob_id.class = BlobClass::Linked {
                    account_id,
                    collection: Collection::SieveScript.into(),
                    document_id: u32::MAX,
                };*/

                // Link blob
                batch.set(
                    BlobOp::Link {
                        hash: blob_id.hash.clone(),
                    },
                    Vec::new(),
                );

                let script_size = blob_id.section.as_ref().unwrap().size as i64;

                if let Some(current) = obj.current() {
                    let current_blob_id = current.inner.blob_id().ok_or_else(|| {
                        trc::StoreCause::NotFound
                            .into_err()
                            .caused_by(trc::location!())
                            .document_id(document_id.unwrap_or(u32::MAX))
                    })?;

                    // Unlink previous blob
                    batch.clear(BlobOp::Link {
                        hash: current_blob_id.hash.clone(),
                    });

                    // Update quota
                    let current_script_size = current_blob_id.section.as_ref().unwrap().size as i64;
                    let quota = match script_size.cmp(&current_script_size) {
                        std::cmp::Ordering::Greater => script_size - current_script_size,
                        std::cmp::Ordering::Less => -current_script_size + script_size,
                        std::cmp::Ordering::Equal => 0,
                    };
                    if quota != 0 {
                        batch.add(DirectoryClass::UsedQuota(account_id), quota);
                    }
                } else {
                    batch.add(DirectoryClass::UsedQuota(account_id), script_size);
                }
            };

            // Write changes
            batch.custom(obj);
            let document_id = if !batch.is_empty() {
                let ids = self.write_batch(batch).await?;
                response.new_state = Some(change_id.into());
                match document_id {
                    Some(document_id) => document_id,
                    None => ids.last_document_id()?,
                }
            } else {
                document_id.unwrap_or(u32::MAX)
            };

            // Deactivate other sieve scripts
            if !was_active && is_active {
                self.sieve_activate_script(account_id, document_id.into())
                    .await?;
            }

            // Add result
            if let Some(create_id) = create_id {
                response.created.insert(
                    create_id,
                    Object::with_capacity(1).with_property(Property::Id, Id::singleton()),
                );
            } else {
                response.updated.append(Id::singleton(), None);
            }
        } else if !will_destroy.is_empty() {
            for id in will_destroy {
                if id.is_singleton() {
                    if let Some(document_id) = self.get_vacation_sieve_script_id(account_id).await?
                    {
                        self.sieve_script_delete(account_id, document_id, false)
                            .await?;
                        batch.log(Changes::delete([document_id]));
                        response.destroyed.push(id);
                        continue;
                    }
                }

                response.not_destroyed.append(id, SetError::not_found());
            }

            // Write changes
            if !batch.is_empty() {
                self.write_batch(batch).await?;
                response.new_state = Some(change_id.into());
            }
        }

        Ok(response)
    }

    fn build_script(&self, obj: &mut ObjectIndexBuilder) -> trc::Result<Vec<u8>> {
        // Build Sieve script
        let mut script = Vec::with_capacity(1024);
        script.extend_from_slice(b"require [\"vacation\", \"relational\", \"date\"];\r\n\r\n");
        let mut num_blocks = 0;

        // Add start date
        if let Value::Date(value) = obj.get(&Property::FromDate) {
            script.extend_from_slice(b"if currentdate :value \"ge\" \"iso8601\" \"");
            script.extend_from_slice(value.to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        // Add end date
        if let Value::Date(value) = obj.get(&Property::ToDate) {
            script.extend_from_slice(b"if currentdate :value \"le\" \"iso8601\" \"");
            script.extend_from_slice(value.to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        script.extend_from_slice(b"vacation :mime ");
        if let Value::Text(value) = obj.get(&Property::Subject) {
            script.extend_from_slice(b":subject \"");
            for &ch in value.as_bytes().iter() {
                match ch {
                    b'\\' | b'\"' => {
                        script.push(b'\\');
                    }
                    b'\r' | b'\n' => {
                        continue;
                    }
                    _ => (),
                }
                script.push(ch);
            }
            script.extend_from_slice(b"\" ");
        }

        let mut text_body = if let Value::Text(value) = obj.get(&Property::TextBody) {
            Cow::from(value.as_str()).into()
        } else {
            None
        };
        let html_body = if let Value::Text(value) = obj.get(&Property::HtmlBody) {
            Cow::from(value.as_str()).into()
        } else {
            None
        };
        match (&html_body, &text_body) {
            (Some(html_body), None) => {
                text_body = Cow::from(html_to_text(html_body.as_ref())).into();
            }
            (None, None) => {
                text_body = Cow::from("I am away.").into();
            }
            _ => (),
        }

        let mut builder = MessageBuilder::new();
        let mut body_len = 0;
        if let Some(html_body) = html_body {
            body_len = html_body.len();
            builder = builder.html_body(html_body);
        }
        if let Some(text_body) = text_body {
            body_len += text_body.len();
            builder = builder.text_body(text_body);
        }
        let mut message_body = Vec::with_capacity(body_len + 128);
        builder.write_body(&mut message_body).ok();

        script.push(b'\"');
        for ch in message_body {
            if [b'\\', b'\"'].contains(&ch) {
                script.push(b'\\');
            }
            script.push(ch);
        }
        script.extend_from_slice(b"\";\r\n");

        // Close blocks
        for _ in 0..num_blocks {
            script.extend_from_slice(b"}\r\n");
        }

        match self.core.sieve.untrusted_compiler.compile(&script) {
            Ok(compiled_script) => {
                // Update blob length
                obj.set(
                    Property::BlobId,
                    BlobId::default().with_section_size(script.len()).into(),
                );

                // Serialize script
                script.extend(bincode::serialize(&compiled_script).unwrap_or_default());

                Ok(script)
            }
            Err(err) => Err(trc::StoreCause::Unexpected
                .caused_by(trc::location!())
                .reason(err)
                .details("Vacation Sieve Script failed to compile.")),
        }
    }
}

fn set_error(mut response: SetResponse, id: Option<String>, err: SetError) -> SetResponse {
    if let Some(id) = id {
        response.not_created.append(id, err);
    } else {
        response.not_updated.append(Id::singleton(), err);
    }
    response
}
