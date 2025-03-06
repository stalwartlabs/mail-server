/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use email::sieve::{
    SieveScript, VacationResponse, activate::SieveScriptActivate, delete::SieveScriptDelete,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{RequestArguments, SetRequest, SetResponse},
    response::references::EvalObjectReferences,
    types::{
        collection::Collection,
        date::UTCDate,
        id::Id,
        property::Property,
        value::{MaybePatchValue, Object, Value},
    },
};
use mail_builder::MessageBuilder;
use mail_parser::decoders::html::html_to_text;
use std::future::Future;
use store::write::{
    Archive, BatchBuilder,
    assert::HashedValue,
    log::{Changes, LogInsert},
};
use trc::AddContext;

use crate::JmapMethods;

use super::get::VacationResponseGet;

pub trait VacationResponseSet: Sync + Send {
    fn vacation_response_set(
        &self,
        request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;

    fn build_script(&self, obj: &mut SieveScript) -> trc::Result<Vec<u8>>;
}

impl VacationResponseSet for Server {
    async fn vacation_response_set(
        &self,
        mut request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse> {
        let account_id = request.account_id.document_id();
        let mut response = self
            .prepare_set_response(&request, Collection::SieveScript)
            .await?;
        let will_destroy = request.unwrap_destroy();
        let resource_token = self.get_resource_token(access_token, account_id).await?;

        // Process set or update requests
        let mut create_id = None;
        let mut changes = None;
        match (request.create, request.update) {
            (Some(create), Some(update)) if !create.is_empty() && !update.is_empty() => {
                return Err(trc::JmapEvent::InvalidArguments
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
        let change_id = self.assign_change_id(account_id)?;
        batch
            .with_change_id(change_id)
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript);

        // Process changes
        if let Some(changes) = changes {
            // Obtain current script
            let document_id = self.get_vacation_sieve_script_id(account_id).await?;
            let mut was_active = false;

            let (mut sieve, prev_sieve) = if let Some(document_id) = document_id {
                let prev_sieve = self
                    .get_property::<HashedValue<Archive>>(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                        Property::Value,
                    )
                    .await?
                    .ok_or_else(|| {
                        trc::StoreEvent::NotFound
                            .into_err()
                            .caused_by(trc::location!())
                    })?
                    .into_deserialized::<SieveScript>()
                    .caused_by(trc::location!())?;
                was_active = prev_sieve.inner.is_active;
                let mut sieve = prev_sieve.inner.clone();
                if sieve.vacation_response.is_none() {
                    sieve.vacation_response = VacationResponse::default().into();
                }

                (sieve, Some(prev_sieve))
            } else {
                (
                    SieveScript {
                        name: "vacation".into(),
                        is_active: false,
                        blob_hash: Default::default(),
                        size: 0,
                        vacation_response: VacationResponse::default().into(),
                    },
                    None,
                )
            };

            // Parse properties
            let mut is_active = false;
            let mut build_script = create_id.is_some();
            let vacation = sieve.vacation_response.as_mut().unwrap();

            for (property, value) in changes.0 {
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
                        vacation.subject = Some(value);
                    }
                    (Property::HtmlBody, MaybePatchValue::Value(Value::Text(value)))
                        if value.len() < 2048 =>
                    {
                        build_script = true;
                        vacation.html_body = Some(value);
                    }
                    (Property::TextBody, MaybePatchValue::Value(Value::Text(value)))
                        if value.len() < 2048 =>
                    {
                        build_script = true;
                        vacation.text_body = Some(value);
                    }
                    (Property::FromDate, MaybePatchValue::Value(Value::Date(date))) => {
                        vacation.from_date = Some(date.timestamp() as u64);
                        build_script = true;
                    }
                    (Property::ToDate, MaybePatchValue::Value(Value::Date(date))) => {
                        vacation.to_date = Some(date.timestamp() as u64);
                        build_script = true;
                    }
                    (Property::IsEnabled, MaybePatchValue::Value(Value::Bool(value))) => {
                        is_active = value;
                    }
                    (Property::IsEnabled, MaybePatchValue::Value(Value::Null)) => {
                        is_active = false;
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
                            match property {
                                Property::Subject => {
                                    vacation.subject = None;
                                }
                                Property::HtmlBody => {
                                    vacation.html_body = None;
                                }
                                Property::TextBody => {
                                    vacation.text_body = None;
                                }
                                Property::FromDate => {
                                    vacation.from_date = None;
                                }
                                Property::ToDate => {
                                    vacation.to_date = None;
                                }
                                _ => unreachable!(),
                            }
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
            sieve.is_active = is_active;

            let mut obj = ObjectIndexBuilder::new()
                .with_current_opt(prev_sieve)
                .with_changes(sieve)
                .with_tenant_id(&resource_token);

            // Update id
            if let Some(document_id) = document_id {
                batch
                    .update_document(document_id)
                    .clear(Property::EmailIds)
                    .log(Changes::update([document_id]));
            } else {
                batch.create_document().log(LogInsert());
            }

            // Create sieve script only if there are changes
            if build_script {
                // Upload new blob
                obj.changes_mut().unwrap().blob_hash = self
                    .put_blob(
                        account_id,
                        &self.build_script(obj.changes_mut().unwrap())?,
                        false,
                    )
                    .await?
                    .hash;
            };

            // Write changes
            batch.custom(obj).caused_by(trc::location!())?;
            let document_id = if !batch.is_empty() {
                let ids = self
                    .store()
                    .write(batch)
                    .await
                    .caused_by(trc::location!())?;
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
                        self.sieve_script_delete(&resource_token, document_id, false)
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
                self.store()
                    .write(batch)
                    .await
                    .caused_by(trc::location!())?;
                response.new_state = Some(change_id.into());
            }
        }

        Ok(response)
    }

    fn build_script(&self, obj: &mut SieveScript) -> trc::Result<Vec<u8>> {
        // Build Sieve script
        let mut script = Vec::with_capacity(1024);
        script.extend_from_slice(b"require [\"vacation\", \"relational\", \"date\"];\r\n\r\n");
        let mut num_blocks = 0;

        // Add start date
        if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.from_date) {
            script.extend_from_slice(b"if currentdate :value \"ge\" \"iso8601\" \"");
            script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        // Add end date
        if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.to_date) {
            script.extend_from_slice(b"if currentdate :value \"le\" \"iso8601\" \"");
            script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        script.extend_from_slice(b"vacation :mime ");
        if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.subject.as_ref())
        {
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

        let mut text_body = if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.text_body.as_ref())
        {
            Cow::from(value.as_str()).into()
        } else {
            None
        };
        let html_body = if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.html_body.as_ref())
        {
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
                obj.size = script.len() as u32;

                // Serialize script
                script.extend(bincode::serialize(&compiled_script).unwrap_or_default());

                Ok(script)
            }
            Err(err) => Err(trc::StoreEvent::UnexpectedError
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
