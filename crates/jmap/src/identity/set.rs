/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::index::ObjectIndexBuilder};
use directory::QueryBy;
use email::identity::{EmailAddress, Identity};
use jmap_proto::{
    error::set::SetError,
    method::set::{RequestArguments, SetRequest, SetResponse},
    response::references::EvalObjectReferences,
    types::{
        collection::{Collection, SyncCollection},
        property::Property,
        state::State,
        value::{MaybePatchValue, Value},
    },
};
use std::future::Future;
use store::write::BatchBuilder;
use trc::AddContext;
use utils::sanitize_email;

pub trait IdentitySet: Sync + Send {
    fn identity_set(
        &self,
        request: SetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;
}

impl IdentitySet for Server {
    async fn identity_set(
        &self,
        mut request: SetRequest<RequestArguments>,
    ) -> trc::Result<SetResponse> {
        let account_id = request.account_id.document_id();
        let identity_ids = self
            .get_document_ids(account_id, Collection::Identity)
            .await?
            .unwrap_or_default();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy();

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut identity = Identity::default();

            for (property, value) in object.0 {
                if let Err(err) = response.eval_object_references(value).and_then(|value| {
                    validate_identity_value(&property, value, &mut identity, true)
                }) {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }

            // Validate email address
            if !identity.email.is_empty() {
                if self
                    .directory()
                    .query(QueryBy::Id(account_id), false)
                    .await?
                    .is_none_or(|p| !p.emails.iter().any(|e| e == &identity.email))
                {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::Email)
                            .with_description(
                                "E-mail address not configured for this account.".to_string(),
                            ),
                    );
                    continue 'create;
                }
            } else {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::Email)
                        .with_description("Missing e-mail address."),
                );
                continue 'create;
            }

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::Identity, 1)
                .await
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Identity)
                .create_document(document_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(identity))
                .caused_by(trc::location!())?
                .commit_point();
            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain identity
            let document_id = id.document_id();
            let identity_ = if let Some(identity_) = self
                .get_archive(account_id, Collection::Identity, document_id)
                .await?
            {
                identity_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let identity = identity_
                .to_unarchived::<Identity>()
                .caused_by(trc::location!())?;
            let mut new_identity = identity
                .deserialize::<Identity>()
                .caused_by(trc::location!())?;

            for (property, value) in object.0 {
                if let Err(err) = response.eval_object_references(value).and_then(|value| {
                    validate_identity_value(&property, value, &mut new_identity, false)
                }) {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            // Update record
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Identity)
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(identity)
                        .with_changes(new_identity),
                )
                .caused_by(trc::location!())?
                .commit_point();
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if identity_ids.contains(document_id) {
                // Update record
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Identity)
                    .delete_document(document_id)
                    .clear(Property::Value)
                    .log_item_delete(SyncCollection::Identity, None)
                    .commit_point();
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}

fn validate_identity_value(
    property: &Property,
    value: MaybePatchValue,
    identity: &mut Identity,
    is_create: bool,
) -> Result<(), SetError> {
    match (property, value) {
        (Property::Name, MaybePatchValue::Value(Value::Text(value))) if value.len() < 255 => {
            identity.name = value;
        }
        (Property::Email, MaybePatchValue::Value(Value::Text(value)))
            if is_create && value.len() < 255 =>
        {
            identity.email = sanitize_email(&value).ok_or_else(|| {
                SetError::invalid_properties()
                    .with_property(Property::Email)
                    .with_description("Invalid e-mail address.")
            })?;
        }
        (Property::TextSignature, MaybePatchValue::Value(Value::Text(value)))
            if value.len() < 2048 =>
        {
            identity.text_signature = value;
        }
        (Property::HtmlSignature, MaybePatchValue::Value(Value::Text(value)))
            if value.len() < 2048 =>
        {
            identity.html_signature = value;
        }
        (Property::ReplyTo | Property::Bcc, MaybePatchValue::Value(Value::List(value))) => {
            let mut addresses = Vec::with_capacity(value.len());
            for addr in value {
                let mut address = EmailAddress {
                    name: None,
                    email: "".into(),
                };
                let mut is_valid = false;
                if let Value::Object(obj) = addr {
                    for (key, value) in obj.0 {
                        match (key, value) {
                            (Property::Email, Value::Text(value)) if value.len() < 255 => {
                                is_valid = true;
                                address.email = value;
                            }
                            (Property::Name, Value::Text(value)) if value.len() < 255 => {
                                address.name = Some(value);
                            }
                            (Property::Name, Value::Null) => (),
                            _ => {
                                is_valid = false;
                                break;
                            }
                        }
                    }
                }

                if is_valid && !address.email.is_empty() {
                    addresses.push(address);
                } else {
                    return Err(SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description("Invalid e-mail address object."));
                }
            }

            match property {
                Property::ReplyTo => {
                    identity.reply_to = Some(addresses);
                }
                Property::Bcc => {
                    identity.bcc = Some(addresses);
                }
                _ => unreachable!(),
            }
        }
        (Property::Name, MaybePatchValue::Value(Value::Null)) => {
            identity.name.clear();
        }
        (Property::TextSignature, MaybePatchValue::Value(Value::Null)) => {
            identity.text_signature.clear();
        }
        (Property::HtmlSignature, MaybePatchValue::Value(Value::Null)) => {
            identity.html_signature.clear();
        }
        (Property::ReplyTo, MaybePatchValue::Value(Value::Null)) => identity.reply_to = None,
        (Property::Bcc, MaybePatchValue::Value(Value::Null)) => identity.bcc = None,
        (property, _) => {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Field could not be set."));
        }
    }

    Ok(())
}
