/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::get::PushSubscriptionFetch;
use base64::{Engine, engine::general_purpose};
use common::{Server, auth::AccessToken};
use email::push::{Keys, PushSubscription};
use jmap_proto::{
    error::set::SetError,
    method::set::{RequestArguments, SetRequest, SetResponse},
    response::references::EvalObjectReferences,
    types::{
        collection::Collection,
        date::UTCDate,
        property::Property,
        type_state::DataType,
        value::{MaybePatchValue, Object, Value},
    },
};
use rand::distr::Alphanumeric;
use std::future::Future;
use store::{
    Serialize,
    rand::{Rng, rng},
    write::{Archiver, BatchBuilder, now},
};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

const EXPIRES_MAX: i64 = 7 * 24 * 3600; // 7 days
const VERIFICATION_CODE_LEN: usize = 32;

pub trait PushSubscriptionSet: Sync + Send {
    fn push_subscription_set(
        &self,
        request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;
}

impl PushSubscriptionSet for Server {
    async fn push_subscription_set(
        &self,
        mut request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse> {
        let account_id = access_token.primary_id();
        let push_ids = self
            .get_document_ids(account_id, Collection::PushSubscription)
            .await?
            .unwrap_or_default();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy();

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut push = PushSubscription::default();

            if push_ids.len() as usize >= self.core.jmap.push_max_total {
                response.not_created.append(id, SetError::forbidden().with_description(
                    "There are too many subscriptions, please delete some before adding a new one.",
                ));
                continue 'create;
            }

            for (property, value) in object.0 {
                if let Err(err) = response
                    .eval_object_references(value)
                    .and_then(|value| validate_push_value(&property, value, &mut push, true))
                {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }

            if push.device_client_id.is_empty() || push.url.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_properties([Property::DeviceClientId, Property::Url])
                        .with_description("Missing required properties"),
                );
                continue 'create;
            }

            // Add expiry time if missing
            if push.expires == 0 {
                push.expires = now() + EXPIRES_MAX as u64;
            }
            let expires = UTCDate::from_timestamp(push.expires as i64);

            // Generate random verification code
            push.verification_code = rng()
                .sample_iter(Alphanumeric)
                .take(VERIFICATION_CODE_LEN)
                .map(char::from)
                .collect::<String>();

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::PushSubscription, 1)
                .await
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .create_document(document_id)
                .set(
                    Property::Value,
                    Archiver::new(push)
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .commit_point();
            response.created.insert(
                id,
                Object::with_capacity(1)
                    .with_property(Property::Id, Value::Id(document_id.into()))
                    .with_property(Property::Keys, Value::Null)
                    .with_property(Property::Expires, expires),
            );
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain push subscription
            let document_id = id.document_id();
            let mut push = if let Some(push) = self
                .get_archive(account_id, Collection::PushSubscription, document_id)
                .await?
            {
                push.deserialize::<email::push::PushSubscription>()
                    .caused_by(trc::location!())?
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            for (property, value) in object.0 {
                if let Err(err) = response
                    .eval_object_references(value)
                    .and_then(|value| validate_push_value(&property, value, &mut push, false))
                {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            // Update record
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .update_document(document_id)
                .set(
                    Property::Value,
                    Archiver::new(push)
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .commit_point();
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if push_ids.contains(document_id) {
                // Update record
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::PushSubscription)
                    .delete_document(document_id)
                    .clear(Property::Value)
                    .commit_point();
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !batch.is_empty() {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        // Update push subscriptions
        if response.has_changes() {
            self.update_push_subscriptions(account_id).await;
        }

        Ok(response)
    }
}

fn validate_push_value(
    property: &Property,
    value: MaybePatchValue,
    push: &mut PushSubscription,
    is_create: bool,
) -> Result<(), SetError> {
    match (property, value) {
        (Property::DeviceClientId, MaybePatchValue::Value(Value::Text(value)))
            if is_create && value.len() < 255 =>
        {
            push.device_client_id = value;
        }
        (Property::Url, MaybePatchValue::Value(Value::Text(value)))
            if is_create && value.len() < 512 && value.starts_with("https://") =>
        {
            push.url = value;
        }
        (Property::Keys, MaybePatchValue::Value(Value::Object(value)))
            if is_create && value.0.len() == 2 =>
        {
            if let (Some(auth), Some(p256dh)) = (
                value
                    .get(&Property::Auth)
                    .as_string()
                    .and_then(|v| general_purpose::URL_SAFE.decode(v).ok()),
                value
                    .get(&Property::P256dh)
                    .as_string()
                    .and_then(|v| general_purpose::URL_SAFE.decode(v).ok()),
            ) {
                push.keys = Some(Keys { auth, p256dh });
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Failed to decode keys."));
            }
        }
        (Property::Expires, MaybePatchValue::Value(Value::Date(value))) => {
            let current_time = now() as i64;
            let expires = value.timestamp();
            push.expires = if expires > current_time && (expires - current_time) > EXPIRES_MAX {
                current_time + EXPIRES_MAX
            } else {
                expires
            } as u64;
        }
        (Property::Expires, MaybePatchValue::Value(Value::Null)) => {
            push.expires = now() + EXPIRES_MAX as u64;
        }
        (Property::Types, MaybePatchValue::Value(Value::List(value))) => {
            push.types.clear();

            for item in value {
                if let Some(dt) = item
                    .as_string()
                    .and_then(|value| DataType::try_from(value).ok())
                {
                    push.types.insert(dt);
                } else {
                    return Err(SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description("Invalid data type."));
                }
            }
        }
        (Property::VerificationCode, MaybePatchValue::Value(Value::Text(value))) if !is_create => {
            if push.verification_code == value {
                push.verified = true;
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Verification code does not match.".to_string()));
            }
        }
        (Property::Keys, MaybePatchValue::Value(Value::Null)) => {
            push.keys = None;
        }
        (Property::Types, MaybePatchValue::Value(Value::Null)) => {
            push.types = Bitmap::all();
        }
        (Property::VerificationCode, MaybePatchValue::Value(Value::Null)) => {}
        (property, _) => {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Field could not be set."));
        }
    }

    if is_create && push.types.is_empty() {
        push.types = Bitmap::all();
    }

    Ok(())
}
