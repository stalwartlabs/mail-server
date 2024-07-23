/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose, Engine};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, property::Property, type_state::DataType, value::Value},
};
use store::{
    write::{now, ValueClass},
    BitmapKey, ValueKey,
};
use utils::map::bitmap::Bitmap;

use crate::{auth::AccessToken, services::state, JMAP};

use super::{EncryptionKeys, PushSubscription, UpdateSubscription};

impl JMAP {
    pub async fn push_subscription_get(
        &self,
        mut request: GetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::DeviceClientId,
            Property::VerificationCode,
            Property::Expires,
            Property::Types,
        ]);
        let account_id = access_token.primary_id();
        let push_ids = self
            .get_document_ids(account_id, Collection::PushSubscription)
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
            account_id: None,
            state: None,
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the push subscription object
            let document_id = id.document_id();
            if !push_ids.contains(document_id) {
                response.not_found.push(id.into());
                continue;
            }
            let mut push = if let Some(push) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::PushSubscription,
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
                    Property::Url | Property::Keys | Property::Value => {
                        return Err(trc::JmapEvent::Forbidden.into_err().details(
                            "The 'url' and 'keys' properties are not readable".to_string(),
                        ));
                    }
                    property => {
                        result.append(property.clone(), push.remove(property));
                    }
                }
            }
            response.list.push(result);
        }

        Ok(response)
    }

    pub async fn fetch_push_subscriptions(&self, account_id: u32) -> trc::Result<state::Event> {
        let mut subscriptions = Vec::new();
        let document_ids = self
            .core
            .storage
            .data
            .get_bitmap(BitmapKey::document_ids(
                account_id,
                Collection::PushSubscription,
            ))
            .await?
            .unwrap_or_default();

        let current_time = now();

        for document_id in document_ids {
            let mut subscription = self
                .core
                .storage
                .data
                .get_value::<Object<Value>>(ValueKey {
                    account_id,
                    collection: Collection::PushSubscription.into(),
                    document_id,
                    class: ValueClass::Property(Property::Value.into()),
                })
                .await?
                .ok_or_else(|| {
                    trc::StoreEvent::NotFound
                        .into_err()
                        .caused_by(trc::location!())
                        .document_id(document_id)
                })?;

            let expires = subscription
                .properties
                .get(&Property::Expires)
                .and_then(|p| p.as_date())
                .ok_or_else(|| {
                    trc::StoreEvent::UnexpectedError
                        .caused_by(trc::location!())
                        .document_id(document_id)
                })?
                .timestamp() as u64;
            if expires > current_time {
                let keys = if let Some((auth, p256dh)) = subscription
                    .properties
                    .remove(&Property::Keys)
                    .and_then(|value| value.try_unwrap_object())
                    .and_then(|mut obj| {
                        (
                            obj.properties
                                .remove(&Property::Auth)
                                .and_then(|value| value.try_unwrap_string())?,
                            obj.properties
                                .remove(&Property::P256dh)
                                .and_then(|value| value.try_unwrap_string())?,
                        )
                            .into()
                    }) {
                    EncryptionKeys {
                        p256dh: general_purpose::URL_SAFE
                            .decode(&p256dh)
                            .unwrap_or_default(),
                        auth: general_purpose::URL_SAFE.decode(&auth).unwrap_or_default(),
                    }
                    .into()
                } else {
                    None
                };
                let verification_code = subscription
                    .properties
                    .remove(&Property::Value)
                    .and_then(|p| p.try_unwrap_string())
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .caused_by(trc::location!())
                            .document_id(document_id)
                    })?;
                let url = subscription
                    .properties
                    .remove(&Property::Url)
                    .and_then(|p| p.try_unwrap_string())
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .caused_by(trc::location!())
                            .document_id(document_id)
                    })?;

                if subscription
                    .properties
                    .get(&Property::VerificationCode)
                    .and_then(|p| p.as_string())
                    .map_or(false, |v| v == verification_code)
                {
                    let types = if let Some(Value::List(value)) =
                        subscription.properties.remove(&Property::Types)
                    {
                        if !value.is_empty() {
                            let mut type_states = Bitmap::new();
                            for type_state in value {
                                if let Some(type_state) = type_state
                                    .as_string()
                                    .and_then(|type_state| DataType::try_from(type_state).ok())
                                {
                                    type_states.insert(type_state);
                                }
                            }
                            type_states
                        } else {
                            Bitmap::all()
                        }
                    } else {
                        Bitmap::all()
                    };

                    // Add verified subscription
                    subscriptions.push(UpdateSubscription::Verified(PushSubscription {
                        id: document_id,
                        url,
                        expires,
                        types,
                        keys,
                    }));
                } else {
                    // Add unverified subscription
                    subscriptions.push(UpdateSubscription::Unverified {
                        id: document_id,
                        url,
                        code: verification_code,
                        keys,
                    });
                }
            }
        }

        Ok(state::Event::UpdateSubscriptions {
            account_id,
            subscriptions,
        })
    }
}
