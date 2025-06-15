/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccessToken,
    ipc::{EncryptionKeys, PushSubscription, StateEvent, UpdateSubscription},
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        collection::Collection,
        date::UTCDate,
        property::Property,
        value::{Object, Value},
    },
};
use store::{
    BitmapKey, ValueKey,
    write::{AlignedBytes, Archive, ValueClass, now},
};
use trc::{AddContext, ServerEvent};
use utils::map::bitmap::Bitmap;

use std::future::Future;

pub trait PushSubscriptionFetch: Sync + Send {
    fn push_subscription_get(
        &self,
        request: GetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;

    fn fetch_push_subscriptions(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<StateEvent>> + Send;

    fn update_push_subscriptions(&self, account_id: u32) -> impl Future<Output = bool> + Send;
}

impl PushSubscriptionFetch for Server {
    async fn push_subscription_get(
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
            let push_ = if let Some(push) = self
                .get_archive(account_id, Collection::PushSubscription, document_id)
                .await?
            {
                push
            } else {
                response.not_found.push(id.into());
                continue;
            };
            let push = push_
                .unarchive::<email::push::PushSubscription>()
                .caused_by(trc::location!())?;
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
                    Property::DeviceClientId => {
                        result.append(
                            Property::DeviceClientId,
                            Value::from(&push.device_client_id),
                        );
                    }
                    Property::Types => {
                        let mut types = Vec::new();
                        for typ in Bitmap::from(&push.types).into_iter() {
                            types.push(Value::Text(typ.to_string()));
                        }
                        result.append(Property::Types, Value::List(types));
                    }
                    Property::Expires => {
                        if push.expires > 0 {
                            result.append(
                                Property::Expires,
                                Value::Date(
                                    UTCDate::from_timestamp(u64::from(push.expires) as i64),
                                ),
                            );
                        } else {
                            result.append(Property::Expires, Value::Null);
                        }
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

    async fn fetch_push_subscriptions(&self, account_id: u32) -> trc::Result<StateEvent> {
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
            let subscription = self
                .core
                .storage
                .data
                .get_value::<Archive<AlignedBytes>>(ValueKey {
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
                })?
                .deserialize::<email::push::PushSubscription>()
                .caused_by(trc::location!())?;

            if subscription.expires > current_time {
                if subscription.verified {
                    // Add verified subscription
                    subscriptions.push(UpdateSubscription::Verified(PushSubscription {
                        id: document_id,
                        url: subscription.url,
                        expires: subscription.expires,
                        types: subscription.types,
                        keys: subscription.keys.map(|keys| EncryptionKeys {
                            p256dh: keys.p256dh,
                            auth: keys.auth,
                        }),
                    }));
                } else {
                    // Add unverified subscription
                    subscriptions.push(UpdateSubscription::Unverified {
                        id: document_id,
                        url: subscription.url,
                        code: subscription.verification_code,
                        keys: subscription.keys.map(|keys| EncryptionKeys {
                            p256dh: keys.p256dh,
                            auth: keys.auth,
                        }),
                    });
                }
            }
        }

        Ok(StateEvent::UpdateSubscriptions {
            account_id,
            subscriptions,
        })
    }

    async fn update_push_subscriptions(&self, account_id: u32) -> bool {
        let push_subs = match self.fetch_push_subscriptions(account_id).await {
            Ok(push_subs) => push_subs,
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .details("Failed to fetch push subscriptions")
                );
                return false;
            }
        };

        let state_tx = self.inner.ipc.state_tx.clone();
        for event in [StateEvent::UpdateSharedAccounts { account_id }, push_subs] {
            if state_tx.send(event).await.is_err() {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Error sending state change.",
                    CausedBy = trc::location!()
                );

                return false;
            }
        }

        true
    }
}
