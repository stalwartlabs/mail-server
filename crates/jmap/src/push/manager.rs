/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose, Engine};
use common::IPC_CHANNEL_BUFFER;
use jmap_proto::types::id::Id;
use store::ahash::{AHashMap, AHashSet};
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;

use crate::{api::StateChangeResponse, JmapInstance, LONG_SLUMBER};

use super::{ece::ece_encrypt, EncryptionKeys, Event, PushServer, PushUpdate};

use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use std::{
    collections::hash_map::Entry,
    time::{Duration, Instant},
};

pub fn spawn_push_manager(core: JmapInstance) -> mpsc::Sender<Event> {
    let (push_tx_, mut push_rx) = mpsc::channel::<Event>(IPC_CHANNEL_BUFFER);
    let push_tx = push_tx_.clone();

    tokio::spawn(async move {
        let mut subscriptions = AHashMap::default();
        let mut last_verify: AHashMap<u32, Instant> = AHashMap::default();
        let mut last_retry = Instant::now();
        let mut retry_timeout = LONG_SLUMBER;
        let mut retry_ids = AHashSet::default();

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(retry_timeout, push_rx.recv()).await;

            // Load settings
            let core_ = core.core.load_full();
            let push_attempt_interval = core_.jmap.push_attempt_interval;
            let push_attempts_max = core_.jmap.push_attempts_max;
            let push_retry_interval = core_.jmap.push_retry_interval;
            let push_timeout = core_.jmap.push_timeout;
            let push_verify_timeout = core_.jmap.push_verify_timeout;
            let push_throttle = core_.jmap.push_throttle;

            match event_or_timeout {
                Ok(Some(event)) => match event {
                    Event::Update { updates } => {
                        for update in updates {
                            match update {
                                PushUpdate::Verify {
                                    id,
                                    account_id,
                                    url,
                                    code,
                                    keys,
                                } => {
                                    let current_time = Instant::now();

                                    #[cfg(feature = "test_mode")]
                                    if url.contains("skip_checks") {
                                        last_verify.insert(
                                            account_id,
                                            current_time
                                                - (push_verify_timeout + Duration::from_millis(1)),
                                        );
                                    }

                                    if last_verify
                                        .get(&account_id)
                                        .map(|last_verify| {
                                            current_time - *last_verify > push_verify_timeout
                                        })
                                        .unwrap_or(true)
                                    {
                                        tokio::spawn(async move {
                                            http_request(
                                                url,
                                                format!(
                                                    concat!(
                                                        "{{\"@type\":\"PushVerification\",",
                                                        "\"pushSubscriptionId\":\"{}\",",
                                                        "\"verificationCode\":\"{}\"}}"
                                                    ),
                                                    Id::from(id),
                                                    code
                                                ),
                                                keys,
                                                push_timeout,
                                            )
                                            .await;
                                        });

                                        last_verify.insert(account_id, current_time);
                                    } else {
                                        trc::event!(
                                            PushSubscription(PushSubscriptionEvent::Error),
                                            Details = "Failed to verify push subscription",
                                            Url = url.clone(),
                                            AccountId = account_id,
                                            Reason = "Too many requests"
                                        );

                                        continue;
                                    }
                                }
                                PushUpdate::Register { id, url, keys } => {
                                    if let Entry::Vacant(entry) = subscriptions.entry(id) {
                                        entry.insert(PushServer {
                                            url,
                                            keys,
                                            num_attempts: 0,
                                            last_request: Instant::now()
                                                - (push_throttle + Duration::from_millis(1)),
                                            state_changes: Vec::new(),
                                            in_flight: false,
                                        });
                                    }
                                }
                                PushUpdate::Unregister { id } => {
                                    subscriptions.remove(&id);
                                }
                            }
                        }
                    }
                    Event::Push { ids, state_change } => {
                        for id in ids {
                            if let Some(subscription) = subscriptions.get_mut(&id) {
                                subscription.state_changes.push(state_change.clone());
                                let last_request = subscription.last_request.elapsed();

                                if !subscription.in_flight
                                    && ((subscription.num_attempts == 0
                                        && last_request > push_throttle)
                                        || ((1..push_attempts_max)
                                            .contains(&subscription.num_attempts)
                                            && last_request > push_attempt_interval))
                                {
                                    subscription.send(id, push_tx.clone(), push_timeout);
                                    retry_ids.remove(&id);
                                } else {
                                    retry_ids.insert(id);
                                }
                            } else {
                                trc::event!(
                                    PushSubscription(PushSubscriptionEvent::NotFound),
                                    Id = id.document_id(),
                                );
                            }
                        }
                    }
                    Event::Reset => {
                        subscriptions.clear();
                    }
                    Event::DeliverySuccess { id } => {
                        if let Some(subscription) = subscriptions.get_mut(&id) {
                            subscription.num_attempts = 0;
                            subscription.in_flight = false;
                            retry_ids.remove(&id);
                        }
                    }
                    Event::DeliveryFailure { id, state_changes } => {
                        if let Some(subscription) = subscriptions.get_mut(&id) {
                            subscription.last_request = Instant::now();
                            subscription.num_attempts += 1;
                            subscription.state_changes.extend(state_changes);
                            subscription.in_flight = false;
                            retry_ids.insert(id);
                        }
                    }
                },
                Ok(None) => {
                    break;
                }
                Err(_) => (),
            }

            retry_timeout = if !retry_ids.is_empty() {
                let last_retry_elapsed = last_retry.elapsed();

                if last_retry_elapsed >= push_retry_interval {
                    let mut remove_ids = Vec::with_capacity(retry_ids.len());

                    for retry_id in &retry_ids {
                        if let Some(subscription) = subscriptions.get_mut(retry_id) {
                            let last_request = subscription.last_request.elapsed();

                            if !subscription.in_flight
                                && ((subscription.num_attempts == 0
                                    && last_request >= push_throttle)
                                    || (subscription.num_attempts > 0
                                        && last_request >= push_attempt_interval))
                            {
                                if subscription.num_attempts < push_attempts_max {
                                    subscription.send(*retry_id, push_tx.clone(), push_timeout);
                                } else {
                                    trc::event!(
                                        PushSubscription(PushSubscriptionEvent::Error),
                                        Details = "Failed to deliver push subscription",
                                        Url = subscription.url.clone(),
                                        Reason = "Too many attempts"
                                    );

                                    subscription.state_changes.clear();
                                    subscription.num_attempts = 0;
                                }
                                remove_ids.push(*retry_id);
                            }
                        } else {
                            remove_ids.push(*retry_id);
                        }
                    }

                    if remove_ids.len() < retry_ids.len() {
                        for remove_id in remove_ids {
                            retry_ids.remove(&remove_id);
                        }
                        last_retry = Instant::now();
                        push_retry_interval
                    } else {
                        retry_ids.clear();
                        LONG_SLUMBER
                    }
                } else {
                    push_retry_interval - last_retry_elapsed
                }
            } else {
                LONG_SLUMBER
            };
        }
    });

    push_tx_
}

impl PushServer {
    fn send(&mut self, id: Id, push_tx: mpsc::Sender<Event>, push_timeout: Duration) {
        let url = self.url.clone();
        let keys = self.keys.clone();
        let state_changes = std::mem::take(&mut self.state_changes);

        self.in_flight = true;
        self.last_request = Instant::now();

        tokio::spawn(async move {
            let mut response = StateChangeResponse::new();
            for state_change in &state_changes {
                for (type_state, change_id) in &state_change.types {
                    response
                        .changed
                        .get_mut_or_insert(state_change.account_id.into())
                        .set(*type_state, (*change_id).into());
                }
            }

            push_tx
                .send(
                    if http_request(
                        url,
                        serde_json::to_string(&response).unwrap(),
                        keys,
                        push_timeout,
                    )
                    .await
                    {
                        Event::DeliverySuccess { id }
                    } else {
                        Event::DeliveryFailure { id, state_changes }
                    },
                )
                .await
                .ok();
        });
    }
}

async fn http_request(
    url: String,
    mut body: String,
    keys: Option<EncryptionKeys>,
    push_timeout: Duration,
) -> bool {
    let client_builder = reqwest::Client::builder().timeout(push_timeout);

    #[cfg(feature = "test_mode")]
    let client_builder = client_builder.danger_accept_invalid_certs(true);

    let mut client = client_builder
        .build()
        .unwrap_or_default()
        .post(&url)
        .header(CONTENT_TYPE, "application/json")
        .header("TTL", "86400");

    if let Some(keys) = keys {
        match ece_encrypt(&keys.p256dh, &keys.auth, body.as_bytes())
            .map(|b| general_purpose::URL_SAFE.encode(b))
        {
            Ok(body_) => {
                body = body_;
                client = client.header(CONTENT_ENCODING, "aes128gcm");
            }
            Err(err) => {
                // Do not reattempt if encryption fails.

                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "Failed to encrypt push subscription",
                    Url = url,
                    Reason = err
                );
                return true;
            }
        }
    }

    match client.body(body).send().await {
        Ok(response) => {
            if response.status().is_success() {
                trc::event!(PushSubscription(PushSubscriptionEvent::Success), Url = url,);

                true
            } else {
                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "HTTP POST failed",
                    Url = url,
                    Code = response.status().as_u16(),
                );

                false
            }
        }
        Err(err) => {
            trc::event!(
                PushSubscription(PushSubscriptionEvent::Error),
                Details = "HTTP POST failed",
                Url = url,
                Reason = err.to_string()
            );

            false
        }
    }
}
