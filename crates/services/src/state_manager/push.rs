/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{IPC_CHANNEL_BUFFER, Inner, LONG_1Y_SLUMBER, core::BuildServer};
use jmap_proto::types::id::Id;
use store::ahash::{AHashMap, AHashSet};
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;

use super::{Event, PushServer, PushUpdate, http::http_request};

pub fn spawn_push_manager(inner: Arc<Inner>) -> mpsc::Sender<Event> {
    let (push_tx_, mut push_rx) = mpsc::channel::<Event>(IPC_CHANNEL_BUFFER);
    let push_tx = push_tx_.clone();

    tokio::spawn(async move {
        let mut subscriptions = AHashMap::default();
        let mut last_verify: AHashMap<u32, Instant> = AHashMap::default();
        let mut last_retry = Instant::now();
        let mut retry_timeout = LONG_1Y_SLUMBER;
        let mut retry_ids = AHashSet::default();

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(retry_timeout, push_rx.recv()).await;

            // Load settings
            let server = inner.build_server();
            let push_attempt_interval = server.core.jmap.push_attempt_interval;
            let push_attempts_max = server.core.jmap.push_attempts_max;
            let push_retry_interval = server.core.jmap.push_retry_interval;
            let push_timeout = server.core.jmap.push_timeout;
            let push_verify_timeout = server.core.jmap.push_verify_timeout;
            let push_throttle = server.core.jmap.push_throttle;

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
                                subscription.state_changes.push(state_change);
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
                        LONG_1Y_SLUMBER
                    }
                } else {
                    push_retry_interval - last_retry_elapsed
                }
            } else {
                LONG_1Y_SLUMBER
            };
        }
    });

    push_tx_
}
