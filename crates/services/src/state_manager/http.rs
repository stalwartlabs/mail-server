/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use base64::Engine;
use common::ipc::EncryptionKeys;

use jmap_proto::{response::status::StateChangeResponse, types::id::Id};
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;

use super::{Event, PushServer, ece::ece_encrypt};

impl PushServer {
    pub fn send(&mut self, id: Id, push_tx: mpsc::Sender<Event>, push_timeout: Duration) {
        let url = self.url.clone();
        let keys = self.keys.clone();
        let state_changes = std::mem::take(&mut self.state_changes);

        self.in_flight = true;
        self.last_request = Instant::now();

        tokio::spawn(async move {
            let mut response = StateChangeResponse::new();
            for state_change in &state_changes {
                for type_state in state_change.types {
                    response
                        .changed
                        .get_mut_or_insert(state_change.account_id.into())
                        .set(type_state, (state_change.change_id).into());
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

pub(crate) async fn http_request(
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
        .post(url.as_str())
        .header(CONTENT_TYPE, "application/json")
        .header("TTL", "86400");

    if let Some(keys) = keys {
        match ece_encrypt(&keys.p256dh, &keys.auth, body.as_bytes())
            .map(|b| base64::engine::general_purpose::URL_SAFE.encode(b))
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
