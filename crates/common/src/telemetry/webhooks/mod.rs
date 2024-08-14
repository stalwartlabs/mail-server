/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::config::telemetry::WebhookTracer;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::hmac;
use serde::Serialize;
use store::write::now;
use tokio::sync::mpsc;
use trc::{
    ipc::subscriber::{EventBatch, SubscriberBuilder},
    ServerEvent, TelemetryEvent,
};

use super::LONG_SLUMBER;

pub(crate) fn spawn_webhook_tracer(builder: SubscriberBuilder, settings: WebhookTracer) {
    let (tx, mut rx) = builder.register();
    tokio::spawn(async move {
        let settings = Arc::new(settings);
        let mut wakeup_time = LONG_SLUMBER;
        let discard_after = settings.discard_after.as_secs();
        let mut pending_events = Vec::new();
        let mut next_delivery = Instant::now();
        let in_flight = Arc::new(AtomicBool::new(false));

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(wakeup_time, rx.recv()).await;
            let now = now();

            match event_or_timeout {
                Ok(Some(events)) => {
                    let mut discard_count = 0;
                    for event in events {
                        if now.saturating_sub(event.inner.timestamp) < discard_after {
                            pending_events.push(event)
                        } else {
                            discard_count += 1;
                        }
                    }

                    if discard_count > 0 {
                        trc::event!(
                            Telemetry(TelemetryEvent::WebhookError),
                            Details = "Discarded stale events",
                            Total = discard_count
                        );
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(_) => (),
            }

            // Process events
            let mut next_retry = None;
            let now = Instant::now();
            if next_delivery <= now {
                if !pending_events.is_empty() {
                    next_delivery = now + settings.throttle;
                    if !in_flight.load(Ordering::Relaxed) {
                        spawn_webhook_handler(
                            settings.clone(),
                            in_flight.clone(),
                            std::mem::take(&mut pending_events),
                            tx.clone(),
                        );
                    }
                }
            } else if !pending_events.is_empty() {
                // Retry later
                let this_retry = next_delivery - now;
                match next_retry {
                    Some(next_retry) if this_retry >= next_retry => {}
                    _ => {
                        next_retry = Some(this_retry);
                    }
                }
            }
            wakeup_time = next_retry.unwrap_or(LONG_SLUMBER);
        }
    });
}

#[derive(Serialize)]
struct EventWrapper {
    events: EventBatch,
}

fn spawn_webhook_handler(
    settings: Arc<WebhookTracer>,
    in_flight: Arc<AtomicBool>,
    events: EventBatch,
    webhook_tx: mpsc::Sender<EventBatch>,
) {
    tokio::spawn(async move {
        in_flight.store(true, Ordering::Relaxed);
        let wrapper = EventWrapper { events };

        if let Err(err) = post_webhook_events(&settings, &wrapper).await {
            trc::event!(Telemetry(TelemetryEvent::WebhookError), Details = err);

            if webhook_tx.send(wrapper.events).await.is_err() {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Failed to send failed webhook events back to main thread",
                    CausedBy = trc::location!()
                );
            }
        }

        in_flight.store(false, Ordering::Relaxed);
    });
}

async fn post_webhook_events(
    settings: &WebhookTracer,
    events: &EventWrapper,
) -> Result<(), String> {
    // Serialize body
    let body = serde_json::to_string(events)
        .map_err(|err| format!("Failed to serialize events: {}", err))?;

    // Add HMAC-SHA256 signature
    let mut headers = settings.headers.clone();
    if !settings.key.is_empty() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, settings.key.as_bytes());
        let tag = hmac::sign(&key, body.as_bytes());

        headers.insert(
            "X-Signature",
            STANDARD.encode(tag.as_ref()).parse().unwrap(),
        );
    }

    // Send request
    let response = reqwest::Client::builder()
        .timeout(settings.timeout)
        .danger_accept_invalid_certs(settings.tls_allow_invalid_certs)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(&settings.url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Webhook request to {} failed: {err}", settings.url))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Webhook request to {} failed with code {}: {}",
            settings.url,
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}
