/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{
    manager::webadmin::Resource,
    webhooks::{WebhookEvent, WebhookEvents},
};
use hyper::{body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jmap::api::http::{fetch_body, ToHttpResponse};
use jmap_proto::error::request::RequestError;
use ring::hmac;
use store::parking_lot::Mutex;
use tokio::{net::TcpListener, sync::watch};

use super::JMAPTest;

pub struct MockWebhookEndpoint {
    pub tx: watch::Sender<bool>,
    pub events: Mutex<Vec<WebhookEvent>>,
    pub reject: AtomicBool,
}

pub async fn test(params: &mut JMAPTest) {
    println!("Running Webhook tests...");

    // Webhooks endpoint starts disabled by default, make sure there are no events.
    tokio::time::sleep(Duration::from_millis(200)).await;
    params.webhook.assert_is_empty();

    // Enable the endpoint
    params.webhook.accept();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check for events
    params.webhook.assert_contains(&["auth.success"]);
}

impl MockWebhookEndpoint {
    pub fn assert_contains(&self, expected: &[&str]) {
        let events =
            serde_json::to_string_pretty(&self.events.lock().drain(..).collect::<Vec<_>>())
                .unwrap();

        for string in expected {
            if !events.contains(string) {
                panic!(
                    "Expected events to contain '{}', but it did not. Events: {}",
                    string, events
                );
            }
        }
    }

    pub fn accept(&self) {
        self.reject.store(false, Ordering::Relaxed);
    }

    pub fn reject(&self) {
        self.reject.store(true, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.events.lock().clear();
    }

    pub fn assert_is_empty(&self) {
        assert!(self.events.lock().is_empty());
    }
}

pub fn spawn_mock_webhook_endpoint() -> Arc<MockWebhookEndpoint> {
    let (tx, rx) = watch::channel(true);
    let endpoint_ = Arc::new(MockWebhookEndpoint {
        tx,
        events: Mutex::new(vec![]),
        reject: true.into(),
    });

    let endpoint = endpoint_.clone();

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:8821")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Milter server to 127.0.0.1:8821: {e}");
            });
        let mut rx_ = rx.clone();

        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {

                            let _ = http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|mut req: hyper::Request<body::Incoming>| {
                                    let endpoint = endpoint.clone();

                                    async move {
                                        // Verify HMAC signature
                                        let key = hmac::Key::new(hmac::HMAC_SHA256, "ovos-moles".as_bytes());
                                        let body = fetch_body(&mut req, 1024 * 1024).await.unwrap();
                                        let tag = STANDARD.decode(req.headers().get("X-Signature").unwrap().to_str().unwrap()).unwrap();
                                        hmac::verify(&key, &body, &tag).expect("Invalid signature");

                                        // Deserialize JSON
                                        let request = serde_json::from_slice::<WebhookEvents>(&body)
                                        .expect("Failed to parse JSON");

                                        if !endpoint.reject.load(Ordering::Relaxed) {
                                            //let c = print!("received webhook: {}", serde_json::to_string_pretty(&request).unwrap());

                                            // Add events
                                            endpoint.events.lock().extend(request.events);

                                            Ok::<_, hyper::Error>(
                                                Resource {
                                                    content_type: "application/json",
                                                    contents: "[]".to_string().into_bytes(),
                                                }
                                                .into_http_response(),
                                            )
                                        } else {
                                            //let c = print!("rejected webhook: {}", serde_json::to_string_pretty(&request).unwrap());

                                            Ok::<_, hyper::Error>(
                                                RequestError::not_found().into_http_response()
                                            )
                                        }

                                    }
                                }),
                            )
                            .await;
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    //println!("Mock jMilter server stopping");
                    break;
                }
            };
        }
    });

    endpoint_
}
