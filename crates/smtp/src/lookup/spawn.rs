/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{collections::VecDeque, sync::Arc, time::Duration};

use crate::config::Host;
use mail_send::smtp::tls::build_tls_connector;
use tokio::sync::{mpsc, oneshot};
use utils::{
    config::{Config, ServerProtocol},
    ipc::{Item, LookupItem, LookupResult},
};

use super::{
    cache::LookupCache, imap::ImapAuthClientBuilder, smtp::SmtpClientBuilder, Event, LookupChannel,
    NextHop, RemoteLookup,
};

impl Host {
    pub fn spawn(self, config: &Config) -> LookupChannel {
        // Create channel
        let local_host = config
            .value("server.hostname")
            .unwrap_or("[127.0.0.1]")
            .to_string();
        let tx_ = self.channel_tx.clone();

        tokio::spawn(async move {
            // Prepare builders
            match self.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                    NextHop {
                        tx: self.channel_tx,
                        host: Arc::new(SmtpClientBuilder {
                            builder: mail_send::SmtpClientBuilder {
                                addr: format!("{}:{}", self.address, self.port),
                                timeout: self.timeout,
                                tls_connector: build_tls_connector(self.tls_allow_invalid_certs),
                                tls_hostname: self.address,
                                tls_implicit: self.tls_implicit,
                                is_lmtp: matches!(self.protocol, ServerProtocol::Lmtp),
                                credentials: None,
                                local_host,
                            },
                            max_rcpt: self.max_requests,
                            max_auth_errors: self.max_errors,
                        }),
                    }
                    .run(
                        self.channel_rx,
                        self.cache_entries,
                        self.cache_ttl_positive,
                        self.cache_ttl_negative,
                        self.concurrency,
                    )
                    .await;
                }
                ServerProtocol::Imap => {
                    NextHop {
                        tx: self.channel_tx,
                        host: Arc::new(
                            ImapAuthClientBuilder::new(
                                format!("{}:{}", self.address, self.port),
                                self.timeout,
                                build_tls_connector(self.tls_allow_invalid_certs),
                                self.address,
                                self.tls_implicit,
                            )
                            .init()
                            .await,
                        ),
                    }
                    .run(
                        self.channel_rx,
                        self.cache_entries,
                        self.cache_ttl_positive,
                        self.cache_ttl_negative,
                        self.concurrency,
                    )
                    .await;
                }
                ServerProtocol::Http | ServerProtocol::Jmap => {
                    eprintln!("HTTP/JMAP lookups are not supported.");
                    std::process::exit(0);
                }
            }
        });

        LookupChannel { tx: tx_ }
    }
}

impl<T: RemoteLookup> NextHop<T> {
    pub async fn run(
        &self,
        mut rx: mpsc::Receiver<Event>,
        entries: usize,
        ttl_pos: Duration,
        ttl_neg: Duration,
        max_concurrent: usize,
    ) {
        // Create caches and queue
        let mut cache = LookupCache::new(entries, ttl_pos, ttl_neg);
        let mut queue = VecDeque::new();
        let mut active_lookups = 0;

        while let Some(event) = rx.recv().await {
            match event {
                Event::Lookup(lookup) => {
                    if let Some(result) = cache.get(&lookup.item) {
                        lookup.result.send(result.into()).logged_unwrap();
                    } else if active_lookups < max_concurrent {
                        active_lookups += 1;
                        self.host.spawn_lookup(lookup, self.tx.clone());
                    } else {
                        queue.push_back(lookup);
                    }
                }
                Event::WorkerReady {
                    item,
                    result,
                    next_lookup,
                } => {
                    match result {
                        Some(true) => cache.insert_pos(item),
                        Some(false) => cache.insert_neg(item),
                        _ => (),
                    }

                    let mut lookup = None;
                    while let Some(queued_lookup) = queue.pop_front() {
                        if let Some(result) = cache.get(&queued_lookup.item) {
                            queued_lookup.result.send(result.into()).logged_unwrap();
                        } else {
                            lookup = queued_lookup.into();
                            break;
                        }
                    }
                    if let Some(next_lookup) = next_lookup {
                        if lookup.is_none() {
                            active_lookups -= 1;
                        }
                        next_lookup.send(lookup).logged_unwrap();
                    } else if let Some(lookup) = lookup {
                        self.host.spawn_lookup(lookup, self.tx.clone());
                    } else {
                        active_lookups -= 1;
                    }
                }
                Event::WorkerFailed => {
                    if let Some(queued_lookup) = queue.pop_front() {
                        self.host.spawn_lookup(queued_lookup, self.tx.clone());
                    } else {
                        active_lookups -= 1;
                    }
                }
                Event::Stop => {
                    queue.clear();
                    break;
                }
                Event::Reload => {
                    cache.clear();
                }
            }
        }
    }
}

impl LookupChannel {
    pub async fn lookup(&self, item: Item) -> Option<LookupResult> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(Event::Lookup(LookupItem { item, result: tx }))
            .await
            .is_ok()
        {
            rx.await.ok()
        } else {
            None
        }
    }
}

impl From<mpsc::Sender<Event>> for LookupChannel {
    fn from(tx: mpsc::Sender<Event>) -> Self {
        LookupChannel { tx }
    }
}

pub trait LoggedUnwrap {
    fn logged_unwrap(self) -> bool;
}

impl<T, E: std::fmt::Debug> LoggedUnwrap for Result<T, E> {
    fn logged_unwrap(self) -> bool {
        match self {
            Ok(_) => true,
            Err(err) => {
                tracing::debug!("Failed to send message over channel: {:?}", err);
                false
            }
        }
    }
}
