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
    collections::BinaryHeap,
    time::{Duration, Instant},
};

use common::IPC_CHANNEL_BUFFER;
use store::{write::purge::PurgeStore, BlobStore, LookupStore, Store};
use tokio::sync::mpsc;
use utils::map::ttl_dashmap::TtlMap;

use crate::{Inner, JmapInstance, JMAP, LONG_SLUMBER};

pub enum Event {
    IndexStart,
    IndexDone,
    AcmeReload,
    AcmeReschedule {
        provider_id: String,
        renew_at: Instant,
    },
    Purge(PurgeType),
    #[cfg(feature = "test_mode")]
    IndexIsActive(tokio::sync::oneshot::Sender<bool>),
    Exit,
}

pub enum PurgeType {
    Data(Store),
    Blobs { store: Store, blob_store: BlobStore },
    Lookup(LookupStore),
    Account(Option<u32>),
}

#[derive(PartialEq, Eq)]
struct Action {
    due: Instant,
    event: ActionClass,
}

#[derive(PartialEq, Eq, Debug)]
enum ActionClass {
    Session,
    Account,
    Store(usize),
    Acme(String),
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Action>,
}

pub fn spawn_housekeeper(core: JmapInstance, mut rx: mpsc::Receiver<Event>) {
    tokio::spawn(async move {
        tracing::debug!("Housekeeper task started.");

        let mut index_busy = true;
        let mut index_pending = false;

        // Index any queued messages
        let jmap = JMAP::from(core.clone());
        tokio::spawn(async move {
            jmap.fts_index_queued().await;
        });
        let mut queue = Queue::default();

        // Add all events to queue
        let core_ = core.core.load();
        queue.schedule(
            Instant::now() + core_.jmap.session_purge_frequency.time_to_next(),
            ActionClass::Session,
        );
        queue.schedule(
            Instant::now() + core_.jmap.account_purge_frequency.time_to_next(),
            ActionClass::Account,
        );
        for (idx, schedule) in core_.storage.purge_schedules.iter().enumerate() {
            queue.schedule(
                Instant::now() + schedule.cron.time_to_next(),
                ActionClass::Store(idx),
            );
        }

        // Add all ACME renewals to heap
        for provider in core_.tls.acme_providers.values() {
            match core_.init_acme(provider).await {
                Ok(renew_at) => {
                    queue.schedule(
                        Instant::now() + renew_at,
                        ActionClass::Acme(provider.id.clone()),
                    );
                }
                Err(err) => {
                    tracing::error!(
                        context = "acme",
                        event = "error",
                        error = ?err,
                        "Failed to initialize ACME certificate manager.");
                }
            };
        }

        loop {
            match tokio::time::timeout(queue.wake_up_time(), rx.recv()).await {
                Ok(Some(event)) => match event {
                    Event::AcmeReload => {
                        let core_ = core.core.load().clone();
                        let inner = core.jmap_inner.clone();

                        tokio::spawn(async move {
                            for provider in core_.tls.acme_providers.values() {
                                match core_.init_acme(provider).await {
                                    Ok(renew_at) => {
                                        inner
                                            .housekeeper_tx
                                            .send(Event::AcmeReschedule {
                                                provider_id: provider.id.clone(),
                                                renew_at: Instant::now() + renew_at,
                                            })
                                            .await
                                            .ok();
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            context = "acme",
                                            event = "error",
                                            error = ?err,
                                            "Failed to reload ACME certificate manager.");
                                    }
                                };
                            }
                        });
                    }
                    Event::AcmeReschedule {
                        provider_id,
                        renew_at,
                    } => {
                        let action = ActionClass::Acme(provider_id);
                        queue.remove_action(&action);
                        queue.schedule(renew_at, action);
                    }
                    Event::IndexStart => {
                        if !index_busy {
                            index_busy = true;
                            let jmap = JMAP::from(core.clone());
                            tokio::spawn(async move {
                                jmap.fts_index_queued().await;
                            });
                        } else {
                            index_pending = true;
                        }
                    }
                    Event::IndexDone => {
                        if index_pending {
                            index_pending = false;
                            let jmap = JMAP::from(core.clone());
                            tokio::spawn(async move {
                                jmap.fts_index_queued().await;
                            });
                        } else {
                            index_busy = false;
                        }
                    }
                    Event::Purge(purge) => match purge {
                        PurgeType::Data(store) => {
                            tokio::spawn(async move {
                                if let Err(err) = store.purge_store().await {
                                    tracing::error!("Failed to purge data store: {err}",);
                                }
                            });
                        }
                        PurgeType::Blobs { store, blob_store } => {
                            tokio::spawn(async move {
                                if let Err(err) = store.purge_blobs(blob_store).await {
                                    tracing::error!("Failed to purge blob store: {err}",);
                                }
                            });
                        }
                        PurgeType::Lookup(store) => {
                            tokio::spawn(async move {
                                if let Err(err) = store.purge_lookup_store().await {
                                    tracing::error!("Failed to purge lookup store: {err}",);
                                }
                            });
                        }
                        PurgeType::Account(account_id) => {
                            let jmap = JMAP::from(core.clone());
                            tokio::spawn(async move {
                                tracing::debug!("Purging accounts.");
                                if let Some(account_id) = account_id {
                                    jmap.purge_account(account_id).await;
                                } else {
                                    jmap.purge_accounts().await;
                                }
                            });
                        }
                    },
                    #[cfg(feature = "test_mode")]
                    Event::IndexIsActive(tx) => {
                        tx.send(index_busy).ok();
                    }
                    Event::Exit => {
                        tracing::debug!("Housekeeper task exiting.");
                        return;
                    }
                },
                Ok(None) => {
                    tracing::debug!("Housekeeper task exiting.");
                    return;
                }
                Err(_) => {
                    let core_ = core.core.load();
                    while let Some(event) = queue.pop() {
                        match event.event {
                            ActionClass::Acme(provider_id) => {
                                let inner = core.jmap_inner.clone();
                                let core = core_.clone();
                                tokio::spawn(async move {
                                    if let Some(provider) =
                                        core.tls.acme_providers.get(&provider_id)
                                    {
                                        tracing::info!(
                                            context = "acme",
                                            event = "order",
                                            domains = ?provider.domains,
                                            "Ordering certificates.");

                                        let renew_at = match core.renew(provider).await {
                                            Ok(renew_at) => {
                                                tracing::info!(
                                                    context = "acme",
                                                    event = "success",
                                                    domains = ?provider.domains,
                                                    next_renewal = ?renew_at,
                                                    "Certificates renewed.");
                                                renew_at
                                            }
                                            Err(err) => {
                                                tracing::error!(
                                                    context = "acme",
                                                    event = "error",
                                                    error = ?err,
                                                    "Failed to renew certificates.");

                                                Duration::from_secs(3600)
                                            }
                                        };

                                        inner.increment_config_version();

                                        inner
                                            .housekeeper_tx
                                            .send(Event::AcmeReschedule {
                                                provider_id: provider_id.clone(),
                                                renew_at: Instant::now() + renew_at,
                                            })
                                            .await
                                            .ok();
                                    }
                                });
                            }
                            ActionClass::Account => {
                                let jmap = JMAP::from(core.clone());
                                tokio::spawn(async move {
                                    tracing::debug!("Purging accounts.");
                                    jmap.purge_accounts().await;
                                });
                                queue.schedule(
                                    Instant::now()
                                        + core_.jmap.account_purge_frequency.time_to_next(),
                                    ActionClass::Account,
                                );
                            }
                            ActionClass::Session => {
                                let inner = core.jmap_inner.clone();
                                tokio::spawn(async move {
                                    tracing::debug!("Purging session cache.");
                                    inner.purge();
                                });
                                queue.schedule(
                                    Instant::now()
                                        + core_.jmap.session_purge_frequency.time_to_next(),
                                    ActionClass::Session,
                                );
                            }
                            ActionClass::Store(idx) => {
                                if let Some(schedule) =
                                    core_.storage.purge_schedules.get(idx).cloned()
                                {
                                    queue.schedule(
                                        Instant::now() + schedule.cron.time_to_next(),
                                        ActionClass::Store(idx),
                                    );
                                    tokio::spawn(async move {
                                        let (class, result) = match schedule.store {
                                            PurgeStore::Data(store) => {
                                                ("data", store.purge_store().await)
                                            }
                                            PurgeStore::Blobs { store, blob_store } => {
                                                ("blob", store.purge_blobs(blob_store).await)
                                            }
                                            PurgeStore::Lookup(lookup_store) => {
                                                ("lookup", lookup_store.purge_lookup_store().await)
                                            }
                                        };

                                        match result {
                                            Ok(_) => {
                                                tracing::debug!(
                                                    "Purged {class} store {}.",
                                                    schedule.store_id
                                                );
                                            }
                                            Err(err) => {
                                                tracing::error!(
                                                    "Failed to purge {class} store {}: {err}",
                                                    schedule.store_id
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

impl Queue {
    pub fn schedule(&mut self, due: Instant, event: ActionClass) {
        tracing::debug!(due_in = due.saturating_duration_since(Instant::now()).as_secs(), event = ?event, "Scheduling housekeeper event.");
        self.heap.push(Action { due, event });
    }

    pub fn remove_action(&mut self, event: &ActionClass) {
        self.heap.retain(|e| &e.event != event);
    }

    pub fn wake_up_time(&self) -> Duration {
        self.heap
            .peek()
            .map(|e| e.due.saturating_duration_since(Instant::now()))
            .unwrap_or(LONG_SLUMBER)
    }

    pub fn pop(&mut self) -> Option<Action> {
        if self.heap.peek()?.due <= Instant::now() {
            self.heap.pop()
        } else {
            None
        }
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.due.cmp(&other.due).reverse()
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Inner {
    pub fn purge(&self) {
        self.sessions.cleanup();
        self.access_tokens.cleanup();
        self.concurrency_limiter
            .retain(|_, limiter| limiter.is_active());
    }
}

pub fn init_housekeeper() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    mpsc::channel::<Event>(IPC_CHANNEL_BUFFER)
}
