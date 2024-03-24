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

use std::{collections::BinaryHeap, time::Instant};

use store::write::purge::PurgeStore;
use tokio::sync::mpsc;
use utils::map::ttl_dashmap::TtlMap;

use crate::{Inner, JmapInstance, JMAP, LONG_SLUMBER};

use super::IPC_CHANNEL_BUFFER;

pub enum Event {
    IndexStart,
    IndexDone,
    #[cfg(feature = "test_mode")]
    IndexIsActive(tokio::sync::oneshot::Sender<bool>),
    Exit,
}

#[derive(PartialEq, Eq)]
struct PurgeEvent {
    due: Instant,
    event: PurgeClass,
}

#[derive(PartialEq, Eq)]
enum PurgeClass {
    Session,
    Store(usize),
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
        let mut heap = BinaryHeap::new();

        // Add all purge events to heap
        let core_ = core.core.load();
        heap.push(PurgeEvent {
            due: Instant::now() + core_.jmap.session_purge_frequency.time_to_next(),
            event: PurgeClass::Session,
        });
        for (idx, schedule) in core_.storage.purge_schedules.iter().enumerate() {
            heap.push(PurgeEvent {
                due: Instant::now() + schedule.cron.time_to_next(),
                event: PurgeClass::Store(idx),
            });
        }

        loop {
            let time_to_next = heap
                .peek()
                .map(|e| e.due.saturating_duration_since(Instant::now()))
                .unwrap_or(LONG_SLUMBER);

            match tokio::time::timeout(time_to_next, rx.recv()).await {
                Ok(Some(event)) => match event {
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
                    while let Some(event) = heap.peek() {
                        if event.due > Instant::now() {
                            break;
                        }
                        let event = heap.pop().unwrap();
                        match event.event {
                            PurgeClass::Session => {
                                let inner = core.jmap_inner.clone();
                                tokio::spawn(async move {
                                    tracing::debug!("Purging session cache.");
                                    inner.purge();
                                });
                                heap.push(PurgeEvent {
                                    due: Instant::now()
                                        + core_.jmap.session_purge_frequency.time_to_next(),
                                    event: PurgeClass::Session,
                                });
                            }
                            PurgeClass::Store(idx) => {
                                if let Some(schedule) =
                                    core_.storage.purge_schedules.get(idx).cloned()
                                {
                                    heap.push(PurgeEvent {
                                        due: Instant::now() + schedule.cron.time_to_next(),
                                        event: PurgeClass::Store(idx),
                                    });
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

impl Ord for PurgeEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.due.cmp(&other.due).reverse()
    }
}

impl PartialOrd for PurgeEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Inner {
    pub fn purge(&self) {
        self.sessions.cleanup();
        self.access_tokens.cleanup();
        self.oauth_codes.cleanup();
        self.concurrency_limiter
            .retain(|_, limiter| limiter.is_active());
    }
}

pub fn init_housekeeper() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    mpsc::channel::<Event>(IPC_CHANNEL_BUFFER)
}
