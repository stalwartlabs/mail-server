/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BinaryHeap,
    time::{Duration, Instant, SystemTime},
};

use common::{config::telemetry::OtelMetrics, IPC_CHANNEL_BUFFER};

#[cfg(feature = "enterprise")]
use common::telemetry::{
    metrics::store::{MetricsStore, SharedMetricHistory},
    tracers::store::TracingStore,
};

use store::{
    write::{now, purge::PurgeStore},
    BlobStore, LookupStore, Store,
};
use tokio::sync::mpsc;
use trc::{Collector, HousekeeperEvent, MetricType};
use utils::map::ttl_dashmap::TtlMap;

use crate::{Inner, JmapInstance, JMAP, LONG_SLUMBER};

pub enum Event {
    AcmeReschedule {
        provider_id: String,
        renew_at: Instant,
    },
    Purge(PurgeType),
    ReloadSettings,
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
    OtelMetrics,
    #[cfg(feature = "enterprise")]
    InternalMetrics,
    CalculateMetrics,
    #[cfg(feature = "enterprise")]
    ReloadSettings,
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Action>,
}

pub fn spawn_housekeeper(core: JmapInstance, mut rx: mpsc::Receiver<Event>) {
    tokio::spawn(async move {
        trc::event!(Housekeeper(HousekeeperEvent::Start));
        let start_time = SystemTime::now();

        // Add all events to queue
        let mut queue = Queue::default();
        {
            let core_ = core.core.load_full();

            // Session purge
            queue.schedule(
                Instant::now() + core_.jmap.session_purge_frequency.time_to_next(),
                ActionClass::Session,
            );

            // Account purge
            queue.schedule(
                Instant::now() + core_.jmap.account_purge_frequency.time_to_next(),
                ActionClass::Account,
            );

            // Store purges
            for (idx, schedule) in core_.storage.purge_schedules.iter().enumerate() {
                queue.schedule(
                    Instant::now() + schedule.cron.time_to_next(),
                    ActionClass::Store(idx),
                );
            }

            // OTEL Push Metrics
            if let Some(otel) = &core_.metrics.otel {
                OtelMetrics::enable_errors();
                queue.schedule(Instant::now() + otel.interval, ActionClass::OtelMetrics);
            }

            // Calculate expensive metrics
            queue.schedule(Instant::now(), ActionClass::CalculateMetrics);

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
                        trc::error!(err.details("Failed to initialize ACME certificate manager."));
                    }
                };
            }

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL

            // Enterprise Edition license management
            #[cfg(feature = "enterprise")]
            if let Some(enterprise) = &core_.enterprise {
                queue.schedule(
                    Instant::now() + enterprise.license.expires_in(),
                    ActionClass::ReloadSettings,
                );

                if let Some(metrics_store) = enterprise.metrics_store.as_ref() {
                    queue.schedule(
                        Instant::now() + metrics_store.interval.time_to_next(),
                        ActionClass::InternalMetrics,
                    );
                }
            }
            // SPDX-SnippetEnd
        }

        // Metrics history
        #[cfg(feature = "enterprise")]
        let metrics_history = SharedMetricHistory::default();

        loop {
            match tokio::time::timeout(queue.wake_up_time(), rx.recv()).await {
                Ok(Some(event)) => match event {
                    Event::ReloadSettings => {
                        let core_ = core.core.load_full();
                        let inner = core.jmap_inner.clone();

                        // Reload OTEL push metrics
                        match &core_.metrics.otel {
                            Some(otel) if !queue.has_action(&ActionClass::OtelMetrics) => {
                                OtelMetrics::enable_errors();

                                queue.schedule(
                                    Instant::now() + otel.interval,
                                    ActionClass::OtelMetrics,
                                );
                            }
                            _ => {}
                        }

                        // Reload ACME certificates
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
                                        trc::error!(err
                                            .details("Failed to reload ACME certificate manager."));
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
                    Event::Purge(purge) => match purge {
                        PurgeType::Data(store) => {
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            let trace_retention = core
                                .core
                                .load()
                                .enterprise
                                .as_ref()
                                .and_then(|e| e.trace_store.as_ref())
                                .and_then(|t| t.retention);
                            #[cfg(feature = "enterprise")]
                            let metrics_retention = core
                                .core
                                .load()
                                .enterprise
                                .as_ref()
                                .and_then(|e| e.metrics_store.as_ref())
                                .and_then(|m| m.retention);
                            // SPDX-SnippetEnd

                            tokio::spawn(async move {
                                trc::event!(
                                    Housekeeper(HousekeeperEvent::PurgeStore),
                                    Type = "data"
                                );
                                if let Err(err) = store.purge_store().await {
                                    trc::error!(err.details("Failed to purge data store"));
                                }

                                // SPDX-SnippetBegin
                                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                                // SPDX-License-Identifier: LicenseRef-SEL
                                #[cfg(feature = "enterprise")]
                                if let Some(trace_retention) = trace_retention {
                                    if let Err(err) = store.purge_spans(trace_retention).await {
                                        trc::error!(err.details("Failed to purge tracing spans"));
                                    }
                                }

                                #[cfg(feature = "enterprise")]
                                if let Some(metrics_retention) = metrics_retention {
                                    if let Err(err) = store.purge_metrics(metrics_retention).await {
                                        trc::error!(err.details("Failed to purge metrics"));
                                    }
                                }
                                // SPDX-SnippetEnd
                            });
                        }
                        PurgeType::Blobs { store, blob_store } => {
                            trc::event!(Housekeeper(HousekeeperEvent::PurgeStore), Type = "blob");

                            tokio::spawn(async move {
                                if let Err(err) = store.purge_blobs(blob_store).await {
                                    trc::error!(err.details("Failed to purge blob store"));
                                }
                            });
                        }
                        PurgeType::Lookup(store) => {
                            trc::event!(Housekeeper(HousekeeperEvent::PurgeStore), Type = "lookup");

                            tokio::spawn(async move {
                                if let Err(err) = store.purge_lookup_store().await {
                                    trc::error!(err.details("Failed to purge lookup store"));
                                }
                            });
                        }
                        PurgeType::Account(account_id) => {
                            let jmap = JMAP::from(core.clone());
                            tokio::spawn(async move {
                                trc::event!(Housekeeper(HousekeeperEvent::PurgeAccounts));

                                if let Some(account_id) = account_id {
                                    jmap.purge_account(account_id).await;
                                } else {
                                    jmap.purge_accounts().await;
                                }
                            });
                        }
                    },
                    Event::Exit => {
                        trc::event!(Housekeeper(HousekeeperEvent::Stop));

                        return;
                    }
                },
                Ok(None) => {
                    trc::event!(Housekeeper(HousekeeperEvent::Stop));
                    return;
                }
                Err(_) => {
                    let core_ = core.core.load_full();
                    while let Some(event) = queue.pop() {
                        match event.event {
                            ActionClass::Acme(provider_id) => {
                                let inner = core.jmap_inner.clone();
                                let core = core_.clone();
                                tokio::spawn(async move {
                                    if let Some(provider) =
                                        core.tls.acme_providers.get(&provider_id)
                                    {
                                        trc::event!(
                                            Acme(trc::AcmeEvent::OrderStart),
                                            Hostname = provider.domains.as_slice()
                                        );

                                        let renew_at = match core.renew(provider).await {
                                            Ok(renew_at) => {
                                                trc::event!(
                                                    Acme(trc::AcmeEvent::OrderCompleted),
                                                    Domain = provider.domains.as_slice(),
                                                    Expires = trc::Value::Timestamp(
                                                        now() + renew_at.as_secs()
                                                    )
                                                );

                                                renew_at
                                            }
                                            Err(err) => {
                                                trc::error!(
                                                    err.details("Failed to renew certificates.")
                                                );

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
                                    trc::event!(Housekeeper(HousekeeperEvent::PurgeAccounts));
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
                                    trc::event!(Housekeeper(HousekeeperEvent::PurgeSessions));
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
                                                trc::event!(
                                                    Housekeeper(HousekeeperEvent::PurgeStore),
                                                    Id = schedule.store_id
                                                );
                                            }
                                            Err(err) => {
                                                trc::error!(err
                                                    .details(format!(
                                                        "Failed to purge {class} store."
                                                    ))
                                                    .id(schedule.store_id));
                                            }
                                        }
                                    });
                                }
                            }
                            ActionClass::OtelMetrics => {
                                if let Some(otel) = &core_.metrics.otel {
                                    queue.schedule(
                                        Instant::now() + otel.interval,
                                        ActionClass::OtelMetrics,
                                    );

                                    let otel = otel.clone();
                                    let core = core_.clone();
                                    tokio::spawn(async move {
                                        otel.push_metrics(core, start_time).await;
                                    });
                                }
                            }
                            ActionClass::CalculateMetrics => {
                                // Calculate expensive metrics every 5 minutes
                                queue.schedule(
                                    Instant::now() + Duration::from_secs(5 * 60),
                                    ActionClass::OtelMetrics,
                                );

                                let core = core_.clone();
                                tokio::spawn(async move {
                                    #[cfg(feature = "enterprise")]
                                    if core.is_enterprise_edition() {
                                        // Obtain queue size
                                        match core.message_queue_size().await {
                                            Ok(total) => {
                                                Collector::update_gauge(
                                                    MetricType::QueueCount,
                                                    total,
                                                );
                                            }
                                            Err(err) => {
                                                trc::error!(
                                                    err.details("Failed to obtain queue size")
                                                );
                                            }
                                        }
                                    }

                                    match tokio::task::spawn_blocking(memory_stats::memory_stats)
                                        .await
                                    {
                                        Ok(Some(stats)) => {
                                            Collector::update_gauge(
                                                MetricType::ServerMemory,
                                                stats.physical_mem as u64,
                                            );
                                        }
                                        Ok(None) => {}
                                        Err(err) => {
                                            trc::error!(trc::EventType::Server(
                                                trc::ServerEvent::ThreadError,
                                            )
                                            .reason(err)
                                            .caused_by(trc::location!())
                                            .details("Join Error"));
                                        }
                                    }
                                });
                            }

                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            ActionClass::InternalMetrics => {
                                if let Some(metrics_store) = &core_
                                    .enterprise
                                    .as_ref()
                                    .and_then(|e| e.metrics_store.as_ref())
                                {
                                    queue.schedule(
                                        Instant::now() + metrics_store.interval.time_to_next(),
                                        ActionClass::InternalMetrics,
                                    );

                                    let metrics_store = metrics_store.store.clone();
                                    let metrics_history = metrics_history.clone();
                                    let core = core_.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) =
                                            metrics_store.write_metrics(core, metrics_history).await
                                        {
                                            trc::error!(err.details("Failed to write metrics"));
                                        }
                                    });
                                }
                            }

                            #[cfg(feature = "enterprise")]
                            ActionClass::ReloadSettings => {
                                match core_.reload().await {
                                    Ok(result) => {
                                        if let Some(new_core) = result.new_core {
                                            if let Some(enterprise) = &new_core.enterprise {
                                                queue.schedule(
                                                    Instant::now()
                                                        + enterprise.license.expires_in(),
                                                    ActionClass::ReloadSettings,
                                                );
                                            }

                                            // Update core
                                            core.core.store(new_core.into());

                                            // Increment version counter
                                            core.jmap_inner.increment_config_version();
                                        }
                                    }
                                    Err(err) => {
                                        trc::error!(err.details("Failed to reload configuration."));
                                    }
                                }
                            } // SPDX-SnippetEnd
                        }
                    }
                }
            }
        }
    });
}

impl Queue {
    pub fn schedule(&mut self, due: Instant, event: ActionClass) {
        trc::event!(
            Housekeeper(HousekeeperEvent::Schedule),
            Due = trc::Value::Timestamp(
                now() + due.saturating_duration_since(Instant::now()).as_secs()
            ),
            Id = format!("{:?}", event)
        );

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

    pub fn has_action(&self, event: &ActionClass) -> bool {
        self.heap.iter().any(|e| &e.event == event)
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
