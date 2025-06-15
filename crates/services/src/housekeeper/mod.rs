/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BinaryHeap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use common::{
    Inner, KV_LOCK_HOUSEKEEPER, LONG_1D_SLUMBER, Server,
    config::telemetry::OtelMetrics,
    core::BuildServer,
    ipc::{BroadcastEvent, HousekeeperEvent, PurgeType},
};

#[cfg(feature = "enterprise")]
use common::telemetry::{
    metrics::store::{MetricsStore, SharedMetricHistory},
    tracers::store::TracingStore,
};

use email::message::delete::EmailDeletion;
use smtp::reporting::SmtpReporting;
use store::{PurgeStore, write::now};
use tokio::sync::mpsc;
use trc::{Collector, MetricType, PurgeEvent};

#[derive(PartialEq, Eq)]
struct Action {
    due: Instant,
    event: ActionClass,
}

#[derive(PartialEq, Eq, Debug)]
enum ActionClass {
    Account,
    Store(usize),
    Acme(String),
    OtelMetrics,
    #[cfg(feature = "enterprise")]
    InternalMetrics,
    CalculateMetrics,
    #[cfg(feature = "enterprise")]
    AlertMetrics,
    #[cfg(feature = "enterprise")]
    RenewLicense,
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Action>,
}

#[cfg(feature = "enterprise")]
const METRIC_ALERTS_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub fn spawn_housekeeper(inner: Arc<Inner>, mut rx: mpsc::Receiver<HousekeeperEvent>) {
    tokio::spawn(async move {
        trc::event!(Housekeeper(trc::HousekeeperEvent::Start));
        let start_time = SystemTime::now();

        // Add all events to queue
        let mut queue = Queue::default();
        {
            let server = inner.build_server();

            // Account purge
            if server.core.network.roles.purge_accounts {
                queue.schedule(
                    Instant::now() + server.core.jmap.account_purge_frequency.time_to_next(),
                    ActionClass::Account,
                );
            }

            // Store purges
            if server.core.network.roles.purge_stores {
                for (idx, schedule) in server.core.storage.purge_schedules.iter().enumerate() {
                    queue.schedule(
                        Instant::now() + schedule.cron.time_to_next(),
                        ActionClass::Store(idx),
                    );
                }
            }

            // OTEL Push Metrics
            if server.core.network.roles.push_metrics {
                if let Some(otel) = &server.core.metrics.otel {
                    OtelMetrics::enable_errors();
                    queue.schedule(Instant::now() + otel.interval, ActionClass::OtelMetrics);
                }
            }

            // Calculate expensive metrics
            queue.schedule(Instant::now(), ActionClass::CalculateMetrics);

            // Add all ACME renewals to heap
            if server.core.network.roles.renew_acme {
                for provider in server.core.acme.providers.values() {
                    match server.init_acme(provider).await {
                        Ok(renew_at) => {
                            queue.schedule(
                                Instant::now() + renew_at,
                                ActionClass::Acme(provider.id.clone()),
                            );
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to initialize ACME certificate manager.")
                            );
                        }
                    };
                }
            }

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL

            // Enterprise Edition license management
            #[cfg(feature = "enterprise")]
            if let Some(enterprise) = &server.core.enterprise {
                queue.schedule(
                    Instant::now() + enterprise.license.renew_in(),
                    ActionClass::RenewLicense,
                );

                if let Some(metrics_store) = enterprise.metrics_store.as_ref() {
                    queue.schedule(
                        Instant::now() + metrics_store.interval.time_to_next(),
                        ActionClass::InternalMetrics,
                    );
                }

                if !enterprise.metrics_alerts.is_empty() {
                    queue.schedule(
                        Instant::now() + METRIC_ALERTS_INTERVAL,
                        ActionClass::AlertMetrics,
                    );
                }
            }
            // SPDX-SnippetEnd
        }

        // Metrics history
        #[cfg(feature = "enterprise")]
        let metrics_history = SharedMetricHistory::default();
        let mut next_metric_update = Instant::now();

        loop {
            match tokio::time::timeout(queue.wake_up_time(), rx.recv()).await {
                Ok(Some(event)) => {
                    match event {
                        HousekeeperEvent::ReloadSettings => {
                            let server = inner.build_server();

                            // Reload OTEL push metrics
                            match &server.core.metrics.otel {
                                Some(otel) if !queue.has_action(&ActionClass::OtelMetrics) => {
                                    OtelMetrics::enable_errors();

                                    queue.schedule(
                                        Instant::now() + otel.interval,
                                        ActionClass::OtelMetrics,
                                    );
                                }
                                _ => {}
                            }

                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            if let Some(enterprise) = &server.core.enterprise {
                                if !queue.has_action(&ActionClass::RenewLicense) {
                                    queue.schedule(
                                        Instant::now() + enterprise.license.renew_in(),
                                        ActionClass::RenewLicense,
                                    );
                                }

                                if let Some(metrics_store) = enterprise.metrics_store.as_ref() {
                                    if !queue.has_action(&ActionClass::InternalMetrics) {
                                        queue.schedule(
                                            Instant::now() + metrics_store.interval.time_to_next(),
                                            ActionClass::InternalMetrics,
                                        );
                                    }
                                }

                                if !enterprise.metrics_alerts.is_empty()
                                    && !queue.has_action(&ActionClass::AlertMetrics)
                                {
                                    queue.schedule(Instant::now(), ActionClass::AlertMetrics);
                                }
                            }
                            // SPDX-SnippetEnd

                            // Reload ACME certificates
                            tokio::spawn(async move {
                                for provider in server.core.acme.providers.values() {
                                    match server.init_acme(provider).await {
                                        Ok(renew_at) => {
                                            server
                                                .inner
                                                .ipc
                                                .housekeeper_tx
                                                .send(HousekeeperEvent::AcmeReschedule {
                                                    provider_id: provider.id.clone(),
                                                    renew_at: Instant::now() + renew_at,
                                                })
                                                .await
                                                .ok();
                                        }
                                        Err(err) => {
                                            trc::error!(err.details(
                                                "Failed to reload ACME certificate manager."
                                            ));
                                        }
                                    };
                                }
                            });
                        }
                        HousekeeperEvent::AcmeReschedule {
                            provider_id,
                            renew_at,
                        } => {
                            let action = ActionClass::Acme(provider_id);
                            queue.remove_action(&action);
                            queue.schedule(renew_at, action);
                        }
                        HousekeeperEvent::Purge(purge) => {
                            let server = inner.build_server();
                            tokio::spawn(async move {
                                server.purge(purge, 0).await;
                            });
                        }
                        HousekeeperEvent::Exit => {
                            trc::event!(Housekeeper(trc::HousekeeperEvent::Stop));

                            return;
                        }
                    }
                }
                Ok(None) => {
                    trc::event!(Housekeeper(trc::HousekeeperEvent::Stop));
                    return;
                }
                Err(_) => {
                    let server = inner.build_server();
                    while let Some(event) = queue.pop() {
                        match event.event {
                            ActionClass::Acme(provider_id) => {
                                trc::event!(Housekeeper(trc::HousekeeperEvent::Run), Type = "acme");

                                let server = server.clone();
                                tokio::spawn(async move {
                                    if let Some(provider) =
                                        server.core.acme.providers.get(&provider_id)
                                    {
                                        trc::event!(
                                            Acme(trc::AcmeEvent::OrderStart),
                                            Hostname = provider.domains.as_slice()
                                        );

                                        let renew_at = match server.renew(provider).await {
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

                                        server
                                            .cluster_broadcast(BroadcastEvent::ReloadSettings)
                                            .await;

                                        server
                                            .inner
                                            .ipc
                                            .housekeeper_tx
                                            .send(HousekeeperEvent::AcmeReschedule {
                                                provider_id: provider_id.clone(),
                                                renew_at: Instant::now() + renew_at,
                                            })
                                            .await
                                            .ok();
                                    }
                                });
                            }
                            ActionClass::Account => {
                                trc::event!(
                                    Housekeeper(trc::HousekeeperEvent::Run),
                                    Type = "purge_account"
                                );

                                let server = server.clone();
                                queue.schedule(
                                    Instant::now()
                                        + server.core.jmap.account_purge_frequency.time_to_next(),
                                    ActionClass::Account,
                                );
                                tokio::spawn(async move {
                                    server.purge(PurgeType::Account(None), 0).await;
                                });
                            }
                            ActionClass::Store(idx) => {
                                if let Some(schedule) =
                                    server.core.storage.purge_schedules.get(idx).cloned()
                                {
                                    trc::event!(
                                        Housekeeper(trc::HousekeeperEvent::Run),
                                        Type = "purge_store",
                                        Id = idx
                                    );

                                    queue.schedule(
                                        Instant::now() + schedule.cron.time_to_next(),
                                        ActionClass::Store(idx),
                                    );

                                    let server = server.clone();
                                    tokio::spawn(async move {
                                        server
                                            .purge(
                                                match schedule.store {
                                                    PurgeStore::Data(store) => {
                                                        PurgeType::Data(store)
                                                    }
                                                    PurgeStore::Blobs { store, blob_store } => {
                                                        PurgeType::Blobs { store, blob_store }
                                                    }
                                                    PurgeStore::Lookup(in_memory_store) => {
                                                        PurgeType::Lookup {
                                                            store: in_memory_store,
                                                            prefix: None,
                                                        }
                                                    }
                                                },
                                                idx as u32,
                                            )
                                            .await;
                                    });
                                }
                            }
                            ActionClass::OtelMetrics => {
                                if let Some(otel) = &server.core.metrics.otel {
                                    trc::event!(
                                        Housekeeper(trc::HousekeeperEvent::Run),
                                        Type = "metrics_report"
                                    );

                                    queue.schedule(
                                        Instant::now() + otel.interval,
                                        ActionClass::OtelMetrics,
                                    );

                                    let otel = otel.clone();

                                    #[cfg(feature = "enterprise")]
                                    let is_enterprise = server.is_enterprise_edition();

                                    #[cfg(not(feature = "enterprise"))]
                                    let is_enterprise = false;

                                    tokio::spawn(async move {
                                        otel.push_metrics(is_enterprise, start_time).await;
                                    });
                                }
                            }
                            ActionClass::CalculateMetrics => {
                                trc::event!(
                                    Housekeeper(trc::HousekeeperEvent::Run),
                                    Type = "metrics_calculate"
                                );

                                // Calculate expensive metrics every 5 minutes
                                queue.schedule(
                                    Instant::now() + Duration::from_secs(5 * 60),
                                    ActionClass::OtelMetrics,
                                );

                                let update_other_metrics = if Instant::now() >= next_metric_update {
                                    next_metric_update =
                                        Instant::now() + Duration::from_secs(86400);
                                    true
                                } else {
                                    false
                                };

                                let server = server.clone();
                                tokio::spawn(async move {
                                    if server.core.network.roles.calculate_metrics {
                                        #[cfg(feature = "enterprise")]
                                        if server.is_enterprise_edition() {
                                            // Obtain queue size
                                            match server.total_queued_messages().await {
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

                                        if update_other_metrics {
                                            match server.total_accounts().await {
                                                Ok(total) => {
                                                    Collector::update_gauge(
                                                        MetricType::UserCount,
                                                        total,
                                                    );
                                                }
                                                Err(err) => {
                                                    trc::error!(
                                                        err.details(
                                                            "Failed to obtain account count"
                                                        )
                                                    );
                                                }
                                            }

                                            match server.total_domains().await {
                                                Ok(total) => {
                                                    Collector::update_gauge(
                                                        MetricType::DomainCount,
                                                        total,
                                                    );
                                                }
                                                Err(err) => {
                                                    trc::error!(
                                                        err.details(
                                                            "Failed to obtain domain count"
                                                        )
                                                    );
                                                }
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
                                            trc::error!(
                                                trc::EventType::Server(
                                                    trc::ServerEvent::ThreadError,
                                                )
                                                .reason(err)
                                                .caused_by(trc::location!())
                                                .details("Join Error")
                                            );
                                        }
                                    }
                                });
                            }

                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            ActionClass::InternalMetrics => {
                                if let Some(metrics_store) = &server
                                    .core
                                    .enterprise
                                    .as_ref()
                                    .and_then(|e| e.metrics_store.as_ref())
                                {
                                    trc::event!(
                                        Housekeeper(trc::HousekeeperEvent::Run),
                                        Type = "metrics_internal"
                                    );

                                    queue.schedule(
                                        Instant::now() + metrics_store.interval.time_to_next(),
                                        ActionClass::InternalMetrics,
                                    );

                                    let metrics_store = metrics_store.store.clone();
                                    let metrics_history = metrics_history.clone();
                                    let core = server.core.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = metrics_store
                                            .write_metrics(core, now(), metrics_history)
                                            .await
                                        {
                                            trc::error!(err.details("Failed to write metrics"));
                                        }
                                    });
                                }
                            }

                            #[cfg(feature = "enterprise")]
                            ActionClass::AlertMetrics => {
                                trc::event!(
                                    Housekeeper(trc::HousekeeperEvent::Run),
                                    Type = "metrics_alert"
                                );

                                let server = server.clone();

                                tokio::spawn(async move {
                                    if let Some(messages) = server.process_alerts().await {
                                        for message in messages {
                                            server
                                                .send_autogenerated(
                                                    message.from,
                                                    message.to.into_iter(),
                                                    message.body,
                                                    None,
                                                    0,
                                                )
                                                .await;
                                        }
                                    }
                                });
                            }

                            #[cfg(feature = "enterprise")]
                            ActionClass::RenewLicense => {
                                trc::event!(
                                    Housekeeper(trc::HousekeeperEvent::Run),
                                    Type = "renew_license"
                                );

                                match server.reload().await {
                                    Ok(result) => {
                                        if let Some(new_core) = result.new_core {
                                            if let Some(enterprise) = &new_core.enterprise {
                                                let renew_in =
                                                    if enterprise.license.is_near_expiration() {
                                                        // Something went wrong during renewal, try again in 1 day or 1 hour,
                                                        // depending on the time left on the license
                                                        if enterprise.license.expires_in()
                                                            < Duration::from_secs(86400)
                                                        {
                                                            Duration::from_secs(3600)
                                                        } else {
                                                            Duration::from_secs(86400)
                                                        }
                                                    } else {
                                                        enterprise.license.renew_in()
                                                    };

                                                queue.schedule(
                                                    Instant::now() + renew_in,
                                                    ActionClass::RenewLicense,
                                                );
                                            }

                                            // Update core
                                            server.inner.shared_core.store(new_core.into());

                                            server
                                                .cluster_broadcast(BroadcastEvent::ReloadSettings)
                                                .await;
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

pub trait Purge: Sync + Send {
    fn purge(&self, purge: PurgeType, store_idx: u32) -> impl Future<Output = ()> + Send;
}

impl Purge for Server {
    async fn purge(&self, purge: PurgeType, store_idx: u32) {
        // Lock task
        let (lock_type, lock_name) = match &purge {
            PurgeType::Data(_) => (
                "data",
                [0u8]
                    .into_iter()
                    .chain(store_idx.to_be_bytes().into_iter())
                    .collect::<Vec<_>>()
                    .into(),
            ),
            PurgeType::Blobs { .. } => (
                "blob",
                [1u8]
                    .into_iter()
                    .chain(store_idx.to_be_bytes().into_iter())
                    .collect::<Vec<_>>()
                    .into(),
            ),
            PurgeType::Lookup { prefix: None, .. } => (
                "in-memory",
                [2u8]
                    .into_iter()
                    .chain(store_idx.to_be_bytes().into_iter())
                    .collect::<Vec<_>>()
                    .into(),
            ),
            PurgeType::Lookup { .. } => ("in-memory-prefix", None),
            PurgeType::Account(_) => ("account", None),
        };
        if let Some(lock_name) = &lock_name {
            match self
                .core
                .storage
                .lookup
                .try_lock(KV_LOCK_HOUSEKEEPER, lock_name, 3600)
                .await
            {
                Ok(true) => (),
                Ok(false) => {
                    trc::event!(Purge(PurgeEvent::InProgress), Details = lock_type);
                    return;
                }
                Err(err) => {
                    trc::error!(err.details("Failed to lock task.").details(lock_type));
                    return;
                }
            }
        }

        trc::event!(Purge(PurgeEvent::Started), Type = lock_type, Id = store_idx);
        let time = Instant::now();

        match purge {
            PurgeType::Data(store) => {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let trace_retention = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_store.as_ref())
                    .and_then(|t| t.retention);
                #[cfg(feature = "enterprise")]
                let metrics_retention = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.metrics_store.as_ref())
                    .and_then(|m| m.retention);
                // SPDX-SnippetEnd

                if let Err(err) = store.purge_store().await {
                    trc::error!(err.details("Failed to purge data store"));
                }

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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
            }
            PurgeType::Blobs { store, blob_store } => {
                if let Err(err) = store.purge_blobs(blob_store).await {
                    trc::error!(err.details("Failed to purge blob store"));
                }
            }
            PurgeType::Lookup { store, prefix } => {
                if let Some(prefix) = prefix {
                    if let Err(err) = store.key_delete_prefix(&prefix).await {
                        trc::error!(
                            err.details("Failed to delete key prefix")
                                .ctx(trc::Key::Key, prefix)
                        );
                    }
                } else if let Err(err) = store.purge_in_memory_store().await {
                    trc::error!(err.details("Failed to purge in-memory store"));
                }
            }
            PurgeType::Account(account_id) => {
                if let Some(account_id) = account_id {
                    self.purge_account(account_id).await;
                } else {
                    self.purge_accounts().await;
                }
            }
        }

        trc::event!(
            Purge(PurgeEvent::Finished),
            Type = lock_type,
            Id = store_idx,
            Elapsed = time.elapsed()
        );

        // Remove lock
        if let Some(lock_name) = &lock_name {
            if let Err(err) = self
                .in_memory_store()
                .remove_lock(KV_LOCK_HOUSEKEEPER, lock_name)
                .await
            {
                trc::error!(
                    err.details("Failed to delete task lock.")
                        .details(lock_type)
                );
            }
        }
    }
}

impl Queue {
    pub fn schedule(&mut self, due: Instant, event: ActionClass) {
        trc::event!(
            Housekeeper(trc::HousekeeperEvent::Schedule),
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
            .unwrap_or(LONG_1D_SLUMBER)
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
