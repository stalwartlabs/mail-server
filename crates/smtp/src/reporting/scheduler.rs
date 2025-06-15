/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use common::{Inner, KV_LOCK_QUEUE_REPORT, Server, core::BuildServer, ipc::ReportingEvent};

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use store::{
    Deserialize, IterateParams, Store, ValueKey,
    write::{BatchBuilder, QueueClass, ReportEvent, ValueClass, now},
};
use tokio::sync::mpsc;

use crate::queue::spool::LOCK_EXPIRY;

use super::{AggregateTimestamp, ReportLock, dmarc::DmarcReporting, tls::TlsReporting};

pub const REPORT_REFRESH: Duration = Duration::from_secs(86400);

impl SpawnReport for mpsc::Receiver<ReportingEvent> {
    fn spawn(mut self, inner: Arc<Inner>) {
        tokio::spawn(async move {
            let mut next_wake_up = REPORT_REFRESH;
            let mut refresh_queue = true;

            loop {
                let server = inner.build_server();

                if refresh_queue {
                    // Read events
                    let events = next_report_event(server.store()).await;
                    let now = now();
                    next_wake_up = events
                        .last()
                        .and_then(|e| {
                            e.due()
                                .filter(|due| *due > now)
                                .map(|due| Duration::from_secs(due - now))
                        })
                        .unwrap_or(REPORT_REFRESH);

                    if events
                        .first()
                        .and_then(|e| e.due())
                        .is_some_and(|due| due <= now)
                    {
                        let server_ = server.clone();
                        tokio::spawn(async move {
                            let mut tls_reports = AHashMap::new();
                            for report_event in events {
                                match report_event {
                                    QueueClass::DmarcReportHeader(event) if event.due <= now => {
                                        let lock_name = event.dmarc_lock();
                                        if server_.try_lock_report(&lock_name).await {
                                            server_.send_dmarc_aggregate_report(event).await;
                                            server_.unlock_report(&lock_name).await;
                                        }
                                    }
                                    QueueClass::TlsReportHeader(event) if event.due <= now => {
                                        tls_reports
                                            .entry(event.domain.clone())
                                            .or_insert_with(Vec::new)
                                            .push(event);
                                    }
                                    _ => (),
                                }
                            }

                            for (_, tls_report) in tls_reports {
                                let lock_name = tls_report.first().unwrap().tls_lock();
                                if server_.try_lock_report(&lock_name).await {
                                    server_.send_tls_aggregate_report(tls_report).await;
                                    server_.unlock_report(&lock_name).await;
                                }
                            }
                        });
                    }
                }

                match tokio::time::timeout(next_wake_up, self.recv()).await {
                    Ok(Some(event)) => {
                        refresh_queue = false;

                        match event {
                            ReportingEvent::Dmarc(event) => {
                                next_wake_up = std::cmp::min(
                                    next_wake_up,
                                    Duration::from_secs(event.interval.due().saturating_sub(now())),
                                );
                                server.schedule_dmarc(event).await;
                            }
                            ReportingEvent::Tls(event) => {
                                next_wake_up = std::cmp::min(
                                    next_wake_up,
                                    Duration::from_secs(event.interval.due().saturating_sub(now())),
                                );
                                server.schedule_tls(event).await;
                            }
                            ReportingEvent::Stop => break,
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        refresh_queue = true;
                    }
                }
            }
        });
    }
}

async fn next_report_event(store: &Store) -> Vec<QueueClass> {
    let now = now();
    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportHeader(
        ReportEvent {
            due: 0,
            policy_hash: 0,
            seq_id: 0,
            domain: String::new(),
        },
    )));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::TlsReportHeader(
        ReportEvent {
            due: now + REPORT_REFRESH.as_secs(),
            policy_hash: 0,
            seq_id: 0,
            domain: String::new(),
        },
    )));

    let mut events = Vec::new();
    let mut old_locks = Vec::new();
    let result = store
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let event = ReportEvent::deserialize(key)?;

                // TODO - REMOVEME - Part of v0.11 migration
                if event.seq_id == 0 {
                    old_locks.push(if *key.last().unwrap() == 0 {
                        QueueClass::DmarcReportHeader(event)
                    } else {
                        QueueClass::TlsReportHeader(event)
                    });
                    return Ok(true);
                }

                let do_continue = event.due <= now;
                events.push(if *key.last().unwrap() == 0 {
                    QueueClass::DmarcReportHeader(event)
                } else {
                    QueueClass::TlsReportHeader(event)
                });
                Ok(do_continue)
            },
        )
        .await;

    // TODO - REMOVEME - Part of v0.11 migration
    if !old_locks.is_empty() {
        let mut batch = BatchBuilder::new();
        for event in old_locks {
            batch.clear(ValueClass::Queue(event));
        }
        if let Err(err) = store.write(batch.build_all()).await {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to remove old report events")
            );
        }
    }

    if let Err(err) = result {
        trc::error!(
            err.caused_by(trc::location!())
                .details("Failed to read from store")
        );
    }

    events
}

pub trait LockReport: Sync + Send {
    fn try_lock_report(&self, lock: &[u8]) -> impl Future<Output = bool> + Send;

    fn unlock_report(&self, lock: &[u8]) -> impl Future<Output = ()> + Send;
}

impl LockReport for Server {
    async fn try_lock_report(&self, key: &[u8]) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_QUEUE_REPORT, key, LOCK_EXPIRY)
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        OutgoingReport(trc::OutgoingReportEvent::Locked),
                        Expires = trc::Value::Timestamp(now() + LOCK_EXPIRY),
                        Key = key
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock report.")
                        .caused_by(trc::location!())
                );
                false
            }
        }
    }

    async fn unlock_report(&self, key: &[u8]) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_QUEUE_REPORT, key)
            .await
        {
            trc::error!(
                err.details("Failed to unlock event.")
                    .caused_by(trc::location!())
            );
        }
    }
}

pub trait ToTimestamp {
    fn to_timestamp(&self) -> u64;
}

impl ToTimestamp for Duration {
    fn to_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.as_secs()
    }
}

pub trait SpawnReport {
    fn spawn(self, core: Arc<Inner>);
}
