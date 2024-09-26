/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use common::{core::BuildServer, ipc::ReportingEvent, Inner, Server};

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use store::{
    write::{now, BatchBuilder, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, Key, Serialize, Store, ValueKey,
};
use tokio::sync::mpsc;

use crate::queue::{manager::LONG_WAIT, spool::LOCK_EXPIRY};

use super::{dmarc::DmarcReporting, tls::TlsReporting, ReportLock};

impl SpawnReport for mpsc::Receiver<ReportingEvent> {
    fn spawn(mut self, inner: Arc<Inner>) {
        tokio::spawn(async move {
            let mut next_wake_up;

            loop {
                // Read events
                let now = now();
                let events = next_report_event(inner.shared_core.load().storage.data.clone()).await;
                next_wake_up = events
                    .last()
                    .and_then(|e| match e {
                        QueueClass::DmarcReportHeader(e) | QueueClass::TlsReportHeader(e)
                            if e.due > now =>
                        {
                            Duration::from_secs(e.due - now).into()
                        }
                        _ => None,
                    })
                    .unwrap_or(LONG_WAIT);

                let server = inner.build_server();
                let server_ = server.clone();
                tokio::spawn(async move {
                    let mut tls_reports = AHashMap::new();
                    for report_event in events {
                        match report_event {
                            QueueClass::DmarcReportHeader(event) if event.due <= now => {
                                if server.try_lock_report(QueueClass::dmarc_lock(&event)).await {
                                    server.send_dmarc_aggregate_report(event).await;
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
                        if server
                            .try_lock_report(QueueClass::tls_lock(tls_report.first().unwrap()))
                            .await
                        {
                            server.send_tls_aggregate_report(tls_report).await;
                        }
                    }
                });

                match tokio::time::timeout(next_wake_up, self.recv()).await {
                    Ok(Some(event)) => match event {
                        ReportingEvent::Dmarc(event) => {
                            server_.schedule_dmarc(event).await;
                        }
                        ReportingEvent::Tls(event) => {
                            server_.schedule_tls(event).await;
                        }
                        ReportingEvent::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => {}
                }
            }
        });
    }
}

async fn next_report_event(store: Store) -> Vec<QueueClass> {
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
            due: u64::MAX,
            policy_hash: 0,
            seq_id: 0,
            domain: String::new(),
        },
    )));

    let mut events = Vec::new();
    let now = now();
    let result = store
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let event = ReportEvent::deserialize(key)?;
                if event.seq_id == 0 {
                    // Skip lock
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

    if let Err(err) = result {
        trc::error!(err
            .caused_by(trc::location!())
            .details("Failed to read from store"));
    }

    events
}

pub trait LockReport: Sync + Send {
    fn try_lock_report(&self, lock: QueueClass) -> impl Future<Output = bool> + Send;
}

impl LockReport for Server {
    async fn try_lock_report(&self, lock: QueueClass) -> bool {
        let now = now();
        match self
            .store()
            .get_value::<u64>(ValueKey::from(ValueClass::Queue(lock.clone())))
            .await
        {
            Ok(Some(expiry)) => {
                if expiry < now {
                    let mut batch = BatchBuilder::new();
                    batch.assert_value(ValueClass::Queue(lock.clone()), expiry);
                    batch.set(
                        ValueClass::Queue(lock.clone()),
                        (now + LOCK_EXPIRY).serialize(),
                    );
                    match self.core.storage.data.write(batch.build()).await {
                        Ok(_) => true,
                        Err(err) if err.is_assertion_failure() => {
                            trc::event!(
                                OutgoingReport(trc::OutgoingReportEvent::LockBusy),
                                Expires = trc::Value::Timestamp(expiry),
                                CausedBy = err,
                                Key = ValueKey::from(ValueClass::Queue(lock)).serialize(0)
                            );
                            false
                        }
                        Err(err) => {
                            trc::error!(err
                                .caused_by(trc::location!())
                                .details("Failed to lock report"));

                            false
                        }
                    }
                } else {
                    trc::event!(
                        OutgoingReport(trc::OutgoingReportEvent::Locked),
                        Expires = trc::Value::Timestamp(expiry),
                        Key = ValueKey::from(ValueClass::Queue(lock)).serialize(0)
                    );

                    false
                }
            }
            Ok(None) => {
                trc::event!(
                    OutgoingReport(trc::OutgoingReportEvent::LockDeleted),
                    Key = ValueKey::from(ValueClass::Queue(lock)).serialize(0)
                );

                false
            }
            Err(err) => {
                trc::error!(err
                    .caused_by(trc::location!())
                    .details("Failed to lock report"));

                false
            }
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
