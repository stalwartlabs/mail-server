/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, RandomState};
use common::Core;
use mail_auth::dmarc::Dmarc;

use std::time::{Duration, Instant, SystemTime};
use store::{
    write::{now, BatchBuilder, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, Serialize, ValueKey,
};
use tokio::sync::mpsc;

use crate::{
    core::{SmtpInstance, SMTP},
    queue::{manager::LONG_WAIT, spool::LOCK_EXPIRY},
};

use super::{Event, ReportLock};

impl SpawnReport for mpsc::Receiver<Event> {
    fn spawn(mut self, core: SmtpInstance) {
        tokio::spawn(async move {
            let mut last_cleanup = Instant::now();
            let mut next_wake_up;

            loop {
                // Read events
                let now = now();
                let events = next_report_event(&core.core.load()).await;
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

                let core = SMTP::from(core.clone());
                let core_ = core.clone();
                tokio::spawn(async move {
                    let mut tls_reports = AHashMap::new();
                    for report_event in events {
                        match report_event {
                            QueueClass::DmarcReportHeader(event) if event.due <= now => {
                                if core_.try_lock_report(QueueClass::dmarc_lock(&event)).await {
                                    core_.send_dmarc_aggregate_report(event).await;
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
                        if core_
                            .try_lock_report(QueueClass::tls_lock(tls_report.first().unwrap()))
                            .await
                        {
                            core_.send_tls_aggregate_report(tls_report).await;
                        }
                    }
                });

                match tokio::time::timeout(next_wake_up, self.recv()).await {
                    Ok(Some(event)) => match event {
                        Event::Dmarc(event) => {
                            core.schedule_dmarc(event).await;
                        }
                        Event::Tls(event) => {
                            core.schedule_tls(event).await;
                        }
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        // Cleanup expired throttles
                        if last_cleanup.elapsed().as_secs() >= 86400 {
                            last_cleanup = Instant::now();
                            core.cleanup();
                        }
                    }
                }
            }
        });
    }
}

async fn next_report_event(core: &Core) -> Vec<QueueClass> {
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
    let result = core
        .storage
        .data
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
        tracing::error!(
            context = "queue",
            event = "error",
            "Failed to read from store: {}",
            err
        );
    }

    events
}

impl SMTP {
    pub async fn try_lock_report(&self, lock: QueueClass) -> bool {
        let now = now();
        match self
            .core
            .storage
            .data
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
                        Err(err) if err.matches(trc::Cause::AssertValue) => {
                            tracing::debug!(
                                context = "queue",
                                event = "locked",
                                key = ?lock,
                                "Lock busy: Event already locked."
                            );
                            false
                        }
                        Err(err) => {
                            tracing::error!(
                                context = "queue",
                                event = "error",
                                "Lock busy: {}",
                                err
                            );
                            false
                        }
                    }
                } else {
                    tracing::debug!(
                        context = "queue",
                        event = "locked",
                        key = ?lock,
                        expiry = expiry - now,
                        "Lock busy: Report already locked."
                    );
                    false
                }
            }
            Ok(None) => {
                tracing::debug!(
                    context = "queue",
                    event = "locked",
                    key = ?lock,
                    "Lock busy: Report lock deleted."
                );
                false
            }
            Err(err) => {
                tracing::error!(
                    context = "queue",
                    event = "error",
                    key = ?lock,
                    "Lock error: {}",
                    err
                );
                false
            }
        }
    }
}

pub trait ToHash {
    fn to_hash(&self) -> u64;
}

impl ToHash for Dmarc {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl ToHash for super::PolicyType {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
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
    fn spawn(self, core: SmtpInstance);
}
