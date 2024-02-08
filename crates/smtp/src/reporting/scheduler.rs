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

use ahash::{AHashMap, RandomState};
use mail_auth::dmarc::Dmarc;

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use store::{
    write::{now, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, ValueKey,
};
use tokio::sync::mpsc;

use crate::{
    core::{worker::SpawnCleanup, SMTP},
    queue::manager::LONG_WAIT,
};

use super::Event;

impl SpawnReport for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<SMTP>) {
        tokio::spawn(async move {
            let mut last_cleanup = Instant::now();
            let mut next_wake_up;

            loop {
                // Read events
                let now = now();
                let events = core.next_report_event().await;
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

                let core_ = core.clone();
                tokio::spawn(async move {
                    let mut tls_reports = AHashMap::new();
                    for report_event in events {
                        match report_event {
                            QueueClass::DmarcReportHeader(event) if event.due <= now => {
                                core_.generate_dmarc_report(event).await;
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

                    for (domain_name, tls_report) in tls_reports {
                        core_.generate_tls_report(domain_name, tls_report).await;
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
                            core.spawn_cleanup();
                        }
                    }
                }
            }
        });
    }
}

impl SMTP {
    pub async fn next_report_event(&self) -> Vec<QueueClass> {
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
        let result = self
            .shared
            .default_data_store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let event = ReportEvent::deserialize(key)?;
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
    fn spawn(self, core: Arc<SMTP>);
}
