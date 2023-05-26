/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::{sync::Arc, time::Duration};

use chrono::{Datelike, TimeZone};
use jmap_proto::types::date::UTCDate;
use store::{write::now, BlobKind};
use tokio::sync::mpsc;
use utils::{config::Config, failed, UnwrapFailure};

use crate::JMAP;

use super::IPC_CHANNEL_BUFFER;

pub enum Event {
    PurgeDb,
    PurgeBlobs,
    Exit,
}

enum SimpleCron {
    EveryDay { hour: u32, minute: u32 },
    EveryWeek { day: u32, hour: u32, minute: u32 },
}

const TASK_PURGE_DB: usize = 0;
const TASK_PURGE_BLOBS: usize = 1;

pub fn spawn_housekeeper(core: Arc<JMAP>, settings: &Config, mut rx: mpsc::Receiver<Event>) {
    let purge_db_at = SimpleCron::parse(
        settings
            .value("jmap.house-keeper.purge-db")
            .unwrap_or("0 3 *"),
    );
    let purge_blobs_at = SimpleCron::parse(
        settings
            .value("jmap.house-keeper.purge-blobs")
            .unwrap_or("30 3 *"),
    );

    tokio::spawn(async move {
        tracing::debug!("Housekeeper task started.");
        loop {
            let time_to_next = [purge_db_at.time_to_next(), purge_blobs_at.time_to_next()];
            let mut tasks_to_run = [false, false];
            let start_time = now();

            match tokio::time::timeout(time_to_next.iter().min().copied().unwrap(), rx.recv()).await
            {
                Ok(Some(event)) => match event {
                    Event::PurgeDb => tasks_to_run[TASK_PURGE_DB] = true,
                    Event::PurgeBlobs => tasks_to_run[TASK_PURGE_BLOBS] = true,
                    Event::Exit => {
                        tracing::debug!("Housekeeper task exiting.");
                        return;
                    }
                },
                Ok(None) => {
                    tracing::debug!("Housekeeper task exiting.");
                    return;
                }
                Err(_) => (),
            }

            // Check which tasks are due for execution
            let now = now();
            for (pos, time_to_next) in time_to_next.into_iter().enumerate() {
                if start_time + time_to_next.as_secs() <= now {
                    tasks_to_run[pos] = true;
                }
            }

            // Spawn tasks
            for (task_id, do_run) in tasks_to_run.into_iter().enumerate() {
                if !do_run {
                    continue;
                }

                let core = core.clone();

                tokio::spawn(async move {
                    match task_id {
                        TASK_PURGE_DB => {
                            tracing::info!("Purging database.");
                            if let Err(err) = core.store.purge_bitmaps().await {
                                tracing::error!("Error while purging bitmaps: {}", err);
                            }
                        }
                        TASK_PURGE_BLOBS => {
                            let ts = UTCDate::from_timestamp((now - 86400) as i64);
                            tracing::info!(
                                "Purging temporary blobs for {}/{}/{}.",
                                ts.day,
                                ts.month,
                                ts.year
                            );
                            if let Err(err) = core
                                .store
                                .bulk_delete_blob(&BlobKind::Temporary {
                                    creation_year: ts.year,
                                    creation_month: ts.month,
                                    creation_day: ts.day,
                                    account_id: 0,
                                    seq: 0,
                                })
                                .await
                            {
                                tracing::error!("Error while purging bitmaps: {}", err);
                            }
                        }
                        _ => unreachable!(),
                    }
                });
            }
        }
    });
}

pub fn init_housekeeper() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    mpsc::channel::<Event>(IPC_CHANNEL_BUFFER)
}

impl SimpleCron {
    pub fn parse(value: &str) -> Self {
        let mut hour = 0;
        let mut minute = 0;

        for (pos, value) in value.split(' ').enumerate() {
            if pos == 0 {
                minute = value.parse::<u32>().failed("parse minute.");
                if !(0..=59).contains(&minute) {
                    failed(&format!("parse minute, invalid value: {}", minute));
                }
            } else if pos == 1 {
                hour = value.parse::<u32>().failed("parse hour.");
                if !(0..=23).contains(&hour) {
                    failed(&format!("parse hour, invalid value: {}", hour));
                }
            } else if pos == 2 {
                if value.as_bytes().first().failed("parse weekday") == &b'*' {
                    return SimpleCron::EveryDay { hour, minute };
                } else {
                    let day = value.parse::<u32>().failed("parse weekday.");
                    if !(1..=7).contains(&hour) {
                        failed(&format!(
                            "parse weekday, invalid value: {}, range is 1 (Monday) to 7 (Sunday).",
                            hour,
                        ));
                    }

                    return SimpleCron::EveryWeek { day, hour, minute };
                }
            }
        }

        failed("parse cron expression.");
    }

    pub fn time_to_next(&self) -> Duration {
        let now = chrono::Local::now();
        let next = match self {
            SimpleCron::EveryDay { hour, minute } => {
                let next = chrono::Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .unwrap();
                if next < now {
                    next + chrono::Duration::days(1)
                } else {
                    next
                }
            }
            SimpleCron::EveryWeek { day, hour, minute } => {
                let next = chrono::Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .unwrap();
                if next < now {
                    next + chrono::Duration::days(
                        (7 - now.weekday().number_from_monday() + *day).into(),
                    )
                } else {
                    next
                }
            }
        };

        (next - now).to_std().unwrap()
    }
}
