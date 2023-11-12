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

use std::{sync::Arc, time::Instant};

use tokio::sync::mpsc;
use utils::{
    config::{cron::SimpleCron, Config},
    map::ttl_dashmap::TtlMap,
    UnwrapFailure,
};

use crate::JMAP;

use super::IPC_CHANNEL_BUFFER;

pub enum Event {
    PurgeDb,
    PurgeBlobs,
    PurgeSessions,
    Exit,
}

const TASK_PURGE_DB: usize = 0;
const TASK_PURGE_BLOBS: usize = 1;
const TASK_PURGE_SESSIONS: usize = 2;

pub fn spawn_housekeeper(core: Arc<JMAP>, settings: &Config, mut rx: mpsc::Receiver<Event>) {
    let purge_db_at = settings
        .property_or_static::<SimpleCron>("jmap.purge.schedule.db", "0 3 *")
        .failed("Initialize housekeeper");
    let purge_blobs_at = settings
        .property_or_static::<SimpleCron>("jmap.purge.schedule.blobs", "30 3 *")
        .failed("Initialize housekeeper");
    let purge_cache = settings
        .property_or_static::<SimpleCron>("jmap.purge.schedule.sessions", "15 * *")
        .failed("Initialize housekeeper");

    tokio::spawn(async move {
        tracing::debug!("Housekeeper task started.");
        loop {
            let time_to_next = [
                purge_db_at.time_to_next(),
                purge_blobs_at.time_to_next(),
                purge_cache.time_to_next(),
            ];
            let mut tasks_to_run = [false, false, false];
            let start_time = Instant::now();

            match tokio::time::timeout(time_to_next.iter().min().copied().unwrap(), rx.recv()).await
            {
                Ok(Some(event)) => match event {
                    Event::PurgeDb => tasks_to_run[TASK_PURGE_DB] = true,
                    Event::PurgeBlobs => tasks_to_run[TASK_PURGE_BLOBS] = true,
                    Event::PurgeSessions => tasks_to_run[TASK_PURGE_SESSIONS] = true,
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
            let now = Instant::now();
            for (pos, time_to_next) in time_to_next.into_iter().enumerate() {
                if start_time + time_to_next <= now {
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
                            tracing::info!("Purging temporary blobs.",);
                            if let Err(err) =
                                core.store.blob_hash_purge(core.blob_store.clone()).await
                            {
                                tracing::error!("Error while purging blobs: {}", err);
                            }
                        }
                        TASK_PURGE_SESSIONS => {
                            tracing::info!("Purging session cache.");
                            core.sessions.cleanup();
                            core.access_tokens.cleanup();
                            core.oauth_codes.cleanup();
                            core.rate_limit_auth
                                .retain(|_, limiter| limiter.lock().is_active());
                            core.rate_limit_unauth
                                .retain(|_, limiter| limiter.lock().is_active());
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
