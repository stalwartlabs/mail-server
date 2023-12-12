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

use std::sync::Arc;

use tokio::sync::mpsc;
use utils::{
    config::{cron::SimpleCron, Config},
    map::ttl_dashmap::TtlMap,
    UnwrapFailure,
};

use crate::JMAP;

use super::IPC_CHANNEL_BUFFER;

pub enum Event {
    PurgeSessions,
    IndexStart,
    IndexDone,
    #[cfg(feature = "test_mode")]
    IndexIsActive(tokio::sync::oneshot::Sender<bool>),
    Exit,
}

pub fn spawn_housekeeper(core: Arc<JMAP>, settings: &Config, mut rx: mpsc::Receiver<Event>) {
    let purge_cache = settings
        .property_or_static::<SimpleCron>("jmap.purge.schedule.sessions", "15 * *")
        .failed("Initialize housekeeper");

    tokio::spawn(async move {
        tracing::debug!("Housekeeper task started.");

        let mut index_busy = true;
        let mut index_pending = false;

        // Index any queued messages
        let core_ = core.clone();
        tokio::spawn(async move {
            core_.fts_index_queued().await;
        });

        loop {
            let time_to_next = purge_cache.time_to_next();
            let mut do_purge = false;

            match tokio::time::timeout(time_to_next, rx.recv()).await {
                Ok(Some(event)) => match event {
                    Event::PurgeSessions => {
                        do_purge = true;
                    }
                    Event::IndexStart => {
                        if !index_busy {
                            index_busy = true;
                            let core = core.clone();
                            tokio::spawn(async move {
                                core.fts_index_queued().await;
                            });
                        } else {
                            index_pending = true;
                        }
                    }
                    Event::IndexDone => {
                        if index_pending {
                            index_pending = false;
                            let core = core.clone();
                            tokio::spawn(async move {
                                core.fts_index_queued().await;
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
                Err(_) => (),
            }

            if do_purge {
                let core = core.clone();
                tokio::spawn(async move {
                    tracing::info!("Purging session cache.");
                    core.sessions.cleanup();
                    core.access_tokens.cleanup();
                    core.oauth_codes.cleanup();
                    core.rate_limit_auth
                        .retain(|_, limiter| limiter.lock().is_active());
                    core.rate_limit_unauth
                        .retain(|_, limiter| limiter.lock().is_active());
                });
            }
        }
    });
}

pub fn init_housekeeper() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    mpsc::channel::<Event>(IPC_CHANNEL_BUFFER)
}
