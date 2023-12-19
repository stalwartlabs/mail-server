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

use std::fmt::Display;

use tokio::sync::watch;
use utils::config::cron::SimpleCron;

use crate::{BlobStore, LookupStore, Store};

pub enum PurgeStore {
    Bitmaps(Store),
    Blobs { store: Store, blob_store: BlobStore },
    Lookup(LookupStore),
}

pub struct PurgeSchedule {
    pub cron: SimpleCron,
    pub store_id: String,
    pub store: PurgeStore,
}

impl PurgeSchedule {
    pub fn spawn(self, mut shutdown_rx: watch::Receiver<bool>) {
        tracing::debug!(
            "Purge {} task started for store {:?}.",
            self.store,
            self.store_id
        );
        tokio::spawn(async move {
            loop {
                if tokio::time::timeout(self.cron.time_to_next(), shutdown_rx.changed())
                    .await
                    .is_ok()
                {
                    tracing::debug!(
                        "Purge {} task exiting for store {:?}.",
                        self.store,
                        self.store_id
                    );
                    return;
                }

                let result = match &self.store {
                    PurgeStore::Bitmaps(store) => store.purge_bitmaps().await,
                    PurgeStore::Blobs { store, blob_store } => {
                        store.purge_blobs(blob_store.clone()).await
                    }
                    PurgeStore::Lookup(store) => store.purge_expired().await,
                };

                if let Err(err) = result {
                    tracing::warn!(
                        "Purge {} task failed for store {:?}: {:?}",
                        self.store,
                        self.store_id,
                        err
                    );
                }
            }
        });
    }
}

impl Display for PurgeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeStore::Bitmaps(_) => write!(f, "bitmaps"),
            PurgeStore::Blobs { .. } => write!(f, "blobs"),
            PurgeStore::Lookup(_) => write!(f, "expired keys"),
        }
    }
}
