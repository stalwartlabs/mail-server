/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use tokio::sync::watch;
use utils::config::cron::SimpleCron;

use crate::{BlobStore, LookupStore, Store};

#[derive(Clone)]
pub enum PurgeStore {
    Data(Store),
    Blobs { store: Store, blob_store: BlobStore },
    Lookup(LookupStore),
}

#[derive(Clone)]
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
                    PurgeStore::Data(store) => store.purge_store().await,
                    PurgeStore::Blobs { store, blob_store } => {
                        store.purge_blobs(blob_store.clone()).await
                    }
                    PurgeStore::Lookup(store) => store.purge_lookup_store().await,
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
            PurgeStore::Data(_) => write!(f, "bitmaps"),
            PurgeStore::Blobs { .. } => write!(f, "blobs"),
            PurgeStore::Lookup(_) => write!(f, "expired keys"),
        }
    }
}
