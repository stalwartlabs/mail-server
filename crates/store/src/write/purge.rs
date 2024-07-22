/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use tokio::sync::watch;
use trc::PurgeEvent;
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
        trc::event!(
            Purge(PurgeEvent::Started),
            Type = self.store.as_str(),
            Id = self.store_id.to_string()
        );

        tokio::spawn(async move {
            loop {
                if tokio::time::timeout(self.cron.time_to_next(), shutdown_rx.changed())
                    .await
                    .is_ok()
                {
                    trc::event!(
                        Purge(PurgeEvent::Finished),
                        Type = self.store.as_str(),
                        Id = self.store_id.to_string()
                    );
                    return;
                }

                trc::event!(
                    Purge(PurgeEvent::Running),
                    Type = self.store.as_str(),
                    Id = self.store_id.to_string()
                );

                let result = match &self.store {
                    PurgeStore::Data(store) => store.purge_store().await,
                    PurgeStore::Blobs { store, blob_store } => {
                        store.purge_blobs(blob_store.clone()).await
                    }
                    PurgeStore::Lookup(store) => store.purge_lookup_store().await,
                };

                if let Err(err) = result {
                    trc::event!(
                        Purge(PurgeEvent::Error),
                        Type = self.store.as_str(),
                        Id = self.store_id.to_string(),
                        CausedBy = err
                    );
                }
            }
        });
    }
}

impl PurgeStore {
    pub fn as_str(&self) -> &'static str {
        match self {
            PurgeStore::Data(_) => "data",
            PurgeStore::Blobs { .. } => "blobs",
            PurgeStore::Lookup(_) => "lookup",
        }
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
