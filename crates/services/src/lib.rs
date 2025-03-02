/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{
    Inner,
    manager::boot::{BootManager, IpcReceivers},
};
use housekeeper::spawn_housekeeper;
use index::spawn_email_queue_task;
use state_manager::manager::spawn_state_manager;

pub mod gossip;
pub mod housekeeper;
pub mod index;
pub mod state_manager;

pub trait StartServices: Sync + Send {
    fn start_services(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait SpawnServices {
    fn spawn_services(&mut self, inner: Arc<Inner>);
}

impl StartServices for BootManager {
    async fn start_services(&mut self) {
        // Unpack webadmin
        if let Err(err) = self
            .inner
            .data
            .webadmin
            .unpack(&self.inner.shared_core.load().storage.blob)
            .await
        {
            trc::event!(
                Resource(trc::ResourceEvent::Error),
                Reason = err,
                Details = "Failed to unpack webadmin bundle"
            );
        }

        self.ipc_rxs.spawn_services(self.inner.clone());
    }
}

impl SpawnServices for IpcReceivers {
    fn spawn_services(&mut self, inner: Arc<Inner>) {
        // Spawn state manager
        spawn_state_manager(inner.clone(), self.state_rx.take().unwrap());

        // Spawn housekeeper
        spawn_housekeeper(inner.clone(), self.housekeeper_rx.take().unwrap());

        // Spawn index task
        spawn_email_queue_task(inner);
    }
}
