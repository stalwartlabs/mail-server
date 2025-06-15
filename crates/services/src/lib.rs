/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use broadcast::publisher::spawn_broadcast_publisher;
use common::{
    Inner,
    manager::boot::{BootManager, IpcReceivers},
};
use housekeeper::spawn_housekeeper;
use state_manager::manager::spawn_state_manager;
use std::sync::Arc;
use task_manager::spawn_task_manager;

pub mod broadcast;
pub mod housekeeper;
pub mod state_manager;
pub mod task_manager;

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

        // Spawn broadcast publisher
        if let Some(event_rx) = self.broadcast_rx.take() {
            // Spawn broadcast publisher
            spawn_broadcast_publisher(inner.clone(), event_rx);
        }

        // Spawn task manager
        spawn_task_manager(inner);
    }
}
