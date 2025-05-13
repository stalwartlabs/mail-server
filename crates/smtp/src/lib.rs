/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{
    manager::boot::{BootManager, IpcReceivers},
    Inner,
};
use queue::manager::SpawnQueue;
use reporting::scheduler::SpawnReport;

pub mod core;
pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod reporting;
pub mod scripts;

pub trait StartQueueManager {
    fn start_queue_manager(&mut self);
}

pub trait SpawnQueueManager {
    fn spawn_queue_manager(&mut self, inner: Arc<Inner>);
}

impl StartQueueManager for BootManager {
    fn start_queue_manager(&mut self) {
        self.ipc_rxs.spawn_queue_manager(self.inner.clone());
    }
}

impl SpawnQueueManager for IpcReceivers {
    fn spawn_queue_manager(&mut self, inner: Arc<Inner>) {
        // Spawn queue manager
        self.queue_rx.take().unwrap().spawn(inner.clone());

        // Spawn report manager
        self.report_rx.take().unwrap().spawn(inner);
    }
}
