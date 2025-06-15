/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{Inner, ipc::BroadcastEvent};
use tokio::sync::mpsc;
use trc::ClusterEvent;

use super::{BROADCAST_TOPIC, BroadcastBatch};

pub fn spawn_broadcast_publisher(inner: Arc<Inner>, mut event_rx: mpsc::Receiver<BroadcastEvent>) {
    let (pubsub, this_node_id) = {
        let _core = inner.shared_core.load();
        let pubsub = inner.shared_core.load().storage.pubsub.clone();
        if pubsub.is_none() {
            return;
        }
        (pubsub, _core.network.node_id as u16)
    };

    tokio::spawn(async move {
        let mut batch = BroadcastBatch::init();

        trc::event!(Cluster(ClusterEvent::PublisherStart));

        while let Some(event) = event_rx.recv().await {
            batch.insert(event);

            while let Ok(event) = event_rx.try_recv() {
                if !batch.insert(event) {
                    break;
                }
            }

            match pubsub
                .publish(BROADCAST_TOPIC, batch.serialize(this_node_id))
                .await
            {
                Ok(_) => {
                    batch.clear();
                }
                Err(err) => {
                    batch.clear();
                    trc::event!(Cluster(ClusterEvent::PublisherError), CausedBy = err);
                }
            }
        }

        trc::event!(Cluster(ClusterEvent::PublisherStop));
    });
}
