/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::broadcast::{BROADCAST_TOPIC, BroadcastBatch};
use common::{
    Inner,
    core::BuildServer,
    ipc::{BroadcastEvent, HousekeeperEvent, StateEvent},
};
use compact_str::CompactString;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use trc::{ClusterEvent, ServerEvent};

pub fn spawn_broadcast_subscriber(inner: Arc<Inner>, mut shutdown_rx: watch::Receiver<bool>) {
    let this_node_id = {
        let _core = inner.shared_core.load();
        if _core.storage.pubsub.is_none() {
            return;
        }
        _core.network.node_id as u16
    };

    tokio::spawn(async move {
        let mut retry_count = 0;

        trc::event!(Cluster(ClusterEvent::SubscriberStart));

        loop {
            let pubsub = inner.shared_core.load().storage.pubsub.clone();
            if pubsub.is_none() {
                trc::event!(
                    Cluster(ClusterEvent::SubscriberError),
                    Details = "PubSub is no longer configured"
                );
                break;
            }

            let mut stream = match pubsub.subscribe(BROADCAST_TOPIC).await {
                Ok(stream) => {
                    retry_count = 0;
                    stream
                }
                Err(err) => {
                    trc::event!(
                        Cluster(ClusterEvent::SubscriberError),
                        CausedBy = err,
                        Details = "Failed to subscribe to channel"
                    );

                    match tokio::time::timeout(
                        Duration::from_secs(1 << retry_count.max(6)),
                        shutdown_rx.changed(),
                    )
                    .await
                    {
                        Ok(_) => {
                            break;
                        }
                        Err(_) => {
                            retry_count += 1;
                            continue;
                        }
                    }
                }
            };

            tokio::select! {
                message = stream.next() => {
                    match message {
                        Some(message) => {
                            let batch = BroadcastBatch::new(message.payload());
                            let node_id = match batch.node_id() {
                                Some(node_id) => {
                                    if node_id != this_node_id {
                                        node_id
                                    } else {
                                        trc::event!(
                                            Cluster(ClusterEvent::MessageSkipped),
                                            Details = message.payload()
                                        );
                                        continue;
                                    }
                                }
                                None => {
                                    trc::event!(
                                        Cluster(ClusterEvent::MessageInvalid),
                                        Details = message.payload()
                                    );
                                    continue;
                                }
                            };

                            let mut max_timestamp = 0;
                            let mut has_errors = false;

                            for event in batch.events() {
                                if let Some(event) = event {
                                    match event {
                                        BroadcastEvent::StateChange(state_change) => {
                                            max_timestamp = std::cmp::max(
                                                max_timestamp,
                                                state_change.change_id,
                                            );
                                            if inner.ipc.state_tx.send(StateEvent::Publish { state_change, broadcast: false }).await.is_err() {
                                                trc::event!(
                                                    Server(ServerEvent::ThreadError),
                                                    Details = "Error sending state change.",
                                                    CausedBy = trc::location!()
                                                );
                                            }
                                        },
                                        BroadcastEvent::ReloadSettings => {
                                            match inner.build_server().reload().await {
                                                Ok(result) => {
                                                    if let Some(new_core) = result.new_core {
                                                        // Update core
                                                        inner.shared_core.store(new_core.into());

                                                        if inner
                                                            .ipc
                                                            .housekeeper_tx
                                                            .send(HousekeeperEvent::ReloadSettings)
                                                            .await
                                                            .is_err()
                                                        {
                                                            trc::event!(
                                                                Server(trc::ServerEvent::ThreadError),
                                                                Details = "Failed to send setting reload event to housekeeper",
                                                                CausedBy = trc::location!(),
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    trc::error!(
                                                        err.details("Failed to reload settings")
                                                            .caused_by(trc::location!())
                                                    );
                                                }
                                            }
                                        },
                                        BroadcastEvent::ReloadBlockedIps => {
                                            if let Err(err) = inner.build_server().reload_blocked_ips().await {
                                                trc::error!(
                                                        err.details("Failed to reload settings")
                                                            .caused_by(trc::location!())
                                                );
                                            }
                                        },
                                    }
                                } else if !has_errors {
                                    trc::event!(
                                        Cluster(ClusterEvent::MessageInvalid),
                                        Details = message.payload()
                                    );
                                    has_errors = true;
                                }

                            }

                            trc::event!(
                                Cluster(ClusterEvent::MessageReceived),
                                From = node_id,
                                To = this_node_id,
                                Details = batch.events().flatten().map(log_event).collect::<Vec<_>>(),
                            );
                        }
                        None => {
                            trc::event!(
                                Cluster(ClusterEvent::SubscriberDisconnected),
                            );
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    break;
                }
            };
        }

        trc::event!(Cluster(ClusterEvent::SubscriberStop));
    });
}

fn log_event(event: BroadcastEvent) -> trc::Value {
    match event {
        BroadcastEvent::StateChange(state_change) => trc::Value::Array(vec![
            state_change.account_id.into(),
            state_change.change_id.into(),
            (*state_change.types.as_ref()).into(),
        ]),
        BroadcastEvent::ReloadSettings => CompactString::const_new("ReloadSettings").into(),
        BroadcastEvent::ReloadBlockedIps => CompactString::const_new("ReloadBlockedIps").into(),
    }
}
