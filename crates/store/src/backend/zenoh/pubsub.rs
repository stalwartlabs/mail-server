/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ZenohPubSub;
use crate::dispatch::pubsub::{Msg, PubSubStream};
use trc::{ClusterEvent, Error, EventType};

pub struct ZenohPubSubStream {
    subs: zenoh::pubsub::Subscriber<zenoh::handlers::FifoChannelHandler<zenoh::sample::Sample>>,
}

impl ZenohPubSub {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        self.session
            .declare_publisher(topic)
            .await
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err)
            })?
            .put(message)
            .await
            .map_err(|err| Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err))
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        self.session
            .declare_subscriber(topic)
            .await
            .map(|subs| PubSubStream::Zenoh(ZenohPubSubStream { subs }))
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })
    }
}

impl ZenohPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        self.subs
            .recv_async()
            .await
            .map(|sample| Msg::Zenoh(sample.payload().to_bytes().into_owned()))
            .ok()
    }
}
