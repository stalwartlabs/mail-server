/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::NatsPubSub;
use crate::dispatch::pubsub::{Msg, PubSubStream};
use futures::StreamExt;
use trc::{ClusterEvent, Error, EventType};

pub struct NatsPubSubStream {
    subs: async_nats::Subscriber,
}

impl NatsPubSub {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        self.client
            .publish(topic, message.into())
            .await
            .map_err(|err| Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err))
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        self.client
            .subscribe(topic)
            .await
            .map(|subs| PubSubStream::Nats(NatsPubSubStream { subs }))
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })
    }
}

impl NatsPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        self.subs.next().await.map(Msg::Nats)
    }
}
