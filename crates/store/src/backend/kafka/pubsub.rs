/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use super::{CustomContext, KafkaPubSub, LoggingConsumer};
use crate::dispatch::pubsub::{Msg, PubSubStream};
use rdkafka::{
    Message,
    consumer::{CommitMode, Consumer, StreamConsumer},
    producer::FutureRecord,
};
use trc::{ClusterEvent, Error, EventType};

pub struct KafkaPubSubStream {
    subs: LoggingConsumer,
}

impl KafkaPubSub {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        self.producer
            .send(
                FutureRecord::<(), [u8]>::to(topic).payload(message.as_slice()),
                Duration::from_secs(0),
            )
            .await
            .map(|_| ())
            .map_err(|(err, _)| {
                Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err)
            })
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        let subs: StreamConsumer<CustomContext> = self
            .consumer_builder
            .create_with_context(CustomContext)
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })?;
        subs.subscribe(&[topic]).map_err(|err| {
            Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
        })?;

        Ok(PubSubStream::Kafka(KafkaPubSubStream { subs }))
    }
}

impl KafkaPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        let msg = self.subs.recv().await.ok()?;
        let _ = self.subs.commit_message(&msg, CommitMode::Async);
        Msg::Kafka(msg.payload().unwrap_or_default().to_vec()).into()
    }
}
