/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::PubSubStore;

pub enum PubSubStream {
    #[cfg(feature = "redis")]
    Redis(crate::backend::redis::pubsub::RedisPubSubStream),
    #[cfg(feature = "redis")]
    RedisCluster(crate::backend::redis::pubsub::RedisClusterPubSubStream),
    #[cfg(feature = "nats")]
    Nats(crate::backend::nats::pubsub::NatsPubSubStream),
    #[cfg(feature = "zenoh")]
    Zenoh(crate::backend::zenoh::pubsub::ZenohPubSubStream),
    #[cfg(feature = "kafka")]
    Kafka(crate::backend::kafka::pubsub::KafkaPubSubStream),
    #[cfg(not(any(feature = "redis", feature = "nats")))]
    Unimplemented,
}

pub enum Msg {
    #[cfg(feature = "redis")]
    Redis(redis::Msg),
    #[cfg(feature = "nats")]
    Nats(async_nats::Message),
    #[cfg(feature = "zenoh")]
    Zenoh(Vec<u8>),
    #[cfg(feature = "kafka")]
    Kafka(Vec<u8>),
    #[cfg(not(any(feature = "redis", feature = "nats")))]
    Unimplemented,
}

#[allow(unused_variables)]
impl PubSubStore {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        match self {
            #[cfg(feature = "redis")]
            PubSubStore::Redis(store) => store.publish(topic, message).await,
            #[cfg(feature = "nats")]
            PubSubStore::Nats(store) => store.publish(topic, message).await,
            #[cfg(feature = "zenoh")]
            PubSubStore::Zenoh(store) => store.publish(topic, message).await,
            #[cfg(feature = "kafka")]
            PubSubStore::Kafka(store) => store.publish(topic, message).await,
            PubSubStore::None => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        match self {
            #[cfg(feature = "redis")]
            PubSubStore::Redis(store) => store.subscribe(topic).await,
            #[cfg(feature = "nats")]
            PubSubStore::Nats(store) => store.subscribe(topic).await,
            #[cfg(feature = "zenoh")]
            PubSubStore::Zenoh(store) => store.subscribe(topic).await,
            #[cfg(feature = "kafka")]
            PubSubStore::Kafka(store) => store.subscribe(topic).await,
            PubSubStore::None => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, PubSubStore::None)
    }
}

impl PubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        match self {
            #[cfg(feature = "redis")]
            PubSubStream::Redis(stream) => stream.next().await,
            #[cfg(feature = "redis")]
            PubSubStream::RedisCluster(stream) => stream.next().await,
            #[cfg(feature = "nats")]
            PubSubStream::Nats(stream) => stream.next().await,
            #[cfg(feature = "zenoh")]
            PubSubStream::Zenoh(stream) => stream.next().await,
            #[cfg(feature = "kafka")]
            PubSubStream::Kafka(stream) => stream.next().await,
            #[cfg(not(any(feature = "redis", feature = "nats")))]
            PubSubStream::Unimplemented => None,
        }
    }
}

impl Msg {
    pub fn payload(&self) -> &[u8] {
        match self {
            #[cfg(feature = "redis")]
            Msg::Redis(msg) => msg.get_payload_bytes(),
            #[cfg(feature = "nats")]
            Msg::Nats(msg) => msg.payload.as_ref(),
            #[cfg(feature = "zenoh")]
            Msg::Zenoh(msg) => msg.as_slice(),
            #[cfg(feature = "kafka")]
            Msg::Kafka(msg) => msg.as_slice(),
            #[cfg(not(any(feature = "redis", feature = "nats")))]
            Msg::Unimplemented => &[],
        }
    }

    pub fn topic(&self) -> &str {
        match self {
            #[cfg(feature = "redis")]
            Msg::Redis(msg) => msg.get_channel_name(),
            #[cfg(feature = "nats")]
            Msg::Nats(msg) => msg.subject.as_str(),
            #[cfg(feature = "zenoh")]
            Msg::Zenoh(_) => "",
            #[cfg(feature = "kafka")]
            Msg::Kafka(_) => "",
            #[cfg(not(any(feature = "redis", feature = "nats")))]
            Msg::Unimplemented => "",
        }
    }
}
