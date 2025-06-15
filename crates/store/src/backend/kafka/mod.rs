/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rdkafka::{
    ClientConfig, ClientContext, TopicPartitionList,
    consumer::{BaseConsumer, ConsumerContext, Rebalance, StreamConsumer},
    error::KafkaResult,
    producer::FutureProducer,
};
use std::{fmt::Debug, time::Duration};
use utils::config::{Config, utils::AsKey};

pub mod pubsub;

pub(super) type LoggingConsumer = StreamConsumer<CustomContext>;

pub struct KafkaPubSub {
    consumer_builder: ClientConfig,
    producer: FutureProducer,
}

impl KafkaPubSub {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let brokers = config
            .values((&prefix, "brokers"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();
        if brokers.is_empty() {
            config.new_build_error((&prefix, "brokers"), "No Kafka brokers specified");
            return None;
        }

        let mut consumer_builder = ClientConfig::new();

        consumer_builder
            .set(
                "group.id",
                config.value_require_non_empty((&prefix, "group-id"))?,
            )
            .set(
                "bootstrap.servers",
                config.value_require_non_empty((&prefix, "brokers"))?,
            )
            .set("enable.partition.eof", "false")
            .set(
                "session.timeout.ms",
                config
                    .property_or_default((&prefix, "timeout.session"), "5s")
                    .unwrap_or(Duration::from_secs(5))
                    .as_millis()
                    .to_string(),
            )
            .set("enable.auto.commit", "true");

        let producer = ClientConfig::new()
            .set(
                "bootstrap.servers",
                config.value_require_non_empty((&prefix, "brokers"))?,
            )
            .set(
                "message.timeout.ms",
                config
                    .property_or_default((&prefix, "timeout.message"), "5s")
                    .unwrap_or(Duration::from_secs(5))
                    .as_millis()
                    .to_string(),
            )
            .create()
            .map_err(|err| {
                config.new_build_error(
                    (&prefix, "config"),
                    format!("Failed to create Kafka producer: {}", err),
                );
            })
            .ok()?;

        KafkaPubSub {
            consumer_builder,
            producer,
        }
        .into()
    }
}

impl Debug for KafkaPubSub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaPubSub").finish()
    }
}

pub(super) struct CustomContext;

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn post_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn commit_callback(&self, _: KafkaResult<()>, _: &TopicPartitionList) {}
}
