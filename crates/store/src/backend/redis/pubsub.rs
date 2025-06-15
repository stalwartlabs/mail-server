/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RedisPool, RedisStore, into_error};
use crate::dispatch::pubsub::{Msg, PubSubStream};
use futures::StreamExt;
use redis::{AsyncCommands, PushInfo, cluster::ClusterConfig, cluster_async::ClusterConnection};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct RedisPubSubStream {
    stream: redis::aio::PubSubStream,
}

pub struct RedisClusterPubSubStream {
    _conn: ClusterConnection,
    rx: UnboundedReceiver<PushInfo>,
}

impl RedisStore {
    pub async fn publish(&self, topic: &'static str, message: Vec<u8>) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => pool
                .get()
                .await
                .map_err(into_error)?
                .as_mut()
                .publish(topic, message)
                .await
                .map_err(into_error),
            RedisPool::Cluster(pool) => pool
                .get()
                .await
                .map_err(into_error)?
                .as_mut()
                .publish(topic, message)
                .await
                .map_err(into_error),
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<PubSubStream> {
        match &self.pool {
            RedisPool::Single(pool) => {
                let mut pubsub = pool
                    .manager()
                    .client
                    .get_async_pubsub()
                    .await
                    .map_err(into_error)?;
                pubsub.subscribe(topic).await.map_err(into_error)?;

                Ok(PubSubStream::Redis(RedisPubSubStream {
                    stream: pubsub.into_on_message(),
                }))
            }
            RedisPool::Cluster(pool) => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

                let mut _conn = pool
                    .manager()
                    .client
                    .get_async_connection_with_config(ClusterConfig::default().set_push_sender(tx))
                    .await
                    .map_err(into_error)?;

                _conn.subscribe(topic).await.map_err(into_error)?;

                Ok(PubSubStream::RedisCluster(RedisClusterPubSubStream {
                    _conn,
                    rx,
                }))
            }
        }
    }
}

impl RedisPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        self.stream.next().await.map(Msg::Redis)
    }
}

impl RedisClusterPubSubStream {
    pub async fn next(&mut self) -> Option<Msg> {
        loop {
            if let Some(msg) = redis::Msg::from_push_info(self.rx.recv().await?) {
                return Some(Msg::Redis(msg));
            }
        }
    }
}
