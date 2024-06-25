/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::managed;
use redis::{
    aio::{ConnectionLike, MultiplexedConnection},
    cluster_async::ClusterConnection,
};

use super::{RedisClusterConnectionManager, RedisConnectionManager};

impl managed::Manager for RedisConnectionManager {
    type Type = MultiplexedConnection;
    type Error = crate::Error;

    async fn create(&self) -> Result<MultiplexedConnection, crate::Error> {
        match tokio::time::timeout(self.timeout, self.client.get_multiplexed_tokio_connection())
            .await
        {
            Ok(conn) => conn.map_err(Into::into),
            Err(_) => Err(crate::Error::InternalError(
                "Redis connection timeout".into(),
            )),
        }
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<crate::Error> {
        conn.req_packed_command(&redis::cmd("PING"))
            .await
            .map(|_| ())
            .map_err(|err| managed::RecycleError::Backend(err.into()))
    }
}

impl managed::Manager for RedisClusterConnectionManager {
    type Type = ClusterConnection;
    type Error = crate::Error;

    async fn create(&self) -> Result<ClusterConnection, crate::Error> {
        match tokio::time::timeout(self.timeout, self.client.get_async_connection()).await {
            Ok(conn) => conn.map_err(Into::into),
            Err(_) => Err(crate::Error::InternalError(
                "Redis connection timeout".into(),
            )),
        }
    }

    async fn recycle(
        &self,
        conn: &mut ClusterConnection,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<crate::Error> {
        conn.req_packed_command(&redis::cmd("PING"))
            .await
            .map(|_| ())
            .map_err(|err| managed::RecycleError::Backend(err.into()))
    }
}
