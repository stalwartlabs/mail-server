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

use super::{into_error, RedisClusterConnectionManager, RedisConnectionManager};

impl managed::Manager for RedisConnectionManager {
    type Type = MultiplexedConnection;
    type Error = trc::Error;

    async fn create(&self) -> Result<MultiplexedConnection, trc::Error> {
        match tokio::time::timeout(self.timeout, self.client.get_multiplexed_tokio_connection())
            .await
        {
            Ok(conn) => conn.map_err(into_error),
            Err(_) => Err(trc::StoreCause::Redis.ctx(trc::Key::Details, "Connection Timeout")),
        }
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<trc::Error> {
        conn.req_packed_command(&redis::cmd("PING"))
            .await
            .map(|_| ())
            .map_err(|err| managed::RecycleError::Backend(into_error(err)))
    }
}

impl managed::Manager for RedisClusterConnectionManager {
    type Type = ClusterConnection;
    type Error = trc::Error;

    async fn create(&self) -> Result<ClusterConnection, trc::Error> {
        match tokio::time::timeout(self.timeout, self.client.get_async_connection()).await {
            Ok(conn) => conn.map_err(into_error),
            Err(_) => Err(trc::StoreCause::Redis.ctx(trc::Key::Details, "Connection Timeout")),
        }
    }

    async fn recycle(
        &self,
        conn: &mut ClusterConnection,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<trc::Error> {
        conn.req_packed_command(&redis::cmd("PING"))
            .await
            .map(|_| ())
            .map_err(|err| managed::RecycleError::Backend(into_error(err)))
    }
}
