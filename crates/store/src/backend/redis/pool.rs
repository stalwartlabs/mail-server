/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
