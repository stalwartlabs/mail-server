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

use std::time::Duration;

use deadpool::{
    managed::{Manager, Pool, PoolError},
    Runtime,
};
use redis::{
    cluster::{ClusterClient, ClusterClientBuilder},
    Client, RedisError,
};
use utils::config::{utils::AsKey, Config};

pub mod lookup;
pub mod pool;

pub struct RedisStore {
    pool: RedisPool,
}

struct RedisConnectionManager {
    client: Client,
    timeout: Duration,
}

struct RedisClusterConnectionManager {
    client: ClusterClient,
    timeout: Duration,
}

enum RedisPool {
    Single(Pool<RedisConnectionManager>),
    Cluster(Pool<RedisClusterConnectionManager>),
}

impl RedisStore {
    pub async fn open(config: &Config, prefix: impl AsKey) -> crate::Result<Self> {
        let prefix = prefix.as_key();

        let db = if let Some(url) = config.value((&prefix, "url")) {
            Self {
                pool: RedisPool::Single(build_pool(
                    config,
                    &prefix,
                    RedisConnectionManager {
                        client: Client::open(url)?,
                        timeout: config.property_or_static((&prefix, "timeout"), "10s")?,
                    },
                )?),
            }
        } else {
            let addresses = config
                .values((&prefix, "urls"))
                .map(|(_, v)| v.to_string())
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(crate::Error::InternalError(format!(
                    "No Redis cluster URLs specified for {prefix:?}"
                )));
            }
            let mut builder = ClusterClientBuilder::new(addresses.into_iter());
            if let Some(value) = config.property((&prefix, "username"))? {
                builder = builder.username(value);
            }
            if let Some(value) = config.property((&prefix, "password"))? {
                builder = builder.password(value);
            }
            if let Some(value) = config.property((&prefix, "retries"))? {
                builder = builder.retries(value);
            }
            if let Some(value) = config.property::<Duration>((&prefix, "max-retry-wait"))? {
                builder = builder.max_retry_wait(value.as_secs());
            }
            if let Some(value) = config.property::<Duration>((&prefix, "min-retry-wait"))? {
                builder = builder.min_retry_wait(value.as_secs());
            }
            if let Some(true) = config.property::<bool>((&prefix, "read-from-replicas"))? {
                builder = builder.read_from_replicas();
            }
            Self {
                pool: RedisPool::Cluster(build_pool(
                    config,
                    &prefix,
                    RedisClusterConnectionManager {
                        client: builder.build()?,
                        timeout: config.property_or_static((&prefix, "timeout"), "10s")?,
                    },
                )?),
            }
        };

        Ok(db)
    }
}

fn build_pool<M: Manager>(
    config: &Config,
    prefix: &str,
    manager: M,
) -> utils::config::Result<Pool<M>> {
    Pool::builder(manager)
        .runtime(Runtime::Tokio1)
        .max_size(config.property_or_static((prefix, "pool.max-connections"), "10")?)
        .create_timeout(
            config
                .property_or_static::<Duration>((prefix, "pool.create-timeout"), "30s")?
                .into(),
        )
        .wait_timeout(config.property_or_static((prefix, "pool.wait-timeout"), "30s")?)
        .recycle_timeout(config.property_or_static((prefix, "pool.recycle-timeout"), "30s")?)
        .build()
        .map_err(|err| {
            format!(
                "Failed to build pool for {prefix:?}: {err}",
                prefix = prefix,
                err = err
            )
        })
}

impl From<PoolError<RedisError>> for crate::Error {
    fn from(value: PoolError<RedisError>) -> Self {
        crate::Error::InternalError(format!("Redis pool error: {}", value))
    }
}

impl From<PoolError<crate::Error>> for crate::Error {
    fn from(value: PoolError<crate::Error>) -> Self {
        crate::Error::InternalError(format!("Connection pool {}", value))
    }
}

impl From<RedisError> for crate::Error {
    fn from(value: RedisError) -> Self {
        crate::Error::InternalError(format!("Redis error: {}", value))
    }
}
