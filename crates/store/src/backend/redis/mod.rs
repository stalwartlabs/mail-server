/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, time::Duration};

use deadpool::{
    managed::{Manager, Pool},
    Runtime,
};
use redis::{
    cluster::{ClusterClient, ClusterClientBuilder},
    Client,
};
use utils::config::{utils::AsKey, Config};

pub mod lookup;
pub mod pool;

#[derive(Debug)]
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
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let urls = config
            .values((&prefix, "urls"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();
        if urls.is_empty() {
            config.new_build_error((&prefix, "urls"), "No Redis URLs specified");
            return None;
        }

        Some(
            match config.value((&prefix, "redis-type")).unwrap_or("single") {
                "single" => {
                    let client = Client::open(urls.into_iter().next().unwrap())
                        .map_err(|err| {
                            config.new_build_error(
                                prefix.as_str(),
                                format!("Failed to open Redis client: {err:?}"),
                            )
                        })
                        .ok()?;
                    let timeout = config
                        .property_or_default((&prefix, "timeout"), "10s")
                        .unwrap_or_default();

                    Self {
                        pool: RedisPool::Single(
                            build_pool(config, &prefix, RedisConnectionManager { client, timeout })
                                .map_err(|err| {
                                    config.new_build_error(
                                        prefix.as_str(),
                                        format!("Failed to build Redis pool: {err:?}"),
                                    )
                                })
                                .ok()?,
                        ),
                    }
                }
                "cluster" => {
                    let mut builder = ClusterClientBuilder::new(urls.into_iter());
                    if let Some(value) = config.property((&prefix, "user")) {
                        builder = builder.username(value);
                    }
                    if let Some(value) = config.property((&prefix, "password")) {
                        builder = builder.password(value);
                    }
                    if let Some(value) = config.property((&prefix, "retry.total")) {
                        builder = builder.retries(value);
                    }
                    if let Some(value) = config
                        .property::<Option<Duration>>((&prefix, "retry.max-wait"))
                        .unwrap_or_default()
                    {
                        builder = builder.max_retry_wait(value.as_millis() as u64);
                    }
                    if let Some(value) = config
                        .property::<Option<Duration>>((&prefix, "retry.min-wait"))
                        .unwrap_or_default()
                    {
                        builder = builder.min_retry_wait(value.as_millis() as u64);
                    }
                    if let Some(true) = config.property::<bool>((&prefix, "read-from-replicas")) {
                        builder = builder.read_from_replicas();
                    }

                    let client = builder
                        .build()
                        .map_err(|err| {
                            config.new_build_error(
                                prefix.as_str(),
                                format!("Failed to open Redis client: {err:?}"),
                            )
                        })
                        .ok()?;
                    let timeout = config
                        .property_or_default::<Duration>((&prefix, "timeout"), "10s")
                        .unwrap_or_else(|| Duration::from_secs(10));

                    Self {
                        pool: RedisPool::Cluster(
                            build_pool(
                                config,
                                &prefix,
                                RedisClusterConnectionManager { client, timeout },
                            )
                            .map_err(|err| {
                                config.new_build_error(
                                    prefix.as_str(),
                                    format!("Failed to build Redis pool: {err:?}"),
                                )
                            })
                            .ok()?,
                        ),
                    }
                }
                invalid => {
                    let err = format!("Invalid Redis type {invalid:?}");
                    config.new_parse_error((&prefix, "redis-type"), err);
                    return None;
                }
            },
        )
    }
}

fn build_pool<M: Manager>(
    config: &mut Config,
    prefix: &str,
    manager: M,
) -> Result<Pool<M>, String> {
    Pool::builder(manager)
        .runtime(Runtime::Tokio1)
        .max_size(
            config
                .property_or_default((prefix, "pool.max-connections"), "10")
                .unwrap_or(10),
        )
        .create_timeout(
            config
                .property_or_default::<Option<Duration>>((prefix, "pool.create-timeout"), "30s")
                .unwrap_or_default(),
        )
        .wait_timeout(
            config
                .property_or_default::<Option<Duration>>((prefix, "pool.wait-timeout"), "30s")
                .unwrap_or_default(),
        )
        .recycle_timeout(
            config
                .property_or_default::<Option<Duration>>((prefix, "pool.recycle-timeout"), "30s")
                .unwrap_or_default(),
        )
        .build()
        .map_err(|err| {
            format!(
                "Failed to build pool for {prefix:?}: {err}",
                prefix = prefix,
                err = err
            )
        })
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::RedisError.reason(err)
}

impl std::fmt::Debug for RedisPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(_) => f.debug_tuple("Single").finish(),
            Self::Cluster(_) => f.debug_tuple("Cluster").finish(),
        }
    }
}
