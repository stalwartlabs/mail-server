/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use redis::AsyncCommands;

use crate::Deserialize;

use super::{into_error, RedisPool, RedisStore};

impl RedisStore {
    pub async fn key_set(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        expires: Option<u64>,
    ) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.key_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
        }
    }

    pub async fn key_incr(
        &self,
        key: Vec<u8>,
        value: i64,
        expires: Option<u64>,
    ) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_incr_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.key_incr_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
        }
    }

    pub async fn key_delete(&self, key: Vec<u8>) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_delete_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_delete_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: Vec<u8>,
    ) -> trc::Result<Option<T>> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn counter_get(&self, key: Vec<u8>) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.counter_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.counter_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn key_exists(&self, key: Vec<u8>) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_exists_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_exists_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    async fn key_get_<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        conn: &mut impl AsyncCommands,
        key: Vec<u8>,
    ) -> trc::Result<Option<T>> {
        if let Some(value) = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<Vec<u8>>>(conn)
            .await
            .map_err(into_error)?
        {
            T::deserialize(&value).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn counter_get_(&self, conn: &mut impl AsyncCommands, key: Vec<u8>) -> trc::Result<i64> {
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<i64>>(conn)
            .await
            .map(|x| x.unwrap_or(0))
            .map_err(into_error)
    }

    async fn key_exists_(&self, conn: &mut impl AsyncCommands, key: Vec<u8>) -> trc::Result<bool> {
        conn.exists(key).await.map_err(into_error)
    }

    async fn key_set_(
        &self,
        conn: &mut impl AsyncCommands,
        key: Vec<u8>,
        value: Vec<u8>,
        expires: Option<u64>,
    ) -> trc::Result<()> {
        if let Some(expires) = expires {
            conn.set_ex(key, value, expires).await.map_err(into_error)
        } else {
            conn.set(key, value).await.map_err(into_error)
        }
    }

    async fn key_incr_(
        &self,
        conn: &mut impl AsyncCommands,
        key: Vec<u8>,
        value: i64,
        expires: Option<u64>,
    ) -> trc::Result<i64> {
        if let Some(expires) = expires {
            redis::pipe()
                .atomic()
                .incr(&key, value)
                .expire(&key, expires as i64)
                .ignore()
                .query_async::<Vec<i64>>(conn)
                .await
                .map_err(into_error)
                .map(|v| v.first().copied().unwrap_or(0))
        } else {
            conn.incr(&key, value).await.map_err(into_error)
        }
    }

    async fn key_delete_(&self, conn: &mut impl AsyncCommands, key: Vec<u8>) -> trc::Result<()> {
        conn.del(key).await.map_err(into_error)
    }
}
