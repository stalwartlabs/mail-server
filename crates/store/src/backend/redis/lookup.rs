/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use redis::AsyncCommands;

use crate::Deserialize;

use super::{RedisPool, RedisStore, into_error};

impl RedisStore {
    pub async fn key_set(&self, key: &[u8], value: &[u8], expires: Option<u64>) -> trc::Result<()> {
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

    pub async fn key_incr(&self, key: &[u8], value: i64, expires: Option<u64>) -> trc::Result<i64> {
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

    pub async fn key_delete(&self, key: &[u8]) -> trc::Result<()> {
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

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_delete_prefix_(pool.get().await.map_err(into_error)?.as_mut(), prefix)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_delete_prefix_(pool.get().await.map_err(into_error)?.as_mut(), prefix)
                    .await
            }
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: &[u8],
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

    pub async fn counter_get(&self, key: &[u8]) -> trc::Result<i64> {
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

    pub async fn key_exists(&self, key: &[u8]) -> trc::Result<bool> {
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
        key: &[u8],
    ) -> trc::Result<Option<T>> {
        if let Some(value) = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<Vec<u8>>>(conn)
            .await
            .map_err(into_error)?
        {
            T::deserialize_owned(value).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn counter_get_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<i64> {
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<i64>>(conn)
            .await
            .map(|x| x.unwrap_or(0))
            .map_err(into_error)
    }

    async fn key_exists_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<bool> {
        conn.exists(key).await.map_err(into_error)
    }

    async fn key_set_(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: &[u8],
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
        key: &[u8],
        value: i64,
        expires: Option<u64>,
    ) -> trc::Result<i64> {
        if let Some(expires) = expires {
            redis::pipe()
                .atomic()
                .incr(key, value)
                .expire(key, expires as i64)
                .ignore()
                .query_async::<Vec<i64>>(conn)
                .await
                .map_err(into_error)
                .map(|v| v.first().copied().unwrap_or(0))
        } else {
            conn.incr(key, value).await.map_err(into_error)
        }
    }

    async fn key_delete_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<()> {
        conn.del(key).await.map_err(into_error)
    }

    async fn key_delete_prefix_(
        &self,
        conn: &mut impl AsyncCommands,
        prefix: &[u8],
    ) -> trc::Result<()> {
        let mut pattern = Vec::with_capacity(prefix.len() + 1);
        pattern.extend_from_slice(prefix);
        pattern.push(b'*');

        let mut cursor = 0;
        loop {
            let (new_cursor, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .cursor_arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(conn)
                .await
                .map_err(into_error)?;

            if !keys.is_empty() {
                conn.del::<_, ()>(&keys).await.map_err(into_error)?;
            }

            if new_cursor != 0 {
                cursor = new_cursor;
            } else {
                return Ok(());
            }
        }
    }
}
