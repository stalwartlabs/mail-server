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

use redis::AsyncCommands;

use crate::{Deserialize, LookupKey, LookupValue};

use super::{RedisPool, RedisStore};

impl RedisStore {
    pub async fn key_set(&self, key: Vec<u8>, value: LookupValue<Vec<u8>>) -> crate::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => self.key_set_(pool.get().await?.as_mut(), key, value).await,
            RedisPool::Cluster(pool) => self.key_set_(pool.get().await?.as_mut(), key, value).await,
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: LookupKey,
    ) -> crate::Result<LookupValue<T>> {
        match &self.pool {
            RedisPool::Single(pool) => self.key_get_(pool.get().await?.as_mut(), key).await,
            RedisPool::Cluster(pool) => self.key_get_(pool.get().await?.as_mut(), key).await,
        }
    }

    async fn key_get_<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        conn: &mut impl AsyncCommands,
        key: LookupKey,
    ) -> crate::Result<LookupValue<T>> {
        match key {
            LookupKey::Key(key) => {
                if let Some(value) = conn.get::<_, Option<Vec<u8>>>(key).await? {
                    T::deserialize(&value).map(|value| LookupValue::Value { value, expires: 0 })
                } else {
                    Ok(LookupValue::None)
                }
            }
            LookupKey::Counter(key) => {
                let value: Option<i64> = conn.get(key).await?;
                Ok(LookupValue::Counter {
                    num: value.unwrap_or(0),
                })
            }
        }
    }

    async fn key_set_(
        &self,
        conn: &mut impl AsyncCommands,
        key: Vec<u8>,
        value: LookupValue<Vec<u8>>,
    ) -> crate::Result<()> {
        match value {
            LookupValue::Value { value, expires } => {
                if expires > 0 {
                    conn.set_ex(key, value, expires).await?;
                } else {
                    conn.set(key, value).await?;
                }
            }
            LookupValue::Counter { num } => conn.incr(key, num).await?,
            LookupValue::None => (),
        }

        Ok(())
    }
}
