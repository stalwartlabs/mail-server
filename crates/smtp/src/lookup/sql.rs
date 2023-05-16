/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use super::{SqlDatabase, SqlQuery};

impl SqlQuery {
    pub async fn exists(&self, param: &str) -> Option<bool> {
        if let Some(result) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.lock().get(param))
        {
            return Some(result);
        }
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
            /*super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }*/
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
        };

        match result {
            Ok(result) => {
                if let Some(cache) = &self.cache {
                    if result {
                        cache.lock().insert_pos(param.to_string());
                    } else {
                        cache.lock().insert_neg(param.to_string());
                    }
                }
                Some(result)
            }
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_one(&self, param: &str) -> Option<Option<String>> {
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            /*super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }*/
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_many(&self, param: &str) -> Option<Vec<String>> {
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            /*super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }*/
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }
}

impl SqlDatabase {
    pub async fn exists(&self, query: &str, params: impl Iterator<Item = String>) -> Option<bool> {
        let result = match self {
            super::SqlDatabase::Postgres(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
            super::SqlDatabase::MySql(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
            /*super::SqlDatabase::MsSql(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }*/
            super::SqlDatabase::SqlLite(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                None
            }
        }
    }

    pub async fn execute(&self, query: &str, params: impl Iterator<Item = String>) -> bool {
        let result = match self {
            super::SqlDatabase::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            super::SqlDatabase::MySql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            /*super::SqlDatabase::MsSql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }*/
            super::SqlDatabase::SqlLite(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
        };

        match result {
            Ok(_) => true,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                false
            }
        }
    }
}
