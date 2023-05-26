/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use crate::JMAP;

use super::{AclToken, AuthDatabase, SqlDatabase};

impl JMAP {
    pub async fn authenticate(&self, account: &str, secret: &str) -> Option<u32> {
        let account_id = self.get_account_id(account).await?;
        let account_secret = self.get_account_secret(account_id).await?;
        if secret == account_secret {
            account_id.into()
        } else {
            tracing::debug!(context = "auth", event = "failed", account = account);
            None
        }
    }

    pub async fn authenticate_with_token(&self, account: &str, secret: &str) -> Option<AclToken> {
        self.get_acl_token(self.authenticate(account, secret).await?)
            .await
    }

    pub async fn get_acl_token(&self, account_id: u32) -> Option<AclToken> {
        self.update_acl_token(AclToken {
            primary_id: account_id,
            member_of: self.get_account_gids(account_id).await,
            access_to: Vec::new(),
        })
        .await
    }

    pub async fn get_account_secret(&self, account_id: u32) -> Option<String> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_secret_by_uid,
                ..
            } => {
                db.fetch_uid_to_string(query_secret_by_uid, account_id as i64)
                    .await
            }
            AuthDatabase::Ldap => None,
        }
    }

    pub async fn get_account_name(&self, account_id: u32) -> Option<String> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_name_by_uid,
                ..
            } => {
                db.fetch_uid_to_string(query_name_by_uid, account_id as i64)
                    .await
            }
            AuthDatabase::Ldap => None,
        }
    }

    pub async fn get_account_id(&self, account: &str) -> Option<u32> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_uid_by_login,
                ..
            } => db
                .fetch_string_to_id(query_uid_by_login, account)
                .await
                .map(|id| id as u32),
            AuthDatabase::Ldap => None,
        }
    }

    pub async fn get_account_gids(&self, account_id: u32) -> Vec<u32> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_gids_by_uid,
                ..
            } => db
                .fetch_uid_to_uids(query_gids_by_uid, account_id as i64)
                .await
                .into_iter()
                .map(|id| id as u32)
                .collect(),
            AuthDatabase::Ldap => vec![],
        }
    }

    pub async fn get_account_login(&self, account_id: u32) -> Option<String> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_login_by_uid,
                ..
            } => {
                db.fetch_uid_to_string(query_login_by_uid, account_id as i64)
                    .await
            }
            AuthDatabase::Ldap => None,
        }
    }

    pub async fn get_uids_by_address(&self, address: &str) -> Vec<u32> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_uids_by_address,
                ..
            } => db
                .fetch_string_to_uids(query_uids_by_address, address)
                .await
                .into_iter()
                .map(|id| id as u32)
                .collect(),
            AuthDatabase::Ldap => vec![],
        }
    }

    pub async fn get_addresses_by_uid(&self, account_id: u32) -> Vec<String> {
        match &self.auth_db {
            AuthDatabase::Sql {
                db,
                query_addresses_by_uid,
                ..
            } => {
                db.fetch_uid_to_strings(query_addresses_by_uid, account_id as i64)
                    .await
            }
            AuthDatabase::Ldap => vec![],
        }
    }

    pub async fn vrfy_address(&self, address: &str) -> Vec<String> {
        match &self.auth_db {
            AuthDatabase::Sql { db, query_vrfy, .. } => {
                db.fetch_string_to_strings(query_vrfy, address).await
            }
            AuthDatabase::Ldap => vec![],
        }
    }

    pub async fn expn_address(&self, address: &str) -> Vec<String> {
        match &self.auth_db {
            AuthDatabase::Sql { db, query_expn, .. } => {
                db.fetch_string_to_strings(query_expn, address).await
            }
            AuthDatabase::Ldap => vec![],
        }
    }
}

// TODO abstract this
impl SqlDatabase {
    pub async fn fetch_uid_to_string(&self, query: &str, uid: i64) -> Option<String> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_optional(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_optional(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_optional(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_optional(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_string_to_id(&self, query: &str, param: &str) -> Option<i64> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_uid_to_strings(&self, query: &str, uid: i64) -> Vec<String> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                vec![]
            }
        }
    }

    pub async fn fetch_uid_to_uids(&self, query: &str, uid: i64) -> Vec<i64> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(uid)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                vec![]
            }
        }
    }

    pub async fn fetch_string_to_uids(&self, query: &str, param: &str) -> Vec<i64> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, i64>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                vec![]
            }
        }
    }

    pub async fn fetch_string_to_strings(&self, query: &str, param: &str) -> Vec<String> {
        let result = match &self {
            SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            /*SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }*/
            SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                vec![]
            }
        }
    }

    pub async fn execute(&self, query: &str, params: impl Iterator<Item = String>) -> bool {
        let result = match self {
            SqlDatabase::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            SqlDatabase::MySql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            /*SqlDatabase::MsSql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }*/
            SqlDatabase::SqlLite(pool) => {
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

#[cfg(feature = "test_mode")]
impl AuthDatabase {
    pub async fn execute(&self, query: &str, params: impl Iterator<Item = String>) -> bool {
        match self {
            AuthDatabase::Sql { db, .. } => db.execute(query, params).await,
            AuthDatabase::Ldap => unimplemented!(),
        }
    }
}
