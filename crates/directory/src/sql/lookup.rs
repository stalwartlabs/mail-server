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

use futures::TryStreamExt;
use mail_send::Credentials;
use sqlx::{any::AnyRow, Column, Row};

use crate::{to_catch_all_address, unwrap_subaddress, Directory, Principal, Type};

use super::{SqlDirectory, SqlMappings};

#[async_trait::async_trait]
impl Directory for SqlDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        let (username, secret) = match credentials {
            Credentials::Plain { username, secret } => (username, secret),
            Credentials::OAuthBearer { token } => (token, token),
            Credentials::XOauth2 { username, secret } => (username, secret),
        };

        match self.principal(username).await {
            Ok(Some(principal)) if principal.verify_secret(secret).await => Ok(Some(principal)),
            Ok(_) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn principal(&self, name: &str) -> crate::Result<Option<Principal>> {
        let result = sqlx::query(&self.mappings.query_name)
            .bind(name)
            .fetch(&self.pool)
            .try_next()
            .await?;
        if let Some(row) = result {
            // Map row to principal
            let mut principal = self.mappings.row_to_principal(row)?;

            // Obtain members
            principal.member_of = sqlx::query_scalar::<_, String>(&self.mappings.query_members)
                .bind(name)
                .fetch(&self.pool)
                .try_collect::<Vec<_>>()
                .await?;

            // Check whether the user is a superuser
            if let Some(idx) = principal
                .member_of
                .iter()
                .position(|group| group.eq_ignore_ascii_case(&self.opt.superuser_group))
            {
                principal.member_of.swap_remove(idx);
                principal.typ = Type::Superuser;
            }

            Ok(Some(principal))
        } else {
            Ok(None)
        }
    }

    async fn emails_by_name(&self, name: &str) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_emails)
            .bind(name)
            .fetch(&self.pool)
            .try_collect::<Vec<_>>()
            .await
            .map_err(Into::into)
    }

    async fn names_by_email(&self, address: &str) -> crate::Result<Vec<String>> {
        let result = sqlx::query_scalar::<_, String>(&self.mappings.query_recipients)
            .bind(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            .fetch(&self.pool)
            .try_collect::<Vec<_>>()
            .await;
        match result {
            Ok(ids) if !ids.is_empty() => Ok(ids),
            Ok(_) if self.opt.catch_all => {
                sqlx::query_scalar::<_, String>(&self.mappings.query_recipients)
                    .bind(to_catch_all_address(address))
                    .fetch(&self.pool)
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(Into::into)
            }
            Ok(_) => Ok(vec![]),
            Err(err) => Err(err.into()),
        }
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        let result = sqlx::query(&self.mappings.query_recipients)
            .bind(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            .fetch(&self.pool)
            .try_next()
            .await;
        match result {
            Ok(Some(_)) => Ok(true),
            Ok(None) if self.opt.catch_all => sqlx::query(&self.mappings.query_recipients)
                .bind(to_catch_all_address(address))
                .fetch(&self.pool)
                .try_next()
                .await
                .map(|id| id.is_some())
                .map_err(Into::into),
            Ok(None) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_verify)
            .bind(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            .fetch(&self.pool)
            .try_collect::<Vec<_>>()
            .await
            .map_err(Into::into)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        sqlx::query_scalar::<_, String>(&self.mappings.query_expand)
            .bind(unwrap_subaddress(address, self.opt.subaddressing).as_ref())
            .fetch(&self.pool)
            .try_collect::<Vec<_>>()
            .await
            .map_err(Into::into)
    }

    async fn query(&self, query: &str, params: &[&str]) -> crate::Result<bool> {
        tracing::trace!(context = "directory", event = "query", query = query, params = ?params);
        let mut q = sqlx::query(query);
        for param in params {
            q = q.bind(param);
        }

        q.fetch(&self.pool)
            .try_next()
            .await
            .map(|r| r.is_some())
            .map_err(Into::into)
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        sqlx::query(&self.mappings.query_domains)
            .bind(domain)
            .fetch(&self.pool)
            .try_next()
            .await
            .map(|id| id.is_some())
            .map_err(Into::into)
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, row: AnyRow) -> crate::Result<Principal> {
        let mut principal = Principal::default();
        for col in row.columns() {
            let idx = col.ordinal();
            let name = col.name();

            if name.eq_ignore_ascii_case(&self.column_name) {
                principal.name = row.try_get::<String, _>(idx)?;
            } else if name.eq_ignore_ascii_case(&self.column_secret) {
                if let Ok(secret) = row.try_get::<String, _>(idx) {
                    principal.secrets.push(secret);
                }
            } else if name.eq_ignore_ascii_case(&self.column_type) {
                match row.try_get::<String, _>(idx)?.as_str() {
                    "individual" | "person" | "user" => principal.typ = Type::Individual,
                    "group" => principal.typ = Type::Group,
                    _ => (),
                }
            } else if name.eq_ignore_ascii_case(&self.column_description) {
                principal.description = row.try_get::<String, _>(idx).ok();
            } else if name.eq_ignore_ascii_case(&self.column_quota) {
                principal.quota = row.try_get::<i64, _>(idx).unwrap_or_default() as u32;
            }
        }

        Ok(principal)
    }
}
