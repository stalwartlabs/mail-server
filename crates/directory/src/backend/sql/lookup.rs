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

use mail_send::Credentials;
use store::{NamedRows, Rows, Store, Value};

use crate::{
    backend::internal::manage::ManageDirectory, Directory, Principal, QueryBy, QueryType, Type,
};

use super::{SqlDirectory, SqlMappings};

#[async_trait::async_trait]
impl Directory for SqlDirectory {
    async fn query(&self, by: QueryBy<'_>) -> crate::Result<Option<Principal>> {
        let mut account_id = None;
        let account_name;
        let mut secret = None;

        let result = match by.t {
            QueryType::Name(username) => {
                account_name = username.to_string();

                self.store
                    .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                    .await?
            }
            QueryType::Id(uid) => {
                if let Some(username) = by.account_name(uid).await? {
                    account_name = username;
                } else {
                    return Ok(None);
                }
                account_id = Some(uid);

                self.store
                    .query::<NamedRows>(
                        &self.mappings.query_name,
                        vec![account_name.clone().into()],
                    )
                    .await?
            }
            QueryType::Credentials(credentials) => {
                let (username, secret_) = match credentials {
                    Credentials::Plain { username, secret } => (username, secret),
                    Credentials::OAuthBearer { token } => (token, token),
                    Credentials::XOauth2 { username, secret } => (username, secret),
                };
                account_name = username.to_string();
                secret = secret_.into();

                self.store
                    .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                    .await?
            }
        };

        if result.rows.is_empty() {
            return Ok(None);
        }

        // Map row to principal
        let mut principal = self.mappings.row_to_principal(result)?;

        // Validate password
        if let Some(secret) = secret {
            if !principal.verify_secret(secret).await {
                tracing::debug!(
                    context = "directory",
                    event = "invalid_password",
                    protocol = "sql",
                    account = account_name,
                    "Invalid password for account"
                );
                return Ok(None);
            }
        }

        // Obtain account ID if not available
        if let Some(account_id) = account_id {
            principal.id = account_id;
        } else if by.has_store() {
            principal.id = by.account_id(&account_name).await?;
        }
        principal.name = account_name;

        if by.has_store() {
            // Obtain members
            if !self.mappings.query_members.is_empty() {
                for row in self
                    .store
                    .query::<Rows>(
                        &self.mappings.query_members,
                        vec![principal.name.clone().into()],
                    )
                    .await?
                    .rows
                {
                    if let Some(Value::Text(account_id)) = row.values.first() {
                        principal.member_of.push(by.account_id(account_id).await?);
                    }
                }
            }

            // Obtain emails
            if !self.mappings.query_emails.is_empty() {
                principal.emails = self
                    .store
                    .query::<Rows>(
                        &self.mappings.query_emails,
                        vec![principal.name.clone().into()],
                    )
                    .await?
                    .into();
            }
        }

        Ok(Some(principal))
    }

    async fn email_to_ids(&self, address: &str, store: &Store) -> crate::Result<Vec<u32>> {
        let mut names = self
            .store
            .query::<Rows>(
                &self.mappings.query_recipients,
                vec![self
                    .opt
                    .subaddressing
                    .to_subaddress(address)
                    .into_owned()
                    .into()],
            )
            .await?;

        if names.rows.is_empty() {
            if let Some(address) = self.opt.catch_all.to_catch_all(address) {
                names = self
                    .store
                    .query::<Rows>(&self.mappings.query_recipients, vec![address.into()])
                    .await?;
            } else {
                return Ok(vec![]);
            }
        }

        let mut ids = Vec::with_capacity(names.rows.len());

        for row in names.rows {
            if let Some(Value::Text(name)) = row.values.first() {
                ids.push(store.get_or_create_account_id(name).await?);
            }
        }

        Ok(ids)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        if self
            .store
            .query::<bool>(
                &self.mappings.query_recipients,
                vec![self
                    .opt
                    .subaddressing
                    .to_subaddress(address)
                    .into_owned()
                    .into()],
            )
            .await?
        {
            Ok(true)
        } else if let Some(address) = self.opt.catch_all.to_catch_all(address) {
            self.store
                .query::<bool>(
                    &self.mappings.query_recipients,
                    vec![address.into_owned().into()],
                )
                .await
                .map_err(Into::into)
        } else {
            Ok(false)
        }
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_verify,
                vec![self
                    .opt
                    .subaddressing
                    .to_subaddress(address)
                    .into_owned()
                    .into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_expand,
                vec![self
                    .opt
                    .subaddressing
                    .to_subaddress(address)
                    .into_owned()
                    .into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        self.store
            .query::<bool>(&self.mappings.query_domains, vec![domain.into()])
            .await
            .map_err(Into::into)
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, rows: NamedRows) -> crate::Result<Principal> {
        let mut principal = Principal::default();

        if let Some(row) = rows.rows.into_iter().next() {
            for (name, value) in rows.names.into_iter().zip(row.values) {
                if name.eq_ignore_ascii_case(&self.column_secret) {
                    if let Value::Text(secret) = value {
                        principal.secrets.push(secret.into_owned());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_type) {
                    match value.to_str().as_ref() {
                        "individual" | "person" | "user" => principal.typ = Type::Individual,
                        "group" => principal.typ = Type::Group,
                        "admin" | "superuser" | "administrator" => principal.typ = Type::Superuser,
                        _ => (),
                    }
                } else if name.eq_ignore_ascii_case(&self.column_description) {
                    if let Value::Text(text) = value {
                        principal.description = text.into_owned().into();
                    }
                } else if name.eq_ignore_ascii_case(&self.column_quota) {
                    if let Value::Integer(quota) = value {
                        principal.quota = quota as u32;
                    }
                }
            }
        }

        Ok(principal)
    }
}
