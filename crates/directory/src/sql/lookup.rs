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
use store::{NamedRows, Rows, Value};

use crate::{Directory, Principal, Type};

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
        let result = self
            .store
            .query::<NamedRows>(&self.mappings.query_name, vec![name.into()])
            .await?;
        if !result.rows.is_empty() {
            // Map row to principal
            let mut principal = self.mappings.row_to_principal(result)?;

            // Obtain members
            principal.member_of = self
                .store
                .query::<Rows>(&self.mappings.query_members, vec![name.into()])
                .await?
                .into();

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
        self.store
            .query::<Rows>(&self.mappings.query_emails, vec![name.into()])
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn names_by_email(&self, address: &str) -> crate::Result<Vec<String>> {
        let ids = self
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

        if !ids.rows.is_empty() {
            Ok(ids.into())
        } else if let Some(address) = self.opt.catch_all.to_catch_all(address) {
            self.store
                .query::<Rows>(&self.mappings.query_recipients, vec![address.into()])
                .await
                .map(Into::into)
                .map_err(Into::into)
        } else {
            Ok(vec![])
        }
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
                if name.eq_ignore_ascii_case(&self.column_name) {
                    principal.name = value.into_string();
                } else if name.eq_ignore_ascii_case(&self.column_secret) {
                    if let Value::Text(secret) = value {
                        principal.secrets.push(secret.into_owned());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_type) {
                    match value.to_str().as_ref() {
                        "individual" | "person" | "user" => principal.typ = Type::Individual,
                        "group" => principal.typ = Type::Group,
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
