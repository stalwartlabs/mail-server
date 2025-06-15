/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqlDirectory, SqlMappings};
use crate::{
    Principal, PrincipalData, QueryBy, ROLE_ADMIN, ROLE_USER, Type,
    backend::{
        RcptType,
        internal::{
            lookup::DirectoryStore,
            manage::{self, ManageDirectory, UpdatePrincipal},
        },
    },
};

use mail_send::Credentials;
use store::{NamedRows, Rows, Value};
use trc::AddContext;

impl SqlDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        let (external_principal, stored_principal) = match by {
            QueryBy::Name(username) => (
                self.mappings
                    .row_to_principal(
                        self.sql_store
                            .sql_query::<NamedRows>(
                                &self.mappings.query_name,
                                vec![username.into()],
                            )
                            .await
                            .caused_by(trc::location!())?,
                    )
                    .caused_by(trc::location!())?
                    .map(|mut p| {
                        p.name = username.into();
                        p
                    }),
                None,
            ),
            QueryBy::Id(uid) => {
                if let Some(principal) = self
                    .data_store
                    .query(QueryBy::Id(uid), return_member_of)
                    .await
                    .caused_by(trc::location!())?
                {
                    (
                        self.mappings
                            .row_to_principal(
                                self.sql_store
                                    .sql_query::<NamedRows>(
                                        &self.mappings.query_name,
                                        vec![principal.name().into()],
                                    )
                                    .await
                                    .caused_by(trc::location!())?,
                            )
                            .caused_by(trc::location!())?,
                        Some(principal),
                    )
                } else {
                    return Ok(None);
                }
            }
            QueryBy::Credentials(credentials) => {
                let (username, secret) = match credentials {
                    Credentials::Plain { username, secret } => (username, secret),
                    Credentials::OAuthBearer { token } => (token, token),
                    Credentials::XOauth2 { username, secret } => (username, secret),
                };

                match self
                    .mappings
                    .row_to_principal(
                        self.sql_store
                            .sql_query::<NamedRows>(
                                &self.mappings.query_name,
                                vec![username.into()],
                            )
                            .await
                            .caused_by(trc::location!())?,
                    )
                    .caused_by(trc::location!())?
                {
                    Some(mut principal) => {
                        // Obtain secrets
                        if !self.mappings.query_secrets.is_empty() {
                            let secrets = self
                                .sql_store
                                .sql_query::<Rows>(
                                    &self.mappings.query_secrets,
                                    vec![username.into()],
                                )
                                .await
                                .caused_by(trc::location!())?;

                            if !secrets.rows.is_empty() {
                                principal.secrets = secrets.into();
                            }
                        }

                        if principal
                            .verify_secret(secret)
                            .await
                            .caused_by(trc::location!())?
                        {
                            principal.name = username.into();
                            (Some(principal), None)
                        } else {
                            (None, None)
                        }
                    }

                    _ => (None, None),
                }
            }
        };

        let mut external_principal = if let Some(external_principal) = external_principal {
            external_principal
        } else {
            return Ok(None);
        };

        // Obtain members
        if return_member_of && !self.mappings.query_members.is_empty() {
            let mut data = Vec::new();
            for row in self
                .sql_store
                .sql_query::<Rows>(
                    &self.mappings.query_members,
                    vec![external_principal.name().into()],
                )
                .await
                .caused_by(trc::location!())?
                .rows
            {
                if let Some(Value::Text(account_id)) = row.values.first() {
                    data.push(
                        self.data_store
                            .get_or_create_principal_id(account_id, Type::Group)
                            .await
                            .caused_by(trc::location!())?,
                    );
                }
            }
            if !data.is_empty() {
                external_principal.data.push(PrincipalData::MemberOf(data));
            }
        }

        // Obtain emails
        if !self.mappings.query_emails.is_empty() {
            let rows = self
                .sql_store
                .sql_query::<Rows>(
                    &self.mappings.query_emails,
                    vec![external_principal.name().into()],
                )
                .await
                .caused_by(trc::location!())?;
            external_principal.emails.extend(
                rows.rows
                    .into_iter()
                    .flat_map(|v| v.values.into_iter().map(|v| v.into_lower_string())),
            );
        }

        // Obtain account ID if not available
        let mut principal = if let Some(stored_principal) = stored_principal {
            stored_principal
        } else {
            let id = self
                .data_store
                .get_or_create_principal_id(external_principal.name(), Type::Individual)
                .await
                .caused_by(trc::location!())?;

            self.data_store
                .query(QueryBy::Id(id), return_member_of)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| manage::not_found(id).caused_by(trc::location!()))?
        };

        // Keep the internal store up to date with the SQL server
        let changes = principal.update_external(external_principal);
        if !changes.is_empty() {
            self.data_store
                .update_principal(
                    UpdatePrincipal::by_id(principal.id)
                        .with_updates(changes)
                        .create_domains(),
                )
                .await
                .caused_by(trc::location!())?;
        }

        Ok(Some(principal))
    }

    pub async fn email_to_id(&self, address: &str) -> trc::Result<Option<u32>> {
        let names = self
            .sql_store
            .sql_query::<Rows>(&self.mappings.query_recipients, vec![address.into()])
            .await
            .caused_by(trc::location!())?;

        for row in names.rows {
            if let Some(Value::Text(name)) = row.values.first() {
                return self
                    .data_store
                    .get_or_create_principal_id(name, Type::Individual)
                    .await
                    .caused_by(trc::location!())
                    .map(Some);
            }
        }

        Ok(None)
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<RcptType> {
        let result = self
            .sql_store
            .sql_query::<bool>(
                &self.mappings.query_recipients,
                vec![address.to_string().into()],
            )
            .await?;

        if result {
            Ok(RcptType::Mailbox)
        } else {
            self.data_store.rcpt(address).await.map(|result| {
                if matches!(result, RcptType::List(_)) {
                    result
                } else {
                    RcptType::Invalid
                }
            })
        }
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.vrfy(address).await
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.data_store.expn(address).await
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.data_store.is_local_domain(domain).await
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, rows: NamedRows) -> trc::Result<Option<Principal>> {
        if rows.rows.is_empty() {
            return Ok(None);
        }

        let mut principal = Principal::new(u32::MAX, Type::Individual);
        let mut role = ROLE_USER;

        if let Some(row) = rows.rows.into_iter().next() {
            for (name, value) in rows.names.into_iter().zip(row.values) {
                if name.eq_ignore_ascii_case(&self.column_secret) {
                    if let Value::Text(text) = value {
                        principal.secrets.push(text.as_ref().into());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_type) {
                    match value.to_str().as_ref() {
                        "individual" | "person" | "user" => {
                            principal.typ = Type::Individual;
                        }
                        "group" => principal.typ = Type::Group,
                        "admin" | "superuser" | "administrator" => {
                            principal.typ = Type::Individual;
                            role = ROLE_ADMIN;
                        }
                        _ => (),
                    }
                } else if name.eq_ignore_ascii_case(&self.column_description) {
                    if let Value::Text(text) = value {
                        principal.description = Some(text.as_ref().into());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_email) {
                    if let Value::Text(text) = value {
                        principal.emails.push(text.to_lowercase());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_quota) {
                    if let Value::Integer(quota) = value {
                        principal.quota = (quota as u64).into();
                    }
                }
            }
        }

        principal.data.push(PrincipalData::Roles(vec![role]));

        Ok(Some(principal))
    }
}
