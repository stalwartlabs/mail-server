/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;
use store::{NamedRows, Rows, Value};
use trc::AddContext;

use crate::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, ManageDirectory, UpdatePrincipal},
        PrincipalField, PrincipalValue,
    },
    Principal, QueryBy, Type, ROLE_ADMIN, ROLE_USER,
};

use super::{SqlDirectory, SqlMappings};

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
                        self.store
                            .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                            .await
                            .caused_by(trc::location!())?,
                    )
                    .caused_by(trc::location!())?
                    .map(|p| p.with_field(PrincipalField::Name, username.to_string())),
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
                                self.store
                                    .query::<NamedRows>(
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
                        self.store
                            .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                            .await
                            .caused_by(trc::location!())?,
                    )
                    .caused_by(trc::location!())?
                {
                    Some(principal)
                        if principal
                            .verify_secret(secret)
                            .await
                            .caused_by(trc::location!())? =>
                    {
                        (
                            Some(principal.with_field(PrincipalField::Name, username.to_string())),
                            None,
                        )
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
            for row in self
                .store
                .query::<Rows>(
                    &self.mappings.query_members,
                    vec![external_principal.name().into()],
                )
                .await
                .caused_by(trc::location!())?
                .rows
            {
                if let Some(Value::Text(account_id)) = row.values.first() {
                    external_principal.append_int(
                        PrincipalField::MemberOf,
                        self.data_store
                            .get_or_create_principal_id(account_id, Type::Group)
                            .await
                            .caused_by(trc::location!())?,
                    );
                }
            }
        }

        // Obtain emails
        if !self.mappings.query_emails.is_empty() {
            external_principal.set(
                PrincipalField::Emails,
                PrincipalValue::StringList(
                    self.store
                        .query::<Rows>(
                            &self.mappings.query_emails,
                            vec![external_principal.name().into()],
                        )
                        .await
                        .caused_by(trc::location!())?
                        .into(),
                ),
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

    pub async fn email_to_ids(&self, address: &str) -> trc::Result<Vec<u32>> {
        let names = self
            .store
            .query::<Rows>(&self.mappings.query_recipients, vec![address.into()])
            .await
            .caused_by(trc::location!())?;

        let mut ids = Vec::with_capacity(names.rows.len());

        for row in names.rows {
            if let Some(Value::Text(name)) = row.values.first() {
                ids.push(
                    self.data_store
                        .get_or_create_principal_id(name, Type::Individual)
                        .await
                        .caused_by(trc::location!())?,
                );
            }
        }

        Ok(ids)
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<bool> {
        self.store
            .query::<bool>(
                &self.mappings.query_recipients,
                vec![address.to_string().into()],
            )
            .await
            .map_err(Into::into)
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_verify,
                vec![address.to_string().into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_expand,
                vec![address.to_string().into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.store
            .query::<bool>(&self.mappings.query_domains, vec![domain.into()])
            .await
            .map_err(Into::into)
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, rows: NamedRows) -> trc::Result<Option<Principal>> {
        if rows.rows.is_empty() {
            return Ok(None);
        }

        let mut principal = Principal::default();
        let mut role = ROLE_USER;

        if let Some(row) = rows.rows.into_iter().next() {
            for (name, value) in rows.names.into_iter().zip(row.values) {
                if self
                    .column_secret
                    .iter()
                    .any(|c| name.eq_ignore_ascii_case(c))
                {
                    if let Value::Text(secret) = value {
                        principal.append_str(PrincipalField::Secrets, secret.into_owned());
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
                        principal.set(PrincipalField::Description, text.into_owned());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_quota) {
                    if let Value::Integer(quota) = value {
                        principal.set(PrincipalField::Quota, quota as u64);
                    }
                }
            }
        }

        Ok(Some(principal.with_field(PrincipalField::Roles, role)))
    }
}
