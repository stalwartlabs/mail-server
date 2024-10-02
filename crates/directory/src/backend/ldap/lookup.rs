/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use mail_send::Credentials;
use trc::AddContext;

use crate::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, ManageDirectory, UpdatePrincipal},
        PrincipalField,
    },
    IntoError, Principal, QueryBy, Type, ROLE_ADMIN, ROLE_USER,
};

use super::{LdapDirectory, LdapMappings};

impl LdapDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        let mut conn = self.pool.get().await.map_err(|err| err.into_error())?;

        let (mut external_principal, stored_principal) = match by {
            QueryBy::Name(username) => {
                if let Some(principal) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(username))
                    .await?
                {
                    (
                        principal.with_field(PrincipalField::Name, username.to_string()),
                        None,
                    )
                } else {
                    return Ok(None);
                }
            }
            QueryBy::Id(uid) => {
                if let Some(stored_principal_) = self
                    .data_store
                    .query(QueryBy::Id(uid), return_member_of)
                    .await?
                {
                    if let Some(principal) = self
                        .find_principal(
                            &mut conn,
                            &self.mappings.filter_name.build(stored_principal_.name()),
                        )
                        .await?
                    {
                        (principal, Some(stored_principal_))
                    } else {
                        return Ok(None);
                    }
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

                if let Some(auth_bind) = &self.auth_bind {
                    let (conn, mut ldap) = LdapConnAsync::with_settings(
                        self.pool.manager().settings.clone(),
                        &self.pool.manager().address,
                    )
                    .await
                    .map_err(|err| err.into_error().caused_by(trc::location!()))?;

                    ldap3::drive!(conn);

                    let dn = auth_bind.build(username);

                    trc::event!(Store(trc::StoreEvent::LdapBind), Details = dn.clone());

                    if ldap
                        .simple_bind(&dn, secret)
                        .await
                        .map_err(|err| err.into_error().caused_by(trc::location!()))?
                        .success()
                        .is_err()
                    {
                        return Ok(None);
                    }

                    match self
                        .find_principal(&mut ldap, &self.mappings.filter_name.build(username))
                        .await
                    {
                        Ok(Some(principal)) => (
                            principal.with_field(PrincipalField::Name, username.to_string()),
                            None,
                        ),
                        Err(err)
                            if err.matches(trc::EventType::Store(trc::StoreEvent::LdapError))
                                && err
                                    .value(trc::Key::Code)
                                    .and_then(|v| v.to_uint())
                                    .map_or(false, |rc| [49, 50].contains(&rc)) =>
                        {
                            return Ok(None);
                        }
                        Ok(None) => return Ok(None),
                        Err(err) => return Err(err),
                    }
                } else if let Some(principal) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(username))
                    .await?
                {
                    if principal.verify_secret(secret).await? {
                        (
                            principal.with_field(PrincipalField::Name, username.to_string()),
                            None,
                        )
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        };

        // Query groups
        match external_principal.take_str_array(PrincipalField::MemberOf) {
            Some(names) if return_member_of => {
                let mut member_of = Vec::with_capacity(names.len());
                for mut name in names {
                    if name.contains('=') {
                        let (rs, _res) = conn
                            .search(
                                &name,
                                Scope::Base,
                                "objectClass=*",
                                &self.mappings.attr_name,
                            )
                            .await
                            .map_err(|err| err.into_error().caused_by(trc::location!()))?
                            .success()
                            .map_err(|err| err.into_error().caused_by(trc::location!()))?;
                        for entry in rs {
                            'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                                if self.mappings.attr_name.contains(&attr) {
                                    if let Some(group) = value.into_iter().next() {
                                        if !group.is_empty() {
                                            name = group;
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    member_of.push(
                        self.data_store
                            .get_or_create_principal_id(&name, Type::Group)
                            .await
                            .caused_by(trc::location!())?,
                    );
                }

                // Map ids
                external_principal.set(PrincipalField::MemberOf, member_of);
            }
            _ => (),
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

        // Keep the internal store up to date with the LDAP server
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
        let filter = self.mappings.filter_email.build(address.as_ref());
        let rs = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_name,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .success()
            .map(|(rs, _res)| rs)
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;

        trc::event!(
            Store(trc::StoreEvent::LdapQuery),
            Details = filter,
            Result = rs
                .iter()
                .map(|e| trc::Value::from(format!("{e:?}")))
                .collect::<Vec<_>>()
        );

        let mut ids = Vec::with_capacity(rs.len());
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            'outer: for attr in &self.mappings.attr_name {
                if let Some(name) = entry.attrs.get(attr).and_then(|v| v.first()) {
                    if !name.is_empty() {
                        ids.push(
                            self.data_store
                                .get_or_create_principal_id(name, Type::Individual)
                                .await?,
                        );
                        break 'outer;
                    }
                }
            }
        }

        Ok(ids)
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<bool> {
        let filter = self.mappings.filter_email.build(address.as_ref());
        self.pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_email_address,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .next()
            .await
            .map(|entry| {
                let success = entry.is_some();

                trc::event!(
                    Store(trc::StoreEvent::LdapQuery),
                    Details = filter,
                    Result = entry.map(|e| trc::Value::from(format!("{e:?}")))
                );

                success
            })
            .map_err(|err| err.into_error().caused_by(trc::location!()))
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        let filter = self.mappings.filter_verify.build(address);
        let mut stream = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_email_address,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;

        let mut emails = Vec::new();
        while let Some(entry) = stream
            .next()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
        {
            let entry = SearchEntry::construct(entry);
            for attr in &self.mappings.attr_email_address {
                if let Some(values) = entry.attrs.get(attr) {
                    for email in values {
                        if !email.is_empty() {
                            emails.push(email.to_string());
                        }
                    }
                }
            }
        }

        trc::event!(
            Store(trc::StoreEvent::LdapQuery),
            Details = filter,
            Result = emails
                .iter()
                .map(|e| trc::Value::from(e.clone()))
                .collect::<Vec<_>>()
        );

        Ok(emails)
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        let filter = self.mappings.filter_expand.build(address);
        let mut stream = self
            .pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                &self.mappings.attr_email_address,
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?;

        let mut emails = Vec::new();
        while let Some(entry) = stream
            .next()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
        {
            let entry = SearchEntry::construct(entry);
            for attr in &self.mappings.attr_email_address {
                if let Some(values) = entry.attrs.get(attr) {
                    for email in values {
                        if !email.is_empty() {
                            emails.push(email.to_string());
                        }
                    }
                }
            }
        }

        trc::event!(
            Store(trc::StoreEvent::LdapQuery),
            Details = filter,
            Result = emails
                .iter()
                .map(|e| trc::Value::from(e.clone()))
                .collect::<Vec<_>>()
        );

        Ok(emails)
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        let filter = self.mappings.filter_domains.build(domain);
        self.pool
            .get()
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &filter,
                Vec::<String>::new(),
            )
            .await
            .map_err(|err| err.into_error().caused_by(trc::location!()))?
            .next()
            .await
            .map(|entry| {
                let success = entry.is_some();

                trc::event!(
                    Store(trc::StoreEvent::LdapQuery),
                    Details = filter,
                    Result = entry.map(|e| trc::Value::from(format!("{e:?}")))
                );

                success
            })
            .map_err(|err| err.into_error().caused_by(trc::location!()))
    }
}

impl LdapDirectory {
    async fn find_principal(
        &self,
        conn: &mut Ldap,
        filter: &str,
    ) -> trc::Result<Option<Principal>> {
        conn.search(
            &self.mappings.base_dn,
            Scope::Subtree,
            filter,
            &self.mappings.attrs_principal,
        )
        .await
        .map_err(|err| err.into_error().caused_by(trc::location!()))?
        .success()
        .map(|(rs, _)| {
            trc::event!(
                Store(trc::StoreEvent::LdapQuery),
                Details = filter.to_string(),
                Result = rs
                    .iter()
                    .map(|e| trc::Value::from(format!("{e:?}")))
                    .collect::<Vec<_>>()
            );

            rs.into_iter().next().map(|entry| {
                self.mappings
                    .entry_to_principal(SearchEntry::construct(entry))
            })
        })
        .map_err(|err| err.into_error().caused_by(trc::location!()))
    }
}

impl LdapMappings {
    fn entry_to_principal(&self, entry: SearchEntry) -> Principal {
        let mut principal = Principal::default();
        let mut role = ROLE_USER;

        for (attr, value) in entry.attrs {
            if self.attr_name.contains(&attr) {
                principal.set(
                    PrincipalField::Name,
                    value.into_iter().next().unwrap_or_default(),
                );
            } else if self.attr_secret.contains(&attr) {
                for item in value {
                    principal.append_str(PrincipalField::Secrets, item);
                }
            } else if self.attr_email_address.contains(&attr) {
                for item in value {
                    principal.prepend_str(PrincipalField::Emails, item);
                }
            } else if self.attr_email_alias.contains(&attr) {
                for item in value {
                    principal.append_str(PrincipalField::Emails, item);
                }
            } else if let Some(idx) = self.attr_description.iter().position(|a| a == &attr) {
                if !principal.has_field(PrincipalField::Description) || idx == 0 {
                    principal.set(
                        PrincipalField::Description,
                        value.into_iter().next().unwrap_or_default(),
                    );
                }
            } else if self.attr_groups.contains(&attr) {
                for item in value {
                    principal.append_str(PrincipalField::MemberOf, item);
                }
            } else if self.attr_quota.contains(&attr) {
                if let Ok(quota) = value.into_iter().next().unwrap_or_default().parse::<u64>() {
                    principal.set(PrincipalField::Quota, quota);
                }
            } else if self.attr_type.contains(&attr) {
                for value in value {
                    match value.to_ascii_lowercase().as_str() {
                        "admin" | "administrator" | "root" | "superuser" => {
                            role = ROLE_ADMIN;
                            principal.typ = Type::Individual
                        }
                        "posixaccount" | "individual" | "person" | "inetorgperson" => {
                            principal.typ = Type::Individual
                        }
                        "posixgroup" | "groupofuniquenames" | "group" => {
                            principal.typ = Type::Group
                        }
                        _ => continue,
                    }
                    break;
                }
            }
        }

        principal.with_field(PrincipalField::Roles, role)
    }
}
