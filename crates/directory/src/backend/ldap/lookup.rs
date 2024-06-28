/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ldap3::{Ldap, LdapConnAsync, LdapError, Scope, SearchEntry};
use mail_send::Credentials;

use crate::{backend::internal::manage::ManageDirectory, DirectoryError, Principal, QueryBy, Type};

use super::{LdapDirectory, LdapMappings};

impl LdapDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> crate::Result<Option<Principal<u32>>> {
        let mut conn = self.pool.get().await?;
        let mut account_id = None;
        let account_name;

        let principal = match by {
            QueryBy::Name(username) => {
                account_name = username.to_string();

                if let Some(principal) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(username))
                    .await?
                {
                    principal
                } else {
                    return Ok(None);
                }
            }
            QueryBy::Id(uid) => {
                if let Some(username) = self.data_store.get_account_name(uid).await? {
                    account_name = username;
                } else {
                    return Ok(None);
                }
                account_id = Some(uid);

                if let Some(principal) = self
                    .find_principal(&mut conn, &self.mappings.filter_name.build(&account_name))
                    .await?
                {
                    principal
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
                account_name = username.to_string();

                if let Some(auth_bind) = &self.auth_bind {
                    let (conn, mut ldap) = LdapConnAsync::with_settings(
                        self.pool.manager().settings.clone(),
                        &self.pool.manager().address,
                    )
                    .await?;

                    ldap3::drive!(conn);

                    ldap.simple_bind(&auth_bind.build(username), secret).await?;

                    match self
                        .find_principal(&mut ldap, &self.mappings.filter_name.build(username))
                        .await
                    {
                        Ok(Some(principal)) => principal,
                        Err(DirectoryError::Ldap(LdapError::LdapResult { result }))
                            if [49, 50].contains(&result.rc) =>
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
                        principal
                    } else {
                        tracing::debug!(
                            context = "directory",
                            event = "invalid_password",
                            protocol = "ldap",
                            account = username,
                            "Invalid password for account"
                        );
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        };
        let mut principal = principal;

        // Obtain account ID if not available
        if let Some(account_id) = account_id {
            principal.id = account_id;
        } else {
            principal.id = self
                .data_store
                .get_or_create_account_id(&account_name)
                .await?;
        }
        principal.name = account_name;

        // Obtain groups
        if return_member_of && !principal.member_of.is_empty() {
            for member_of in principal.member_of.iter_mut() {
                if member_of.contains('=') {
                    let (rs, _res) = conn
                        .search(
                            member_of,
                            Scope::Base,
                            "objectClass=*",
                            &self.mappings.attr_name,
                        )
                        .await?
                        .success()?;
                    for entry in rs {
                        'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                            if self.mappings.attr_name.contains(&attr) {
                                if let Some(group) = value.into_iter().next() {
                                    if !group.is_empty() {
                                        *member_of = group;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Map ids
            self.data_store
                .map_principal(principal, true)
                .await
                .map(Some)
        } else {
            principal.member_of.clear();
            Ok(Some(principal.into()))
        }
    }

    pub async fn email_to_ids(&self, address: &str) -> crate::Result<Vec<u32>> {
        let rs = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_email.build(address.as_ref()),
                &self.mappings.attr_name,
            )
            .await?
            .success()
            .map(|(rs, _res)| rs)?;

        let mut ids = Vec::with_capacity(rs.len());
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            'outer: for attr in &self.mappings.attr_name {
                if let Some(name) = entry.attrs.get(attr).and_then(|v| v.first()) {
                    if !name.is_empty() {
                        ids.push(self.data_store.get_or_create_account_id(name).await?);
                        break 'outer;
                    }
                }
            }
        }

        Ok(ids)
    }

    pub async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        self.pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_email.build(address.as_ref()),
                &self.mappings.attr_email_address,
            )
            .await?
            .next()
            .await
            .map(|entry| entry.is_some())
            .map_err(|e| e.into())
    }

    pub async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut stream = self
            .pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_verify.build(address),
                &self.mappings.attr_email_address,
            )
            .await?;

        let mut emails = Vec::new();
        while let Some(entry) = stream.next().await? {
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

        Ok(emails)
    }

    pub async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut stream = self
            .pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_expand.build(address),
                &self.mappings.attr_email_address,
            )
            .await?;

        let mut emails = Vec::new();
        while let Some(entry) = stream.next().await? {
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

        Ok(emails)
    }

    pub async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        self.pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_domains.build(domain),
                Vec::<String>::new(),
            )
            .await?
            .next()
            .await
            .map(|entry| entry.is_some())
            .map_err(|e| e.into())
    }
}

impl LdapDirectory {
    async fn find_principal(
        &self,
        conn: &mut Ldap,
        filter: &str,
    ) -> crate::Result<Option<Principal<String>>> {
        conn.search(
            &self.mappings.base_dn,
            Scope::Subtree,
            filter,
            &self.mappings.attrs_principal,
        )
        .await?
        .success()
        .map(|(rs, _)| {
            rs.into_iter().next().map(|entry| {
                self.mappings
                    .entry_to_principal(SearchEntry::construct(entry))
            })
        })
        .map_err(Into::into)
    }
}

impl LdapMappings {
    fn entry_to_principal(&self, entry: SearchEntry) -> Principal<String> {
        let mut principal = Principal::default();

        tracing::debug!(
            context = "ldap",
            event = "fetch_principal",
            entry = ?entry,
            "LDAP entry"
        );

        for (attr, value) in entry.attrs {
            if self.attr_name.contains(&attr) {
                principal.name = value.into_iter().next().unwrap_or_default();
            } else if self.attr_secret.contains(&attr) {
                principal.secrets.extend(value);
            } else if self.attr_email_address.contains(&attr) {
                for value in value {
                    if principal.emails.is_empty() {
                        principal.emails.push(value);
                    } else {
                        principal.emails.insert(0, value);
                    }
                }
            } else if self.attr_email_alias.contains(&attr) {
                principal.emails.extend(value);
            } else if let Some(idx) = self.attr_description.iter().position(|a| a == &attr) {
                if principal.description.is_none() || idx == 0 {
                    principal.description = value.into_iter().next();
                }
            } else if self.attr_groups.contains(&attr) {
                principal.member_of.extend(value);
            } else if self.attr_quota.contains(&attr) {
                if let Ok(quota) = value.into_iter().next().unwrap_or_default().parse() {
                    principal.quota = quota;
                }
            } else if self.attr_type.contains(&attr) {
                for value in value {
                    match value.to_ascii_lowercase().as_str() {
                        "admin" | "administrator" | "root" | "superuser" => {
                            principal.typ = Type::Superuser
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

        principal
    }
}
