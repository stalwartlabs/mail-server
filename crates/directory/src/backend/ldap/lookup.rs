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

use ldap3::{Ldap, LdapConnAsync, LdapError, Scope, SearchEntry};
use mail_send::Credentials;
use store::Store;

use crate::{
    backend::internal::manage::ManageDirectory, Directory, DirectoryError, Principal, QueryBy,
    QueryType, Type,
};

use super::{LdapDirectory, LdapMappings};

#[async_trait::async_trait]
impl Directory for LdapDirectory {
    async fn query(&self, by: QueryBy<'_>) -> crate::Result<Option<Principal>> {
        let mut conn = self.pool.get().await?;
        let mut account_id = None;
        let account_name;

        let principal = match by.t {
            QueryType::Name(username) => {
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
            QueryType::Id(uid) => {
                if let Some(username) = by.account_name(uid).await? {
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
            QueryType::Credentials(credentials) => {
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
                    if principal.principal.verify_secret(secret).await {
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
        let groups = principal.groups;
        let mut principal = principal.principal;

        // Obtain account ID if not available
        if let Some(account_id) = account_id {
            principal.id = account_id;
        } else if by.has_store() {
            principal.id = by.account_id(&account_name).await?;
        }
        principal.name = account_name;

        // Obtain groups
        if by.has_store() && !groups.is_empty() {
            principal.member_of = Vec::with_capacity(groups.len());
            for group in groups {
                if group.contains('=') {
                    let (rs, _res) = conn
                        .search(
                            &group,
                            Scope::Base,
                            "objectClass=*",
                            &self.mappings.attr_name,
                        )
                        .await?
                        .success()?;
                    for entry in rs {
                        'outer: for (attr, value) in SearchEntry::construct(entry).attrs {
                            if self.mappings.attr_name.contains(&attr) {
                                if let Some(group) = value.first() {
                                    if !group.is_empty() {
                                        principal.member_of.push(by.account_id(group).await?);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    principal.member_of.push(by.account_id(&group).await?);
                }
            }
        }

        Ok(Some(principal))
    }

    async fn email_to_ids(&self, address: &str, store: &Store) -> crate::Result<Vec<u32>> {
        let mut rs = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self
                    .mappings
                    .filter_email
                    .build(self.opt.subaddressing.to_subaddress(address).as_ref()),
                &self.mappings.attr_name,
            )
            .await?
            .success()
            .map(|(rs, _res)| rs)?;

        if rs.is_empty() {
            if let Some(address) = self.opt.catch_all.to_catch_all(address) {
                rs = self
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
            } else {
                return Ok(Vec::new());
            }
        }

        let mut ids = Vec::with_capacity(rs.len());
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            'outer: for attr in &self.mappings.attr_name {
                if let Some(name) = entry.attrs.get(attr).and_then(|v| v.first()) {
                    if !name.is_empty() {
                        ids.push(store.get_or_create_account_id(name).await?);
                        break 'outer;
                    }
                }
            }
        }

        Ok(ids)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        match self
            .pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self
                    .mappings
                    .filter_email
                    .build(self.opt.subaddressing.to_subaddress(address).as_ref()),
                &self.mappings.attr_email_address,
            )
            .await?
            .next()
            .await
        {
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                if let Some(address) = self.opt.catch_all.to_catch_all(address) {
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
                } else {
                    Ok(false)
                }
            }

            Err(e) => Err(e.into()),
        }
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut stream = self
            .pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self
                    .mappings
                    .filter_verify
                    .build(self.opt.subaddressing.to_subaddress(address).as_ref()),
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

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut stream = self
            .pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self
                    .mappings
                    .filter_expand
                    .build(self.opt.subaddressing.to_subaddress(address).as_ref()),
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

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
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
    ) -> crate::Result<Option<PrincipalWithGroups>> {
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

struct PrincipalWithGroups {
    principal: Principal,
    groups: Vec<String>,
}

impl LdapMappings {
    fn entry_to_principal(&self, entry: SearchEntry) -> PrincipalWithGroups {
        let mut groups = Vec::new();
        let mut principal = Principal::default();

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
                groups.extend(value);
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
                        "posixgroup" | "group" => principal.typ = Type::Group,
                        _ => continue,
                    }
                    break;
                }
            }
        }

        PrincipalWithGroups { principal, groups }
    }
}
