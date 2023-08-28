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

use ldap3::{ResultEntry, Scope, SearchEntry};
use mail_send::Credentials;

use crate::{Directory, Principal, QueryColumn, Type};

use super::{LdapDirectory, LdapMappings};

#[async_trait::async_trait]
impl Directory for LdapDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        let (username, secret) = match credentials {
            Credentials::Plain { username, secret } => (username, secret),
            Credentials::OAuthBearer { token } => (token, token),
            Credentials::XOauth2 { username, secret } => (username, secret),
        };
        match self
            .find_principal(&self.mappings.filter_name.build(username))
            .await
        {
            Ok(Some(principal)) => {
                if principal.verify_secret(secret).await {
                    Ok(Some(principal))
                } else {
                    Ok(None)
                }
            }
            result => result,
        }
    }

    async fn principal(&self, name: &str) -> crate::Result<Option<Principal>> {
        self.find_principal(&self.mappings.filter_name.build(name))
            .await
    }

    async fn emails_by_name(&self, name: &str) -> crate::Result<Vec<String>> {
        let (rs, _res) = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_name.build(name),
                &self.mappings.attrs_email,
            )
            .await?
            .success()?;

        let mut emails = Vec::new();
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            for attr in &self.mappings.attrs_email {
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

    async fn names_by_email(&self, address: &str) -> crate::Result<Vec<String>> {
        let names = self
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
            .map(|(rs, _res)| self.extract_names(rs))?;

        if !names.is_empty() {
            Ok(names)
        } else if let Some(address) = self.opt.catch_all.to_catch_all(address) {
            self.pool
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
                .map(|(rs, _res)| self.extract_names(rs))
                .map_err(|e| e.into())
        } else {
            Ok(names)
        }
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

    async fn lookup(&self, query: &str, params: &[&str]) -> crate::Result<bool> {
        self.query_(query, params)
            .await
            .map(|entry| entry.is_some())
    }

    async fn query(&self, query: &str, params: &[&str]) -> crate::Result<Vec<QueryColumn>> {
        self.query_(query, params).await.map(|entry| {
            if let Some(entry) = entry {
                let mut object = String::new();
                for (attr, values) in SearchEntry::construct(entry).attrs {
                    for value in values {
                        object.push_str(&attr);
                        object.push(':');
                        object.push_str(&value);
                        object.push('\n');
                    }
                }
                vec![QueryColumn::Text(object)]
            } else {
                vec![]
            }
        })
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
    async fn query_(&self, query: &str, params: &[&str]) -> crate::Result<Option<ResultEntry>> {
        let mut conn = self.pool.get().await?;
        tracing::trace!(context = "directory", event = "query", query = query, params = ?params);

        if !params.is_empty() {
            let mut expanded_query = String::with_capacity(query.len() + params.len() * 2);
            for (pos, item) in query.split('?').enumerate() {
                if pos > 0 {
                    if let Some(param) = params.get(pos - 1) {
                        expanded_query.push_str(param);
                    }
                }
                expanded_query.push_str(item);
            }
            conn.streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &expanded_query,
                Vec::<String>::new(),
            )
            .await
        } else {
            conn.streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                query,
                Vec::<String>::new(),
            )
            .await
        }?
        .next()
        .await
        .map_err(|e| e.into())
    }

    async fn find_principal(&self, filter: &str) -> crate::Result<Option<Principal>> {
        let (rs, _res) = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                filter,
                &self.mappings.attrs_principal,
            )
            .await?
            .success()?;

        if let Some(mut principal) = rs.into_iter().next().map(|entry| {
            self.mappings
                .entry_to_principal(SearchEntry::construct(entry))
        }) {
            // Map groups
            if !principal.member_of.is_empty() {
                let mut conn = self.pool.get().await?;
                let mut names = Vec::with_capacity(principal.member_of.len());
                for group in principal.member_of {
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
                                            if !group
                                                .eq_ignore_ascii_case(&self.opt.superuser_group)
                                            {
                                                names.push(group.to_string());
                                            } else {
                                                principal.typ = Type::Superuser;
                                            }
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                        }
                    } else if !group.eq_ignore_ascii_case(&self.opt.superuser_group) {
                        names.push(group);
                    } else {
                        principal.typ = Type::Superuser;
                    }
                }
                principal.member_of = names;
            }
            Ok(Some(principal))
        } else {
            Ok(None)
        }
    }

    fn extract_names(&self, rs: Vec<ResultEntry>) -> Vec<String> {
        let mut names = Vec::with_capacity(rs.len());
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            'outer: for attr in &self.mappings.attr_name {
                if let Some(value) = entry.attrs.get(attr).and_then(|v| v.first()) {
                    if !value.is_empty() {
                        names.push(value.to_string());
                        break 'outer;
                    }
                }
            }
        }
        names
    }
}

impl LdapMappings {
    pub fn entry_to_principal(&self, entry: SearchEntry) -> Principal {
        let mut principal = Principal::default();
        for (attr, value) in entry.attrs {
            if self.attr_name.contains(&attr) {
                principal.name = value.into_iter().next().unwrap_or_default();
            } else if self.attr_secret.contains(&attr) {
                principal.secrets.extend(value);
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
            } else if attr.eq_ignore_ascii_case("objectClass") {
                if value.contains(&self.obj_user) {
                    principal.typ = Type::Individual;
                } else if value.contains(&self.obj_group) {
                    principal.typ = Type::Group;
                }
            }
        }

        principal
    }
}
