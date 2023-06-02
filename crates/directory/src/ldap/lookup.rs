use ldap3::{Scope, SearchEntry};
use mail_send::Credentials;

use crate::{Directory, Principal, Type};

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
            .find_principal(&self.mappings.filter_login.build(username))
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

    async fn principal_by_name(&self, name: &str) -> crate::Result<Option<Principal>> {
        self.find_principal(&self.mappings.filter_name.build(name))
            .await
    }

    async fn principal_by_id(&self, id: u32) -> crate::Result<Option<Principal>> {
        self.find_principal(&self.mappings.filter_id.build(&id.to_string()))
            .await
    }

    async fn member_of(&self, principal: &Principal) -> crate::Result<Vec<u32>> {
        if principal.member_of.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.pool.get().await?;
        let mut ids = Vec::with_capacity(principal.member_of.len());
        for group in &principal.member_of {
            let (rs, _res) = if group.contains('=') {
                conn.search(group, Scope::Base, "objectClass=*", &self.mappings.attr_id)
                    .await?
                    .success()?
            } else {
                conn.search(
                    &self.mappings.base_dn,
                    Scope::Subtree,
                    &self.mappings.filter_name.build(group),
                    &self.mappings.attr_id,
                )
                .await?
                .success()?
            };
            for entry in rs {
                for (attr, value) in SearchEntry::construct(entry).attrs {
                    if self.mappings.attr_id.contains(&attr) {
                        if let Some(id) = value.first() {
                            if let Ok(id) = id.parse() {
                                ids.push(id);
                            }
                        }
                    }
                }
            }
        }

        Ok(ids)
    }

    async fn emails_by_id(&self, id: u32) -> crate::Result<Vec<String>> {
        let (rs, _res) = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_id.build(&id.to_string()),
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

    async fn ids_by_email(&self, email: &str) -> crate::Result<Vec<u32>> {
        let (rs, _res) = self
            .pool
            .get()
            .await?
            .search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_email.build(email),
                &self.mappings.attr_id,
            )
            .await?
            .success()?;

        let mut ids = Vec::new();
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            'outer: for attr in &self.mappings.attr_id {
                if let Some(values) = entry.attrs.get(attr) {
                    for id in values {
                        if let Ok(id) = id.parse() {
                            ids.push(id);
                            break 'outer;
                        }
                    }
                }
            }
        }

        Ok(ids)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        self.pool
            .get()
            .await?
            .streaming_search(
                &self.mappings.base_dn,
                Scope::Subtree,
                &self.mappings.filter_email.build(address),
                &self.mappings.attr_email_address,
            )
            .await?
            .next()
            .await
            .map(|entry| entry.is_some())
            .map_err(|e| e.into())
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
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

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
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

    async fn query(&self, query: &str, params: &[&str]) -> crate::Result<bool> {
        let mut conn = self.pool.get().await?;

        Ok(if !params.is_empty() {
            let mut expanded_query = String::with_capacity(query.len() + params.len() * 2);
            for (pos, item) in query.split('$').enumerate() {
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
        .await?
        .is_some())
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
        Ok(rs.into_iter().next().map(|entry| {
            self.mappings
                .entry_to_principal(SearchEntry::construct(entry))
        }))
    }
}

impl LdapMappings {
    pub fn entry_to_principal(&self, entry: SearchEntry) -> Principal {
        let mut principal = Principal {
            id: u32::MAX,
            ..Default::default()
        };
        for (attr, value) in entry.attrs {
            if let Some(idx) = self.attr_id.iter().position(|a| a == &attr) {
                if principal.id == u32::MAX || idx == 0 {
                    if let Ok(id) = value.into_iter().next().unwrap_or_default().parse() {
                        principal.id = id;
                    }
                }
            } else if self.attr_name.contains(&attr) {
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
