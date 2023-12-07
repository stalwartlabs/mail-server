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

use crate::{Directory, Principal};

use super::{EmailType, MemoryDirectory};

#[async_trait::async_trait]
impl Directory for MemoryDirectory {
    async fn authenticate(
        &self,
        credentials: &Credentials<String>,
    ) -> crate::Result<Option<Principal>> {
        let (username, secret) = match credentials {
            Credentials::Plain { username, secret } => (username, secret),
            Credentials::OAuthBearer { token } => (token, token),
            Credentials::XOauth2 { username, secret } => (username, secret),
        };
        match self.principals.get(username) {
            Some(principal) if principal.verify_secret(secret).await => Ok(Some(principal.clone())),
            _ => Ok(None),
        }
    }

    async fn principal(&self, name: &str) -> crate::Result<Option<Principal>> {
        Ok(self.principals.get(name).cloned())
    }

    async fn emails_by_name(&self, name: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        if let Some(emails) = self.names_to_email.get(name) {
            for email in emails {
                match email {
                    EmailType::Primary(email) | EmailType::Alias(email) => {
                        result.push(email.clone())
                    }
                    _ => {}
                }
            }
        }

        Ok(result)
    }

    async fn names_by_email(&self, address: &str) -> crate::Result<Vec<String>> {
        Ok(self
            .emails_to_names
            .get(self.opt.subaddressing.to_subaddress(address).as_ref())
            .or_else(|| {
                self.opt
                    .catch_all
                    .to_catch_all(address)
                    .and_then(|address| self.emails_to_names.get(address.as_ref()))
            })
            .map(|names| {
                names
                    .iter()
                    .map(|t| match t {
                        EmailType::Primary(name)
                        | EmailType::Alias(name)
                        | EmailType::List(name) => name.to_string(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default())
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        Ok(self
            .emails_to_names
            .contains_key(self.opt.subaddressing.to_subaddress(address).as_ref())
            || self
                .opt
                .catch_all
                .to_catch_all(address)
                .map_or(false, |address| {
                    self.emails_to_names.contains_key(address.as_ref())
                }))
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        let address = self.opt.subaddressing.to_subaddress(address);
        for (key, value) in &self.emails_to_names {
            if key.contains(address.as_ref())
                && value.iter().any(|t| matches!(t, EmailType::Primary(_)))
            {
                result.push(key.clone())
            }
        }
        Ok(result)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut result = Vec::new();
        let address = self.opt.subaddressing.to_subaddress(address);
        for (key, value) in &self.emails_to_names {
            if key == address.as_ref() {
                for item in value {
                    if let EmailType::List(name) = item {
                        for addr in self.names_to_email.get(name).unwrap() {
                            if let EmailType::Primary(addr) = addr {
                                result.push(addr.clone())
                            }
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        Ok(self.domains.contains(domain))
    }
}
