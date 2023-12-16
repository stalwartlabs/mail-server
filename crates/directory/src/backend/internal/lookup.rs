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
use store::{
    write::{DirectoryValue, ValueClass},
    IterateParams, Store, ValueKey,
};

use crate::{Directory, Principal, QueryBy};

use super::manage::ManageDirectory;

#[async_trait::async_trait]
impl Directory for Store {
    async fn query(&self, by: QueryBy<'_>) -> crate::Result<Option<Principal<u32>>> {
        let (username, secret) = match by {
            QueryBy::Name(name) => (name, None),
            QueryBy::Id(account_id) => {
                return self
                    .get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                        DirectoryValue::Principal(account_id),
                    )))
                    .await
                    .map_err(Into::into);
            }
            QueryBy::Credentials(credentials) => match credentials {
                Credentials::Plain { username, secret } => {
                    (username.as_str(), secret.as_str().into())
                }
                Credentials::OAuthBearer { token } => (token.as_str(), token.as_str().into()),
                Credentials::XOauth2 { username, secret } => {
                    (username.as_str(), secret.as_str().into())
                }
            },
        };

        if let Some(account_id) = self.get_account_id(username).await? {
            match (
                self.get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                    DirectoryValue::Principal(account_id),
                )))
                .await?,
                secret,
            ) {
                (Some(principal), Some(secret)) if principal.verify_secret(secret).await => {
                    Ok(Some(principal))
                }
                (Some(principal), None) => Ok(Some(principal)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn email_to_ids(&self, email: &str) -> crate::Result<Vec<u32>> {
        self.get_value::<Vec<u32>>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::EmailToId(email.as_bytes().to_vec()),
        )))
        .await
        .map(|ids| ids.unwrap_or_default())
        .map_err(Into::into)
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        self.get_value::<()>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::Domain(domain.as_bytes().to_vec()),
        )))
        .await
        .map(|ids| ids.is_some())
        .map_err(Into::into)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        self.get_value::<()>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::EmailToId(address.as_bytes().to_vec()),
        )))
        .await
        .map(|ids| ids.is_some())
        .map_err(Into::into)
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut results = Vec::new();
        let address = address.split('@').next().unwrap_or(address);
        if address.len() > 3 {
            self.iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Directory(DirectoryValue::EmailToId(vec![0u8]))),
                    ValueKey::from(ValueClass::Directory(DirectoryValue::EmailToId(
                        vec![u8::MAX; 10],
                    ))),
                )
                .no_values(),
                |key, _| {
                    let key =
                        std::str::from_utf8(key.get(1..).unwrap_or_default()).unwrap_or_default();
                    if key.split('@').next().unwrap_or(key).contains(address) {
                        results.push(key.to_string());
                    }
                    Ok(true)
                },
            )
            .await?;
        }

        Ok(results)
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        let mut results = Vec::new();
        for account_id in self.email_to_ids(address).await? {
            if let Some(email) = self
                .get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                    DirectoryValue::Principal(account_id),
                )))
                .await?
                .and_then(|p| p.emails.into_iter().next())
            {
                results.push(email);
            }
        }

        Ok(results)
    }
}
