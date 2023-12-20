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
    write::{DirectoryClass, ValueClass},
    IterateParams, Store, ValueKey,
};

use crate::{Principal, QueryBy, Type};

use super::{manage::ManageDirectory, PrincipalIdType};

#[async_trait::async_trait]
pub trait DirectoryStore: Sync + Send {
    async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> crate::Result<Option<Principal<u32>>>;
    async fn email_to_ids(&self, email: &str) -> crate::Result<Vec<u32>>;

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool>;
    async fn rcpt(&self, address: &str) -> crate::Result<bool>;
    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>>;
    async fn expn(&self, address: &str) -> crate::Result<Vec<String>>;
}

#[async_trait::async_trait]
impl DirectoryStore for Store {
    async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> crate::Result<Option<Principal<u32>>> {
        let (account_id, secret) = match by {
            QueryBy::Name(name) => (self.get_account_id(name).await?, None),
            QueryBy::Id(account_id) => (account_id.into(), None),
            QueryBy::Credentials(credentials) => match credentials {
                Credentials::Plain { username, secret } => {
                    (self.get_account_id(username).await?, secret.as_str().into())
                }
                Credentials::OAuthBearer { token } => {
                    (self.get_account_id(token).await?, token.as_str().into())
                }
                Credentials::XOauth2 { username, secret } => {
                    (self.get_account_id(username).await?, secret.as_str().into())
                }
            },
        };

        if let Some(account_id) = account_id {
            match (
                self.get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                    DirectoryClass::Principal(account_id),
                )))
                .await?,
                secret,
            ) {
                (Some(mut principal), Some(secret)) if principal.verify_secret(secret).await => {
                    if return_member_of {
                        principal.member_of = self.get_member_of(principal.id).await?;
                    }
                    Ok(Some(principal))
                }
                (Some(mut principal), None) => {
                    if return_member_of {
                        principal.member_of = self.get_member_of(principal.id).await?;
                    }

                    Ok(Some(principal))
                }
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn email_to_ids(&self, email: &str) -> crate::Result<Vec<u32>> {
        if let Some(ptype) = self
            .get_value::<PrincipalIdType>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::EmailToId(email.as_bytes().to_vec()),
            )))
            .await?
        {
            if ptype.typ != Type::List {
                Ok(vec![ptype.account_id])
            } else {
                self.get_members(ptype.account_id).await.map_err(Into::into)
            }
        } else {
            Ok(Vec::new())
        }
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        self.get_value::<()>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::Domain(domain.as_bytes().to_vec()),
        )))
        .await
        .map(|ids| ids.is_some())
        .map_err(Into::into)
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        self.get_value::<()>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::EmailToId(address.as_bytes().to_vec()),
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
                    ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(vec![0u8]))),
                    ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(
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
                    DirectoryClass::Principal(account_id),
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
