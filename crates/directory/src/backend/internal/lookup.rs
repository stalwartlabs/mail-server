/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;
use store::{
    write::{DirectoryClass, ValueClass},
    Deserialize, IterateParams, Store, ValueKey,
};
use trc::AddContext;

use crate::{Principal, QueryBy, Type};

use super::{manage::ManageDirectory, PrincipalField, PrincipalInfo};

#[allow(async_fn_in_trait)]
pub trait DirectoryStore: Sync + Send {
    async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>>;
    async fn email_to_ids(&self, email: &str) -> trc::Result<Vec<u32>>;
    async fn is_local_domain(&self, domain: &str) -> trc::Result<bool>;
    async fn rcpt(&self, address: &str) -> trc::Result<bool>;
    async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>>;
    async fn expn(&self, address: &str) -> trc::Result<Vec<String>>;
}

impl DirectoryStore for Store {
    async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        let (account_id, secret) = match by {
            QueryBy::Name(name) => (self.get_principal_id(name).await?, None),
            QueryBy::Id(account_id) => (account_id.into(), None),
            QueryBy::Credentials(credentials) => match credentials {
                Credentials::Plain { username, secret } => (
                    self.get_principal_id(username).await?,
                    secret.as_str().into(),
                ),
                Credentials::OAuthBearer { token } => {
                    (self.get_principal_id(token).await?, token.as_str().into())
                }
                Credentials::XOauth2 { username, secret } => (
                    self.get_principal_id(username).await?,
                    secret.as_str().into(),
                ),
            },
        };

        if let Some(account_id) = account_id {
            if let Some(mut principal) = self.get_principal(account_id).await? {
                if let Some(secret) = secret {
                    if !principal.verify_secret(secret).await? {
                        return Ok(None);
                    }
                }

                if return_member_of {
                    for member in self.get_member_of(principal.id).await? {
                        let field = match member.typ {
                            Type::List => PrincipalField::Lists,
                            Type::Role => PrincipalField::Roles,
                            _ => PrincipalField::MemberOf,
                        };
                        principal.append_int(field, member.principal_id);
                    }
                }
                return Ok(Some(principal));
            }
        }
        Ok(None)
    }

    async fn email_to_ids(&self, email: &str) -> trc::Result<Vec<u32>> {
        if let Some(ptype) = self
            .get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::EmailToId(email.as_bytes().to_vec()),
            )))
            .await?
        {
            if ptype.typ != Type::List {
                Ok(vec![ptype.id])
            } else {
                self.get_members(ptype.id).await
            }
        } else {
            Ok(Vec::new())
        }
    }

    async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::NameToId(domain.as_bytes().to_vec()),
        )))
        .await
        .map(|p| p.map_or(false, |p| p.typ == Type::Domain))
    }

    async fn rcpt(&self, address: &str) -> trc::Result<bool> {
        self.get_value::<()>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::EmailToId(address.as_bytes().to_vec()),
        )))
        .await
        .map(|ids| ids.is_some())
    }

    async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        let mut results = Vec::new();
        let address = address.split('@').next().unwrap_or(address);
        if address.len() > 3 {
            self.iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(vec![0u8]))),
                    ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(
                        vec![u8::MAX; 10],
                    ))),
                ),
                |key, value| {
                    let key =
                        std::str::from_utf8(key.get(1..).unwrap_or_default()).unwrap_or_default();
                    if key.split('@').next().unwrap_or(key).contains(address)
                        && PrincipalInfo::deserialize(value)
                            .caused_by(trc::location!())?
                            .typ
                            != Type::List
                    {
                        results.push(key.to_string());
                    }
                    Ok(true)
                },
            )
            .await.caused_by(trc::location!())?;
        }

        Ok(results)
    }

    async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        let mut results = Vec::new();
        if let Some(ptype) = self
            .get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::EmailToId(address.as_bytes().to_vec()),
            )))
            .await?
            .filter(|p| p.typ == Type::List)
        {
            for account_id in self.get_members(ptype.id).await? {
                if let Some(email) = self
                    .get_principal(account_id)
                    .await?
                    .and_then(|mut p| p.take_str(PrincipalField::Emails))
                {
                    results.push(email);
                }
            }
        }

        Ok(results)
    }
}
