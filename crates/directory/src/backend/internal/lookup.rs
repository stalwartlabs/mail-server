/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PrincipalInfo, manage::ManageDirectory};
use crate::{Principal, PrincipalData, QueryBy, Type, backend::RcptType};

use mail_send::Credentials;
use store::{
    Deserialize, IterateParams, Store, ValueKey,
    write::{DirectoryClass, ValueClass},
};
use trc::AddContext;

#[allow(async_fn_in_trait)]
pub trait DirectoryStore: Sync + Send {
    async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>>;
    async fn email_to_id(&self, address: &str) -> trc::Result<Option<u32>>;
    async fn is_local_domain(&self, domain: &str) -> trc::Result<bool>;
    async fn rcpt(&self, address: &str) -> trc::Result<RcptType>;
    async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>>;
    async fn expn(&self, address: &str) -> trc::Result<Vec<String>>;
    async fn expn_by_id(&self, id: u32) -> trc::Result<Vec<String>>;
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
                    let mut roles = vec![];
                    let mut lists = vec![];
                    let mut member_of = vec![];

                    for member in self.get_member_of(principal.id).await? {
                        match member.typ {
                            Type::List => lists.push(member.principal_id),
                            Type::Role => roles.push(member.principal_id),
                            _ => member_of.push(member.principal_id),
                        }
                    }

                    if !roles.is_empty() {
                        principal.data.push(PrincipalData::Roles(roles));
                    }
                    if !lists.is_empty() {
                        principal.data.push(PrincipalData::Lists(lists));
                    }
                    if !member_of.is_empty() {
                        principal.data.push(PrincipalData::MemberOf(member_of));
                    }
                }
                return Ok(Some(principal));
            }
        }
        Ok(None)
    }

    async fn email_to_id(&self, address: &str) -> trc::Result<Option<u32>> {
        self.get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::EmailToId(address.as_bytes().to_vec()),
        )))
        .await
        .map(|ptype| ptype.map(|ptype| ptype.id))
    }

    async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::NameToId(domain.as_bytes().to_vec()),
        )))
        .await
        .map(|p| p.is_some_and(|p| p.typ == Type::Domain))
    }

    async fn rcpt(&self, address: &str) -> trc::Result<RcptType> {
        if let Some(pinfo) = self
            .get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::EmailToId(address.as_bytes().to_vec()),
            )))
            .await?
        {
            if pinfo.typ != Type::List {
                Ok(RcptType::Mailbox)
            } else {
                self.expn_by_id(pinfo.id).await.map(RcptType::List)
            }
        } else {
            Ok(RcptType::Invalid)
        }
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
                        results.push(key.into());
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(results)
    }

    async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        if let Some(ptype) = self
            .get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::EmailToId(address.as_bytes().to_vec()),
            )))
            .await?
            .filter(|p| p.typ == Type::List)
        {
            self.expn_by_id(ptype.id).await
        } else {
            Ok(vec![])
        }
    }

    async fn expn_by_id(&self, list_id: u32) -> trc::Result<Vec<String>> {
        let mut results = Vec::new();
        for account_id in self.get_members(list_id).await? {
            if let Some(email) = self
                .get_principal(account_id)
                .await?
                .and_then(|p| p.emails.into_iter().next())
            {
                results.push(email);
            }
        }

        if let Some(emails) = self.get_principal(list_id).await?.and_then(|p| {
            p.data.into_iter().find_map(|data| {
                if let PrincipalData::ExternalMembers(members) = data {
                    Some(members)
                } else {
                    None
                }
            })
        }) {
            results.extend(emails);
        }

        Ok(results)
    }
}
