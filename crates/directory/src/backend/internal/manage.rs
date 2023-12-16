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

use jmap_proto::types::collection::Collection;
use store::{
    write::{assert::HashedValue, BatchBuilder, DirectoryValue, ValueClass},
    IterateParams, Serialize, Store, ValueKey,
};

use crate::{Directory, DirectoryError, ManagementError, Principal, QueryBy, Type};

use super::{PrincipalAction, PrincipalField, PrincipalUpdate, PrincipalValue};

#[async_trait::async_trait]
pub trait ManageDirectory {
    async fn get_account_id(&self, name: &str) -> crate::Result<Option<u32>>;
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32>;
    async fn get_account_name(&self, account_id: u32) -> crate::Result<Option<String>>;
    async fn create_account(&self, principal: Principal<String>) -> crate::Result<u32>;
    async fn update_account(
        &self,
        by: QueryBy<'_>,
        changes: Vec<PrincipalUpdate>,
    ) -> crate::Result<()>;
    async fn delete_account(&self, by: QueryBy<'_>) -> crate::Result<()>;
    async fn create_domain(&self, domain: &str) -> crate::Result<()>;
    async fn delete_domain(&self, domain: &str) -> crate::Result<()>;
    async fn list_accounts(
        &self,
        start_from: Option<&str>,
        limit: usize,
    ) -> crate::Result<Vec<String>>;
    async fn map_group_ids(&self, principal: Principal<u32>) -> crate::Result<Principal<String>>;
    async fn map_group_names(
        &self,
        principal: Principal<String>,
        create_if_missing: bool,
    ) -> crate::Result<Principal<u32>>;
}

#[async_trait::async_trait]
impl ManageDirectory for Store {
    async fn get_account_name(&self, account_id: u32) -> crate::Result<Option<String>> {
        self.get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::Principal(account_id),
        )))
        .await
        .map_err(Into::into)
        .map(|v| {
            if let Some(v) = v {
                Some(v.name)
            } else {
                tracing::debug!(
                    context = "directory",
                    event = "not_found",
                    account = account_id,
                    "Principal not found for account id"
                );

                None
            }
        })
    }

    async fn get_account_id(&self, name: &str) -> crate::Result<Option<u32>> {
        self.get_value::<u32>(ValueKey::from(ValueClass::Directory(
            DirectoryValue::NameToId(name.as_bytes().to_vec()),
        )))
        .await
        .map_err(Into::into)
    }

    // Used by all directories except internal
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32> {
        let mut try_count = 0;

        loop {
            // Try to obtain ID
            if let Some(account_id) = self.get_account_id(name).await? {
                return Ok(account_id);
            }

            // Assign new ID
            let account_id = self
                .assign_document_id(u32::MAX, Collection::Principal)
                .await?;

            // Write account ID
            let name_key =
                ValueClass::Directory(DirectoryValue::NameToId(name.as_bytes().to_vec()));
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .create_document(account_id)
                .assert_value(name_key.clone(), ())
                .set(name_key, account_id.serialize())
                .set(
                    ValueClass::Directory(DirectoryValue::Principal(account_id)),
                    Principal {
                        id: account_id,
                        typ: Type::Individual,
                        name: name.to_string(),
                        ..Default::default()
                    }
                    .serialize(),
                );

            match self.write(batch.build()).await {
                Ok(_) => {
                    return Ok(account_id);
                }
                Err(store::Error::AssertValueFailed) if try_count < 3 => {
                    try_count += 1;
                    continue;
                }
                Err(err) => {
                    tracing::error!(event = "error",
                                            context = "store",
                                            error = ?err,
                                            "Failed to generate account id");
                    return Err(err.into());
                }
            }
        }
    }

    async fn create_account(&self, principal: Principal<String>) -> crate::Result<u32> {
        // Make sure the principal has a name
        if principal.name.is_empty() {
            return Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name,
            )));
        }

        // Map group names
        let mut principal = self.map_group_names(principal, false).await?;

        // Make sure new name is not taken
        principal.name = principal.name.to_lowercase();
        if self.get_account_id(&principal.name).await?.is_some() {
            return Err(DirectoryError::Management(ManagementError::NotUniqueField(
                PrincipalField::Name,
            )));
        }

        // Make sure the e-mail is not taken and validate domain
        for email in principal.emails.iter_mut() {
            *email = email.to_lowercase();
            if self.rcpt(email).await? {
                return Err(DirectoryError::Management(ManagementError::NotUniqueField(
                    PrincipalField::Emails,
                )));
            }
            if let Some(domain) = email.split('@').nth(1) {
                if !self.is_local_domain(domain).await? {
                    return Err(DirectoryError::Management(ManagementError::NotFound(
                        domain.to_string(),
                    )));
                }
            }
        }

        // Assign accountId
        let account_id = self
            .assign_document_id(u32::MAX, Collection::Principal)
            .await?;

        // Write principal
        let mut batch = BatchBuilder::new();
        batch
            .assert_value(
                ValueClass::Directory(DirectoryValue::NameToId(
                    principal.name.clone().into_bytes(),
                )),
                (),
            )
            .set(
                ValueClass::Directory(DirectoryValue::Principal(account_id)),
                (&principal).serialize(),
            )
            .set(
                ValueClass::Directory(DirectoryValue::NameToId(principal.name.into_bytes())),
                account_id.serialize(),
            );

        // Write email to id mapping
        let ids = if matches!(principal.typ, Type::List) {
            principal.member_of
        } else {
            vec![account_id]
        };

        for email in principal.emails {
            batch.set(
                ValueClass::Directory(DirectoryValue::EmailToId(email.into_bytes())),
                (&ids).serialize(),
            );
        }

        self.write(batch.build()).await?;

        Ok(account_id)
    }

    async fn delete_account(&self, by: QueryBy<'_>) -> crate::Result<()> {
        let account_id = match by {
            QueryBy::Name(name) => self.get_account_id(name).await?.ok_or_else(|| {
                DirectoryError::Management(ManagementError::NotFound(name.to_string()))
            })?,
            QueryBy::Id(account_id) => account_id,
            QueryBy::Credentials(_) => unreachable!(),
        };

        let principal = self
            .get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                DirectoryValue::Principal(account_id),
            )))
            .await?
            .ok_or_else(|| {
                DirectoryError::Management(ManagementError::NotFound(account_id.to_string()))
            })?;

        // Unlink all account's blobs
        self.blob_hash_unlink_account(account_id).await?;

        // Revoke ACLs
        self.acl_revoke_all(account_id).await?;

        // Delete account data
        self.purge_account(account_id).await?;

        // Delete account
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .clear(DirectoryValue::NameToId(principal.name.into_bytes()))
            .clear(DirectoryValue::Principal(account_id))
            .clear(DirectoryValue::UsedQuota(account_id));

        for email in principal.emails {
            batch.clear(DirectoryValue::EmailToId(email.into_bytes()));
        }

        self.write(batch.build()).await?;

        Ok(())
    }

    async fn update_account(
        &self,
        by: QueryBy<'_>,
        changes: Vec<PrincipalUpdate>,
    ) -> crate::Result<()> {
        let account_id = match by {
            QueryBy::Name(name) => self.get_account_id(name).await?.ok_or_else(|| {
                DirectoryError::Management(ManagementError::NotFound(name.to_string()))
            })?,
            QueryBy::Id(account_id) => account_id,
            QueryBy::Credentials(_) => unreachable!(),
        };

        // Fetch principal
        let mut principal = self
            .get_value::<HashedValue<Principal<u32>>>(ValueKey::from(ValueClass::Directory(
                DirectoryValue::Principal(account_id),
            )))
            .await?
            .ok_or_else(|| {
                DirectoryError::Management(ManagementError::NotFound(account_id.to_string()))
            })?;

        // Apply changes
        let mut batch = BatchBuilder::new();
        let is_list = matches!(principal.inner.typ, Type::List);
        let mut has_list_changes = false;
        batch.assert_value(
            ValueClass::Directory(DirectoryValue::Principal(account_id)),
            &principal,
        );
        for change in changes {
            match (change.action, change.field, change.value) {
                (PrincipalAction::Set, PrincipalField::Name, PrincipalValue::String(new_name)) => {
                    // Make sure new name is not taken
                    let new_name = new_name.to_lowercase();
                    if principal.inner.name != new_name {
                        if self.get_account_id(&new_name).await?.is_some() {
                            return Err(DirectoryError::Management(
                                ManagementError::NotUniqueField(PrincipalField::Name),
                            ));
                        }

                        batch.clear(ValueClass::Directory(DirectoryValue::NameToId(
                            principal.inner.name.as_bytes().to_vec(),
                        )));

                        principal.inner.name = new_name.clone();

                        batch.set(
                            ValueClass::Directory(DirectoryValue::NameToId(new_name.into_bytes())),
                            account_id.serialize(),
                        );
                    }
                }
                (PrincipalAction::Set, PrincipalField::Type, PrincipalValue::Type(new_type))
                    if principal.inner.typ != Type::List && new_type != Type::List =>
                {
                    principal.inner.typ = new_type;
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Secrets,
                    PrincipalValue::StringList(secrets),
                ) => {
                    principal.inner.secrets = secrets;
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Description,
                    PrincipalValue::String(description),
                ) => {
                    if !description.is_empty() {
                        principal.inner.description = Some(description);
                    } else {
                        principal.inner.description = None;
                    }
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::Integer(quota)) => {
                    principal.inner.quota = quota;
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Emails,
                    PrincipalValue::StringList(emails),
                ) => {
                    // Validate unique emails
                    let emails = emails
                        .into_iter()
                        .map(|v| v.to_lowercase())
                        .collect::<Vec<_>>();
                    for email in &emails {
                        if !principal.inner.emails.contains(email) {
                            if self.rcpt(email).await? {
                                return Err(DirectoryError::Management(
                                    ManagementError::NotUniqueField(PrincipalField::Emails),
                                ));
                            }
                            if let Some(domain) = email.split('@').nth(1) {
                                if !self.is_local_domain(domain).await? {
                                    return Err(DirectoryError::Management(
                                        ManagementError::NotFound(domain.to_string()),
                                    ));
                                }
                            }
                            if !is_list {
                                batch.set(
                                    ValueClass::Directory(DirectoryValue::EmailToId(
                                        email.as_bytes().to_vec(),
                                    )),
                                    vec![account_id].serialize(),
                                );
                            }
                        }
                    }
                    if !is_list {
                        for email in &principal.inner.emails {
                            if !emails.contains(email) {
                                batch.clear(ValueClass::Directory(DirectoryValue::EmailToId(
                                    email.as_bytes().to_vec(),
                                )));
                            }
                        }
                    }

                    principal.inner.emails = emails;
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::MemberOf,
                    PrincipalValue::StringList(members),
                ) => {
                    if is_list {
                        has_list_changes = true;
                    }
                    principal.inner.member_of = Vec::with_capacity(members.len());
                    for member in members {
                        let account_id = self.get_account_id(&member).await?.ok_or_else(|| {
                            DirectoryError::Management(ManagementError::NotFound(member))
                        })?;
                        principal.inner.member_of.push(account_id);
                    }
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::MemberOf,
                    PrincipalValue::String(member),
                ) => {
                    let account_id = self.get_account_id(&member).await?.ok_or_else(|| {
                        DirectoryError::Management(ManagementError::NotFound(member))
                    })?;
                    if !principal.inner.member_of.contains(&account_id) {
                        principal.inner.member_of.push(account_id);
                        if is_list {
                            has_list_changes = true;
                        }
                    }
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if !principal.inner.emails.contains(&email) {
                        if self.rcpt(&email).await? {
                            return Err(DirectoryError::Management(
                                ManagementError::NotUniqueField(PrincipalField::Emails),
                            ));
                        }
                        if let Some(domain) = email.split('@').nth(1) {
                            if !self.is_local_domain(domain).await? {
                                return Err(DirectoryError::Management(ManagementError::NotFound(
                                    domain.to_string(),
                                )));
                            }
                        }
                        if !is_list {
                            batch.set(
                                ValueClass::Directory(DirectoryValue::EmailToId(
                                    email.as_bytes().to_vec(),
                                )),
                                vec![account_id].serialize(),
                            );
                        }
                        principal.inner.emails.push(email);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::MemberOf,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(account_id) = self.get_account_id(&member).await? {
                        if let Some(pos) = principal
                            .inner
                            .member_of
                            .iter()
                            .position(|v| *v == account_id)
                        {
                            principal.inner.member_of.remove(pos);
                            if is_list {
                                has_list_changes = true;
                            }
                        }
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if let Some(pos) = principal.inner.emails.iter().position(|v| *v == email) {
                        if !is_list {
                            batch.clear(ValueClass::Directory(DirectoryValue::EmailToId(
                                email.as_bytes().to_vec(),
                            )));
                        }
                        principal.inner.emails.remove(pos);
                    }
                }
                _ => {
                    return Err(DirectoryError::Unsupported);
                }
            }
        }

        if has_list_changes {
            for email in &principal.inner.emails {
                batch.set(
                    ValueClass::Directory(DirectoryValue::EmailToId(email.as_bytes().to_vec())),
                    (&principal.inner.member_of).serialize(),
                );
            }
        }

        batch.set(
            ValueClass::Directory(DirectoryValue::Principal(account_id)),
            principal.inner.serialize(),
        );

        self.write(batch.build()).await?;

        Ok(())
    }

    async fn create_domain(&self, domain: &str) -> crate::Result<()> {
        if !domain.contains('.') {
            return Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name,
            )));
        }
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Directory(DirectoryValue::Domain(domain.to_lowercase().into_bytes())),
            vec![],
        );
        self.write(batch.build()).await.map_err(Into::into)
    }

    async fn delete_domain(&self, domain: &str) -> crate::Result<()> {
        if !domain.contains('.') {
            return Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name,
            )));
        }
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Directory(DirectoryValue::Domain(
            domain.to_lowercase().into_bytes(),
        )));
        self.write(batch.build()).await.map_err(Into::into)
    }

    async fn map_group_ids(&self, principal: Principal<u32>) -> crate::Result<Principal<String>> {
        let mut mapped = Principal {
            id: principal.id,
            typ: principal.typ,
            quota: principal.quota,
            name: principal.name,
            secrets: principal.secrets,
            emails: principal.emails,
            member_of: Vec::with_capacity(principal.member_of.len()),
            description: principal.description,
        };

        for account_id in principal.member_of {
            if let Some(name) = self.get_account_name(account_id).await? {
                mapped.member_of.push(name);
            }
        }

        Ok(mapped)
    }

    async fn map_group_names(
        &self,
        principal: Principal<String>,
        create_if_missing: bool,
    ) -> crate::Result<Principal<u32>> {
        let mut mapped = Principal {
            id: principal.id,
            typ: principal.typ,
            quota: principal.quota,
            name: principal.name,
            secrets: principal.secrets,
            emails: principal.emails,
            member_of: Vec::with_capacity(principal.member_of.len()),
            description: principal.description,
        };

        for member in principal.member_of {
            let account_id = if create_if_missing {
                self.get_or_create_account_id(&member).await?
            } else {
                self.get_account_id(&member)
                    .await?
                    .ok_or_else(|| DirectoryError::Management(ManagementError::NotFound(member)))?
            };
            mapped.member_of.push(account_id);
        }

        Ok(mapped)
    }

    async fn list_accounts(
        &self,
        start_from: Option<&str>,
        limit: usize,
    ) -> crate::Result<Vec<String>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryValue::NameToId(
            start_from.unwrap_or("").as_bytes().to_vec(),
        )));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryValue::NameToId(vec![
            u8::MAX;
            10
        ])));

        let mut results = Vec::with_capacity(limit);
        self.iterate(
            IterateParams::new(from_key, to_key).no_values().ascending(),
            |key, _| {
                results
                    .push(String::from_utf8_lossy(key.get(1..).unwrap_or_default()).into_owned());
                Ok(limit == 0 || results.len() < limit)
            },
        )
        .await?;

        Ok(results)
    }
}

impl From<Principal<String>> for Principal<u32> {
    fn from(principal: Principal<String>) -> Self {
        Principal {
            id: principal.id,
            typ: principal.typ,
            quota: principal.quota,
            name: principal.name,
            secrets: principal.secrets,
            emails: principal.emails,
            member_of: Vec::with_capacity(0),
            description: principal.description,
        }
    }
}
