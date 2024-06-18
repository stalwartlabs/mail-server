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
    write::{
        assert::HashedValue, key::DeserializeBigEndian, AssignedIds, BatchBuilder, DirectoryClass,
        MaybeDynamicId, MaybeDynamicValue, SerializeWithId, ValueClass,
    },
    Deserialize, IterateParams, Serialize, Store, ValueKey, U32_LEN,
};

use crate::{DirectoryError, ManagementError, Principal, QueryBy, Type};

use super::{
    lookup::DirectoryStore, PrincipalAction, PrincipalField, PrincipalIdType, PrincipalUpdate,
    PrincipalValue,
};

#[allow(async_fn_in_trait)]
pub trait ManageDirectory: Sized {
    async fn get_account_id(&self, name: &str) -> crate::Result<Option<u32>>;
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32>;
    async fn get_account_name(&self, account_id: u32) -> crate::Result<Option<String>>;
    async fn get_member_of(&self, account_id: u32) -> crate::Result<Vec<u32>>;
    async fn get_members(&self, account_id: u32) -> crate::Result<Vec<u32>>;
    async fn create_account(
        &self,
        principal: Principal<String>,
        members: Vec<String>,
    ) -> crate::Result<u32>;
    async fn update_account(
        &self,
        by: QueryBy<'_>,
        changes: Vec<PrincipalUpdate>,
    ) -> crate::Result<()>;
    async fn delete_account(&self, by: QueryBy<'_>) -> crate::Result<()>;
    async fn list_accounts(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
    ) -> crate::Result<Vec<String>>;
    async fn map_group_ids(&self, principal: Principal<u32>) -> crate::Result<Principal<String>>;
    async fn map_principal(
        &self,
        principal: Principal<String>,
        create_if_missing: bool,
    ) -> crate::Result<Principal<u32>>;
    async fn map_group_names(
        &self,
        members: Vec<String>,
        create_if_missing: bool,
    ) -> crate::Result<Vec<u32>>;
    async fn create_domain(&self, domain: &str) -> crate::Result<()>;
    async fn delete_domain(&self, domain: &str) -> crate::Result<()>;
    async fn list_domains(&self, filter: Option<&str>) -> crate::Result<Vec<String>>;
}

impl ManageDirectory for Store {
    async fn get_account_name(&self, account_id: u32) -> crate::Result<Option<String>> {
        self.get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::Principal(account_id),
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
        self.get_value::<PrincipalIdType>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::NameToId(name.as_bytes().to_vec()),
        )))
        .await
        .map(|v| v.map(|v| v.account_id))
        .map_err(Into::into)
    }

    // Used by all directories except internal
    async fn get_or_create_account_id(&self, name: &str) -> crate::Result<u32> {
        let mut try_count = 0;
        let name = name.to_lowercase();

        loop {
            // Try to obtain ID
            if let Some(account_id) = self.get_account_id(&name).await? {
                return Ok(account_id);
            }

            // Write account ID
            let name_key =
                ValueClass::Directory(DirectoryClass::NameToId(name.as_bytes().to_vec()));
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .assert_value(name_key.clone(), ())
                .create_document()
                .set(name_key, DynamicPrincipalIdType(Type::Individual))
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Dynamic(0))),
                    Principal {
                        typ: Type::Individual,
                        name: name.to_string(),
                        ..Default::default()
                    },
                );

            match self
                .write(batch.build())
                .await
                .and_then(|r| r.last_document_id())
            {
                Ok(account_id) => {
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

    async fn create_account(
        &self,
        principal: Principal<String>,
        members: Vec<String>,
    ) -> crate::Result<u32> {
        // Make sure the principal has a name
        if principal.name.is_empty() {
            return Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name,
            )));
        }

        // Map group names
        let mut principal = self.map_principal(principal, false).await?;
        let members = self.map_group_names(members, false).await?;

        // Make sure new name is not taken
        principal.name = principal.name.to_lowercase();
        if self.get_account_id(&principal.name).await?.is_some() {
            return Err(DirectoryError::Management(ManagementError::AlreadyExists {
                field: PrincipalField::Name,
                value: principal.name,
            }));
        }

        // Make sure the e-mail is not taken and validate domain
        for email in principal.emails.iter_mut() {
            *email = email.to_lowercase();
            if self.rcpt(email).await? {
                return Err(DirectoryError::Management(ManagementError::AlreadyExists {
                    field: PrincipalField::Emails,
                    value: email.to_string(),
                }));
            }
            if let Some(domain) = email.split('@').nth(1) {
                if !self.is_local_domain(domain).await? {
                    return Err(DirectoryError::Management(ManagementError::NotFound(
                        domain.to_string(),
                    )));
                }
            }
        }

        // Write principal
        let mut batch = BatchBuilder::new();
        let ptype = DynamicPrincipalIdType(principal.typ.into_base_type());
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .create_document()
            .assert_value(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal.name.clone().into_bytes(),
                )),
                (),
            )
            .set(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Dynamic(0))),
                principal.clone(),
            )
            .set(
                ValueClass::Directory(DirectoryClass::NameToId(principal.name.into_bytes())),
                ptype,
            );

        // Write email to id mapping
        for email in principal.emails {
            batch.set(
                ValueClass::Directory(DirectoryClass::EmailToId(email.into_bytes())),
                ptype,
            );
        }

        // Write membership
        for member_of in principal.member_of {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Dynamic(0),
                    member_of: MaybeDynamicId::Static(member_of),
                }),
                vec![],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Static(member_of),
                    has_member: MaybeDynamicId::Dynamic(0),
                }),
                vec![],
            );
        }
        for member_id in members {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Static(member_id),
                    member_of: MaybeDynamicId::Dynamic(0),
                }),
                vec![],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Dynamic(0),
                    has_member: MaybeDynamicId::Static(member_id),
                }),
                vec![],
            );
        }

        self.write(batch.build())
            .await
            .and_then(|r| r.last_document_id())
            .map_err(Into::into)
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
                DirectoryClass::Principal(account_id),
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
            .clear(DirectoryClass::NameToId(principal.name.into_bytes()))
            .clear(DirectoryClass::Principal(MaybeDynamicId::Static(
                account_id,
            )))
            .clear(DirectoryClass::UsedQuota(account_id));

        for email in principal.emails {
            batch.clear(DirectoryClass::EmailToId(email.into_bytes()));
        }

        for member_id in self.get_member_of(account_id).await? {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(account_id),
                member_of: MaybeDynamicId::Static(member_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(member_id),
                has_member: MaybeDynamicId::Static(account_id),
            });
        }

        for member_id in self.get_members(account_id).await? {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(member_id),
                member_of: MaybeDynamicId::Static(account_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(account_id),
                has_member: MaybeDynamicId::Static(member_id),
            });
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
                DirectoryClass::Principal(account_id),
            )))
            .await?
            .ok_or_else(|| {
                DirectoryError::Management(ManagementError::NotFound(account_id.to_string()))
            })?;

        // Obtain members and memberOf
        let mut member_of = self.get_member_of(account_id).await?;
        let mut members = self.get_members(account_id).await?;

        // Apply changes
        let mut batch = BatchBuilder::new();
        let ptype =
            PrincipalIdType::new(account_id, principal.inner.typ.into_base_type()).serialize();
        let update_principal = !changes.is_empty()
            && !changes
                .iter()
                .all(|c| matches!(c.field, PrincipalField::MemberOf | PrincipalField::Members));

        if update_principal {
            batch.assert_value(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                    account_id,
                ))),
                &principal,
            );
        }
        for change in changes {
            match (change.action, change.field, change.value) {
                (PrincipalAction::Set, PrincipalField::Name, PrincipalValue::String(new_name)) => {
                    // Make sure new name is not taken
                    let new_name = new_name.to_lowercase();
                    if principal.inner.name != new_name {
                        if self.get_account_id(&new_name).await?.is_some() {
                            return Err(DirectoryError::Management(
                                ManagementError::AlreadyExists {
                                    field: PrincipalField::Name,
                                    value: new_name,
                                },
                            ));
                        }

                        batch.clear(ValueClass::Directory(DirectoryClass::NameToId(
                            principal.inner.name.as_bytes().to_vec(),
                        )));

                        principal.inner.name.clone_from(&new_name);

                        batch.set(
                            ValueClass::Directory(DirectoryClass::NameToId(new_name.into_bytes())),
                            ptype.clone(),
                        );
                    }
                }
                (PrincipalAction::Set, PrincipalField::Type, PrincipalValue::String(new_type)) => {
                    if let Some(new_type) = Type::parse(&new_type) {
                        if matches!(principal.inner.typ, Type::Individual | Type::Superuser)
                            && matches!(new_type, Type::Individual | Type::Superuser)
                        {
                            principal.inner.typ = new_type;
                            continue;
                        }
                    }
                    return Err(DirectoryError::Unsupported);
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

                // Emails
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
                                    ManagementError::AlreadyExists {
                                        field: PrincipalField::Emails,
                                        value: email.to_string(),
                                    },
                                ));
                            }
                            if let Some(domain) = email.split('@').nth(1) {
                                if !self.is_local_domain(domain).await? {
                                    return Err(DirectoryError::Management(
                                        ManagementError::NotFound(domain.to_string()),
                                    ));
                                }
                            }
                            batch.set(
                                ValueClass::Directory(DirectoryClass::EmailToId(
                                    email.as_bytes().to_vec(),
                                )),
                                ptype.clone(),
                            );
                        }
                    }

                    for email in &principal.inner.emails {
                        if !emails.contains(email) {
                            batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )));
                        }
                    }

                    principal.inner.emails = emails;
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
                                ManagementError::AlreadyExists {
                                    field: PrincipalField::Emails,
                                    value: email,
                                },
                            ));
                        }
                        if let Some(domain) = email.split('@').nth(1) {
                            if !self.is_local_domain(domain).await? {
                                return Err(DirectoryError::Management(ManagementError::NotFound(
                                    domain.to_string(),
                                )));
                            }
                        }
                        batch.set(
                            ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )),
                            ptype.clone(),
                        );
                        principal.inner.emails.push(email);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if let Some(pos) = principal.inner.emails.iter().position(|v| *v == email) {
                        batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                            email.as_bytes().to_vec(),
                        )));
                        principal.inner.emails.remove(pos);
                    }
                }

                // MemberOf
                (
                    PrincipalAction::Set,
                    PrincipalField::MemberOf,
                    PrincipalValue::StringList(members),
                ) => {
                    let mut new_member_of = Vec::new();
                    for member in members {
                        let member_id = self.get_account_id(&member).await?.ok_or_else(|| {
                            DirectoryError::Management(ManagementError::NotFound(member))
                        })?;
                        if !member_of.contains(&member_id) {
                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: MaybeDynamicId::Static(account_id),
                                    member_of: MaybeDynamicId::Static(member_id),
                                }),
                                vec![],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: MaybeDynamicId::Static(member_id),
                                    has_member: MaybeDynamicId::Static(account_id),
                                }),
                                vec![],
                            );
                        }

                        new_member_of.push(member_id);
                    }

                    for member_id in &member_of {
                        if !new_member_of.contains(member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(account_id),
                                member_of: MaybeDynamicId::Static(*member_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(*member_id),
                                has_member: MaybeDynamicId::Static(account_id),
                            }));
                        }
                    }

                    member_of = new_member_of;
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::MemberOf,
                    PrincipalValue::String(member),
                ) => {
                    let member_id = self.get_account_id(&member).await?.ok_or_else(|| {
                        DirectoryError::Management(ManagementError::NotFound(member))
                    })?;
                    if !member_of.contains(&member_id) {
                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(account_id),
                                member_of: MaybeDynamicId::Static(member_id),
                            }),
                            vec![],
                        );
                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(member_id),
                                has_member: MaybeDynamicId::Static(account_id),
                            }),
                            vec![],
                        );
                        member_of.push(member_id);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::MemberOf,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(member_id) = self.get_account_id(&member).await? {
                        if let Some(pos) = member_of.iter().position(|v| *v == member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(account_id),
                                member_of: MaybeDynamicId::Static(member_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(member_id),
                                has_member: MaybeDynamicId::Static(account_id),
                            }));
                            member_of.remove(pos);
                        }
                    }
                }

                (
                    PrincipalAction::Set,
                    PrincipalField::Members,
                    PrincipalValue::StringList(members_),
                ) => {
                    let mut new_members = Vec::new();
                    for member in members_ {
                        let member_id = self.get_account_id(&member).await?.ok_or_else(|| {
                            DirectoryError::Management(ManagementError::NotFound(member))
                        })?;
                        if !members.contains(&member_id) {
                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: MaybeDynamicId::Static(member_id),
                                    member_of: MaybeDynamicId::Static(account_id),
                                }),
                                vec![],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: MaybeDynamicId::Static(account_id),
                                    has_member: MaybeDynamicId::Static(member_id),
                                }),
                                vec![],
                            );
                        }

                        new_members.push(member_id);
                    }

                    for member_id in &members {
                        if !new_members.contains(member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(*member_id),
                                member_of: MaybeDynamicId::Static(account_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(account_id),
                                has_member: MaybeDynamicId::Static(*member_id),
                            }));
                        }
                    }

                    members = new_members;
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Members,
                    PrincipalValue::String(member),
                ) => {
                    let member_id = self.get_account_id(&member).await?.ok_or_else(|| {
                        DirectoryError::Management(ManagementError::NotFound(member))
                    })?;
                    if !members.contains(&member_id) {
                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(member_id),
                                member_of: MaybeDynamicId::Static(account_id),
                            }),
                            vec![],
                        );
                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(account_id),
                                has_member: MaybeDynamicId::Static(member_id),
                            }),
                            vec![],
                        );
                        members.push(member_id);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Members,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(member_id) = self.get_account_id(&member).await? {
                        if let Some(pos) = members.iter().position(|v| *v == member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(member_id),
                                member_of: MaybeDynamicId::Static(account_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(account_id),
                                has_member: MaybeDynamicId::Static(member_id),
                            }));
                            members.remove(pos);
                        }
                    }
                }

                _ => {
                    return Err(DirectoryError::Unsupported);
                }
            }
        }

        if update_principal {
            batch.set(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                    account_id,
                ))),
                principal.inner.serialize(),
            );
        }

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
            ValueClass::Directory(DirectoryClass::Domain(domain.to_lowercase().into_bytes())),
            vec![],
        );
        self.write(batch.build())
            .await
            .map_err(Into::into)
            .map(|_| ())
    }

    async fn delete_domain(&self, domain: &str) -> crate::Result<()> {
        if !domain.contains('.') {
            return Err(DirectoryError::Management(ManagementError::MissingField(
                PrincipalField::Name,
            )));
        }
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Directory(DirectoryClass::Domain(
            domain.to_lowercase().into_bytes(),
        )));
        self.write(batch.build())
            .await
            .map_err(Into::into)
            .map(|_| ())
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

    async fn map_principal(
        &self,
        principal: Principal<String>,
        create_if_missing: bool,
    ) -> crate::Result<Principal<u32>> {
        Ok(Principal {
            id: principal.id,
            typ: principal.typ,
            quota: principal.quota,
            name: principal.name,
            secrets: principal.secrets,
            emails: principal.emails,
            member_of: self
                .map_group_names(principal.member_of, create_if_missing)
                .await?,
            description: principal.description,
        })
    }

    async fn map_group_names(
        &self,
        members: Vec<String>,
        create_if_missing: bool,
    ) -> crate::Result<Vec<u32>> {
        let mut member_ids = Vec::with_capacity(members.len());

        for member in members {
            let account_id = if create_if_missing {
                self.get_or_create_account_id(&member).await?
            } else {
                self.get_account_id(&member)
                    .await?
                    .ok_or_else(|| DirectoryError::Management(ManagementError::NotFound(member)))?
            };
            member_ids.push(account_id);
        }

        Ok(member_ids)
    }

    async fn list_accounts(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
    ) -> crate::Result<Vec<String>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![
            u8::MAX;
            10
        ])));

        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let pt = PrincipalIdType::deserialize(value)?;

                if typ.map_or(true, |t| pt.typ == t) {
                    results.push((
                        pt.account_id,
                        String::from_utf8_lossy(key.get(1..).unwrap_or_default()).into_owned(),
                    ));
                }

                Ok(true)
            },
        )
        .await?;

        if let Some(filter) = filter {
            let mut filtered = Vec::new();
            let filters = filter
                .split_whitespace()
                .map(|r| r.to_lowercase())
                .collect::<Vec<_>>();

            for (account_id, account_name) in results {
                let principal = self
                    .get_value::<Principal<u32>>(ValueKey::from(ValueClass::Directory(
                        DirectoryClass::Principal(account_id),
                    )))
                    .await?
                    .ok_or_else(|| {
                        DirectoryError::Management(ManagementError::NotFound(
                            account_id.to_string(),
                        ))
                    })?;
                if filters.iter().all(|f| {
                    principal.name.to_lowercase().contains(f)
                        || principal
                            .description
                            .as_ref()
                            .map_or(false, |d| d.to_lowercase().contains(f))
                        || principal
                            .emails
                            .iter()
                            .any(|email| email.to_lowercase().contains(f))
                }) {
                    filtered.push(account_name);
                }
            }

            Ok(filtered)
        } else {
            Ok(results.into_iter().map(|(_, name)| name).collect())
        }
    }

    async fn list_domains(&self, filter: Option<&str>) -> crate::Result<Vec<String>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Domain(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Domain(vec![
            u8::MAX;
            10
        ])));

        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).no_values().ascending(),
            |key, _| {
                let domain = String::from_utf8_lossy(key.get(1..).unwrap_or_default()).into_owned();
                if filter.map_or(true, |f| domain.contains(f)) {
                    results.push(domain);
                }
                Ok(true)
            },
        )
        .await?;

        Ok(results)
    }

    async fn get_member_of(&self, account_id: u32) -> crate::Result<Vec<u32>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::MemberOf {
            principal_id: account_id,
            member_of: 0,
        }));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::MemberOf {
            principal_id: account_id,
            member_of: u32::MAX,
        }));
        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).no_values(),
            |key, _| {
                results.push(key.deserialize_be_u32(key.len() - U32_LEN)?);
                Ok(true)
            },
        )
        .await?;
        Ok(results)
    }

    async fn get_members(&self, account_id: u32) -> crate::Result<Vec<u32>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Members {
            principal_id: account_id,
            has_member: 0,
        }));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Members {
            principal_id: account_id,
            has_member: u32::MAX,
        }));
        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).no_values(),
            |key, _| {
                results.push(key.deserialize_be_u32(key.len() - U32_LEN)?);
                Ok(true)
            },
        )
        .await?;
        Ok(results)
    }
}

impl SerializeWithId for Principal<u32> {
    fn serialize_with_id(&self, ids: &AssignedIds) -> store::Result<Vec<u8>> {
        let mut principal = self.clone();
        principal.id = ids.last_document_id()?;
        Ok(principal.serialize())
    }
}

impl From<Principal<u32>> for MaybeDynamicValue {
    fn from(principal: Principal<u32>) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(principal))
    }
}

#[derive(Clone, Copy)]
struct DynamicPrincipalIdType(Type);

impl SerializeWithId for DynamicPrincipalIdType {
    fn serialize_with_id(&self, ids: &AssignedIds) -> store::Result<Vec<u8>> {
        ids.last_document_id()
            .map(|account_id| PrincipalIdType::new(account_id, self.0).serialize())
    }
}

impl From<DynamicPrincipalIdType> for MaybeDynamicValue {
    fn from(value: DynamicPrincipalIdType) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(value))
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
