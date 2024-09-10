/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::collection::Collection;
use store::{
    write::{
        assert::HashedValue, key::DeserializeBigEndian, AssignedIds, BatchBuilder, DirectoryClass,
        MaybeDynamicId, MaybeDynamicValue, SerializeWithId, ValueClass,
    },
    Deserialize, IterateParams, Serialize, Store, ValueKey, U32_LEN,
};
use trc::AddContext;

use crate::{Principal, QueryBy, Type};

use super::{
    lookup::DirectoryStore, PrincipalAction, PrincipalField, PrincipalIdType, PrincipalUpdate,
    PrincipalValue, SpecialSecrets,
};

#[allow(async_fn_in_trait)]
pub trait ManageDirectory: Sized {
    async fn get_account_id(&self, name: &str) -> trc::Result<Option<u32>>;
    async fn get_or_create_account_id(&self, name: &str) -> trc::Result<u32>;
    async fn get_account_name(&self, account_id: u32) -> trc::Result<Option<String>>;
    async fn get_member_of(&self, account_id: u32) -> trc::Result<Vec<u32>>;
    async fn get_members(&self, account_id: u32) -> trc::Result<Vec<u32>>;
    async fn create_account(&self, principal: Principal) -> trc::Result<u32>;
    async fn update_account(
        &self,
        by: QueryBy<'_>,
        changes: Vec<PrincipalUpdate>,
    ) -> trc::Result<()>;
    async fn delete_account(&self, by: QueryBy<'_>) -> trc::Result<()>;
    async fn list_accounts(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
    ) -> trc::Result<Vec<String>>;
    async fn map_group_ids(&self, principal: Principal) -> trc::Result<Principal>;
    async fn map_principal(
        &self,
        principal: Principal,
        create_if_missing: bool,
    ) -> trc::Result<Principal>;
    async fn map_group_names(
        &self,
        members: Vec<String>,
        create_if_missing: bool,
    ) -> trc::Result<Vec<u32>>;
    async fn create_domain(&self, domain: &str) -> trc::Result<()>;
    async fn delete_domain(&self, domain: &str) -> trc::Result<()>;
    async fn list_domains(&self, filter: Option<&str>) -> trc::Result<Vec<String>>;
}

impl ManageDirectory for Store {
    async fn get_account_name(&self, account_id: u32) -> trc::Result<Option<String>> {
        self.get_value::<Principal>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::Principal(account_id),
        )))
        .await
        .map(|v| v.and_then(|mut v| v.take_str(PrincipalField::Name)))
        .caused_by(trc::location!())
    }

    async fn get_account_id(&self, name: &str) -> trc::Result<Option<u32>> {
        self.get_value::<PrincipalIdType>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::NameToId(name.as_bytes().to_vec()),
        )))
        .await
        .map(|v| v.map(|v| v.account_id))
        .caused_by(trc::location!())
    }

    // Used by all directories except internal
    async fn get_or_create_account_id(&self, name: &str) -> trc::Result<u32> {
        let mut try_count = 0;
        let name = name.to_lowercase();

        loop {
            // Try to obtain ID
            if let Some(account_id) = self
                .get_account_id(&name)
                .await
                .caused_by(trc::location!())?
            {
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
                        ..Default::default()
                    }
                    .with_field(PrincipalField::Name, name.to_string()),
                );

            match self
                .write(batch.build())
                .await
                .and_then(|r| r.last_document_id())
            {
                Ok(account_id) => {
                    return Ok(account_id);
                }
                Err(err) => {
                    if err.is_assertion_failure() && try_count < 3 {
                        try_count += 1;
                        continue;
                    } else {
                        return Err(err.caused_by(trc::location!()));
                    }
                }
            }
        }
    }

    async fn create_account(&self, mut principal: Principal) -> trc::Result<u32> {
        // Make sure the principal has a name
        let name = principal.name().to_lowercase();
        if name.is_empty() {
            return Err(err_missing(PrincipalField::Name));
        }

        // Map group names
        let members = self
            .map_group_names(
                principal
                    .take(PrincipalField::Members)
                    .map(|v| v.into_str_array())
                    .unwrap_or_default(),
                false,
            )
            .await
            .caused_by(trc::location!())?;
        let mut principal = self
            .map_principal(principal, false)
            .await
            .caused_by(trc::location!())?;

        // Make sure new name is not taken
        if self
            .get_account_id(&name)
            .await
            .caused_by(trc::location!())?
            .is_some()
        {
            return Err(err_exists(PrincipalField::Name, name));
        }
        principal.set(PrincipalField::Name, name);

        // Make sure the e-mail is not taken and validate domain
        for email in principal.iter_mut_str(PrincipalField::Emails) {
            *email = email.to_lowercase();
            if self.rcpt(email).await.caused_by(trc::location!())? {
                return Err(err_exists(PrincipalField::Emails, email.to_string()));
            }
            if let Some(domain) = email.split('@').nth(1) {
                if !self
                    .is_local_domain(domain)
                    .await
                    .caused_by(trc::location!())?
                {
                    return Err(not_found(domain.to_string()));
                }
            }
        }

        // Write principal
        let mut batch = BatchBuilder::new();
        let ptype = DynamicPrincipalIdType(principal.typ);
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .create_document()
            .assert_value(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal.name().to_string().into_bytes(),
                )),
                (),
            )
            .set(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Dynamic(0))),
                principal.clone(),
            )
            .set(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal
                        .take_str(PrincipalField::Name)
                        .unwrap()
                        .into_bytes(),
                )),
                ptype,
            );

        // Write email to id mapping
        if let Some(emails) = principal
            .take(PrincipalField::Emails)
            .map(|v| v.into_str_array())
        {
            for email in emails {
                batch.set(
                    ValueClass::Directory(DirectoryClass::EmailToId(email.into_bytes())),
                    ptype,
                );
            }
        }

        // Write membership
        for member_of in principal.iter_int(PrincipalField::MemberOf) {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Dynamic(0),
                    member_of: MaybeDynamicId::Static(member_of as u32),
                }),
                vec![],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Static(member_of as u32),
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
    }

    async fn delete_account(&self, by: QueryBy<'_>) -> trc::Result<()> {
        let account_id = match by {
            QueryBy::Name(name) => self
                .get_account_id(name)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| not_found(name.to_string()))?,
            QueryBy::Id(account_id) => account_id,
            QueryBy::Credentials(_) => unreachable!(),
        };

        let mut principal = self
            .get_value::<Principal>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(account_id),
            )))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(account_id.to_string()))?;

        // Unlink all account's blobs
        self.blob_hash_unlink_account(account_id)
            .await
            .caused_by(trc::location!())?;

        // Revoke ACLs
        self.acl_revoke_all(account_id)
            .await
            .caused_by(trc::location!())?;

        // Delete account data
        self.purge_account(account_id)
            .await
            .caused_by(trc::location!())?;

        // Delete account
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .clear(DirectoryClass::NameToId(
                principal
                    .take_str(PrincipalField::Name)
                    .unwrap_or_default()
                    .into_bytes(),
            ))
            .clear(DirectoryClass::Principal(MaybeDynamicId::Static(
                account_id,
            )))
            .clear(DirectoryClass::UsedQuota(account_id));

        if let Some(emails) = principal.take_str_array(PrincipalField::Emails) {
            for email in emails {
                batch.clear(DirectoryClass::EmailToId(email.into_bytes()));
            }
        }

        for member_id in self
            .get_member_of(account_id)
            .await
            .caused_by(trc::location!())?
        {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(account_id),
                member_of: MaybeDynamicId::Static(member_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(member_id),
                has_member: MaybeDynamicId::Static(account_id),
            });
        }

        for member_id in self
            .get_members(account_id)
            .await
            .caused_by(trc::location!())?
        {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(member_id),
                member_of: MaybeDynamicId::Static(account_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(account_id),
                has_member: MaybeDynamicId::Static(member_id),
            });
        }

        self.write(batch.build())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn update_account(
        &self,
        by: QueryBy<'_>,
        changes: Vec<PrincipalUpdate>,
    ) -> trc::Result<()> {
        let account_id = match by {
            QueryBy::Name(name) => self
                .get_account_id(name)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| not_found(name.to_string()))?,
            QueryBy::Id(account_id) => account_id,
            QueryBy::Credentials(_) => unreachable!(),
        };

        // Fetch principal
        let mut principal = self
            .get_value::<HashedValue<Principal>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(account_id),
            )))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(account_id.to_string()))?;

        // Obtain members and memberOf
        let mut member_of = self
            .get_member_of(account_id)
            .await
            .caused_by(trc::location!())?;
        let mut members = self
            .get_members(account_id)
            .await
            .caused_by(trc::location!())?;

        // Apply changes
        let mut batch = BatchBuilder::new();
        let ptype = PrincipalIdType::new(account_id, principal.inner.typ).serialize();
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
                    if principal.inner.name() != new_name {
                        if self
                            .get_account_id(&new_name)
                            .await
                            .caused_by(trc::location!())?
                            .is_some()
                        {
                            return Err(err_exists(PrincipalField::Name, new_name));
                        }

                        batch.clear(ValueClass::Directory(DirectoryClass::NameToId(
                            principal.inner.name().as_bytes().to_vec(),
                        )));

                        principal.inner.set(PrincipalField::Name, new_name.clone());

                        batch.set(
                            ValueClass::Directory(DirectoryClass::NameToId(new_name.into_bytes())),
                            ptype.clone(),
                        );
                    }
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Secrets,
                    value @ (PrincipalValue::StringList(_) | PrincipalValue::String(_)),
                ) => {
                    principal.inner.set(PrincipalField::Secrets, value);
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Secrets,
                    PrincipalValue::String(secret),
                ) => {
                    if !principal
                        .inner
                        .has_str_value(PrincipalField::Secrets, &secret)
                    {
                        if secret.is_otp_auth() {
                            // Add OTP Auth URLs to the beginning of the list
                            principal.inner.prepend_str(PrincipalField::Secrets, secret);
                        } else {
                            principal.inner.append_str(PrincipalField::Secrets, secret);
                        }
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Secrets,
                    PrincipalValue::String(secret),
                ) => {
                    if secret.is_app_password() || secret.is_otp_auth() {
                        principal.inner.retain_str(PrincipalField::Secrets, |v| {
                            *v != secret && !v.starts_with(&secret)
                        });
                    } else if !secret.is_empty() {
                        principal
                            .inner
                            .retain_str(PrincipalField::Secrets, |v| *v != secret);
                    } else {
                        principal
                            .inner
                            .retain_str(PrincipalField::Secrets, |v| !v.is_password());
                    }
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Description,
                    PrincipalValue::String(description),
                ) => {
                    if !description.is_empty() {
                        principal
                            .inner
                            .set(PrincipalField::Description, description);
                    } else {
                        principal.inner.remove(PrincipalField::Description);
                    }
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::Integer(quota)) => {
                    principal.inner.set(PrincipalField::Quota, quota);
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
                        if !principal.inner.has_str_value(PrincipalField::Emails, email) {
                            if self.rcpt(email).await.caused_by(trc::location!())? {
                                return Err(err_exists(PrincipalField::Emails, email.to_string()));
                            }
                            if let Some(domain) = email.split('@').nth(1) {
                                if !self
                                    .is_local_domain(domain)
                                    .await
                                    .caused_by(trc::location!())?
                                {
                                    return Err(not_found(domain.to_string()));
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

                    for email in principal.inner.iter_str(PrincipalField::Emails) {
                        if !emails.contains(email) {
                            batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )));
                        }
                    }

                    principal.inner.set(PrincipalField::Emails, emails);
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if !principal
                        .inner
                        .has_str_value(PrincipalField::Emails, &email)
                    {
                        if self.rcpt(&email).await.caused_by(trc::location!())? {
                            return Err(err_exists(PrincipalField::Emails, email));
                        }
                        if let Some(domain) = email.split('@').nth(1) {
                            if !self
                                .is_local_domain(domain)
                                .await
                                .caused_by(trc::location!())?
                            {
                                return Err(not_found(domain.to_string()));
                            }
                        }
                        batch.set(
                            ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )),
                            ptype.clone(),
                        );
                        principal.inner.append_str(PrincipalField::Emails, email);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if principal
                        .inner
                        .has_str_value(PrincipalField::Emails, &email)
                    {
                        principal
                            .inner
                            .retain_str(PrincipalField::Emails, |v| *v != email);
                        batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                            email.into_bytes(),
                        )));
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
                        let member_id = self
                            .get_account_id(&member)
                            .await
                            .caused_by(trc::location!())?
                            .ok_or_else(|| not_found(member))?;
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
                    let member_id = self
                        .get_account_id(&member)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or_else(|| not_found(member))?;
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
                    if let Some(member_id) = self
                        .get_account_id(&member)
                        .await
                        .caused_by(trc::location!())?
                    {
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
                        let member_id = self
                            .get_account_id(&member)
                            .await
                            .caused_by(trc::location!())?
                            .ok_or_else(|| not_found(member))?;
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
                    let member_id = self
                        .get_account_id(&member)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or_else(|| not_found(member))?;
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
                    if let Some(member_id) = self
                        .get_account_id(&member)
                        .await
                        .caused_by(trc::location!())?
                    {
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
                    return Err(trc::StoreEvent::NotSupported.caused_by(trc::location!()));
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

        self.write(batch.build())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn create_domain(&self, domain: &str) -> trc::Result<()> {
        if !domain.contains('.') {
            return Err(err_missing(PrincipalField::Name));
        }
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Directory(DirectoryClass::Domain(domain.to_lowercase().into_bytes())),
            vec![],
        );
        self.write(batch.build()).await.map(|_| ())
    }

    async fn delete_domain(&self, domain: &str) -> trc::Result<()> {
        if !domain.contains('.') {
            return Err(err_missing(PrincipalField::Name));
        }
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Directory(DirectoryClass::Domain(
            domain.to_lowercase().into_bytes(),
        )));
        self.write(batch.build()).await.map(|_| ())
    }

    async fn map_group_ids(&self, mut principal: Principal) -> trc::Result<Principal> {
        if let Some(member_of) = principal.take_int_array(PrincipalField::MemberOf) {
            for account_id in member_of {
                if let Some(name) = self
                    .get_account_name(account_id as u32)
                    .await
                    .caused_by(trc::location!())?
                {
                    principal.append_str(PrincipalField::MemberOf, name);
                }
            }
        }

        Ok(principal)
    }

    async fn map_principal(
        &self,
        mut principal: Principal,
        create_if_missing: bool,
    ) -> trc::Result<Principal> {
        if let Some(member_of) = principal.take_str_array(PrincipalField::MemberOf) {
            principal.set(
                PrincipalField::MemberOf,
                self.map_group_names(member_of, create_if_missing)
                    .await
                    .caused_by(trc::location!())?,
            );
        }

        Ok(principal)
    }

    async fn map_group_names(
        &self,
        members: Vec<String>,
        create_if_missing: bool,
    ) -> trc::Result<Vec<u32>> {
        let mut member_ids = Vec::with_capacity(members.len());

        for member in members {
            let account_id = if create_if_missing {
                self.get_or_create_account_id(&member)
                    .await
                    .caused_by(trc::location!())?
            } else {
                self.get_account_id(&member)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| not_found(member))?
            };
            member_ids.push(account_id);
        }

        Ok(member_ids)
    }

    async fn list_accounts(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
    ) -> trc::Result<Vec<String>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![
            u8::MAX;
            10
        ])));

        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let pt = PrincipalIdType::deserialize(value).caused_by(trc::location!())?;

                if typ.map_or(true, |t| pt.typ == t) {
                    results.push((
                        pt.account_id,
                        String::from_utf8_lossy(key.get(1..).unwrap_or_default()).into_owned(),
                    ));
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if let Some(filter) = filter {
            let mut filtered = Vec::new();
            let filters = filter
                .split_whitespace()
                .map(|r| r.to_lowercase())
                .collect::<Vec<_>>();

            for (account_id, account_name) in results {
                let principal = self
                    .get_value::<Principal>(ValueKey::from(ValueClass::Directory(
                        DirectoryClass::Principal(account_id),
                    )))
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| not_found(account_id.to_string()))?;
                if filters.iter().all(|f| {
                    principal.name().to_lowercase().contains(f)
                        || principal
                            .description()
                            .as_ref()
                            .map_or(false, |d| d.to_lowercase().contains(f))
                        || principal
                            .iter_str(PrincipalField::Emails)
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

    async fn list_domains(&self, filter: Option<&str>) -> trc::Result<Vec<String>> {
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
        .await
        .caused_by(trc::location!())?;

        Ok(results)
    }

    async fn get_member_of(&self, account_id: u32) -> trc::Result<Vec<u32>> {
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
        .await
        .caused_by(trc::location!())?;
        Ok(results)
    }

    async fn get_members(&self, account_id: u32) -> trc::Result<Vec<u32>> {
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
        .await
        .caused_by(trc::location!())?;
        Ok(results)
    }
}

impl SerializeWithId for Principal {
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>> {
        let mut principal = self.clone();
        principal.id = ids.last_document_id().caused_by(trc::location!())?;
        Ok(principal.serialize())
    }
}

impl From<Principal> for MaybeDynamicValue {
    fn from(principal: Principal) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(principal))
    }
}

#[derive(Clone, Copy)]
struct DynamicPrincipalIdType(Type);

impl SerializeWithId for DynamicPrincipalIdType {
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>> {
        ids.last_document_id()
            .map(|account_id| PrincipalIdType::new(account_id, self.0).serialize())
    }
}

impl From<DynamicPrincipalIdType> for MaybeDynamicValue {
    fn from(value: DynamicPrincipalIdType) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(value))
    }
}

pub fn err_missing(field: impl Into<trc::Value>) -> trc::Error {
    trc::ManageEvent::MissingParameter.ctx(trc::Key::Key, field)
}

pub fn err_exists(field: impl Into<trc::Value>, value: impl Into<trc::Value>) -> trc::Error {
    trc::ManageEvent::AlreadyExists
        .ctx(trc::Key::Key, field)
        .ctx(trc::Key::Value, value)
}

pub fn not_found(value: impl Into<trc::Value>) -> trc::Error {
    trc::ManageEvent::NotFound.ctx(trc::Key::Key, value)
}

pub fn unsupported(details: impl Into<trc::Value>) -> trc::Error {
    trc::ManageEvent::NotSupported.ctx(trc::Key::Details, details)
}

pub fn enterprise() -> trc::Error {
    trc::ManageEvent::NotSupported.ctx(trc::Key::Details, "Enterprise feature")
}

pub fn error(details: impl Into<trc::Value>, reason: Option<impl Into<trc::Value>>) -> trc::Error {
    trc::ManageEvent::Error
        .ctx(trc::Key::Details, details)
        .ctx_opt(trc::Key::Reason, reason)
}

impl From<PrincipalField> for trc::Value {
    fn from(value: PrincipalField) -> Self {
        trc::Value::Static(value.as_str())
    }
}
