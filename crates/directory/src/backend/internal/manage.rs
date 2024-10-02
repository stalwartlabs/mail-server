/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use jmap_proto::types::collection::Collection;
use store::{
    write::{
        assert::HashedValue, key::DeserializeBigEndian, AssignedIds, BatchBuilder, DirectoryClass,
        MaybeDynamicId, MaybeDynamicValue, SerializeWithId, ValueClass,
    },
    Deserialize, IterateParams, Serialize, Store, ValueKey, U32_LEN,
};
use trc::AddContext;

use crate::{
    Permission, Principal, QueryBy, Type, MAX_TYPE_ID, ROLE_ADMIN, ROLE_TENANT_ADMIN, ROLE_USER,
};

use super::{
    lookup::DirectoryStore, PrincipalAction, PrincipalField, PrincipalInfo, PrincipalUpdate,
    PrincipalValue, SpecialSecrets,
};

pub struct MemberOf {
    pub principal_id: u32,
    pub typ: Type,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PrincipalList {
    pub items: Vec<Principal>,
    pub total: u64,
}

pub struct UpdatePrincipal<'x> {
    query: QueryBy<'x>,
    changes: Vec<PrincipalUpdate>,
    tenant_id: Option<u32>,
    create_domains: bool,
}

#[allow(async_fn_in_trait)]
pub trait ManageDirectory: Sized {
    async fn get_principal_id(&self, name: &str) -> trc::Result<Option<u32>>;
    async fn get_principal_info(&self, name: &str) -> trc::Result<Option<PrincipalInfo>>;
    async fn get_or_create_principal_id(&self, name: &str, typ: Type) -> trc::Result<u32>;
    async fn get_principal(&self, principal_id: u32) -> trc::Result<Option<Principal>>;
    async fn get_member_of(&self, principal_id: u32) -> trc::Result<Vec<MemberOf>>;
    async fn get_members(&self, principal_id: u32) -> trc::Result<Vec<u32>>;
    async fn create_principal(
        &self,
        principal: Principal,
        tenant_id: Option<u32>,
    ) -> trc::Result<u32>;
    async fn update_principal(&self, params: UpdatePrincipal<'_>) -> trc::Result<()>;
    async fn delete_principal(&self, by: QueryBy<'_>) -> trc::Result<()>;
    async fn list_principals(
        &self,
        filter: Option<&str>,
        tenant_id: Option<u32>,
        types: &[Type],
        fields: &[PrincipalField],
        page: usize,
        limit: usize,
    ) -> trc::Result<PrincipalList>;
    async fn count_principals(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
        tenant_id: Option<u32>,
    ) -> trc::Result<u64>;
    async fn map_field_ids(
        &self,
        principal: &mut Principal,
        fields: &[PrincipalField],
    ) -> trc::Result<()>;
}

#[allow(async_fn_in_trait)]
trait ValidateDirectory: Sized {
    async fn validate_email(
        &self,
        email: &str,
        tenant_id: Option<u32>,
        create_if_missing: bool,
    ) -> trc::Result<()>;
}

impl ManageDirectory for Store {
    async fn get_principal(&self, principal_id: u32) -> trc::Result<Option<Principal>> {
        self.get_value::<Principal>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::Principal(principal_id),
        )))
        .await
        .caused_by(trc::location!())
        .map(|v| {
            v.map(|mut v| {
                v.id = principal_id;
                v
            })
        })
    }

    async fn get_principal_id(&self, name: &str) -> trc::Result<Option<u32>> {
        self.get_principal_info(name).await.map(|v| v.map(|v| v.id))
    }
    async fn get_principal_info(&self, name: &str) -> trc::Result<Option<PrincipalInfo>> {
        self.get_value::<PrincipalInfo>(ValueKey::from(ValueClass::Directory(
            DirectoryClass::NameToId(name.as_bytes().to_vec()),
        )))
        .await
        .caused_by(trc::location!())
    }

    // Used by all directories except internal
    async fn get_or_create_principal_id(&self, name: &str, typ: Type) -> trc::Result<u32> {
        let mut try_count = 0;
        let name = name.to_lowercase();

        loop {
            // Try to obtain ID
            if let Some(principal_id) = self
                .get_principal_id(&name)
                .await
                .caused_by(trc::location!())?
            {
                return Ok(principal_id);
            }

            // Write principal ID
            let name_key =
                ValueClass::Directory(DirectoryClass::NameToId(name.as_bytes().to_vec()));
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .assert_value(name_key.clone(), ())
                .create_document()
                .set(name_key, DynamicPrincipalInfo::new(typ, None))
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Dynamic(0))),
                    Principal {
                        typ,
                        ..Default::default()
                    }
                    .with_field(PrincipalField::Name, name.to_string()),
                );

            // Add default user role
            if typ == Type::Individual {
                batch
                    .set(
                        ValueClass::Directory(DirectoryClass::MemberOf {
                            principal_id: MaybeDynamicId::Dynamic(0),
                            member_of: MaybeDynamicId::Static(ROLE_USER),
                        }),
                        vec![Type::Role as u8],
                    )
                    .set(
                        ValueClass::Directory(DirectoryClass::Members {
                            principal_id: MaybeDynamicId::Static(ROLE_USER),
                            has_member: MaybeDynamicId::Dynamic(0),
                        }),
                        vec![],
                    );
            }

            match self
                .write(batch.build())
                .await
                .and_then(|r| r.last_document_id())
            {
                Ok(principal_id) => {
                    return Ok(principal_id);
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

    async fn create_principal(
        &self,
        mut principal: Principal,
        mut tenant_id: Option<u32>,
    ) -> trc::Result<u32> {
        // Make sure the principal has a name
        let name = principal.name().to_lowercase();
        if name.is_empty() {
            return Err(err_missing(PrincipalField::Name));
        }
        let mut valid_domains: AHashSet<String> = AHashSet::new();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Validate tenant
        #[cfg(feature = "enterprise")]
        if let Some(tenant_id) = tenant_id {
            let tenant = self
                .query(QueryBy::Id(tenant_id), false)
                .await?
                .ok_or_else(|| {
                    trc::ManageEvent::NotFound
                        .into_err()
                        .id(tenant_id)
                        .details("Tenant not found")
                        .caused_by(trc::location!())
                })?;

            // Enforce tenant quotas
            if let Some(limit) = tenant
                .get_int_array(PrincipalField::Quota)
                .and_then(|quotas| quotas.get(principal.typ() as usize + 1))
                .copied()
                .filter(|q| *q > 0)
            {
                // Obtain number of principals
                let total = self
                    .count_principals(None, principal.typ().into(), tenant_id.into())
                    .await
                    .caused_by(trc::location!())?;

                if total >= limit {
                    trc::bail!(trc::LimitEvent::TenantQuota
                        .into_err()
                        .details("Tenant principal quota exceeded")
                        .ctx(trc::Key::Details, principal.typ().as_str())
                        .ctx(trc::Key::Limit, limit)
                        .ctx(trc::Key::Total, total));
                }
            }
        }

        // SPDX-SnippetEnd

        // Make sure new name is not taken
        if self
            .get_principal_id(&name)
            .await
            .caused_by(trc::location!())?
            .is_some()
        {
            return Err(err_exists(PrincipalField::Name, name));
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Obtain tenant id, only if no default tenant is provided
        #[cfg(feature = "enterprise")]
        if let (Some(tenant_name), None) = (principal.take_str(PrincipalField::Tenant), tenant_id) {
            tenant_id = self
                .get_principal_info(&tenant_name)
                .await
                .caused_by(trc::location!())?
                .filter(|v| v.typ == Type::Tenant)
                .ok_or_else(|| not_found(tenant_name.clone()))?
                .id
                .into();
        }

        // Tenants must provide principal names including a valid domain
        #[cfg(feature = "enterprise")]
        if let Some(tenant_id) = tenant_id {
            if matches!(principal.typ, Type::Tenant) {
                return Err(error(
                    "Invalid field",
                    "Tenants cannot contain a tenant field".into(),
                ));
            }

            principal.set(PrincipalField::Tenant, tenant_id);

            if !matches!(principal.typ, Type::Tenant | Type::Domain) {
                if let Some(domain) = name.split('@').nth(1) {
                    if self
                        .get_principal_info(domain)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|v| v.typ == Type::Domain && v.has_tenant_access(tenant_id.into()))
                        .is_some()
                    {
                        valid_domains.insert(domain.to_string());
                    }
                }

                if valid_domains.is_empty() {
                    return Err(error(
                        "Invalid principal name",
                        "Principal name must include a valid domain assigned to the tenant".into(),
                    ));
                }
            }
        }
        // SPDX-SnippetEnd

        principal.set(PrincipalField::Name, name);

        // Map member names
        let mut members = Vec::new();
        let mut member_of = Vec::new();
        for (field, expected_type) in [
            (PrincipalField::Members, None),
            (PrincipalField::MemberOf, Some(Type::Group)),
            (PrincipalField::Lists, Some(Type::List)),
            (PrincipalField::Roles, Some(Type::Role)),
        ] {
            if let Some(names) = principal.take_str_array(field) {
                let list = if field == PrincipalField::Members {
                    &mut members
                } else {
                    &mut member_of
                };

                for name in names {
                    list.push(
                        self.get_principal_info(&name)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|v| {
                                expected_type.map_or(true, |t| v.typ == t)
                                    && v.has_tenant_access(tenant_id)
                            })
                            .or_else(|| field.map_internal_roles(&name))
                            .ok_or_else(|| not_found(name))?,
                    );
                }
            }
        }

        // Map permissions
        for field in [
            PrincipalField::EnabledPermissions,
            PrincipalField::DisabledPermissions,
        ] {
            if let Some(names) = principal.take_str_array(field) {
                let mut permissions = Vec::with_capacity(names.len());
                for name in names {
                    let permission = Permission::from_name(&name)
                        .ok_or_else(|| {
                            error(
                                format!("Invalid {} value", field.as_str()),
                                format!("Permission {name:?} is invalid").into(),
                            )
                        })?
                        .id() as u64;

                    if !permissions.contains(&permission) {
                        permissions.push(permission);
                    }
                }

                if !permissions.is_empty() {
                    principal.set(field, permissions);
                }
            }
        }

        // Make sure the e-mail is not taken and validate domain
        if principal.typ != Type::OauthClient {
            for email in principal.iter_mut_str(PrincipalField::Emails) {
                *email = email.to_lowercase();
                if self.rcpt(email).await.caused_by(trc::location!())? {
                    return Err(err_exists(PrincipalField::Emails, email.to_string()));
                }
                if let Some(domain) = email.split('@').nth(1) {
                    if valid_domains.insert(domain.to_string()) {
                        self.get_principal_info(domain)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|v| v.typ == Type::Domain && v.has_tenant_access(tenant_id))
                            .ok_or_else(|| not_found(domain.to_string()))?;
                    }
                }
            }
        }

        // Write principal
        let mut batch = BatchBuilder::new();
        let pinfo_name = DynamicPrincipalInfo::new(principal.typ, tenant_id);
        let pinfo_email = DynamicPrincipalInfo::new(principal.typ, None);
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
                (&principal).serialize(),
            )
            .set(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal
                        .take_str(PrincipalField::Name)
                        .unwrap()
                        .into_bytes(),
                )),
                pinfo_name,
            );

        // Write email to id mapping
        if let Some(emails) = principal
            .take(PrincipalField::Emails)
            .map(|v| v.into_str_array())
        {
            for email in emails {
                batch.set(
                    ValueClass::Directory(DirectoryClass::EmailToId(email.into_bytes())),
                    pinfo_email,
                );
            }
        }

        // Write membership
        for member_of in member_of {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Dynamic(0),
                    member_of: MaybeDynamicId::Static(member_of.id),
                }),
                vec![member_of.typ as u8],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Static(member_of.id),
                    has_member: MaybeDynamicId::Dynamic(0),
                }),
                vec![],
            );
        }
        for member in members {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: MaybeDynamicId::Static(member.id),
                    member_of: MaybeDynamicId::Dynamic(0),
                }),
                vec![principal.typ as u8],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: MaybeDynamicId::Dynamic(0),
                    has_member: MaybeDynamicId::Static(member.id),
                }),
                vec![],
            );
        }

        self.write(batch.build())
            .await
            .and_then(|r| r.last_document_id())
    }

    async fn delete_principal(&self, by: QueryBy<'_>) -> trc::Result<()> {
        // Obtain principal
        let principal_id = match by {
            QueryBy::Name(name) => self
                .get_principal_id(name)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| not_found(name.to_string()))?,
            QueryBy::Id(principal_id) => principal_id,
            QueryBy::Credentials(_) => unreachable!(),
        };
        let mut principal = self
            .get_principal(principal_id)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(principal_id.to_string()))?;
        let mut batch = BatchBuilder::new();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Make sure tenant has no data
        #[cfg(feature = "enterprise")]
        match principal.typ {
            Type::Individual | Type::Group => {
                // Update tenant quota
                if let Some(tenant_id) = principal.tenant() {
                    let quota = self
                        .get_counter(DirectoryClass::UsedQuota(principal_id))
                        .await
                        .caused_by(trc::location!())?;
                    if quota > 0 {
                        batch.add(DirectoryClass::UsedQuota(tenant_id), -quota);
                    }
                }
            }
            Type::Tenant => {
                let tenant_members = self
                    .list_principals(
                        None,
                        principal.id().into(),
                        &[
                            Type::Individual,
                            Type::Group,
                            Type::Role,
                            Type::List,
                            Type::Resource,
                            Type::Other,
                            Type::Location,
                            Type::Domain,
                            Type::ApiKey,
                        ],
                        &[PrincipalField::Name],
                        0,
                        0,
                    )
                    .await
                    .caused_by(trc::location!())?;

                if tenant_members.total > 0 {
                    let mut message =
                        String::from("Tenant must have no members to be deleted: Found: ");

                    for (num, principal) in tenant_members.items.iter().enumerate() {
                        if num > 0 {
                            message.push_str(", ");
                        }
                        message.push_str(principal.name());
                    }

                    if tenant_members.total > 5 {
                        message.push_str(" and ");
                        message.push_str(&(tenant_members.total - 5).to_string());
                        message.push_str(" others");
                    }

                    return Err(error("Tenant has members", message.into()));
                }
            }
            Type::Domain => {
                if let Some(tenant_id) = principal.tenant() {
                    let name = principal.name();
                    let tenant_members = self
                        .list_principals(
                            None,
                            tenant_id.into(),
                            &[
                                Type::Individual,
                                Type::Group,
                                Type::Role,
                                Type::List,
                                Type::Resource,
                                Type::Other,
                                Type::Location,
                            ],
                            &[PrincipalField::Name],
                            0,
                            0,
                        )
                        .await
                        .caused_by(trc::location!())?;
                    let domain_members = tenant_members
                        .items
                        .iter()
                        .filter(|v| {
                            v.name()
                                .rsplit_once('@')
                                .map_or(false, |(_, d)| d.eq_ignore_ascii_case(name))
                        })
                        .collect::<Vec<_>>();
                    let total_domain_members = domain_members.len();

                    if total_domain_members > 0 {
                        let mut message =
                            String::from("Domains must have no members to be deleted: Found: ");

                        for (num, principal) in domain_members.iter().enumerate() {
                            if num > 0 {
                                message.push_str(", ");
                            }
                            message.push_str(principal.name());
                        }

                        if total_domain_members > 5 {
                            message.push_str(" and ");
                            message.push_str(&(total_domain_members - 5).to_string());
                            message.push_str(" others");
                        }

                        return Err(error("Domain has members", message.into()));
                    }
                }
            }

            _ => {}
        }
        // SPDX-SnippetEnd

        // Unlink all principal's blobs
        self.blob_hash_unlink_account(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Revoke ACLs
        self.acl_revoke_all(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Delete principal data
        self.purge_account(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Delete principal
        batch
            .with_account_id(principal_id)
            .clear(DirectoryClass::NameToId(
                principal
                    .take_str(PrincipalField::Name)
                    .unwrap_or_default()
                    .into_bytes(),
            ))
            .clear(DirectoryClass::Principal(MaybeDynamicId::Static(
                principal_id,
            )))
            .clear(DirectoryClass::UsedQuota(principal_id));

        if let Some(emails) = principal.take_str_array(PrincipalField::Emails) {
            for email in emails {
                batch.clear(DirectoryClass::EmailToId(email.into_bytes()));
            }
        }

        for member in self
            .get_member_of(principal_id)
            .await
            .caused_by(trc::location!())?
        {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(principal_id),
                member_of: MaybeDynamicId::Static(member.principal_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(member.principal_id),
                has_member: MaybeDynamicId::Static(principal_id),
            });
        }

        for member_id in self
            .get_members(principal_id)
            .await
            .caused_by(trc::location!())?
        {
            batch.clear(DirectoryClass::MemberOf {
                principal_id: MaybeDynamicId::Static(member_id),
                member_of: MaybeDynamicId::Static(principal_id),
            });
            batch.clear(DirectoryClass::Members {
                principal_id: MaybeDynamicId::Static(principal_id),
                has_member: MaybeDynamicId::Static(member_id),
            });
        }

        self.write(batch.build())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn update_principal(&self, params: UpdatePrincipal<'_>) -> trc::Result<()> {
        let principal_id = match params.query {
            QueryBy::Name(name) => self
                .get_principal_id(name)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| not_found(name.to_string()))?,
            QueryBy::Id(principal_id) => principal_id,
            QueryBy::Credentials(_) => unreachable!(),
        };
        let changes = params.changes;
        let tenant_id = params.tenant_id;

        // Fetch principal
        let mut principal = self
            .get_value::<HashedValue<Principal>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(principal_id),
            )))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(principal_id))?;
        principal.inner.id = principal_id;
        let validate_emails = principal.inner.typ != Type::OauthClient;

        // Obtain members and memberOf
        let mut member_of = self
            .get_member_of(principal_id)
            .await
            .caused_by(trc::location!())?
            .into_iter()
            .map(|v| v.principal_id)
            .collect::<Vec<_>>();
        let mut members = self
            .get_members(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Prepare changes
        let mut batch = BatchBuilder::new();
        let mut pinfo_name =
            PrincipalInfo::new(principal_id, principal.inner.typ, principal.inner.tenant())
                .serialize();
        let pinfo_email = PrincipalInfo::new(principal_id, principal.inner.typ, None).serialize();
        let update_principal = !changes.is_empty()
            && !changes.iter().all(|c| {
                matches!(
                    c.field,
                    PrincipalField::MemberOf
                        | PrincipalField::Members
                        | PrincipalField::Lists
                        | PrincipalField::Roles
                )
            });

        if update_principal {
            batch.assert_value(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                    principal_id,
                ))),
                &principal,
            );
        }

        let mut used_quota: Option<i64> = None;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Obtain used quota
        #[cfg(feature = "enterprise")]
        if tenant_id.is_none()
            && changes
                .iter()
                .any(|c| matches!(c.field, PrincipalField::Tenant))
        {
            let quota = self
                .get_counter(DirectoryClass::UsedQuota(principal_id))
                .await
                .caused_by(trc::location!())?;
            if quota > 0 {
                used_quota = Some(quota);
            }
        }

        // SPDX-SnippetEnd

        // Allowed principal types for Member fields
        let allowed_member_types = match principal.inner.typ() {
            Type::Group => &[Type::Individual, Type::Group][..],
            Type::Resource => &[Type::Resource][..],
            Type::Location => &[
                Type::Location,
                Type::Resource,
                Type::Individual,
                Type::Group,
                Type::Other,
            ][..],
            Type::List => &[Type::Individual, Type::Group][..],
            Type::Other
            | Type::Domain
            | Type::Tenant
            | Type::Individual
            | Type::ApiKey
            | Type::OauthClient => &[][..],
            Type::Role => &[Type::Role][..],
        };
        let mut valid_domains = AHashSet::new();

        // Process changes
        for change in changes {
            match (change.action, change.field, change.value) {
                (PrincipalAction::Set, PrincipalField::Name, PrincipalValue::String(new_name)) => {
                    // Make sure new name is not taken
                    let new_name = new_name.to_lowercase();
                    if principal.inner.name() != new_name {
                        if tenant_id.is_some()
                            && !matches!(principal.inner.typ, Type::Tenant | Type::Domain)
                        {
                            if let Some(domain) = new_name.split('@').nth(1) {
                                if self
                                    .get_principal_info(domain)
                                    .await
                                    .caused_by(trc::location!())?
                                    .filter(|v| {
                                        v.typ == Type::Domain && v.has_tenant_access(tenant_id)
                                    })
                                    .is_some()
                                {
                                    valid_domains.insert(domain.to_string());
                                }
                            }

                            if valid_domains.is_empty() {
                                return Err(error(
                                    "Invalid principal name",
                                    "Principal name must include a valid domain assigned to the tenant".into(),
                                ));
                            }
                        }

                        if self
                            .get_principal_id(&new_name)
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
                            pinfo_name.clone(),
                        );
                    }
                }

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                (
                    PrincipalAction::Set,
                    PrincipalField::Tenant,
                    PrincipalValue::String(tenant_name),
                ) if tenant_id.is_none() => {
                    if !tenant_name.is_empty() {
                        let tenant_info = self
                            .get_principal_info(&tenant_name)
                            .await
                            .caused_by(trc::location!())?
                            .ok_or_else(|| not_found(tenant_name.clone()))?;

                        if tenant_info.typ != Type::Tenant {
                            return Err(error(
                                "Not a tenant",
                                format!("Principal {tenant_name:?} is not a tenant").into(),
                            ));
                        }

                        if principal.inner.tenant() == Some(tenant_info.id) {
                            continue;
                        }

                        // Update quota
                        if let Some(used_quota) = used_quota {
                            if let Some(old_tenant_id) = principal.inner.tenant() {
                                batch.add(DirectoryClass::UsedQuota(old_tenant_id), -used_quota);
                            }
                            batch.add(DirectoryClass::UsedQuota(tenant_info.id), used_quota);
                        }

                        principal.inner.set(PrincipalField::Tenant, tenant_info.id);
                        pinfo_name = PrincipalInfo::new(
                            principal_id,
                            principal.inner.typ,
                            tenant_info.id.into(),
                        )
                        .serialize();
                    } else if let Some(tenant_id) = principal.inner.tenant() {
                        // Update quota
                        if let Some(used_quota) = used_quota {
                            batch.add(DirectoryClass::UsedQuota(tenant_id), -used_quota);
                        }

                        principal.inner.remove(PrincipalField::Tenant);
                        pinfo_name =
                            PrincipalInfo::new(principal_id, principal.inner.typ, None).serialize();
                    } else {
                        continue;
                    }

                    batch.set(
                        ValueClass::Directory(DirectoryClass::NameToId(
                            principal.inner.name().as_bytes().to_vec(),
                        )),
                        pinfo_name.clone(),
                    );
                }

                // SPDX-SnippetEnd
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
                    PrincipalField::Description | PrincipalField::Picture,
                    PrincipalValue::String(value),
                ) => {
                    if !value.is_empty() {
                        principal.inner.set(change.field, value);
                    } else {
                        principal.inner.remove(change.field);
                    }
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::Integer(quota))
                    if matches!(
                        principal.inner.typ,
                        Type::Individual | Type::Group | Type::Tenant
                    ) =>
                {
                    principal.inner.set(PrincipalField::Quota, quota);
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::String(quota))
                    if matches!(
                        principal.inner.typ,
                        Type::Individual | Type::Group | Type::Tenant
                    ) && quota.is_empty() =>
                {
                    principal.inner.remove(PrincipalField::Quota);
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Quota,
                    PrincipalValue::IntegerList(quotas),
                ) if matches!(principal.inner.typ, Type::Tenant)
                    && quotas.len() <= (MAX_TYPE_ID + 2) =>
                {
                    principal.inner.set(PrincipalField::Quota, quotas);
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
                            if validate_emails {
                                self.validate_email(email, tenant_id, params.create_domains)
                                    .await?;
                            }
                            batch.set(
                                ValueClass::Directory(DirectoryClass::EmailToId(
                                    email.as_bytes().to_vec(),
                                )),
                                pinfo_email.clone(),
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
                        if validate_emails {
                            self.validate_email(&email, tenant_id, params.create_domains)
                                .await?;
                        }
                        batch.set(
                            ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )),
                            pinfo_email.clone(),
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
                    PrincipalField::MemberOf | PrincipalField::Lists | PrincipalField::Roles,
                    PrincipalValue::StringList(members),
                ) => {
                    let mut new_member_of = Vec::new();
                    for member in members {
                        let member_info = self
                            .get_principal_info(&member)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|p| p.has_tenant_access(tenant_id))
                            .or_else(|| change.field.map_internal_roles(&member))
                            .ok_or_else(|| not_found(member.clone()))?;

                        validate_member_of(
                            change.field,
                            principal.inner.typ,
                            member_info.typ,
                            &member,
                        )?;

                        if !member_of.contains(&member_info.id) {
                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: MaybeDynamicId::Static(principal_id),
                                    member_of: MaybeDynamicId::Static(member_info.id),
                                }),
                                vec![member_info.typ as u8],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: MaybeDynamicId::Static(member_info.id),
                                    has_member: MaybeDynamicId::Static(principal_id),
                                }),
                                vec![],
                            );
                        }

                        new_member_of.push(member_info.id);
                    }

                    for member_id in &member_of {
                        if !new_member_of.contains(member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(principal_id),
                                member_of: MaybeDynamicId::Static(*member_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(*member_id),
                                has_member: MaybeDynamicId::Static(principal_id),
                            }));
                        }
                    }

                    member_of = new_member_of;
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::MemberOf | PrincipalField::Lists | PrincipalField::Roles,
                    PrincipalValue::String(member),
                ) => {
                    let member_info = self
                        .get_principal_info(&member)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|p| p.has_tenant_access(tenant_id))
                        .or_else(|| change.field.map_internal_roles(&member))
                        .ok_or_else(|| not_found(member.clone()))?;

                    if !member_of.contains(&member_info.id) {
                        validate_member_of(
                            change.field,
                            principal.inner.typ,
                            member_info.typ,
                            &member,
                        )?;

                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(principal_id),
                                member_of: MaybeDynamicId::Static(member_info.id),
                            }),
                            vec![member_info.typ as u8],
                        );

                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(member_info.id),
                                has_member: MaybeDynamicId::Static(principal_id),
                            }),
                            vec![],
                        );

                        member_of.push(member_info.id);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::MemberOf | PrincipalField::Lists | PrincipalField::Roles,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(member_id) = self
                        .get_principal_id(&member)
                        .await
                        .caused_by(trc::location!())?
                        .or_else(|| change.field.map_internal_role_name(&member))
                    {
                        if let Some(pos) = member_of.iter().position(|v| *v == member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(principal_id),
                                member_of: MaybeDynamicId::Static(member_id),
                            }));

                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(member_id),
                                has_member: MaybeDynamicId::Static(principal_id),
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
                        let member_info = self
                            .get_principal_info(&member)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|p| p.has_tenant_access(tenant_id))
                            .ok_or_else(|| not_found(member.clone()))?;

                        if !allowed_member_types.contains(&member_info.typ) {
                            return Err(error(
                                "Invalid members value",
                                format!(
                                    "Principal {member:?} is not one of {}.",
                                    allowed_member_types
                                        .iter()
                                        .map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                                .into(),
                            ));
                        }

                        if !members.contains(&member_info.id) {
                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: MaybeDynamicId::Static(member_info.id),
                                    member_of: MaybeDynamicId::Static(principal_id),
                                }),
                                vec![principal.inner.typ as u8],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: MaybeDynamicId::Static(principal_id),
                                    has_member: MaybeDynamicId::Static(member_info.id),
                                }),
                                vec![],
                            );
                        }

                        new_members.push(member_info.id);
                    }

                    for member_id in &members {
                        if !new_members.contains(member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(*member_id),
                                member_of: MaybeDynamicId::Static(principal_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(principal_id),
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
                    let member_info = self
                        .get_principal_info(&member)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|p| p.has_tenant_access(tenant_id))
                        .ok_or_else(|| not_found(member.clone()))?;

                    if !members.contains(&member_info.id) {
                        if !allowed_member_types.contains(&member_info.typ) {
                            return Err(error(
                                "Invalid members value",
                                format!(
                                    "Principal {member:?} is not one of {}.",
                                    allowed_member_types
                                        .iter()
                                        .map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                                .into(),
                            ));
                        }

                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(member_info.id),
                                member_of: MaybeDynamicId::Static(principal_id),
                            }),
                            vec![principal.inner.typ as u8],
                        );
                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(principal_id),
                                has_member: MaybeDynamicId::Static(member_info.id),
                            }),
                            vec![],
                        );
                        members.push(member_info.id);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Members,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(member_id) = self
                        .get_principal_id(&member)
                        .await
                        .caused_by(trc::location!())?
                    {
                        if let Some(pos) = members.iter().position(|v| *v == member_id) {
                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: MaybeDynamicId::Static(member_id),
                                member_of: MaybeDynamicId::Static(principal_id),
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: MaybeDynamicId::Static(principal_id),
                                has_member: MaybeDynamicId::Static(member_id),
                            }));
                            members.remove(pos);
                        }
                    }
                }

                (
                    PrincipalAction::Set,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::StringList(names),
                ) => {
                    let mut permissions = Vec::with_capacity(names.len());
                    for name in names {
                        let permission = Permission::from_name(&name)
                            .ok_or_else(|| {
                                error(
                                    format!("Invalid {} value", change.field.as_str()),
                                    format!("Permission {name:?} is invalid").into(),
                                )
                            })?
                            .id() as u64;

                        if !permissions.contains(&permission) {
                            permissions.push(permission);
                        }
                    }

                    if !permissions.is_empty() {
                        principal.inner.set(change.field, permissions);
                    } else {
                        principal.inner.remove(change.field);
                    }
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::String(name),
                ) => {
                    let permission = Permission::from_name(&name)
                        .ok_or_else(|| {
                            error(
                                format!("Invalid {} value", change.field.as_str()),
                                format!("Permission {name:?} is invalid").into(),
                            )
                        })?
                        .id() as u64;

                    principal.inner.append_int(change.field, permission);
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::String(name),
                ) => {
                    let permission = Permission::from_name(&name)
                        .ok_or_else(|| {
                            error(
                                format!("Invalid {} value", change.field.as_str()),
                                format!("Permission {name:?} is invalid").into(),
                            )
                        })?
                        .id() as u64;

                    principal
                        .inner
                        .retain_int(change.field, |v| *v != permission);
                }
                (PrincipalAction::Set, PrincipalField::Urls, PrincipalValue::StringList(urls)) => {
                    if !urls.is_empty() {
                        principal.inner.set(change.field, urls);
                    } else {
                        principal.inner.remove(change.field);
                    }
                }
                (PrincipalAction::AddItem, PrincipalField::Urls, PrincipalValue::String(url)) => {
                    if !principal.inner.has_str_value(change.field, &url) {
                        principal.inner.append_str(change.field, url);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Urls,
                    PrincipalValue::String(url),
                ) => {
                    if principal.inner.has_str_value(change.field, &url) {
                        principal.inner.retain_str(change.field, |v| *v != url);
                    }
                }

                (_, field, value) => {
                    return Err(error(
                        "Invalid parameter",
                        format!("Invalid value {:?} for {}", value, field.as_str()).into(),
                    ));
                }
            }
        }

        if update_principal {
            batch.set(
                ValueClass::Directory(DirectoryClass::Principal(MaybeDynamicId::Static(
                    principal_id,
                ))),
                principal.inner.serialize(),
            );
        }

        self.write(batch.build())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn list_principals(
        &self,
        filter: Option<&str>,
        tenant_id: Option<u32>,
        types: &[Type],
        fields: &[PrincipalField],
        page: usize,
        limit: usize,
    ) -> trc::Result<PrincipalList> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![
            u8::MAX;
            10
        ])));

        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let pt = PrincipalInfo::deserialize(value).caused_by(trc::location!())?;

                if (types.is_empty() || types.contains(&pt.typ)) && pt.has_tenant_access(tenant_id)
                {
                    results.push(Principal::new(pt.id, pt.typ).with_field(
                        PrincipalField::Name,
                        String::from_utf8_lossy(key.get(1..).unwrap_or_default()).into_owned(),
                    ));
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if filter.is_none()
            && !fields.is_empty()
            && fields.iter().all(|f| matches!(f, PrincipalField::Name))
        {
            return Ok(PrincipalList {
                total: results.len() as u64,
                items: results
                    .into_iter()
                    .skip(page.saturating_sub(1) * limit)
                    .take(if limit > 0 { limit } else { usize::MAX })
                    .collect(),
            });
        }

        let mut result = PrincipalList::default();
        let filters = filter.and_then(|filter| {
            let filters = filter
                .split_whitespace()
                .map(|r| r.to_lowercase())
                .collect::<Vec<_>>();
            if !filters.is_empty() {
                Some(filters)
            } else {
                None
            }
        });

        let mut offset = limit * page.saturating_sub(1);
        let mut is_done = false;
        let map_principals = fields.is_empty()
            || fields.iter().any(|f| {
                matches!(
                    f,
                    PrincipalField::Tenant
                        | PrincipalField::MemberOf
                        | PrincipalField::Lists
                        | PrincipalField::Roles
                        | PrincipalField::EnabledPermissions
                        | PrincipalField::DisabledPermissions
                        | PrincipalField::Members
                        | PrincipalField::UsedQuota
                )
            });

        for mut principal in results {
            if !is_done || filters.is_some() {
                principal = self
                    .query(QueryBy::Id(principal.id), map_principals)
                    .await
                    .caused_by(trc::location!())?
                    .ok_or_else(|| not_found(principal.name().to_string()))?;
            }

            if filters.as_ref().map_or(true, |filters| {
                filters.iter().all(|f| principal.find_str(f))
            }) {
                result.total += 1;

                if offset == 0 {
                    if !is_done {
                        if !fields.is_empty() {
                            principal.fields.retain(|k, _| fields.contains(k));
                        }

                        if map_principals {
                            self.map_field_ids(&mut principal, fields)
                                .await
                                .caused_by(trc::location!())?;
                        }
                        result.items.push(principal);
                        is_done = limit != 0 && result.items.len() >= limit;
                    }
                } else {
                    offset -= 1;
                }
            }
        }

        Ok(result)
    }

    async fn count_principals(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
        tenant_id: Option<u32>,
    ) -> trc::Result<u64> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![
            u8::MAX;
            10
        ])));

        let mut count = 0;
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let pt = PrincipalInfo::deserialize(value).caused_by(trc::location!())?;
                let name =
                    std::str::from_utf8(key.get(1..).unwrap_or_default()).unwrap_or_default();

                if typ.map_or(true, |t| pt.typ == t)
                    && pt.has_tenant_access(tenant_id)
                    && filter.map_or(true, |f| name.contains(f))
                {
                    count += 1;
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| count)
    }

    async fn get_member_of(&self, principal_id: u32) -> trc::Result<Vec<MemberOf>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::MemberOf {
            principal_id,
            member_of: 0,
        }));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::MemberOf {
            principal_id,
            member_of: u32::MAX,
        }));
        let mut results = Vec::new();
        self.iterate(IterateParams::new(from_key, to_key), |key, value| {
            results.push(MemberOf {
                principal_id: key.deserialize_be_u32(key.len() - U32_LEN)?,
                typ: value
                    .first()
                    .map(|v| Type::from_u8(*v))
                    .unwrap_or(Type::Group),
            });
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;
        Ok(results)
    }

    async fn get_members(&self, principal_id: u32) -> trc::Result<Vec<u32>> {
        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Members {
            principal_id,
            has_member: 0,
        }));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Members {
            principal_id,
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

    async fn map_field_ids(
        &self,
        principal: &mut Principal,
        fields: &[PrincipalField],
    ) -> trc::Result<()> {
        // Map groups
        for field in [
            PrincipalField::MemberOf,
            PrincipalField::Lists,
            PrincipalField::Roles,
        ] {
            if let Some(member_of) = principal
                .take_int_array(field)
                .filter(|_| fields.is_empty() || fields.contains(&field))
            {
                for principal_id in member_of {
                    match principal_id as u32 {
                        ROLE_ADMIN if field == PrincipalField::Roles => {
                            principal.append_str(field, "admin");
                        }
                        ROLE_TENANT_ADMIN if field == PrincipalField::Roles => {
                            principal.append_str(field, "tenant-admin");
                        }
                        ROLE_USER if field == PrincipalField::Roles => {
                            principal.append_str(field, "user");
                        }
                        principal_id => {
                            if let Some(name) = self
                                .get_principal(principal_id)
                                .await
                                .caused_by(trc::location!())?
                                .and_then(|mut p| p.take_str(PrincipalField::Name))
                            {
                                principal.append_str(field, name);
                            }
                        }
                    }
                }
            }
        }

        // Obtain member names
        if fields.is_empty() || fields.contains(&PrincipalField::Members) {
            match principal.typ {
                Type::Group | Type::List | Type::Role => {
                    for member_id in self.get_members(principal.id).await? {
                        if let Some(mut member_principal) =
                            self.query(QueryBy::Id(member_id), false).await?
                        {
                            if let Some(name) = member_principal.take_str(PrincipalField::Name) {
                                principal.append_str(PrincipalField::Members, name);
                            }
                        }
                    }
                }
                Type::Domain => {
                    let from_key =
                        ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(vec![])));
                    let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(
                        vec![u8::MAX; 10],
                    )));
                    let domain_name = principal.name();
                    let mut total: u64 = 0;
                    self.iterate(
                        IterateParams::new(from_key, to_key).no_values(),
                        |key, _| {
                            if std::str::from_utf8(key.get(1..).unwrap_or_default())
                                .unwrap_or_default()
                                .rsplit_once('@')
                                .map_or(false, |(_, domain)| domain == domain_name)
                            {
                                total += 1;
                            }
                            Ok(true)
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;
                    principal.set(PrincipalField::Members, total);
                }
                Type::Tenant => {
                    let from_key =
                        ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
                    let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(
                        vec![u8::MAX; 10],
                    )));
                    let mut total: u64 = 0;

                    self.iterate(IterateParams::new(from_key, to_key), |_, value| {
                        let pinfo =
                            PrincipalInfo::deserialize(value).caused_by(trc::location!())?;

                        if pinfo.typ == Type::Individual
                            && pinfo.has_tenant_access(Some(principal.id))
                        {
                            total += 1;
                        }
                        Ok(true)
                    })
                    .await
                    .caused_by(trc::location!())?;

                    principal.set(PrincipalField::Members, total);
                }
                _ => {}
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Map tenant name
        #[cfg(feature = "enterprise")]
        if let Some(tenant_id) = principal.take_int(PrincipalField::Tenant) {
            if fields.is_empty() || fields.contains(&PrincipalField::Tenant) {
                if let Some(name) = self
                    .get_principal(tenant_id as u32)
                    .await
                    .caused_by(trc::location!())?
                    .and_then(|mut p| p.take_str(PrincipalField::Name))
                {
                    principal.set(PrincipalField::Tenant, name);
                }
            }
        }

        // SPDX-SnippetEnd

        // Obtain used quota
        if matches!(principal.typ, Type::Individual | Type::Group | Type::Tenant)
            && (fields.is_empty() || fields.contains(&PrincipalField::UsedQuota))
        {
            let quota = self
                .get_counter(DirectoryClass::UsedQuota(principal.id))
                .await
                .caused_by(trc::location!())?;
            if quota > 0 {
                principal.set(PrincipalField::UsedQuota, quota as u64);
            }
        }

        // Map permissions
        for field in [
            PrincipalField::EnabledPermissions,
            PrincipalField::DisabledPermissions,
        ] {
            if let Some(permissions) = principal.take_int_array(field) {
                for permission in permissions {
                    if let Some(name) = Permission::from_id(permission as usize) {
                        principal.append_str(field, name.name().to_string());
                    }
                }
            }
        }

        Ok(())
    }
}

impl ValidateDirectory for Store {
    async fn validate_email(
        &self,
        email: &str,
        tenant_id: Option<u32>,
        create_if_missing: bool,
    ) -> trc::Result<()> {
        if self.rcpt(email).await.caused_by(trc::location!())? {
            Err(err_exists(PrincipalField::Emails, email.to_string()))
        } else if let Some(domain) = email.split('@').nth(1) {
            match self
                .get_principal_info(domain)
                .await
                .caused_by(trc::location!())?
            {
                Some(v) if v.typ == Type::Domain && v.has_tenant_access(tenant_id) => Ok(()),
                None if create_if_missing => self
                    .create_principal(
                        Principal::new(0, Type::Domain)
                            .with_field(PrincipalField::Name, domain.to_string())
                            .with_field(PrincipalField::Description, domain.to_string()),
                        tenant_id,
                    )
                    .await
                    .caused_by(trc::location!())
                    .map(|_| ()),
                _ => Err(not_found(domain.to_string())),
            }
        } else {
            Err(error("Invalid email", "Email address is invalid".into()))
        }
    }
}

impl PrincipalField {
    pub fn map_internal_role_name(&self, name: &str) -> Option<u32> {
        match (self, name) {
            (PrincipalField::Roles, "admin") => Some(ROLE_ADMIN),
            (PrincipalField::Roles, "tenant-admin") => Some(ROLE_TENANT_ADMIN),
            (PrincipalField::Roles, "user") => Some(ROLE_USER),
            _ => None,
        }
    }

    pub fn map_internal_roles(&self, name: &str) -> Option<PrincipalInfo> {
        self.map_internal_role_name(name)
            .map(|role_id| PrincipalInfo::new(role_id, Type::Role, None))
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

impl<'x> UpdatePrincipal<'x> {
    pub fn by_id(id: u32) -> Self {
        Self {
            query: QueryBy::Id(id),
            changes: Vec::new(),
            create_domains: false,
            tenant_id: None,
        }
    }

    pub fn by_name(name: &'x str) -> Self {
        Self {
            query: QueryBy::Name(name),
            changes: Vec::new(),
            create_domains: false,
            tenant_id: None,
        }
    }

    pub fn with_tenant(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    pub fn with_updates(mut self, changes: Vec<PrincipalUpdate>) -> Self {
        self.changes = changes;
        self
    }

    pub fn create_domains(mut self) -> Self {
        self.create_domains = true;
        self
    }
}

fn validate_member_of(
    field: PrincipalField,
    typ: Type,
    member_type: Type,
    member_name: &str,
) -> trc::Result<()> {
    let expected_types = match (field, typ) {
        (PrincipalField::MemberOf, Type::Individual) => &[Type::Group, Type::Individual][..],
        (PrincipalField::MemberOf, Type::Group) => &[Type::Group][..],
        (PrincipalField::Lists, Type::Individual | Type::Group) => &[Type::List][..],
        (PrincipalField::Roles, Type::Individual | Type::Tenant | Type::Role) => &[Type::Role][..],
        _ => &[][..],
    };

    if expected_types.is_empty() || !expected_types.contains(&member_type) {
        Err(error(
            format!("Invalid {} value", field.as_str()),
            if !expected_types.is_empty() {
                format!(
                    "Principal {member_name:?} is not a {}.",
                    expected_types
                        .iter()
                        .map(|t| t.as_str().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into()
            } else {
                format!("Principal {member_name:?} cannot be added as a member.").into()
            },
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicPrincipalInfo {
    typ: Type,
    tenant: Option<u32>,
}

impl DynamicPrincipalInfo {
    pub fn new(typ: Type, tenant: Option<u32>) -> Self {
        Self { typ, tenant }
    }
}

impl SerializeWithId for DynamicPrincipalInfo {
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>> {
        ids.last_document_id()
            .map(|principal_id| PrincipalInfo::new(principal_id, self.typ, self.tenant).serialize())
    }
}

impl From<DynamicPrincipalInfo> for MaybeDynamicValue {
    fn from(value: DynamicPrincipalInfo) -> Self {
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
