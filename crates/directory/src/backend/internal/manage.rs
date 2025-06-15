/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    PrincipalAction, PrincipalField, PrincipalInfo, PrincipalSet, PrincipalUpdate, PrincipalValue,
    SpecialSecrets, lookup::DirectoryStore,
};
use crate::{
    MemberOf, Permission, PermissionGrant, Permissions, Principal, PrincipalData, PrincipalQuota,
    QueryBy, ROLE_ADMIN, ROLE_TENANT_ADMIN, ROLE_USER, Type, backend::RcptType,
    core::principal::build_search_index,
};
use ahash::{AHashMap, AHashSet};
use compact_str::CompactString;
use jmap_proto::types::collection::Collection;
use nlp::tokenizers::word::WordTokenizer;
use store::{
    Deserialize, IterateParams, Serialize, SerializeInfallible, Store, U32_LEN, ValueKey,
    backend::MAX_TOKEN_LENGTH,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, DirectoryClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use utils::sanitize_email;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PrincipalList<T> {
    pub items: Vec<T>,
    pub total: u64,
}

pub struct UpdatePrincipal<'x> {
    query: QueryBy<'x>,
    allowed_permissions: Option<&'x Permissions>,
    changes: Vec<PrincipalUpdate>,
    tenant_id: Option<u32>,
    create_domains: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct ChangedPrincipals(AHashMap<u32, ChangedPrincipal>);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChangedPrincipal {
    pub typ: Type,
    pub member_change: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CreatedPrincipal {
    pub id: u32,
    pub changed_principals: ChangedPrincipals,
}

#[allow(async_fn_in_trait)]
pub trait ManageDirectory: Sized {
    async fn get_principal_id(&self, name: &str) -> trc::Result<Option<u32>>;
    async fn get_principal_info(&self, name: &str) -> trc::Result<Option<PrincipalInfo>>;
    async fn get_or_create_principal_id(&self, name: &str, typ: Type) -> trc::Result<u32>;
    async fn get_principal(&self, principal_id: u32) -> trc::Result<Option<Principal>>;
    async fn get_principal_name(&self, principal_id: u32) -> trc::Result<Option<String>>;
    async fn get_member_of(&self, principal_id: u32) -> trc::Result<Vec<MemberOf>>;
    async fn get_members(&self, principal_id: u32) -> trc::Result<Vec<u32>>;
    async fn create_principal(
        &self,
        principal: PrincipalSet,
        tenant_id: Option<u32>,
        allowed_permissions: Option<&Permissions>,
    ) -> trc::Result<CreatedPrincipal>;
    async fn update_principal(&self, params: UpdatePrincipal<'_>)
    -> trc::Result<ChangedPrincipals>;
    async fn delete_principal(&self, by: QueryBy<'_>) -> trc::Result<ChangedPrincipals>;
    async fn list_principals(
        &self,
        filter: Option<&str>,
        tenant_id: Option<u32>,
        types: &[Type],
        fetch: bool,
        page: usize,
        limit: usize,
    ) -> trc::Result<PrincipalList<Principal>>;
    async fn count_principals(
        &self,
        filter: Option<&str>,
        typ: Option<Type>,
        tenant_id: Option<u32>,
    ) -> trc::Result<u64>;
    async fn map_principal(
        &self,
        principal: Principal,
        fields: &[PrincipalField],
    ) -> trc::Result<PrincipalSet>;
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
        let archive = self
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(principal_id),
            )))
            .await
            .caused_by(trc::location!())?;

        if let Some(archive) = archive {
            let mut principal = archive
                .deserialize::<Principal>()
                .caused_by(trc::location!())?;
            principal.id = principal_id;
            Ok(Some(principal))
        } else {
            Ok(None)
        }
    }

    async fn get_principal_name(&self, principal_id: u32) -> trc::Result<Option<String>> {
        let archive = self
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(principal_id),
            )))
            .await
            .caused_by(trc::location!())?;

        if let Some(archive) = archive {
            let principal = archive
                .unarchive::<Principal>()
                .caused_by(trc::location!())?;
            Ok(Some(principal.name.as_str().into()))
        } else {
            Ok(None)
        }
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
        let mut principal_id = None;

        loop {
            // Try to obtain ID
            if let Some(principal_id) = self
                .get_principal_id(&name)
                .await
                .caused_by(trc::location!())?
            {
                return Ok(principal_id);
            }

            let principal_id = if let Some(principal_id) = principal_id {
                principal_id
            } else {
                let principal_id_ = self
                    .assign_document_ids(u32::MAX, Collection::Principal, 1)
                    .await
                    .caused_by(trc::location!())?;
                principal_id = Some(principal_id_);
                principal_id_
            };

            // Prepare principal
            let mut principal = Principal::new(principal_id, typ);
            principal.name = name.as_str().into();

            // Write principal ID
            let name_key =
                ValueClass::Directory(DirectoryClass::NameToId(name.as_bytes().to_vec()));
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(u32::MAX)
                .with_collection(Collection::Principal)
                .assert_value(name_key.clone(), ())
                .create_document(principal_id);
            build_search_index(&mut batch, principal_id, None, Some(&principal));
            batch
                .set(
                    name_key,
                    PrincipalInfo::new(principal_id, typ, None).serialize(),
                )
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                    Archiver::new(principal)
                        .serialize()
                        .caused_by(trc::location!())?,
                );

            // Add default user role
            if typ == Type::Individual {
                batch
                    .set(
                        ValueClass::Directory(DirectoryClass::MemberOf {
                            principal_id,
                            member_of: ROLE_USER,
                        }),
                        vec![Type::Role as u8],
                    )
                    .set(
                        ValueClass::Directory(DirectoryClass::Members {
                            principal_id: ROLE_USER,
                            has_member: principal_id,
                        }),
                        vec![],
                    );
            }

            match self.write(batch.build_all()).await {
                Ok(_) => {
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
        mut principal_set: PrincipalSet,
        mut tenant_id: Option<u32>,
        allowed_permissions: Option<&Permissions>,
    ) -> trc::Result<CreatedPrincipal> {
        // Make sure the principal has a name
        let name = principal_set.name().to_lowercase();
        if name.is_empty() {
            return Err(err_missing(PrincipalField::Name));
        }
        let mut valid_domains: AHashSet<String> = AHashSet::new();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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
                .principal_quota(&principal_set.typ())
                .filter(|q| *q > 0)
            {
                // Obtain number of principals
                let total = self
                    .count_principals(None, principal_set.typ().into(), tenant_id.into())
                    .await
                    .caused_by(trc::location!())?;

                if total >= limit {
                    trc::bail!(
                        trc::LimitEvent::TenantQuota
                            .into_err()
                            .details("Tenant principal quota exceeded")
                            .ctx(trc::Key::Details, principal_set.typ().as_str())
                            .ctx(trc::Key::Limit, limit)
                            .ctx(trc::Key::Total, total)
                    );
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

        let mut principal_create = Principal::new(0, principal_set.typ());

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Obtain tenant id, only if no default tenant is provided
        #[cfg(feature = "enterprise")]
        if let (Some(tenant_name), None) =
            (principal_set.take_str(PrincipalField::Tenant), tenant_id)
        {
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
            if matches!(principal_set.typ, Type::Tenant) {
                return Err(error(
                    "Invalid field",
                    "Tenants cannot contain a tenant field".into(),
                ));
            }

            principal_create.tenant = tenant_id.into();

            if !matches!(principal_create.typ, Type::Tenant | Type::Domain) {
                if let Some(domain) = name.split('@').nth(1) {
                    if self
                        .get_principal_info(domain)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|v| v.typ == Type::Domain && v.has_tenant_access(tenant_id.into()))
                        .is_some()
                    {
                        valid_domains.insert(domain.into());
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

        // Set fields
        principal_create.name = name;
        principal_create.description = principal_set.take_str(PrincipalField::Description);
        principal_create.secrets = principal_set
            .take_str_array(PrincipalField::Secrets)
            .unwrap_or_default();
        if let Some(picture) = principal_set.take_str(PrincipalField::Picture) {
            principal_create.data.push(PrincipalData::Picture(picture));
        }
        if let Some(urls) = principal_set.take_str_array(PrincipalField::Urls) {
            principal_create.data.push(PrincipalData::Urls(urls));
        }
        if let Some(urls) = principal_set.take_str_array(PrincipalField::ExternalMembers) {
            principal_create
                .data
                .push(PrincipalData::ExternalMembers(urls));
        }
        if let Some(quotas) = principal_set.take_int_array(PrincipalField::Quota) {
            let mut principal_quotas = Vec::new();

            for (idx, quota) in quotas.into_iter().take(Type::MAX_ID + 2).enumerate() {
                if idx != 0 {
                    principal_quotas.push(PrincipalQuota {
                        quota,
                        typ: Type::from_u8((idx - 1) as u8),
                    });
                } else if quota != 0 {
                    principal_create.quota = Some(quota);
                }
            }

            if !principal_quotas.is_empty() {
                principal_create
                    .data
                    .push(PrincipalData::PrincipalQuota(principal_quotas));
            }
        }

        // Map member names
        let mut members = Vec::new();
        let mut member_of = Vec::new();
        let mut changed_principals = ChangedPrincipals::default();
        for (field, expected_type) in [
            (PrincipalField::Members, None),
            (PrincipalField::MemberOf, Some(Type::Group)),
            (PrincipalField::Lists, Some(Type::List)),
            (PrincipalField::Roles, Some(Type::Role)),
        ] {
            if let Some(names) = principal_set.take_str_array(field) {
                let list = if field == PrincipalField::Members {
                    &mut members
                } else {
                    &mut member_of
                };

                for name in names {
                    let item = match (
                        self.get_principal_info(&name)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|v| {
                                expected_type.is_none_or(|t| v.typ == t)
                                    && v.has_tenant_access(tenant_id)
                            }),
                        field.map_internal_roles(&name),
                    ) {
                        (_, Some(v)) => v,
                        (Some(v), _) => {
                            if field == PrincipalField::Members {
                                // Update principal members
                                changed_principals.add_change(
                                    v.id,
                                    v.typ,
                                    PrincipalField::MemberOf,
                                );
                            }
                            v
                        }
                        _ => {
                            return Err(not_found(name));
                        }
                    };

                    list.push(item);
                }
            }
        }

        // Map permissions
        let mut permissions = AHashMap::new();
        for field in [
            PrincipalField::EnabledPermissions,
            PrincipalField::DisabledPermissions,
        ] {
            let is_disabled = field == PrincipalField::DisabledPermissions;
            if let Some(names) = principal_set.take_str_array(field) {
                for name in names {
                    let permission = Permission::from_name(&name).ok_or_else(|| {
                        error(
                            format!("Invalid {} value", field.as_str()),
                            format!("Permission {name:?} is invalid").into(),
                        )
                    })?;

                    if !permissions.contains_key(&permission) {
                        if allowed_permissions
                            .as_ref()
                            .is_none_or(|p| p.get(permission as usize))
                            || is_disabled
                        {
                            permissions.insert(permission, is_disabled);
                        } else {
                            return Err(error(
                                "Invalid permission",
                                format!("Your account cannot grant the {name:?} permission").into(),
                            ));
                        }
                    }
                }
            }
        }
        if !permissions.is_empty() {
            principal_create.data.push(PrincipalData::Permissions(
                permissions
                    .into_iter()
                    .map(|(k, v)| PermissionGrant {
                        permission: k,
                        grant: !v,
                    })
                    .collect(),
            ));
        }

        // Make sure the e-mail is not taken and validate domain
        if principal_create.typ != Type::OauthClient {
            for email in principal_set
                .take_str_array(PrincipalField::Emails)
                .unwrap_or_default()
            {
                let email = email.to_lowercase();
                if self.rcpt(&email).await.caused_by(trc::location!())? != RcptType::Invalid {
                    return Err(err_exists(PrincipalField::Emails, email.to_string()));
                }
                if let Some(domain) = email.split('@').nth(1) {
                    if valid_domains.insert(domain.into()) {
                        self.get_principal_info(domain)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|v| v.typ == Type::Domain && v.has_tenant_access(tenant_id))
                            .ok_or_else(|| not_found(domain.to_string()))?;
                    }
                }
                principal_create.emails.push(email);
            }
        }

        // Write principal
        let principal_id = self
            .assign_document_ids(u32::MAX, Collection::Principal, 1)
            .await
            .caused_by(trc::location!())?;
        principal_create.id = principal_id;
        let mut batch = BatchBuilder::new();
        let pinfo_name = PrincipalInfo::new(principal_id, principal_create.typ, tenant_id);
        let pinfo_email = PrincipalInfo::new(principal_id, principal_create.typ, None);

        // Serialize
        let archiver = Archiver::new(principal_create);
        let principal_bytes = archiver.serialize().caused_by(trc::location!())?;
        let principal_create = archiver.into_inner();

        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .create_document(principal_id)
            .assert_value(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal_create.name().as_bytes().to_vec(),
                )),
                (),
            );
        build_search_index(&mut batch, principal_id, None, Some(&principal_create));
        batch
            .set(
                ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                principal_bytes,
            )
            .set(
                ValueClass::Directory(DirectoryClass::NameToId(
                    principal_create.name.as_bytes().to_vec(),
                )),
                pinfo_name.serialize(),
            );

        // Write email to id mapping
        for email in principal_create.emails {
            batch.set(
                ValueClass::Directory(DirectoryClass::EmailToId(email.as_bytes().to_vec())),
                pinfo_email.serialize(),
            );
        }

        // Write membership
        for member_of in member_of {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id,
                    member_of: member_of.id,
                }),
                vec![member_of.typ as u8],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id: member_of.id,
                    has_member: principal_id,
                }),
                vec![],
            );
        }
        for member in members {
            batch.set(
                ValueClass::Directory(DirectoryClass::MemberOf {
                    principal_id: member.id,
                    member_of: principal_id,
                }),
                vec![principal_create.typ as u8],
            );
            batch.set(
                ValueClass::Directory(DirectoryClass::Members {
                    principal_id,
                    has_member: member.id,
                }),
                vec![],
            );
        }

        self.write(batch.build_all())
            .await
            .map(|_| CreatedPrincipal {
                id: principal_id,
                changed_principals,
            })
    }

    async fn delete_principal(&self, by: QueryBy<'_>) -> trc::Result<ChangedPrincipals> {
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

        let principal_ = self
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(principal_id),
            )))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(principal_id.to_string()))?;
        let principal = principal_
            .unarchive::<Principal>()
            .caused_by(trc::location!())?;
        let typ = Type::from(&principal.typ);

        let mut batch = BatchBuilder::new();
        batch.with_account_id(u32::MAX);

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Make sure tenant has no data
        let tenant = principal.tenant.as_ref().map(|t| t.to_native());
        #[cfg(feature = "enterprise")]
        match typ {
            Type::Individual | Type::Group => {
                // Update tenant quota
                if let Some(tenant_id) = tenant {
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
                        principal_id.into(),
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
                        false,
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
                if let Some(tenant_id) = tenant {
                    let name = principal.name.as_str();
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
                            false,
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
                                .is_some_and(|(_, d)| d.eq_ignore_ascii_case(name))
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

        // Revoke ACLs, obtain all changed principals
        let mut changed_principals = ChangedPrincipals::default();

        for member_id in self
            .acl_revoke_all(principal_id)
            .await
            .caused_by(trc::location!())?
        {
            changed_principals.add_change(
                member_id,
                Type::Individual,
                PrincipalField::EnabledPermissions,
            );
        }

        // Delete principal data
        self.danger_destroy_account(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Delete principal
        batch
            .delete_document(principal_id)
            .clear(DirectoryClass::NameToId(principal.name.as_bytes().to_vec()))
            .clear(DirectoryClass::Principal(principal_id))
            .clear(DirectoryClass::UsedQuota(principal_id));

        for email in principal.emails.iter() {
            batch.clear(DirectoryClass::EmailToId(email.as_bytes().to_vec()));
        }

        build_search_index(&mut batch, principal_id, Some(principal), None);

        for member in self
            .get_member_of(principal_id)
            .await
            .caused_by(trc::location!())?
        {
            // Update changed principals
            changed_principals.add_member_change(
                principal_id,
                typ,
                member.principal_id,
                member.typ,
            );

            // Remove memberOf
            batch.clear(DirectoryClass::MemberOf {
                principal_id,
                member_of: member.principal_id,
            });
            batch.clear(DirectoryClass::Members {
                principal_id: member.principal_id,
                has_member: principal_id,
            });
        }

        for member_id in self
            .get_members(principal_id)
            .await
            .caused_by(trc::location!())?
        {
            // Update changed principals
            if let Some(member_info) = self
                .get_principal(member_id)
                .await
                .caused_by(trc::location!())?
            {
                changed_principals.add_member_change(member_id, member_info.typ, principal_id, typ);
            }

            // Remove members
            batch.clear(DirectoryClass::MemberOf {
                principal_id: member_id,
                member_of: principal_id,
            });
            batch.clear(DirectoryClass::Members {
                principal_id,
                has_member: member_id,
            });
        }

        self.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        changed_principals.add_deletion(principal_id, typ);

        Ok(changed_principals)
    }

    async fn update_principal(
        &self,
        params: UpdatePrincipal<'_>,
    ) -> trc::Result<ChangedPrincipals> {
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
        let principal_ = self
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Directory(
                DirectoryClass::Principal(principal_id),
            )))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| not_found(principal_id))?;
        let prev_principal = principal_
            .to_unarchived::<Principal>()
            .caused_by(trc::location!())?;
        let mut principal = prev_principal
            .deserialize::<Principal>()
            .caused_by(trc::location!())?;
        principal.id = principal_id;
        let principal_type = principal.typ;
        let validate_emails = principal_type != Type::OauthClient;

        // Keep track of changed principals
        let mut changed_principals = ChangedPrincipals::default();

        // Obtain members and memberOf
        let mut member_of = self
            .get_member_of(principal_id)
            .await
            .caused_by(trc::location!())?;
        let mut members = self
            .get_members(principal_id)
            .await
            .caused_by(trc::location!())?;

        // Prepare changes
        let mut batch = BatchBuilder::new();
        let mut pinfo_name =
            PrincipalInfo::new(principal_id, principal_type, principal.tenant()).serialize();
        let pinfo_email = PrincipalInfo::new(principal_id, principal_type, None).serialize();
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

        let mut used_quota: Option<i64> = None;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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
        let allowed_member_types = match principal_type {
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
                    if principal.name() != new_name {
                        if tenant_id.is_some()
                            && !matches!(principal_type, Type::Tenant | Type::Domain)
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
                            principal.name().as_bytes().to_vec(),
                        )));

                        batch.set(
                            ValueClass::Directory(DirectoryClass::NameToId(
                                new_name.as_bytes().to_vec(),
                            )),
                            pinfo_name.clone(),
                        );
                        principal.name = new_name;

                        // Name changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);
                    }
                }

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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

                        if principal.tenant() == Some(tenant_info.id) {
                            continue;
                        }

                        // Update quota
                        if let Some(used_quota) = used_quota {
                            if let Some(old_tenant_id) = principal.tenant() {
                                batch.add(DirectoryClass::UsedQuota(old_tenant_id), -used_quota);
                            }
                            batch.add(DirectoryClass::UsedQuota(tenant_info.id), used_quota);
                        }

                        // Tenant changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);

                        principal.tenant = tenant_info.id.into();
                        pinfo_name =
                            PrincipalInfo::new(principal_id, principal_type, tenant_info.id.into())
                                .serialize();
                    } else if let Some(tenant_id) = principal.tenant() {
                        // Update quota
                        if let Some(used_quota) = used_quota {
                            batch.add(DirectoryClass::UsedQuota(tenant_id), -used_quota);
                        }

                        // Tenant changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);

                        principal.tenant = None;
                        pinfo_name =
                            PrincipalInfo::new(principal_id, principal_type, None).serialize();
                    } else {
                        continue;
                    }

                    batch.set(
                        ValueClass::Directory(DirectoryClass::NameToId(
                            principal.name().as_bytes().to_vec(),
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
                    // Password changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);

                    principal.secrets = value.into_str_array();
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Secrets,
                    PrincipalValue::String(secret),
                ) => {
                    if !principal.secrets.contains(&secret) {
                        if secret.is_otp_auth() {
                            // Add OTP Auth URLs to the beginning of the list
                            principal.secrets.insert(0, secret);

                            // Password changed, update changed principals
                            changed_principals.add_change(
                                principal_id,
                                principal_type,
                                change.field,
                            );
                        } else {
                            principal.secrets.push(secret);
                            // Password changed, update changed principals
                            changed_principals.add_change(
                                principal_id,
                                principal_type,
                                change.field,
                            );
                        }
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Secrets,
                    PrincipalValue::String(secret),
                ) => {
                    // Password changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);

                    if secret.is_app_password() || secret.is_otp_auth() {
                        principal
                            .secrets
                            .retain(|v| *v != secret && !v.starts_with(secret.as_str()));
                    } else if !secret.is_empty() {
                        principal.secrets.retain(|v| *v != secret);
                    } else {
                        principal.secrets.retain(|v| !v.is_password());
                    }
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Description | PrincipalField::Picture,
                    PrincipalValue::String(value),
                ) => {
                    if !value.is_empty() {
                        principal.description = Some(value);
                    } else {
                        principal.description = None;
                    }
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::Integer(quota))
                    if matches!(
                        principal_type,
                        Type::Individual | Type::Group | Type::Tenant
                    ) =>
                {
                    // Quota changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);
                    principal.quota = Some(quota);
                }
                (PrincipalAction::Set, PrincipalField::Quota, PrincipalValue::String(quota))
                    if matches!(
                        principal_type,
                        Type::Individual | Type::Group | Type::Tenant
                    ) && quota.is_empty() =>
                {
                    // Quota changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);
                    principal.quota = None;
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::Quota,
                    PrincipalValue::IntegerList(quotas),
                ) if matches!(principal_type, Type::Tenant)
                    && quotas.len() <= (Type::MAX_ID + 2) =>
                {
                    let mut new_quota = None;
                    let mut principal_quotas = Vec::new();

                    for (idx, quota) in quotas.into_iter().enumerate() {
                        if idx != 0 {
                            principal_quotas.push(PrincipalQuota {
                                quota,
                                typ: Type::from_u8((idx - 1) as u8),
                            });
                        } else if quota != 0 {
                            new_quota = Some(quota);
                        }
                    }

                    principal.quota = new_quota;
                    principal
                        .data
                        .retain(|v| !matches!(v, PrincipalData::PrincipalQuota(_)));
                    if !principal_quotas.is_empty() {
                        principal
                            .data
                            .push(PrincipalData::PrincipalQuota(principal_quotas));
                    }
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
                        if !principal.emails.contains(email) {
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

                    for email in &principal.emails {
                        if !emails.contains(email) {
                            batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                                email.as_bytes().to_vec(),
                            )));
                        }
                    }

                    // Emails changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);

                    principal.emails = emails;
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if !principal.emails.contains(&email) {
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
                        principal.emails.push(email);

                        // Emails changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Emails,
                    PrincipalValue::String(email),
                ) => {
                    let email = email.to_lowercase();
                    if let Some(idx) = principal.emails.iter().position(|v| v == &email) {
                        principal.emails.remove(idx);
                        batch.clear(ValueClass::Directory(DirectoryClass::EmailToId(
                            email.as_bytes().to_vec(),
                        )));

                        // Emails changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);
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
                        let member_info = match (
                            self.get_principal_info(&member)
                                .await
                                .caused_by(trc::location!())?
                                .filter(|p| p.has_tenant_access(tenant_id)),
                            change.field.map_internal_roles(&member),
                        ) {
                            (_, Some(v)) => v,
                            (Some(v), _) => v,
                            _ => {
                                return Err(not_found(member.clone()));
                            }
                        };

                        validate_member_of(change.field, principal_type, member_info.typ, &member)?;

                        if !member_of.iter().any(|v| v.principal_id == member_info.id) {
                            // Update changed principal ids
                            changed_principals.add_member_change(
                                principal_id,
                                principal_type,
                                member_info.id,
                                member_info.typ,
                            );

                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id,
                                    member_of: member_info.id,
                                }),
                                vec![member_info.typ as u8],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: member_info.id,
                                    has_member: principal_id,
                                }),
                                vec![],
                            );
                        }

                        new_member_of.push(MemberOf {
                            principal_id: member_info.id,
                            typ: member_info.typ,
                        });
                    }

                    for member in &member_of {
                        if !new_member_of
                            .iter()
                            .any(|v| v.principal_id == member.principal_id)
                        {
                            // Update changed principal ids
                            changed_principals.add_member_change(
                                principal_id,
                                principal_type,
                                member.principal_id,
                                member.typ,
                            );

                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id,
                                member_of: member.principal_id,
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id: member.principal_id,
                                has_member: principal_id,
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
                    let member_info = match (
                        self.get_principal_info(&member)
                            .await
                            .caused_by(trc::location!())?
                            .filter(|p| p.has_tenant_access(tenant_id)),
                        change.field.map_internal_roles(&member),
                    ) {
                        (_, Some(v)) => v,
                        (Some(v), _) => v,
                        _ => {
                            return Err(not_found(member.clone()));
                        }
                    };

                    if !member_of.iter().any(|v| v.principal_id == member_info.id) {
                        validate_member_of(change.field, principal_type, member_info.typ, &member)?;

                        // Update changed principal ids
                        changed_principals.add_member_change(
                            principal_id,
                            principal_type,
                            member_info.id,
                            member_info.typ,
                        );

                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id,
                                member_of: member_info.id,
                            }),
                            vec![member_info.typ as u8],
                        );

                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id: member_info.id,
                                has_member: principal_id,
                            }),
                            vec![],
                        );

                        member_of.push(MemberOf {
                            principal_id: member_info.id,
                            typ: member_info.typ,
                        });
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::MemberOf | PrincipalField::Lists | PrincipalField::Roles,
                    PrincipalValue::String(member),
                ) => {
                    if let Some(member_info) =
                        self.get_principal_info(&member)
                            .await
                            .caused_by(trc::location!())?
                            .or_else(|| {
                                change.field.map_internal_role_name(&member).map(|id| {
                                    PrincipalInfo {
                                        id,
                                        typ: Type::Role,
                                        tenant: None,
                                    }
                                })
                            })
                    {
                        for (pos, member) in member_of.iter().enumerate() {
                            if member.principal_id == member_info.id {
                                // Update changed principal ids
                                changed_principals.add_member_change(
                                    principal_id,
                                    principal_type,
                                    member_info.id,
                                    member_info.typ,
                                );

                                batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id,
                                    member_of: member_info.id,
                                }));

                                batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                    principal_id: member_info.id,
                                    has_member: principal_id,
                                }));

                                member_of.remove(pos);
                                break;
                            }
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
                            // Update changed principal ids
                            changed_principals.add_member_change(
                                member_info.id,
                                member_info.typ,
                                principal_id,
                                principal_type,
                            );

                            batch.set(
                                ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: member_info.id,
                                    member_of: principal_id,
                                }),
                                vec![principal_type as u8],
                            );
                            batch.set(
                                ValueClass::Directory(DirectoryClass::Members {
                                    principal_id,
                                    has_member: member_info.id,
                                }),
                                vec![],
                            );
                        }

                        new_members.push(member_info.id);
                    }

                    for member_id in &members {
                        if !new_members.contains(member_id) {
                            // Update changed principal ids
                            if principal_type != Type::List {
                                if let Some(member_info) = self
                                    .get_principal(*member_id)
                                    .await
                                    .caused_by(trc::location!())?
                                {
                                    changed_principals.add_member_change(
                                        *member_id,
                                        member_info.typ,
                                        principal_id,
                                        principal_type,
                                    );
                                }
                            }

                            batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: *member_id,
                                member_of: principal_id,
                            }));
                            batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                principal_id,
                                has_member: *member_id,
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

                        // Update changed principal ids
                        changed_principals.add_member_change(
                            member_info.id,
                            member_info.typ,
                            principal_id,
                            principal_type,
                        );

                        batch.set(
                            ValueClass::Directory(DirectoryClass::MemberOf {
                                principal_id: member_info.id,
                                member_of: principal_id,
                            }),
                            vec![principal_type as u8],
                        );
                        batch.set(
                            ValueClass::Directory(DirectoryClass::Members {
                                principal_id,
                                has_member: member_info.id,
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
                    if let Some(member_info) = self
                        .get_principal_info(&member)
                        .await
                        .caused_by(trc::location!())?
                    {
                        for (pos, member_id) in members.iter().enumerate() {
                            if *member_id == member_info.id {
                                // Update changed principal ids
                                changed_principals.add_member_change(
                                    member_info.id,
                                    member_info.typ,
                                    principal_id,
                                    principal_type,
                                );

                                batch.clear(ValueClass::Directory(DirectoryClass::MemberOf {
                                    principal_id: member_info.id,
                                    member_of: principal_id,
                                }));
                                batch.clear(ValueClass::Directory(DirectoryClass::Members {
                                    principal_id,
                                    has_member: member_info.id,
                                }));
                                members.remove(pos);
                                break;
                            }
                        }
                    }
                }

                (
                    PrincipalAction::Set,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::StringList(names),
                ) => {
                    let is_disabled = change.field == PrincipalField::DisabledPermissions;
                    let mut permissions = AHashSet::with_capacity(names.len());
                    for name in names {
                        let permission = Permission::from_name(&name).ok_or_else(|| {
                            error(
                                format!("Invalid {} value", change.field.as_str()),
                                format!("Permission {name:?} is invalid").into(),
                            )
                        })?;

                        if !permissions.contains(&permission) {
                            if params
                                .allowed_permissions
                                .as_ref()
                                .is_none_or(|p| p.get(permission as usize))
                                || is_disabled
                            {
                                permissions.insert(permission);
                            } else {
                                return Err(error(
                                    "Invalid permission",
                                    format!("Your account cannot grant the {name:?} permission")
                                        .into(),
                                ));
                            }
                        }
                    }

                    principal.remove_permissions(!is_disabled);

                    if !permissions.is_empty() {
                        principal.add_permissions(permissions.into_iter().map(|permission| {
                            PermissionGrant {
                                permission,
                                grant: !is_disabled,
                            }
                        }));
                    }

                    // Permissions changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::String(name),
                ) => {
                    let permission = Permission::from_name(&name).ok_or_else(|| {
                        error(
                            format!("Invalid {} value", change.field.as_str()),
                            format!("Permission {name:?} is invalid").into(),
                        )
                    })?;

                    if params
                        .allowed_permissions
                        .as_ref()
                        .is_none_or(|p| p.get(permission as usize))
                        || change.field == PrincipalField::DisabledPermissions
                    {
                        principal.add_permission(
                            permission,
                            change.field == PrincipalField::EnabledPermissions,
                        );

                        // Permissions changed, update changed principals
                        changed_principals.add_change(principal_id, principal_type, change.field);
                    } else {
                        return Err(error(
                            "Invalid permission",
                            format!("Your account cannot grant the {name:?} permission").into(),
                        ));
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                    PrincipalValue::String(name),
                ) => {
                    let permission = Permission::from_name(&name).ok_or_else(|| {
                        error(
                            format!("Invalid {} value", change.field.as_str()),
                            format!("Permission {name:?} is invalid").into(),
                        )
                    })?;

                    principal.remove_permission(
                        permission,
                        change.field == PrincipalField::EnabledPermissions,
                    );

                    // Permissions changed, update changed principals
                    changed_principals.add_change(principal_id, principal_type, change.field);
                }
                (
                    PrincipalAction::Set,
                    PrincipalField::ExternalMembers,
                    PrincipalValue::StringList(items),
                ) => {
                    principal
                        .data
                        .retain(|v| !matches!(v, PrincipalData::ExternalMembers(_)));
                    if !items.is_empty() {
                        principal.data.push(PrincipalData::ExternalMembers(
                            items
                                .into_iter()
                                .map(|item| {
                                    sanitize_email(&item).ok_or_else(|| {
                                        error(
                                            "Invalid email address",
                                            format!(
                                                "Invalid value {:?} for {}",
                                                item,
                                                change.field.as_str()
                                            )
                                            .into(),
                                        )
                                    })
                                })
                                .collect::<trc::Result<_>>()?,
                        ));
                    }
                }
                (PrincipalAction::Set, PrincipalField::Urls, PrincipalValue::StringList(items)) => {
                    principal
                        .data
                        .retain(|v| !matches!(v, PrincipalData::Urls(_)));

                    if !items.is_empty() {
                        principal.data.push(PrincipalData::Urls(items));
                    }
                }
                (
                    PrincipalAction::AddItem,
                    PrincipalField::Urls | PrincipalField::ExternalMembers,
                    PrincipalValue::String(mut item),
                ) => {
                    if matches!(change.field, PrincipalField::ExternalMembers) {
                        item = sanitize_email(&item).ok_or_else(|| {
                            error(
                                "Invalid email address",
                                format!("Invalid value {:?} for {}", item, change.field.as_str())
                                    .into(),
                            )
                        })?
                    }

                    let mut found = false;
                    for data in &mut principal.data {
                        match (data, change.field) {
                            (PrincipalData::Urls(urls), PrincipalField::Urls) => {
                                if !urls.contains(&item) {
                                    urls.push(item.clone());
                                }
                                found = true;
                                break;
                            }
                            (
                                PrincipalData::ExternalMembers(emails),
                                PrincipalField::ExternalMembers,
                            ) => {
                                if !emails.contains(&item) {
                                    emails.push(item.clone());
                                }
                                found = true;
                                break;
                            }
                            _ => {}
                        }
                    }

                    if !found {
                        match change.field {
                            PrincipalField::Urls => {
                                principal.data.push(PrincipalData::Urls(vec![item]))
                            }
                            PrincipalField::ExternalMembers => principal
                                .data
                                .push(PrincipalData::ExternalMembers(vec![item])),
                            _ => {}
                        }
                    }
                }
                (
                    PrincipalAction::RemoveItem,
                    PrincipalField::Urls | PrincipalField::ExternalMembers,
                    PrincipalValue::String(item),
                ) => {
                    for data in &mut principal.data {
                        match (data, change.field) {
                            (PrincipalData::Urls(urls), PrincipalField::Urls) => {
                                urls.retain(|v| *v != item);
                                break;
                            }
                            (
                                PrincipalData::ExternalMembers(emails),
                                PrincipalField::ExternalMembers,
                            ) => {
                                emails.retain(|v| *v != item);
                                break;
                            }
                            _ => {}
                        }
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
            build_search_index(
                &mut batch,
                principal_id,
                Some(prev_principal.inner),
                Some(&principal),
            );

            batch
                .assert_value(
                    ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                    prev_principal,
                )
                .set(
                    ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                    Archiver::new(principal)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
        }

        self.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        Ok(changed_principals)
    }

    async fn list_principals(
        &self,
        filter: Option<&str>,
        tenant_id: Option<u32>,
        types: &[Type],
        fetch: bool,
        page: usize,
        limit: usize,
    ) -> trc::Result<PrincipalList<Principal>> {
        let filter = if let Some(filter) = filter.filter(|f| !f.trim().is_empty()) {
            let mut matches = RoaringBitmap::new();

            for token in WordTokenizer::new(filter, MAX_TOKEN_LENGTH) {
                let word_bytes = token.word.as_bytes();
                let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Index {
                    word: word_bytes.to_vec(),
                    principal_id: 0,
                }));
                let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::Index {
                    word: word_bytes.to_vec(),
                    principal_id: u32::MAX,
                }));

                let mut word_matches = RoaringBitmap::new();
                self.iterate(
                    IterateParams::new(from_key, to_key).no_values(),
                    |key, _| {
                        let id_pos = key.len() - U32_LEN;
                        if key.get(1..id_pos).is_some_and(|v| v == word_bytes) {
                            word_matches.insert(key.deserialize_be_u32(id_pos)?);
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                )
                .await
                .caused_by(trc::location!())?;

                if matches.is_empty() {
                    matches = word_matches;
                } else {
                    matches &= word_matches;
                    if matches.is_empty() {
                        break;
                    }
                }
            }

            if !matches.is_empty() {
                Some(matches)
            } else {
                return Ok(PrincipalList {
                    total: 0,
                    items: vec![],
                });
            }
        } else {
            None
        };

        let from_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![])));
        let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::NameToId(vec![
            u8::MAX;
            10
        ])));

        let max_items = if limit > 0 { limit } else { usize::MAX };
        let mut offset = page.saturating_sub(1) * limit;
        let mut result = PrincipalList {
            items: Vec::new(),
            total: 0,
        };
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let pt = PrincipalInfo::deserialize(value).caused_by(trc::location!())?;

                if (types.is_empty() || types.contains(&pt.typ))
                    && pt.has_tenant_access(tenant_id)
                    && filter.as_ref().is_none_or(|filter| filter.contains(pt.id))
                {
                    result.total += 1;
                    if offset == 0 {
                        if result.items.len() < max_items {
                            let mut principal = Principal::new(pt.id, pt.typ);
                            principal.name =
                                String::from_utf8_lossy(key.get(1..).unwrap_or_default())
                                    .into_owned();
                            result.items.push(principal);
                        }
                    } else {
                        offset -= 1;
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if fetch && !result.items.is_empty() {
            let mut items = Vec::with_capacity(result.items.len());

            for principal in result.items {
                items.push(
                    self.query(QueryBy::Id(principal.id), fetch)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or_else(|| not_found(principal.name().to_string()))?,
                );
            }
            result.items = items;

            Ok(result)
        } else {
            Ok(result)
        }
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

                if typ.is_none_or(|t| pt.typ == t)
                    && pt.has_tenant_access(tenant_id)
                    && filter.is_none_or(|f| name.contains(f))
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

    async fn map_principal(
        &self,
        principal: Principal,
        fields: &[PrincipalField],
    ) -> trc::Result<PrincipalSet> {
        let mut result = PrincipalSet::new(principal.id, principal.typ);

        let has_enabled = fields.is_empty() || fields.contains(&PrincipalField::EnabledPermissions);
        let has_disabled =
            fields.is_empty() || fields.contains(&PrincipalField::DisabledPermissions);
        let mut principal_quotas = Vec::new();

        for data in principal.data {
            match data {
                PrincipalData::MemberOf(items)
                    if fields.is_empty() || fields.contains(&PrincipalField::MemberOf) =>
                {
                    for principal_id in items {
                        if let Some(name) = self
                            .get_principal_name(principal_id)
                            .await
                            .caused_by(trc::location!())?
                        {
                            result.append_str(PrincipalField::MemberOf, name);
                        }
                    }
                }
                PrincipalData::Roles(items)
                    if fields.is_empty() || fields.contains(&PrincipalField::Roles) =>
                {
                    for principal_id in items {
                        match principal_id {
                            ROLE_ADMIN => {
                                result.append_str(PrincipalField::Roles, "admin");
                            }
                            ROLE_TENANT_ADMIN => {
                                result.append_str(PrincipalField::Roles, "tenant-admin");
                            }
                            ROLE_USER => {
                                result.append_str(PrincipalField::Roles, "user");
                            }
                            principal_id => {
                                if let Some(name) = self
                                    .get_principal_name(principal_id)
                                    .await
                                    .caused_by(trc::location!())?
                                {
                                    result.append_str(PrincipalField::Roles, name);
                                }
                            }
                        }
                    }
                }
                PrincipalData::Lists(items)
                    if fields.is_empty() || fields.contains(&PrincipalField::Lists) =>
                {
                    for principal_id in items {
                        if let Some(name) = self
                            .get_principal_name(principal_id)
                            .await
                            .caused_by(trc::location!())?
                        {
                            result.append_str(PrincipalField::Lists, name);
                        }
                    }
                }
                PrincipalData::Permissions(permission_grants) if has_enabled || has_disabled => {
                    for grant in permission_grants {
                        if grant.grant {
                            if has_enabled {
                                result.append_str(
                                    PrincipalField::EnabledPermissions,
                                    grant.permission.name(),
                                );
                            }
                        } else if has_disabled {
                            result.append_str(
                                PrincipalField::DisabledPermissions,
                                grant.permission.name(),
                            );
                        }
                    }
                }
                PrincipalData::Picture(compact_string) => {
                    if fields.is_empty() || fields.contains(&PrincipalField::Picture) {
                        result.set(PrincipalField::Picture, compact_string);
                    }
                }
                PrincipalData::ExternalMembers(compact_strings) => {
                    if fields.is_empty() || fields.contains(&PrincipalField::ExternalMembers) {
                        result.set(PrincipalField::ExternalMembers, compact_strings);
                    }
                }
                PrincipalData::Urls(compact_strings) => {
                    if fields.is_empty() || fields.contains(&PrincipalField::Urls) {
                        result.set(PrincipalField::Urls, compact_strings);
                    }
                }
                PrincipalData::PrincipalQuota(principal_quotas_) => {
                    principal_quotas = principal_quotas_;
                }
                _ => (),
            }
        }

        // Obtain member names
        if fields.is_empty() || fields.contains(&PrincipalField::Members) {
            match principal.typ {
                Type::Group | Type::List | Type::Role => {
                    for member_id in self.get_members(principal.id).await? {
                        if let Some(member_principal) =
                            self.query(QueryBy::Id(member_id), false).await?
                        {
                            result.append_str(PrincipalField::Members, member_principal.name);
                        }
                    }
                }
                Type::Domain => {
                    let from_key =
                        ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(vec![])));
                    let to_key = ValueKey::from(ValueClass::Directory(DirectoryClass::EmailToId(
                        vec![u8::MAX; 10],
                    )));
                    let domain_name = &principal.name;
                    let mut total: u64 = 0;
                    self.iterate(
                        IterateParams::new(from_key, to_key).no_values(),
                        |key, _| {
                            if std::str::from_utf8(key.get(1..).unwrap_or_default())
                                .unwrap_or_default()
                                .rsplit_once('@')
                                .is_some_and(|(_, domain)| domain == domain_name)
                            {
                                total += 1;
                            }
                            Ok(true)
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;
                    result.set(PrincipalField::Members, total);
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

                    result.set(PrincipalField::Members, total);
                }
                _ => {}
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Map tenant name
        #[cfg(feature = "enterprise")]
        if let Some(tenant_id) = principal.tenant {
            if fields.is_empty() || fields.contains(&PrincipalField::Tenant) {
                if let Some(name) = self
                    .get_principal_name(tenant_id)
                    .await
                    .caused_by(trc::location!())?
                {
                    result.set(PrincipalField::Tenant, name);
                }
            }
        }

        // SPDX-SnippetEnd

        // Map fields
        for (name, value) in [
            (PrincipalField::Name, Some(principal.name)),
            (PrincipalField::Description, principal.description),
        ] {
            if let Some(value) = value {
                if fields.is_empty() || fields.contains(&name) {
                    result.set(name, value);
                }
            }
        }
        for (name, value) in [
            (PrincipalField::Secrets, principal.secrets),
            (PrincipalField::Emails, principal.emails),
        ] {
            if fields.is_empty() || fields.contains(&name) {
                result.set(name, value);
            }
        }
        if fields.is_empty() || fields.contains(&PrincipalField::Quota) {
            if !principal_quotas.is_empty() {
                let mut quotas = vec![0u64; Type::MAX_ID + 2];
                if let Some(quota) = principal.quota {
                    quotas[0] = quota;
                }
                for quota in principal_quotas {
                    quotas[(quota.typ as usize) + 1] = quota.quota;
                }

                result.set(PrincipalField::Quota, quotas);
            } else if let Some(quota) = principal.quota {
                result.set(PrincipalField::Quota, quota);
            }
        }

        // Obtain used quota
        if matches!(principal.typ, Type::Individual | Type::Group | Type::Tenant)
            && (fields.is_empty() || fields.contains(&PrincipalField::UsedQuota))
        {
            let quota = self
                .get_counter(DirectoryClass::UsedQuota(principal.id))
                .await
                .caused_by(trc::location!())?;
            if quota > 0 {
                result.set(PrincipalField::UsedQuota, quota as u64);
            }
        }

        Ok(result)
    }
}

impl ValidateDirectory for Store {
    async fn validate_email(
        &self,
        email: &str,
        tenant_id: Option<u32>,
        create_if_missing: bool,
    ) -> trc::Result<()> {
        if self.rcpt(email).await.caused_by(trc::location!())? != RcptType::Invalid {
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
                        PrincipalSet::new(0, Type::Domain)
                            .with_field(PrincipalField::Name, domain)
                            .with_field(PrincipalField::Description, domain),
                        tenant_id,
                        None,
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

impl<'x> UpdatePrincipal<'x> {
    pub fn by_id(id: u32) -> Self {
        Self {
            query: QueryBy::Id(id),
            changes: Vec::new(),
            create_domains: false,
            tenant_id: None,
            allowed_permissions: None,
        }
    }

    pub fn by_name(name: &'x str) -> Self {
        Self {
            query: QueryBy::Name(name),
            changes: Vec::new(),
            create_domains: false,
            tenant_id: None,
            allowed_permissions: None,
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

    pub fn with_allowed_permissions(mut self, permissions: &'x Permissions) -> Self {
        self.allowed_permissions = permissions.into();
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

impl ChangedPrincipals {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_change(principal_id: u32, principal_type: Type, field: PrincipalField) -> Self {
        let mut set = Self::default();
        set.add_change(principal_id, principal_type, field);
        set
    }

    pub fn add_change(&mut self, principal_id: u32, principal_type: Type, field: PrincipalField) {
        if matches!(
            (principal_type, field),
            (
                Type::Individual | Type::Group,
                PrincipalField::Name
                    | PrincipalField::Quota
                    | PrincipalField::Secrets
                    | PrincipalField::Emails
                    | PrincipalField::MemberOf
                    | PrincipalField::Members
                    | PrincipalField::Tenant
                    | PrincipalField::Roles
                    | PrincipalField::EnabledPermissions
                    | PrincipalField::DisabledPermissions,
            ) | (
                Type::Tenant | Type::Role | Type::ApiKey | Type::OauthClient,
                PrincipalField::MemberOf
                    | PrincipalField::Members
                    | PrincipalField::Secrets
                    | PrincipalField::Tenant
                    | PrincipalField::Roles
                    | PrincipalField::EnabledPermissions
                    | PrincipalField::DisabledPermissions,
            )
        ) && principal_id < ROLE_USER
        {
            self.0
                .entry(principal_id)
                .or_insert_with(|| ChangedPrincipal::new(principal_type))
                .update_member_change(matches!(
                    (field, principal_type),
                    (
                        PrincipalField::EnabledPermissions | PrincipalField::DisabledPermissions,
                        Type::Role | Type::Tenant
                    )
                ));
        }
    }

    pub fn add_member_change(
        &mut self,
        principal_id: u32,
        principal_type: Type,
        member_id: u32,
        member_type: Type,
    ) {
        match (principal_type, member_type) {
            (Type::Group | Type::Role, Type::Individual | Type::ApiKey | Type::OauthClient) => {
                self.0
                    .entry(member_id)
                    .or_insert_with(|| ChangedPrincipal::new(member_type));
            }
            (Type::Individual | Type::ApiKey | Type::OauthClient, Type::Group | Type::Role) => {
                self.0
                    .entry(principal_id)
                    .or_insert_with(|| ChangedPrincipal::new(principal_type));
            }
            (
                Type::Group | Type::Tenant | Type::Role,
                Type::Individual | Type::Group | Type::Tenant | Type::Role,
            ) => {
                if principal_id < ROLE_USER {
                    self.0
                        .entry(principal_id)
                        .or_insert_with(|| ChangedPrincipal::new(principal_type))
                        .update_member_change(matches!(member_type, Type::Role));
                }
                if member_id < ROLE_USER {
                    self.0
                        .entry(member_id)
                        .or_insert_with(|| ChangedPrincipal::new(member_type))
                        .update_member_change(matches!(principal_type, Type::Role));
                }
            }
            _ => {}
        }
    }

    pub fn add_deletion(&mut self, principal_id: u32, principal_type: Type) {
        if matches!(
            principal_type,
            Type::Individual
                | Type::Group
                | Type::Tenant
                | Type::Role
                | Type::ApiKey
                | Type::OauthClient
        ) {
            self.0
                .entry(principal_id)
                .or_insert_with(|| ChangedPrincipal::new(principal_type));
        }
    }

    pub fn contains(&self, principal_id: u32) -> bool {
        self.0.contains_key(&principal_id)
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<u32, ChangedPrincipal> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ChangedPrincipal {
    pub fn new(typ: Type) -> Self {
        Self {
            typ,
            member_change: false,
        }
    }

    pub fn update_member_change(&mut self, member_change: bool) {
        if !self.member_change && member_change {
            self.member_change = true;
        }
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
        trc::Value::String(CompactString::const_new(value.as_str()))
    }
}
