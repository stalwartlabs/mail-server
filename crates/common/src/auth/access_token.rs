/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{
    backend::internal::{lookup::DirectoryStore, PrincipalField},
    Permission, Principal, QueryBy,
};
use jmap_proto::{
    request::RequestMethod,
    types::{acl::Acl, collection::Collection, id::Id},
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
    time::Instant,
};
use store::query::acl::AclQuery;
use trc::AddContext;
use utils::map::{
    bitmap::{Bitmap, BitmapItem},
    ttl_dashmap::TtlMap,
    vec_map::VecMap,
};

use crate::Server;

use super::{roles::RolePermissions, AccessToken, ResourceToken, TenantInfo};

impl Server {
    pub async fn build_access_token(&self, mut principal: Principal) -> trc::Result<AccessToken> {
        let mut role_permissions = RolePermissions::default();

        // Apply role permissions
        for role_id in principal.iter_int(PrincipalField::Roles) {
            role_permissions.union(self.get_role_permissions(role_id as u32).await?.as_ref());
        }

        // Add principal permissions
        for (permissions, field) in [
            (
                &mut role_permissions.enabled,
                PrincipalField::EnabledPermissions,
            ),
            (
                &mut role_permissions.disabled,
                PrincipalField::DisabledPermissions,
            ),
        ] {
            for permission in principal.iter_int(field) {
                let permission = permission as usize;
                if permission < Permission::COUNT {
                    permissions.set(permission);
                }
            }
        }

        // Apply principal permissions
        let mut permissions = role_permissions.finalize();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        let mut tenant = None;
        #[cfg(feature = "enterprise")]
        if self.is_enterprise_edition() {
            if let Some(tenant_id) = principal.get_int(PrincipalField::Tenant).map(|v| v as u32) {
                // Limit tenant permissions
                permissions.intersection(&self.get_role_permissions(tenant_id).await?.enabled);

                // Obtain tenant quota
                tenant = Some(TenantInfo {
                    id: tenant_id,
                    quota: self
                        .store()
                        .query(QueryBy::Id(tenant_id), false)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or_else(|| {
                            trc::SecurityEvent::Unauthorized
                                .into_err()
                                .details("Tenant not found")
                                .id(tenant_id)
                                .caused_by(trc::location!())
                        })?
                        .get_int(PrincipalField::Quota)
                        .unwrap_or_default(),
                });
            }
        }

        // SPDX-SnippetEnd

        Ok(AccessToken {
            primary_id: principal.id(),
            member_of: principal
                .iter_int(PrincipalField::MemberOf)
                .map(|v| v as u32)
                .collect(),
            access_to: VecMap::new(),
            tenant,
            name: principal.take_str(PrincipalField::Name).unwrap_or_default(),
            description: principal.take_str(PrincipalField::Description),
            emails: principal
                .take_str_array(PrincipalField::Emails)
                .unwrap_or_default(),
            quota: principal.quota(),
            permissions,
        })
    }

    pub async fn get_access_token(&self, account_id: u32) -> trc::Result<AccessToken> {
        let err = match self.directory().query(QueryBy::Id(account_id), true).await {
            Ok(Some(principal)) => {
                return self
                    .update_access_token(self.build_access_token(principal).await?)
                    .await
            }
            Ok(None) => Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!())),
            Err(err) => Err(err),
        };

        match &self.core.jmap.fallback_admin {
            Some((_, secret)) if account_id == u32::MAX => {
                self.update_access_token(
                    self.build_access_token(Principal::fallback_admin(secret))
                        .await?,
                )
                .await
            }
            _ => err,
        }
    }

    pub async fn update_access_token(
        &self,
        mut access_token: AccessToken,
    ) -> trc::Result<AccessToken> {
        for grant_account_id in [access_token.primary_id]
            .into_iter()
            .chain(access_token.member_of.iter().copied())
        {
            for acl_item in self
                .store()
                .acl_query(AclQuery::HasAccess { grant_account_id })
                .await
                .caused_by(trc::location!())?
            {
                if !access_token.is_member(acl_item.to_account_id) {
                    let acl = Bitmap::<Acl>::from(acl_item.permissions);
                    let collection = Collection::from(acl_item.to_collection);
                    if !collection.is_valid() {
                        return Err(trc::StoreEvent::DataCorruption
                            .ctx(trc::Key::Reason, "Corrupted collection found in ACL key.")
                            .details(format!("{acl_item:?}"))
                            .account_id(grant_account_id)
                            .caused_by(trc::location!()));
                    }

                    let mut collections: Bitmap<Collection> = Bitmap::new();
                    if acl.contains(Acl::Read) || acl.contains(Acl::Administer) {
                        collections.insert(collection);
                    }
                    if collection == Collection::Mailbox
                        && (acl.contains(Acl::ReadItems) || acl.contains(Acl::Administer))
                    {
                        collections.insert(Collection::Email);
                    }

                    if !collections.is_empty() {
                        access_token
                            .access_to
                            .get_mut_or_insert_with(acl_item.to_account_id, Bitmap::new)
                            .union(&collections);
                    }
                }
            }
        }

        Ok(access_token)
    }

    pub fn cache_access_token(&self, access_token: Arc<AccessToken>) {
        self.inner.data.access_tokens.insert_with_ttl(
            access_token.primary_id(),
            access_token,
            Instant::now() + self.core.jmap.session_cache_ttl,
        );
    }

    pub async fn get_cached_access_token(&self, primary_id: u32) -> trc::Result<Arc<AccessToken>> {
        if let Some(access_token) = self.inner.data.access_tokens.get_with_ttl(&primary_id) {
            Ok(access_token)
        } else {
            // Refresh ACL token
            self.get_access_token(primary_id).await.map(|access_token| {
                let access_token = Arc::new(access_token);
                self.cache_access_token(access_token.clone());
                access_token
            })
        }
    }
}

impl AccessToken {
    pub fn from_id(primary_id: u32) -> Self {
        Self {
            primary_id,
            ..Default::default()
        }
    }

    pub fn with_access_to(self, access_to: VecMap<u32, Bitmap<Collection>>) -> Self {
        Self { access_to, ..self }
    }

    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.set(permission.id());
        self
    }

    pub fn state(&self) -> u32 {
        // Hash state
        let mut s = DefaultHasher::new();
        self.member_of.hash(&mut s);
        self.access_to.hash(&mut s);
        s.finish() as u32
    }

    pub fn primary_id(&self) -> u32 {
        self.primary_id
    }

    pub fn secondary_ids(&self) -> impl Iterator<Item = &u32> {
        self.member_of
            .iter()
            .chain(self.access_to.iter().map(|(id, _)| id))
    }

    pub fn is_member(&self, account_id: u32) -> bool {
        self.primary_id == account_id
            || self.member_of.contains(&account_id)
            || self.has_permission(Permission::Impersonate)
    }

    pub fn is_primary_id(&self, account_id: u32) -> bool {
        self.primary_id == account_id
    }

    #[inline(always)]
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.get(permission.id())
    }

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<()> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::SecurityEvent::Unauthorized
                .into_err()
                .details(permission.name()))
        }
    }

    pub fn permissions(&self) -> Vec<Permission> {
        const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
        const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
        let mut permissions = Vec::new();

        for (block_num, bytes) in self.permissions.inner().iter().enumerate() {
            let mut bytes = *bytes;

            while bytes != 0 {
                let item = USIZE_MASK - bytes.leading_zeros();
                bytes ^= 1 << item;
                if let Some(permission) =
                    Permission::from_id((block_num * USIZE_BITS) + item as usize)
                {
                    permissions.push(permission);
                }
            }
        }
        permissions
    }

    pub fn is_shared(&self, account_id: u32) -> bool {
        !self.is_member(account_id) && self.access_to.iter().any(|(id, _)| *id == account_id)
    }

    pub fn shared_accounts(&self, collection: impl Into<Collection>) -> impl Iterator<Item = &u32> {
        let collection = collection.into();
        self.member_of
            .iter()
            .chain(self.access_to.iter().filter_map(move |(id, cols)| {
                if cols.contains(collection) {
                    id.into()
                } else {
                    None
                }
            }))
    }

    pub fn has_access(&self, to_account_id: u32, to_collection: impl Into<Collection>) -> bool {
        let to_collection = to_collection.into();
        self.is_member(to_account_id)
            || self.access_to.iter().any(|(id, collections)| {
                *id == to_account_id && collections.contains(to_collection)
            })
    }

    pub fn assert_has_access(
        &self,
        to_account_id: Id,
        to_collection: Collection,
    ) -> trc::Result<&Self> {
        if self.has_access(to_account_id.document_id(), to_collection) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden.into_err().details(format!(
                "You do not have access to account {}",
                to_account_id
            )))
        }
    }

    pub fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self> {
        if self.is_member(account_id.document_id()) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details(format!("You are not an owner of account {}", account_id)))
        }
    }

    pub fn assert_has_jmap_permission(&self, request: &RequestMethod) -> trc::Result<()> {
        let permission = match request {
            RequestMethod::Get(m) => match &m.arguments {
                jmap_proto::method::get::RequestArguments::Email(_) => Permission::JmapEmailGet,
                jmap_proto::method::get::RequestArguments::Mailbox => Permission::JmapMailboxGet,
                jmap_proto::method::get::RequestArguments::Thread => Permission::JmapThreadGet,
                jmap_proto::method::get::RequestArguments::Identity => Permission::JmapIdentityGet,
                jmap_proto::method::get::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionGet
                }
                jmap_proto::method::get::RequestArguments::PushSubscription => {
                    Permission::JmapPushSubscriptionGet
                }
                jmap_proto::method::get::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptGet
                }
                jmap_proto::method::get::RequestArguments::VacationResponse => {
                    Permission::JmapVacationResponseGet
                }
                jmap_proto::method::get::RequestArguments::Principal => {
                    Permission::JmapPrincipalGet
                }
                jmap_proto::method::get::RequestArguments::Quota => Permission::JmapQuotaGet,
                jmap_proto::method::get::RequestArguments::Blob(_) => Permission::JmapBlobGet,
            },
            RequestMethod::Set(m) => match &m.arguments {
                jmap_proto::method::set::RequestArguments::Email => Permission::JmapEmailSet,
                jmap_proto::method::set::RequestArguments::Mailbox(_) => Permission::JmapMailboxSet,
                jmap_proto::method::set::RequestArguments::Identity => Permission::JmapIdentitySet,
                jmap_proto::method::set::RequestArguments::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionSet
                }
                jmap_proto::method::set::RequestArguments::PushSubscription => {
                    Permission::JmapPushSubscriptionSet
                }
                jmap_proto::method::set::RequestArguments::SieveScript(_) => {
                    Permission::JmapSieveScriptSet
                }
                jmap_proto::method::set::RequestArguments::VacationResponse => {
                    Permission::JmapVacationResponseSet
                }
            },
            RequestMethod::Changes(m) => match m.arguments {
                jmap_proto::method::changes::RequestArguments::Email => {
                    Permission::JmapEmailChanges
                }
                jmap_proto::method::changes::RequestArguments::Mailbox => {
                    Permission::JmapMailboxChanges
                }
                jmap_proto::method::changes::RequestArguments::Thread => {
                    Permission::JmapThreadChanges
                }
                jmap_proto::method::changes::RequestArguments::Identity => {
                    Permission::JmapIdentityChanges
                }
                jmap_proto::method::changes::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionChanges
                }
                jmap_proto::method::changes::RequestArguments::Quota => {
                    Permission::JmapQuotaChanges
                }
            },
            RequestMethod::Copy(m) => match m.arguments {
                jmap_proto::method::copy::RequestArguments::Email => Permission::JmapEmailCopy,
            },
            RequestMethod::CopyBlob(_) => Permission::JmapBlobCopy,
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::ParseEmail(_) => Permission::JmapEmailParse,
            RequestMethod::QueryChanges(m) => match m.arguments {
                jmap_proto::method::query::RequestArguments::Email(_) => {
                    Permission::JmapEmailQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Mailbox(_) => {
                    Permission::JmapMailboxQueryChanges
                }
                jmap_proto::method::query::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                jmap_proto::method::query::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Principal => {
                    Permission::JmapPrincipalQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Quota => {
                    Permission::JmapQuotaQueryChanges
                }
            },
            RequestMethod::Query(m) => match m.arguments {
                jmap_proto::method::query::RequestArguments::Email(_) => Permission::JmapEmailQuery,
                jmap_proto::method::query::RequestArguments::Mailbox(_) => {
                    Permission::JmapMailboxQuery
                }
                jmap_proto::method::query::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionQuery
                }
                jmap_proto::method::query::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptQuery
                }
                jmap_proto::method::query::RequestArguments::Principal => {
                    Permission::JmapPrincipalQuery
                }
                jmap_proto::method::query::RequestArguments::Quota => Permission::JmapQuotaQuery,
            },
            RequestMethod::SearchSnippet(_) => Permission::JmapSearchSnippet,
            RequestMethod::ValidateScript(_) => Permission::JmapSieveScriptValidate,
            RequestMethod::LookupBlob(_) => Permission::JmapBlobLookup,
            RequestMethod::UploadBlob(_) => Permission::JmapBlobUpload,
            RequestMethod::Echo(_) => Permission::JmapEcho,
            RequestMethod::Error(_) => return Ok(()),
        };

        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("You are not authorized to perform this action"))
        }
    }

    pub fn as_resource_token(&self) -> ResourceToken {
        ResourceToken {
            account_id: self.primary_id,
            quota: self.quota,
            tenant: self.tenant,
        }
    }
}
