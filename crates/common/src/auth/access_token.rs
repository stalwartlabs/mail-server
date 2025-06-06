/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use directory::{
    Permission, Principal, PrincipalData, QueryBy, Type,
    backend::internal::{
        lookup::DirectoryStore,
        manage::{ChangedPrincipals, ManageDirectory},
    },
};
use jmap_proto::{
    request::RequestMethod,
    types::{acl::Acl, collection::Collection, id::Id},
};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};
use store::{dispatch::lookup::KeyValue, query::acl::AclQuery};
use trc::AddContext;
use utils::map::{
    bitmap::{Bitmap, BitmapItem},
    vec_map::VecMap,
};

use crate::{
    KV_TOKEN_REVISION, Server,
    listener::limiter::{ConcurrencyLimiter, LimiterResult},
};

use super::{AccessToken, ResourceToken, TenantInfo, roles::RolePermissions};

pub enum PrincipalOrId {
    Principal(Principal),
    Id(u32),
}

impl Server {
    async fn build_access_token_from_principal(
        &self,
        mut principal: Principal,
        revision: u64,
    ) -> trc::Result<AccessToken> {
        let mut role_permissions = RolePermissions::default();

        // Apply role permissions
        for role_id in principal.roles() {
            role_permissions.union(self.get_role_permissions(*role_id).await?.as_ref());
        }

        // Add principal permissions
        for permission in principal.permissions() {
            if permission.grant {
                role_permissions.enabled.set(permission.permission.id());
            } else {
                role_permissions.disabled.set(permission.permission.id());
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
            if let Some(tenant_id) = principal.tenant {
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
                        .quota
                        .unwrap_or_default(),
                });
            }
        }

        // SPDX-SnippetEnd

        // Build access token
        let mut access_token = AccessToken {
            primary_id: principal.id(),
            member_of: principal
                .member_of_mut()
                .map(std::mem::take)
                .unwrap_or_default(),
            access_to: VecMap::new(),
            tenant,
            name: principal.name,
            description: principal.description,
            emails: principal.emails,
            quota: principal.quota.unwrap_or_default(),
            locale: principal.data.iter().find_map(|data| {
                if let PrincipalData::Locale(v) = data {
                    Some(v.to_string())
                } else {
                    None
                }
            }),
            permissions,
            concurrent_imap_requests: self.core.imap.rate_concurrent.map(ConcurrencyLimiter::new),
            concurrent_http_requests: self
                .core
                .jmap
                .request_max_concurrent
                .map(ConcurrencyLimiter::new),
            concurrent_uploads: self
                .core
                .jmap
                .upload_max_concurrent
                .map(ConcurrencyLimiter::new),
            obj_size: 0,
            revision,
        };

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

        Ok(access_token.update_size())
    }

    async fn build_access_token(&self, account_id: u32, revision: u64) -> trc::Result<AccessToken> {
        let err = match self.directory().query(QueryBy::Id(account_id), true).await {
            Ok(Some(principal)) => {
                return self
                    .build_access_token_from_principal(principal, revision)
                    .await;
            }
            Ok(None) => Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!())),
            Err(err) => Err(err),
        };

        match &self.core.jmap.fallback_admin {
            Some((_, secret)) if account_id == u32::MAX => {
                self.build_access_token_from_principal(Principal::fallback_admin(secret), revision)
                    .await
            }
            _ => err,
        }
    }

    pub async fn get_access_token(
        &self,
        principal: impl Into<PrincipalOrId>,
    ) -> trc::Result<Arc<AccessToken>> {
        let principal = principal.into();

        // Obtain current revision
        let principal_id = principal.id();
        let revision = self.fetch_token_revision(principal_id).await;

        match self
            .inner
            .cache
            .access_tokens
            .get_value_or_guard_async(&principal_id)
            .await
        {
            Ok(token) => {
                if revision == Some(token.revision) {
                    Ok(token)
                } else {
                    let revision = revision.unwrap_or(u64::MAX);
                    let token: Arc<AccessToken> = match principal {
                        PrincipalOrId::Principal(principal) => {
                            self.build_access_token_from_principal(principal, revision)
                                .await?
                        }
                        PrincipalOrId::Id(account_id) => {
                            self.build_access_token(account_id, revision).await?
                        }
                    }
                    .into();

                    self.inner
                        .cache
                        .access_tokens
                        .insert(token.primary_id(), token.clone());

                    Ok(token)
                }
            }
            Err(guard) => {
                let revision = revision.unwrap_or(u64::MAX);
                let token: Arc<AccessToken> = match principal {
                    PrincipalOrId::Principal(principal) => {
                        self.build_access_token_from_principal(principal, revision)
                            .await?
                    }
                    PrincipalOrId::Id(account_id) => {
                        self.build_access_token(account_id, revision).await?
                    }
                }
                .into();
                let _ = guard.insert(token.clone());
                Ok(token)
            }
        }
    }

    pub async fn increment_token_revision(&self, changed_principals: ChangedPrincipals) {
        let mut nested_principals = Vec::new();

        for (id, changed_principal) in changed_principals.iter() {
            self.increment_revision(*id).await;

            if changed_principal.member_change {
                if changed_principal.typ == Type::Tenant {
                    match self
                        .store()
                        .list_principals(
                            None,
                            (*id).into(),
                            &[Type::Individual, Type::Group, Type::Role, Type::ApiKey],
                            false,
                            0,
                            0,
                        )
                        .await
                    {
                        Ok(principals) => {
                            for principal in principals.items {
                                if !changed_principals.contains(principal.id()) {
                                    self.increment_revision(principal.id()).await;
                                }
                            }
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to list principals")
                                    .caused_by(trc::location!())
                                    .account_id(*id)
                            );
                        }
                    }
                } else {
                    nested_principals.push(*id);
                }
            }
        }

        if !nested_principals.is_empty() {
            let mut fetched_ids = AHashSet::new();
            let mut ids = nested_principals.into_iter();
            let mut ids_stack = vec![];

            loop {
                if let Some(id) = ids.next() {
                    // Skip if already fetched
                    if !fetched_ids.insert(id) {
                        continue;
                    }

                    // Increment revision
                    if !changed_principals.contains(id) {
                        self.increment_revision(id).await;
                    }

                    // Obtain principal
                    match self.store().get_members(id).await {
                        Ok(members) => {
                            ids_stack.push(ids);
                            ids = members.into_iter();
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to obtain principal")
                                    .caused_by(trc::location!())
                                    .account_id(id)
                            );
                        }
                    }
                } else if let Some(prev_ids) = ids_stack.pop() {
                    ids = prev_ids;
                } else {
                    break;
                }
            }
        }
    }

    async fn increment_revision(&self, id: u32) {
        if let Err(err) = self
            .in_memory_store()
            .counter_incr(
                KeyValue::with_prefix(KV_TOKEN_REVISION, id.to_be_bytes(), 1).expires(30 * 86400),
                false,
            )
            .await
        {
            trc::error!(
                err.details("Failed to increment principal revision")
                    .account_id(id)
            );
        }
    }

    pub async fn fetch_token_revision(&self, id: u32) -> Option<u64> {
        match self
            .in_memory_store()
            .counter_get(KeyValue::<()>::build_key(
                KV_TOKEN_REVISION,
                id.to_be_bytes(),
            ))
            .await
        {
            Ok(revision) => (revision as u64).into(),
            Err(err) => {
                trc::error!(
                    err.details("Failed to obtain principal revision")
                        .account_id(id)
                );
                None
            }
        }
    }
}

impl From<u32> for PrincipalOrId {
    fn from(id: u32) -> Self {
        Self::Id(id)
    }
}

impl From<Principal> for PrincipalOrId {
    fn from(principal: Principal) -> Self {
        Self::Principal(principal)
    }
}

impl PrincipalOrId {
    pub fn id(&self) -> u32 {
        match self {
            Self::Principal(principal) => principal.id(),
            Self::Id(id) => *id,
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

    pub fn all_ids(&self) -> impl Iterator<Item = u32> {
        [self.primary_id]
            .into_iter()
            .chain(self.member_of.iter().copied())
            .chain(self.access_to.iter().map(|(id, _)| *id))
    }

    pub fn all_ids_by_collection(&self, collection: Collection) -> impl Iterator<Item = u32> {
        [self.primary_id]
            .into_iter()
            .chain(self.member_of.iter().copied())
            .chain(self.access_to.iter().filter_map(move |(id, cols)| {
                if cols.contains(collection) {
                    Some(*id)
                } else {
                    None
                }
            }))
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

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<bool> {
        if self.has_permission(permission) {
            Ok(true)
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

    pub fn has_account_access(&self, to_account_id: u32) -> bool {
        self.is_member(to_account_id) || self.access_to.iter().any(|(id, _)| *id == to_account_id)
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

    pub fn is_http_request_allowed(&self) -> LimiterResult {
        self.concurrent_http_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_imap_request_allowed(&self) -> LimiterResult {
        self.concurrent_imap_requests
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn is_upload_allowed(&self) -> LimiterResult {
        self.concurrent_uploads
            .as_ref()
            .map_or(LimiterResult::Disabled, |limiter| limiter.is_allowed())
    }

    pub fn update_size(mut self) -> Self {
        self.obj_size = (std::mem::size_of::<AccessToken>()
            + (self.member_of.len() * std::mem::size_of::<u32>())
            + (self.access_to.len() * (std::mem::size_of::<u32>() + std::mem::size_of::<u64>()))
            + self.name.len()
            + self.description.as_ref().map_or(0, |v| v.len())
            + self.emails.iter().map(|v| v.len()).sum::<usize>()) as u64;
        self
    }
}
