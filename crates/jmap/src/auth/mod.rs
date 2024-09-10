/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead},
    AeadInPlace, Aes256GcmSiv, KeyInit, Nonce,
};

use directory::{backend::internal::PrincipalField, Permission, Principal, PERMISSION_BITMAP_SIZE};
use jmap_proto::{
    request::RequestMethod,
    types::{collection::Collection, id::Id},
};
use store::blake3;
use trc::ipc::bitset::Bitset;
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

pub mod acl;
pub mod authenticate;
pub mod oauth;
pub mod rate_limit;

#[derive(Debug, Clone, Default)]
pub struct AccessToken {
    pub primary_id: u32,
    pub member_of: Vec<u32>,
    pub access_to: VecMap<u32, Bitmap<Collection>>,
    pub name: String,
    pub description: Option<String>,
    pub quota: u64,
    pub permissions: Bitset<PERMISSION_BITMAP_SIZE>,
}

impl AccessToken {
    pub fn new(mut principal: Principal) -> Self {
        Self {
            primary_id: principal.id(),
            member_of: principal
                .iter_int(PrincipalField::MemberOf)
                .map(|v| v as u32)
                .collect(),
            access_to: VecMap::new(),
            name: principal.take_str(PrincipalField::Name).unwrap_or_default(),
            description: principal.take_str(PrincipalField::Description),
            quota: principal.quota(),
            permissions: Default::default(),
        }
    }

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
        let mut permissions = Vec::new();
        for (block_num, bytes) in self.permissions.inner().iter().enumerate() {
            let mut bytes = *bytes;

            while bytes != 0 {
                let item = std::mem::size_of::<usize>() - 1 - bytes.leading_zeros() as usize;
                bytes ^= 1 << item;
                permissions.push(
                    Permission::from_id((block_num * std::mem::size_of::<usize>()) + item).unwrap(),
                );
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
}

pub struct SymmetricEncrypt {
    aes: Aes256GcmSiv,
}

impl SymmetricEncrypt {
    pub const ENCRYPT_TAG_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;

    pub fn new(key: &[u8], context: &str) -> Self {
        SymmetricEncrypt {
            aes: Aes256GcmSiv::new(&GenericArray::clone_from_slice(
                &blake3::derive_key(context, key)[..],
            )),
        }
    }

    #[allow(clippy::ptr_arg)]
    pub fn encrypt_in_place(&self, bytes: &mut Vec<u8>, nonce: &[u8]) -> Result<(), String> {
        self.aes
            .encrypt_in_place(Nonce::from_slice(nonce), b"", bytes)
            .map_err(|e| e.to_string())
    }

    pub fn encrypt(&self, bytes: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        self.aes
            .encrypt(Nonce::from_slice(nonce), bytes)
            .map_err(|e| e.to_string())
    }

    pub fn decrypt(&self, bytes: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        self.aes
            .decrypt(Nonce::from_slice(nonce), bytes)
            .map_err(|e| e.to_string())
    }
}
