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

use directory::{Principal, Type};
use jmap_proto::{
    error::method::MethodError,
    types::{collection::Collection, id::Id},
};
use store::blake3;
use utils::map::bitmap::Bitmap;

pub mod acl;
pub mod authenticate;
pub mod oauth;
pub mod rate_limit;

#[derive(Debug, Clone, Default)]
pub struct AccessToken {
    pub primary_id: u32,
    pub member_of: Vec<u32>,
    pub access_to: Vec<(u32, Bitmap<Collection>)>,
    pub name: String,
    pub description: Option<String>,
    pub quota: u64,
    pub is_superuser: bool,
}

impl AccessToken {
    pub fn new(principal: Principal<u32>) -> Self {
        Self {
            primary_id: principal.id,
            member_of: principal.member_of,
            access_to: Vec::new(),
            name: principal.name,
            description: principal.description,
            quota: principal.quota,
            is_superuser: principal.typ == Type::Superuser,
        }
    }

    pub fn with_access_to(self, access_to: Vec<(u32, Bitmap<Collection>)>) -> Self {
        Self { access_to, ..self }
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
        self.primary_id == account_id || self.member_of.contains(&account_id) || self.is_superuser
    }

    pub fn is_primary_id(&self, account_id: u32) -> bool {
        self.primary_id == account_id
    }

    pub fn is_super_user(&self) -> bool {
        self.is_superuser
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
            Err(MethodError::Forbidden(format!(
                "You do not have access to account {}",
                to_account_id
            ))
            .into())
        }
    }

    pub fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self> {
        if self.is_member(account_id.document_id()) {
            Ok(self)
        } else {
            Err(
                MethodError::Forbidden(format!("You are not an owner of account {}", account_id))
                    .into(),
            )
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
