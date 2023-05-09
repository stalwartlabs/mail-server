use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead},
    AeadInPlace, Aes256GcmSiv, KeyInit, Nonce,
};

use jmap_proto::types::collection::Collection;
use store::{blake3, write::key::KeySerializer, Key, Serialize, SUBSPACE_VALUES};
use utils::map::bitmap::Bitmap;

pub mod account;
pub mod acl;
pub mod authenticate;
pub mod oauth;
pub mod rate_limit;

#[derive(Debug, Clone)]
pub struct AclToken {
    pub primary_id: u32,
    pub member_of: Vec<u32>,
    pub access_to: Vec<(u32, Bitmap<Collection>)>,
}

#[derive(Debug, Clone)]
pub enum AuthenticationResults {
    Success(AccountDetails),
    Failure,
}

#[derive(Debug, Clone)]
pub struct AccountDetails {
    pub id: String,
    pub member_of: Vec<String>,
}

pub struct AccountKey {
    pub name: String,
}

impl AclToken {
    pub fn new(primary_id: u32) -> Self {
        Self {
            primary_id,
            member_of: Vec::new(),
            access_to: Vec::new(),
        }
    }

    pub fn with_member_of(self, member_of: Vec<u32>) -> Self {
        Self { member_of, ..self }
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

impl AccountKey {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl Serialize for AccountKey {
    fn serialize(self) -> Vec<u8> {
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<u32>() + self.name.len() + 1)
                    .write(SUBSPACE_VALUES)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<u32>() + self.name.len())
            }
        }
        .write(0u32)
        .write(self.name.as_bytes())
        .finalize()
    }
}

impl Key for AccountKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_VALUES
    }
}
