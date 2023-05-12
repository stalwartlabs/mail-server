use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead},
    AeadInPlace, Aes256GcmSiv, KeyInit, Nonce,
};

use jmap_proto::types::collection::Collection;
use store::blake3;
use utils::map::bitmap::Bitmap;

pub mod account;
pub mod acl;
pub mod authenticate;
pub mod oauth;
pub mod rate_limit;

pub enum AuthDatabase {
    Sql {
        db: SqlDatabase,
        query_uid_by_login: String,
        query_login_by_uid: String,
        query_secret_by_uid: String,
        query_gids_by_uid: String,
    },
    Ldap,
}

pub enum SqlDatabase {
    Postgres(sqlx::Pool<sqlx::Postgres>),
    MySql(sqlx::Pool<sqlx::MySql>),
    //MsSql(sqlx::Pool<sqlx::Mssql>),
    SqlLite(sqlx::Pool<sqlx::Sqlite>),
}

#[derive(Debug, Clone)]
pub struct AclToken {
    pub primary_id: u32,
    pub member_of: Vec<u32>,
    pub access_to: Vec<(u32, Bitmap<Collection>)>,
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
