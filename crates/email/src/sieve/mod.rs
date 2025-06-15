/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::KV_SIEVE_ID;

use sieve::Sieve;
use store::{blake3, write::ArchiveVersion};
use utils::BlobHash;

pub mod activate;
pub mod delete;
pub mod index;
pub mod ingest;

#[derive(Debug, Clone)]
pub struct ActiveScript {
    pub document_id: u32,
    pub version: ArchiveVersion,
    pub script_name: String,
    pub script: Arc<Sieve>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct SieveScript {
    pub name: String,
    pub is_active: bool,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub vacation_response: Option<VacationResponse>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct VacationResponse {
    pub from_date: Option<u64>,
    pub to_date: Option<u64>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

impl SieveScript {
    pub fn new(name: impl Into<String>, blob_hash: BlobHash) -> Self {
        SieveScript {
            name: name.into(),
            is_active: false,
            blob_hash,
            vacation_response: None,
            size: 0,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_blob_hash(mut self, blob_hash: BlobHash) -> Self {
        self.blob_hash = blob_hash;
        self
    }

    pub fn with_is_active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
        self
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    pub fn set_is_active(&mut self, is_active: bool) {
        self.is_active = is_active;
    }

    pub fn with_vacation_response(mut self, vacation_response: VacationResponse) -> Self {
        self.vacation_response = Some(vacation_response);
        self
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SeenIdHash(pub [u8; 32]);

impl SeenIdHash {
    pub fn new(account_id: u32, hash: u32, id: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&account_id.to_be_bytes());
        hasher.update(&hash.to_be_bytes());
        hasher.update(id.as_bytes());
        SeenIdHash(hasher.finalize().into())
    }

    pub fn key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.0.len() + 1);
        result.push(KV_SIEVE_ID);
        result.extend_from_slice(&self.0);
        result
    }
}

impl AsRef<[u8]> for SeenIdHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
