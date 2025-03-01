/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashSet, sync::Arc};

use sieve::Sieve;
use store::{ahash::RandomState, blake3, write::Archive};
use utils::BlobHash;

pub mod activate;
pub mod delete;
pub mod index;
pub mod ingest;
pub mod serialize;

#[derive(Debug, Clone)]
pub struct ActiveScript {
    pub document_id: u32,
    pub script_name: String,
    pub script: Arc<Sieve>,
    pub seen_ids: Option<Archive>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone)]
pub struct SeenIdHash {
    hash: [u8; 32],
    expiry: u64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct SeenIds {
    pub ids: HashSet<SeenIdHash, RandomState>,
    pub has_changes: bool,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
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
}

impl SeenIdHash {
    pub fn new(id: &str, expiry: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(id.as_bytes());
        SeenIdHash {
            hash: hasher.finalize().into(),
            expiry,
        }
    }
}

impl PartialOrd for SeenIdHash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeenIdHash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expiry.cmp(&other.expiry)
    }
}

impl std::hash::Hash for SeenIdHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for SeenIdHash {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for SeenIdHash {}

impl std::hash::Hash for ArchivedSeenIdHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for ArchivedSeenIdHash {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for ArchivedSeenIdHash {}
