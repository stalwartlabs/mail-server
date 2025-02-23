/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use jmap_proto::types::blob::BlobId;
use sieve::Sieve;
use store::{ahash::AHashSet, blake3};

pub mod index;
pub mod ingest;
pub mod serialize;

pub struct ActiveScript {
    pub document_id: u32,
    pub script_name: String,
    pub script: Arc<Sieve>,
    pub seen_ids: SeenIds,
}

#[derive(Debug, Clone)]
pub struct SeenIdHash {
    hash: [u8; 32],
    expiry: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SeenIds {
    pub ids: AHashSet<SeenIdHash>,
    pub has_changes: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SieveScript {
    pub name: String,
    pub is_active: bool,
    pub blob_id: BlobId,
    pub vacation_response: Option<VacationResponse>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VacationResponse {
    pub from_date: Option<u64>,
    pub to_date: Option<u64>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

impl SieveScript {
    pub fn new(name: impl Into<String>, blob_id: BlobId) -> Self {
        SieveScript {
            name: name.into(),
            is_active: false,
            blob_id,
            vacation_response: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_blob_id(mut self, blob_id: BlobId) -> Self {
        self.blob_id = blob_id;
        self
    }

    pub fn with_is_active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
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
