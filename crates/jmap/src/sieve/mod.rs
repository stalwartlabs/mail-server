/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::sync::Arc;

use serde::ser::SerializeSeq;
use sieve::Sieve;
use store::{ahash::AHashSet, blake3, write::now};

pub mod get;
pub mod ingest;
pub mod query;
pub mod set;
pub mod validate;

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
        self.expiry.partial_cmp(&other.expiry)
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

// SeenIds serializer
impl serde::Serialize for SeenIds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq((self.ids.len() * 2).into())?;
        for id in &self.ids {
            seq.serialize_element(&id.expiry)?;
            seq.serialize_element(&id.hash)?;
        }

        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for SeenIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(SeenIdsVisitor)
    }
}

struct SeenIdsVisitor;

impl<'de> serde::de::Visitor<'de> for SeenIdsVisitor {
    type Value = SeenIds;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("invalid SeenIds")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let num_entries = seq.size_hint().unwrap_or(0) / 2;
        let mut seen_ids = SeenIds {
            ids: AHashSet::with_capacity(num_entries),
            has_changes: false,
        };
        let now = now();

        for _ in 0..num_entries {
            let expiry = seq
                .next_element::<u64>()?
                .ok_or_else(|| serde::de::Error::custom("Expected expiry."))?;
            if expiry > now {
                seen_ids.ids.insert(SeenIdHash {
                    hash: seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("Expected hash."))?,
                    expiry,
                });
            } else {
                seq.next_element::<[u8; 32]>()?
                    .ok_or_else(|| serde::de::Error::custom("Expected hash."))?;
                seen_ids.has_changes = true;
            }
        }

        Ok(seen_ids)
    }
}
